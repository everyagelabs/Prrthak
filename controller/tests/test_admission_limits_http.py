from io import BytesIO
import json
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from controller.auth import AuthDenied
from controller.http_limits import RequestLimits
from controller.production_http import application


LOCAL = "/api/v1/auth/local"
ENTRA = "/api/v1/auth/login"
SAML = "/api/v1/auth/saml/login"
ENROLL = "/api/v1/agent/enroll"


class FixtureTLS:
    def __init__(self, address, routed):
        self.peer = ("172.20.0.2" if routed else address, 12345)
        if routed:
            self._prthak_proxy_address = (address, 23456)

    def getpeername(self):
        return self.peer

    def shutdown(self, how):
        pass


class AdmissionLimitsHttpTests(unittest.TestCase):
    def setUp(self):
        self.now = 0
        limits = RequestLimits(clock=lambda: self.now)
        app = SimpleNamespace(
            limits=limits, demo=False, platform=None, signer=object(),
            auth=SimpleNamespace(local_login=self.local_login, begin_login=self.begin_login),
            store=SimpleNamespace(enroll=self.enroll),
            recovering=lambda: False, principal=lambda headers: None,
            endpoint_identity=self.endpoint_identity,
        )
        self.wsgi = application(app)
        tls = patch("controller.app.ssl.SSLSocket", FixtureTLS)
        saml = patch("controller.auth_providers.saml", return_value=SimpleNamespace(begin_login=self.begin_login))
        fence = patch("controller.app.offline_update_fenced", return_value=False)
        for patcher in (tls, saml, fence):
            patcher.start()
            self.addCleanup(patcher.stop)

    @staticmethod
    def local_login(value, headers):
        if value.get("username") != "operator":
            raise AuthDenied("Invalid credentials")
        return {"principal": {"role": "read_only"}, "cookies": []}

    @staticmethod
    def begin_login(headers):
        return {"location": "https://identity.example.test/"}

    @staticmethod
    def enroll(token, hostname, csr, signer):
        if token != "valid":
            raise PermissionError("Invalid enrollment token")
        return {"server_id": "enrolled"}

    @staticmethod
    def endpoint_identity(connection, headers):
        raise PermissionError("Verified client certificate required")

    def request(self, address, method, path, *, body=None, claimed=None, routed=False):
        connection = FixtureTLS(address, routed)
        payload = json.dumps(body).encode() if body is not None else b""
        environ = {
            "gunicorn.socket": connection,
            "REMOTE_ADDR": connection.peer[0],
            "REMOTE_PORT": str(connection.peer[1]),
            "REQUEST_METHOD": method,
            "PATH_INFO": path,
            "CONTENT_TYPE": "application/json",
            "CONTENT_LENGTH": str(len(payload)),
            "wsgi.input": BytesIO(payload),
        }
        if claimed is not None:
            environ["HTTP_X_FORWARDED_FOR"] = claimed
            environ["HTTP_FORWARDED"] = f"for={claimed}"
            environ["HTTP_X_REAL_IP"] = claimed
        reply = []

        def start_response(status, headers):
            reply.append((int(status.split()[0]), dict(headers)))
            return lambda value: None

        list(self.wsgi(environ, start_response))
        return reply[0]

    def test_routed_sign_in_isolated_by_client_and_ignores_forwarded_headers(self):
        attacker, operator = "192.0.2.1", "192.0.2.2"
        failed_login = {"username": "wrong", "password": "wrong"}
        for _ in range(10):
            self.assertEqual(self.request(attacker, "POST", LOCAL, body=failed_login, routed=True)[0], 403)
        for count in range(12):
            status, headers = self.request(attacker, "POST", LOCAL, body=failed_login,
                                           routed=True, claimed=f"198.51.100.{count + 1}")
            self.assertEqual(status, 429)
            self.assertIn("Retry-After", headers)

        valid_login = {"username": "operator", "password": "test"}
        self.assertEqual(self.request(operator, "POST", LOCAL, body=valid_login, routed=True, claimed=attacker)[0], 200)
        for path in (ENTRA, SAML):
            with self.subTest(path=path):
                self.assertEqual(self.request(operator, "GET", path, routed=True, claimed=attacker)[0], 302)
        self.now = 10
        self.assertEqual(self.request(attacker, "POST", LOCAL, body=failed_login, routed=True)[0], 403)

    def test_routed_enrollment_preserves_other_clients_and_sign_in(self):
        attacker, installer = "192.0.2.1", "192.0.2.2"
        for _ in range(20):
            self.assertEqual(self.request(attacker, "POST", ENROLL, body={"token": "invalid"}, routed=True)[0], 403)
        self.assertEqual(self.request(attacker, "POST", ENROLL, body={"token": "valid"}, routed=True, claimed=installer)[0], 429)
        self.assertEqual(self.request(installer, "POST", ENROLL, body={"token": "valid"}, routed=True, claimed=attacker)[0], 201)
        self.assertEqual(self.request(attacker, "GET", ENTRA, routed=True)[0], 302)
        self.now = 0.5
        self.assertEqual(self.request(attacker, "POST", ENROLL, body={"token": "valid"}, routed=True)[0], 201)

    def test_wrong_methods_leave_sign_in_and_enrollment_budgets_available(self):
        address = "192.0.2.1"
        for _ in range(21):
            self.request(address, "POST", ENTRA, body={})
            self.request(address, "GET", ENROLL)
        self.assertEqual(self.request(address, "GET", ENTRA)[0], 302)
        self.assertEqual(self.request(address, "POST", ENROLL, body={"token": "valid"})[0], 201)

    def test_sign_in_ceiling_bounds_distributed_requests_independently_of_enrollment(self):
        rate, burst = RequestLimits.CEILINGS["login"]
        for index in range(burst):
            self.assertEqual(self.request(f"198.51.100.{index + 1}", "GET", ENTRA)[0], 302)
        address = "203.0.113.1"
        self.assertEqual(self.request(address, "GET", ENTRA)[0], 429)
        self.assertEqual(self.request(address, "POST", ENROLL, body={"token": "valid"})[0], 201)
        self.now = 1 / rate
        self.assertEqual(self.request(address, "GET", ENTRA)[0], 302)
