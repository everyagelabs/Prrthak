"""HTTPS GUI bootstrap boundary with real signed OIDC and native kit parsing."""
import http.client
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import urlencode

from controller.app import App
from controller.auth import EntraConfig
from controller.pki import Signer, init_ca
from controller.store import Store
from controller.tests import test_auth as fixture
from controller.tests.test_gui_setup import ManagerClient
from test_integration import running


@unittest.skipUnless(fixture.HAS_CRYPTO, "GUI acceptance requires installed controller auth dependencies")
class GUIInstallationHTTPS(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pki_temp = tempfile.TemporaryDirectory()
        cls.pki = init_ca(cls.pki_temp.name)

    @classmethod
    def tearDownClass(cls):
        cls.pki_temp.cleanup()

    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.directory = Path(temp.name).resolve()
        self.store = Store(self.directory / "data")
        self.app = App(self.store, tokens={"super_admin": "super-private-token", "admin": "admin-private-token", "read_only": "read-private-token"},
            signer=Signer(self.pki / "ca.pem", self.pki / "ca-key.pem"), controller_certificate=self.pki / "controller.pem")
        server_tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_tls.load_cert_chain(self.pki / "controller.pem", self.pki / "controller-key.pem")
        self.tls = ssl.create_default_context(cafile=str(self.pki / "ca.pem"))
        context = running(self.app, server_tls)
        self.port = context.__enter__()
        self.addCleanup(context.__exit__, None, None, None)
        self.origin = "https://localhost:" + str(self.port)
        self.client = ManagerClient()
        manager_patch = patch("controller.gui_setup.NodeClient", return_value=self.client)
        manager_patch.start()
        self.addCleanup(manager_patch.stop)

    def http(self, method, path, body=None, role="super", extra=None):
        connection = http.client.HTTPSConnection("localhost", self.port, context=self.tls, timeout=15)
        headers = {"Origin": self.origin, **({"Authorization": "Bearer " + role + "-private-token"} if role else {}), **(extra or {})}
        if body is not None:
            headers["Content-Type"] = "application/json"
        connection.request(method, "/api/v1/" + path, json.dumps(body).encode() if body is not None else None, headers)
        response = connection.getresponse()
        raw = response.read()
        result = response.status, json.loads(raw) if raw else None, dict(response.getheaders())
        connection.close()
        return result

    def kit_body(self):
        return {"family": "rhel", "architecture": "amd64", "controller_url": self.origin, "expected_hostname": socket.gethostname(),
                "interval_seconds": 30, "discovery_interval_seconds": 900}

    def test_role_origin_and_no_store_download_boundary(self):
        for role in ("admin", "read"):
            self.assertEqual(self.http("GET", "platform/setup", role=role)[0], 403)
        self.assertEqual(self.http("GET", "platform/setup")[0], 200)
        self.assertEqual(self.http("POST", "agent-installation/kit", self.kit_body(), role="read")[0], 403)
        self.assertEqual(self.http("POST", "agent-installation/kit", self.kit_body(), role="admin", extra={"Origin": "https://other.example"})[0], 403)
        self.assertEqual(self.store.all("tokens"), [])
        status, kit, headers = self.http("POST", "agent-installation/kit", self.kit_body(), role="admin")
        self.assertEqual(status, 201, kit)
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertIn("attachment", headers["Content-Disposition"])
        self.assertNotIn("PRIVATE KEY", json.dumps(kit))
        self.assertNotIn(kit["enrollment_token"], json.dumps(self.store.all("audit") + self.store.all("tokens")))

    def test_candidate_callback_verifies_without_bootstrapping_application_access(self):
        from cryptography.hazmat.primitives.asymmetric import rsa
        config = EntraConfig(fixture.TENANT, fixture.CLIENT, self.origin + "/api/v1/auth/callback", "candidate-private-secret", fixture.SUPER)
        provider = fixture.LocalMicrosoft(config, rsa.generate_private_key(public_exponent=65537, key_size=2048))
        environment = {"SEG_ENTRA_TENANT_ID": fixture.TENANT, "SEG_ENTRA_CLIENT_ID": fixture.CLIENT,
            "SEG_ENTRA_REDIRECT_URI": config.redirect_uri, "SEG_BOOTSTRAP_SUPER_ADMIN_OID": fixture.SUPER,
            "SEG_HTTP_WORKERS": "", "SEG_HTTP_THREADS": "32", "SEG_DB_POOL_META_MAX": "8", "SEG_DB_POOL_TRAFFIC_MAX": "2", "SEG_DB_POOL_WAIT_SECONDS": "5"}
        code, plan, _ = self.http("POST", "platform/setup/preview", {"expected_revision": 7, "expected_config_digest": "f" * 64,
            "environment": environment, "client_secret": config.client_secret})
        self.assertEqual(code, 200, plan)
        confirmation = {"preview_id": plan["id"], **{key: plan[key] for key in ("digest", "confirmation_nonce", "confirmation_phrase")}}
        self.assertEqual(self.http("POST", "platform/setup/apply", confirmation)[0], 400)
        with patch("controller.auth.MicrosoftProvider", return_value=provider):
            code, result, headers = self.http("POST", "platform/setup/login", {"preview_id": plan["id"]})
            self.assertEqual(code, 200, result)
            query = provider.issue(result["location"], fixture.SUPER)
            binding = headers["Set-Cookie"].split(";", 1)[0]
            code, result, headers = self.http("GET", "auth/callback?" + urlencode(query, doseq=True), role=None, extra={"Cookie": binding})
            self.assertEqual(code, 303, result)
            self.assertEqual(headers["Location"], "/settings?setup=verified")
        self.assertEqual(self.store.all("auth_users"), [])
        self.assertEqual(self.store.all("auth_sessions"), [])
        self.assertFalse(self.app.auth.enabled)
        code, result, _ = self.http("POST", "platform/setup/apply", confirmation)
        self.assertEqual(code, 202, result)
        self.assertEqual(result["status"], "queued")
        self.assertNotIn(config.client_secret, json.dumps(result))

    @unittest.skipUnless(os.environ.get("SEG_AGENT_BINARY"), "Set SEG_AGENT_BINARY for real bootstrap-kit consumption")
    def test_downloaded_kit_is_consumed_by_real_agent_helper_without_firewall_access(self):
        code, kit, _ = self.http("POST", "agent-installation/kit", self.kit_body(), role="admin")
        self.assertEqual(code, 201, kit)
        source = self.directory / "agent-setup.json"
        source.write_text(json.dumps(kit))
        source.chmod(0o600)
        output = self.directory / "prepared"
        output.mkdir(mode=0o700)
        result = subprocess.run([os.environ["SEG_AGENT_BINARY"], "--prepare-setup", str(source), "--setup-output", str(output)],
                                capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn(kit["enrollment_token"], result.stdout + result.stderr)
        config = json.loads((output / "agent.json").read_text())
        self.assertEqual(config["controller_url"], self.origin)
        self.assertFalse(config["enforce"])
        self.assertEqual((output / "enrollment-token").read_text().strip(), kit["enrollment_token"])


if __name__ == "__main__":
    unittest.main()
