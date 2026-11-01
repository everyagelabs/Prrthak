"""Real mTLS identity/address acceptance behind a different transport address.

Every controller, CA, client certificate and database is temporary. Loopback is
the actual TCP peer; agent inventory and observed traffic use different fixture
addresses. Proxy headers are deliberately hostile. No endpoint or firewall is
contacted or changed.
"""
from contextlib import ExitStack
from pathlib import Path
import secrets
import ssl
import subprocess
import tempfile
import unittest

from controller.app import App
from controller.auth import EntraAuth, EntraConfig
from controller.pki import Signer, init_ca
from controller.store import Store
from test_integration import request, running


class NATIdentityTLSIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.resources = ExitStack()
        self.addCleanup(self.resources.close)
        self.root = Path(self.resources.enter_context(tempfile.TemporaryDirectory(prefix="prthak-nat-mtls-")))
        self.pki = init_ca(self.root / "tls")
        self.store = Store(self.root / "controller")
        self.admin = secrets.token_urlsafe(48)
        self.admin_headers = {"Authorization": "Bearer " + self.admin}
        self.browser = ssl.create_default_context(cafile=str(self.pki / "ca.pem"))
        self.app = App(self.store, signer=Signer(self.pki / "ca.pem", self.pki / "ca-key.pem"),
                       tokens={"super_admin": self.admin}, auth=EntraAuth(self.store, EntraConfig()),
                       controller_certificate=self.pki / "controller.pem",
                       controller_private_key=self.pki / "controller-key.pem")
        self.transport = []
        endpoint_identity = self.app.endpoint_identity

        def observe_transport(connection, headers):
            identity = endpoint_identity(connection, headers)
            self.transport.append({"peer": connection.getpeername()[0], "identity": identity,
                                   "header_identity": headers.get("X-Agent-ID")})
            return identity

        self.app.endpoint_identity = observe_transport
        server_tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_tls.minimum_version = ssl.TLSVersion.TLSv1_2
        server_tls.load_cert_chain(self.pki / "controller.pem", self.pki / "controller-key.pem")
        server_tls.load_verify_locations(self.pki / "ca.pem")
        server_tls.verify_mode = ssl.CERT_OPTIONAL
        self.port = self.resources.enter_context(running(self.app, server_tls))

    def dashboard(self, method, path, payload=None):
        return request(self.port, method, "/api/v1/" + path, payload, self.admin_headers, self.browser)

    def enroll(self, hostname, reservation_id=None):
        body = {"name": "NAT fixture " + hostname}
        if reservation_id:
            body["server_id"] = reservation_id
        status, token, _ = self.dashboard("POST", "enrollment-tokens", body)
        self.assertEqual(status, 201)
        key, csr, certificate = [self.root / (hostname + suffix) for suffix in (".key", ".csr", ".pem")]
        subprocess.run(["openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key),
                        "-out", str(csr), "-subj", "/CN=untrusted-csr-name"], check=True, capture_output=True)
        status, enrollment, _ = request(self.port, "POST", "/api/v1/agent/enroll",
            {"token": token["token"], "hostname": hostname, "csr": csr.read_text()}, context=self.browser)
        self.assertEqual(status, 201)
        certificate.write_text(enrollment["certificate"])
        context = ssl.create_default_context(cafile=str(self.pki / "ca.pem"))
        context.load_cert_chain(certificate, key)
        return enrollment["server_id"], context

    @staticmethod
    def spoofed_headers(identity):
        return {"X-Agent-ID": identity, "X-Forwarded-For": "198.51.100.71, 198.51.100.72",
                "X-Real-IP": "198.51.100.73", "Forwarded": "for=198.51.100.74;proto=https"}

    def report(self, identifier, context, hostname, ips, spoof_identity):
        status, result, _ = request(self.port, "POST", "/api/v1/agent/report",
            {"hostname": hostname, "ips": ips, "firewalld_state": "running", "agent_version": "0.5.0",
             "listeners": [{"port": 443, "protocol": "tcp", "address": "0.0.0.0", "service": "https"}],
             "capabilities": ["learning_discovery_v1", "agent_polling_config_v1"]},
            self.spoofed_headers(spoof_identity), context)
        self.assertEqual(status, 200, result)
        self.assertEqual(result["server_id"], identifier)

    def visible_server(self, identifier):
        status, record, _ = self.dashboard("GET", "servers/" + identifier)
        self.assertEqual(status, 200)
        for path, field in (("servers", "items"), ("overview", "servers")):
            status, body, _ = self.dashboard("GET", path)
            self.assertEqual(status, 200)
            listed = next(row for row in body[field] if row["id"] == identifier)
            self.assertEqual(listed["ips"], record["ips"])
        return record

    def test_certificate_identity_and_reported_addresses_win_over_nat_peer_and_proxy_headers(self):
        first, first_tls = self.enroll("nat-endpoint-a")
        second, second_tls = self.enroll("nat-endpoint-b")
        self.report(first, first_tls, "nat-endpoint-a", ["10.243.5.21", "2001:db8:5::21"], second)
        self.assertEqual(self.visible_server(first)["ips"], ["10.243.5.21", "2001:db8:5::21"])
        self.assertEqual(self.visible_server(second)["ips"], [])
        self.report(second, second_tls, "nat-endpoint-b", ["10.244.8.40"], first)
        self.assertEqual(self.visible_server(second)["ips"], ["10.244.8.40"])
        self.report(first, first_tls, "nat-endpoint-a", ["10.243.5.99"], second)
        self.assertEqual(self.visible_server(first)["ips"], ["10.243.5.99"])
        # Removing all agent-reported addresses cannot reveal an LB, stale
        # inventory value or the controller-side TCP peer as a live address.
        self.report(first, first_tls, "nat-endpoint-a", [], second)
        self.assertEqual(self.visible_server(first)["ips"], [])
        status, policy, _ = request(self.port, "GET", "/api/v1/agent/policy",
                                   headers=self.spoofed_headers(second), context=first_tls)
        self.assertEqual(status, 200)
        self.assertEqual(policy["server_id"], first)
        self.assertEqual(request(self.port, "GET", "/api/v1/agent/policy",
                                 headers=self.spoofed_headers(first), context=self.browser)[0], 403)
        self.assertEqual({row["peer"] for row in self.transport}, {"127.0.0.1"})
        self.assertTrue(any(row["identity"] == first and row["header_identity"] == second for row in self.transport))
        self.assertEqual({row["id"] for row in self.store.servers()}, {first, second})

    def test_observed_flow_source_survives_different_controller_peer_and_identity_headers(self):
        first, first_tls = self.enroll("flow-endpoint-a")
        second, second_tls = self.enroll("flow-endpoint-b")
        self.report(first, first_tls, "flow-endpoint-a", ["10.243.6.21"], second)
        self.report(second, second_tls, "flow-endpoint-b", ["10.244.6.22"], first)
        status, session, _ = self.dashboard("POST", "learning", {"server_ids": [first],
            "selection_mode": "manual", "policy_action": "observe", "ports": [{"port": 443, "protocol": "tcp"}],
            "duration_seconds": 120})
        self.assertEqual(status, 201)
        batch = {"batch_id": "nat-source-proof", "session_id": session["id"], "events": [{"source_ip": "10.80.20.44",
            "port": 443, "protocol": "tcp", "verdict": "observed", "count": 7,
            "first_seen": session["starts_at"], "last_seen": session["starts_at"]}]}
        # A certificate from another host cannot upload by spoofing this host's
        # header, while the assigned certificate works with the opposite header.
        self.assertEqual(request(self.port, "POST", "/api/v1/agent/flows", batch,
                                 self.spoofed_headers(first), second_tls)[0], 403)
        self.assertEqual(request(self.port, "POST", "/api/v1/agent/flows", batch,
                                 self.spoofed_headers(second), first_tls)[0], 202)
        self.store.process_flows()
        status, flows, _ = self.dashboard("GET", "flows?server_id=" + first)
        self.assertEqual(status, 200)
        self.assertEqual([(row["server_id"], row["source_ip"], row["port"], row["protocol"], row["count"])
                          for row in flows["items"]], [(first, "10.80.20.44", 443, "tcp", 7)])
        status, evidence, _ = self.dashboard("GET", "learning/" + session["id"] + "/recommendations")
        self.assertEqual(status, 200)
        self.assertEqual([(row["server_id"], row["source_ip"], row["source_cidr"])
                          for row in evidence["rows"]], [(first, "10.80.20.44", "10.80.20.44/32")])
        self.assertEqual({row["peer"] for row in self.transport}, {"127.0.0.1"})
        self.assertEqual(self.visible_server(first)["ips"], ["10.243.6.21"])

    def test_dashboard_cannot_override_agent_ips_and_planning_remains_unverified_through_enrollment(self):
        identifier, context = self.enroll("immutable-agent-addresses")
        self.report(identifier, context, "immutable-agent-addresses", ["10.243.9.11"], "forged-header")
        status, record, _ = self.dashboard("PATCH", "servers/" + identifier,
            {"ips": ["198.51.100.99"], "planned_ips": ["198.51.100.98"], "peer_ip": "198.51.100.97"})
        self.assertIn(status, (200, 400))
        self.assertEqual(self.visible_server(identifier)["ips"], ["10.243.9.11"])
        status, reservation, _ = self.dashboard("POST", "servers", {"hostname": "planned-nat-host", "ips": ["10.250.50.10"]})
        self.assertEqual(status, 201)
        self.assertEqual(reservation["ips"], [])
        self.assertEqual(reservation["planned_ips"], ["10.250.50.10"])
        self.assertEqual(reservation["address_status"], "planned_unverified")
        status, listing, _ = self.dashboard("GET", "server-reservations")
        self.assertEqual(status, 200)
        self.assertEqual(listing["items"][0]["ips"], [])
        self.assertEqual(listing["items"][0]["planned_ips"], ["10.250.50.10"])
        self.assertNotIn(reservation["id"], {row["id"] for row in self.dashboard("GET", "servers")[1]["items"]})
        enrolled, enrolled_tls = self.enroll("planned-nat-host", reservation["id"])
        self.assertEqual(enrolled, reservation["id"])
        self.assertEqual(self.visible_server(enrolled)["ips"], [])
        self.report(enrolled, enrolled_tls, "planned-nat-host", ["10.243.9.41"], identifier)
        self.assertEqual(self.visible_server(enrolled)["ips"], ["10.243.9.41"])
        self.assertEqual(self.dashboard("GET", "server-reservations")[1]["items"], [])


if __name__ == "__main__":
    unittest.main()
