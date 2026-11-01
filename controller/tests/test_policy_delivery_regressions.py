"""Small adversarial delivery checks; no fleet load, real DC or firewall changes.

Two Store/App objects model independent workers against owned temporary SQLite
storage. HTTPS checks use real registered mTLS leaves and existing keep-alive
connections so conditional replies cannot bypass current certificate admission.
"""
from datetime import timedelta
import hashlib
import http.client
import json
from pathlib import Path
import secrets
import ssl
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from controller import agent_settings, endpoint_certificates, managed, server_management
from controller.app import App, Server
from controller.auth import EntraAuth, EntraConfig, SESSION_COOKIE
from controller.pki import Signer, init_ca
from controller.policy_signing import verify
from controller.store import Store, digest, now, parse_time, stamp


def heartbeat(identifier="target"):
    return {"hostname": identifier, "ips": ["192.0.2.10"], "listeners": [],
            "firewalld_state": "running", "discovery_performed": False,
            "capabilities": ["signed_assignments_v1", "agent_polling_config_v1"]}


class PolicyDeliveryRegressionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="prthak-delivery-unit-")
        self.addCleanup(temporary.cleanup)
        self.store = Store(temporary.name)
        self.peer = Store(temporary.name)
        self.store.report("target", heartbeat())

    def policy(self, sources, identifier=None):
        return self.store.save_policy({"name": "Exact delivery fixture", "selector": {}, "mode": "monitor",
            "services": [{"port": 8443, "protocol": "tcp", "sources": sources}]}, "fixture", identifier)

    def _interleave_report(self, control):
        """Allow a control writer during a stale read, or serialize it safely."""
        assembled, release, control_done = threading.Event(), threading.Event(), threading.Event()
        original_get = self.peer._get
        paused, errors = [], []

        def delayed_read(db, table, identifier):
            result = original_get(db, table, identifier)
            if table == "servers" and identifier == "target" and not paused:
                paused.append(True)
                assembled.set()
                if not release.wait(8):
                    raise AssertionError("Fixture did not release report")
            return result

        def report():
            try:
                self.peer.report("target", heartbeat())
            except Exception as error:
                errors.append(error)

        def change():
            try:
                control()
            except Exception as error:
                errors.append(error)
            finally:
                control_done.set()

        with patch.object(self.peer, "_get", side_effect=delayed_read):
            reporter = threading.Thread(target=report)
            reporter.start()
            self.assertTrue(assembled.wait(5))
            writer = threading.Thread(target=change)
            writer.start()
            # A safe BEGIN IMMEDIATE report holds the writer. The old deferred
            # report lets this complete, exposing its stale whole-row overwrite.
            control_done.wait(0.5)
            release.set()
            reporter.join(10)
            writer.join(10)
            self.assertFalse(reporter.is_alive())
            self.assertFalse(writer.is_alive())
        self.assertEqual(errors, [])

    def test_report_cannot_erase_concurrent_metadata_or_new_compiled_policy(self):
        def change():
            self.store.update_server("target", {"tags": {"application": "billing"}}, "fixture")
            self.policy(["192.0.2.88/32"])

        self._interleave_report(change)
        current = self.store.assignment("target")[0]
        self.assertEqual(self.store.get("servers", "target")["tags"], {"application": "billing"})
        self.assertEqual(current["services"][0]["sources"], ["192.0.2.88/32"])
        self.assertEqual(current["version"], 2)

    def test_report_cannot_resurrect_an_endpoint_retired_by_another_store(self):
        plan = server_management.delete_preview(self.store, "target", "fixture")
        self.assertTrue(plan["can_delete"], plan["blockers"])

        def retire():
            result = server_management.delete_confirm(self.store, "target", {
                "plan_id": plan["id"], "confirmation_nonce": plan["confirmation_nonce"]}, "fixture")
            self.assertEqual(result["status"], "applied")

        self._interleave_report(retire)
        with self.store.read_meta() as db:
            self.assertIsNone(self.store._get(db, "servers", "target"))
            self.assertIsNotNone(self.store._get(db, "retired_endpoints", "target"))
        with self.assertRaises(PermissionError):
            self.peer.report("target", heartbeat())

    def test_midrun_policy_edit_reaches_warm_peer_despite_old_preview_receipt(self):
        policy = self.policy(["192.0.2.41/32"])
        old, old_etag = self.peer.assignment("target")
        self.assertEqual(self.peer.assignment("target"), (old, old_etag))
        self.policy(["192.0.2.42/32"], policy["id"])
        self.peer.report("target", {**heartbeat(), "managed_enforcement": {
            "status": "preview", "version": old["version"], "digest": old["digest"],
            "last_good_version": 0, "last_good_digest": "", "updated_at": stamp()}})
        current, current_etag = self.peer.assignment("target")
        self.assertGreater(current["version"], old["version"])
        self.assertGreater(current["assignment_generation"], old["assignment_generation"])
        self.assertNotEqual(current_etag, old_etag)
        self.assertEqual(current["services"][0]["sources"], ["192.0.2.42/32"])
        self.assertEqual(self.store.assignment("target"), (current, current_etag))

    def test_warm_peer_recomputes_polling_after_group_and_tag_changes(self):
        group = self.store.save_group({"name": "Billing scope", "type": "dynamic",
            "selector": {"application": "billing"}}, "fixture")
        agent_settings.save(self.store, {"expected_revision": 0,
            "defaults": {"control_interval_seconds": 60, "discovery_interval_seconds": 900},
            "rules": [{"id": "billing", "name": "Billing faster", "group_ids": [group["id"]],
                "control_interval_seconds": 5, "discovery_interval_seconds": 120}]}, "fixture")
        before = self.peer.assignment("target")[0]
        self.store.update_server("target", {"tags": {"application": "billing"}}, "fixture")
        tagged = self.peer.assignment("target")[0]
        self.assertEqual(tagged["version"], before["version"])
        self.assertEqual(tagged["polling_settings"]["control_interval_seconds"], 5)
        self.assertGreater(tagged["assignment_generation"], before["assignment_generation"])
        self.store.save_group({"name": "Payments scope", "type": "dynamic",
            "selector": {"application": "payments"}}, "fixture", group["id"])
        regrouped = self.peer.assignment("target")[0]
        self.assertEqual(regrouped["polling_settings"]["control_interval_seconds"], 60)
        self.assertGreater(regrouped["assignment_generation"], tagged["assignment_generation"])

    def test_session_clock_edges_advance_assignment_without_intent_mutation(self):
        at = now().replace(microsecond=0)
        session = {"id": "time-edge", "server_ids": ["target"], "ports": [{"port": 8443, "protocol": "tcp"}],
            "selection_mode": "manual", "policy_action": "observe", "status": "active",
            "starts_at": stamp(at + timedelta(seconds=10)), "expires_at": stamp(at + timedelta(seconds=20))}
        with self.store.meta() as db:
            self.store._put(db, "sessions", session)
        values = []
        for seconds in (0, 10, 20, 321):
            with patch("controller.store.now", return_value=at + timedelta(seconds=seconds)):
                values.append(self.peer.assignment("target")[0])
        self.assertEqual(values[0]["learning_sessions"], [])
        self.assertEqual([item["id"] for item in values[1]["learning_sessions"]], ["time-edge"])
        self.assertEqual(values[2]["learning_sessions"], [])
        self.assertEqual(values[2]["learning_tombstones"][0]["status"], "expired")
        self.assertEqual(values[3]["learning_tombstones"], [])
        self.assertEqual([item["assignment_generation"] for item in values], sorted({item["assignment_generation"] for item in values}))
        self.assertEqual(len({item["version"] for item in values}), 1)

    def test_current_checker_disable_and_approval_expiry_revoke_warm_delivery(self):
        config = EntraConfig("11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222",
            "https://controller.example/api/v1/auth/callback", "isolated-fixture-secret")
        auth = EntraAuth(self.store, config, provider=object())
        for store in (self.store, self.peer):
            store.approval_tenant_id = config.tenant_id
            store.approval_auth_fingerprint = config.fingerprint

        def person(oid):
            identifier = config.tenant_id + ":" + oid
            raw = secrets.token_urlsafe(32)
            with self.store.meta() as db:
                self.store._put(db, "auth_users", {"id": identifier, "tenant_id": config.tenant_id,
                    "object_id": oid, "role": "admin", "enabled": True})
                self.store._put(db, "auth_sessions", {"id": hashlib.sha256(raw.encode()).hexdigest(),
                    "user_id": identifier, "expires_at": stamp(now() + timedelta(hours=8)), "config": config.fingerprint})
            return auth.authenticate({"Cookie": SESSION_COOKIE + "=" + raw})

        maker, checker = person("33333333-3333-3333-3333-333333333333"), person("44444444-4444-4444-4444-444444444444")
        baseline = {"management_sources": ["192.0.2.0/24"], "ssh_ports": [2022],
            "controller_url": "https://controller.example", "management_probe_url": "https://controller.example/api/v1/agent/enforcement/check", "zone": "public"}
        self.store.report("target", {**heartbeat(), "protection": {**baseline, "digest": digest(baseline), "ready": True, "blockers": []}})
        self.store.save_policy({"name": "Approved delivery", "selector": {}, "mode": "enforce",
            "services": [{"port": 8443, "sources": ["192.0.2.42/32"]}]}, maker["actor"])
        plan = managed.rollout(self.store, {"name": "Exact live people", "server_ids": ["target"]}, maker["actor"], principal=maker)
        approved = self.peer.assignment("target")[0]
        self.assertTrue(approved["enforcement"]["authorized"])
        with self.store.meta() as db:
            user = self.store._get(db, "auth_users", maker["user"]["id"])
            self.store._put(db, "auth_users", {**user, "enabled": False})
        disabled = self.peer.assignment("target")[0]
        self.assertFalse(disabled["enforcement"]["authorized"])
        self.assertGreater(disabled["assignment_generation"], approved["assignment_generation"])
        with self.store.meta() as db:
            self.store._put(db, "auth_users", user)
        expiry = parse_time(approved["enforcement"]["expires_at"])
        with patch("controller.managed.now", return_value=expiry), patch("controller.store.now", return_value=expiry):
            expired = self.peer.assignment("target")[0]
        self.assertFalse(expired["enforcement"]["authorized"])


class PolicyDeliveryHTTPSRegressions(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="prthak-delivery-https-")
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        pki = init_ca(root)
        self.store, self.peer = Store(root / "state"), Store(root / "state")
        self.store.report("target", heartbeat())
        # Keep unrelated five-minute boundaries from making a legitimate
        # refreshed signature race an assertion about unchanged conditional GET.
        clock = patch("controller.policy_signing.time.time", return_value=int(time.time()) // 300 * 300 + 10)
        clock.start()
        self.addCleanup(clock.stop)
        signer = Signer(pki / "ca.pem", pki / "ca-key.pem")
        key = ec.generate_private_key(ec.SECP256R1())
        ca = x509.load_pem_x509_certificate(signer.ca.read_bytes())
        ca_key = serialization.load_pem_private_key(signer.ca_key.read_bytes(), None)
        self.leaf = x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "target")])).issuer_name(ca.subject).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now()-timedelta(minutes=1)).not_valid_after(now()+timedelta(days=1)).add_extension(x509.BasicConstraints(ca=False,path_length=None), True).add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),False).sign(ca_key, hashes.SHA256())
        cert_path, key_path = root / "client.pem", root / "client-key.pem"
        cert_path.write_bytes(self.leaf.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        key_path.chmod(0o600)
        with self.store.meta() as db:
            server = self.store._get(db, "servers", "target")
            endpoint_certificates.record_issued(self.store, db, server, cert_path.read_text())
            self.store._put(db, "servers", server)
        self.client_tls = ssl.create_default_context(cafile=str(pki / "ca.pem"))
        self.client_tls.load_cert_chain(cert_path, key_path)
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(pki / "controller.pem", pki / "controller-key.pem")
        tls.load_verify_locations(pki / "ca.pem")
        tls.verify_mode = ssl.CERT_REQUIRED
        self.apps, self.ports = [], []
        for store in (self.store, self.peer):
            app = App(store, signer=signer, controller_id="delivery-fixture",
                controller_certificate=pki / "controller.pem", controller_private_key=pki / "controller-key.pem")
            app.start_jobs = lambda: None
            server = Server(("127.0.0.1", 0), app)
            server.socket = tls.wrap_socket(server.socket, server_side=True)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            self.addCleanup(thread.join, 3)
            self.addCleanup(server.server_close)
            self.addCleanup(server.shutdown)
            self.apps.append(app)
            self.ports.append(server.server_address[1])
        self.trust = self.apps[0].platform.policy_signer().public_trust()

    def connection(self, worker=0):
        connection = http.client.HTTPSConnection("localhost", self.ports[worker], context=self.client_tls, timeout=10)
        self.addCleanup(connection.close)
        return connection

    def poll(self, connection, etag=None):
        connection.request("GET", "/api/v1/agent/policy", headers={"If-None-Match": etag} if etag else {})
        reply = connection.getresponse()
        raw = reply.read()
        return reply.status, json.loads(raw) if raw else None, dict(reply.getheaders())

    def test_actual_policy_edit_invalidates_both_worker_etags_and_returns_exact_sources(self):
        policy = self.store.save_policy({"name": "Before edit", "selector": {}, "mode": "monitor",
            "services": [{"port": 8443, "sources": ["192.0.2.41/32"]}]}, "fixture")
        connections = [self.connection(0), self.connection(1)]
        old = [self.poll(connection) for connection in connections]
        for connection, (status, value, headers) in zip(connections, old):
            self.assertEqual(status, 200)
            verify(value, self.trust)
            self.assertEqual(self.poll(connection, headers["ETag"])[0], 304)
        self.store.save_policy({**policy, "name": "Actually changed midrun",
            "services": [{"port": 8443, "sources": ["192.0.2.42/32", "2001:db8::42/128"]}]}, "fixture", policy["id"])
        for connection, (_, prior, headers) in zip(connections, old):
            status, value, newer = self.poll(connection, headers["ETag"])
            self.assertEqual(status, 200)
            verify(value, self.trust)
            self.assertGreater(value["version"], prior["version"])
            self.assertGreater(value["assignment_generation"], prior["assignment_generation"])
            self.assertEqual(value["services"][0]["sources"], ["192.0.2.42/32", "2001:db8::42/128"])
            self.assertNotEqual(newer["ETag"], headers["ETag"])

    def test_signature_bucket_refreshes_unchanged_assignment_instead_of_stale_304(self):
        connection = self.connection()
        at = int(time.time()) // 300 * 300 + 1
        with patch("controller.policy_signing.time.time", return_value=at):
            status, first, headers = self.poll(connection)
            self.assertEqual(status, 200)
            verify(first, self.trust, at=at)
            self.assertEqual(self.poll(connection, headers["ETag"])[0], 304)
        with patch("controller.policy_signing.time.time", return_value=at+300):
            status, second, newer = self.poll(connection, headers["ETag"])
            self.assertEqual(status, 200)
            verify(second, self.trust, at=at+300)
        self.assertEqual(first["assignment_generation"], second["assignment_generation"])
        self.assertNotEqual(first["signature"], second["signature"])
        self.assertNotEqual(headers["ETag"], newer["ETag"])

    def test_revoked_leaf_is_rejected_before_conditional_reply_on_existing_tls_connection(self):
        connection = self.connection()
        status, _, headers = self.poll(connection)
        self.assertEqual(status, 200)
        self.assertEqual(self.poll(connection, headers["ETag"])[0], 304)
        plan = endpoint_certificates.revoke_preview(self.peer, {"server_id": "target"}, "fixture")
        endpoint_certificates.revoke_apply(self.peer, {"preview_id": plan["id"],
            **{key: plan[key] for key in ("digest", "confirmation_nonce", "confirmation_phrase")}}, "fixture")
        status, value, _ = self.poll(connection, headers["ETag"])
        self.assertEqual(status, 403, value)

    def test_leaf_expiry_is_rechecked_after_tls_handshake_before_conditional_reply(self):
        connection = self.connection()
        status, _, headers = self.poll(connection)
        self.assertEqual(status, 200)
        with patch("controller.endpoint_certificates.now", return_value=self.leaf.not_valid_after_utc):
            status, value, _ = self.poll(connection, headers["ETag"])
        self.assertEqual(status, 403, value)


if __name__ == "__main__":
    unittest.main()
