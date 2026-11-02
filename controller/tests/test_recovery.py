"""Actual SQLite files, crypto, live session rows; only process actuator is fake."""
import copy
from datetime import timedelta
import hashlib
import os
from pathlib import Path
import secrets
import sqlite3
import tempfile
import types
import unittest
from unittest.mock import patch

from controller import maintenance, recovery
from controller.auth import EntraAuth, EntraConfig, SESSION_COOKIE
from controller.firewall import WorkflowConflict
from controller.platform import PlatformManager, _read_json
from controller.platform_runtime import FENCE_NAME, RuntimeSafetyError
from controller.store import Store, now, stamp


class Child:
    def poll(self):
        return None


class Supervisor:
    def __init__(self, manager):
        self.manager, self.source_dir = manager, manager.data_dir
        self.arguments, self.child, self.starts = [], Child(), []
        self.stops, self.stop_verified = 0, True
        self.probe = lambda arguments, profile: True

    def stop(self, child):
        self.stops += 1
        return self.stop_verified

    def start_child(self, profile):
        recovery.assert_start_allowed(self.manager, profile)
        environment = recovery.child_environment(self.manager)
        if profile is None:
            # A stale/unsupervised process cannot enter the replacement pair.
            with self.assert_raises(RuntimeSafetyError):
                Store(self.source_dir)
            with patch.dict(os.environ, environment):
                actual = Store(self.source_dir)
                self.starts.append(actual.get("servers", "target"))
        self.child = Child()
        return []

    @staticmethod
    def assert_raises(error):
        return unittest.TestCase().assertRaises(error)


class SQLiteRecoveryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Isolated recovery fixture")])
        certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now() - timedelta(minutes=2)).not_valid_after(now() + timedelta(days=30)).add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).sign(key, hashes.SHA256()))
        cls.pem = certificate.public_bytes(serialization.Encoding.PEM)
        cls.key = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        leaf_key = ec.generate_private_key(ec.SECP256R1())
        leaf = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])).issuer_name(name).public_key(leaf_key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now() - timedelta(minutes=2)).not_valid_after(now() + timedelta(days=10)).add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True).add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False).add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False).sign(key, hashes.SHA256()))
        cls.leaf = leaf.public_bytes(serialization.Encoding.PEM)
        cls.leaf_key = leaf_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.store = Store(self.directory)
        pki = self.directory / "pki"
        pki.mkdir(mode=0o700)
        for name, value in (("ca.pem", self.pem), ("ca-key.pem", self.key), ("controller.pem", self.leaf), ("controller-key.pem", self.leaf_key)):
            (pki / name).write_bytes(value)
            (pki / name).chmod(0o600)
        self.manager = PlatformManager(self.directory)
        app = types.SimpleNamespace(store=self.store, demo=False, controller_id="node-a", site="site-a", controller_certificate=pki / "controller.pem", controller_private_key=pki / "controller-key.pem", signer=types.SimpleNamespace(ca=pki / "ca.pem", ca_key=pki / "ca-key.pem"))
        self.manager.attach(app)
        self.config = EntraConfig(tenant_id="11111111-1111-1111-1111-111111111111", client_id="22222222-2222-2222-2222-222222222222", redirect_uri="https://controller.test/api/v1/auth/callback", client_secret="private recovery identity fixture")
        self.auth = EntraAuth(self.store, self.config, provider=object())
        self.store.approval_tenant_id, self.store.approval_auth_fingerprint = self.config.tenant_id, self.config.fingerprint
        self.maker = self.person("33333333-3333-3333-3333-333333333333")
        self.checker = self.person("44444444-4444-4444-4444-444444444444")
        self.store.report("target", {"hostname": "target", "ips": ["10.0.0.10"], "listeners": []})
        self.original = self.store.save_policy({"name": "Archived desired intent", "selector": {}, "mode": "enforce", "services": [{"port": 443, "sources": ["10.0.1.1/32"]}]}, self.maker["actor"])
        self.backup = maintenance.backup_create(self.store, self.maker["actor"])
        self.changed = self.store.save_policy({**self.original, "name": "Current desired intent", "services": [{"port": 443, "sources": ["10.0.1.2/32"]}]}, self.maker["actor"], self.original["id"])
        self.highwater = self.store.assignment("target")[0]["version"]

    def person(self, oid, role="super_admin"):
        identity, raw = self.config.tenant_id + ":" + oid, secrets.token_urlsafe(32)
        with self.store.meta() as db:
            self.store._put(db, "auth_users", {"id": identity, "tenant_id": self.config.tenant_id, "object_id": oid, "enabled": True, "role": role, "display_name": "Recovery reviewer"})
            self.store._put(db, "auth_sessions", {"id": hashlib.sha256(raw.encode()).hexdigest(), "user_id": identity, "expires_at": stamp(now() + timedelta(hours=1)), "config": self.config.fingerprint})
        return self.auth.authenticate({"Cookie": SESSION_COOKIE + "=" + raw})

    def plan(self):
        return recovery.preview(self.manager, {"backup_id": self.backup["id"], "reason": "Restore isolated verified business intent"}, self.maker["actor"], self.maker)

    def submit(self, plan):
        return recovery.confirm(self.manager, {"preview_id": plan["id"], "digest": plan["digest"], "confirmation_nonce": plan["confirmation_nonce"]}, self.maker["actor"], self.maker)["preview"]

    def approve(self, plan):
        return recovery.confirm(self.manager, {"preview_id": plan["id"], "digest": plan["digest"], "confirmation_nonce": plan["confirmation_nonce"], "challenge": plan["confirmation_phrase"]}, self.maker["actor"], self.maker)

    def queued(self):
        return self.approve(self.submit(self.plan()))["job"]["id"]

    def test_pending_port_change_blocks_recovery_preview_and_final_approval(self):
        def port_state(status):
            with self.store.meta() as db:
                self.store._put(db, 'maintenance_settings', {'id': 'application_port:another-controller', 'job_id': 'port-operation', 'status': status})
        port_state('pending')
        with self.assertRaises(recovery.RecoveryBusy):
            self.plan()
        port_state('applied')
        plan = self.submit(self.plan())
        port_state('pending')
        with self.assertRaises(recovery.RecoveryBusy):
            self.approve(plan)
        with self.assertRaises(KeyError):
            self.store.get('maintenance_settings', recovery.CONTROL_ID)
        port_state('rolled_back')
        self.assertEqual(self.approve(plan)['job']['operation'], 'recovery')

    def test_live_super_admin_two_same_actor_confirmations_and_exact_review_required(self):
        admin = self.person("55555555-5555-5555-5555-555555555555", "admin")
        with self.assertRaises(PermissionError):
            recovery.preview(self.manager, {"backup_id": self.backup["id"], "reason": "Insufficient privileged identity"}, admin["actor"], admin)
        with self.assertRaises(PermissionError):
            recovery.preview(self.manager, {"backup_id": self.backup["id"], "reason": "A shared token is not a person"}, "legacy-token:super_admin", {"auth_type": "token"})
        plan = self.submit(self.plan())
        request = {"preview_id": plan["id"], "digest": plan["digest"], "confirmation_nonce": plan["confirmation_nonce"], "challenge": plan["confirmation_phrase"]}
        with self.assertRaises(PermissionError):
            recovery.confirm(self.manager, request, self.checker["actor"], self.checker)
        with self.assertRaises(WorkflowConflict):
            recovery.confirm(self.manager, {**request, "digest": "0" * 64}, self.checker["actor"], self.checker)
        self.assertEqual(self.store.get("policies", self.original["id"])["name"], "Current desired intent")

    def test_two_submitted_plans_cannot_replace_active_recovery_owner(self):
        first, second = self.plan(), self.plan()
        first, second = self.submit(first), self.submit(second)
        self.approve(first)
        with self.assertRaises(WorkflowConflict):
            self.approve(second)
        self.assertEqual(self.store.get("maintenance_settings", recovery.CONTROL_ID)["recovery_id"], first["id"])

    def test_actual_sqlite_restore_retains_history_and_never_claims_endpoint_applied(self):
        with self.store.meta() as db:
            self.store._put(db, 'maintenance_settings', {'id': 'assignment_guard:target', 'generation': 900, 'digest': '0' * 64})
        identifier = self.queued()
        supervisor = Supervisor(self.manager)
        self.assertFalse(recovery.supervisor_tick(supervisor))
        restored = Store(self.directory)
        self.assertEqual(restored.get("policies", self.original["id"])["name"], "Archived desired intent")
        assignment = restored.assignment("target")[0]
        self.assertGreater(assignment['assignment_generation'], 900)
        self.assertGreater(assignment["version"], self.highwater)
        self.assertFalse(assignment["enforcement"]["authorized"])
        self.assertEqual(restored.get("servers", "target")["apply_status"], "pending")
        self.assertEqual(restored.all("auth_sessions"), [])
        self.assertEqual(restored.all("auth_states"), [])
        self.assertEqual(restored.get("maintenance_backups", self.backup["id"])["id"], self.backup["id"])
        record = _read_json(recovery._directory(self.manager, identifier) / "control.json")
        self.assertEqual(record["phase"], "completed")
        self.assertTrue((self.directory / record["original_snapshot"] / "inventory.sqlite3").is_file())
        self.assertTrue((recovery._directory(self.manager, identifier) / "protected-material" / "issuer_key.pem").is_file())
        self.assertFalse((self.directory / FENCE_NAME).exists())
        self.assertFalse((self.manager.root / recovery.LOCAL_FENCE).exists())
        public = json_text = str(self.manager.job(identifier))
        self.assertNotIn("writer_nonce", public)
        self.assertNotIn("BEGIN PRIVATE KEY", json_text)

    def test_restore_rebuilds_endpoint_learning_index_without_restarting_capture(self):
        with self.store.meta() as db:
            self.store._put(db, "sessions", {"id":"restore-active-scope", "server_ids":["target"], "status":"active",
                "selection_mode":"manual", "policy_action":"observe", "ports":[{"port":443,"protocol":"tcp"}],
                "starts_at":stamp(now()-timedelta(minutes=1)), "expires_at":stamp(now()+timedelta(hours=1))})
        self.backup = maintenance.backup_create(self.store,self.maker["actor"])
        self.queued()
        self.assertFalse(recovery.supervisor_tick(Supervisor(self.manager)))
        restored = Store(self.directory)
        self.assertEqual(restored.get("sessions","restore-active-scope")["status"],"stopped")
        assignment = restored.assignment("target")[0]
        self.assertEqual(assignment["learning_sessions"],[])
        self.assertEqual([scope["id"] for scope in assignment["learning_tombstones"]],["restore-active-scope"])
        with restored.read_meta() as db:
            self.assertEqual(db.execute("SELECT status FROM learning_session_targets WHERE session_id=?",("restore-active-scope",)).fetchone()[0],"stopped")

    def test_revocations_disabled_users_retired_and_new_identities_are_high_water(self):
        disabled = self.person("55555555-5555-5555-5555-555555555555")
        with self.store.meta() as db:
            row = self.store._get(db, "auth_users", disabled["user"]["id"])
            row["enabled"] = False
            self.store._put(db, "auth_users", row)
            self.store._put(db, "maintenance_settings", {"id": "endpoint_certificate:current", "server_id": "target", "status": "revoked"})
            self.store._put(db, "tokens", {"id": "unused", "used": False})
            self.store._put(db, "tokens", {"id": "used", "used": True, "csr_hash": "original-bound-key"})
            self.store._put(db, "maintenance_settings", {"id": "endpoint_recovery:unused", "used": False})
        self.store.report("newer", {"hostname": "newer", "ips": ["10.0.0.11"], "listeners": []})
        with self.store.meta() as db:
            self.store._put(db, "retired_endpoints", {"id": "target", "server_id": "target", "retired_at": stamp()})
            db.execute("DELETE FROM servers WHERE id='target'")
        self.queued()
        supervisor = Supervisor(self.manager)
        # This test intentionally retires the ordinary fixture target.
        supervisor.start_child = lambda profile: self.start_without_target(supervisor, profile)
        self.assertFalse(recovery.supervisor_tick(supervisor))
        restored = Store(self.directory)
        self.assertIsNone(self.store._get(sqlite3.connect(restored.meta_path), "servers", "target"))
        self.assertFalse(restored.get("auth_users", disabled["user"]["id"])["enabled"])
        self.assertEqual(restored.get("maintenance_settings", "endpoint_certificate:current")["status"], "revoked")
        self.assertEqual([value["id"] for value in restored.all("tokens")], ["used"])
        newer = restored.get("servers", "newer")
        self.assertEqual(newer["tags"], {})
        self.assertEqual(newer["ips"], ["10.0.0.11"])
        restored.evaluate_health()
        self.assertEqual(restored.get('servers', 'newer')['service_health_status'], 'unknown')
        self.assertNotEqual(restored.get('servers', 'newer')['status'], 'healthy')
        self.assertIsNone(restored._get(sqlite3.connect(restored.meta_path), "maintenance_settings", "endpoint_recovery:unused"))

    def start_without_target(self, supervisor, profile):
        recovery.assert_start_allowed(self.manager, profile)
        with patch.dict(os.environ, recovery.child_environment(self.manager)):
            Store(self.directory)
        supervisor.child = Child()
        return []

    def test_unverified_drain_never_replaces_and_keeps_old_writers_fenced(self):
        identifier = self.queued()
        supervisor = Supervisor(self.manager)
        supervisor.stop_verified = False
        self.assertTrue(recovery.supervisor_tick(supervisor))
        with self.assertRaises(RuntimeSafetyError):
            Store(self.directory)
        with sqlite3.connect(self.store.meta_path) as db:
            self.assertEqual(Store._get(db, "policies", self.original["id"])["name"], "Current desired intent")
        self.assertEqual(self.manager.job(identifier)["status"], "blocked")
        self.assertEqual(supervisor.starts, [])

    def test_corrupt_archive_is_rejected_before_any_writer_is_stopped(self):
        identifier = self.queued()
        (self.manager.root / "backups" / (self.backup["id"] + ".zip")).write_bytes(b"changed archive")
        supervisor = Supervisor(self.manager)
        self.assertFalse(recovery.supervisor_tick(supervisor))
        self.assertEqual(supervisor.stops, 0)
        self.assertFalse((self.directory / FENCE_NAME).exists())
        self.assertEqual(self.manager.job(identifier)["phase"], "cancelled")
        self.assertEqual(self.store.get("policies", self.original["id"])["name"], "Current desired intent")

    def test_changed_issuer_key_or_revoked_approver_cancels_before_fence(self):
        self.queued()
        with self.store.meta() as db:
            checker = self.store._get(db, "auth_users", self.maker["user"]["id"])
            checker["role"] = "admin"
            self.store._put(db, "auth_users", checker)
        supervisor = Supervisor(self.manager)
        self.assertFalse(recovery.supervisor_tick(supervisor))
        self.assertEqual(supervisor.stops, 0)
        self.assertFalse((self.directory / FENCE_NAME).exists())

    def test_external_signing_key_change_invalidates_recovery_before_stop(self):
        key = self.directory / 'separate-signing.seed'
        key.write_bytes(secrets.token_bytes(32))
        key.chmod(0o600)
        with patch.dict(os.environ, {'SEG_POLICY_SIGNING_KEY_FILE': str(key), 'SEG_POLICY_SIGNING_DEPLOYMENT_ID': '77777777-7777-7777-7777-777777777777'}):
            self.queued()
            key.write_bytes(secrets.token_bytes(32))
            supervisor = Supervisor(self.manager)
            self.assertFalse(recovery.supervisor_tick(supervisor))
            self.assertEqual(supervisor.stops, 0)
            self.assertFalse((self.directory / FENCE_NAME).exists())

    def test_crash_between_pair_replacements_replays_exact_candidates(self):
        identifier = self.queued()
        supervisor = Supervisor(self.manager)
        original_replace = os.replace
        failed = False

        def replace(source, target):
            nonlocal failed
            if str(source).endswith("-traffic.sqlite3") and not failed:
                failed = True
                raise OSError("isolated power-loss fixture")
            return original_replace(source, target)

        with patch("controller.recovery.os.replace", replace):
            self.assertTrue(recovery.supervisor_tick(supervisor))
        self.assertTrue((self.directory / FENCE_NAME).exists())
        self.assertEqual(_read_json(recovery._directory(self.manager, identifier) / "control.json")["phase"], "replacing")
        self.assertFalse(recovery.supervisor_tick(supervisor))
        self.assertEqual(Store(self.directory).get("policies", self.original["id"])["name"], "Archived desired intent")

    def test_crash_after_fence_before_drain_publication_resumes_same_owner(self):
        identifier = self.queued()
        supervisor = Supervisor(self.manager)
        save = recovery._local_save

        def crash(manager, record):
            if record['phase'] == 'draining':
                raise SystemExit('isolated abrupt parent-exit fixture')
            return save(manager, record)

        with patch('controller.recovery._local_save', crash):
            with self.assertRaises(SystemExit):
                recovery.supervisor_tick(supervisor)
        self.assertEqual(_read_json(recovery._directory(self.manager, identifier) / 'control.json')['phase'], 'queued')
        self.assertEqual(_read_json(self.directory / FENCE_NAME)['state'], 'RECOVERING')
        self.assertFalse(recovery.supervisor_tick(supervisor))
        self.assertEqual(Store(self.directory).get('policies', self.original['id'])['name'], 'Archived desired intent')

    def test_missing_remote_profile_cannot_turn_retired_sqlite_into_fallback(self):
        self.queued()
        from controller.platform_runtime import atomic_private_json
        atomic_private_json(self.directory / FENCE_NAME, {'state': 'RETIRED', 'deployment_id': 'another-managed-deployment'})
        # A persisted pending record must not overwrite a retirement fence.
        with sqlite3.connect(self.store.meta_path) as db:
            record = Store._get(db, 'maintenance_settings', recovery.CONTROL_ID)
        recovery._local_save(self.manager, record)
        self.assertTrue(recovery.supervisor_tick(Supervisor(self.manager)))
        self.assertEqual(_read_json(self.directory / FENCE_NAME)['state'], 'RETIRED')

    def test_unknown_immutable_history_conflict_fails_closed(self):
        with self.store.meta() as db:
            safety = recovery._safety(db)
        rows = safety["bundle_history"]
        altered = copy.deepcopy(rows)
        parsed = __import__("json").loads(altered[0][-1])
        parsed["digest"] = "conflicting immutable identity"
        altered[0][-1] = __import__("json").dumps(parsed)
        with self.store.meta() as db:
            with self.assertRaises(recovery.RecoveryError):
                recovery._merge_immutable(db, "bundle_history", altered)

    def test_private_ready_uses_committed_corporate_name_over_old_db_profile(self):
        supervisor = Supervisor(self.manager)
        with patch("controller.platform_runtime.probe_readiness", return_value=True) as actual:
            supervisor.probe = actual
            with patch.object(self.manager, "launch_tls", return_value={"hostname": "current.example.test"}):
                self.assertTrue(recovery._wait_ready(supervisor, [], {"controller_server_name": "10.90.0.1"}, "a" * 64))
            self.assertEqual(actual.call_args.kwargs["tls_hostname"], "current.example.test")
            self.assertEqual(actual.call_args.kwargs["recovery_nonce"], "a" * 64)


if __name__ == "__main__":
    unittest.main()
