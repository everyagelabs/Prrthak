import copy
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import tempfile
import types
import unittest
import uuid
from datetime import timedelta

from controller import endpoint_configuration as lifecycle
from controller.auth import EntraAuth, EntraConfig, SESSION_COOKIE
from controller.firewall import WorkflowConflict
from controller.policy_signing import PolicySigner
from controller.store import Store, now, stamp


class EndpointConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = Store(self.temp.name)
        self.config = EntraConfig(tenant_id="11111111-1111-1111-1111-111111111111", client_id="22222222-2222-2222-2222-222222222222", redirect_uri="https://controller.example/api/v1/auth/callback", client_secret="private-fixture")
        self.auth = EntraAuth(self.store, self.config, provider=object())
        self.store.approval_tenant_id = self.config.tenant_id
        self.store.approval_auth_fingerprint = self.config.fingerprint
        self.maker = self.person("33333333-3333-3333-3333-333333333333")
        signer = PolicySigner(self.temp.name + "/signer", str(uuid.uuid4()), create=True)
        self.app = types.SimpleNamespace(demo=False, store=self.store, platform=types.SimpleNamespace(policy_signer=lambda: signer))
        self.current = {"controller_url": "https://controller.example", "control_url": "https://controller.example:8788", "discovery_url": "https://controller.example:8789", **{key: False for key in lifecycle.FLAGS}, "management_sources": [], "protected_ssh_ports": [], "zone": ""}
        self.store.report("target", {"hostname": "target", "ips": ["10.70.0.1"], "firewalld_state": "running", "listeners": [{"port": 2022, "protocol": "tcp", "process": "sshd"}], "capabilities": [lifecycle.CAPABILITY], "configuration_state": {"digest": "b" * 64, **self.current}})
        with self.store.meta() as db:
            lifecycle.initialize(db)
        self.value = {"server_id": "target", "settings": {**self.current, "enforce": True, "management_sources": ["10.90.0.0/24"], "protected_ssh_ports": [2022], "zone": "public"}, "controller_ca_pem": "", "retain_old_origin": False}

    def person(self, oid, role="admin"):
        identifier = self.config.tenant_id + ":" + oid
        raw = secrets.token_urlsafe(32)
        with self.store.meta() as db:
            self.store._put(db, "auth_users", {"id": identifier, "tenant_id": self.config.tenant_id, "object_id": oid, "role": role, "enabled": True, "display_name": "Fixture person"})
            self.store._put(db, "auth_sessions", {"id": hashlib.sha256(raw.encode()).hexdigest(), "user_id": identifier, "expires_at": stamp(now() + timedelta(hours=8)), "config": self.config.fingerprint})
        return self.auth.authenticate({"Cookie": SESSION_COOKIE + "=" + raw})

    def preview(self, value=None, principal=None):
        principal = principal or self.maker
        return lifecycle.preview(self.app, value or self.value, principal["actor"], principal)

    def confirm(self, plan, principal):
        return lifecycle.confirm(self.app, plan["id"], {"plan_digest": plan["plan_digest"], "confirmation": "CONFIGURE " + plan["id"]}, principal["actor"], principal)

    def approved(self):
        return self.preview()

    def test_shared_tokens_and_fake_people_cannot_mint_privileged_review(self):
        with self.assertRaises(PermissionError):
            lifecycle.preview(self.app, self.value, "admin", {"auth_type": "token", "actor": "admin", "role": "super_admin"})
        self.assertEqual(lifecycle.listing(self.app)["items"], [])

    def test_admin_save_immediately_authorizes_exact_signed_kit_without_checker(self):
        plan=self.preview()
        kit=lifecycle.kit(self.app,plan["id"],self.maker["actor"])
        self.assertEqual(plan["status"],"approved")
        proof=kit["manifest"]["approval"]
        self.assertEqual(proof["mode"],"single_admin")
        self.assertEqual(proof["requester"]["user_id"],proof["submitted_by"]["user_id"])
        self.assertEqual(proof["requester"]["user_id"],proof["approved_by"]["user_id"])
        self.assertEqual(proof["scope"],{"kind":"endpoint_configuration","server_ids":["target"]})
        self.assertNotIn("pilot",proof)
        self.assertEqual(kit["manifest"]["scope"]["settings"]["protected_ssh_ports"],[2022])
        self.assertEqual(kit["signature"]["algorithm"],"Ed25519")
        self.assertNotIn("PRIVATE KEY",json.dumps(kit))
        self.assertLessEqual((lifecycle.parse_time(kit["manifest"]["expires_at"])-lifecycle.parse_time(kit["manifest"]["issued_at"])).total_seconds(),900)
        self.assertFalse(self.store.get("servers","target")["configuration_state"]["enforce"])

    def test_management_scope_actual_ssh_and_retained_origins_are_required(self):
        cases = [{"management_sources": []}, {"management_sources": ["0.0.0.0/0"]}, {"protected_ssh_ports": [22]}, {"zone": ""}, {"enforce": "true"}, {"control_url": "http://controller.example"}, {"control_url": "https://new-controller.example"}]
        for change in cases:
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.preview({**self.value, "settings": {**self.value["settings"], **change}})
        migration = {**self.value, "retain_old_origin": True, "settings": {**self.value["settings"], "control_url": "https://new-controller.example"}}
        self.assertTrue(self.preview(migration)["scope"]["retain_old_origin"])

    def test_changed_identity_addresses_or_configuration_invalidates_frozen_review(self):
        plan = self.approved()
        original = self.store.get("servers", "target")
        for change in ({"ips": ["10.70.0.2"]}, {"hostname": "other-host"}, {"configuration_state": {**original["configuration_state"], "digest": "c" * 64}}):
            with self.subTest(change=change):
                with self.store.meta() as db:
                    self.store._put(db, "servers", {**original, **change})
                with self.assertRaises(WorkflowConflict):
                    lifecycle.kit(self.app, plan["id"], "admin")
                with self.store.meta() as db:
                    self.store._put(db, "servers", original)

    def test_disabled_admin_revokes_further_download_and_fresh_witness(self):
        plan = self.approved()
        with self.store.meta() as db:
            person = self.store._get(db, "auth_users", self.maker["user"]["id"])
            self.store._put(db, "auth_users", {**person, "enabled": False})
        with self.assertRaises(PermissionError):
            lifecycle.kit(self.app, plan["id"], "admin")
        with self.assertRaises(PermissionError):
            lifecycle.check(self.app, "target", {"review_id": plan["id"], "plan_digest": plan["plan_digest"], "candidate_digest": "c" * 64, "phase": "before", "nonce": "d" * 32})

    def test_fresh_witness_binds_identity_and_requires_exact_candidate_report(self):
        plan = self.approved()
        request = {"review_id": plan["id"], "plan_digest": plan["plan_digest"], "candidate_digest": "c" * 64, "phase": "before", "nonce": "d" * 32}
        witness=lifecycle.check(self.app, "target", request)
        self.assertEqual(witness["phase"], "before")
        self.assertEqual(witness["nonce"],request["nonce"])
        self.assertEqual((lifecycle.parse_time(witness["expires_at"])-lifecycle.parse_time(witness["issued_at"])).total_seconds(),30)
        self.assertEqual(witness["signature"]["algorithm"],"Ed25519")
        with self.assertRaises(PermissionError):
            lifecycle.check(self.app, "another-agent", request)
        with self.assertRaises(WorkflowConflict):
            lifecycle.check(self.app, "target", {**request, "phase": "after"})
        with self.store.meta() as db:
            server = self.store._get(db, "servers", "target")
            server["configuration_state"] = {"digest": "c" * 64, **plan["scope"]["settings"]}
            self.store._put(db, "servers", server)
        self.assertEqual(lifecycle.check(self.app, "target", {**request, "phase": "after"})["candidate_digest"], "c" * 64)

    def test_requester_can_revoke_kit_authority_without_changing_endpoint(self):
        plan = self.approved()
        lifecycle.revoke(self.app, plan["id"], self.maker["actor"], self.maker)
        with self.assertRaises(ValueError):
            lifecycle.kit(self.app, plan["id"], "admin")
        self.assertFalse(self.store.get("servers", "target")["configuration_state"]["enforce"])

    def test_no_pilot_mode_or_extra_optin_and_read_only_cannot_apply(self):
        self.assertNotIn("allow_single_admin_pilot",lifecycle.FIELDS)
        self.assertEqual(self.preview()["approval"]["mode"],"single_admin")
        value=copy.deepcopy(self.value);value["settings"]["allow_single_admin_pilot"]=True
        with self.assertRaises(ValueError):self.preview(value)
        reader=self.person("55555555-5555-5555-5555-555555555555","read_only")
        with self.assertRaises(PermissionError):self.preview(principal=reader)
        legacy={"digest":"b"*64,**self.current,"allow_single_admin_pilot":True}
        self.assertNotIn("allow_single_admin_pilot",lifecycle.report(legacy))

    def test_host_deny_false_preserves_legacy_receipts_and_signed_scope(self):
        legacy = {key: value for key, value in self.current.items() if key != lifecycle.HOST_DENY_FLAG}
        reported = lifecycle.report({"digest": "b" * 64, **legacy})
        self.assertIs(reported[lifecycle.HOST_DENY_FLAG], False)
        plan = self.preview()
        self.assertNotIn(lifecycle.HOST_DENY_FLAG, plan["scope"]["settings"])
        kit = lifecycle.kit(self.app, plan["id"], self.maker["actor"])
        self.assertNotIn(lifecycle.HOST_DENY_FLAG, kit["manifest"]["scope"]["settings"])
        for malformed in ("false", 0, None):
            with self.subTest(malformed=malformed), self.assertRaises(ValueError):
                lifecycle.report({"digest": "b" * 64, **legacy, lifecycle.HOST_DENY_FLAG: malformed})

    def test_host_deny_optin_requires_new_agent_enforcement_and_no_auto_allow(self):
        value = copy.deepcopy(self.value)
        value["settings"][lifecycle.HOST_DENY_FLAG] = True
        with self.assertRaisesRegex(ValueError, "Upgrade"):
            self.preview(value)
        server = self.store.get("servers", "target")
        with self.store.meta() as db:
            self.store._put(db, "servers", {**server, "capabilities": [*server["capabilities"], lifecycle.HOST_DENY_CAPABILITY]})
        for changes in ({"enforce": False}, {"learning_auto_allow": True}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.preview({**value, "settings": {**value["settings"], **changes}})
        plan = self.preview(value)
        self.assertIs(plan["scope"]["settings"][lifecycle.HOST_DENY_FLAG], True)
        self.assertIs(lifecycle.kit(self.app, plan["id"], self.maker["actor"])["manifest"]["scope"]["settings"][lifecycle.HOST_DENY_FLAG], True)

    def test_legacy_client_cannot_silently_clear_existing_host_deny_optin(self):
        server = self.store.get("servers", "target")
        with self.store.meta() as db:
            self.store._put(db, "servers", {**server, "capabilities": [*server["capabilities"], lifecycle.HOST_DENY_CAPABILITY], "configuration_state": {**server["configuration_state"], lifecycle.HOST_DENY_FLAG: True}})
        value = copy.deepcopy(self.value)
        value["settings"].pop(lifecycle.HOST_DENY_FLAG)
        with self.assertRaisesRegex(ValueError, "Explicitly preserve or disable"):
            self.preview(value)
        value["settings"][lifecycle.HOST_DENY_FLAG] = False
        self.assertNotIn(lifecycle.HOST_DENY_FLAG, self.preview(value)["scope"]["settings"])

    def test_stale_and_unsupported_hosts_or_credential_fields_are_refused(self):
        for field, value in (("last_seen", stamp(now() - timedelta(minutes=5))), ("capabilities", [])):
            original = self.store.get("servers", "target")
            with self.store.meta() as db:
                self.store._put(db, "servers", {**original, field: value})
            with self.assertRaises((ValueError, WorkflowConflict)):
                self.preview()
            with self.store.meta() as db:
                self.store._put(db, "servers", original)
        with self.assertRaises(ValueError):
            self.preview({**self.value, "private_key": "injected"})
        with self.assertRaises(ValueError):
            lifecycle.report({"digest": "b" * 64, **self.current, "enrollment_token": "injected"})

    @unittest.skipUnless(os.environ.get("SEG_AGENT_BINARY"), "Set SEG_AGENT_BINARY for genuine backend-to-Go configuration signature interoperability")
    def test_real_backend_signed_configuration_passes_strict_native_helper_without_network_or_writes(self):
        binary = os.environ["SEG_AGENT_BINARY"]
        root = Path(self.temp.name).resolve()
        trust = root / "pinned-public-trust.json"
        trust.write_text(json.dumps(self.app.platform.policy_signer().public_trust()))
        config = json.loads((Path(__file__).resolve().parents[2] / "agent/config.example.json").read_text())
        config.update(controller_url=self.current["controller_url"], control_url=self.current["control_url"], discovery_url=self.current["discovery_url"], policy_signing_trust_file=str(trust))
        config_path = root / "local-agent.json"
        config_path.write_text(json.dumps(config)); config_path.chmod(0o600)
        receipt = subprocess.run([binary, "--configuration-state", "--config", str(config_path)], check=True, capture_output=True, text=True, timeout=15)
        server = self.store.get("servers", "target")
        with self.store.meta() as db:
            server["configuration_state"] = lifecycle.report(json.loads(receipt.stdout))
            self.store._put(db, "servers", server)
        with self.store.meta() as db:
            person=self.store._get(db,"auth_users",self.maker["user"]["id"])
            person["display_name"]="Pratik <Admin> पृथक् 😀\x7f"
            self.store._put(db,"auth_users",person)
        plan = self.approved()
        kit = lifecycle.kit(self.app, plan["id"], self.maker["actor"])
        path = root / "private-configuration.json"
        path.write_text(json.dumps(kit)); path.chmod(0o600)
        result = subprocess.run([binary, "--check-configuration", str(path), "--config", str(config_path)], capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("native identity/network/systemd acceptance remains separate", result.stdout)
        old_binary = os.environ.get("SEG_AGENT_OLD_BINARY")
        if old_binary:
            old_result = subprocess.run([old_binary, "--check-configuration", str(path), "--config", str(config_path)], capture_output=True, text=True, timeout=15)
            self.assertEqual(old_result.returncode, 0, old_result.stderr)
        kit["manifest"]["scope"]["settings"]["learning_auto_allow"] = True
        path.write_text(json.dumps(kit))
        result = subprocess.run([binary, "--check-configuration", str(path), "--config", str(config_path)], capture_output=True, text=True, timeout=15)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("differs from independent signature", result.stderr)
        self.assertEqual(json.loads(config_path.read_text()), config)
        with self.store.meta() as db:
            server = self.store._get(db, "servers", "target")
            server["capabilities"].append(lifecycle.HOST_DENY_CAPABILITY)
            self.store._put(db, "servers", server)
        self.value["settings"][lifecycle.HOST_DENY_FLAG] = True
        opted_in = self.approved()
        opted_kit = lifecycle.kit(self.app, opted_in["id"], self.maker["actor"])
        path.write_text(json.dumps(opted_kit))
        enabled = subprocess.run([binary, "--check-configuration", str(path), "--config", str(config_path)], capture_output=True, text=True, timeout=15)
        self.assertEqual(enabled.returncode, 0, enabled.stderr)
        self.assertTrue(opted_kit["manifest"]["scope"]["settings"][lifecycle.HOST_DENY_FLAG])
        if old_binary:
            refused = subprocess.run([old_binary, "--check-configuration", str(path), "--config", str(config_path)], capture_output=True, text=True, timeout=15)
            self.assertNotEqual(refused.returncode, 0)
        self.assertEqual(json.loads(config_path.read_text()), config)


if __name__ == "__main__":
    unittest.main()
