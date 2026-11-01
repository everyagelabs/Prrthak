"""Real temporary SQLite/person/proof regressions for same-fingerprint cutover."""
import copy
import json
import os
import unittest
from unittest.mock import patch

from controller import approvals, firewall, gui_setup, learning_policies as lp, provider_lifecycle as provider
from controller.store import Store, digest, stamp
from controller.tests import test_endpoint_configuration as endpoint_fixture
from controller.tests import test_gui_setup as gui_fixture
from controller.tests import test_auth as auth_fixture
from controller.tests import test_endpoint_certificates as certificate_fixture
from controller.tests import test_platform as platform_fixture


class PendingAuthorityTests(unittest.TestCase):
    def setUp(self):
        self.fixture = endpoint_fixture.EndpointConfigurationTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.store = self.fixture.store

    def invalidate(self):
        with self.store.meta() as db:
            provider.invalidate(self.store, db, {"created_by": "isolated-cutover", "review_id": "same-fingerprint-cutover"})

    def proof(self, identifier, maker=None, checker=None):
        maker = maker or self.fixture.maker
        plan = {"id": identifier, "plan_digest": digest({"review": identifier})}
        with self.store.meta() as db:
            approvals.request(self.store, db, plan, maker["actor"], maker)
            approvals.decide(self.store, db, plan, maker["actor"], maker)
        return approvals.proof(plan)

    def learned(self, applied=False):
        baseline = {"management_sources": ["10.90.0.0/24"], "ssh_ports": [2022], "controller_url": "https://controller.example",
                    "management_probe_url": "https://controller.example/api/v1/agent/enforcement/check", "zone": "public"}
        self.store.report("target", {"hostname": "target", "ips": ["10.70.0.1"], "listeners": [], "firewalld_state": "running",
            "capabilities": ["signed_assignments_v1", "learning_auto_allow_v1"],
            "protection": {**baseline, "digest": digest(baseline), "ready": True, "blockers": []}})
        proof = self.proof("pending-learning-review")
        with self.store.meta() as db:
            server = self.store._get(db, "servers", "target")
            policy = {"id": "learned-policy", "session_id": "observed-session", "server_id": "target", "hostname": "target",
                "origin": "reviewed", "status": "applied" if applied else "pending", "revision": 1,
                "services": [{"port": 8080, "protocol": "tcp", "sources": ["192.0.2.10/32"]}], "approval_proof": proof, **lp._bindings(server)}
            lp._put_policy(self.store, db, policy)
            host = lp.refresh_host(self.store, db, server)
            if applied:
                host.update(applied_services=copy.deepcopy(host["services"]), applied_policy_ids=host["policy_ids"], applied_generation=host["generation"])
                self.store._put(db, "learning_allow_hosts", host)
            self.assertTrue(lp.assignment(self.store, db, server)["authorized"])
        return policy, host

    def test_pending_imported_firewall_authority_is_revoked_but_terminal_history_is_preserved(self):
        self.store.report("target", {"hostname": "target", "ips": ["10.70.0.1"], "listeners": [], "firewalld_state": "running",
            "capabilities": ["signed_assignments_v1"], "firewall_snapshot": {"collected_at": stamp(), "status": "ok", "capabilities": ["firewall_changes_v1"],
            "rules": [{"scope": "runtime", "zone": "public", "kind": "port", "value": "8080/tcp", "editable": True}]}})
        plan = firewall.create_change(self.store, {"name": "Old authority", "server_ids": ["target"], "rule_key": firewall.fingerprints("runtime", "public", "port", "8080/tcp")[1],
            "operation": "remove", "scopes": ["runtime"]}, self.fixture.maker["actor"], principal=self.fixture.maker)
        plan = firewall.confirm_change(self.store, plan["id"], {"confirmation_nonce": plan["confirmation_nonce"]}, self.fixture.maker["actor"], principal=self.fixture.maker)
        plan = firewall.confirm_change(self.store, plan["id"], {"confirmation_nonce": plan["confirmation_nonce"], "challenge": plan["confirmation_phrase"]}, self.fixture.maker["actor"], principal=self.fixture.maker)
        terminal = {**copy.deepcopy(plan), "id": "completed-history", "status": "applied"}
        with self.store.meta() as db:
            self.store._put(db, "firewall_changes", terminal)
            self.assertEqual(len(firewall.assignments(self.store, db, "target")), 1)
        self.invalidate()
        with self.store.meta() as db:
            self.assertEqual(firewall.assignments(self.store, db, "target"), [])
            changed = self.store._get(db, "firewall_changes", plan["id"])
            self.assertEqual(changed["status"], "invalidated")
            self.assertEqual(changed["confirmation_nonce"], "")
            self.assertEqual(changed["approval_proof"], plan["approval_proof"])
            self.assertEqual(self.store._get(db, "firewall_changes", terminal["id"]), terminal)

    def test_pending_learning_tuple_cannot_use_old_review_after_secret_rotation(self):
        policy, host = self.learned()
        self.invalidate()
        with self.store.meta() as db:
            current = self.store._get(db, "learning_allow_policies", policy["id"])
            assigned = lp.assignment(self.store, db, self.store._get(db, "servers", "target"))
            self.assertFalse(assigned["authorized"])
            self.assertEqual(assigned["services"], host["services"])
            self.assertEqual(current["approval_proof"]["stage"], "revoked")
            history = self.store._get(db, "maintenance_settings", "provider_revoked_learning_proof:" + policy["id"] + ":" + policy["approval_proof"]["binding_digest"])
            self.assertEqual(history["approval_proof"], policy["approval_proof"])
            self.assertLessEqual(len(json.dumps(current)), len(json.dumps(policy)))

    def test_committed_learning_grants_and_history_are_not_removed_by_cutover(self):
        policy, host = self.learned(applied=True)
        self.invalidate()
        with self.store.meta() as db:
            current = self.store._get(db, "learning_allow_hosts", "target")
            assigned = lp.assignment(self.store, db, self.store._get(db, "servers", "target"))
            self.assertFalse(assigned["authorized"])
            self.assertEqual(current["applied_services"], host["services"])
            self.assertEqual(assigned["services"], host["services"])
            self.assertEqual(current["generation"], host["generation"])
            self.assertFalse(self.store._get(db, "learning_allow_policies", policy["id"]).get("removed", False))

    def test_new_independent_review_replaces_invalidated_proof_without_erasing_history(self):
        policy, _ = self.learned()
        self.invalidate()
        maker = self.fixture.person("33333333-3333-3333-3333-333333333333")
        checker = self.fixture.person("44444444-4444-4444-4444-444444444444")
        proof = self.proof("fresh-learning-review", maker, checker)
        with self.store.meta() as db:
            current = self.store._get(db, "learning_allow_policies", policy["id"])
            current["approval_proof"] = proof
            lp._put_policy(self.store, db, current)
            self.assertTrue(lp.assignment(self.store, db, self.store._get(db, "servers", "target"))["authorized"])
            history = self.store._get(db, "maintenance_settings", "provider_revoked_learning_proof:" + policy["id"] + ":" + policy["approval_proof"]["binding_digest"])
            self.assertEqual(history["approval_proof"], policy["approval_proof"])

    def test_existing_immutable_proof_history_is_verified_and_never_overwritten(self):
        policy, _ = self.learned()
        key = "provider_revoked_learning_proof:" + policy["id"] + ":" + policy["approval_proof"]["binding_digest"]
        original = {"id": key, "policy_id": policy["id"], "approval_proof": policy["approval_proof"], "revoked_at": "2000-01-01T00:00:00Z", "review_id": "first-cutover"}
        with self.store.meta() as db:
            self.store._put(db, "maintenance_settings", original)
        self.invalidate()
        self.assertEqual(self.store.get("maintenance_settings", key), original)

    def test_conflicting_immutable_proof_history_aborts_invalidation_transaction(self):
        policy, _ = self.learned()
        key = "provider_revoked_learning_proof:" + policy["id"] + ":" + policy["approval_proof"]["binding_digest"]
        with self.store.meta() as db:
            self.store._put(db, "maintenance_settings", {"id": key, "policy_id": policy["id"], "approval_proof": {"different": "proof"}})
        before = self.store.all("auth_sessions")
        with self.assertRaisesRegex(ValueError, "immutable identity"):
            self.invalidate()
        self.assertEqual(self.store.all("auth_sessions"), before)
        self.assertEqual(self.store.get("learning_allow_policies", policy["id"])["approval_proof"], policy["approval_proof"])


class ProviderReviewEpochTests(unittest.TestCase):
    def setUp(self):
        self.fixture = gui_fixture.GUISetupTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.maker = self.fixture.active_super()
        self.checker = self.fixture.active_super(auth_fixture.ADMIN)

    def change_epoch(self):
        secondary = Store(self.fixture.directory / "db")
        with secondary.meta() as db:
            provider.invalidate(secondary, db, {"created_by": "completed-other-review", "review_id": "other-transition"})
            secondary._put(db, "maintenance_settings", {"id": provider.AUTHORITY, "fingerprint": self.fixture.app.auth.config.fingerprint, "epoch": "a" * 32})

    def test_old_candidate_and_maker_submission_cannot_resume_after_same_fingerprint_epoch_change(self):
        plan = self.fixture.verified_plan(self.fixture.request(True), self.maker)
        self.change_epoch()
        with patch.dict(os.environ, {"PRTHAK_PROVIDER_EPOCH": "a" * 32}):
            checker = self.fixture.active_super(auth_fixture.ADMIN)
            with self.assertRaisesRegex(firewall.WorkflowConflict, "Sign-in authority changed"):
                gui_setup.apply(self.fixture.manager, self.fixture.confirmation(plan), checker, self.fixture.client)
            state = gui_setup.status(self.fixture.manager, checker, self.fixture.client)
            self.assertEqual(state["reviews"], [])
            self.assertIsNone(state["setup_pending"])

    def test_queue_rechecks_captured_epoch_after_another_store_changes_authority(self):
        plan = self.fixture.verified_plan(self.fixture.request(True), self.maker)
        with self.fixture.store.meta() as db:
            approvals.decide(self.fixture.store, db, plan, self.maker["actor"], self.maker)
        request = json.loads(self.fixture.manager.vault.get(plan["request_ref"]))
        self.change_epoch()
        with patch.dict(os.environ, {"PRTHAK_PROVIDER_EPOCH": "a" * 32}), self.assertRaisesRegex(firewall.WorkflowConflict, "Sign-in authority changed"):
            provider.queue(self.fixture.manager, plan, request)
        self.assertIsNone(provider.get(self.fixture.manager))

    def test_new_review_on_current_epoch_still_queues_and_old_job_history_can_be_read(self):
        self.change_epoch()
        with patch.dict(os.environ, {"PRTHAK_PROVIDER_EPOCH": "a" * 32}):
            maker = self.fixture.active_super()
            checker = self.fixture.active_super(auth_fixture.ADMIN)
            plan = self.fixture.verified_plan(self.fixture.request(True), maker)
            result = gui_setup.apply(self.fixture.manager, self.fixture.confirmation(plan), maker, self.fixture.client)
            self.assertEqual(result["provider_transition"]["phase"], "prepare")
            self.assertTrue(plan["summary"]["client_secret_supplied"])
            self.assertFalse(plan["summary"]["initial_entra"])
        with self.fixture.store.meta() as db:
            self.fixture.store._put(db, "maintenance_settings", {"id": provider.AUTHORITY, "fingerprint": self.fixture.app.auth.config.fingerprint, "epoch": "b" * 32})
        history = gui_setup._load(self.fixture.manager, plan["id"])
        self.assertTrue(history["job_id"].startswith("provider:"))


class ProviderCredentialCutoverTests(unittest.TestCase):
    def test_unused_tokens_fail_after_cutover_but_consumed_retries_and_active_leaf_survive(self):
        from controller import endpoint_certificates
        fixture = certificate_fixture.EndpointCertificateTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        unused_recovery = endpoint_certificates.recovery_token(fixture.store, fixture.server_id, "old-super")
        unused_enrollment = fixture.store.create_token("pending-old-enrollment", "old-admin")
        used_enrollment = fixture.store.create_token("completed-enrollment", "old-admin")
        enrollment_csr = fixture.csr()
        enrolled = fixture.store.enroll(used_enrollment["token"], "enrolled-before-cutover", enrollment_csr, fixture.signer)
        used_recovery = endpoint_certificates.recovery_token(fixture.store, fixture.server_id, "old-super")
        recovery_body = {"token": used_recovery["token"], "hostname": "billing-test", "csr": fixture.csr()}
        recovered = endpoint_certificates.recover(fixture.store, recovery_body, fixture.signer)
        with fixture.store.meta() as db:
            before = {row["id"]: row for row in fixture.store._all(db, "maintenance_settings") if row["id"].startswith("endpoint_certificate:")}
            provider.invalidate(fixture.store, db, {"created_by": "new-authority", "review_id": "cutover"})
        with self.assertRaises(PermissionError):
            fixture.store.enroll(unused_enrollment["token"], "after-cutover", fixture.csr(), fixture.signer)
        with self.assertRaises(PermissionError):
            endpoint_certificates.recover(fixture.store, {"token": unused_recovery["token"], "hostname": "billing-test", "csr": fixture.csr()}, fixture.signer)
        self.assertEqual(fixture.store.enroll(used_enrollment["token"], "enrolled-before-cutover", enrollment_csr, fixture.signer), enrolled)
        self.assertEqual(endpoint_certificates.recover(fixture.store, recovery_body, fixture.signer), recovered)
        with fixture.store.read_meta() as db:
            after = {row["id"]: row for row in fixture.store._all(db, "maintenance_settings") if row["id"].startswith("endpoint_certificate:")}
        self.assertTrue(before)
        self.assertEqual(before, after)

    @unittest.skipUnless(platform_fixture.HAS_PG, "Join profile parsing requires installed psycopg; no PostgreSQL connection is made")
    def test_unused_controller_join_code_is_revoked_while_consumed_response_is_retained(self):
        from pathlib import Path
        import types
        from controller.pki import init_ca, Signer
        fixture = platform_fixture.PlatformManagerTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        fixture.save()
        pki = init_ca(Path(fixture.temp.name) / "private-join-pki")
        ca = fixture.manager.root / "database-ca.pem"
        ca.write_text((pki / "ca.pem").read_text())
        store = Store(Path(fixture.temp.name) / "join-metadata")
        store.ha = True  # Real SQLite/crypto transport fixture, never represented as a live PostgreSQL cluster.
        fixture.manager.attach(types.SimpleNamespace(store=store, demo=False, signer=Signer(pki / "ca.pem", pki / "ca-key.pem"), controller_id="source",
            cluster=lambda: {"nodes": []}, auth=types.SimpleNamespace(enabled=False, config=None), tokens={}))
        fixture.manager.commit_active_profile({"deployment_id": fixture.spec["cluster_id"], "epoch": 1, "active_revision": 1,
            "controller_origin": "https://localhost:8787", "mode": "dc_dr", "spec": fixture.manager.configuration(True)["spec"],
            "metadata_dsn": "host=10.70.0.1 dbname=prthak_metadata user=app password=synthetic sslrootcert=" + str(ca),
            "traffic_dsn": "host=10.70.0.1 dbname=prthak_traffic user=app password=synthetic sslrootcert=" + str(ca)})
        identity = {"node_id": "joining", "site": "dr", "node_ip": "10.70.0.50"}
        issued = fixture.manager.create_join_token(identity, "old-super")
        code = fixture.manager._join_code(issued["join_code"])
        request = {"action": "inspect", "token_id": code["id"], "secret": code["secret"], **identity}
        self.assertEqual(fixture.manager.enroll_node(request)["node_id"], identity["node_id"])
        consumed = {"id": "platform_join:already-consumed", "consumed": True, "request_digest": "a" * 64, "sealed_response": {"ciphertext": "private-cached-response"}}
        unrelated = {"id": "platformXjoin:unrelated-setting", "value": "preserve"}
        with store.meta() as db:
            store._put(db, "maintenance_settings", consumed)
            store._put(db, "maintenance_settings", unrelated)
            provider.invalidate(store, db, {"created_by": "new-authority", "review_id": "cutover"})
        with self.assertRaises(PermissionError):
            fixture.manager.enroll_node(request)
        self.assertEqual(store.get("maintenance_settings", consumed["id"]), consumed)
        self.assertEqual(store.get("maintenance_settings", unrelated["id"]), unrelated)


if __name__ == "__main__":
    unittest.main()
