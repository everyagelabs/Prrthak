import json
import tempfile
import unittest
from datetime import timedelta
from unittest.mock import patch

from controller.firewall import WorkflowConflict
from controller.managed import binding_digest, difference
from controller.store import Store, digest, now, parse_time, stamp


class ManagedPolicyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = Store(self.temp.name)
        self.store.lab_approvals = True  # Explicit isolated single-actor lab fixture.
        self.report("target", "10.0.0.1")
        self.report("source", "10.0.0.2")
        self.store.update_server("target", {"tags": {"role": "api"}}, "admin")
        self.store.update_server("source", {"tags": {"role": "lb"}}, "admin")
        self.policy = self.store.save_policy({"name": "API access", "selector": {"role": "api"}, "mode": "enforce", "services": [{"port": 8080, "protocol": "tcp", "sources": [], "source_selector": {"role": "lb"}}]}, "admin")
        self.report("target", "10.0.0.1", protection=self.protected())

    def protected(self, **extra):
        baseline = {"management_sources": ["10.99.0.0/24"], "ssh_ports": [2022], "controller_url": "https://controller.example", "management_probe_url": "https://controller.example/api/v1/agent/enforcement/check", "zone": "public", **extra}
        return {**baseline, "digest": digest(baseline), "ready": True, "blockers": []}

    def report(self, identifier, address, **extra):
        return self.store.report(identifier, {"hostname": identifier, "ips": [address], "listeners": [{"port": 2022, "protocol": "tcp", "address": "0.0.0.0", "process": "sshd", "service": "SSH"}], "firewalld_state": "running", "applied_version": 0, "apply_status": "preview", **extra})

    def draft(self):
        return self.store.create_managed_rollout({"name": "Explicit managed review", "server_ids": ["target"]}, "admin")

    def approve(self):
        first = self.draft()
        second = self.store.confirm_managed_rollout(first["id"], {"confirmation_nonce": first["confirmation_nonce"]}, "admin")
        return self.store.confirm_managed_rollout(first["id"], {"confirmation_nonce": second["confirmation_nonce"], "challenge": second["confirmation_phrase"]}, "admin")

    def outcome(self, status="enforced", **extra):
        bundle = self.store.assignment("target")[0]
        approval = bundle["enforcement"]
        return {"status": status, "version": bundle["version"], "digest": bundle["digest"], "approval_id": approval["approval_id"], "error": "", "rollback_reason": "", "last_good_version": 0, "last_good_digest": "", "updated_at": stamp(), **extra}

    def mark_enforced(self):
        plan = self.approve()
        outcome = self.outcome()
        self.report("target", "10.0.0.1", managed_enforcement=outcome, applied_version=outcome["version"], apply_status="synced")
        return plan, outcome

    def test_shared_canonical_digest_fixture_matches_agent(self):
        payload = {"mode": "enforce", "services": [{"mode": "enforce", "port": 2022, "protocol": "tcp", "sources": ["10.20.0.0/24"]}]}
        self.assertEqual(digest(payload), "50dc53b2113dd1efea4171fd1aede923aee1125fa5bde70d92a4e7a221d9b229")
        self.assertEqual(binding_digest("srv-1", 7, digest(payload), "a" * 64), "a22253beac3394755aad68a4c84ea523b3dbb84b0180787b5071ec2e612cea0f")

    def test_native_readback_metadata_preserves_precision_and_rejects_unpaired_boundaries(self):
        self.approve()
        at = now()
        precise = at.isoformat(timespec="microseconds").replace("+00:00", "789Z")
        result = self.outcome(generation="a" * 32, committed_at=stamp(at - timedelta(seconds=1)),
                              updated_at=precise, already_present=True, verification_id="observation-1", verification_readback_at=precise)
        self.report("target", "10.0.0.1", managed_enforcement=result)
        saved = self.store.get("servers", "target")["managed_enforcement"]
        self.assertEqual(saved["updated_at"], precise)
        self.assertEqual(saved["verification_readback_at"], precise)
        self.assertIs(saved["already_present"], True)
        for changes in ({"already_present": "true"}, {"generation": "<invalid>"}, {"committed_at": stamp(at + timedelta(seconds=5))}, {"verification_readback_at": None}):
            before = self.store.get("servers", "target")
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.report("target", "10.0.0.1", managed_enforcement={**result, **changes})
            self.assertEqual(self.store.get("servers", "target"), before)
        missing = dict(result)
        missing.pop("verification_id")
        with self.assertRaises(ValueError):
            self.report("target", "10.0.0.1", managed_enforcement=missing)

    def test_policy_revision_and_bundle_history_are_immutable_and_restore_is_new(self):
        original = self.store.policy_revisions(self.policy["id"], 1)
        original_bundle = self.store.assignment("target")[0]
        changed = self.store.save_policy({**self.policy, "services": [{"port": 8443, "protocol": "tcp", "sources": ["10.77.0.0/24"]}]}, "admin", self.policy["id"])
        self.assertEqual(changed["revision"], 2)
        self.assertEqual(self.store.policy_revisions(self.policy["id"], 1), original)
        restored = self.store.rollback_policy(self.policy["id"], 1, "Restore the reviewed former configuration", "admin")
        self.assertEqual(restored["revision"], 3)
        current = self.store.assignment("target")[0]
        self.assertGreater(current["version"], original_bundle["version"])
        self.assertEqual(current["digest"], original_bundle["digest"])
        self.assertFalse(current["enforcement"]["authorized"])
        self.assertEqual(self.store.policy_history("target", original_bundle["version"])["digest"], original_bundle["digest"])
        changes = difference(original, self.store.policy_revisions(self.policy["id"], 2))["changes"]
        self.assertTrue(any(change["field"] == "services" for change in changes))

    def test_deleted_policy_restore_does_not_reset_revision_counter(self):
        self.store.delete_policy(self.policy["id"], "admin")
        restored = self.store.rollback_policy(self.policy["id"], 1, "Restore accidentally removed configuration", "admin")
        self.assertEqual(restored["revision"], 2)
        self.assertEqual(len(self.store.policy_revisions(self.policy["id"])), 2)

    def test_enforce_intent_requires_two_distinct_bound_confirmations(self):
        before = self.store.assignment("target")[0]
        self.assertFalse(before["enforcement"]["authorized"])
        draft = self.draft()
        self.assertEqual(draft["preview"]["targets"][0]["protection_status"], "ready")
        self.assertEqual(draft["preview"]["targets"][0]["services"], before["services"])
        first = self.store.confirm_managed_rollout(draft["id"], {"confirmation_nonce": draft["confirmation_nonce"], "confirmation_count": 2, "challenge": draft["confirmation_phrase"]}, "admin")
        self.assertEqual(first["confirmation_count"], 1)
        self.assertFalse(self.store.assignment("target")[0]["enforcement"]["authorized"])
        with self.assertRaises(WorkflowConflict):
            self.store.confirm_managed_rollout(draft["id"], {"confirmation_nonce": draft["confirmation_nonce"], "challenge": draft["confirmation_phrase"]}, "admin")
        with self.assertRaises(WorkflowConflict):
            self.store.confirm_managed_rollout(draft["id"], {"confirmation_nonce": first["confirmation_nonce"], "challenge": "wrong"}, "admin")
        queued = self.store.confirm_managed_rollout(draft["id"], {"confirmation_nonce": first["confirmation_nonce"], "challenge": first["confirmation_phrase"]}, "admin")
        approved = self.store.assignment("target")[0]["enforcement"]
        self.assertTrue(approved["authorized"])
        self.assertEqual(approved["approval_id"], queued["id"])
        self.assertEqual(approved["confirmation_count"], 2)
        self.assertEqual(approved["approved_digest"], before["digest"])

    def test_source_membership_change_requires_new_authorization_and_unrelated_labels_do_not_bump(self):
        self.approve()
        before = self.store.assignment("target")[0]
        self.store.update_server("source", {"tags": {"role": "lb", "unrelated": "label"}}, "admin")
        unchanged = self.store.assignment("target")[0]
        self.assertEqual(unchanged["version"], before["version"])
        self.assertTrue(unchanged["enforcement"]["authorized"])
        self.report("source", "10.0.0.3")
        changed = self.store.assignment("target")[0]
        self.assertGreater(changed["version"], before["version"])
        self.assertFalse(changed["enforcement"]["authorized"])
        self.assertEqual(changed["services"][0]["sources"], ["10.0.0.3/32"])

    def test_protection_and_target_ip_changes_invalidate_confirmation_and_witness(self):
        approved_plan = self.approve()
        current = self.store.assignment("target")[0]
        approval = current["enforcement"]
        payload = {"version": current["version"], "digest": current["digest"], "approval_id": approval["approval_id"], "protection_digest": approval["protection_digest"], "binding_digest": approval["binding_digest"]}
        verified = self.store.verify_managed_enforcement("target", payload)
        self.assertEqual(verified["ips"], ["10.0.0.1"])
        self.report("target", "10.0.0.99")
        self.assertFalse(self.store.assignment("target")[0]["enforcement"]["authorized"])
        with self.assertRaises(PermissionError):
            self.store.verify_managed_enforcement("target", payload)
        draft = self.draft()
        self.report("target", "10.0.0.99", protection=self.protected(management_sources=["10.98.0.0/24"]))
        with self.assertRaises(WorkflowConflict):
            self.store.confirm_managed_rollout(draft["id"], {"confirmation_nonce": draft["confirmation_nonce"]}, "admin")
        self.assertEqual(self.store.managed_rollouts(approved_plan["id"])["status"], "invalidated")

    def test_cancel_and_expiry_revoke_admission_without_rewriting_versions(self):
        plan = self.approve()
        current = self.store.assignment("target")[0]
        self.store.cancel_managed_rollout(plan["id"], "admin")
        self.assertFalse(self.store.assignment("target")[0]["enforcement"]["authorized"])
        self.assertEqual(self.store.assignment("target")[0]["version"], current["version"])
        other = self.approve()
        with patch("controller.managed.now", return_value=parse_time(other["expires_at"]) + timedelta(seconds=1)):
            self.assertFalse(self.store.assignment("target")[0]["enforcement"]["authorized"])

    def test_monitor_only_and_unready_or_unrestricted_baselines_cannot_be_approved(self):
        self.store.save_policy({**self.policy, "mode": "monitor"}, "admin", self.policy["id"])
        draft = self.draft()
        self.assertTrue(draft["preview"]["targets"][0]["blockers"])
        with self.assertRaises(WorkflowConflict):
            self.store.confirm_managed_rollout(draft["id"], {"confirmation_nonce": draft["confirmation_nonce"]}, "admin")
        self.store.save_policy(self.policy, "admin", self.policy["id"])
        unsafe = self.protected(management_sources=["0.0.0.0/0"])
        self.report("target", "10.0.0.1", protection=unsafe)
        self.assertFalse(self.store.get("servers", "target")["protection"]["ready"])
        draft = self.draft()
        with self.assertRaises(WorkflowConflict):
            self.store.confirm_managed_rollout(draft["id"], {"confirmation_nonce": draft["confirmation_nonce"]}, "admin")

    def test_poll_authorization_never_loads_whole_fleet_rollout_json(self):
        self.approve()
        original = self.store._get
        def no_whole_plan(db, table, identifier):
            if table == "managed_rollouts":
                raise AssertionError("Endpoint poll must only read normalized per-host approval")
            return original(db, table, identifier)
        with patch.object(self.store, "_get", side_effect=no_whole_plan):
            self.assertTrue(self.store.assignment("target")[0]["enforcement"]["authorized"])

    def test_valid_outcomes_are_linked_outside_immutable_bundle_and_bare_version_is_not_synced(self):
        desired = self.store.assignment("target")[0]
        self.report("target", "10.0.0.1", applied_version=desired["version"], apply_status="synced")
        self.assertNotEqual(self.store.get("servers", "target")["apply_status"], "synced")
        self.assertEqual(self.store.get("servers", "target")["applied_version"], 0)
        plan, outcome = self.mark_enforced()
        server = self.store.get("servers", "target")
        self.assertEqual(server["apply_status"], "synced")
        self.assertTrue(server["_managed_rules_active"])
        linked = self.store.policy_history("target", outcome["version"])
        self.assertEqual(linked["outcomes"][0]["status"], "enforced")
        with self.store.read_meta() as db:
            immutable = json.loads(db.execute("SELECT data FROM bundle_history WHERE server_id=? AND version=?", ("target", outcome["version"])).fetchone()[0])
        self.assertNotIn("outcomes", immutable)
        with self.assertRaises(PermissionError):
            self.report("source", "10.0.0.2", managed_enforcement=outcome)
        with self.assertRaises(PermissionError):
            self.report("target", "10.0.0.1", managed_enforcement={**outcome, "digest": "a" * 64})

    def test_confirmed_managed_allow_queues_once_after_apply(self):
        with self.store.meta() as db:
            self.store._put(db, "notification_settings", {"id": "settings", "enabled": True, "revision": 1,
                            "channels": [{"type": "email", "enabled": True, "event_types": ["port_allowed"]}]})
        self.approve()
        self.assertEqual(self.store.all("notification_events"), [])
        outcome = self.outcome()
        for _ in range(2):
            self.report("target", "10.0.0.1", managed_enforcement=outcome)
        events = self.store.all("notification_events")
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["server_id"], "target")
        self.assertIn("8080/tcp", events[0]["message"])

    def test_endpoint_applied_view_uses_exact_installed_named_rules_and_protected_sources(self):
        from controller.endpoint_applied_policies import listing

        group = self.store.save_group({"name": "Load balancers", "type": "static", "server_ids": ["source"]}, "admin")
        policy = self.store.save_policy({**self.policy, "name": "API access via LB", "services": [
            {"port": 8443, "protocol": "tcp", "source_group_ids": [group["id"]]},
            {"port": 2022, "protocol": "tcp", "sources": ["192.0.2.1"]},
        ]}, "admin", self.policy["id"])
        self.assertEqual(listing(self.store, "target")["managed"]["rows"], [])
        _, applied = self.mark_enforced()
        self.store.save_policy({**policy, "name": "New desired name", "services": [{"port": 9090, "sources": ["192.0.2.2"]}]},
                               "admin", policy["id"])
        group["name"] = "Renamed source group"
        self.store.save_group(group, "admin", group["id"])
        view = listing(self.store, "target")["managed"]
        self.assertEqual((view["state"], view["version"]), ("confirmed", applied["version"]))
        by_port = [row for row in view["rows"] if row["destination_port"] == "8443/tcp"]
        self.assertEqual([(row["policy_name"], row["action"]) for row in by_port],
                         [("API access via LB", "allow"), ("Managed port fallback", "deny")])
        self.assertEqual((by_port[0]["sources"], by_port[0]["source_groups"]), (["10.0.0.2/32"], ["Load balancers"]))
        self.assertEqual(next(row["sources"] for row in view["rows"] if row["policy_name"] == "Protected SSH access"), ["10.99.0.0/24"])
        self.assertNotIn("9090/tcp", {row["destination_port"] for row in view["rows"]})
        history = self.store.policy_history("target", applied["version"])
        self.assertTrue(all(row["sources"] is None for row in history["policy_contributors"]))
        page = listing(self.store, "target", limit=1, managed_offset=1)["managed"]
        self.assertEqual(page["rows"], view["rows"][1:2])
        self.assertTrue(page["has_more"])

    def test_endpoint_applied_view_marks_legacy_sources_and_offline_runtime(self):
        from controller.endpoint_applied_policies import listing

        _, applied = self.mark_enforced()
        with self.store.meta() as db:
            history = json.loads(db.execute("SELECT data FROM bundle_history WHERE server_id=? AND version=?", ("target", applied["version"])).fetchone()[0])
            history.pop("policy_contributors")
            db.execute("UPDATE bundle_history SET data=? WHERE server_id=? AND version=?", (json.dumps(history), "target", applied["version"]))
        with patch("controller.store.now", return_value=now() + timedelta(hours=1)):
            view = listing(self.store, "target")["managed"]
        self.assertEqual(view["state"], "last_confirmed")
        allowed = next(row for row in view["rows"] if row["action"] == "allow")
        self.assertEqual(allowed["policy_name"], "Managed bundle")
        self.assertEqual(allowed["sources"], ["10.0.0.2/32"])
        self.assertIn("not recorded", allowed["note"])

    def test_last_policy_removal_requires_reviewed_cleanup_and_reports_deactivation_intent(self):
        _, old = self.mark_enforced()
        self.store.delete_policy(self.policy["id"], "admin")
        desired = self.store.assignment("target")[0]
        self.assertEqual(desired["mode"], "monitor")
        self.assertGreater(desired["version"], old["version"])
        self.assertFalse(desired["enforcement"]["authorized"])
        plan = self.approve()
        self.assertEqual(plan["preview"]["targets"][0]["intent"], "remove_managed_rules")
        approved = self.store.assignment("target")[0]
        self.assertTrue(approved["enforcement"]["authorized"])
        self.assertEqual(approved["enforcement"]["intent"], "remove_managed_rules")
        result = self.outcome()
        self.report("target", "10.0.0.1", managed_enforcement=result, applied_version=result["version"], apply_status="synced")
        server = self.store.get("servers", "target")
        self.assertFalse(server["_managed_rules_active"])
        self.assertEqual(server["managed_enforcement"]["intent"], "remove_managed_rules")
        self.assertFalse(self.store.assignment("target")[0]["enforcement"]["authorized"])

    def test_reapproval_same_second_revokes_old_delivery_and_witness(self):
        first = self.approve()
        old = self.store.assignment("target")[0]
        second = self.approve()
        new = self.store.assignment("target")[0]
        self.assertNotEqual(first["id"], second["id"])
        self.assertEqual(new["enforcement"]["approval_id"], second["id"])
        with self.assertRaises(PermissionError):
            self.store.verify_managed_enforcement("target", {"version": old["version"], "digest": old["digest"], **{key: old["enforcement"][key] for key in ("approval_id", "protection_digest", "binding_digest")}})
        with self.store.meta() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM managed_approvals WHERE server_id=? AND active=1", ("target",)).fetchone()[0], 1)

    def test_historical_rollout_retains_results_after_later_rollout_outcomes(self):
        first, old = self.mark_enforced()
        self.store.save_policy({**self.policy, "services": [{"port": 8081, "protocol": "tcp", "sources": ["10.0.0.0/24"]}]}, "admin", self.policy["id"])
        second = self.approve()
        new = self.outcome()
        self.report("target", "10.0.0.1", managed_enforcement=new, applied_version=new["version"], apply_status="synced")
        self.assertEqual(self.store.managed_rollouts(first["id"])["results"]["target"]["version"], old["version"])
        self.assertEqual(self.store.managed_rollouts(second["id"])["results"]["target"]["version"], new["version"])

    def test_rollback_requires_explicit_known_last_good_and_preserves_previous_state(self):
        _, old = self.mark_enforced()
        self.store.save_policy({**self.policy, "services": [{"port": 8081, "protocol": "tcp", "sources": ["10.0.0.0/24"]}]}, "admin", self.policy["id"])
        self.approve()
        missing = self.outcome(status="rolled_back")
        missing.pop("last_good_version")
        missing.pop("last_good_digest")
        for result in (missing, self.outcome(status="rolled_back", last_good_version=0, last_good_digest="")):
            with self.assertRaises(ValueError):
                self.report("target", "10.0.0.1", managed_enforcement=result, applied_version=0, apply_status="rolled_back")
        self.assertEqual(self.store.get("servers", "target")["last_good_version"], old["version"])
        self.assertEqual(self.store.get("servers", "target")["applied_version"], old["version"])

    def test_first_failed_apply_can_explicitly_restore_unmanaged_baseline_zero(self):
        self.approve()
        result = self.outcome(status="rolled_back", last_good_version=0, last_good_digest="", rollback_reason="Initial trial failed")
        self.report("target", "10.0.0.1", managed_enforcement=result, applied_version=0, apply_status="rolled_back")
        self.assertEqual(self.store.get("servers", "target")["applied_version"], 0)

    def test_valid_rollback_outcome_restores_last_good_without_decreasing_desired_history(self):
        _, old = self.mark_enforced()
        self.store.save_policy({**self.policy, "services": [{"port": 8081, "protocol": "tcp", "sources": ["10.0.0.0/24"]}]}, "admin", self.policy["id"])
        self.approve()
        attempted = self.outcome(status="rolled_back", last_good_version=old["version"], last_good_digest=old["digest"], rollback_reason="Fresh SSH witness failed")
        self.report("target", "10.0.0.1", managed_enforcement=attempted, applied_version=old["version"], apply_status="rolled_back")
        server = self.store.get("servers", "target")
        self.assertEqual(server["applied_version"], old["version"])
        self.assertGreater(server["desired_version"], old["version"])
        self.assertEqual(server["apply_status"], "rolled_back")
        self.assertEqual(server["last_good_version"], old["version"])
        self.assertTrue(any(outcome["status"] == "rolled_back" for outcome in self.store.policy_history("target", attempted["version"])["outcomes"]))


if __name__ == "__main__":
    unittest.main()
