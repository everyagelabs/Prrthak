import hashlib
import tempfile
import unittest
from datetime import timedelta
from unittest.mock import patch

from controller.firewall import WorkflowConflict, classify, fingerprints
from controller.firewall_views import endpoint_access_snapshot
from controller.store import Store, now, parse_time, stamp


class FirewallTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = Store(self.temp.name)
        self.store.lab_approvals = True  # Explicit isolated single-actor lab fixture.
        self.base = parse_time(stamp())
        self.port = {"scope": "runtime", "zone": "public", "kind": "port", "value": "80/tcp", "editable": True}
        self.log = {"scope": "runtime", "zone": "public", "kind": "rich_rule", "value": 'rule port port="8080" protocol="tcp" log prefix="OBS: "', "editable": True}
        self.report("a", [self.port, {**self.port, "scope": "permanent"}, self.log])
        self.report("b", [self.port, self.log])
        self.report("c", [{**self.port, "value": "2022/tcp"}])

    def report(self, identifier, rules=None, **extra):
        body = {"hostname": identifier, "ips": [{"a": "10.0.0.1", "b": "10.0.0.2", "c": "10.0.0.3"}[identifier]], "listeners": [], "firewalld_state": "running", "applied_version": 1, "apply_status": "synced", **extra}
        if rules is not None:
            body["firewall_snapshot"] = {"collected_at": stamp(), "status": "ok", "digest": "0" * 64, "rules": rules, "capabilities": ["firewall_changes_v1"]}
        return self.store.report(identifier, body)

    def draft(self, kind="port", value="80/tcp", hosts=None, operation="remove", new_value=None):
        return self.store.create_firewall_change({"name": "Reviewed bulk edit", "server_ids": hosts or ["a", "b"], "rule_key": fingerprints("runtime", "public", kind, value)[1], "operation": operation, "new_value": new_value, "scopes": ["runtime", "permanent"]}, "admin")

    def queue(self, plan):
        current = self.store.confirm_firewall_change(plan["id"], {"confirmation_nonce": plan["confirmation_nonce"]}, "admin")
        if current["status"] == "awaiting_second_confirmation":
            current = self.store.confirm_firewall_change(plan["id"], {"confirmation_nonce": current["confirmation_nonce"], "challenge": current["confirmation_phrase"]}, "admin")
        return current

    def test_snapshot_identity_and_exact_common_rule_host_scope_counts(self):
        data = self.store.firewall_inventory()
        rule = next(row for row in data["common_rules"] if row["kind"] == "port" and row["value"] == "80/tcp")
        self.assertEqual(rule["host_count"], 2)
        self.assertEqual(rule["scope_host_counts"], {"runtime": 2, "permanent": 1})
        self.assertEqual(rule["scopes"], ["permanent", "runtime"])
        snapshot = self.store.get("servers", "a")["firewall_snapshot"]
        expected = hashlib.sha256("\n".join(sorted(rule["fingerprint"] for rule in snapshot["rules"])).encode()).hexdigest()
        self.assertEqual(snapshot["digest"], expected)
        self.assertNotEqual(snapshot["digest"], "0" * 64)
        self.assertEqual(snapshot["rules"][0]["fingerprint"], fingerprints(snapshot["rules"][0]["scope"], "public", snapshot["rules"][0]["kind"], snapshot["rules"][0]["value"])[0])

    def test_error_and_partial_snapshot_preserve_previous_rules_and_block_changes(self):
        old = self.store.get("servers", "a")["firewall_snapshot"]
        self.report("a", firewall_snapshot={"status": "error", "collected_at": stamp(), "rules": [], "error": "firewalld unavailable"})
        retained = self.store.get("servers", "a")["firewall_snapshot"]
        self.assertEqual(retained["rules"], old["rules"])
        self.assertEqual(retained["digest"], old["digest"])
        self.assertEqual(retained["status"], "error")
        with self.assertRaises(ValueError):
            self.draft(hosts=["a"])

    def test_endpoint_access_lists_runtime_decisions_and_zone_bindings(self):
        self.report("a", [
            self.port, self.log,
            {**self.port, "scope": "permanent", "value": "8443/tcp"},
            {**self.port, "zone": "unused", "value": "5432/tcp"},
            {**self.port, "zone": "unused", "kind": "target", "value": "default"},
            {**self.port, "zone": "", "kind": "default_zone", "value": "public"},
            {**self.port, "kind": "interface", "value": "ens192"},
            {**self.port, "zone": "internal", "kind": "source", "value": "10.30.0.0/16"},
            {**self.port, "zone": "internal", "kind": "rich_rule",
             "value": 'rule family="ipv4" source address="10.30.8.0/24" port port="443" protocol="tcp" reject'},
        ])
        view = endpoint_access_snapshot(self.store.get("servers", "a"))
        self.assertEqual(view["state"], "reported")
        self.assertEqual(view["total"], 2)
        self.assertEqual([(row["action"], row["destination_port"]) for row in view["rows"]], [("deny", "443/tcp"), ("allow", "80/tcp")])
        self.assertEqual(view["rows"][0]["sources"], ["10.30.8.0/24"])
        self.assertEqual(view["zones"][0]["sources"], ["10.30.0.0/16"])
        self.assertEqual(view["zones"][1]["interfaces"], ["ens192"])
        self.assertTrue(view["zones"][1]["is_default"])

    def test_endpoint_access_labels_cached_inventory_after_agent_stops_reporting(self):
        server = self.store.get("servers", "a")
        server["last_seen"] = stamp(now() - timedelta(hours=1))
        view = endpoint_access_snapshot(server)
        self.assertEqual(view["state"], "stale")
        self.assertEqual(view["rows"][0]["status"], "Last reported")
        self.assertEqual(view["observed_at"], server["firewall_snapshot"]["collected_at"])
        missing = endpoint_access_snapshot({key: value for key, value in server.items() if key != "firewall_snapshot"})
        self.assertEqual(missing["state"], "unavailable")
        self.assertEqual(missing["rows"], [])

    def test_preview_binds_explicit_targets_and_before_after_unmatched_impact(self):
        plan = self.draft(hosts=["a", "b", "c"], operation="replace", new_value="8080/tcp")
        self.assertEqual(plan["preview"]["matched_host_count"], 2)
        self.assertEqual(plan["preview"]["unmatched_server_ids"], ["c"])
        self.assertEqual(len(plan["preview"]["before"]), 3)
        self.assertEqual({row["value"] for row in plan["preview"]["after"]}, {"8080/tcp"})
        self.assertEqual(plan["server_ids"], ["a", "b", "c"])
        self.assertEqual(set(plan["operations_by_server"]), {"a", "b"})
        self.assertEqual(len(plan["plan_digest"]), 64)

    def test_risky_change_requires_two_distinct_steps_and_current_typed_challenge(self):
        plan = self.draft()
        old_policy, old_etag = self.store.assignment("a")
        self.assertTrue(plan["requires_double_confirmation"])
        self.assertEqual(old_policy["firewall_changes"], [])
        first = self.store.confirm_firewall_change(plan["id"], {"confirmation_nonce": plan["confirmation_nonce"], "confirmation_count": 200, "challenge": plan["confirmation_phrase"]}, "admin")
        self.assertEqual(first["status"], "awaiting_second_confirmation")
        self.assertEqual(first["confirmation_count"], 1)
        self.assertNotEqual(first["confirmation_nonce"], plan["confirmation_nonce"])
        for bad in ({"confirmation_nonce": plan["confirmation_nonce"], "challenge": plan["confirmation_phrase"]}, {"confirmation_nonce": first["confirmation_nonce"], "challenge": "wrong"}):
            with self.assertRaises(WorkflowConflict):
                self.store.confirm_firewall_change(plan["id"], bad, "admin")
        self.assertEqual(self.store.get("firewall_changes", plan["id"])["confirmation_count"], 1)
        queued = self.store.confirm_firewall_change(plan["id"], {"confirmation_nonce": first["confirmation_nonce"], "challenge": first["confirmation_phrase"], "server_ids": ["c"]}, "admin")
        current, tag = self.store.assignment("a")
        self.assertEqual(queued["status"], "queued")
        self.assertEqual(queued["confirmation_count"], 2)
        self.assertEqual(current["version"], old_policy["version"])
        self.assertNotEqual(tag, old_etag)
        self.assertEqual(current["firewall_changes"][0]["expected_snapshot_digest"], queued["snapshot_digests"]["a"])
        self.assertEqual(self.store.assignment("c")[0]["firewall_changes"], [])

    def test_log_only_removal_uses_one_review_but_existing_deny_requires_second(self):
        normal = self.draft(kind="rich_rule", value=self.log["value"], hosts=["a"])
        self.assertFalse(normal["requires_double_confirmation"])
        self.assertEqual(self.queue(normal)["confirmation_count"], 1)
        deny = {"scope": "runtime", "zone": "public", "kind": "rich_rule", "value": 'rule source address="192.0.2.0/24" drop', "editable": True, "action": "accept", "risk": "low"}
        self.report("b", [self.log, deny])
        risky = self.draft(kind="rich_rule", value=self.log["value"], hosts=["b"])
        self.assertTrue(risky["requires_double_confirmation"])
        imported = self.store.get("servers", "b")["firewall_snapshot"]["rules"]
        self.assertEqual(next(rule for rule in imported if rule["value"] == deny["value"])["risk"], "high")

    def test_tags_snapshot_drift_and_expiry_invalidate_before_confirmation(self):
        plan = self.draft(hosts=["a"])
        self.store.update_server("a", {"tags": {"application": "changed"}}, "admin")
        with self.assertRaises(WorkflowConflict):
            self.store.confirm_firewall_change(plan["id"], {"confirmation_nonce": plan["confirmation_nonce"]}, "admin")
        self.assertEqual(self.store.get("firewall_changes", plan["id"])["status"], "invalidated")
        second = self.draft(hosts=["b"])
        self.report("b", [self.port, {**self.port, "value": "443/tcp"}])
        with self.assertRaises(WorkflowConflict):
            self.store.confirm_firewall_change(second["id"], {"confirmation_nonce": second["confirmation_nonce"]}, "admin")
        third = self.draft(hosts=["b"])
        with patch("controller.firewall.now", return_value=parse_time(third["expires_at"]) + timedelta(seconds=1)):
            with self.assertRaises(WorkflowConflict):
                self.store.confirm_firewall_change(third["id"], {"confirmation_nonce": third["confirmation_nonce"]}, "admin")
        self.assertEqual(self.store.get("firewall_changes", third["id"])["status"], "expired")

    def test_read_only_kinds_and_malformed_replacement_are_rejected(self):
        target = {"scope": "runtime", "zone": "public", "kind": "target", "value": "DROP", "editable": True}
        self.report("a", [target])
        with self.assertRaises(ValueError):
            self.draft(kind="target", value="DROP", hosts=["a"])
        with self.assertRaises(ValueError):
            self.draft(hosts=["b"], operation="replace", new_value="80/tcp\n--panic-on")

    def test_results_are_host_and_digest_authorized_and_do_not_advance_policy(self):
        queued = self.queue(self.draft(hosts=["a"]))
        result = {"id": queued["id"], "plan_digest": queued["plan_digest"], "status": "preview", "message": "Local apply opt-in disabled"}
        before = self.store.get("servers", "a")["applied_version"]
        with self.assertRaises(PermissionError):
            self.report("b", firewall_change_results=[result])
        with self.assertRaises(PermissionError):
            self.report("a", firewall_change_results=[{**result, "plan_digest": "0" * 64}])
        response = self.report("a", firewall_change_results=[result])
        self.assertEqual(response["ack_firewall_change_ids"], [queued["id"]])
        self.assertEqual(self.store.get("servers", "a")["applied_version"], before)
        self.assertEqual(self.store.get("firewall_changes", queued["id"])["status"], "preview")
        self.assertEqual(self.store.assignment("a")[0]["firewall_changes"], [])
        response = self.report("a", firewall_change_results=[result])
        self.assertEqual(response["ack_firewall_change_ids"], [queued["id"]])

    def test_any_any_targets_and_unrestricted_accepts_are_recomputed_high_risk(self):
        for kind, value in (("target", "ACCEPT"), ("zone_target", "ACCEPT"), ("rich_rule", "rule accept"), ("rich_rule", 'rule family="ipv4" source address="0.0.0.0/0" accept'), ("rich_rule", 'rule family="ipv6" source address="::/0" accept'), ("port", "1-65535/tcp")):
            with self.subTest(kind=kind, value=value):
                self.assertEqual(classify(kind, value), ("accept", "high"))
        self.assertEqual(classify("rich_rule", 'rule source address="10.0.0.0/24" accept')[1], "medium")

    def test_multiline_policy_inventory_is_read_only_and_custom_service_ports_are_not_guessed(self):
        service = {"scope": "runtime", "zone": "public", "kind": "service", "value": "ssh", "editable": True, "ports": [{"port": "2022", "protocol": "tcp"}]}
        policy = {"scope": "runtime", "zone": "", "kind": "policy", "value": "example\n  target: DROP\n  services: ssh", "editable": True}
        self.report("a", [service, policy])
        self.report("b", [{**service, "ports": [{"port": "22", "protocol": "tcp"}]}])
        data = self.store.firewall_inventory()
        common = next(rule for rule in data["common_rules"] if rule["kind"] == "service")
        self.assertEqual(common["port_resolution"], "mixed")
        self.assertEqual(common["ports"], [])
        exact = self.store.firewall_inventory({"a"})["common_rules"]
        self.assertEqual(next(rule for rule in exact if rule["kind"] == "service")["ports"], [{"port": "2022", "protocol": "tcp"}])
        self.assertFalse(next(rule for rule in exact if rule["kind"] == "policy")["editable"])

    def test_cancelled_or_expired_queued_changes_are_not_delivered(self):
        queued = self.queue(self.draft(hosts=["a"]))
        self.store.cancel_firewall_change(queued["id"], "admin")
        self.assertEqual(self.store.assignment("a")[0]["firewall_changes"], [])
        other = self.queue(self.draft(hosts=["b"]))
        with patch("controller.firewall.now", return_value=parse_time(other["expires_at"]) + timedelta(seconds=1)):
            self.assertEqual(self.store.assignment("b")[0]["firewall_changes"], [])


if __name__ == "__main__":
    unittest.main()
