import tempfile
import unittest

from controller import firewall
from controller.store import Store, stamp


class ExtendedFirewallTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = Store(self.temp.name)
        self.store.lab_approvals = True
        self.caps = list(firewall.EXTENDED_CAPABILITIES.values())
        self.snapshot_caps = self.caps + ["firewall_changes_v1", "runtime-direct-visible", "permanent-direct-visible"]
        self.direct = "ipv4 filter INPUT 0 -s 10.4.0.0/24 -p tcp -m tcp --dport 8080 -j ACCEPT"
        self.redirect = "port=8080:proto=tcp:toport=8443:toaddr="
        self.rules = [{"scope": scope, "zone": "public", "kind": "target", "value": "ACCEPT", "editable": scope == "permanent"} for scope in ("runtime", "permanent")]
        self.rules += [{"scope": scope, "zone": "", "kind": "direct", "value": self.direct, "editable": True} for scope in ("runtime", "permanent")]
        self.rules += [{"scope": scope, "zone": "public", "kind": "forward_port", "value": self.redirect, "editable": True} for scope in ("runtime", "permanent")]
        self.report()

    def report(self, *, rules=None, caps=None, snapshot_caps=None, **extra):
        return self.store.report("host", {"hostname": "host", "ips": ["10.0.0.8"], "listeners": [], "firewalld_state": "running", "capabilities": self.caps if caps is None else caps,
            "firewall_snapshot": {"collected_at": stamp(), "status": "ok", "rules": self.rules if rules is None else rules, "capabilities": self.snapshot_caps if snapshot_caps is None else snapshot_caps}, **extra})

    def draft(self, kind="target", old="ACCEPT", new="DROP", scopes=None, operation="replace"):
        return self.store.create_firewall_change({"name": "Exact extended edit", "server_ids": ["host"],
            "rule_key": firewall.fingerprints("permanent", "" if kind == "direct" else "public", kind, old)[1],
            "new_value": new, "operation": operation, "scopes": scopes or ["permanent"]}, "admin")

    def queue(self, plan):
        first = self.store.confirm_firewall_change(plan["id"], {"confirmation_nonce": plan["confirmation_nonce"]}, "admin")
        self.assertEqual(first["status"], "awaiting_second_confirmation")
        return self.store.confirm_firewall_change(plan["id"], {"confirmation_nonce": first["confirmation_nonce"], "challenge": first["confirmation_phrase"]}, "admin")

    def test_permanent_target_is_editable_in_common_view_but_never_removed_or_runtime_changed(self):
        common = next(row for row in self.store.firewall_inventory()["common_rules"] if row["kind"] == "target")
        self.assertTrue(common["editable"])
        self.assertEqual(common["editable_scopes"], ["permanent"])
        plan = self.draft()
        self.assertTrue(plan["requires_double_confirmation"])
        self.assertEqual(plan["preview"]["before"][0]["scope"], "permanent")
        self.assertIn("running target remains unchanged", plan["preview"]["warnings"][0])
        self.queue(plan)
        for values in ({"operation": "remove", "new": None}, {"scopes": ["runtime"]}, {"new": "CONTINUE"}):
            with self.subTest(values=values), self.assertRaises(ValueError):
                self.draft(**values)

    def test_direct_and_local_redirect_use_exact_values_and_independent_review(self):
        for kind, old, new in (("direct", self.direct, self.direct.replace("8080", "8443")), ("forward_port", self.redirect, self.redirect.replace("8443", "9443"))):
            with self.subTest(kind=kind):
                plan = self.draft(kind, old, new, scopes=["runtime", "permanent"])
                self.assertTrue(plan["requires_double_confirmation"])
                self.assertEqual(len(plan["operations_by_server"]["host"]), 2)
                self.assertEqual({row["old_value"] for row in plan["operations_by_server"]["host"]}, {old})
                self.queue(plan)

    def test_explicit_decision_preserves_direct_arguments_and_only_replaces_permanent_target(self):
        direct = "ipv4 filter INPUT 0 -s 10.4.0.0/24  -j   ACCEPT -p tcp --dport 8080"
        self.report(rules=[{**rule, "value": direct} if rule["kind"] == "direct" else rule for rule in self.rules])
        for kind, old, zone, scopes, expected in (
            ("direct", direct, "", ["runtime", "permanent"], direct.replace("ACCEPT", "REJECT")),
            ("target", "ACCEPT", "public", ["permanent"], "REJECT"),
        ):
            with self.subTest(kind=kind):
                request = {"name": "Reviewed verdict", "server_ids": ["host"],
                           "rule_key": firewall.fingerprints("permanent", zone, kind, old)[1],
                           "operation": "replace", "decision": "reject", "scopes": scopes}
                plan = self.store.create_firewall_change(request, "admin")
                self.assertTrue(plan["requires_double_confirmation"])
                self.assertEqual({row["scope"] for row in plan["preview"]["after"]}, set(scopes))
                self.assertEqual({row["value"] for row in plan["preview"]["after"]}, {expected})
        with self.assertRaisesRegex(ValueError, "view-only"):
            self.store.create_firewall_change({**request, "scopes": ["runtime"]}, "admin")
        with self.assertRaisesRegex(ValueError, "does not support changing its decision"):
            self.store.create_firewall_change({**request, "rule_key": firewall.fingerprints(
                "permanent", "public", "forward_port", self.redirect)[1]}, "admin")

    def test_missing_capabilities_or_scope_evidence_fail_closed(self):
        self.report(caps=[])
        with self.assertRaisesRegex(ValueError, "Upgrade"):
            self.draft()
        self.report(snapshot_caps=[])
        self.assertFalse(next(row for row in self.store.firewall_inventory()["common_rules"] if row["kind"] == "target")["editable"])
        self.report(snapshot_caps=[cap for cap in self.snapshot_caps if cap != "permanent-direct-visible"])
        with self.assertRaisesRegex(ValueError, "complete runtime and permanent"):
            self.draft("direct", self.direct, None, operation="remove")
        self.report(rules=[row for row in self.rules if not (row["kind"] == "target" and row["scope"] == "runtime")])
        with self.assertRaisesRegex(ValueError, "matching runtime and permanent zone"):
            self.draft("forward_port", self.redirect, None, operation="remove")

    def test_unsupported_nat_direct_and_shell_syntax_are_never_promoted(self):
        invalid = [("direct", self.direct + " ; touch /tmp/no"), ("direct", self.direct.replace("filter", "nat")),
                   ("direct", self.direct.replace("INPUT", "FORWARD")), ("direct", self.direct.replace("-s 10.4.0.0/24", "-s example.test")),
                   ("direct", self.direct + " -j DROP"), ("direct", self.direct.replace("-m tcp", "-m conntrack")),
                   ("forward_port", self.redirect + "10.1.0.5"), ("forward_port", self.redirect.replace("toport=8443", "toport=0"))]
        for kind, value in invalid:
            with self.subTest(value=value), self.assertRaises(ValueError):
                firewall.typed_value(kind, value)
        self.assertEqual(firewall.resolved_ports("direct", self.direct, []), [{"port": "8080", "protocol": "tcp"}])
        self.assertEqual(firewall.classify("direct", self.direct), ("accept", "high"))

    def test_current_configuration_and_capability_changes_invalidate_old_review(self):
        plan = self.draft()
        self.report(caps=[])
        with self.assertRaises(firewall.WorkflowConflict):
            self.queue(plan)

    def test_semantic_aliases_cannot_add_then_delete_the_same_extended_rule(self):
        aliases = [self.direct.replace(" -p", "  -p"), self.direct.replace("INPUT 0", "INPUT 00"),
                   self.direct.replace("10.4.0.0/24", "10.4.0.9/24"), self.direct.replace("-m tcp ", "")]
        for value in aliases:
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "textual alias"):
                self.draft("direct", self.direct, value)
        with self.assertRaisesRegex(ValueError, "textual alias"):
            self.draft("forward_port", self.redirect, self.redirect.replace("8080", "08080"))

    def test_configured_channel_binding_is_not_heartbeat_timestamp_noise(self):
        server = self.store.get("servers", "host")
        original = firewall.target_digest(server)
        server["configuration_state"] = {"controller_url": "https://control.example:8787", "control_url": "https://control.example:8788", "discovery_url": "https://control.example:8789", "config_digest": "a" * 64}
        changed = firewall.target_digest(server)
        self.assertNotEqual(original, changed)
        server["configuration_state"]["updated_at"] = stamp()
        self.assertEqual(changed, firewall.target_digest(server))


if __name__ == "__main__":
    unittest.main()
