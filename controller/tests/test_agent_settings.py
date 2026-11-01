import copy
import tempfile
import unittest

from controller import agent_settings as settings
from controller.firewall import WorkflowConflict
from controller.store import Store, digest


class AgentSettingsTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.store = Store(self.temporary.name)
        with self.store.meta() as db:
            settings.initialize(db)
        for identifier, application, capabilities in (("billing", "billing", [settings.CAPABILITY]), ("payments", "payments", [settings.CAPABILITY]), ("old", "billing", [])):
            self.store.report(identifier, {"hostname": identifier, "ips": ["10.1.1." + str(len(identifier))], "listeners": [], "capabilities": capabilities, "firewalld_state": "running"})
            self.store.update_server(identifier, {"tags": {"application": application, "environment": "production"}}, "admin")
        self.group = self.store.save_group({"name": "Billing", "type": "dynamic", "selector": {"application": "billing"}, "server_ids": []}, "admin")

    def body(self, rules=(), **defaults):
        return {"expected_revision": settings.get(self.store)["revision"], "defaults": {**settings.DEFAULTS, **defaults}, "rules": list(rules)}

    def rule(self, identifier, **extra):
        return {"id": identifier, "name": identifier, "enabled": True, "priority": 0, "server_ids": [], "group_ids": [], "selector": {"application": "billing"}, "control_interval_seconds": 30, **extra}

    def test_read_and_preview_are_nonmutating_and_default_only_changes_exact_hosts(self):
        before = {table: self.store.all(table) for table in ("servers", "policies", "audit")}
        body = self.body([self.rule("billing-fast", control_interval_seconds=10, discovery_interval_seconds=120)])
        result = settings.preview(self.store, body)
        self.assertEqual(result["effective_change_count"], 2)
        self.assertEqual({row["server_id"] for row in result["affected_servers"]}, {"billing", "old"})
        self.assertEqual(settings.get(self.store)["revision"], 0)
        self.assertEqual({table: self.store.all(table) for table in before}, before)
        saved = settings.save(self.store, body, "super-admin")
        self.assertEqual(saved["revision"], 1)
        self.assertEqual(settings.assignment(self.store, "billing")["control_interval_seconds"], 10)
        self.assertEqual(settings.assignment(self.store, "payments")["control_interval_seconds"], 30)
        self.assertEqual(settings.assignment(self.store, "old")["discovery_interval_seconds"], 120)
        self.assertEqual(next(row for row in saved["servers"] if row["server_id"] == "old")["status"], "unsupported")

    def test_priority_specificity_and_stable_tie_break_resolve_each_interval_independently(self):
        rules = [self.rule("tag", control_interval_seconds=25, discovery_interval_seconds=600),
                 self.rule("group", selector={}, group_ids=[self.group["id"]], control_interval_seconds=20),
                 self.rule("server-z", selector={}, server_ids=["billing"], control_interval_seconds=15),
                 self.rule("server-a", selector={}, server_ids=["billing"], control_interval_seconds=10),
                 self.rule("high-priority", priority=9, selector={"application": "billing", "environment": "production"}, discovery_interval_seconds=90, control_interval_seconds=None)]
        settings.save(self.store, self.body(rules), "super-admin")
        result = settings.assignment(self.store, "billing")
        self.assertEqual(result["control_interval_seconds"], 10)
        self.assertEqual(result["discovery_interval_seconds"], 90)
        self.assertEqual(result["field_rules"], {"control_interval_seconds": "server-a", "discovery_interval_seconds": "high-priority"})
        self.assertEqual(result["digest"], digest({"control_interval_seconds": 10, "discovery_interval_seconds": 90}))
        rules.reverse()
        settings.save(self.store, self.body(rules), "super-admin")
        self.assertEqual(settings.assignment(self.store, "billing")["digest"], result["digest"])

    def test_higher_priority_overrides_more_specific_rules_and_disabled_rules_do_nothing(self):
        rules = [self.rule("server", selector={}, server_ids=["billing"], priority=0, control_interval_seconds=10), self.rule("high-tag", priority=1, control_interval_seconds=25), self.rule("disabled", enabled=False, priority=100, control_interval_seconds=5)]
        settings.save(self.store, self.body(rules), "super-admin")
        self.assertEqual(settings.assignment(self.store, "billing")["control_interval_seconds"], 25)

    def test_dynamic_group_membership_is_resolved_from_current_central_tags(self):
        settings.save(self.store, self.body([self.rule("group-only", selector={}, group_ids=[self.group["id"]], control_interval_seconds=15)]), "super-admin")
        self.assertEqual(settings.assignment(self.store, "payments")["control_interval_seconds"], 30)
        self.store.update_server("payments", {"tags": {"application": "billing"}}, "admin")
        self.assertEqual(settings.assignment(self.store, "payments")["control_interval_seconds"], 15)
        self.store.update_server("billing", {"tags": {"application": "payments"}}, "admin")
        self.assertEqual(settings.assignment(self.store, "billing")["control_interval_seconds"], 30)

    def test_stale_and_invalid_settings_cannot_change_polling_or_security(self):
        valid = self.body([self.rule("valid")])
        settings.save(self.store, valid, "super-admin")
        with self.assertRaises(WorkflowConflict):
            settings.save(self.store, valid, "super-admin")
        for change in ({"control_interval_seconds": 4}, {"control_interval_seconds": True}, {"discovery_interval_seconds": 59}, {"discovery_interval_seconds": 86401}):
            with self.assertRaises(ValueError):
                settings.save(self.store, self.body(**change), "super-admin")
        for rule in (self.rule("bad", enforce=True), self.rule("bad", selector={}, group_ids=["missing"]), self.rule("bad", selector={}, server_ids=[]), self.rule("bad", selector="application=billing")):
            with self.assertRaises(ValueError):
                settings.save(self.store, self.body([rule]), "super-admin")
        self.assertEqual(settings.get(self.store)["revision"], 1)

    def test_exact_receipts_distinguish_pending_current_error_and_unsupported(self):
        settings.save(self.store, self.body(control_interval_seconds=90), "super-admin")
        desired = settings.assignment(self.store, "billing")
        def send(receipt):
            with self.store.meta() as db:
                server = self.store._get(db, "servers", "billing")
                settings.report(self.store, db, server, {"polling_settings": receipt})
                self.store._put(db, "servers", server)
            return next(row for row in settings.get(self.store)["servers"] if row["server_id"] == "billing")
        self.assertEqual(send({"version": 0, "digest": desired["digest"], "status": "applied"})["status"], "pending")
        self.assertEqual(send({"version": 1, "digest": desired["digest"], "status": "applied"})["status"], "current")
        self.assertEqual(send({"version": 1, "digest": desired["digest"], "status": "error", "error": "Cannot persist remote settings"})["status"], "error")
        self.assertEqual(send({"version": 9, "digest": desired["digest"], "status": "applied"})["status"], "ahead_of_controller")

    def test_noop_reorder_keeps_revision_and_generated_ids_match_preview(self):
        rule = self.rule("ignored")
        del rule["id"]
        preview = settings.preview(self.store, self.body([rule]))
        saved = settings.save(self.store, self.body([rule]), "super-admin")
        self.assertEqual(preview["after"]["rules"][0]["id"], saved["rules"][0]["id"])
        self.assertEqual(settings.save(self.store, self.body(saved["rules"]), "super-admin")["revision"], 1)

    def test_restore_of_older_controller_configuration_keeps_inventory_and_newer_receipt(self):
        first = settings.save(self.store, self.body(control_interval_seconds=90), "super-admin")
        settings.save(self.store, self.body(control_interval_seconds=45), "super-admin")
        settings.save(self.store, self.body(control_interval_seconds=15), "super-admin")
        retained = settings.assignment(self.store, "billing")
        with self.store.meta() as db:
            self.store._put(db, "agent_polling_settings", {key: value for key, value in first.items() if key not in ("servers", "capability", "precedence")})
        receipt = {"version": retained["version"], "digest": retained["digest"], "status": "applied"}
        self.store.report("billing", {"hostname": "after-restore", "ips": ["10.99.0.1"], "listeners": [], "capabilities": [settings.CAPABILITY], "polling_settings": receipt})
        row = next(row for row in settings.get(self.store)["servers"] if row["server_id"] == "billing")
        self.assertEqual(row["hostname"], "after-restore")
        self.assertEqual(row["status"], "ahead_of_controller")
        self.assertEqual(row["observed"]["version"], 3)
        self.assertEqual(row["desired"]["version"], 1)
        self.assertEqual(self.store.server("billing")["ips"], ["10.99.0.1"])
