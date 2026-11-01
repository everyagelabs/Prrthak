import tempfile
import unittest

from controller.store import Store


class ApplicationGroupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = Store(self.temp.name)

    def host(self, identifier, application=None):
        self.store.report(identifier, {"hostname": identifier, "ips": ["10.1.0." + str(len(self.store.servers()) + 1)],
            "listeners": [], "firewalld_state": "running"})
        if application is not None:
            self.store.update_server(identifier, {"tags": {"application": application}}, "admin")

    def group(self, application):
        return next(group for group in self.store.groups() if group.get("application") == application)

    def policy(self, identifier):
        return self.store.save_policy({"name": "Shared group access", "mode": "monitor", "group_ids": [identifier],
            "services": [{"port": 8080, "protocol": "tcp", "sources": ["10.90.0.0/24"]}]}, "admin")

    def test_each_admin_approved_application_has_one_live_dynamic_group(self):
        for identifier, application in (("a", "billing"), ("b", "platform"), ("c", "payments"), ("d", "billing"), ("e", "orders")):
            self.host(identifier, application)
        groups = self.store.groups()
        self.assertEqual({group["application"] for group in groups}, {"billing", "platform", "payments", "orders"})
        self.assertEqual(len(groups), 4)
        self.assertEqual(self.group("billing")["member_ids"], ["a", "d"])
        self.assertTrue(all(group["type"] == "dynamic" and group["managed"] and group["origin"] == "application" for group in groups))
        self.assertEqual(self.store.overview()["groups"], groups)

    def test_existing_saved_application_group_keeps_id_name_and_editability(self):
        existing = self.store.save_group({"name": "Billing fleet", "type": "dynamic", "selector": {"application": "billing"}}, "admin")
        self.host("billing-one", "billing")
        current = self.group("billing")
        self.assertEqual(current["id"], existing["id"])
        self.assertEqual(current["name"], "Billing fleet")
        self.assertFalse(current["managed"])
        self.assertEqual(current["origin"], "saved")
        self.assertEqual(len(self.store.groups()), 1)
        self.store.save_group({"name": "Billing critical", "type": "dynamic", "selector": {"application": "billing", "criticality": "high"}}, "admin", existing["id"])
        self.assertEqual(len(self.store.groups()), 2)
        self.assertNotEqual(self.group("billing")["id"], existing["id"])
        self.assertTrue(self.group("billing")["managed"])

    def test_deleting_unreferenced_saved_representative_creates_missing_automatic_group(self):
        existing = self.store.save_group({"name": "Billing", "type": "dynamic", "selector": {"application": "billing"}}, "admin")
        self.host("billing-one", "billing")
        self.store.delete_group(existing["id"], "admin")
        automatic = self.group("billing")
        self.assertNotEqual(automatic["id"], existing["id"])
        self.assertTrue(automatic["managed"])
        self.assertEqual(automatic["member_ids"], ["billing-one"])

    def test_custom_and_static_groups_survive_and_do_not_duplicate_exact_application(self):
        self.host("billing-one", "billing")
        automatic = self.group("billing")
        reused = self.store.save_group({"name": "Billing endpoints", "type": "dynamic", "selector": {"application": "billing"}}, "admin")
        self.assertEqual(reused["id"], automatic["id"])
        self.assertEqual(reused["name"], "Billing endpoints")
        self.store.save_group({"name": "Critical billing", "type": "dynamic", "selector": {"application": "billing", "criticality": "high"}}, "admin")
        self.store.save_group({"name": "Hand picked", "type": "static", "server_ids": ["billing-one"]}, "admin")
        groups = self.store.groups()
        self.assertEqual(len(groups), 3)
        self.assertEqual(sum(group.get("application") == "billing" for group in groups), 1)
        self.assertEqual(sum(group["managed"] for group in groups), 1)

    def test_automatic_membership_is_protected_but_display_name_can_change(self):
        self.host("billing-one", "billing")
        automatic = self.group("billing")
        for invalid in ({"type": "static", "server_ids": ["billing-one"]}, {"type": "dynamic", "selector": {"application": "payments"}}, {"type": "dynamic", "selector": {"application": "billing", "criticality": "high"}}):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                self.store.save_group({"name": "Changed", **invalid}, "admin", automatic["id"])
        with self.assertRaises(ValueError):
            self.store.delete_group(automatic["id"], "admin")
        renamed = self.store.save_group({"name": "Billing service estate", "type": "dynamic", "selector": automatic["selector"]}, "admin", automatic["id"])
        self.assertEqual(renamed["id"], automatic["id"])
        self.assertEqual(renamed["application"], "billing")
        self.assertTrue(renamed["managed"])

    def test_membership_follows_tags_without_broadening_empty_group_policy(self):
        self.host("billing-one", "billing")
        self.host("outside", "payments")
        group = self.group("billing")
        self.policy(group["id"])
        self.assertEqual(self.store.assignment("billing-one")[0]["services"][0]["port"], 8080)
        self.assertEqual(self.store.assignment("outside")[0]["services"], [])
        self.store.update_server("billing-one", {"tags": {"application": "platform"}}, "admin")
        empty = self.group("billing")
        self.assertEqual(empty["id"], group["id"])
        self.assertEqual(empty["member_ids"], [])
        self.assertEqual(self.store.assignment("billing-one")[0]["services"], [])
        self.assertEqual(self.store.assignment("outside")[0]["services"], [])
        self.host("new-billing", "billing")
        self.assertEqual(self.group("billing")["id"], group["id"])
        self.assertEqual(self.group("billing")["member_ids"], ["new-billing"])
        self.assertEqual(self.store.assignment("new-billing")[0]["services"][0]["port"], 8080)

    def test_startup_backfills_groups_without_changing_policy_versions(self):
        self.host("platform-one", "platform")
        original = self.group("platform")
        version = self.store.assignment("platform-one")[0]["version"]
        # Mimic an existing deployment from before automatic groups.
        with self.store.meta() as db:
            db.execute("DELETE FROM groups WHERE id=?", (original["id"],))
        restarted = Store(self.temp.name)
        self.assertEqual(restarted.groups()[0]["id"], original["id"])
        self.assertEqual(restarted.assignment("platform-one")[0]["version"], version)

    def test_agent_cannot_invent_application_groups_but_dashboard_tags_can(self):
        self.host("reporter")
        self.store.report("reporter", {"hostname": "reporter", "ips": ["10.1.0.1"], "listeners": [], "tags": {"application": "invented"}})
        self.assertEqual(self.store.groups(), [])
        with self.assertRaises(ValueError):
            self.store.create_token("provisioned", "admin", {"application": "payments"})
        token = self.store.create_token("provisioned", "admin")
        enrollment = self.store.enroll(token["token"], "new-payments", "-----BEGIN CERTIFICATE REQUEST-----\nrequest", lambda *args: ("certificate", "ca"))
        self.assertNotIn('payments', {group.get('application') for group in self.store.groups()})
        self.store.update_server(enrollment["server_id"], {"tag_updates": {"application": "payments"}}, "admin")
        self.assertEqual(self.group("payments")["member_ids"], [enrollment["server_id"]])


if __name__ == "__main__":
    unittest.main()
