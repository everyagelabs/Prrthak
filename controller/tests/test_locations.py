import tempfile
import unittest

from controller.store import Store, stamp


class LocationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = Store(self.temp.name)
        self.report("one", "10.0.0.1")
        self.report("two", "10.0.0.2")

    def report(self, identifier, ip, **extra):
        return self.store.report(identifier, {"hostname": identifier, "ips": [ip], "listeners": [], "firewalld_state": "running", "apply_status": "preview", **extra})

    def location(self, name="Mumbai", **extra):
        return self.store.save_location({"name": name, "location": name + ", India", "type": "datacenter", **extra}, "admin")

    def policy(self, **extra):
        return self.store.save_policy({"name": "Located service", "mode": "monitor", "selector": {}, "services": [{"port": 8080, "protocol": "tcp", "sources": ["10.99.0.0/24"]}], **extra}, "admin")

    def test_location_must_be_created_first_and_server_has_one_separate_identity(self):
        for identifier in ("missing", ["one", "two"], {"name": "Mumbai"}):
            with self.assertRaises(ValueError):
                self.store.update_server("one", {"location_id": identifier}, "admin")
        first, second = self.location(), self.location("Hyderabad")
        self.store.update_server("one", {"location_id": first["id"], "tags": {"application": "billing", "owner": "finance"}}, "admin")
        value = self.store.update_server("one", {"location_id": second["id"]}, "admin")
        self.assertEqual(value["location_id"], second["id"])
        self.assertEqual(value["location"]["name"], "Hyderabad")
        self.assertEqual(value["tags"], {"application": "billing", "owner": "finance"})
        self.assertEqual(self.store.locations()[0]["server_count"], 1)
        self.assertIsNone(self.store.update_server("one", {"location_id": None}, "admin")["location"])

    def test_agent_and_existing_dc_tags_never_create_or_assign_catalogue(self):
        self.report("one", "10.0.0.1", location_id="invented", tags={"dc": "Invented"})
        with self.store.meta() as db:
            server = self.store._get(db, "servers", "one")
            server["tags"] = {"DC": "Mumbai", "application": "billing"}
            self.store._put(db, "servers", server)
        restarted = Store(self.temp.name)
        self.assertEqual(restarted.locations(), [])
        value = restarted.server("one")
        self.assertIsNone(value["location_id"])
        self.assertEqual(value["location_migration_candidates"], {"DC": "Mumbai"})
        self.location()
        self.assertIsNone(self.store.server("one")["location_id"])

    def test_reserved_location_tag_aliases_rejected_while_custom_tags_are_independent(self):
        for key in ("dc", "DC", "location", "Location_ID", "data-center", "data_centre", "datacenter", "location_type"):
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.store.update_server("one", {"tags": {key: "arbitrary"}}, "admin")
        custom = {"application": "billing", "criticality": "high", "cloud_provider": "example", "region": "east", "account": "bank"}
        self.assertEqual(self.store.update_server("one", {"tags": custom}, "admin")["tags"], custom)
        with self.assertRaises(ValueError):
            self.store.create_token("invalid", "admin", {"dc": "Mumbai"})

    def test_name_geographic_location_edit_keeps_uuid_policy_and_group_membership(self):
        location = self.location()
        self.store.update_server("one", {"location_id": location["id"]}, "admin")
        policy = self.policy(selector={"DC": "Mumbai"})
        group = self.store.save_group({"name": "DC members", "type": "dynamic", "selector": {"dc": location["key"]}}, "admin")
        self.assertEqual(policy["selector"], {"location_id": location["id"]})
        self.assertEqual(group["selector"], {"location_id": location["id"]})
        before = self.store.assignment("one")[0]
        changed = self.store.save_location({**location, "name": "Primary west", "location": "New street, Mumbai"}, "admin", location["id"])
        self.assertEqual(changed["id"], location["id"])
        self.assertEqual(changed["key"], location["key"])
        self.assertEqual(self.store.assignment("one")[0]["version"], before["version"])
        self.assertEqual(self.store.groups()[0]["member_ids"], ["one"])
        self.assertEqual(self.store.server("one")["location"]["name"], "Primary west")
        self.assertEqual(self.policy(name="Legacy alias still resolves", selector={"dc": "Mumbai"})["selector"], {"location_id": location["id"]})
        with self.assertRaises(ValueError):
            self.location("Mumbai")
        for field in ("id", "key"):
            with self.assertRaises(ValueError):
                self.store.save_location({**changed, field: "different"}, "admin", changed["id"])

    def test_legacy_policy_alias_remains_bound_on_rename_and_unknown_never_matches_all(self):
        location = self.location()
        self.store.update_server("one", {"location_id": location["id"]}, "admin")
        legacy = {"id": "legacy", "revision": 1, "name": "Migrated policy", "selector": {"DC": "Mumbai"}, "services": [{"port": 2022, "protocol": "tcp", "sources": ["10.99.0.0/24"], "source_selector": {}}], "mode": "monitor", "created_at": stamp(), "updated_at": stamp()}
        with self.store.meta() as db:
            self.store._put(db, "policies", legacy)
            self.store.compile_all(db)
        before = self.store.assignment("one")[0]
        self.store.save_location({**location, "name": "West primary"}, "admin", location["id"])
        self.assertEqual(self.store.assignment("one")[0]["version"], before["version"])
        self.assertEqual(self.store.assignment("two")[0]["services"], [])
        with self.store.meta() as db:
            self.store._put(db, "policies", {**legacy, "selector": {"dc": "Unknown"}})
            self.store.compile_all(db)
        self.assertEqual(self.store.assignment("one")[0]["services"], [])
        self.assertEqual(self.store.assignment("two")[0]["services"], [])
        with self.assertRaises(ValueError):
            self.policy(selector={"location_id": "unknown"})

    def test_location_source_selector_updates_only_effective_policy_changes(self):
        first, second = self.location(), self.location("Hyderabad")
        self.store.update_server("one", {"location_id": first["id"]}, "admin")
        self.policy(services=[{"port": 8080, "protocol": "tcp", "sources": [], "source_selector": {"location_id": first["id"]}}])
        before = self.store.assignment("two")[0]
        self.assertEqual(before["services"][0]["sources"], ["10.0.0.1/32"])
        self.store.save_location({**first, "name": "Renamed"}, "admin", first["id"])
        self.assertEqual(self.store.assignment("two")[0]["version"], before["version"])
        self.store.update_server("one", {"location_id": second["id"]}, "admin")
        changed = self.store.assignment("two")[0]
        self.assertGreater(changed["version"], before["version"])
        self.assertEqual(changed["services"][0]["sources"], [])

    def test_delete_blocks_assigned_and_referenced_location_then_allows_unused(self):
        location = self.location()
        self.store.update_server("one", {"location_id": location["id"]}, "admin")
        with self.assertRaises(ValueError):
            self.store.delete_location(location["id"], "admin")
        self.store.update_server("one", {"location_id": None}, "admin")
        policy = self.policy(selector={"location_id": location["id"]})
        with self.assertRaises(ValueError):
            self.store.delete_location(location["id"], "admin")
        self.store.delete_policy(policy["id"], "admin")
        self.store.delete_location(location["id"], "admin")
        self.assertEqual(self.store.locations(), [])

    def test_identity_only_enrollment_and_dashboard_location_cannot_be_overridden_by_agent(self):
        location = self.location()
        with self.assertRaises(ValueError):
            self.store.create_token("New billing host", "admin", {"application": "billing"}, location["id"])
        with self.assertRaises(ValueError):
            self.store.create_token("Unknown", "admin", {}, "unknown")
        token = self.store.create_token("New billing host", "admin")
        enrolled = self.store.enroll(token["token"], "new-host", "-----BEGIN CERTIFICATE REQUEST-----\nrequest", lambda *args: ("certificate", "ca"))
        server_id = enrolled["server_id"]
        self.assertIsNone(self.store.server(server_id)["location_id"])
        self.store.update_server(server_id, {"location_id": location["id"], "tag_updates": {"application": "billing"}}, "admin")
        self.assertEqual(self.store.server(server_id)["location_id"], location["id"])
        self.report(server_id, "10.0.0.3", location_id="forged", location={"name": "forged"})
        self.assertEqual(self.store.server(server_id)["location_id"], location["id"])
        self.assertEqual(self.store.overview()["locations"][0]["id"], location["id"])

    def test_invalid_catalogue_records_rejected_and_empty_cloud_is_valid(self):
        for value in ({"name": "No geography", "type": "datacenter"}, {"name": "Invalid", "location": "Delhi", "type": "zone"}, {"name": "", "location": "Delhi", "type": "cloud"}):
            with self.assertRaises(ValueError):
                self.store.save_location(value, "admin")
        value = self.location("Cloud Europe", type="cloud", provider="example", region="eu-1")
        self.assertEqual(value["type"], "cloud")
        self.assertEqual(self.store.locations()[0]["server_count"], 0)


if __name__ == "__main__":
    unittest.main()
