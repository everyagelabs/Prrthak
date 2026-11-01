import tempfile
import unittest
from datetime import timedelta
from unittest.mock import patch

from controller import metadata, metadata_csv
from controller.firewall import WorkflowConflict
from controller.store import Store, now, stamp


class CSVMetadataTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = Store(self.temp.name)
        self.noida = self.location("Noida 81 DC")
        self.mumbai = self.location("Mumbai DC")

    def location(self, name):
        return self.store.save_location({"name": name, "location": "India", "type": "datacenter"}, "admin")

    def host(self, identifier="one", ip="10.241.1.10", **extra):
        self.store.report(identifier, {"hostname": identifier, "ips": [ip], "listeners": [],
            "firewalld_state": "running", **extra})

    def preview(self, text):
        return metadata_csv.preview(self.store, {"csv": text}, "admin")

    def apply(self, plan):
        return metadata_csv.apply(self.store, plan["id"], {"confirmation_nonce": plan["confirmation_nonce"]}, "admin")

    def test_standard_alias_headers_bom_quotes_and_literal_values(self):
        locations = self.store.locations()
        value = '\ufeffIP Address,Application Name,DC Name,Zone,Criticality,tag.owner\r\n10.241.1.10,"billing, payments",Noida 81 DC,production,high,"Finance\nOperations"\r\n'
        parsed = metadata_csv.parse_csv(value, locations)
        self.assertEqual(parsed["errors"], [])
        row = parsed["rows"][0]
        self.assertEqual(row["line"], 2)
        self.assertEqual(row["tags"], {"application": "billing, payments", "network_zone": "production", "criticality": "high", "owner": "Finance\nOperations"})
        self.assertEqual(row["location_id"], self.noida["id"])
        formula = metadata_csv.parse_csv('ip,application\n10.241.1.10,"=HYPERLINK(""https://example.invalid"")"\n', locations)
        self.assertEqual(formula["errors"], [])
        self.assertTrue(formula["rows"][0]["tags"]["application"].startswith("=HYPERLINK"))

    def test_bad_headers_ips_values_and_quoting_block_whole_file(self):
        bad = (
            "application\nbilling\n", "ip,IP Address\n10.1.1.1,10.1.1.2\n",
            "ip,tag.dc\n10.1.1.1,Noida\n", "ip,password\n10.1.1.1,secret\n",
            "ip,application\n10.1.1.1/24,billing\n", "ip,application\nwebserver,billing\n",
            "ip,application\nfe80::1%eth0,billing\n", "ip,dc\n10.1.1.1,Missing DC\n",
            "ip,application\n10.1.1.1,billing\n10.1.1.1,payments\n",
            'ip,application\n10.1.1.1,"broken\n', "ip,application\n10.1.1.1,billing,extra\n",
            "ip,application\n10.1.1.1," + "x" * 129 + "\n",
            "ip,hostname\n10.1.1.1,informational\n", "ip,application,dc\n10.1.1.1,,\n",
        )
        for text in bad:
            with self.subTest(text=text):
                plan = self.preview(text)
                self.assertEqual(plan["status"], "invalid")
                self.assertTrue(plan["errors"])
                self.assertNotIn("confirmation_nonce", plan)
                with self.assertRaises(WorkflowConflict):
                    metadata_csv.apply(self.store, plan["id"], {}, "admin")
        self.assertEqual(self.store.all("metadata_ip_profiles"), [])

    def test_size_and_row_limits(self):
        for value in (None, "ip\n" + "x" * metadata_csv.MAX_BYTES, "ip\na\0b\n"):
            with self.subTest(value_type=type(value).__name__), self.assertRaises(ValueError):
                metadata_csv.parse_csv(value, self.store.locations())
        with patch.object(metadata_csv, "MAX_ROWS", 2):
            parsed = metadata_csv.parse_csv("ip,application\n10.1.1.1,a\n10.1.1.2,b\n10.1.1.3,c\n", self.store.locations())
        self.assertTrue(any("data rows" in error["message"] for error in parsed["errors"]))

    def test_preview_is_readonly_then_applies_current_and_future_profiles(self):
        self.host()
        plan = self.preview("ip,application,dc,tag.owner\n10.241.1.10,billing,Noida 81 DC,finance\n10.241.1.11,payments,Noida 81 DC,payments-team\n")
        self.assertEqual(plan["status"], "draft")
        self.assertEqual(plan["summary"]["current_servers"], 1)
        self.assertEqual(plan["summary"]["future_ips"], 1)
        self.assertEqual(plan["summary"]["changed_servers"], 1)
        self.assertEqual(self.store.server("one")["tags"], {})
        self.assertEqual(self.store.all("metadata_ip_profiles"), [])
        applied = self.apply(plan)
        self.assertEqual(applied["status"], "applied")
        self.assertNotIn("confirmation_nonce", applied)
        current = self.store.server("one")
        self.assertEqual(current["tags"], {"application": "billing", "owner": "finance"})
        self.assertEqual(current["location_id"], self.noida["id"])
        self.assertEqual(current["tag_sources"]["application"]["type"], "csv")
        self.host("future", "10.241.1.11", tags={"application": "forged"}, location_id=self.mumbai["id"])
        future = self.store.server("future")
        self.assertEqual(future["tags"]["application"], "payments")
        self.assertEqual(future["location_id"], self.noida["id"])
        self.host("future", "10.241.1.11", tags={"application": "different"})
        self.assertEqual(self.store.server("future")["tags"]["application"], "payments")

    def test_manual_overrides_and_removal_tombstones_survive_csv_and_blank_cells(self):
        self.host()
        self.store.update_server("one", {"tags": {"application": "manual-app"}, "location_id": self.mumbai["id"]}, "admin")
        plan = self.preview("ip,application,dc,tag.owner\n10.241.1.10,billing,Noida 81 DC,finance\n")
        self.assertEqual(set(plan["rows"][0]["overridden_fields"]), {"application", "location_id"})
        self.apply(plan)
        self.assertEqual(self.store.server("one")["tags"], {"application": "manual-app", "owner": "finance"})
        self.assertEqual(self.store.server("one")["location_id"], self.mumbai["id"])
        self.store.update_server("one", {"tag_updates": {"owner": None}}, "admin")
        self.apply(self.preview("ip,application,dc,tag.owner\n10.241.1.10,,,replacement\n"))
        self.assertNotIn("owner", self.store.server("one")["tags"])
        profile = self.store.get("metadata_ip_profiles", "10.241.1.10")
        self.assertEqual(profile["tags"]["application"], "billing")
        self.assertEqual(profile["location_id"], self.noida["id"])
        self.store.update_server("one", {"reset_tag_keys": ["application", "owner"], "location_mode": "automatic"}, "admin")
        server = self.store.server("one")
        self.assertEqual(server["tags"], {"application": "billing", "owner": "replacement"})
        self.assertEqual(server["location_id"], self.noida["id"])

    def test_shared_ip_or_conflicting_multihomed_defaults_cannot_be_applied(self):
        self.host("one")
        self.host("two")
        shared = self.preview("ip,application\n10.241.1.10,billing\n")
        self.assertEqual(shared["status"], "invalid")
        self.assertEqual(shared["summary"]["current_servers"], 2)
        self.assertEqual(shared["rows"][0]["server_ids"], ["one", "two"])
        self.assertEqual(self.store.all("metadata_ip_profiles"), [])
        self.host("two", "10.241.1.11")
        self.store.report("one", {"hostname": "one", "ips": ["10.241.1.10", "10.241.1.12"], "listeners": [], "firewalld_state": "running"})
        conflict = self.preview("ip,application\n10.241.1.10,billing\n10.241.1.12,payments\n")
        self.assertEqual(conflict["status"], "invalid")
        self.assertTrue(any("Different CSV" in error["message"] for error in conflict["errors"]))

    def test_plan_rejects_ip_metadata_rule_or_profile_drift_but_not_heartbeat(self):
        self.host()
        plan = self.preview("ip,application\n10.241.1.10,billing\n")
        self.host(discovery_performed=False)
        self.apply(plan)
        with self.assertRaises(WorkflowConflict):
            self.apply(plan)
        stale = self.preview("ip,application\n10.241.1.10,payments\n")
        self.store.update_server("one", {"tag_updates": {"owner": "manual"}}, "admin")
        with self.assertRaises(WorkflowConflict):
            self.apply(stale)
        future = self.preview("ip,application\n10.241.1.20,platform\n")
        self.host("new", "10.241.1.20")
        with self.assertRaises(WorkflowConflict):
            self.apply(future)
        expires = self.preview("ip,application\n10.241.1.10,payments\n")
        with patch("controller.metadata.now", return_value=now() + timedelta(minutes=11)):
            with self.assertRaises(WorkflowConflict):
                self.apply(expires)

    def test_apply_is_atomic_and_compiles_once(self):
        self.host()
        plan = self.preview("ip,application\n10.241.1.10,billing\n10.241.1.11,payments\n")
        with patch.object(self.store, "compile_all", side_effect=RuntimeError("test compile failure")):
            with self.assertRaises(RuntimeError):
                self.apply(plan)
        self.assertEqual(self.store.all("metadata_ip_profiles"), [])
        self.assertEqual(self.store.server("one")["tags"], {})
        self.assertEqual(self.store.get("metadata_plans", plan["id"])["status"], "draft")
        original = self.store.compile_all
        with patch.object(self.store, "compile_all", wraps=original) as compiler:
            self.apply(plan)
        self.assertEqual(compiler.call_count, 1)
        self.assertEqual(len(self.store.all("metadata_ip_profiles")), 2)

    def test_exact_csv_location_overrides_subnet_until_manually_pinned_or_reset(self):
        subnet = metadata.subnet_preview(self.store, {"cidr": "10.241.0.0/16", "location_id": self.noida["id"]})
        metadata.subnet_apply(self.store, subnet["id"], {"confirmation_nonce": subnet["confirmation_nonce"]}, "admin")
        self.host()
        self.assertEqual(self.store.server("one")["location_source"]["type"], "subnet")
        self.apply(self.preview("ip,application,dc\n10.241.1.10,billing,Mumbai DC\n"))
        self.assertEqual(self.store.server("one")["location_id"], self.mumbai["id"])
        self.assertEqual(self.store.server("one")["location_source"]["type"], "csv")
        self.store.update_server("one", {"location_id": self.noida["id"]}, "admin")
        self.host()
        self.assertEqual(self.store.server("one")["location_source"]["type"], "manual")
        self.store.update_server("one", {"location_mode": "automatic"}, "admin")
        self.assertEqual(self.store.server("one")["location_id"], self.mumbai["id"])
        self.host(ip="10.241.2.10")
        self.assertEqual(self.store.server("one")["location_id"], self.noida["id"])
        self.assertEqual(self.store.server("one")["location_source"]["type"], "subnet")

    def test_ipv6_canonical_profiles_and_preview_survive_controller_restart(self):
        plan = self.preview("ip,application,dc\n2001:0DB8:0:0:0:0:0:10,billing,Noida 81 DC\n")
        self.assertEqual(plan["rows"][0]["ip"], "2001:db8::10")
        restarted = Store(self.temp.name)
        metadata_csv.apply(restarted, plan["id"], {"confirmation_nonce": plan["confirmation_nonce"]}, "admin")
        restarted.report("v6", {"hostname": "v6", "ips": ["2001:db8::10"], "listeners": [], "firewalld_state": "running"})
        self.assertEqual(restarted.server("v6")["tags"]["application"], "billing")
        self.assertEqual(restarted.server("v6")["location_id"], self.noida["id"])
        duplicate = metadata_csv.preview(restarted, {"csv": "ip,application\n2001:db8::10,billing\n2001:0db8::10,payments\n"}, "admin")
        self.assertEqual(duplicate["status"], "invalid")

    def test_profile_listing_pages_current_future_and_ambiguous_bindings(self):
        self.host()
        self.apply(self.preview("ip,application\n10.241.1.10,billing\n10.241.1.11,payments\n2001:db8::10,platform\n"))
        self.host("two", "10.241.1.11")
        self.host("three", "10.241.1.11")
        page = metadata_csv.listing(self.store, limit=2)
        self.assertEqual(page["total"], 3)
        self.assertEqual([profile["ip"] for profile in page["items"]], ["10.241.1.10", "10.241.1.11"])
        self.assertEqual(page["items"][0]["binding_status"], "current")
        self.assertEqual(page["items"][1]["binding_status"], "conflict")
        self.assertEqual(page["items"][1]["server_ids"], ["three", "two"])
        future = metadata_csv.listing(self.store, limit=2, offset=2)["items"][0]
        self.assertEqual(future["binding_status"], "future")
        self.assertEqual(future["server_count"], 0)
        self.assertEqual(future["tags"], {"application": "platform"})
        for arguments in ({"limit": 0}, {"limit": 501}, {"limit": True}, {"offset": -1}):
            with self.subTest(arguments=arguments), self.assertRaises(ValueError):
                metadata_csv.listing(self.store, **arguments)

    def test_remove_future_profile_is_reviewed_durable_and_frees_location_guard(self):
        self.apply(self.preview("ip,application,dc\n2001:db8::10,billing,Mumbai DC\n"))
        with self.assertRaisesRegex(ValueError, "CSV profile"):
            self.store.delete_location(self.mumbai["id"], "admin")
        plan = metadata_csv.delete_preview(self.store, "2001:0DB8:0:0:0:0:0:10", "admin")
        self.assertEqual(plan["kind"], "csv_profile_delete")
        self.assertEqual(plan["summary"]["future_ips"], 1)
        self.assertEqual(plan["rows"][0]["profile_before"]["tags"], {"application": "billing"})
        self.assertIsNone(plan["rows"][0]["profile_after"])
        self.assertIsNotNone(self.store.get("metadata_ip_profiles", "2001:db8::10"))
        restarted = Store(self.temp.name)
        metadata_csv.apply(restarted, plan["id"], {"confirmation_nonce": plan["confirmation_nonce"]}, "admin")
        with self.assertRaises(KeyError):
            restarted.get("metadata_ip_profiles", "2001:db8::10")
        restarted.delete_location(self.mumbai["id"], "admin")
        self.assertFalse(any(location["id"] == self.mumbai["id"] for location in restarted.locations()))
        restarted.report("future", {"hostname": "future", "ips": ["2001:db8::10"], "listeners": [], "firewalld_state": "running"})
        self.assertEqual(restarted.server("future")["tags"], {})
        self.assertIsNone(restarted.server("future")["location_id"])

    def test_profile_removal_keeps_manual_values_and_uses_subnet_fallback(self):
        subnet = metadata.subnet_preview(self.store, {"cidr": "10.241.0.0/16", "location_id": self.noida["id"]})
        metadata.subnet_apply(self.store, subnet["id"], {"confirmation_nonce": subnet["confirmation_nonce"]}, "admin")
        self.host()
        self.host("two", "10.241.1.11")
        self.apply(self.preview("ip,application,dc,tag.owner\n10.241.1.10,billing,Mumbai DC,finance\n10.241.1.11,payments,Mumbai DC,payments\n"))
        self.store.update_server("one", {"tag_updates": {"application": "manual-app", "owner": None}, "location_id": self.mumbai["id"]}, "admin")
        protected = metadata_csv.delete_preview(self.store, "10.241.1.10", "admin")
        self.assertEqual(protected["summary"]["changed_servers"], 0)
        self.assertEqual(set(protected["rows"][0]["overridden_fields"]), {"application", "owner", "location_id"})
        self.apply(protected)
        self.assertEqual(self.store.server("one")["tags"], {"application": "manual-app"})
        self.assertEqual(self.store.server("one")["location_id"], self.mumbai["id"])
        fallback = metadata_csv.delete_preview(self.store, "10.241.1.11", "admin")
        self.assertEqual(fallback["rows"][0]["after"]["tags"], {})
        self.assertEqual(fallback["rows"][0]["after"]["location_source"]["type"], "subnet")
        self.assertEqual(fallback["rows"][0]["after"]["location_id"], self.noida["id"])
        original = self.store.compile_all
        with patch.object(self.store, "compile_all", wraps=original) as compiler:
            self.apply(fallback)
        self.assertEqual(compiler.call_count, 1)
        self.assertEqual(self.store.server("two")["location_id"], self.noida["id"])
        self.store.update_server("one", {"reset_tag_keys": ["application", "owner"], "location_mode": "automatic"}, "admin")
        self.assertEqual(self.store.server("one")["tags"], {})
        self.assertEqual(self.store.server("one")["location_id"], self.noida["id"])

    def test_profile_delete_stale_nonce_expiry_replay_and_atomic_failure_guards(self):
        self.apply(self.preview("ip,application\n10.241.1.10,billing\n"))
        stale = metadata_csv.delete_preview(self.store, "10.241.1.10", "admin")
        self.apply(self.preview("ip,application\n10.241.1.10,payments\n"))
        with self.assertRaises(WorkflowConflict):
            self.apply(stale)
        plan = metadata_csv.delete_preview(self.store, "10.241.1.10", "admin")
        with self.assertRaises(WorkflowConflict):
            metadata_csv.apply(self.store, plan["id"], {"confirmation_nonce": "wrong"}, "admin")
        with patch("controller.metadata.now", return_value=now() + timedelta(minutes=11)):
            with self.assertRaises(WorkflowConflict):
                self.apply(plan)
        with patch.object(self.store, "compile_all", side_effect=RuntimeError("test compile failure")):
            with self.assertRaises(RuntimeError):
                self.apply(plan)
        self.assertEqual(self.store.get("metadata_ip_profiles", "10.241.1.10")["tags"], {"application": "payments"})
        self.assertEqual(self.store.get("metadata_plans", plan["id"])["status"], "draft")
        self.apply(plan)
        with self.assertRaises(WorkflowConflict):
            self.apply(plan)
        with self.assertRaises(KeyError):
            metadata_csv.delete_preview(self.store, "10.241.1.10", "admin")

    def test_removing_one_multihomed_profile_retains_other_default_and_updates_provenance(self):
        self.store.report("one", {"hostname": "one", "ips": ["10.241.1.10", "10.241.1.11"], "listeners": [], "firewalld_state": "running"})
        self.apply(self.preview("ip,application,dc\n10.241.1.10,billing,Mumbai DC\n10.241.1.11,billing,Mumbai DC\n"))
        plan = metadata_csv.delete_preview(self.store, "10.241.1.10", "admin")
        self.assertEqual(plan["summary"]["changed_servers"], 1)
        self.assertEqual(plan["rows"][0]["after"]["tags"], {"application": "billing"})
        self.assertEqual(plan["rows"][0]["after"]["tag_sources"]["application"]["ips"], ["10.241.1.11"])
        self.apply(plan)
        self.assertEqual(self.store.server("one")["tags"], {"application": "billing"})
        self.assertEqual(self.store.server("one")["location_source"]["ips"], ["10.241.1.11"])


if __name__ == "__main__":
    unittest.main()
