from copy import deepcopy
from datetime import timedelta
import tempfile
import unittest

from controller.endpoint_diagnostics import UFW_EXPORT, fast_discovery, preparation_status
from controller.store import Store, now, parse_time, stamp


class EndpointDiagnosticsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = Store(self.temp.name)
        self.at = now() - timedelta(seconds=2)
        self.report = {
            "hostname": "billing-01", "ips": ["192.0.2.42"],
            "os": "rhel", "os_version": "9", "firewalld_version": "1.3.4",
            "firewall_backend": "nftables", "firewalld_state": "running",
            "listeners": [{"port": 2022, "protocol": "tcp", "process": "sshd"}],
            "discovery_performed": True, "discovered_at": stamp(self.at),
            "capabilities": ["fast_listener_discovery_v1"],
            "fast_discovery": self.fast(),
        }

    def fast(self, **updates):
        return {"backend": "inet_diag", "status": "active", "interval_seconds": 5,
                "checked_at": stamp(), **updates}

    def prepared(self, **updates):
        return {
            "schema_version": 1, "status": "assessment_only", "checked_at": stamp(),
            "install_dependencies": False, "dependencies_changed": False,
            "ufw": {"installed": True, "active": True, "assessment": "exported",
                    "migration_required": True, "export_path": UFW_EXPORT},
            "firewalld": {"installed": True}, **updates,
        }

    def test_receipts_survive_public_detail_and_inventory_without_exposing_rules(self):
        self.store.report("host", {**self.report, "preparation_status": self.prepared()})
        for server in (self.store.server("host"), next(x for x in self.store.servers() if x["id"] == "host")):
            self.assertEqual(server["fast_discovery"]["interval_seconds"], 5)
            self.assertTrue(server["preparation_status"]["ufw"]["active"])
            self.assertNotIn("active", server["preparation_status"]["firewalld"])
            self.assertEqual(server["preparation_status"]["ufw"]["export_path"], UFW_EXPORT)

    def test_cached_status_cannot_freshen_or_delete_listener_inventory(self):
        self.store.report("host", {**self.report, "preparation_status": self.prepared()})
        before = self.store.get("servers", "host")
        self.store.report("host", {**self.report, "discovery_performed": False, "listeners": [],
                                  "fast_discovery": self.fast(status="error", error="snapshot unavailable")})
        after = self.store.get("servers", "host")
        self.assertEqual(after["listeners"], before["listeners"])
        self.assertEqual(after["last_discovery_at"], before["last_discovery_at"])
        self.assertEqual(after["preparation_status"], before["preparation_status"])
        self.assertEqual(after["fast_discovery"]["status"], "error")
        self.assertFalse(any(a["kind"] == "service_down" for a in self.store.all("alerts")))

    def test_fresh_restart_inventory_updates_os_and_services_with_same_central_identity(self):
        self.store.report("host", self.report)
        self.store.update_server("host", {"tags": {"application": "billing", "owner": "finance"}}, "admin")
        before = self.store.get("servers", "host")
        self.store.report("host", {**self.report, "os_version": "9.6", "firewalld_version": "2.3.1",
            "discovered_at": stamp(), "listeners": self.report["listeners"] + [{"port": 8443, "protocol": "tcp", "process": "billing"}],
            "tags": {"application": "agent-must-not-override"}})
        after = self.store.get("servers", "host")
        self.assertEqual(after["os_version"], "9.6")
        self.assertEqual(after["firewalld_version"], "2.3.1")
        self.assertEqual(after["tags"], before["tags"])
        self.assertEqual(after["desired_version"], before["desired_version"])
        self.assertEqual(len(self.store.servers()), 1)
        self.assertEqual({x["port"] for x in after["listeners"]}, {2022, 8443})
        self.assertTrue(any(x["kind"] == "service_discovered" and x.get("details", {}).get("port") == 8443 for x in self.store.all("alerts")))

    def test_legacy_agent_downgrade_clears_fast_claim_but_retains_preparation_history(self):
        self.store.report("host", {**self.report, "preparation_status": self.prepared()})
        legacy = {key: value for key, value in self.report.items() if key != "fast_discovery"}
        self.store.report("host", {**legacy, "capabilities": []})
        server = self.store.get("servers", "host")
        self.assertNotIn("fast_discovery", server)
        self.assertEqual(server["preparation_status"]["status"], "assessment_only")

    def test_invalid_diagnostics_reject_whole_report_without_inventory_or_identity_changes(self):
        self.store.report("host", self.report)
        before = self.store.get("servers", "host")
        invalid = [
            {"fast_discovery": self.fast(interval_seconds=True)},
            {"fast_discovery": self.fast(interval_seconds=5.0)},
            {"fast_discovery": self.fast(status=[])},
            {"fast_discovery": self.fast(checked_at=stamp(now() + timedelta(minutes=2)))},
            {"fast_discovery": self.fast(error="é" * 513)},
            {"fast_discovery": self.fast(last_change_at=stamp(now() + timedelta(seconds=10)))},
            {"preparation_status": self.prepared(schema_version=1.0)},
            {"preparation_status": self.prepared(raw_rules="private firewall rules")},
            {"preparation_status": self.prepared(install_dependencies="false")},
        ]
        bad_export = self.prepared()
        bad_export["ufw"]["export_path"] = "/etc/shadow"
        invalid.append({"preparation_status": bad_export})
        for fields in invalid:
            with self.subTest(fields=fields):
                with self.assertRaises(ValueError):
                    self.store.report("host", {**self.report, "hostname": "must-not-persist", **fields})
                self.assertEqual(self.store.get("servers", "host"), before)

    def test_unknown_service_states_remain_unknown_and_false_is_not_dropped(self):
        value = self.prepared()
        value["ufw"].pop("active")
        value["firewalld"]["active"] = False
        result = preparation_status(value)
        self.assertNotIn("active", result["ufw"])
        self.assertIs(result["firewalld"]["active"], False)
        self.assertIs(result["dependencies_changed"], False)
        self.assertEqual(value, result)
        self.assertIsNot(value["ufw"], result["ufw"])

    def test_export_reference_requires_matching_assessment_and_contains_no_rule_payload(self):
        for extra in ({"rules": "secret rules"}, {"export_path": ""}, {"assessment": "error"}, {"active": 1}):
            value = deepcopy(self.prepared())
            value["ufw"].update(extra)
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                preparation_status(value)
        status = fast_discovery(self.fast(last_change_at=stamp(self.at)))
        self.assertLessEqual(parse_time(status["last_change_at"]), parse_time(status["checked_at"]))


if __name__ == "__main__":
    unittest.main()
