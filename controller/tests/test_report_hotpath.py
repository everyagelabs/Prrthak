from datetime import timedelta
import tempfile
import unittest
from unittest.mock import patch

from controller.store import Store, now, stamp


class ReportAndHealthHotpathTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.store = Store(self.temp.name)
        self.report = {"hostname": "billing-host", "ips": ["192.0.2.10"], "listeners": [{"port": 2022, "protocol": "tcp"}], "firewalld_state": "running", "discovery_performed": True, "discovered_at": stamp()}
        self.store.report("host", self.report)

    def test_stable_report_persists_once_and_retains_central_metadata_and_version(self):
        self.store.update_server("host", {"tags": {"application": "billing"}}, "fixture")
        original = self.store.get("servers", "host")
        writes, real = [], self.store._put
        def track(db, table, value):
            if table == "servers": writes.append(value["id"])
            return real(db, table, value)
        with patch.object(self.store, "_put", side_effect=track):
            self.store.report("host", {**self.report, "discovery_performed": False, "tags": {"application": "attacker"}})
        current = self.store.get("servers", "host")
        self.assertEqual(writes, ["host"])
        self.assertEqual(current["tags"], original["tags"])
        self.assertEqual(current["_compiled"], original["_compiled"])
        self.assertEqual(current["desired_version"], original["desired_version"])

    def test_preview_receipt_and_polling_ack_are_durable_with_one_host_write(self):
        bundle = self.store.assignment("host")[0]
        value = {**self.report, "discovery_performed": False, "managed_enforcement": {"status": "preview", "version": bundle["version"], "digest": bundle["digest"], "last_good_version": 0, "last_good_digest": "", "updated_at": stamp()}, "polling_settings": {"version": bundle["polling_settings"]["version"], "digest": bundle["polling_settings"]["digest"], "status": "applied"}}
        writes, real = [], self.store._put
        def track(db, table, document):
            if table == "servers": writes.append(document["id"])
            return real(db, table, document)
        with patch.object(self.store, "_put", side_effect=track): self.store.report("host", value)
        current = self.store.get("servers", "host")
        self.assertEqual(writes, ["host"])
        self.assertEqual(current["managed_enforcement"]["digest"], bundle["digest"])
        self.assertEqual(current["agent_polling_observed"]["status"], "applied")
        self.assertEqual(len(self.store.all("managed_outcomes")), 1)

    def test_invalid_late_field_rolls_back_without_partial_report(self):
        before = self.store.get("servers", "host")
        with self.assertRaises(ValueError):
            self.store.report("host", {**self.report, "hostname": "must-not-persist", "polling_settings": {"version": -1}})
        self.assertEqual(self.store.get("servers", "host"), before)

    def test_steady_health_of_five_thousand_hosts_does_not_rewrite_inventory(self):
        at = now()
        with self.store.meta() as db:
            seed = self.store._get(db, "servers", "host")
            for index in range(4999):
                self.store._put(db, "servers", {**seed, "id": "health-" + str(index), "hostname": "health-" + str(index), "last_seen": stamp(at), "last_discovery_at": stamp(at)})
        self.store.evaluate_health(at)
        original, writes = self.store._put, []
        def track(db, table, value):
            if table == "servers": writes.append(value["id"])
            return original(db, table, value)
        with patch.object(self.store, "_put", side_effect=track): self.store.evaluate_health(at + timedelta(seconds=30))
        self.assertEqual(writes, [])

    def test_health_expiry_badge_and_offline_transitions_still_persist(self):
        at = now()
        with self.store.meta() as db:
            server = self.store._get(db, "servers", "host")
            server["listeners"][0].update(is_new=True, new_until=stamp(at + timedelta(seconds=5)))
            self.store._put(db, "servers", server)
        self.store.evaluate_health(at)
        self.store.evaluate_health(at + timedelta(seconds=6))
        self.assertFalse(self.store.get("servers", "host")["listeners"][0]["is_new"])
        self.store.evaluate_health(at + timedelta(hours=1))
        self.assertEqual(self.store.get("servers", "host")["status"], "offline")
        self.assertTrue(any(value["kind"] == "agent_offline" for value in self.store.all("alerts")))
