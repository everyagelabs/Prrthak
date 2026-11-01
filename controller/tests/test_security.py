import tempfile
import unittest
from datetime import timedelta
from unittest.mock import patch

from controller.store import Store, parse_time, stamp


class SecurityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = Store(self.temp.name)
        self.base = parse_time(stamp())
        self.monitor = {"enabled": True, "status": "active", "rate_limited": True, "dropped_events": 0}
        self.report(0, [], performed=True)

    def event(self, identifier, port=6000, offset=0, **extra):
        point = stamp(self.base + timedelta(seconds=offset))
        return {"event_id": identifier, "source_ip": "192.0.2.15", "destination_ip": "10.0.0.1", "port": port, "protocol": "tcp", "count": 1, "first_seen": point, "last_seen": point, "inventory_checked_at": point, "kind": "unexpected_port_hit", "listening": False, **extra}

    def report(self, offset, events, performed=False, monitor=None):
        point = self.base + timedelta(seconds=offset)
        with patch("controller.store.now", return_value=point), patch("controller.security.now", return_value=point):
            return self.store.report("host", {"hostname": "host", "ips": ["10.0.0.1"], "listeners": [{"port": 22, "protocol": "tcp", "address": "0.0.0.0", "process": "sshd"}], "firewalld_state": "running", "discovery_performed": performed, "discovered_at": stamp(point), "security_monitor": monitor if monitor is not None else self.monitor, "security_events": events})

    def alerts(self, kind=None):
        return [alert for alert in self.store.all("alerts") if (not kind or alert["kind"] == kind) and alert["kind"] in ("unexpected_port_hit", "possible_scan")]

    def test_event_ids_are_transactionally_deduplicated_and_port_counts_aggregate_one_hour(self):
        event = self.event("first", count=2)
        first = self.report(1, [event])
        self.assertEqual(first["ack_security_event_ids"], ["first"])
        self.report(2, [event])
        self.assertEqual(self.alerts("unexpected_port_hit")[0]["details"]["count"], 2)
        self.report(60, [self.event("second", offset=30, count=3)])
        self.assertEqual(len(self.alerts("unexpected_port_hit")), 1)
        self.assertEqual(self.alerts("unexpected_port_hit")[0]["details"]["count"], 5)
        with self.assertRaises(ValueError):
            self.report(61, [{**event, "count": 99}])

    def test_five_distinct_ports_in_event_time_window_create_one_possible_scan(self):
        newest = self.event("newest", port=6004, offset=120)
        self.report(200, [newest])
        older = [self.event(f"older-{index}", port=6000 + index, offset=index * 30) for index in range(4)]
        self.report(260, older)
        scans = self.alerts("possible_scan")
        self.assertEqual(len(scans), 1)
        self.assertEqual(scans[0]["details"]["ports"], [6000, 6001, 6002, 6003, 6004])
        self.assertIn("possible", scans[0]["details"]["assessment"])
        self.report(300, [self.event("sixth", port=6005, offset=150)])
        self.assertEqual(len(self.alerts("possible_scan")), 1)

    def test_receipt_burst_does_not_turn_slow_observations_into_a_scan(self):
        events = [self.event(f"slow-{index}", port=7000 + index, offset=index * 100) for index in range(5)]
        self.report(500, events)
        self.assertEqual(self.alerts("possible_scan"), [])

    def test_known_listener_and_stale_check_and_disabled_monitor_are_excluded_but_acknowledged(self):
        known = self.event("known", port=22, offset=1, inventory_checked_at=stamp(self.base))
        stale = self.event("stale", port=6001, offset=181, inventory_checked_at=stamp(self.base))
        response = self.report(200, [known, stale])
        self.assertEqual(set(response["ack_security_event_ids"]), {"known", "stale"})
        self.assertEqual(self.alerts(), [])
        self.report(220, [self.event("off", offset=210)], monitor={"enabled": False, "status": "off"})
        self.assertEqual(self.alerts(), [])

    def test_newer_signed_closed_port_check_overrules_old_listening_cache(self):
        response = self.report(61, [self.event("stopped-ssh", port=22, offset=60)])
        self.assertEqual(response["ack_security_event_ids"], ["stopped-ssh"])
        self.assertEqual(len(self.alerts("unexpected_port_hit")), 1)
        self.assertEqual(self.alerts("unexpected_port_hit")[0]["details"]["port"], 22)

    def test_spooled_monitoring_observation_survives_current_monitor_disabled(self):
        event = self.event("spooled", offset=30, observed_while_monitoring=True)
        self.report(3600, [event], monitor={"enabled": False, "status": "off"})
        self.assertEqual(len(self.alerts("unexpected_port_hit")), 1)
        self.assertEqual(self.alerts("unexpected_port_hit")[0]["details"]["last_seen"], event["last_seen"])
        self.report(3660, [event], monitor={"enabled": False, "status": "off"})
        self.assertEqual(self.alerts("unexpected_port_hit")[0]["details"]["count"], 1)

    def test_alert_dedupe_uses_indexed_pointer_instead_of_history_scan(self):
        original = self.store._all
        def guarded(db, table):
            if table == "alerts":
                raise AssertionError("Security ingestion must not scan all historical alerts")
            return original(db, table)
        with patch.object(self.store, "_all", side_effect=guarded):
            self.report(1, [self.event("indexed-first")])
            self.report(2, [self.event("indexed-second", offset=1)])
        self.assertEqual(self.alerts("unexpected_port_hit")[0]["details"]["count"], 2)

    def test_nonlocal_destination_ignored_and_unknown_or_old_observations_rejected(self):
        self.report(1, [self.event("forwarded", destination_ip="10.0.0.99")])
        self.assertEqual(self.alerts(), [])
        with self.assertRaises(ValueError):
            self.report(2, [self.event("unknown", listening=True)])
        with self.assertRaises(ValueError):
            self.report(3, [self.event("too-old", offset=-86401)])


if __name__ == "__main__":
    unittest.main()
