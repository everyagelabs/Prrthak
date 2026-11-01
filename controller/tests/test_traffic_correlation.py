import json
import tempfile
import unittest
from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import Mock, patch

from controller import security, traffic_correlation as correlation
from controller.store import Store, parse_time, stamp


class TrafficCorrelationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = Store(self.temp.name)
        self.base = parse_time(stamp())
        self.limits = correlation.DEFAULT_LIMITS

    def server(self, identifier, **extra):
        return {"id": identifier, "hostname": identifier, "ips": ["10.0.0." + str(int(identifier[1:]) + 1)],
                "listeners": [{"port": 22, "protocol": "tcp"}], "last_discovery_at": stamp(self.base),
                "security_monitor": {"enabled": True, "status": "active"}, **extra}

    def event(self, identifier, host="h0", offset=0, **extra):
        point = stamp(self.base + timedelta(seconds=offset))
        return {"event_id": identifier, "source_ip": "192.0.2.15", "destination_ip": self.server(host)["ips"][0],
                "port": 6000, "protocol": "tcp", "count": 1, "first_seen": point, "last_seen": point,
                "inventory_checked_at": point, "kind": "unexpected_port_hit", "listening": False, **extra}

    def clock(self, offset=0):
        point = self.base + timedelta(seconds=offset)
        return (patch("controller.store.now", return_value=point),
                patch("controller.security.now", return_value=point),
                patch.object(correlation, "now", return_value=point),
                patch.object(correlation, "DEFAULT_LIMITS", self.limits))

    def ingest(self, host, values, offset=0, **extra):
        a, b, c, d = self.clock(offset)
        with a, b, c, d, self.store.lock, self.store.meta() as db:
            return security.ingest_events(self.store, db, self.server(host, **extra), values)

    def alerts(self):
        return [alert for alert in self.store.all("alerts") if alert["kind"] == correlation.KIND]

    def state(self):
        with self.store.read_meta() as db:
            row = db.execute("SELECT data FROM security_alert_windows WHERE id=?", (correlation.STATE_ID,)).fetchone()
        return json.loads(row[0]) if row else None

    def pattern(self, offset=0, prefix="event"):
        for index in range(3):
            host = "h" + str(index)
            self.ingest(host, [self.event(prefix + host, host, offset)], offset)

    def test_report_hook_emits_exact_bounded_destinations_and_leaves_policy_unchanged(self):
        for index in range(3):
            host = "h" + str(index)
            a, b, c, d = self.clock()
            with a, b, c, d:
                result = self.store.report(host, {**self.server(host), "security_events": [self.event(host, host)], "firewalld_state": "running"})
            self.assertEqual(result["ack_security_event_ids"], [host])
        alert, = self.alerts()
        details = alert["details"]
        self.assertEqual((alert["severity"], details["source_ip"], details["protocol"], details["port"]), ("warning", "192.0.2.15", "tcp", 6000))
        self.assertEqual(details["target_server_ids"], ["h0", "h1", "h2"])
        self.assertEqual(details["destination_count"], 3)
        self.assertEqual([(item["server_id"], item["destination_ip"]) for item in details["destinations"]], [("h0", "10.0.0.1"), ("h1", "10.0.0.2"), ("h2", "10.0.0.3")])
        self.assertTrue(all(set(item) == {"server_id", "hostname", "destination_ip", "last_seen"} for item in details["destinations"]))
        self.assertEqual(self.store.all("policies"), [])
        self.assertEqual(len([item for item in self.store.all("alerts") if item["kind"] == "unexpected_port_hit"]), 3)

    def test_counts_replays_and_address_aliases_do_not_multiply_one_destination(self):
        first = self.event("first", count=100000000)
        self.ingest("h0", [first])
        self.ingest("h0", [first])
        self.ingest("h0", [self.event("new-id", destination_ip="10.0.0.90", count=100000000)], ips=["10.0.0.1", "10.0.0.90"])
        self.ingest("h1", [self.event("second-host", "h1")])
        self.assertEqual(self.alerts(), [])
        group, = self.state()["groups"].values()
        self.assertEqual(set(group["hosts"]), {"h0", "h1"})
        self.ingest("h2", [self.event("third-host", "h2")])
        self.assertEqual(self.alerts()[0]["details"]["destination_count"], 3)

    def test_source_protocol_and_port_are_separate_exact_dimensions(self):
        for host in ("h0", "h1"):
            self.ingest(host, [self.event(host, host)])
        self.ingest("h2", [self.event("udp", "h2", protocol="udp"), self.event("other-port", "h2", port=6001), self.event("other-source", "h2", source_ip="192.0.2.16")])
        self.assertEqual(self.alerts(), [])
        self.ingest("h2", [self.event("matches", "h2")])
        alert, = self.alerts()
        self.assertEqual((alert["details"]["source_ip"], alert["details"]["protocol"], alert["details"]["port"]), ("192.0.2.15", "tcp", 6000))

    def test_out_of_order_event_times_within_live_window_correlate(self):
        for index, offset in enumerate((-10, -30, -20)):
            host = "h" + str(index)
            self.ingest(host, [self.event(host, host, offset)], 0)
        self.assertEqual(self.alerts()[0]["details"]["last_seen"], stamp(self.base - timedelta(seconds=10)))

    def test_receipt_burst_old_spool_and_future_clock_do_not_extend_window(self):
        for index, offset in enumerate((-400, -260, 0)):
            host = "h" + str(index)
            self.ingest(host, [self.event(host, host, offset)], 0)
        self.assertEqual(self.alerts(), [])
        group, = self.state()["groups"].values()
        self.assertEqual(set(group["hosts"]), {"h1", "h2"})
        # Even admitted clock skew cannot combine observations >300s apart.
        self.ingest("h3", [self.event("future", "h3", 60)], 0)
        self.ingest("h4", [self.event("outside-anchor", "h4", -290)], 0)
        self.assertEqual(self.alerts(), [])

    def test_replay_preserves_acknowledgment_and_never_refreshes_event_time(self):
        self.pattern()
        alert, = self.alerts()
        with self.store.meta() as db:
            alert["status"] = "acknowledged"
            self.store._put(db, "alerts", alert)
        for index in range(3):
            host = "h" + str(index)
            self.ingest(host, [self.event("event" + host, host)], 200)
            self.ingest(host, [self.event("new-id" + host, host)], 200)
        self.assertEqual(len(self.alerts()), 1)
        self.assertEqual(self.alerts()[0]["status"], "acknowledged")
        group, = self.state()["groups"].values()
        self.assertEqual(group["latest_seen"], stamp(self.base))

    def test_cooldown_allows_later_new_window_without_reopening_old_alert(self):
        self.pattern()
        self.pattern(100, "ongoing")
        self.assertEqual(len(self.alerts()), 1)
        self.pattern(901, "later")
        self.assertEqual(len(self.alerts()), 2)

    def test_empty_observation_expiry_and_existing_prune_remove_state(self):
        self.pattern()
        with self.store.meta() as db:
            result = correlation.observe(self.store, db, self.server("h0"), [], at=self.base + timedelta(seconds=1000))
        self.assertEqual(result["groups"], 0)
        self.assertIsNone(self.state())
        self.pattern()
        with patch("controller.security.now", return_value=self.base + timedelta(seconds=1000)), self.store.meta() as db:
            security.prune(db)
        self.assertIsNone(self.state())
        self.assertEqual(len(self.alerts()), 1)

    def test_all_existing_admission_gates_still_apply(self):
        self.ingest("h0", [self.event("listener", port=22)])
        self.ingest("h1", [self.event("forwarded", "h1", destination_ip="10.99.99.99")])
        self.ingest("h2", [self.event("stale", "h2", inventory_checked_at=stamp(self.base - timedelta(seconds=181)))])
        self.ingest("h3", [self.event("off", "h3")], security_monitor={"enabled": False, "status": "off"})
        self.assertEqual(self.alerts(), [])
        self.assertIsNone(self.state())
        with self.store.read_meta() as db:
            receipts = [json.loads(row[0]) for row in db.execute("SELECT data FROM security_event_receipts")]
        self.assertEqual(len(receipts), 4)
        self.assertFalse(any(item["accepted"] for item in receipts))

    def test_shared_addresses_and_claimed_allowed_verdict_remain_ambiguous_advisory(self):
        for index in range(3):
            host = "h" + str(index)
            self.ingest(host, [self.event(host, host, destination_ip="10.0.0.99", verdict="allowed")], ips=["10.0.0.99"])
        details = self.alerts()[0]["details"]
        self.assertTrue(details["shared_destination_address"])
        self.assertEqual(details["verdict"], "observed")
        self.assertEqual(details["connection_success"], "unknown")
        self.assertEqual(details["automatic_action"], "none")
        self.assertIn("Authorized scanners", details["assessment"])
        self.assertIn("NAT/shared", details["assessment"])
        self.assertNotIn("source_server_id", details)

    def test_total_sources_tuples_and_tuples_per_source_are_bounded(self):
        self.limits = correlation.Limits(max_sources=2, max_groups=3, max_groups_per_source=2)
        events = [self.event("a1"), self.event("a2", port=6001), self.event("a3", port=6002),
                  self.event("b", source_ip="192.0.2.16"), self.event("c", source_ip="192.0.2.17")]
        self.ingest("h0", events)
        state = self.state()
        self.assertEqual(len(state["groups"]), 3)
        self.assertEqual(len({item["source_ip"] for item in state["groups"].values()}), 2)
        self.assertEqual(state["dropped_observations"], 2)
        self.assertTrue(state["coverage_limited"])

    def test_destination_cap_does_not_evict_active_members_or_reset_deduplication(self):
        self.limits = correlation.Limits(distinct_hosts=2, max_destinations=2)
        for index in range(4):
            host = "h" + str(index)
            self.ingest(host, [self.event(host, host)])
        state = self.state()
        group, = state["groups"].values()
        self.assertEqual(set(group["hosts"]), {"h0", "h1"})
        self.assertEqual(state["dropped_observations"], 2)
        self.assertEqual(len(self.alerts()), 1)

    def test_state_raw_utf8_bytes_are_rejected_before_json_decode(self):
        self.limits = correlation.Limits(max_state_bytes=1024)
        with self.store.meta() as db:
            db.execute("INSERT INTO security_alert_windows(id,expires_at,data) VALUES(?,?,?)", (correlation.STATE_ID, stamp(self.base + timedelta(hours=1)), '"' + "é" * 800 + '"'))
        loads = Mock(side_effect=AssertionError("Oversized state reached JSON decoder"))
        with patch.object(correlation, "json", SimpleNamespace(loads=loads, dumps=json.dumps)), self.store.meta() as db:
            result = correlation.observe(self.store, db, self.server("h0"), [], at=self.base, limits=self.limits)
        loads.assert_not_called()
        self.assertTrue(result["coverage_limited"])
        self.assertLess(len(json.dumps(self.state()).encode()), 1024)

    def test_legacy_unicode_expansion_resets_advisory_state_without_failing_ingest(self):
        self.ingest("h0", [self.event("first")])
        state = self.state()
        group, = state["groups"].values()
        group["hosts"]["h0"]["hostname"] = "汉" * 253
        raw = json.dumps(state, ensure_ascii=False, separators=(",", ":"))
        encoded = correlation._encode(state)
        budget = (len(raw.encode()) + len(encoded)) // 2
        self.assertGreaterEqual(budget, 1024)
        self.assertLess(len(raw.encode()), budget)
        self.assertGreater(len(encoded), budget)
        self.limits = correlation.Limits(max_state_bytes=budget)
        with self.store.meta() as db:
            db.execute("UPDATE security_alert_windows SET data=? WHERE id=?", (raw, correlation.STATE_ID))
        self.assertEqual(self.ingest("h1", [self.event("after-reset", "h1")]), ["after-reset"])
        self.assertTrue(self.state()["coverage_limited"])
        self.assertLessEqual(len(correlation._encode(self.state())), budget)

    def test_alerts_per_batch_are_bounded_and_deferred_pattern_survives(self):
        self.limits = correlation.Limits(distinct_hosts=2, max_alerts_per_batch=1)
        self.ingest("h0", [self.event("first-port"), self.event("second-port", port=6001)])
        self.ingest("h1", [self.event("first-host2", "h1"), self.event("second-host2", "h1", port=6001)])
        alert, = self.alerts()
        self.assertTrue(alert["details"]["coverage_limited"])
        pending = 6001 if alert["details"]["port"] == 6000 else 6000
        self.assertEqual(self.state()["dropped_observations"], 0)
        self.ingest("h1", [self.event("retry-pending", "h1", port=pending)])
        self.assertEqual({item["details"]["port"] for item in self.alerts()}, {6000, 6001})

    def test_malformed_stored_timestamp_overflow_resets_without_losing_receipt(self):
        self.ingest("h0", [self.event("first")])
        state = self.state()
        group, = state["groups"].values()
        group["latest_seen"] = "0001-01-01T00:00:00+01:00"
        with self.store.meta() as db:
            db.execute("UPDATE security_alert_windows SET data=? WHERE id=?", (json.dumps(state), correlation.STATE_ID))
        self.assertEqual(self.ingest("h1", [self.event("after-reset", "h1")]), ["after-reset"])
        self.assertTrue(self.state()["coverage_limited"])
        self.assertEqual(len(self.state()["groups"]), 1)

    def test_separate_store_workers_share_state_and_deduplication(self):
        original = self.store
        self.ingest("h0", [self.event("worker1")])
        self.store = Store(self.temp.name)
        self.ingest("h1", [self.event("worker2", "h1")])
        self.store = original
        self.ingest("h2", [self.event("worker1-again", "h2")])
        self.assertEqual(len(self.alerts()), 1)
        self.store = Store(self.temp.name)
        self.ingest("h2", [self.event("new-receipt-same-observation", "h2")])
        self.assertEqual(len(self.alerts()), 1)

    def test_small_byte_budget_keeps_receipts_and_per_host_alerts_and_bounded_state(self):
        self.limits = correlation.Limits(max_state_bytes=2048)
        values = [self.event(str(index), source_ip="192.0.2." + str(index + 1)) for index in range(10)]
        self.assertEqual(self.ingest("h0", values, hostname="x" * 253), [str(index) for index in range(10)])
        state = self.state()
        self.assertTrue(state["coverage_limited"])
        self.assertGreater(state["dropped_observations"], 0)
        with self.store.read_meta() as db:
            self.assertLessEqual(db.execute("SELECT length(CAST(data AS BLOB)) FROM security_alert_windows WHERE id=?", (correlation.STATE_ID,)).fetchone()[0], 2048)
        self.assertEqual(len([item for item in self.store.all("alerts") if item["kind"] == "unexpected_port_hit"]), 10)

    def test_alert_failure_rolls_back_receipt_and_state_then_retry_succeeds(self):
        for host in ("h0", "h1"):
            self.ingest(host, [self.event(host, host)])
        before = self.state()
        original = self.store._event
        def fail_correlation(db, key, kind, *args, **kwargs):
            if kind == correlation.KIND:
                raise RuntimeError("Disposable alert failure")
            return original(db, key, kind, *args, **kwargs)
        with patch.object(self.store, "_event", side_effect=fail_correlation), self.assertRaises(RuntimeError):
            self.ingest("h2", [self.event("third", "h2")])
        self.assertEqual(self.state(), before)
        with self.store.read_meta() as db:
            self.assertIsNone(db.execute("SELECT id FROM security_event_receipts WHERE id=?", ("h2:third",)).fetchone())
        self.assertEqual(self.alerts(), [])
        self.ingest("h2", [self.event("third", "h2")])
        self.assertEqual(len(self.alerts()), 1)

    def test_no_global_alert_scan_and_ambiguous_sources_are_ignored(self):
        original = self.store._all
        def guarded(db, table):
            if table == "alerts":
                raise AssertionError("Correlation must use primary-key state/alert lookups")
            return original(db, table)
        with patch.object(self.store, "_all", side_effect=guarded):
            for index in range(3):
                host = "h" + str(index)
                self.ingest(host, [self.event("unknown" + host, host, source_ip="0.0.0.0"), self.event("real" + host, host)])
        self.assertEqual(len(self.alerts()), 1)
        self.assertEqual(len(self.state()["groups"]), 1)

    def test_code_owned_configuration_and_batch_limits_are_validated(self):
        for values in ({"distinct_hosts": True}, {"distinct_hosts": 1}, {"distinct_hosts": 4, "max_destinations": 3},
                       {"window_seconds": 600, "cooldown_seconds": 300}, {"max_groups": 100000}, {"max_state_bytes": 3000000}):
            with self.subTest(values=values), self.assertRaises(ValueError):
                correlation.Limits(**values)
        with self.store.meta() as db, self.assertRaises(ValueError):
            correlation.observe(self.store, db, self.server("h0"), [self.event("a")] * 101)


if __name__ == "__main__":
    unittest.main()
