"""Read-only ingress what-if analysis using real isolated metadata/traffic SQL."""
import copy
from datetime import timedelta
import json
import tempfile
import unittest
from unittest.mock import patch

from controller import policy_impact as impact
from controller.firewall import WorkflowConflict
from controller.store import Store, now, stamp


class PolicyImpactTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="prthak-impact-")
        self.addCleanup(temporary.cleanup)
        self.store = Store(temporary.name)
        self.at = now().replace(microsecond=0)
        self.sequence = 0
        self.policy = {"id": "billing-access", "name": "Billing", "revision": 3, "mode": "enforce", "selector": {"application": "billing"}, "group_ids": [], "services": [{"port": 443, "protocol": "tcp", "sources": ["192.0.2.0/24", "2001:db8::/64"], "source_selector": {}, "source_group_ids": []}]}
        self.server("billing-a")
        self.server("billing-b")
        self.server("payments", app="payments")
        self.put("policies", self.policy)

    def put(self, table, value):
        with self.store.meta() as db:
            self.store._put(db, table, value)

    def server(self, identifier, app="billing", **changes):
        item = {"id": identifier, "hostname": identifier, "ips": ["10.44.0.10", "2001:db8:44::10"], "tags": {"application": app}, "location_id": None, "last_seen": stamp(self.at), "protection_reported_at": stamp(self.at), "protection": {"ready": True, "management_sources": ["10.90.0.0/24", "2001:db8:90::/64"], "ssh_ports": [2022]}, "learning_coverage": {"session_id": "learning-a", "dropped_events": 2, "rate_limited": True, "capture_gaps": ["socket overflow"], "capture_backends": [{"backend": "conntrack", "lost_events": None}]}, **changes}
        self.put("servers", item)
        return item

    def observation(self, source="192.0.2.10", *, server="billing-a", port=443, protocol="tcp", origin="learning", scope="learning-a", kind="accepted_connection", count=1, seconds_ago=20, processed=1):
        family = "ipv6" if ":" in source else "ipv4"
        backend, unit, verdict = {"accepted_connection": ("conntrack", "connections", "allowed"), "denied_packet": ("nflog", "packets", "denied"), "legacy_log": ("journal", "log_records", "allowed")}[kind]
        with self.store.traffic() as db:
            for _ in range(count):
                self.sequence += 1
                at = stamp(self.at - timedelta(seconds=seconds_ago))
                fields = (server, scope, source, port, protocol, verdict, kind, backend, unit, family)
                if origin == "learning":
                    db.execute("INSERT INTO flows(batch_key,event_index,server_id,session_id,source_ip,port,protocol,verdict,capture_kind,capture_backend,count_unit,address_family,count,first_seen,last_seen,capture_processed) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,1,?,?,?)", ("batch-" + str(self.sequence), 0, *fields, at, at, processed))
                else:
                    db.execute("INSERT INTO hit_events(id,server_id,monitor_id,batch_key,event_digest,source_ip,port,protocol,event_time,expires_at,data,processed,capture_kind,capture_backend,count_unit,address_family,verdict) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", ("event-" + str(self.sequence), server, scope, "batch", "digest", source, port, protocol, at, stamp(self.at + timedelta(hours=1)), "{}", processed, kind, backend, unit, family, verdict))

    def preview(self, value=None, **kwargs):
        with patch.object(impact, "now", return_value=self.at):
            return impact.preview(self.store, value, **({"policy_id": "billing-access"} if not kwargs else kwargs))

    def proposed(self, services=None, **policy_changes):
        policy = {**copy.deepcopy(self.policy), **policy_changes}
        if services is not None:
            policy["services"] = services
        return {"policy": policy, "policy_id": self.policy["id"], "expected_revision": 3}

    def test_saved_preview_is_read_only_and_never_publishes_or_changes_authority(self):
        self.observation()
        with self.store.read_meta() as db:
            before = {table: self.store._all(db, table) for table in ("servers", "policies", "policy_revisions", "audit", "managed_approvals", "policy_deployments")}
        with patch.object(self.store, "_put", side_effect=AssertionError("preview wrote")), patch.object(self.store, "compile_all", side_effect=AssertionError("preview compiled authority")), patch.object(self.store, "save_policy", side_effect=AssertionError("preview saved")), patch.object(self.store, "audit", side_effect=AssertionError("preview audited")):
            result = self.preview()
        with self.store.read_meta() as db:
            after = {table: self.store._all(db, table) for table in before}
        self.assertEqual(before, after)
        self.assertTrue(result["read_only"])
        self.assertEqual(result["items"][0]["proposed_decision"], "would_allow")
        self.assertFalse(result["policy"]["proposed"])
        with self.assertRaises(ValueError):
            self.preview({"policy": self.policy})

    def test_restriction_accounts_for_overlap_and_ipv6_instead_of_one_policy_alone(self):
        overlapping = {**copy.deepcopy(self.policy), "id": "other-app-access", "services": [{"port": 443, "protocol": "tcp", "sources": ["198.51.100.10/32"]}]}
        self.put("policies", overlapping)
        for source in ("192.0.2.10", "192.0.2.11", "198.51.100.10", "2001:db8::99"):
            self.observation(source)
        request = self.proposed([{**self.policy["services"][0], "sources": ["192.0.2.10/32", "2001:db8::/64"]}])
        result = self.preview(request, proposed=True)
        by_source = {row["source_ip"]: row for row in result["items"]}
        self.assertEqual(by_source["192.0.2.11"]["current_decision"], "would_allow")
        self.assertEqual(by_source["192.0.2.11"]["proposed_decision"], "would_block")
        self.assertEqual(by_source["198.51.100.10"]["proposed_decision"], "would_allow")
        self.assertEqual(by_source["2001:db8::99"]["proposed_decision"], "would_allow")
        self.assertEqual(result["summary"]["target_servers"], 2)
        self.assertEqual(result["summary"]["effective_changed_servers"], 2)

    def test_removed_targets_are_included_and_unmanaged_ports_are_unknown(self):
        self.observation(server="billing-a")
        self.observation(server="billing-b", source="192.0.2.11")
        self.put("groups", {"id": "billing-a-only", "type": "static", "name": "One host", "server_ids": ["billing-a"], "selector": {}})
        request = self.proposed(selector={}, group_ids=["billing-a-only"])
        result = self.preview(request, proposed=True)
        self.assertEqual(result["summary"]["target_servers"], 2)
        removed = next(row for row in result["items"] if row["server_id"] == "billing-b")
        self.assertEqual(removed["proposed_decision"], "unverified")
        self.assertIn("outside managed", removed["reason"])

    def test_service_groups_source_groups_and_tags_use_the_real_compiler(self):
        self.put("service_groups", {"id": "web", "name": "Web", "revision": 2, "ports": [{"port": 8443, "protocol": "tcp"}, {"port": 9443, "protocol": "udp"}]})
        self.put("groups", {"id": "sources", "name": "Client nodes", "type": "dynamic", "selector": {"application": "payments"}, "server_ids": []})
        self.observation("2001:db8:44::10", port=9443, protocol="udp")
        request = self.proposed([{"service_group_id": "web", "sources": [], "source_selector": {}, "source_group_ids": ["sources"]}])
        result = self.preview(request, proposed=True)
        self.assertEqual(result["items"][0]["proposed_decision"], "would_allow")
        self.assertEqual(result["items"][0]["current_decision"], "unverified")
        request["policy"]["services"][0]["source_group_ids"] = ["missing"]
        with self.assertRaisesRegex(ValueError, "unknown saved source"):
            self.preview(request, proposed=True)

    def test_whole_host_deny_keeps_actual_ssh_and_family_specific_dhcp_exceptions(self):
        self.server("billing-a", host_default_deny_state={"enabled": True})
        for source, port, protocol in (("10.90.0.22", 2022, "tcp"), ("192.0.2.77", 2022, "tcp"), ("192.0.2.77", 68, "udp"), ("2001:db8::77", 546, "udp"), ("192.0.2.77", 546, "udp"), ("2001:db8::77", 68, "udp")):
            self.observation(source, port=port, protocol=protocol)
        rows = {(row["source_ip"], row["port"]): row for row in self.preview()["items"]}
        self.assertEqual(rows[("10.90.0.22", 2022)]["proposed_decision"], "would_allow")
        self.assertIn("Protected SSH", rows[("10.90.0.22", 2022)]["reason"])
        self.assertEqual(rows[("192.0.2.77", 2022)]["proposed_decision"], "would_block")
        for key in (("192.0.2.77", 68), ("2001:db8::77", 546)):
            self.assertEqual(rows[key]["proposed_decision"], "would_allow")
        for key in (("192.0.2.77", 546), ("2001:db8::77", 68)):
            self.assertEqual(rows[key]["proposed_decision"], "would_block")

    def test_monitor_only_stale_protection_and_learned_overlays_never_claim_rejection(self):
        self.observation("203.0.113.8")
        from controller.learning_policies import _put_policy
        with self.store.meta() as db:
            _put_policy(self.store, db, {"id": "learned", "server_id": "billing-a", "session_id": "learning-a", "removed": False, "removal_pending": False, "services": []})
        result = self.preview()
        self.assertEqual(result["items"][0]["proposed_decision"], "unverified")
        self.assertIn("overlay", result["items"][0]["reason"])
        self.server("billing-a", last_seen=stamp(self.at - timedelta(minutes=10)))
        self.assertIn("Fresh authenticated", self.preview()["items"][0]["reason"])
        self.server("billing-a", protection_reported_at=stamp(self.at - timedelta(minutes=10)))
        self.assertEqual(self.preview()["items"][0]["proposed_decision"], "unverified")
        request = self.proposed(mode="monitor")
        self.server("billing-a")
        self.assertEqual(self.preview(request, proposed=True)["items"][0]["proposed_decision"], "unverified")

    def test_monitor_learning_packet_connection_and_legacy_counts_never_merge(self):
        self.observation(count=3)
        self.observation(kind="denied_packet", count=2)
        self.observation(kind="legacy_log", count=4)
        self.observation(origin="monitoring", scope="monitor-a", count=2)
        self.observation(origin="monitoring", scope="monitor-b", kind="denied_packet", count=3)
        result = self.preview()
        self.assertEqual(result["total"], 5)
        counts = {(item["origin"], item["capture_scope_id"], item["count_unit"]): item["count"] for item in result["summary"]["counts_by_origin_unit"]}
        self.assertEqual(counts[("learning", "learning-a", "connections")], 3)
        self.assertEqual(counts[("learning", "learning-a", "packets")], 2)
        self.assertEqual(counts[("learning", "learning-a", "log_records")], 4)
        self.assertEqual(counts[("monitoring", "monitor-a", "connections")], 2)
        self.assertEqual(counts[("monitoring", "monitor-b", "packets")], 3)
        legacy = next(row for row in result["items"] if row["capture_kind"] == "legacy_log")
        self.assertTrue(legacy["coverage"]["legacy_sampled_logs"])
        self.assertNotIn("verified", legacy["proposed_decision"])

    def test_filters_precede_pagination_and_exclude_pending_or_outside_window_observations(self):
        for index in range(4):
            self.observation("192.0.2." + str(10 + index), seconds_ago=10 + index)
        self.observation("203.0.113.10", seconds_ago=1)
        self.observation("192.0.2.88", processed=0)
        self.observation("192.0.2.89", seconds_ago=4000)
        self.observation("192.0.2.90", server="payments")
        value = {"source_ip": "192.0.2.0/24", "ports": ["443/tcp"], "server_ids": ["billing-a"], "outcome": "would_allow", "limit": 2}
        first = self.preview(value)
        second = self.preview({**value, "offset": first["next_offset"], "as_of": first["as_of"], "context_digest": first["context_digest"]})
        self.assertEqual((first["total"], first["has_more"], second["total"], second["has_more"]), (4, True, 4, False))
        self.assertTrue({row["source_ip"] for row in first["items"]}.isdisjoint({row["source_ip"] for row in second["items"]}))
        self.assertEqual(self.preview({**value, "ports": ["443/udp"]})["total"], 0)

    def test_coverage_is_bound_to_exact_origin_and_scope_without_full_window_claim(self):
        self.observation()
        self.observation(scope="historical-scope")
        rows = {row["capture_scope_id"]: row for row in self.preview()["items"]}
        self.assertEqual(rows["learning-a"]["coverage"]["dropped_events"], 2)
        self.assertTrue(rows["learning-a"]["coverage"]["rate_limited"])
        self.assertFalse(rows["historical-scope"]["coverage"]["receipt_available"])
        self.assertIsNone(rows["historical-scope"]["coverage"]["dropped_events"])
        self.assertTrue(all(not row["coverage"]["complete_window"] for row in rows.values()))

    def test_no_observations_and_analysis_limit_are_explicit_unknowns(self):
        empty = self.preview()
        self.assertEqual(empty["summary"]["servers_without_observations"], 2)
        self.assertTrue(empty["coverage"]["unknown_dependencies"])
        self.assertEqual(empty["items"], [])
        for source in ("192.0.2.1", "192.0.2.2", "192.0.2.3"):
            self.observation(source)
        with patch.object(impact, "MAX_RELATIONSHIPS", 2):
            limited = self.preview()
        self.assertTrue(limited["total_is_lower_bound"])
        self.assertTrue(limited["coverage"]["evaluation_limit_reached"])
        self.assertIsNone(limited["summary"]["servers_without_observations"])
        self.assertEqual(limited["summary"]["relationships"], 2)

    def test_stale_revision_unknown_group_and_changed_context_fail_without_publication(self):
        request = self.proposed()
        request["expected_revision"] = 2
        with self.assertRaises(WorkflowConflict):
            self.preview(request, proposed=True)
        first = self.preview()
        self.put("policies", {**self.policy, "services": [{"port": 443, "protocol": "tcp", "sources": []}]})
        with self.assertRaises(WorkflowConflict):
            self.preview({"context_digest": first["context_digest"]})
        for value in ({"window_seconds": True}, {"window_seconds": 86401}, {"limit": 101}, {"offset": 20001}, {"source_ip": "::ffff:192.0.2.1"}, {"source_ip": "fe80::1%eth0"}, {"ports": ["443/tcp OR 1=1"]}, {"server_ids": ["not an id"]}, {"context_digest": "bad"}, {"outcome": "safe"}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.preview(value)

    def test_5000_server_scope_and_large_firewall_snapshots_do_not_leak_or_expand_response(self):
        base = self.store.get("servers", "billing-a")
        with self.store.meta() as db:
            db.execute("DELETE FROM servers")
            db.executemany("INSERT INTO servers(id,data) VALUES(?,?)", [("host-" + str(index), json.dumps({**base, "id": "host-" + str(index), "hostname": "host-" + str(index), "firewall_snapshot": {"private_fixture": "not part of analysis projection"}})) for index in range(5000)])
        with patch.object(self.store, "_all", side_effect=AssertionError("unbounded canonical read")):
            result = self.preview()
        self.assertEqual(result["summary"]["target_servers"], 5000)
        self.assertEqual(result["targets"]["total"], 5000)
        self.assertEqual(len(result["targets"]["items"]), 100)
        self.assertTrue(result["targets"]["has_more"])
        self.assertNotIn("private_fixture", json.dumps(result))
        self.assertLess(len(json.dumps(result)), 100000)
        with patch.object(impact, "MAX_SOURCE_EXPANSIONS", 1), self.assertRaisesRegex(ValueError, "analysis budget"):
            self.preview()
