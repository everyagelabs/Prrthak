import copy
import hashlib
import json
import unittest
from datetime import datetime, timedelta, timezone

from controller.firewall_counters import ingest, normalize, view

NOW = datetime(2026, 11, 4, 1, tzinfo=timezone.utc)
BOOT = "11111111-2222-4333-8444-555555555555"


def stamp(value):
    return value.isoformat().replace("+00:00", "Z")


def identity(row, boot=BOOT):
    row["id"] = hashlib.sha256("\0".join((row["family"], row["table"], row["chain"], row["basis"], row["expression"], str(row["ordinal"]))).encode()).hexdigest()
    row["instance_id"] = hashlib.sha256("\0".join((boot, row["family"], row["table"], row["table_handle"], row["chain"], row["handle"])).encode()).hexdigest()
    return row


def rule(**changes):
    return identity({"family": "inet", "table": "firewalld", "table_handle": "3", "chain": "filter_IN_public_allow", "handle": "5", "ordinal": 0, "zone": "public", "kind": "zone", "basis": "kernel_rule", "provenance": "firewalld_table", "expression": '[{"match":{"left":{"payload":{"field":"dport","protocol":"tcp"}},"op":"==","right":443}},{"counter":"[packet/byte counter]"},{"accept":null}]', "action": "accept", "counter_status": "available", "packets": "9007199254740993", "bytes": "18446744073709551600", "reason": "", **changes})


def sample(rows=None, **changes):
    return {"schema_version": 1, "backend": "nftables", "status": "ok", "collected_at": stamp(NOW), "boot_id": BOOT, "rules": rows if rows is not None else [rule()], "reason": "", "truncated": False, **changes}


class NativeFirewallCounterTests(unittest.TestCase):
    def test_exact_large_packet_bytes_are_not_connections_or_historical_deltas(self):
        server = {"id": "node", "discovery_interval_seconds": 900}
        original = sample()
        self.assertTrue(ingest(server, original, NOW))
        stored = server["firewall_counters"]["rules"][0]
        self.assertEqual(stored["packets"], "9007199254740993")
        self.assertEqual(stored["bytes"], "18446744073709551600")
        self.assertIsNone(stored["delta_packets"])
        self.assertEqual(stored["delta_status"], "baseline")
        later = NOW + timedelta(seconds=900)
        self.assertTrue(ingest(server, sample([rule(packets="9007199254740995", bytes="18446744073709551615")], collected_at=stamp(later)), later))
        row = server["firewall_counters"]["rules"][0]
        self.assertEqual((row["delta_packets"], row["delta_bytes"]), ("2", "15"))
        self.assertEqual(row["delta_since"], stamp(NOW))
        self.assertEqual(row["delta_status"], "observed")
        page = view(server, now=later)
        self.assertEqual((page["count_unit"], page["byte_unit"]), ("packets", "bytes"))
        self.assertIn("do not sum", page["coverage_note"])
        self.assertNotIn("digest", original)

    def test_repeated_cached_and_older_samples_never_change_the_delta_or_latest_observation(self):
        server = {"id": "node"}
        old = sample()
        ingest(server, old, NOW)
        newer = sample([rule(packets="9007199254740994", bytes="18446744073709551601")], collected_at=stamp(NOW + timedelta(seconds=60)))
        ingest(server, newer, NOW + timedelta(seconds=60))
        expected = copy.deepcopy(server)
        self.assertFalse(ingest(server, newer, NOW + timedelta(seconds=90)))
        self.assertFalse(ingest(server, old, NOW + timedelta(seconds=90)))
        self.assertEqual(server, expected)
        altered = copy.deepcopy(newer)
        altered["rules"][0]["packets"] = "9999999999999999"
        with self.assertRaisesRegex(ValueError, "cached"):
            ingest(server, altered, NOW + timedelta(seconds=90))
        self.assertEqual(server, expected)

    def test_boot_table_handle_rule_handle_and_decreased_values_start_reset_baselines(self):
        for changes in ({"table_handle": "13"}, {"handle": "50"}, {"packets": "1", "bytes": "60"}, {"boot_id": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"}):
            with self.subTest(changes=changes):
                server = {"id": "node"}
                ingest(server, sample(), NOW)
                boot = changes.get("boot_id", BOOT)
                new_rule = rule(**{key: value for key, value in changes.items() if key != "boot_id"})
                identity(new_rule, boot)
                later = NOW + timedelta(seconds=60)
                ingest(server, sample([new_rule], boot_id=boot, collected_at=stamp(later)), later)
                row = server["firewall_counters"]["rules"][0]
                self.assertTrue(row["reset_detected"])
                self.assertEqual(row["delta_status"], "reset")
                self.assertIsNone(row["delta_packets"])
                self.assertIsNone(row["delta_bytes"])

    def test_counter_disabled_and_implicit_chain_policies_are_unavailable_not_zero(self):
        unavailable = rule(counter_status="unavailable", packets=None, bytes=None, reason="NftablesCounters is off or unsupported.")
        normalized = normalize(sample([unavailable], status="unavailable", reason="No native counters are enabled."), NOW)
        self.assertIsNone(normalized["rules"][0]["packets"])
        server = {"id": "node"}
        ingest(server, sample([unavailable], status="unavailable", reason="No native counters are enabled."), NOW)
        later = NOW + timedelta(seconds=60)
        ingest(server, sample(collected_at=stamp(later)), later)
        self.assertEqual(server["firewall_counters"]["rules"][0]["delta_status"], "baseline")
        policy = rule(chain="filter_INPUT", basis="chain_policy", kind="base", zone="", expression='{"policy":"accept"}', handle="1", counter_status="unavailable", packets=None, bytes=None, reason="Implicit nft chain policy has no independent counter.")
        normalize(sample([policy], status="unavailable", reason="No standalone policy counter."), NOW)

    def test_missing_boot_generation_never_claims_verified_deltas(self):
        row = identity(rule(), "")
        server = {"id": "node"}
        ingest(server, sample([row], boot_id=""), NOW)
        self.assertEqual(server["firewall_counters"]["rules"][0]["delta_status"], "generation_unknown")
        self.assertIsNone(server["firewall_counters"]["rules"][0]["delta_packets"])
        later = NOW + timedelta(seconds=60)
        ingest(server, sample(collected_at=stamp(later)), later)
        self.assertEqual(server["firewall_counters"]["rules"][0]["delta_status"], "baseline")
        self.assertFalse(server["firewall_counters"]["rules"][0]["reset_detected"])

    def test_foreign_tables_invalid_uint64s_and_hostile_protocol_fields_are_rejected(self):
        cases = [sample(schema_version=True), sample(extra="unexpected"), sample(backend="foreign"), sample(collected_at=stamp(NOW + timedelta(minutes=6))), sample(boot_id="not-a-boot-id"), sample(rules=[rule(table="docker")]), sample(rules=[rule(packets=7)]), sample(rules=[rule(packets="01")]), sample(rules=[rule(packets="-1")]), sample(rules=[rule(packets="18446744073709551616")]), sample(rules=[rule(bytes=True)]), sample(rules=[rule(counter_status="unavailable")]), sample(rules=[{**rule(), "id": "f" * 64}]), sample(rules=[rule(chain="bad\nchain")]), sample(rules=[rule(ordinal=True)]), sample(rules=[rule(expression="[")]), sample(rules=[rule(reason="bad\nreason")])]
        for body in cases:
            with self.subTest(body=body), self.assertRaises(ValueError):
                normalize(body, NOW)
        for expression in ('[{"accept":null,"accept":null}]', '[NaN]', '[' * 30 + ']' * 30):
            with self.subTest(expression=expression), self.assertRaises(ValueError):
                normalize(sample([rule(expression=expression)]), NOW)

    def test_duplicates_and_payload_budget_are_bounded(self):
        with self.assertRaises(ValueError):
            normalize(sample([rule(), rule()]), NOW)
        with self.assertRaises(ValueError):
            normalize(sample([rule(handle=str(i + 1), ordinal=i) for i in range(513)]), NOW)
        with self.assertRaises(ValueError):
            normalize(sample([rule(expression='["' + "x" * 2000 + '"]')]), NOW)

    def test_legacy_firewalld_chain_and_default_builtin_policy_provenance_is_explicit(self):
        direct = rule(family="ipv4", table="filter", table_handle="", chain="INPUT_direct", zone="", kind="direct", provenance="firewalld_chain", expression='["-p","tcp","--dport","22","-j","DROP"]', action="drop", packets="0", bytes="0")
        policy = rule(family="ipv4", table="filter", table_handle="", chain="INPUT", zone="", kind="base", basis="chain_policy", provenance="firewalld_builtin_pattern", expression='{"policy":"drop"}', handle="0", action="drop", packets="1", bytes="60")
        normalize(sample([direct, policy], backend="iptables"), NOW)
        for row in (rule(**{**direct, "chain": "DOCKER"}), rule(**{**policy, "basis": "kernel_rule", "expression": '["-p","tcp","--dport","6666","-j","ACCEPT"]'})):
            with self.assertRaises(ValueError):
                normalize(sample([row], backend="iptables"), NOW)

    def test_read_only_view_paginates_exact_scope_and_marks_offline_or_old_samples(self):
        server = {"id": "node", "discovery_interval_seconds": 60}
        rows = [rule(handle=str(i + 1), ordinal=i) for i in range(12)]
        ingest(server, sample(rows), NOW)
        seen = []
        after = ""
        while True:
            page = view(server, after=after, limit=5, now=NOW)
            self.assertEqual(page["total"], 12)
            self.assertFalse(page["stale"])
            seen.extend(row["id"] for row in page["items"])
            if not page["has_more"]:
                break
            after = page["next_after"]
        self.assertEqual(len(set(seen)), 12)
        self.assertEqual(view(server, search="missing", now=NOW)["total"], 0)
        self.assertTrue(view(server, now=NOW + timedelta(seconds=181))["stale"])
        server["status"] = "offline"
        self.assertTrue(view(server, now=NOW)["stale"])
        with self.assertRaises(ValueError):
            view(server, limit=101)
        with self.assertRaises(ValueError):
            view(server, after="untrusted")

    def test_missing_old_agent_sample_has_reason_and_never_synthetic_counts(self):
        page = view({"id": "old-node"}, now=NOW)
        self.assertEqual(page["status"], "unavailable")
        self.assertEqual(page["items"], [])
        self.assertNotIn("packets", page)
        self.assertTrue(page["reason"])


if __name__ == "__main__":
    unittest.main()
