import tempfile
import unittest
from datetime import timedelta
from unittest.mock import patch

from controller.store import Store, parse_time, stamp


class PolicyServiceHealthTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = Store(self.temp.name)
        self.base = parse_time(stamp())
        self.report(0)

    def clock(self, offset):
        at = self.base + timedelta(seconds=offset)
        return patch.multiple("controller.store", now=lambda: at), patch("controller.service_health.now", return_value=at)

    def run_at(self, offset, function):
        first, second = self.clock(offset)
        with first, second:
            return function()

    def report(self, offset, listeners=None, performed=True, **extra):
        body = {"hostname": "endpoint", "ips": ["10.0.0.8"], "listeners": listeners or [],
                "discovery_performed": performed, "discovered_at": stamp(self.base + timedelta(seconds=offset)),
                "firewalld_state": "running", **extra}
        return self.run_at(offset, lambda: self.store.report("endpoint", body))

    def policy(self, offset=1, port=443, protocol="tcp", sources=None, **extra):
        value = {"name": "Expected web", "selector": {}, "mode": "monitor",
                 "services": [{"port": port, "protocol": protocol, "sources": ["10.2.0.1"] if sources is None else sources}], **extra}
        return self.run_at(offset, lambda: self.store.save_policy(value, "admin"))

    def evaluate(self, offset):
        self.run_at(offset, lambda: self.store.evaluate_health(at=self.base + timedelta(seconds=offset)))

    def alert(self, port=443, protocol="tcp"):
        return self.store.get("alerts", f"service:endpoint:{protocol}:{port}")

    def test_allowed_never_observed_requires_scan_after_policy_then_alerts(self):
        self.policy()
        self.report(2, performed=False)
        self.evaluate(2)
        self.assertTrue(self.store.get("servers", "endpoint")["policy_expectation_pending"])
        with self.assertRaises(KeyError):
            self.alert()
        self.report(3)
        self.evaluate(3)
        alert = self.alert()
        self.assertEqual((alert["kind"], alert["severity"], alert["details"]["basis"]),
                         ("service_down", "critical", "effective_policy_intent"))
        self.assertEqual(self.store.get("servers", "endpoint")["service_health_status"], "degraded")
        occurrence = alert["occurrence_id"]
        self.evaluate(4)
        self.assertEqual(self.alert()["occurrence_id"], occurrence)

    def test_cached_invented_listener_and_failed_or_stale_scan_cannot_recover(self):
        self.policy()
        self.report(3)
        self.evaluate(3)
        listener = {"port": 443, "protocol": "tcp", "address": "0.0.0.0"}
        self.report(4, [listener], performed=False)
        self.evaluate(4)
        self.assertEqual(self.alert()["status"], "open")
        self.report(5, [listener], discovery_error="ss failed")
        self.evaluate(5)
        self.assertEqual(self.alert()["status"], "open")
        self.assertEqual(self.store.get("servers", "endpoint")["service_health_status"], "unknown")
        self.evaluate(1000)
        self.assertEqual(self.alert()["status"], "open")
        self.report(1001, [listener])
        self.evaluate(1001)
        self.assertEqual(self.alert()["status"], "resolved")

    def test_withdrawn_policy_waits_for_fresh_scan_and_does_not_claim_recovery(self):
        policy = self.policy()
        self.report(3)
        self.evaluate(3)
        self.run_at(4, lambda: self.store.delete_policy(policy["id"], "admin"))
        self.report(5, performed=False)
        self.evaluate(5)
        self.assertEqual(self.alert()["status"], "open")
        self.report(6)
        self.evaluate(6)
        self.assertEqual(self.alert()["resolution_reason"], "expectation_withdrawn")
        self.assertTrue(any(row["kind"] == "service_expectation_withdrawn" for row in self.store.all("alerts")))
        self.assertFalse(any(row["kind"] == "recovered" and "443/tcp" in row["message"] for row in self.store.all("alerts")))

    def test_sources_empty_is_not_an_allowed_service_and_protocol_is_exact(self):
        self.policy(port=80, sources=[])
        self.policy(offset=2, port=443, protocol="udp")
        self.report(4, [{"port": 443, "protocol": "tcp"}])
        self.evaluate(4)
        self.assertEqual(self.alert(protocol="udp")["status"], "open")
        with self.assertRaises(KeyError):
            self.alert(port=80)

    def test_service_group_and_tag_membership_recompute_expectations(self):
        self.store.update_server("endpoint", {"tags": {"application": "Billing"}}, "admin")
        from controller.service_groups import save
        group = save(self.store, {"name": "Web", "ports": [{"port": 80, "protocol": "tcp"}, {"port": 443, "protocol": "tcp"}]}, "admin")
        self.policy(services=[{"service_group_id": group["id"], "sources": ["10.2.0.1"]}], selector={"application": "Billing"})
        self.report(3)
        self.evaluate(3)
        self.assertEqual(self.alert(80)["status"], "open")
        self.assertEqual(self.alert(443)["status"], "open")
        self.run_at(4, lambda: self.store.update_server("endpoint", {"tags": {"application": "Payments"}}, "admin"))
        self.report(5)
        self.evaluate(5)
        self.assertEqual(self.alert(80)["resolution_reason"], "expectation_withdrawn")
        self.assertEqual(self.store.get("servers", "endpoint")["policy_expected_services"], [])

    def test_manual_expectation_survives_policy_removal(self):
        self.store.update_server("endpoint", {"expected_services": [{"port": 443, "protocol": "tcp"}]}, "admin")
        policy = self.policy()
        self.report(3)
        self.evaluate(3)
        self.run_at(4, lambda: self.store.delete_policy(policy["id"], "admin"))
        self.report(5)
        self.evaluate(5)
        self.assertEqual(self.alert()["status"], "open")

    def test_same_second_or_older_discovery_cannot_satisfy_new_expectation(self):
        self.policy()
        self.report(1)
        self.evaluate(1)
        with self.assertRaises(KeyError):
            self.alert()
        self.report(2)
        self.evaluate(2)
        self.assertEqual(self.alert()["status"], "open")

    def test_retry_of_ahead_clock_inventory_is_not_a_new_post_policy_scan(self):
        self.report(0, discovered_at=stamp(self.base + timedelta(seconds=50)))
        self.policy()
        revision = self.store.get("servers", "endpoint")["_discovery_revision"]
        self.report(2, discovered_at=stamp(self.base + timedelta(seconds=50)))
        self.evaluate(2)
        self.assertEqual(self.store.get("servers", "endpoint")["_discovery_revision"], revision)
        with self.assertRaises(KeyError):
            self.alert()
        self.report(3, discovered_at=stamp(self.base + timedelta(seconds=53)))
        self.evaluate(3)
        self.assertEqual(self.alert()["status"], "open")

    def test_source_only_edit_does_not_reset_port_health_freshness(self):
        policy = self.policy()
        self.report(3)
        self.evaluate(3)
        before = self.store.get("servers", "endpoint")["_policy_health"]
        changed = {**policy, "services": [{"port": 443, "protocol": "tcp", "sources": ["10.9.0.1"]}]}
        self.run_at(4, lambda: self.store.save_policy(changed, "admin", identifier=policy["id"]))
        self.assertEqual(self.store.get("servers", "endpoint")["_policy_health"], before)

    def test_learning_overlay_ports_are_expected_without_becoming_applied_authority(self):
        from controller.learning_policies import _put_policy, refresh_host
        policy = {"id": "reviewed-learning", "session_id": "session-fixture", "server_id": "endpoint", "hostname": "endpoint",
                  "origin": "reviewed", "revision": 1, "status": "pending", "services": [{"port": 9443, "protocol": "tcp", "sources": ["10.2.0.1/32"]}]}
        def materialize():
            with self.store.lock, self.store.meta() as db:
                _put_policy(self.store, db, policy)
                refresh_host(self.store, db, self.store._get(db, "servers", "endpoint"))
        self.run_at(1, materialize)
        self.report(2)
        self.evaluate(2)
        self.assertEqual(self.alert(9443)["details"]["basis"], "effective_policy_intent")
        self.assertEqual(self.store.get("learning_allow_policies", policy["id"])["status"], "pending")
        self.assertNotEqual(self.store.get("learning_allow_hosts", "endpoint").get("status"), "applied")
        policy.update({"removed": True, "services": []})
        self.run_at(3, materialize)
        self.report(4)
        self.evaluate(4)
        self.assertEqual(self.alert(9443)["resolution_reason"], "expectation_withdrawn")


if __name__ == "__main__":
    unittest.main()
