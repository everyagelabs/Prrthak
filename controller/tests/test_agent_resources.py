from datetime import timedelta
import tempfile
import unittest

from controller.agent_resources import CAPABILITY, EVENT
from controller.store import Store, now, stamp


class AgentResourceTests(unittest.TestCase):
    def test_thresholds_deduplicate_recover_and_do_not_treat_unknown_as_healthy(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(directory)
            at = now() - timedelta(minutes=10)
            def report(minute, **samples):
                store.report("test-agent", {
                    "hostname": "billing-test", "ips": ["10.241.5.12"], "listeners": [],
                    "capabilities": [CAPABILITY],
                    "resource_usage": {key: {"value": value, "observed_at": stamp(at + timedelta(minutes=minute))}
                                       for key, value in samples.items()},
                })
            def alerts():
                return {alert["details"]["metric"]: alert for alert in store.all("alerts") if alert["kind"] == EVENT}

            report(0, cpu_basis_points=399, memory_bytes=1_599_999_999, storage_bytes=7_999_999_999)
            self.assertEqual(alerts(), {})
            report(1, cpu_basis_points=400, memory_bytes=1_600_000_000, storage_bytes=8_000_000_000)
            warnings = alerts()
            self.assertEqual(len(warnings), 3)
            self.assertTrue(all(value["status"] == "open" and value["severity"] == "warning" for value in warnings.values()))
            self.assertNotIn("_resource_usage_seen", store.server("test-agent"))
            report(2, cpu_basis_points=399, memory_bytes=True)
            self.assertEqual(alerts(), warnings)
            self.assertEqual(set(store.server("test-agent")["resource_usage"]), {"cpu_basis_points"})
            report(0, cpu_basis_points=10, memory_bytes=0)
            self.assertEqual(alerts(), warnings)
            report(3, cpu_basis_points=374, memory_bytes=1_499_999_999, storage_bytes=7_499_999_999)
            self.assertTrue(all(value["status"] == "resolved" for value in alerts().values()))
            report(4, cpu_basis_points=400)
            self.assertNotEqual(alerts()["cpu_basis_points"]["occurrence_id"], warnings["cpu_basis_points"]["occurrence_id"])
            self.assertEqual(alerts()["cpu_basis_points"]["status"], "open")
