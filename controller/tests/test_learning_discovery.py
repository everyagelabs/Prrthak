import tempfile
import unittest
from datetime import timedelta
from unittest.mock import patch

from controller.learning import preview
from controller.seed import mark_synthetic_hosts, tick_synthetic_hosts
from controller.store import Store, now, parse_time, stamp


class LearningDiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = Store(self.temp.name)
        self.store.lab_approvals = True  # Explicit isolated automatic-learning lab fixture.
        self.base = parse_time(stamp())
        self.report("a", [self.listener(22)], offset=-10)
        self.report("b", [self.listener(80)], offset=-10)

    @staticmethod
    def listener(port, protocol="tcp", address="0.0.0.0"):
        return {"port": port, "protocol": protocol, "address": address, "process": "test-service"}

    def report(self, identifier, listeners, offset=1, **extra):
        at = self.base + timedelta(seconds=offset)
        value = {"hostname": identifier, "ips": ["10.1.1.1" if identifier == "a" else "10.1.1.2"], "listeners": listeners, "discovery_performed": True, "discovered_at": stamp(at), "firewalld_state": "running", "agent_version": "0.3.0", "capabilities": ["learning_discovery_v1"], **extra}
        with patch("controller.store.now", return_value=at):
            return self.store.report(identifier, value)

    def start(self, ids=None, **extra):
        with patch("controller.learning.now", return_value=self.base):
            return self.store.create_session({"server_ids": ids or ["a", "b"], "selection_mode": "discovered", "duration_seconds": 60, **extra}, "admin")

    def ack(self, session, identifier, listeners, **extra):
        return self.report(identifier, listeners, learning_discovery_session_ids=[session["id"]], **extra)

    def batch(self, session, port, identifier="batch-1"):
        return {"batch_id": identifier, "session_id": session["id"], "events": [{"source_ip": "10.5.5.5", "port": port, "protocol": "tcp", "first_seen": stamp(self.base + timedelta(seconds=1)), "last_seen": stamp(self.base + timedelta(seconds=1))}]}

    def test_auto_allow_requires_explicit_consent_fresh_mode_and_upgraded_agents(self):
        with self.assertRaisesRegex(ValueError, "explicit"):
            self.start(["a"], policy_action="auto_allow")
        with self.assertRaisesRegex(ValueError, "0.4.0"):
            self.start(["a"], policy_action="auto_allow", auto_allow_confirmed=True)
        self.report("a", [self.listener(8443)], capabilities=["learning_discovery_v1", "learning_auto_allow_v1"], agent_version="0.4.0")
        with self.assertRaisesRegex(ValueError, "fresh"):
            self.start(["a"], selection_mode="manual", ports=[{"port": 8443, "protocol": "tcp"}], policy_action="auto_allow", auto_allow_confirmed=True)
        with self.assertRaisesRegex(ValueError, "explicit"):
            self.start(["a"], policy_action="auto_allow", auto_allow_confirmed=1)
        session = self.start(["a"], policy_action="auto_allow", auto_allow_confirmed=True)
        self.assertEqual(session["policy_action"], "auto_allow")
        self.assertEqual(session["auto_allow_authorized_by"], "admin")
        self.assertTrue(session["auto_allow_confirmed"])

    def test_filtered_discovery_learns_only_443_while_inventory_keeps_22_and_80(self):
        listeners = [self.listener(port) for port in (22, 80, 443)]
        caps = ["learning_discovery_v1", "learning_auto_allow_v1"]
        self.report("a", listeners, capabilities=caps, agent_version="0.4.0")
        chosen = [{"port": 443, "protocol": "tcp"}]
        cached = preview(self.store, {"server_ids": ["a"], "port_filter": chosen})
        self.assertEqual(cached["servers"][0]["ports"], chosen)
        session = self.start(["a"], port_filter=chosen, policy_action="auto_allow", auto_allow_confirmed=True)
        self.ack(session, "a", listeners + [self.listener(443, "udp")], capabilities=caps, agent_version="0.4.0")
        assignment = self.store.assignment("a")[0]
        self.assertEqual(assignment["learning_sessions"][0]["ports"], chosen)
        self.assertEqual({item["port"] for item in self.store.get("servers", "a")["listeners"]}, {22, 80, 443})
        for port in (22, 80):
            with self.assertRaisesRegex(ValueError, "not selected"):
                self.store.enqueue_flows("a", self.batch(session, port, str(port)))
        self.store.enqueue_flows("a", self.batch(session, 443))
        self.store.process_flows()
        generated = self.store.all("learning_allow_policies")
        self.assertEqual(len(generated), 1)
        self.assertEqual(generated[0]["services"], [{"port": 443, "protocol": "tcp", "sources": ["10.5.5.5/32"]}])

    def test_filtered_discovery_does_not_fall_back_to_other_listeners(self):
        chosen = [{"port": 443, "protocol": "tcp"}]
        for invalid in ([], None, [{"port": "443"}], [{"port": 443, "protocol": "sctp"}]):
            with self.assertRaises(ValueError):
                self.start(["a"], port_filter=invalid)
        session = self.start(["a"], port_filter=chosen)
        self.ack(session, "a", [self.listener(22), self.listener(80)])
        snapshot = self.store.get("sessions", session["id"])
        self.assertEqual(snapshot["server_ports"]["a"], [])
        self.assertEqual(snapshot["discovery_results"]["a"]["status"], "no_listeners")
        self.assertEqual(self.store.get("servers", "a")["collector_desired_status"], "off")

    def test_start_waits_for_fresh_per_host_snapshot_then_freezes_it(self):
        before, _ = self.store.assignment("a")
        cached = preview(self.store, {"server_ids": ["a", "b"]})
        self.assertEqual(cached["freshness"], "cached_preview")
        self.assertEqual(cached["servers"][0]["ports"], [{"protocol": "tcp", "port": 22}])
        session = self.start()
        pending, pending_etag = self.store.assignment("a")
        self.assertEqual(pending["learning_sessions"][0]["ports"], [])
        self.assertTrue(pending["learning_sessions"][0]["discovery_pending"])
        self.assertEqual(self.store.get("servers", "a")["collector_desired_status"], "off")
        with self.assertRaises(ValueError):
            self.store.enqueue_flows("a", self.batch(session, 22))
        self.ack(session, "a", [self.listener(2022), self.listener(8080), self.listener(8080, address="::"), self.listener(53, "udp", "::"), self.listener(9999, address="127.0.0.1"), self.listener(9998, address="::1"), self.listener(9997, address="::ffff:127.0.0.1"), self.listener(9996, address="")])
        self.ack(session, "b", [self.listener(5432)])
        a, a_etag = self.store.assignment("a")
        b, _ = self.store.assignment("b")
        a_ports = a["learning_sessions"][0]["ports"]
        self.assertEqual(a_ports, [{"protocol": "tcp", "port": 2022}, {"protocol": "tcp", "port": 8080}, {"protocol": "udp", "port": 53}])
        self.assertEqual(b["learning_sessions"][0]["ports"], [{"protocol": "tcp", "port": 5432}])
        self.assertNotIn("server_ports", a["learning_sessions"][0])
        self.assertFalse(a["learning_sessions"][0]["discovery_pending"])
        self.assertNotEqual(a_etag, pending_etag)
        self.assertEqual((a["version"], a["digest"], a["services"]), (before["version"], before["digest"], before["services"]))
        self.assertEqual(self.store.enqueue_flows("a", self.batch(session, 8080))["accepted"], 1)
        self.assertTrue(self.store.enqueue_flows("a", self.batch(session, 8080))["duplicate"])
        with self.assertRaises(ValueError):
            self.store.enqueue_flows("b", self.batch(session, 8080))
        self.report("a", [self.listener(8443)], offset=2)
        self.ack(session, "a", [self.listener(8443)], offset=3)
        frozen, _ = self.store.assignment("a")
        self.assertEqual(frozen["learning_sessions"][0]["ports"], a_ports)
        self.assertTrue(any(alert["kind"] == "service_discovered" and alert["details"]["port"] == 8443 for alert in self.store.all("alerts")))
        self.assertEqual(self.store.process_flows(), 1)
        with patch("controller.store.now", return_value=self.base + timedelta(seconds=4)):
            self.store.stop_session(session["id"], "admin")
            stopped, _ = self.store.assignment("b")
        self.assertEqual(stopped["learning_tombstones"][0]["ports"], [{"protocol": "tcp", "port": 5432}])
        self.assertEqual(self.store.enqueue_flows("a", self.batch(session, 8080, "tail"))["accepted"], 1)

    def test_cached_or_pre_start_scan_and_foreign_ack_cannot_authorize_ports(self):
        session = self.start(["a"])
        for extra in ({"discovery_performed": False}, {"discovered_at": stamp(self.base - timedelta(seconds=1))}, {"discovered_at": None}):
            with self.assertRaises(ValueError):
                self.ack(session, "a", [self.listener(8080)], **extra)
        with self.assertRaises(ValueError):
            self.ack(session, "b", [self.listener(5432)])
        pending = self.store.get("sessions", session["id"])
        self.assertEqual(pending["discovery_pending_server_ids"], ["a"])
        self.assertEqual(pending["server_ports"]["a"], [])
        self.assertEqual(self.store.get("servers", "a")["listeners"][0]["port"], 22)

    def test_failed_scan_retries_no_listeners_never_means_all_ports(self):
        session = self.start(["a"])
        self.ack(session, "a", [], discovery_error="ss command failed")
        failure = self.store.get("sessions", session["id"])
        self.assertEqual(failure["discovery_results"]["a"]["status"], "error")
        server = self.store.get("servers", "a")
        self.assertEqual(server["learning_discovery_status"], "error")
        self.assertEqual(server["collector_desired_status"], "off")
        self.assertEqual(server["listeners"][0]["port"], 22)
        self.ack(session, "a", [self.listener(80, address="127.0.0.1")], offset=2)
        empty = self.store.get("sessions", session["id"])
        self.assertEqual(empty["discovery_results"]["a"]["status"], "no_listeners")
        self.assertEqual(empty["discovery_pending_server_ids"], [])
        self.assertEqual(self.store.get("servers", "a")["collector_desired_status"], "off")
        with self.assertRaises(ValueError):
            self.store.enqueue_flows("a", self.batch(session, 80))
        self.ack(session, "a", [self.listener(80)], offset=3)
        self.assertEqual(self.store.get("sessions", session["id"])["server_ports"]["a"], [])

    def test_expired_pending_session_cannot_be_activated_and_tombstone_is_empty(self):
        session = self.start(["a"])
        self.ack(session, "a", [self.listener(8080)], offset=61)
        self.assertEqual(self.store.get("sessions", session["id"])["server_ports"]["a"], [])
        with patch("controller.store.now", return_value=self.base + timedelta(seconds=61)):
            self.store.evaluate_health()
            assignment, _ = self.store.assignment("a")
        self.assertEqual(assignment["learning_sessions"], [])
        self.assertEqual(assignment["learning_tombstones"][0]["ports"], [])
        self.assertEqual(self.store.get("servers", "a")["collector_desired_status"], "off")

    def test_pending_and_ready_snapshots_survive_restart_and_stop_race(self):
        session = self.start(["a"])
        self.store = Store(self.temp.name)
        self.store.lab_approvals = True  # Explicit isolated automatic-learning lab fixture.
        self.assertTrue(self.store.assignment("a")[0]["learning_sessions"][0]["discovery_pending"])
        self.ack(session, "a", [self.listener(8080)])
        self.store = Store(self.temp.name)
        self.store.lab_approvals = True  # Explicit isolated automatic-learning lab fixture.
        self.ack(session, "a", [self.listener(9090)], offset=2)
        self.assertEqual(self.store.assignment("a")[0]["learning_sessions"][0]["ports"], [{"protocol": "tcp", "port": 8080}])
        other = self.start(["b"])
        with patch("controller.store.now", return_value=self.base + timedelta(seconds=2)):
            self.store.stop_session(other["id"], "admin")
        self.ack(other, "b", [self.listener(5432)], offset=3)
        self.assertEqual(self.store.get("sessions", other["id"])["server_ports"]["b"], [])

    def test_unsupported_agents_fail_explicitly_and_manual_legacy_is_unchanged(self):
        self.report("b", [], capabilities=[], agent_version="0.2.0")
        with self.assertRaisesRegex(ValueError, "Upgrade these agents or use manual ports"):
            self.start()
        manual = self.store.create_session({"server_ids": ["b"], "ports": [{"port": 80, "protocol": "tcp"}]}, "admin")
        self.assertEqual(manual["selection_mode"], "manual")
        self.assertEqual(self.store.assignment("b")[0]["learning_sessions"][0]["ports"], [{"protocol": "tcp", "port": 80}])
        legacy = {**manual, "id": "old-manual"}
        legacy.pop("selection_mode")
        with self.store.meta() as db:
            self.store._put(db, "sessions", legacy)
        self.assertEqual(self.store.enqueue_flows("b", self.batch(legacy, 80))["accepted"], 1)
        auto = self.start(["a"])
        self.report("a", [], capabilities=[], agent_version="0.2.0")
        self.assertEqual(self.store.assignment("a")[0]["learning_sessions"], [])
        self.assertEqual(self.store.get("servers", "a")["learning_discovery_status"], "unsupported")
        self.assertEqual(self.store.get("sessions", auto["id"])["server_ports"]["a"], [])

    def test_report_list_sizes_ids_and_excessive_scan_are_validated(self):
        session = self.start(["a"])
        for ids in ("not-a-list", [session["id"]] * 101, ["invalid/id"], [{}]):
            with self.assertRaises(ValueError):
                self.report("a", [], learning_discovery_session_ids=ids)
        self.ack(session, "a", [self.listener(port) for port in range(1, 102)])
        result = self.store.get("sessions", session["id"])
        self.assertEqual(result["discovery_results"]["a"]["status"], "error")
        self.assertEqual(result["server_ports"]["a"], [])
        self.assertEqual(result["discovery_pending_server_ids"], ["a"])

    def test_offline_hosts_stay_pending_until_ack_and_only_named_demo_hosts_simulate(self):
        self.report("a", [], offset=-181)
        session = self.start(["a"])
        self.assertEqual(self.store.get("servers", "a")["learning_discovery_status"], "offline")
        tick_synthetic_hosts(self.store, self.base + timedelta(seconds=1))
        self.assertEqual(self.store.get("sessions", session["id"])["server_ports"]["a"], [])
        self.store.report("srv-cloud-01", {"hostname": "fixture", "ips": ["10.3.3.3"], "listeners": [self.listener(2022), self.listener(8080)], "firewalld_state": "running"})
        mark_synthetic_hosts(self.store)
        demo = self.start(["srv-cloud-01"])
        tick_synthetic_hosts(self.store, self.base + timedelta(seconds=1))
        result = self.store.get("sessions", demo["id"])
        self.assertEqual(result["server_ports"]["srv-cloud-01"], [{"protocol": "tcp", "port": 2022}, {"protocol": "tcp", "port": 8080}])
        self.assertTrue(result["synthetic"])
        self.assertTrue(result["discovery_results"]["srv-cloud-01"]["synthetic"])
