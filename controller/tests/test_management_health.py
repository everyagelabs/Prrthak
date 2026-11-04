import copy
import unittest
from unittest.mock import Mock, patch

from controller.management_health import ManagementHealth, ManagementHealthUnavailable, PROBE_SOURCE, PROBE_TARGETS, probe_configuration


class ManagementHealthTests(unittest.TestCase):
    def setUp(self):
        self.approved = {"server_id": "node-a", "version": 8, "digest": "d" * 64,
            "protection_digest": "p" * 64, "binding_digest": "b" * 64,
            "ips": ["10.40.0.21"], "ssh_ports": [2022, 2222],
            "management_sources": ["10.90.0.0/24"]}
        self.store = Mock()
        self.store.verify_managed_enforcement.return_value = self.approved
        self.payload = {"nonce": "a" * 32, "ssh_ports": [2022, 2222]}
        self.health = ManagementHealth("10.90.0.5", ["10.40.0.0/24"])

    def test_each_actual_ssh_port_is_probed_and_proof_is_transaction_bound(self):
        def probe(target, port, deadline):
            return {"target_ip": target, "port": port, "source_ip": "10.90.0.5", "ssh_banner_verified": True}
        with patch.object(self.health, "_ssh", side_effect=probe) as probe:
            result = self.health.check(self.store, "node-a", self.payload)
        self.assertEqual([call.args[1] for call in probe.call_args_list], [2022, 2222])
        for field in ("server_id", "version", "digest", "protection_digest", "binding_digest"):
            self.assertEqual(result[field], self.approved[field])
        self.assertEqual(result["nonce"], self.payload["nonce"])
        self.assertEqual(result["status"], "healthy")
        self.assertEqual(self.store.verify_managed_enforcement.call_count, 2)

    def test_no_probe_configuration_fails_closed(self):
        with self.assertRaises(ManagementHealthUnavailable):
            ManagementHealth("", []).check(self.store, "node-a", self.payload)

    def test_appliance_witness_requires_exact_authenticated_host_evidence(self):
        evidence = [{"target_ip": "10.40.0.21", "source_ip": "10.90.0.5", "port": port,
                     "ssh_banner_verified": True} for port in [2022, 2222]]
        host_probe = Mock(return_value={"ssh_checks": evidence})
        health = ManagementHealth("10.90.0.5", ["10.40.0.0/24"], host_probe=host_probe)
        with patch.object(health, "_ssh") as container_probe:
            self.assertEqual(health.check(self.store, "node-a", self.payload)["ssh_checks"], evidence)
            host_probe.assert_called_once_with({"source_ip": "10.90.0.5", "target_ip": "10.40.0.21", "ports": [2022, 2222]})
            container_probe.assert_not_called()
            evidence[0]["source_ip"] = "172.20.0.2"
            with self.assertRaises(ManagementHealthUnavailable):
                health.check(self.store, "node-a", self.payload)

    def test_reviewed_probe_configuration_is_paired_literal_and_bounded(self):
        config = {PROBE_SOURCE: "10.90.0.5", PROBE_TARGETS: "10.40.0.0/24, 10.40.0.0/24"}
        self.assertEqual(probe_configuration(config), {**config, PROBE_TARGETS: "10.40.0.0/24"})
        for changes in ({PROBE_SOURCE: "localhost"}, {PROBE_SOURCE: "127.0.0.1"}, {PROBE_TARGETS: ""},
                        {PROBE_TARGETS: "0.0.0.0/0"}, {PROBE_TARGETS: "2001:db8::/32"}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                probe_configuration({**config, **changes})

    def test_probe_source_must_be_in_pinned_management_cidrs(self):
        self.approved["management_sources"] = ["10.91.0.0/24"]
        with self.assertRaises(ManagementHealthUnavailable):
            self.health.check(self.store, "node-a", self.payload)

    def test_arbitrary_request_addresses_are_ignored_and_unapproved_ports_rejected(self):
        self.payload.update({"ips": ["10.40.0.99"], "ssh_ports": [22]})
        with patch.object(self.health, "_ssh") as probe:
            with self.assertRaises(ValueError):
                self.health.check(self.store, "node-a", self.payload)
            probe.assert_not_called()

    def test_missing_scope_or_special_target_never_probes(self):
        for addresses in (["10.41.0.1"], ["127.0.0.1"], ["169.254.169.254"], ["::1"], ["0.0.0.0"], ["224.0.0.1"]):
            with self.subTest(addresses=addresses):
                self.approved["ips"] = addresses
                with patch.object(self.health, "_ssh") as probe:
                    with self.assertRaises(ManagementHealthUnavailable):
                        self.health.check(self.store, "node-a", self.payload)
                    probe.assert_not_called()

    def test_broad_probe_scope_is_forbidden(self):
        with self.assertRaises(ValueError):
            ManagementHealth("10.90.0.5", ["0.0.0.0/0"])

    def test_ip_or_approval_change_during_probe_invalidates_proof(self):
        changed = copy.deepcopy(self.approved)
        changed["ips"] = ["10.40.0.22"]
        self.store.verify_managed_enforcement.side_effect = [self.approved, changed]
        with patch.object(self.health, "_ssh", return_value={}):
            with self.assertRaises(ManagementHealthUnavailable):
                self.health.check(self.store, "node-a", self.payload)

    def test_failed_ssh_check_cannot_return_success_and_releases_capacity(self):
        with patch.object(self.health, "_ssh", side_effect=ManagementHealthUnavailable("test timeout")):
            with self.assertRaises(ManagementHealthUnavailable):
                self.health.check(self.store, "node-a", self.payload)
        self.assertTrue(self.health.slots.acquire(blocking=False))
        self.health.slots.release()

    def test_saturated_probe_capacity_fails_closed_without_scanning(self):
        for _ in range(8):
            self.assertTrue(self.health.slots.acquire(blocking=False))
        with patch.object(self.health, "_ssh") as probe:
            with self.assertRaises(ManagementHealthUnavailable):
                self.health.check(self.store, "node-a", self.payload)
            probe.assert_not_called()
        for _ in range(8):
            self.health.slots.release()

    def test_nonce_is_required_before_any_approval_or_network_work(self):
        for nonce in (None, "", "short", "z" * 129, "a b" * 12):
            with self.subTest(nonce=nonce):
                with self.assertRaises(ValueError):
                    self.health.check(self.store, "node-a", {**self.payload, "nonce": nonce})
        self.store.verify_managed_enforcement.assert_not_called()

    def test_new_ssh_connection_binds_approved_source_and_validates_complete_banner(self):
        connection = Mock()
        connection.recv.side_effect = [b"notice\r\nSSH-2.", b"0-OpenSSH_9\r\n"]
        connection.getsockname.return_value = ("10.90.0.5", 40123)
        with patch("controller.management_health.socket.socket", return_value=connection):
            import time
            proof = self.health._ssh("10.40.0.21", 2022, time.monotonic() + 8)
        connection.bind.assert_called_once_with(("10.90.0.5", 0))
        connection.connect.assert_called_once_with(("10.40.0.21", 2022))
        self.assertTrue(proof["ssh_banner_verified"])
        connection.close.assert_called_once()

    def test_http_or_partial_ssh_banner_is_not_ssh_reachability(self):
        for packets in ([b"HTTP/1.1 200 OK\r\n", b""], [b"SSH-2.0-incomplete", b""], [b"notice\nSSH-2.0-incomplete", b""]):
            connection = Mock()
            connection.getsockname.return_value = ("10.90.0.5", 40123)
            connection.recv.side_effect = packets
            with self.subTest(packets=packets), patch("controller.management_health.socket.socket", return_value=connection):
                import time
                with self.assertRaises(ManagementHealthUnavailable):
                    self.health._ssh("10.40.0.21", 2022, time.monotonic() + 8)
                connection.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
