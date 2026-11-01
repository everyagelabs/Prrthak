"""The learning witness uses its own authority and checks it around network I/O."""
import copy
import unittest
from unittest.mock import Mock, patch

from controller.management_health import ManagementHealth, ManagementHealthUnavailable


class LearningHealthTests(unittest.TestCase):
    def setUp(self):
        self.store = Mock()
        self.health = ManagementHealth("10.90.0.5", ["10.70.0.0/24"])
        self.payload = {"nonce": "a" * 32, "ssh_ports": [2022]}
        self.authority = {"server_id": "node-a", "version": 3, "generation": 3,
                          "digest": "d" * 64, "protection_digest": "p" * 64,
                          "target_ips_digest": "t" * 64, "binding_digest": "b" * 64,
                          "ips": ["10.70.0.11"], "ssh_ports": [2022],
                          "management_sources": ["10.90.0.0/24"]}

    def test_learning_witness_binds_overlay_generation_and_never_uses_normal_approval(self):
        with patch("controller.learning_policies.verify_assignment", return_value=self.authority) as verify:
            with patch.object(self.health, "_ssh", return_value={"ssh_banner_verified": True}) as probe:
                result = self.health.check_learning(self.store, "node-a", self.payload)
        self.assertEqual(verify.call_count, 2)
        probe.assert_called_once()
        self.store.verify_managed_enforcement.assert_not_called()
        for field in ("server_id", "version", "generation", "digest", "protection_digest", "target_ips_digest", "binding_digest"):
            self.assertEqual(result[field], self.authority[field])
        self.assertEqual(result["nonce"], self.payload["nonce"])
        self.assertTrue(result["controller_ok"])

    def test_expired_or_stopped_authority_cannot_probe(self):
        with patch("controller.learning_policies.verify_assignment", side_effect=PermissionError("grant stopped")):
            with patch.object(self.health, "_ssh") as probe:
                with self.assertRaises(PermissionError):
                    self.health.check_learning(self.store, "node-a", self.payload)
                probe.assert_not_called()

    def test_overlay_change_or_stop_during_probe_cannot_commit(self):
        changed = copy.deepcopy(self.authority)
        changed["generation"] += 1
        for replacement in (changed, PermissionError("grant stopped during SSH check")):
            with self.subTest(replacement=type(replacement).__name__):
                with patch("controller.learning_policies.verify_assignment", side_effect=[self.authority, replacement]):
                    with patch.object(self.health, "_ssh", return_value={}):
                        with self.assertRaises((ManagementHealthUnavailable, PermissionError)):
                            self.health.check_learning(self.store, "node-a", self.payload)
                self.assertTrue(self.health.slots.acquire(blocking=False))
                self.health.slots.release()

    def test_unapproved_ssh_ports_and_missing_nonce_do_not_probe(self):
        with patch("controller.learning_policies.verify_assignment", return_value=self.authority):
            with patch.object(self.health, "_ssh") as probe:
                for payload in ({**self.payload, "ssh_ports": [22]}, {**self.payload, "nonce": ""}):
                    with self.assertRaises(ValueError):
                        self.health.check_learning(self.store, "node-a", payload)
                probe.assert_not_called()
