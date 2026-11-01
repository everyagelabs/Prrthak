import json
from pathlib import Path
import tempfile
import types
import unittest

from controller.agent_installation import create_kit
from controller.pki import Signer, init_ca
from controller.store import Store


class AgentKitTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.pki = init_ca(cls.temp.name)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.store = Store(temp.name)
        self.app = types.SimpleNamespace(demo=False, signer=Signer(self.pki / "ca.pem", self.pki / "ca-key.pem"),
                                         controller_certificate=self.pki / "controller.pem", store=self.store)
        self.body = {"family": "rhel", "architecture": "amd64", "expected_hostname": "billing-01",
                     "controller_url": "https://localhost:8787", "interval_seconds": 30, "discovery_interval_seconds": 900}

    def test_private_monitor_kit_has_public_ca_only_and_hashed_one_use_token(self):
        kit = create_kit(self.app, self.body, "admin")
        self.assertEqual(kit["schema_version"], 1)
        self.assertEqual(kit["expected_hostname"], "billing-01")
        self.assertNotIn("PRIVATE KEY", json.dumps(kit))
        for key in ("enforce", "allow_firewall_changes", "learning_auto_allow", "unexpected_port_monitor_enabled"):
            self.assertFalse(kit["config"][key])
        self.assertEqual(kit["config"]["interval_seconds"], 30)
        self.assertEqual(len(self.store.all("tokens")), 1)
        self.assertNotIn(kit["enrollment_token"], json.dumps(self.store.all("tokens") + self.store.all("audit")))

    def test_invalid_url_san_ca_interval_or_injected_opt_in_mints_no_credential(self):
        for changes in ({"controller_url": "http://localhost"}, {"controller_url": "https://unrelated.example"},
                        {"controller_ca_pem": "not-pem"}, {"controller_ca_pem": (self.pki / "ca-key.pem").read_text()},
                        {"controller_ca_pem": (self.pki / "ca.pem").read_text() * 17},
                        {"interval_seconds": True}, {"discovery_interval_seconds": 1}, {"enforce": True},
                        {"family": "windows"}, {"expected_hostname": "bad\nhost"}):
            with self.subTest(changes=list(changes)), self.assertRaises(ValueError):
                create_kit(self.app, {**self.body, **changes}, "admin")
        self.assertEqual(self.store.all("tokens"), [])

    def test_separate_channel_origins_are_included_only_after_actual_tls_name_verification(self):
        kit = create_kit(self.app, {**self.body, "control_url": "https://localhost:8788", "discovery_url": "https://localhost:8789"}, "admin")
        self.assertEqual(kit["config"]["control_url"], "https://localhost:8788")
        self.assertEqual(kit["config"]["discovery_url"], "https://localhost:8789")
        count = len(self.store.all("tokens"))
        for channels in ({"control_url": "http://localhost"}, {"discovery_url": "https://unrelated.example"}):
            with self.subTest(channels=channels), self.assertRaises(ValueError):
                create_kit(self.app, {**self.body, **channels}, "admin")
        self.assertEqual(len(self.store.all("tokens")), count)

    def test_demo_does_not_issue_real_bootstrap_data(self):
        self.app.demo = True
        with self.assertRaises(ValueError):
            create_kit(self.app, self.body, "demo")
        self.assertEqual(self.store.all("tokens"), [])


if __name__ == "__main__":
    unittest.main()
