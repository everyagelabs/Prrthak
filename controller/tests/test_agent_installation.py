import json
from pathlib import Path
import tempfile
import types
import unittest

from controller.agent_installation import create_kit, create_fleet_kit
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

    def test_restricted_management_sources_are_pinned_at_install_without_enforcement(self):
        sources = ["10.90.0.10/32", "2001:db8:90::10/128", "10.91.0.0/24", "10.90.0.10"]
        kit = create_kit(self.app, {**self.body, "management_sources": sources}, "admin")
        self.assertEqual(kit["config"]["management_sources"], ["10.90.0.10/32", "10.91.0.0/24", "2001:db8:90::10/128"])
        self.assertEqual(kit["schema_version"], 1)
        for key in ("enforce", "allow_firewall_changes", "learning_auto_allow", "unexpected_port_monitor_enabled"):
            self.assertFalse(kit["config"][key])
        fleet = create_fleet_kit(self.app, {**{key: value for key, value in self.body.items() if key != "expected_hostname"}, "management_sources": sources}, "admin")["kit"]
        self.assertEqual(fleet["schema_version"], 2)
        self.assertEqual(fleet["config"]["management_sources"], kit["config"]["management_sources"])
        self.assertFalse(fleet["config"]["enforce"])

    def test_invalid_or_unrestricted_bootstrap_management_pins_never_mint_credentials(self):
        for sources in (None, True, "10.90.0.10/32", [None], ["0.0.0.0/0"], ["::/0"], ["10.91.0.1/24"],
                        ["::ffff:192.0.2.1/128"], ["fe80::1%eth0/128"], ["999.0.0.1/32"],
                        ["10.90.0.10/32"] * 101, ["1" * 129]):
            for create, body in ((create_kit, self.body), (create_fleet_kit, {key: value for key, value in self.body.items() if key != "expected_hostname"})):
                with self.subTest(sources=sources, kind=create.__name__), self.assertRaises(ValueError):
                    create(self.app, {**body, "management_sources": sources}, "admin")
        self.assertEqual(self.store.all("tokens"), [])
        self.assertEqual(self.store.all("audit"), [])

    def test_preparation_is_explicit_schema_three_with_existing_enrollment_lifetimes(self):
        from controller.store import parse_time
        for options in ({"install_dependencies": True, "ufw_action": "preserve"},
                        {"install_dependencies": False, "ufw_action": "assess"},
                        {"install_dependencies": True, "ufw_action": "assess"}):
            with self.subTest(options=options):
                individual = create_kit(self.app, {**self.body, "installation_options": options}, "admin")
                self.assertEqual(individual["schema_version"], 3)
                self.assertEqual(individual["installation_options"], options)
                self.assertEqual(individual["expected_hostname"], "billing-01")
                self.assertNotIn("enrollment_profile_id", individual)
                self.assertEqual((parse_time(individual["expires_at"]) - parse_time(individual["issued_at"])).total_seconds(), 900)
                body = {key: value for key, value in self.body.items() if key != "expected_hostname"}
                fleet = create_fleet_kit(self.app, {**body, "name": "Prepared fleet", "installation_options": options}, "admin")
                kit = fleet["kit"]
                self.assertEqual(kit["schema_version"], 3)
                self.assertEqual(kit["installation_options"], options)
                self.assertEqual(kit["enrollment_profile_id"], fleet["profile"]["id"])
                self.assertFalse(kit["expected_hostname"])
                self.assertEqual((parse_time(kit["expires_at"]) - parse_time(kit["issued_at"])).total_seconds(), 24 * 3600)
                for current in (individual, kit):
                    self.assertFalse(current["config"]["enforce"])
                    self.assertFalse(current["config"]["allow_firewall_changes"])
                    self.assertFalse(current["config"]["learning_auto_allow"])
                    self.assertNotIn(current["enrollment_token"], json.dumps(self.store.all("tokens") + self.store.all("audit")))

    def test_invalid_or_unselected_preparation_never_mints_a_credential(self):
        fleet_body = {key: value for key, value in self.body.items() if key != "expected_hostname"}
        malformed = (None, True, {}, {"install_dependencies": True},
                     {"install_dependencies": "true", "ufw_action": "preserve"},
                     {"install_dependencies": 1, "ufw_action": "preserve"},
                     {"install_dependencies": False, "ufw_action": "preserve"},
                     {"install_dependencies": False, "ufw_action": "migrate"},
                     {"install_dependencies": True, "ufw_action": ["preserve"]},
                     {"install_dependencies": True, "ufw_action": "assess", "command": "ufw disable"})
        for value in malformed:
            for callback, body in ((create_kit, self.body), (create_fleet_kit, fleet_body)):
                with self.subTest(value=value, callback=callback.__name__), self.assertRaises(ValueError):
                    callback(self.app, {**body, "installation_options": value}, "admin")
        self.assertEqual(self.store.all("tokens"), [])
        self.assertEqual(self.store.all("audit"), [])

    def test_omitted_preparation_preserves_the_legacy_fleet_schema(self):
        body = {key: value for key, value in self.body.items() if key != "expected_hostname"}
        result = create_fleet_kit(self.app, body, "admin")
        self.assertEqual(result["kit"]["schema_version"], 2)
        self.assertNotIn("installation_options", result["kit"])


if __name__ == "__main__":
    unittest.main()
