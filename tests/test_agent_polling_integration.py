"""Optional native-agent polling acceptance through real loopback mTLS.

SEG_AGENT_BINARY must name the freshly built native agent. Configuration,
certificates, inventory and polling cache belong only to temporary fixtures.
Enforcement, firewall changes, learning allows and monitoring are disabled.
"""
from contextlib import ExitStack
import json
import os
from pathlib import Path
import secrets
import ssl
import subprocess
import tempfile
import time
import unittest

from controller.app import App
from controller.auth import EntraAuth, EntraConfig
from controller.pki import Signer, init_ca
from controller.store import Store
from test_integration import request, running


@unittest.skipUnless(os.environ.get("SEG_AGENT_BINARY"), "Set SEG_AGENT_BINARY to the current native agent")
class NativeAgentPollingIntegrationTests(unittest.TestCase):
    def test_global_and_billing_payments_overrides_reach_running_timers_and_persist_exact_receipts(self):
        with ExitStack() as resources:
            root = Path(resources.enter_context(tempfile.TemporaryDirectory(prefix="prthak-native-polling-")))
            pki = init_ca(root / "tls")
            store = Store(root / "controller")
            token = secrets.token_urlsafe(48)
            headers = {"Authorization": "Bearer " + token}
            browser = ssl.create_default_context(cafile=str(pki / "ca.pem"))
            app = App(store, signer=Signer(pki / "ca.pem", pki / "ca-key.pem"), tokens={"super_admin": token},
                      auth=EntraAuth(store, EntraConfig()), controller_certificate=pki / "controller.pem",
                      controller_private_key=pki / "controller-key.pem")
            tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            tls.load_cert_chain(pki / "controller.pem", pki / "controller-key.pem")
            tls.load_verify_locations(pki / "ca.pem")
            tls.verify_mode = ssl.CERT_OPTIONAL
            assignments = []
            original_assignment = store.assignment
            reports = []
            original_report = store.report

            def observed_report(identifier, value):
                result = original_report(identifier, value)
                reports.append({key: value.get(key) for key in ("control_interval_seconds", "discovery_interval_seconds", "polling_settings")})
                return result

            def observed_assignment(identifier):
                result = original_assignment(identifier)
                assignments.append((time.monotonic(), result[0]["polling_settings"]))
                return result

            store.assignment = observed_assignment
            store.report = observed_report
            port = resources.enter_context(running(app, tls))

            def api(method, path, body=None):
                status, result, _ = request(port, method, "/api/v1/" + path, body, headers, browser)
                self.assertIn(status, (200, 201), result)
                return result

            group = api("POST", "groups", {"name": "Payments polling", "type": "dynamic", "selector": {"application": "payments"}})
            config = {"expected_revision": 0, "defaults": {"control_interval_seconds": 5, "discovery_interval_seconds": 600},
                "rules": [{"id": "billing-tag", "name": "Billing tag polling", "enabled": True, "priority": 10,
                           "selector": {"application": "billing"}, "control_interval_seconds": 5, "discovery_interval_seconds": 120},
                          {"id": "payments-group", "name": "Payments group polling", "enabled": True, "priority": 20,
                           "group_ids": [group["id"]], "control_interval_seconds": 5, "discovery_interval_seconds": 180}]}
            self.assertEqual(api("POST", "platform/agent-settings/preview", config)["target_server_count"], 0)
            self.assertEqual(api("POST", "platform/agent-settings", config)["revision"], 1)
            bootstrap = api("POST", "enrollment-tokens", {"name": "Native polling fixture"})
            token_path = root / "enrollment.token"
            token_path.write_text(bootstrap["token"])
            token_path.chmod(0o600)
            state_dir, config_path = root / "agent", root / "agent.json"
            local_config = {"controller_url": "https://localhost:" + str(port), "state_dir": str(state_dir),
                "ca_cert": str(pki / "ca.pem"), "enrollment_token_file": str(token_path), "interval_seconds": 300,
                "discovery_interval_seconds": 900, "request_timeout_seconds": 3, "enforce": False,
                "allow_firewall_changes": False, "learning_auto_allow": False, "unexpected_port_monitor_enabled": False}
            config_path.write_text(json.dumps(local_config))
            log = resources.enter_context((root / "agent.log").open("wb"))
            environment = dict(os.environ)
            environment.pop("SEG_ENROLLMENT_TOKEN", None)
            processes = []

            def start():
                process = subprocess.Popen([os.environ["SEG_AGENT_BINARY"], "--config", str(config_path)],
                    env=environment, stdout=log, stderr=log)
                processes.append(process)
                return process

            def stop(process):
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=8)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=3)

            resources.callback(lambda: [stop(process) for process in processes])
            process = start()

            def wait_current(discovery, seconds=15):
                deadline = time.monotonic() + seconds
                last = None
                while time.monotonic() < deadline:
                    if process.poll() is not None:
                        self.fail("Native fixture agent exited: " + (root / "agent.log").read_text()[-3000:])
                    rows = api("GET", "platform/agent-settings")["servers"]
                    if rows:
                        last = rows[0]
                        if (last["status"] == "current" and last["desired"]["discovery_interval_seconds"] == discovery
                                and last["reported_control_interval_seconds"] == 5
                                and last["reported_discovery_interval_seconds"] == discovery):
                            self.assertEqual(last["observed"]["version"], 1)
                            self.assertEqual(last["observed"]["digest"], last["desired"]["digest"])
                            return last
                    time.sleep(0.1)
                self.fail("Native polling receipt did not match desired timing: " + str(last))

            row = wait_current(600)
            identifier = row["server_id"]
            deadline = time.monotonic() + 9
            while len(assignments) < 2 and time.monotonic() < deadline:
                time.sleep(0.1)
            self.assertGreaterEqual(len(assignments), 2, "The running agent retained its 300-second local timer")
            elapsed = assignments[1][0] - assignments[0][0]
            self.assertGreaterEqual(elapsed, 4.5)
            self.assertLess(elapsed, 9)
            api("PATCH", "servers/" + identifier, {"tags": {"application": "billing"}})
            billing = wait_current(120)
            api("PATCH", "servers/" + identifier, {"tags": {"application": "payments"}})
            payments = wait_current(180)
            self.assertNotEqual(billing["desired"]["digest"], payments["desired"]["digest"])
            self.assertEqual(api("GET", "platform/agent-settings")["revision"], 1)
            cached = json.loads((state_dir / "polling-settings.json").read_text())
            self.assertEqual(cached["digest"], payments["observed"]["digest"])
            self.assertEqual(cached["matched_rule_ids"], ["payments-group"])
            self.assertEqual((state_dir / "polling-settings.json").stat().st_mode & 0o777, 0o600)
            self.assertEqual(json.loads(config_path.read_text()), local_config)
            from controller import __version__
            self.assertEqual(store.server(identifier)["agent_version"], __version__)
            stop(process)
            before_restart = len(reports)
            process = start()
            deadline = time.monotonic() + 10
            while len(reports) == before_restart and time.monotonic() < deadline:
                time.sleep(0.1)
            self.assertGreater(len(reports), before_restart, "Restarted native agent did not report")
            first_report = reports[before_restart]
            self.assertEqual(first_report["control_interval_seconds"], 5)
            self.assertEqual(first_report["discovery_interval_seconds"], 180)
            self.assertEqual(first_report["polling_settings"]["digest"], cached["digest"],
                             "The first report must use persisted timing before fetching a new assignment")
            wait_current(180)
            self.assertEqual(len(store.servers()), 1)
            self.assertEqual(json.loads((state_dir / "polling-settings.json").read_text())["digest"], cached["digest"])


if __name__ == "__main__":
    unittest.main()
