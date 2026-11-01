import io
import tempfile
import unittest
from datetime import timedelta
from email.message import Message
from pathlib import Path
from unittest.mock import patch

from controller.app import App, handler_for
from controller.store import Store, now, parse_time, stamp


class DiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = Store(self.temp.name)
        self.base = parse_time(stamp())
        self.ssh = {"port": 2022, "protocol": "tcp", "address": "0.0.0.0", "process": "sshd", "service": "ssh", "application": "OpenSSH", "systemd_unit": "ssh.service", "pid": 123}
        self.nginx = {"port": 8080, "protocol": "tcp", "address": "0.0.0.0", "process": "nginx", "service": "nginx", "application": "Nginx", "systemd_unit": "nginx.service", "pid": 456}

    def report(self, offset, listeners, performed=True, **extra):
        at = self.base + timedelta(seconds=offset)
        value = {"hostname": "custom-service-host", "ips": ["10.1.1.1"], "listeners": listeners, "firewalld_state": "running", "discovery_performed": performed, "discovery_interval_seconds": 900, "discovered_at": stamp(at), **extra}
        with patch("controller.store.now", return_value=at):
            self.store.report("endpoint", value)
        return self.store.get("servers", "endpoint")

    def alerts(self, kind=None):
        return [alert for alert in self.store.all("alerts") if not kind or alert["kind"] == kind]

    def test_ssh_2022_metadata_and_first_seen_survive_cached_heartbeats(self):
        initial = self.report(0, [self.ssh])
        listener = initial["listeners"][0]
        self.assertEqual(listener["port"], 2022)
        self.assertEqual(listener["application"], "OpenSSH")
        self.assertEqual(listener["service"], "ssh")
        self.assertEqual(listener["systemd_unit"], "ssh.service")
        self.assertEqual(listener["pid"], 123)
        self.assertEqual(listener["first_seen"], stamp(self.base))
        cached = self.report(60, [self.nginx], performed=False)
        self.assertEqual(cached["listeners"], initial["listeners"])
        self.assertEqual(cached["last_discovery_at"], initial["last_discovery_at"])
        self.assertEqual(cached["discovery_changes"], initial["discovery_changes"])
        self.assertEqual(cached["last_seen"], stamp(self.base + timedelta(seconds=60)))
        self.assertEqual(len(self.alerts("service_discovered")), 1)
        self.assertEqual(self.alerts("service_discovered")[0]["severity"], "info")
        scan = self.report(900, [{**self.ssh, "pid": 999}])
        self.assertEqual(scan["listeners"][0]["first_seen"], listener["first_seen"])
        self.assertEqual(scan["listeners"][0]["last_seen"], stamp(self.base + timedelta(seconds=900)))
        self.assertEqual(scan["listeners"][0]["pid"], 999)
        self.assertEqual(scan["discovery_changes"], [])
        self.assertEqual(len(self.alerts()), 1)

    def test_new_nginx_8080_generates_one_alert_highlight_and_ack_clears_it(self):
        self.report(0, [self.ssh])
        added = self.report(900, [self.ssh, self.nginx])
        nginx = next(listener for listener in added["listeners"] if listener["port"] == 8080)
        self.assertTrue(nginx["is_new"])
        self.assertEqual(nginx["application"], "Nginx")
        change = added["discovery_changes"][0]
        self.assertEqual((change["kind"], change["port"], change["service"]), ("new", 8080, "nginx"))
        alert = next(item for item in self.alerts("service_discovered") if item["details"]["port"] == 8080)
        self.assertEqual(alert["severity"], "warning")
        self.assertIn("nginx", alert["message"])
        self.assertIn("8080/tcp", alert["message"])
        for offset in (960, 1020, 1080):
            cached = self.report(offset, [], performed=False)
            self.assertEqual(len(cached["listeners"]), 2)
            self.assertEqual(cached["last_discovery_at"], added["last_discovery_at"])
        self.assertEqual(len(self.alerts("service_discovered")), 2)
        self.store.acknowledge(alert["id"], "admin")
        acknowledged = self.store.get("servers", "endpoint")
        self.assertFalse(next(item for item in acknowledged["listeners"] if item["port"] == 8080)["is_new"])
        unchanged = self.report(1800, [self.ssh, self.nginx])
        unchanged_nginx = next(item for item in unchanged["listeners"] if item["port"] == 8080)
        self.assertFalse(unchanged_nginx["is_new"])
        self.assertEqual(unchanged_nginx["first_seen"], nginx["first_seen"])
        self.assertEqual(len(self.alerts("service_discovered")), 2)

    def test_same_port_application_change_alerts_but_pid_restart_does_not(self):
        first = self.report(0, [self.nginx])
        initial = first["listeners"][0]
        apache = {**self.nginx, "process": "httpd", "service": "httpd", "application": "Apache HTTP Server", "systemd_unit": "httpd.service", "pid": 999}
        changed = self.report(900, [apache])
        self.assertEqual(changed["discovery_changes"][0]["kind"], "changed")
        self.assertEqual(changed["listeners"][0]["first_seen"], initial["first_seen"])
        self.assertEqual(len(self.alerts("service_changed")), 1)
        self.assertEqual(self.alerts("service_changed")[0]["details"]["port"], 8080)
        self.store.acknowledge(initial["discovery_alert_id"], "admin")
        self.assertTrue(self.store.get("servers", "endpoint")["listeners"][0]["is_new"])
        self.report(1800, [{**apache, "pid": 1001}])
        self.assertEqual(len(self.alerts("service_changed")), 1)
        self.assertEqual(self.store.get("servers", "endpoint")["discovery_changes"], [])

    def test_discovery_staleness_and_failures_do_not_invent_service_outages(self):
        initial = self.report(0, [self.ssh])
        self.store.update_server("endpoint", {"expected_services": [{"port": 443, "protocol": "tcp"}]}, "admin")
        self.report(901, [], performed=False)
        with patch("controller.store.now", return_value=self.base + timedelta(seconds=901)):
            self.store.evaluate_health()
        stale = self.store.get("servers", "endpoint")
        self.assertEqual(stale["discovery_status"], "stale")
        self.assertEqual(stale["service_health_status"], "unknown")
        self.assertEqual(stale["last_discovery_at"], initial["last_discovery_at"])
        self.assertEqual(self.alerts("service_down"), [])
        failed = self.report(902, [], discovery_error="ss failed")
        self.assertEqual(failed["discovery_status"], "error")
        self.assertEqual(failed["listeners"], initial["listeners"])
        self.assertEqual(failed["last_discovery_at"], initial["last_discovery_at"])
        self.report(960, [], performed=False)
        self.assertEqual(self.store.get("servers", "endpoint")["discovery_error"], "ss failed")
        self.assertEqual(self.alerts("service_down"), [])

    def test_removed_listener_event_requires_fresh_scan_and_highlights_expire(self):
        self.report(0, [self.ssh, self.nginx])
        self.report(60, [], performed=False)
        self.assertEqual(self.alerts("service_down"), [])
        removed = self.report(900, [self.ssh])
        self.assertEqual(removed["discovery_changes"][0]["kind"], "removed")
        self.assertEqual(removed["discovery_changes"][0]["port"], 8080)
        self.assertEqual(len(self.alerts("service_down")), 1)
        self.report(960, [], performed=False)
        self.assertEqual(len(self.alerts("service_down")), 1)
        with patch("controller.store.now", return_value=self.base + timedelta(hours=25)):
            public = self.store.public(self.store.get("servers", "endpoint"))
        self.assertFalse(public["listeners"][0]["is_new"])

    def test_duplicate_endpoint_worker_pids_do_not_duplicate_initial_alerts(self):
        server = self.report(0, [self.nginx, {**self.nginx, "pid": 200}])
        self.assertEqual(len(server["listeners"]), 1)
        self.assertEqual(len(self.alerts("service_discovered")), 1)
        self.report(900, [{**self.nginx, "pid": 201}, {**self.nginx, "pid": 300}])
        self.assertEqual(len(self.alerts()), 1)


class SectionURLTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.dashboard = root / "dashboard"
        self.dashboard.mkdir()
        (self.dashboard / "index.html").write_text("<html>Prṛthak · पृथक्</html>")
        (self.dashboard / "app.js").write_text("console.log('asset');")
        self.app = App(Store(root / "data"), dashboard=self.dashboard)

    def request(self, path, method="GET"):
        handler = object.__new__(handler_for(self.app))
        handler.command, handler.path = method, path
        handler.connection = object()
        handler.client_address = ("127.0.0.1", 12345)
        handler.headers = Message()
        handler.wfile = io.BytesIO()
        captured = {"headers": {}}
        handler.send_response = lambda status: captured.update(status=status)
        handler.send_header = lambda key, value: captured["headers"].update({key: value})
        handler.end_headers = lambda: None
        handler.dispatch()
        captured["body"] = handler.wfile.getvalue()
        return captured

    def test_direct_section_paths_serve_shell_and_unknown_paths_do_not(self):
        for path in ("/", "/overview", "/servers", "/policies", "/traffic", "/alerts", "/activity", "/firewall", "/locations", "/locations/", "/servers/"):
            with self.subTest(path=path):
                response = self.request(path)
                self.assertEqual(response["status"], 200)
                self.assertIn("Prṛthak".encode(), response["body"])
        self.assertEqual(self.request("/app.js")["status"], 200)
        for path in ("/unknown", "/admin", "/%2e%2e/controller/store.py", "/../../etc/passwd", "/api-key.txt"):
            with self.subTest(path=path):
                self.assertEqual(self.request(path)["status"], 404)
        self.assertEqual(self.request("/servers", "POST")["status"], 405)
        self.assertEqual(self.request("/api/v1/servers")["status"], 401)
        self.assertEqual(handler_for(self.app).server_version, "Prthak/0.6")
        handler_for(self.app).server_version.encode("latin-1")


if __name__ == "__main__":
    unittest.main()
