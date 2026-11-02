"""Alert pages must never hide live outages behind bounded historical rows."""
from datetime import timedelta
from email.message import Message
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from controller import alert_views
from controller.app import App, handler_for
from controller.store import Store, now, parse_time, stamp
from controller.tests import private_pg


class AlertPageChecks:
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.store = self.make_store()
        self.at = parse_time(stamp())
        for index, name in enumerate(("billing", "payments")):
            self.store.report(name, {"hostname": name, "ips": [f"192.0.2.{10 + index}"], "listeners": [], "firewalld_state": "running"})

    def make_store(self):
        return Store(self.temp.name)

    def seed_alerts(self, count, *, status="resolved", prefix="history", server="billing", offset=0):
        with self.store.meta() as db:
            for index in range(count):
                self.store._put(db, "alerts", {"id": f"{prefix}-{index:04d}", "kind": "agent_offline", "server_id": server, "status": status, "severity": "critical", "message": "Agent heartbeat missing: " + server, "created_at": stamp(self.at + timedelta(seconds=offset + index)), **({"resolved_at": stamp()} if status == "resolved" else {})})

    def test_old_open_offline_alert_survives_more_than_five_hundred_newer_recoveries(self):
        self.seed_alerts(1, status="open", prefix="old-outage")
        self.seed_alerts(601, offset=1)
        with patch.object(self.store, "all", side_effect=AssertionError("No full alert history read")):
            result = alert_views.listing(self.store)
        self.assertEqual([row["id"] for row in result["items"]], ["old-outage-0000"])
        self.assertEqual((result["total"], result["all_count"], result["unacknowledged_count"], result["critical_count"]), (1, 602, 1, 1))
        self.assertFalse(result["has_more"])
        history = alert_views.listing(self.store, {"include_resolved": True, "limit": 100, "offset": 600})
        self.assertEqual((history["total"], len(history["items"])), (602, 2))
        self.assertIn("old-outage-0000", [row["id"] for row in history["items"]])

    def test_every_active_outage_is_paged_with_exact_counts_and_stable_tie_order(self):
        self.seed_alerts(507, status="open", prefix="outage")
        identifiers = []
        for offset in range(0, 507, 100):
            result = alert_views.listing(self.store, {"limit": 100, "offset": offset})
            self.assertEqual((result["total"], result["unresolved_count"], result["open_count"]), (507, 507, 507))
            self.assertLessEqual(len(result["items"]), 100)
            identifiers += [row["id"] for row in result["items"]]
        self.assertEqual(len(set(identifiers)), 507)
        self.assertEqual(identifiers[0], "outage-0506")
        with self.store.meta() as db:
            for name in ("tie-a", "tie-b"):
                self.store._put(db, "alerts", {"id": name, "server_id": "billing", "status": "open", "created_at": stamp(self.at + timedelta(days=1))})
        self.assertEqual([row["id"] for row in alert_views.listing(self.store, {"limit": 2})["items"]], ["tie-b", "tie-a"])

    def test_scope_search_known_ports_and_lateral_targets_match_counts(self):
        alerts = [
            {"id": "host", "server_id": "billing", "details": {}},
            {"id": "ssh", "server_id": "billing", "details": {"port": 22, "protocol": "tcp"}},
            {"id": "https", "server_id": "billing", "details": {"port": 443, "protocol": "tcp"}},
            {"id": "udp", "server_id": "billing", "details": {"port": 443, "protocol": "udp"}},
            {"id": "lateral", "kind": "possible_lateral_movement", "server_id": "payments", "details": {"ports": [22, 443], "protocol": "tcp", "target_server_ids": ["billing"]}},
            {"id": "other", "server_id": "payments", "details": {}},
        ]
        with self.store.meta() as db:
            for row in alerts:
                self.store._put(db, "alerts", {"status": "open", "severity": "critical", "message": "needle%_ literal", "created_at": stamp(), **row})
        query = {"server_ids": ["billing"], "listener_server_ids": ["billing"], "ports": ["443/tcp"]}
        result = alert_views.listing(self.store, query)
        self.assertEqual(set(row["id"] for row in result["items"]), {"host", "https", "lateral"})
        self.assertEqual(result["critical_count"], 3)
        self.assertEqual(alert_views.listing(self.store, {**query, "search": "needle%_"})["total"], 3)
        self.assertEqual(alert_views.listing(self.store, {**query, "search": "not found"})["total"], 0)
        self.assertEqual(alert_views.listing(self.store, {**query, "search": "not found", "search_server_ids": ["billing"]})["total"], 3)
        self.assertEqual(alert_views.listing(self.store, {**query, "listener_server_ids": []})["total"], 2)
        self.assertEqual(alert_views.listing(self.store, {"server_ids": []})["total"], 0)

    def test_bounds_and_large_details_do_not_turn_into_unbounded_navigation(self):
        for value in ({"limit": 0}, {"limit": 101}, {"offset": -1}, {"limit": True}, {"include_resolved": "true"}, {"server_ids": "billing"}, {"ports": ["65536"]}, {"ports": ["443/sctp"]}, {"search": "x" * 257}, {"command": "delete"}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                alert_views.listing(self.store, value)
        with self.store.meta() as db:
            self.store._put(db, "alerts", {"id": "huge", "server_id": "billing", "status": "open", "message": "x" * 100000, "created_at": stamp(), "details": {"raw": "private-large-detail" * 10000}})
        result = alert_views.listing(self.store)
        self.assertEqual(len(result["items"][0]["message"]), 2048)
        self.assertTrue(result["items"][0]["details"]["omitted"])
        self.assertEqual(result["total"], 1)

    def test_malformed_historical_details_cannot_break_port_or_target_filtering(self):
        details = ("not JSON", None, {"listener": "not an object"}, {"ports": "443"}, {"ports": {"one": 443}},
                   {"ports": ["not-a-port", None, {}, 22]}, {"port": "not-a-port"},
                   {"ports": ["not-a-port", None, {}, 443], "protocol": "tcp"})
        with self.store.meta() as db:
            for index, value in enumerate(details):
                self.store._put(db, "alerts", {"id": f"malformed-{index}", "server_id": "billing", "status": "open", "created_at": stamp(), "details": value})
            for suffix, targets in (("bad", "billing"), ("mixed", [None, {}, "billing"])):
                self.store._put(db, "alerts", {"id": "lateral-" + suffix, "kind": "possible_lateral_movement", "server_id": "payments", "status": "open", "created_at": stamp(), "details": {"target_server_ids": targets, "port": 443, "protocol": "tcp"}})
        query = {"server_ids": ["billing"], "ports": ["443/tcp"], "listener_server_ids": []}
        result = alert_views.listing(self.store, query)
        self.assertEqual(set(row["id"] for row in result["items"]), {"malformed-7", "lateral-mixed"})
        self.assertEqual(result["total"], 2)

    def test_real_heartbeat_recovery_updates_paged_outage_counts_once(self):
        # Scope to one real host: stale inventory and a repeated evaluator must
        # produce one outage, then a real resumed report must close it once.
        body = {"hostname": "billing", "ips": ["192.0.2.10"], "listeners": [], "firewalld_state": "running", "control_interval_seconds": 30}
        with patch("controller.store.now", return_value=self.at):
            self.store.report("billing", body)
        query = {"server_ids": ["billing"]}
        self.store.evaluate_health(at=self.at + timedelta(seconds=180))
        self.assertEqual(alert_views.listing(self.store, query)["total"], 0)
        for seconds in (181, 211):
            self.store.evaluate_health(at=self.at + timedelta(seconds=seconds))
        outage = alert_views.listing(self.store, query)
        self.assertEqual((outage["total"], outage["items"][0]["kind"]), (1, "agent_offline"))
        resumed = self.at + timedelta(seconds=220)
        with patch("controller.store.now", return_value=resumed):
            self.store.report("billing", body)
            self.store.evaluate_health()
            self.store.evaluate_health()
        self.assertEqual(alert_views.listing(self.store, query)["total"], 0)
        history = alert_views.listing(self.store, {**query, "include_resolved": True})
        self.assertEqual(history["total"], 2)
        self.assertEqual(sum(row["kind"] == "recovered" for row in history["items"]), 1)
        self.assertTrue(all(row["status"] == "resolved" for row in history["items"]))


class SQLiteAlertPages(AlertPageChecks, unittest.TestCase):
    def test_overview_counts_and_default_rows_ignore_resolved_history(self):
        # Use real reports for the normal inventory projection needed by overview.
        self.store.report("billing", {"hostname": "billing", "ips": ["192.0.2.10"], "listeners": [], "firewalld_state": "running"})
        self.store.report("payments", {"hostname": "payments", "ips": ["192.0.2.11"], "listeners": [], "firewalld_state": "running"})
        self.seed_alerts(503, status="open", prefix="outage")
        self.seed_alerts(601, offset=1000)
        result = self.store.overview()
        self.assertEqual(result["stats"]["active_alerts"], 503)
        self.assertEqual(result["alert_pagination"]["total"], 503)
        self.assertEqual(len(result["alerts"]), 50)
        self.assertTrue(all(row["status"] == "open" for row in result["alerts"]))

    def test_read_only_query_is_authenticated_bounded_and_cannot_acknowledge(self):
        app = App(self.store, tokens={"read_only": "reader"})
        self.seed_alerts(501, status="open")

        def request(method, path, body=None, token="reader"):
            handler = object.__new__(handler_for(app))
            handler.command, handler.path, handler.connection = method, path, object()
            handler.client_address = ("127.0.0.1", 12345)
            handler.headers = Message()
            if token:
                handler.headers["Authorization"] = "Bearer " + token
            handler.body = lambda: body
            captured = {}
            handler.response = lambda status, value=None, headers=None: captured.update(status=status, value=value)
            handler.dispatch()
            return captured

        page = request("POST", "/api/v1/alerts/query", {"limit": 100, "offset": 500})
        self.assertEqual((page["status"], page["value"]["total"], len(page["value"]["items"])), (200, 501, 1))
        self.assertEqual(request("GET", "/api/v1/alerts?limit=100&offset=500")["status"], 200)
        self.assertEqual(request("POST", "/api/v1/alerts/query", {}, token=None)["status"], 401)
        self.assertEqual(request("POST", "/api/v1/alerts/history-0000/ack", {})["status"], 403)
        for path in ("/api/v1/alerts?limit=101", "/api/v1/alerts?include_resolved=1", "/api/v1/alerts?unknown=x", "/api/v1/alerts?limit=1&limit=2"):
            self.assertEqual(request("GET", path)["status"], 400)
        self.assertEqual(request("POST", "/api/v1/alerts/query", {"limit": 501})["status"], 400)


PG_NAMES = private_pg.names("alert_views")


@unittest.skipUnless(os.environ.get("PRTHAK_PLATFORM_PG_ACCEPTANCE") == "1", "Owner opt-in for private PostgreSQL alert fixture")
class PostgreSQLAlertPages(AlertPageChecks, unittest.TestCase):
    @classmethod
    def verify(cls, db, expected):
        user, directory, database = db.execute("SELECT current_user,current_setting('data_directory'),current_database()").fetchone()
        if user != "prthak_test" or Path(directory).resolve() != private_pg.data_directory() or database != expected:
            raise RuntimeError("Only the prepared private PostgreSQL fixture is allowed")

    @classmethod
    def setUpClass(cls):
        import psycopg
        from psycopg import sql
        from psycopg.conninfo import make_conninfo
        cls.driver, cls.sql = psycopg, sql
        cls.parameters = private_pg.parameters()
        with psycopg.connect(**cls.parameters, dbname="postgres", autocommit=True) as db:
            cls.verify(db, "postgres")
            for name in PG_NAMES.values():
                if db.execute("SELECT 1 FROM pg_database WHERE datname=%s", (name,)).fetchone():
                    raise RuntimeError("Refusing to reuse a pre-existing private fixture database")
                db.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(name)))
        cls.dsns = {namespace: make_conninfo(**cls.parameters, dbname=name) for namespace, name in PG_NAMES.items()}

    def reset(self):
        for namespace, dsn in self.dsns.items():
            with self.driver.connect(dsn, autocommit=True) as db:
                self.verify(db, PG_NAMES[namespace])
                db.execute("DROP SCHEMA public CASCADE"); db.execute("CREATE SCHEMA public")

    def make_store(self):
        from controller.postgres import PostgresStore
        self.reset(); self.addCleanup(self.reset)
        return PostgresStore(self.dsns["metadata"], self.dsns["traffic"])
