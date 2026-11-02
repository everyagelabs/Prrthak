"""Complete historical audit navigation/export; no deployment databases used."""
import csv
from datetime import timedelta
from email.message import Message
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from controller import audit_views
from controller.app import App, handler_for
from controller.store import Store, parse_time, stamp
from controller.tests import private_pg


class AuditPageChecks:
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.store = self.make_store()
        self.at = parse_time("2026-11-02T00:00:00Z")

    def make_store(self):
        return Store(self.temp.name)

    def event(self, identifier, **updates):
        value = {"id": identifier, "action": "policy.updated", "actor": "admin-one", "created_at": stamp(self.at), "details": {"policy_id": "billing"}, **updates}
        with self.store.meta() as db:
            self.store._put(db, "audit", value)
        return value

    def history(self, count=607):
        with self.store.meta() as db:
            for index in range(count):
                self.store._put(db, "audit", {"id": f"event-{index:04d}", "action": "server.updated", "actor": "other", "created_at": stamp(self.at + timedelta(seconds=index + 1)), "details": {}})

    def test_old_matching_history_survives_more_than_five_hundred_newer_events(self):
        self.history()
        self.event("old-billing-event", actor="billing-admin%_", action="policy.created")
        with patch.object(self.store, "all", side_effect=AssertionError("History must not load the entire table")):
            result = audit_views.listing(self.store, {"search": "billing-admin%_"})
        self.assertEqual((result["total"], result["items"][0]["id"], result["has_more"]), (1, "old-billing-event", False))
        self.assertEqual(audit_views.listing(self.store, {"search": "billing-admin%_missing"})["total"], 0)
        page = audit_views.listing(self.store, {"limit": 100, "offset": 600})
        self.assertEqual((page["total"], len(page["items"])), (608, 8))
        self.assertIn("old-billing-event", [x["id"] for x in page["items"]])

    def test_all_history_is_paged_with_exact_totals_and_stable_id_ties(self):
        self.history()
        self.event("tie-a"); self.event("tie-b")
        identifiers = []
        for offset in range(0, 609, 100):
            page = audit_views.listing(self.store, {"limit": 100, "offset": offset})
            self.assertEqual(page["total"], 609)
            identifiers.extend(x["id"] for x in page["items"])
            self.assertEqual(page["has_more"], offset + len(page["items"]) < 609)
        self.assertEqual(len(set(identifiers)), 609)
        self.assertEqual(identifiers[-2:], ["tie-b", "tie-a"])

    def test_exact_actor_action_and_inclusive_timezone_dates_combine_before_paging(self):
        for seconds, actor, action in ((0, "admin-one", "policy.updated"), (1, "admin-one", "policy.updated"), (2, "admin-two", "policy.updated"), (3, "admin-one", "policy.deleted")):
            self.event(str(seconds), actor=actor, action=action, created_at=stamp(self.at + timedelta(seconds=seconds)))
        scope = {"actor": "admin-one", "action": "policy.updated", "from_at": "2026-11-02T05:30:00.500+05:30", "to_at": "2026-11-02T00:00:01Z"}
        result = audit_views.listing(self.store, scope)
        self.assertEqual([x["id"] for x in result["items"]], ["1"])
        with audit_views.csv_spool(self.store, scope) as (source, _):
            exported = list(csv.DictReader(io.StringIO(source.read().decode("utf-8-sig"))))
        self.assertEqual([x["id"] for x in exported], ["1"])
        self.event("invalid-time", created_at="not-a-timestamp")
        self.assertEqual(audit_views.listing(self.store, scope)["total"], 1)

    def test_complete_export_keeps_older_events_and_redacts_sensitive_values_with_formula_safety(self):
        self.history()
        self.event("private-old", actor=" \t=HYPERLINK(unsafe)", details={"reason": "old event", "password": "never-return", "nested": [{"client_secret": "also-private", "token_id": "public-reference", "api_key": "hidden-api-key"}], "raw": "-----BEGIN PRIVATE KEY----- private bytes"})
        with audit_views.csv_spool(self.store) as (source, size):
            raw = source.read(); self.assertEqual(len(raw), size)
        exported = list(csv.DictReader(io.StringIO(raw.decode("utf-8-sig"))))
        self.assertEqual(len(exported), 608)
        old = next(x for x in exported if x["id"] == "private-old")
        self.assertTrue(old["actor"].startswith("'"))
        self.assertNotIn(b"never-return", raw); self.assertNotIn(b"also-private", raw); self.assertNotIn(b"private bytes", raw); self.assertNotIn(b"hidden-api-key", raw)
        details = json.loads(old["details_json"])
        self.assertEqual(details["nested"][0]["token_id"], "public-reference")
        self.assertEqual(details["nested"][0]["client_secret"], "[REDACTED]")
        self.assertEqual(audit_views.listing(self.store, {"search": "never-return"})["total"], 0)

    def test_large_navigation_details_are_explicit_but_complete_csv_does_not_truncate(self):
        text = "large retained audit detail " * 60000
        self.event("large", details={"reason": text})
        page = audit_views.listing(self.store)
        self.assertTrue(page["items"][0]["details_omitted"])
        previous_limit = csv.field_size_limit(audit_views.MAX_EVENT_BYTES)
        try:
            with audit_views.csv_spool(self.store) as (source, _):
                entry = next(csv.DictReader(io.StringIO(source.read().decode("utf-8-sig"))))
        finally:
            csv.field_size_limit(previous_limit)
        self.assertEqual(json.loads(entry["details_json"])["reason"], text)
        self.event("string", details="plain string")
        self.event("boolean", details=True)
        values = {x["id"]: x["details"] for x in audit_views.listing(self.store)["items"]}
        self.assertEqual(values["string"], "plain string"); self.assertIs(values["boolean"], True)

    def test_export_bounds_fail_before_yield_and_capacity_recovers(self):
        self.event("one")
        yielded = False
        with self.assertRaisesRegex(ValueError, "Complete audit CSV"):
            with audit_views.csv_spool(self.store, max_bytes=64):
                yielded = True
        self.assertFalse(yielded)
        with audit_views.csv_spool(self.store), audit_views.csv_spool(self.store):
            with self.assertRaises(audit_views.ExportBusy):
                with audit_views.csv_spool(self.store):
                    self.fail("Third export must not enter")
        with audit_views.csv_spool(self.store) as (source, _):
            self.assertTrue(source.read().startswith(b"\xef\xbb\xbf"))
        self.event("oversized", details={"reason": "é" * (audit_views.MAX_EVENT_BYTES // 2)})
        with self.assertRaisesRegex(ValueError, "event exceeds"):
            with audit_views.csv_spool(self.store):
                self.fail("Oversized row must not reach response headers")

    def test_invalid_filters_and_injection_are_rejected_or_literal(self):
        self.event("safe")
        for value in ({"limit": 101}, {"limit": True}, {"offset": -1}, {"offset": 1.0}, {"search": "x" * 257}, {"action": []}, {"from_at": "yesterday"}, {"to_at": "2026-11-02"}, {"from_at": "2026-11-03T00:00:00Z", "to_at": "2026-11-02T00:00:00Z"}, {"command": "delete"}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                audit_views.listing(self.store, value)
        for query in ({"limit": ["1", "2"]}, {"unknown": ["x"]}, {"limit": ["1.0"]}, {"search": []}):
            with self.subTest(query=query), self.assertRaises(ValueError):
                audit_views.query_parameters(query)
        self.assertEqual(audit_views.listing(self.store, {"search": "'; DROP TABLE audit; --"})["total"], 0)
        self.assertEqual(audit_views.listing(self.store)["total"], 1)
        with self.assertRaises(ValueError):
            with audit_views.csv_spool(self.store, {"limit": 1}):
                self.fail("A complete export cannot accept page truncation")


class SQLiteAuditPages(AuditPageChecks, unittest.TestCase):
    def test_read_only_routes_query_and_complete_export_but_cannot_write(self):
        self.history(501)
        app = App(self.store, tokens={"read_only": "reader"})
        def request(method, path, body=None, token="reader"):
            handler = object.__new__(handler_for(app))
            handler.command, handler.path, handler.connection = method, path, object()
            handler.client_address = ("127.0.0.1", 12345); handler.headers = Message()
            if token: handler.headers["Authorization"] = "Bearer " + token
            handler.body = lambda: body
            captured = {"headers": {}}
            handler.response = lambda status, value=None, headers=None: captured.update(status=status, value=value)
            handler.send_response = lambda status: captured.update(status=status)
            handler.send_header = lambda key, value: captured["headers"].update({key: value})
            handler.end_headers = lambda: None
            handler.wfile = io.BytesIO()
            handler.dispatch(); captured["bytes"] = handler.wfile.getvalue()
            return captured
        page = request("POST", "/api/v1/audit/query", {"offset": 500, "limit": 50})
        self.assertEqual((page["status"], page["value"]["total"], len(page["value"]["items"])), (200, 501, 1))
        self.assertEqual(request("GET", "/api/v1/audit?offset=500&limit=50")["status"], 200)
        result = request("POST", "/api/v1/audit/export.csv", {})
        self.assertEqual(result["status"], 200)
        self.assertEqual(len(list(csv.DictReader(io.StringIO(result["bytes"].decode("utf-8-sig"))))), 501)
        self.assertIn("text/csv", result["headers"]["Content-Type"])
        self.assertEqual(request("POST", "/api/v1/audit/query", {}, token=None)["status"], 401)
        self.assertEqual(request("POST", "/api/v1/audit/export.csv", {}, token=None)["status"], 401)
        self.assertEqual(request("POST", "/api/v1/policies", {})["status"], 403)
        self.assertEqual(request("GET", "/api/v1/audit?limit=1&limit=2")["status"], 400)
        self.assertEqual(request("POST", "/api/v1/audit/export.csv", {"limit": 1})["status"], 400)


PG_NAMES = private_pg.names("audit_views")


@unittest.skipUnless(os.environ.get("PRTHAK_PLATFORM_PG_ACCEPTANCE") == "1", "Owner opt-in for private PostgreSQL audit fixture")
class PostgreSQLAuditPages(AuditPageChecks, unittest.TestCase):
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
        cls.driver, cls.sql = psycopg, sql; cls.parameters = private_pg.parameters()
        with psycopg.connect(**cls.parameters, dbname="postgres", autocommit=True) as db:
            cls.verify(db, "postgres")
            for name in PG_NAMES.values():
                if db.execute("SELECT 1 FROM pg_database WHERE datname=%s", (name,)).fetchone():
                    raise RuntimeError("Refusing to reuse pre-existing fixture database")
                db.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(name)))
        cls.dsns = {namespace: make_conninfo(**cls.parameters, dbname=name) for namespace, name in PG_NAMES.items()}

    def reset(self):
        for namespace, dsn in self.dsns.items():
            with self.driver.connect(dsn, autocommit=True) as db:
                self.verify(db, PG_NAMES[namespace]); db.execute("DROP SCHEMA public CASCADE"); db.execute("CREATE SCHEMA public")

    def make_store(self):
        from controller.postgres import PostgresStore
        self.reset(); self.addCleanup(self.reset)
        return PostgresStore(self.dsns["metadata"], self.dsns["traffic"])
