"""Small SQLite fixtures; optional private PG cases are run only by the owner."""
from contextlib import contextmanager
from datetime import timedelta
from controller.tests import private_pg as pg_fixture

import copy
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from controller import session_views as views
from controller.store import Store, now, stamp


class SessionViewChecks:
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="prthak-session-view-")
        self.addCleanup(self.temporary.cleanup)
        self.store = self.make_store()
        self.ids = [f"host-{index:03d}" for index in range(200)]
        self.manual_ports = [{"port": 22, "protocol": "tcp"}, {"port": 53, "protocol": "udp"}]
        self.canary = "PRIVATE_CANONICAL_MATRIX_" + "x" * 20000
        self.initial = {"id": "initial-session-live", "status": "draft", "created_at": "2026-01-06T00:00:00Z", "expires_at": stamp(now() + timedelta(hours=1)), "digest": "a" * 64, "plan_digest": "b" * 64, "confirmation_nonce": "private-nonce", "scope": {"targets": [{"server_id": self.ids[0], "matrix": self.canary}]}}
        self.live = {
            "id": "session-live", "status": "active", "starts_at": "2026-01-06T00:00:00Z", "expires_at": stamp(now() + timedelta(hours=1)),
            "selection_mode": "discovered", "policy_action": "auto_allow", "server_ids": self.ids,
            "ports": [{"port": 65000, "protocol": "tcp"}], "port_filter": [{"port": 443, "protocol": "tcp"}],
            "server_ports": {identifier: [{"port": 10000 + index, "protocol": "tcp"}] for index, identifier in enumerate(self.ids)},
            "discovery_pending_server_ids": [self.ids[1], self.ids[3]], "evidence_revision": 7,
            "discovery_results": {
                self.ids[0]: {"status": "ready", "ports": [{"port": 10000, "protocol": "tcp"}], "discovered_at": "2026-01-06T00:01:00Z", "listeners": [{"process": "PRIVATE_LISTENER_SNAPSHOT"}]},
                self.ids[1]: {"status": "error", "error": "e" * 4200},
                self.ids[2]: {"status": "no_listeners", "ports": []},
            },
            "initial_approval_state": "awaiting_review", "initial_approval_plan": self.initial,
            "initial_approval_scope": {"private": self.canary}, "initial_approval_proof": {"private": self.canary},
        }
        self.expired = {"id": "session-expired", "status": "active", "starts_at": "2026-01-05T00:00:00Z", "expires_at": stamp(now() - timedelta(hours=1)), "selection_mode": "manual", "policy_action": "observe", "server_ids": [self.ids[0], "host-other"], "ports": self.manual_ports, "port_filter": []}
        self.stopped = {**self.expired, "id": "session-stopped", "status": "stopped", "starts_at": "2026-01-04T00:00:00Z", "server_ids": ["host-stopped"]}
        self.compiled = {"server_id": "server-a", "version": 4, "digest": "c" * 64, "mode": "enforce", "services": [{"port": 443, "protocol": "tcp", "sources": ["10.20.0.1/32", "10.20.0.2/32"]}]}
        with self.store.meta() as db:
            for session in (self.live, self.expired, self.stopped): self.store._put(db, "sessions", session)
            self.store._put(db, "servers", {"id": "server-a", "_compiled": self.compiled, "listeners": [{"private": self.canary}]})
            self.store._put(db, "servers", {"id": "server-empty", "listeners": []})

    def make_store(self):
        return Store(self.temporary.name)

    def array_parser(self):
        original = json.loads
        def arrays_only(raw):
            self.assertTrue(raw.lstrip().startswith("["), "Read-only telemetry parsed a canonical object")
            self.assertNotIn("PRIVATE_CANONICAL_MATRIX", raw)
            self.assertNotIn("PRIVATE_LISTENER_SNAPSHOT", raw)
            return original(raw)
        return Mock(side_effect=arrays_only)

    def assert_summary(self, value):
        self.assertTrue(value["summary_only"])
        for field in ("server_ports", "discovery_results", "discovery_pending_server_ids", "initial_approval_scope", "initial_approval_proof", "initial_approval_target_bindings", "listeners"):
            self.assertNotIn(field, value)
        if value.get("initial_approval_plan"):
            self.assertTrue(value["initial_approval_plan"]["summary_only"])
            for field in ("scope", "targets", "confirmation_nonce", "confirmation_phrase", "proof"):
                self.assertNotIn(field, value["initial_approval_plan"])

    def test_listing_pages_count_active_count_and_only_parses_projected_arrays(self):
        loads = self.array_parser()
        with patch.object(Store, "_all", side_effect=AssertionError("No global canonical sessions")), patch.object(views, "json", SimpleNamespace(loads=loads)):
            page = views.listing(self.store, limit=1)
            second = views.listing(self.store, limit=1, offset=1)
        self.assertEqual((page["total"], page["active_total"], len(page["items"]), page["has_more"]), (3, 1, 1, True))
        self.assertEqual(page["items"][0]["id"], "session-live")
        self.assertEqual(second["items"][0]["id"], "session-expired")
        self.assertEqual(loads.call_count, 6)
        self.assertEqual(page["items"][0]["ports"], [])
        self.assertEqual(page["items"][0]["discovery_pending_count"], 2)
        self.assertEqual(page["items"][0]["discovery_error_count"], 1)
        self.assert_summary(page["items"][0])

    def test_membership_filter_is_exact_and_never_truncates_the_member_array(self):
        result = views.listing(self.store, server_id=self.ids[0], limit=20)
        self.assertEqual((result["total"], result["active_total"]), (2, 1))
        self.assertEqual([item["id"] for item in result["items"]], ["session-live", "session-expired"])
        self.assertEqual(result["items"][0]["server_ids"], self.ids)
        self.assertEqual(result["items"][0]["server_count"], len(self.ids))
        self.assertEqual(result["server_id"], self.ids[0])
        for identifier in ("host-00", "host-missing"):
            empty = views.listing(self.store, server_id=identifier, limit=1)
            self.assertEqual((empty["total"], empty["items"], empty["has_more"]), (0, [], False))

    def test_header_keeps_exact_membership_and_only_navigation_for_initial_review(self):
        loads = self.array_parser()
        with patch.object(Store, "_all", side_effect=AssertionError("No global session parse")), patch.object(views, "json", SimpleNamespace(loads=loads)), self.store.read_meta() as db:
            header = views.header(db, self.live["id"])
            with self.assertRaises(KeyError): views.header(db, "missing-session")
        self.assertEqual(header["server_ids"], self.ids)
        self.assertEqual(header["evidence_revision"], 7)
        self.assertEqual(header["initial_approval_plan"]["id"], self.initial["id"])
        self.assertEqual(header["initial_approval_plan"]["digest"], self.initial["digest"])
        self.assertEqual(loads.call_count, 3)
        self.assert_summary(header)

    def test_discovered_host_page_uses_each_selected_hosts_exact_ports_without_listeners(self):
        loads = self.array_parser()
        with patch.object(Store, "_all", side_effect=AssertionError("No global session parse")), patch.object(views, "json", SimpleNamespace(loads=loads)):
            page = views.hosts(self.store, self.live["id"], limit=2, offset=1)
        self.assertEqual((page["total"], len(page["items"]), page["has_more"]), (200, 2, True))
        self.assertEqual([item["server_id"] for item in page["items"]], self.ids[1:3])
        for index, item in enumerate(page["items"], 1):
            self.assertEqual(item["ports"], self.live["server_ports"][self.ids[index]])
            self.assertNotIn("listeners", item)
            self.assertNotIn("discovery_results", item)
        self.assertEqual(page["items"][0]["status"], "error")
        self.assertEqual(len(page["items"][0]["error"]), 4096)
        self.assertTrue(page["items"][0]["pending"])
        self.assertFalse(page["items"][1]["pending"])
        self.assertEqual(loads.call_count, 2)

    def test_manual_host_page_preserves_exact_manual_ports_and_page_end(self):
        page = views.hosts(self.store, self.expired["id"], limit=1, offset=1)
        self.assertEqual((page["total"], len(page["items"]), page["has_more"]), (2, 1, False))
        self.assertEqual(page["items"][0]["server_id"], "host-other")
        self.assertEqual(page["items"][0]["ports"], self.manual_ports)
        self.assertEqual(page["items"][0]["status"], "manual")
        self.assertFalse(page["items"][0]["pending"])

    def test_array_size_bounds_reject_before_decoding(self):
        fail = Mock(side_effect=AssertionError("Oversized projected arrays cannot be decoded"))
        with patch.object(views, "MAX_IDS_BYTES", 128), patch.object(views, "json", SimpleNamespace(loads=fail)):
            with self.assertRaisesRegex(ValueError, "bound"): views.listing(self.store, limit=1)
        with patch.object(views, "MAX_PORT_BYTES", 2), patch.object(views, "json", SimpleNamespace(loads=fail)):
            with self.assertRaisesRegex(ValueError, "bound"): views.hosts(self.store, self.live["id"], limit=1)
        fail.assert_not_called()

    def test_compiled_policy_is_selected_bounded_and_snapshot_consistent(self):
        original = self.store.read_meta
        changed = {**self.compiled, "services": [{"private": "later-write" * 100}]}
        store = self.store
        class Cursor:
            def __init__(self, cursor): self.cursor = cursor
            def fetchone(self):
                value = self.cursor.fetchone()
                with store.meta() as writer: store._put(writer, "servers", {"id": "server-a", "_compiled": changed})
                return value
        class Connection:
            def __init__(self, db): self.db = db; self.dialect = getattr(db, "dialect", "sqlite")
            def execute(self, sql, args=()):
                cursor = self.db.execute(sql, args)
                return Cursor(cursor) if sql.startswith(("SELECT length(", "SELECT octet_length(")) else cursor
        @contextmanager
        def interleaved():
            with original() as db: yield Connection(db)
        loads = Mock(wraps=json.loads)
        with patch.object(Store, "_all", side_effect=AssertionError("No global sessions")), patch.object(Store, "assignment", side_effect=AssertionError("Public policy cannot construct authority assignments")), patch.object(views, "json", SimpleNamespace(loads=loads)), patch.object(self.store, "read_meta", interleaved):
            self.assertEqual(views.compiled_policy(self.store, "server-a"), self.compiled)
        loads.assert_called_once()
        fail = Mock(side_effect=AssertionError("Oversized compiled policy cannot decode"))
        with patch.object(views, "MAX_DETAIL_BYTES", 16), patch.object(views, "json", SimpleNamespace(loads=fail)):
            with self.assertRaisesRegex(ValueError, "bound"): views.compiled_policy(self.store, "server-a")
        fail.assert_not_called()
        self.assertIsNone(views.compiled_policy(self.store, "server-empty"))
        with self.assertRaises(KeyError): views.compiled_policy(self.store, "missing-server")

    def test_navigation_keeps_canonical_session_unchanged_and_indexes_are_idempotent(self):
        before = copy.deepcopy(self.live)
        views.listing(self.store, limit=1); views.hosts(self.store, self.live["id"], limit=1)
        with self.store.meta() as db:
            views.header(db, self.live["id"])
            views.initialize(db); views.initialize(db)
            self.assertEqual(self.store._get(db, "sessions", self.live["id"]), before)
            if getattr(db, "dialect", "sqlite") == "postgresql":
                names = {row[0] for row in db.execute("SELECT indexname FROM pg_indexes WHERE schemaname='public'")}
            else:
                names = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='index'")}
        self.assertTrue({"public_learning_session_start", "public_learning_session_active"} <= names)

    def test_invalid_paging_membership_and_unknown_host_scope_fail_closed(self):
        for limit, offset in ((True, 0), (0, 0), (21, 0), ("1", 0), (1, True), (1, -1)):
            with self.subTest(limit=limit, offset=offset), self.assertRaises(ValueError): views.listing(self.store, limit=limit, offset=offset)
        for limit, offset in ((True, 0), (0, 0), (101, 0), (1, True), (1, -1)):
            with self.subTest(host_limit=limit, offset=offset), self.assertRaises(ValueError): views.hosts(self.store, self.live["id"], limit=limit, offset=offset)
        for identifier in ("", "host' OR 1=1--", "x" * 101, 1):
            with self.subTest(identifier=identifier), self.assertRaises(ValueError): views.listing(self.store, server_id=identifier)
        with self.assertRaises(KeyError): views.hosts(self.store, "missing-session")


class SessionViewSQLiteTests(SessionViewChecks, unittest.TestCase):
    pass


ROOT = Path(__file__).resolve().parents[2]
PG_NAMES = pg_fixture.names("session")


@unittest.skipUnless(os.environ.get("PRTHAK_PLATFORM_PG_ACCEPTANCE") == "1", "Owner opt-in for the private PostgreSQL session fixture")
class SessionViewPostgresTests(SessionViewChecks, unittest.TestCase):
    @classmethod
    def verify(cls, db, expected):
        user, directory, database = db.execute("SELECT current_user,current_setting('data_directory'),current_database()").fetchone()
        if user != "prthak_test" or Path(directory).resolve() != pg_fixture.data_directory() or database != expected:
            raise RuntimeError("Only the prepared private cluster and literal approval queue databases are allowed")

    @classmethod
    def setUpClass(cls):
        import psycopg
        from psycopg import sql
        from psycopg.conninfo import make_conninfo
        cls.driver, cls.sql = psycopg, sql
        cls.parameters = pg_fixture.parameters()
        with psycopg.connect(**cls.parameters, dbname="postgres", autocommit=True) as db:
            cls.verify(db, "postgres")
            for name in PG_NAMES.values():
                if db.execute("SELECT 1 FROM pg_database WHERE datname=%s", (name,)).fetchone(): raise RuntimeError("Refusing to reuse a pre-existing private fixture database")
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
