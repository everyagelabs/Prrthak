"""Bounded approval navigation and whole selected authority, using small fixtures."""
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

from controller import approval_views as views
from controller import learning_policies as lp
from controller.store import Store, now, stamp


class ApprovalViewChecks:
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="prthak-approval-view-")
        self.addCleanup(self.temporary.cleanup)
        self.store = self.make_store()
        self.future = stamp(now() + timedelta(hours=1))
        self.expired = stamp(now() - timedelta(hours=1))
        self.plan = {
            "id": "live-preview", "session_id": "session-a", "kind": "recommendation",
            "name": "Frozen reviewed access", "status": "reviewed", "created_at": "2026-01-05T00:00:00Z",
            "expires_at": self.future, "digest": "a" * 64, "plan_digest": "b" * 64,
            "created_by": "requester", "confirmation_count": 1, "confirmation_nonce": "private-exact-nonce",
            "approval": {"mode": "independent", "stage": "submitted", "requester": {"user_id": "maker", "tenant_id": "tenant", "actor": "maker@fixture", "display_name": "Requester", "role": "admin"}},
            "targets": [{"server_id": "fixture-a", "services": [{"port": 443, "protocol": "tcp", "sources": ["10.20.0.1/32", "10.20.0.2/32"]}], "binding_digest": "c" * 64}],
            "selected_row_ids": ["evidence-one", "evidence-two"],
            "authority_matrix": {"fixture-a": {"source_digest": "d" * 64, "rows": [["10.20.0.1/32", 443], ["10.20.0.2/32", 443]]}},
        }
        self.initial = {**copy.deepcopy(self.plan), "id": "live-initial", "status": "draft", "created_at": "2026-01-06T00:00:00Z"}
        self.session = {"id": "session-a", "status": "active", "initial_approval_plan": self.initial}
        with self.store.meta() as db:
            for plan in (
                self.plan,
                {**self.plan, "id": "expired-preview", "expires_at": self.expired},
                {**self.plan, "id": "applied-preview", "status": "applied"},
                {**self.plan, "id": "unrelated-preview", "session_id": "session-b", "created_at": "2026-01-04T00:00:00Z"},
            ):
                self.store._put(db, "learning_policy_previews", plan)
            self.store._put(db, "sessions", self.session)
            other = {**self.initial, "id": "unrelated-initial", "session_id": "session-b", "created_at": "2026-01-03T00:00:00Z"}
            self.store._put(db, "sessions", {"id": "session-b", "status": "active", "initial_approval_plan": other})

    def make_store(self):
        return Store(self.temporary.name)

    def assert_summary(self, item):
        self.assertTrue(item["summary_only"])
        for key in ("targets", "authority_matrix", "selected_row_ids", "confirmation_nonce", "confirmation_phrase"):
            self.assertNotIn(key, item)

    def test_one_item_page_filters_before_canonical_parse(self):
        fail = Mock(side_effect=AssertionError("Queue cannot parse canonical JSON"))
        with patch.object(Store, "_all", side_effect=AssertionError("Queue cannot load all canonical rows")), patch.object(views, "json", SimpleNamespace(loads=fail)):
            first = lp.approval_reviews(self.store, "session-a", limit=1)
            second = lp.approval_reviews(self.store, "session-a", limit=1, offset=1)
        self.assertEqual((first["total"], len(first["items"]), first["has_more"]), (2, 1, True))
        self.assertEqual(first["items"][0]["id"], "live-initial")
        self.assertEqual((second["total"], len(second["items"]), second["has_more"]), (2, 1, False))
        self.assertEqual(second["items"][0]["id"], "live-preview")
        self.assert_summary(first["items"][0]); self.assert_summary(second["items"][0])
        fail.assert_not_called()

    def test_global_counts_order_and_offset_are_bounded(self):
        result = views.listing(self.store, limit=2, offset=1)
        self.assertEqual((result["total"], len(result["items"]), result["has_more"]), (4, 2, True))
        self.assertEqual([row["id"] for row in result["items"]], ["live-preview", "unrelated-preview"])
        self.assertTrue(all(row["summary_only"] for row in result["items"]))
        empty = views.listing(self.store, "session-missing", limit=1)
        self.assertEqual((empty["total"], empty["items"], empty["has_more"]), (0, [], False))

    def test_summary_text_is_bounded_without_changing_canonical_authority(self):
        plan = {**self.plan, "name": "漢" * 700}
        with self.store.meta() as db:
            self.store._put(db, "learning_policy_previews", plan)
        item = next(row for row in views.listing(self.store)["items"] if row["id"] == plan["id"])
        self.assertEqual(item["name"], "漢" * views.SUMMARY_TEXT)
        self.assert_summary(item)
        self.assertEqual(views.detail(self.store, plan["id"]), plan)

    def test_selected_details_load_once_and_preserve_whole_authority(self):
        for identifier, expected in ((self.plan["id"], self.plan), (self.initial["id"], {**self.initial, "kind": "initial_learning"})):
            with self.subTest(identifier=identifier):
                loads = Mock(wraps=json.loads)
                with patch.object(Store, "_all", side_effect=AssertionError("Detail cannot load all rows")), patch.object(views, "json", SimpleNamespace(loads=loads)):
                    detail = lp.approval_review(self.store, identifier)
                self.assertEqual(detail, expected)
                self.assertEqual(detail["confirmation_nonce"], "private-exact-nonce")
                self.assertEqual(detail["digest"], "a" * 64)
                self.assertEqual(detail["targets"], expected["targets"])
                self.assertEqual(detail["authority_matrix"], expected["authority_matrix"])
                loads.assert_called_once()

    def test_detail_byte_bound_rejects_before_parsing_preview_or_parent_session(self):
        tiny = {"id": "small-initial", "status": "draft"}
        self.assertLess(len(json.dumps(tiny).encode()), 128)
        with self.store.meta() as db:
            self.store._put(db, "sessions", {"id": "session-large-parent", "status": "active", "padding": "x" * 256, "initial_approval_plan": tiny})
        fail = Mock(side_effect=AssertionError("Oversized authority must be rejected before JSON parsing"))
        with patch.object(views, "MAX_REVIEW_BYTES", 128), patch.object(views, "json", SimpleNamespace(loads=fail)):
            for identifier in (self.plan["id"], tiny["id"]):
                with self.subTest(identifier=identifier), self.assertRaisesRegex(ValueError, "detail limit"):
                    views.detail(self.store, identifier)
        fail.assert_not_called()

    def test_duplicate_preview_and_initial_or_two_initial_ids_fail_closed(self):
        with self.store.meta() as db:
            self.store._put(db, "sessions", {"id": "duplicate-preview-owner", "status": "active", "initial_approval_plan": {**self.initial, "id": self.plan["id"]}})
            self.store._put(db, "sessions", {"id": "duplicate-initial-owner", "status": "active", "initial_approval_plan": self.initial})
        fail = Mock(side_effect=AssertionError("Ambiguous detail cannot parse authority"))
        with patch.object(views, "json", SimpleNamespace(loads=fail)):
            for identifier in (self.plan["id"], self.initial["id"]):
                with self.subTest(identifier=identifier), self.assertRaisesRegex(ValueError, "ambiguous"):
                    views.detail(self.store, identifier)
        fail.assert_not_called()

    def test_completed_reviews_leave_queue_and_detail_retains_exact_current_state(self):
        applied = {**self.plan, "status": "applied"}
        authorized = {**self.initial, "status": "authorized"}
        with self.store.meta() as db:
            self.store._put(db, "learning_policy_previews", applied)
            self.store._put(db, "sessions", {**self.session, "initial_approval_plan": authorized})
        result = views.listing(self.store, "session-a", limit=1)
        self.assertEqual((result["total"], result["items"]), (0, []))
        self.assertEqual(views.detail(self.store, applied["id"]), applied)
        self.assertEqual(views.detail(self.store, authorized["id"]), {**authorized, "kind": "initial_learning"})

    def test_invalid_paging_identifiers_and_missing_detail_are_rejected(self):
        for limit, offset in ((True, 0), (0, 0), (501, 0), ("1", 0), (1, True), (1, -1), (1, "0")):
            with self.subTest(limit=limit, offset=offset), self.assertRaises(ValueError):
                views.listing(self.store, limit=limit, offset=offset)
        for identifier in ("", "x' OR 1=1--", "x" * 129, 1):
            with self.subTest(identifier=identifier):
                with self.assertRaises(ValueError): views.listing(self.store, session_id=identifier)
                with self.assertRaises(ValueError): views.detail(self.store, identifier)
        with self.assertRaises(KeyError): views.detail(self.store, "missing-review")

    def test_fixed_scalar_index_ddl_is_valid_and_idempotent(self):
        with self.store.meta() as db:
            views.initialize(db)
            views.initialize(db)
            if getattr(db, "dialect", "sqlite") == "postgresql":
                names = {row[0] for row in db.execute("SELECT indexname FROM pg_indexes WHERE schemaname='public'")}
            else:
                names = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='index'")}
        self.assertTrue({"learning_review_queue", "learning_review_session", "initial_learning_review_id", "initial_learning_review_queue"} <= names)


class ApprovalViewSQLiteTests(ApprovalViewChecks, unittest.TestCase):
    pass


ROOT = Path(__file__).resolve().parents[2]
PG_NAMES = pg_fixture.names("approval")


@unittest.skipUnless(os.environ.get("PRTHAK_PLATFORM_PG_ACCEPTANCE") == "1", "Opt in to the private PostgreSQL approval queue fixture")
class ApprovalViewPostgresTests(ApprovalViewChecks, unittest.TestCase):
    @classmethod
    def _verify(cls, connection, expected_database):
        user, directory, database = connection.execute("SELECT current_user,current_setting('data_directory'),current_database()").fetchone()
        if user != "prthak_test" or Path(directory).resolve() != pg_fixture.data_directory() or database != expected_database:
            raise RuntimeError("Only the prepared private cluster and literal approval queue fixture databases are allowed")

    @classmethod
    def setUpClass(cls):
        import psycopg
        from psycopg import sql
        from psycopg.conninfo import make_conninfo
        cls.driver, cls.sql = psycopg, sql
        cls.parameters = pg_fixture.parameters()
        with psycopg.connect(**cls.parameters, dbname="postgres", autocommit=True) as db:
            cls._verify(db, "postgres")
            for name in PG_NAMES.values():
                if db.execute("SELECT 1 FROM pg_database WHERE datname=%s", (name,)).fetchone():
                    raise RuntimeError("Refusing to reuse a pre-existing private fixture database")
                db.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(name)))
        cls.dsns = {namespace: make_conninfo(**cls.parameters, dbname=name) for namespace, name in PG_NAMES.items()}

    def reset(self):
        for namespace, dsn in self.dsns.items():
            with self.driver.connect(dsn, autocommit=True) as db:
                self._verify(db, PG_NAMES[namespace])
                db.execute("DROP SCHEMA public CASCADE")
                db.execute("CREATE SCHEMA public")

    def make_store(self):
        from controller.postgres import PostgresStore
        self.reset()
        self.addCleanup(self.reset)
        return PostgresStore(self.dsns["metadata"], self.dsns["traffic"])
