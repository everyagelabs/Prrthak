"""Public navigation never materializes the fleet's frozen grant matrices."""
from datetime import timedelta
from controller.tests import private_pg as pg_fixture

import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import tracemalloc
import unittest
import uuid
from unittest.mock import patch

from controller import managed, managed_views as views
from controller.app import App, handler_for
from controller.store import Store, now, stamp


class ManagedPublicViewsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="prthak-managed-views-")
        self.addCleanup(self.temp.cleanup)
        self.store = self.make_store()
        self.seed()

    def make_store(self):
        return Store(self.temp.name)

    def seed(self, count=7, sources=3):
        with self.store.meta() as db:
            for index in range(count):
                number = index + 1
                service = {"port": 8443, "protocol": "tcp", "sources": [f"10.{source // 65536}.{source // 256 % 256}.{source % 256}/32" for source in range(sources)]}
                revision = {"id": "billing-policy", "revision": number, "name": "Billing", "mode": "enforce", "services": [service], "selector": {"application": "billing"}, "created_at": stamp(), "actor": "tester"}
                bundle = {"server_id": "host-1", "version": number, "digest": "f" * 64, "services": [service], "created_at": stamp()}
                db.execute("INSERT INTO policy_revisions(id,policy_id,revision,created_at,data) VALUES(?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET data=excluded.data", ("billing-policy:" + str(number), "billing-policy", number, stamp(), json.dumps(revision)))
                db.execute("INSERT INTO bundle_history(id,server_id,version,digest,created_at,data) VALUES(?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET data=excluded.data", ("host-1:" + str(number), "host-1", number, bundle["digest"], stamp(), json.dumps(bundle)))
                plan = {"id": "rollout-" + str(number), "name": "Billing_%" if index % 2 else "Payments", "status": "completed", "server_ids": ["host-1" if index % 2 else "host-2"], "bindings": {}, "preview": {"targets": [{"server_id": "host-1", "bundle": bundle}]}, "created_at": stamp(now() + timedelta(seconds=index)), "expires_at": stamp(now() + timedelta(hours=1)), "confirmation_count": 2, "requires_double_confirmation": True}
                self.store._put(db, "managed_rollouts", plan)

    def test_lists_project_no_canonical_json_and_count_before_page(self):
        with patch.object(views, "json", SimpleNamespace(loads=lambda *args: self.fail("Navigation decoded canonical grant JSON"))), patch.object(self.store, "_all", side_effect=AssertionError("Navigation loaded a fleet table")):
            selected = views.rollouts(self.store, limit=1, offset=1, server_ids=["host-1"], search="Billing_%")
            self.assertEqual(selected["total"], 3)
            self.assertEqual(selected["items"][0]["id"], "rollout-4")
            self.assertTrue(selected["has_more"])
            self.assertEqual(selected["items"][0]["target_count"], 1)
            self.assertEqual(selected["items"][0]["matching_target_count"], 1)
            self.assertEqual(views.rollouts(self.store, server_ids=[])["total"], 0)
            for page in (views.revisions(self.store, "billing-policy", 2, 2), views.history(self.store, "host-1", 2, 2)):
                self.assertEqual(page["total"], 7)
                self.assertEqual(len(page["items"]), 2)
                self.assertTrue(page["has_more"])
                self.assertNotIn("services", page["items"][0])
                self.assertTrue(page["items"][0]["summary_only"])

    def test_full_exact_details_and_differences_retain_all_sources(self):
        selected = views.revision(self.store, "billing-policy", 3)
        self.assertEqual(len(selected["services"][0]["sources"]), 3)
        self.assertNotIn("summary_only", selected)
        self.assertEqual(views.bundle(self.store, "host-1", 4)["version"], 4)
        self.assertEqual(views.revision_diff(self.store, "billing-policy", 2, 6)["to_revision"], 6)
        self.assertEqual(views.bundle_diff(self.store, "host-1", 1, 5)["from_revision"], 1)
        self.assertEqual(len(views.rollout(self.store, "rollout-2")["preview"]["targets"][0]["bundle"]["services"][0]["sources"]), 3)

    def test_exact_size_rejected_before_decode_and_summary_still_accessible(self):
        with self.store.meta() as db:
            for table, owner, where in (("policy_revisions", "billing-policy", "policy_id=? AND revision=1"), ("bundle_history", "host-1", "server_id=? AND version=1"), ("managed_rollouts", "rollout-1", "id=?")):
                row = db.execute("SELECT data FROM " + table + " WHERE " + where, (owner,)).fetchone()
                value = json.loads(row[0]); value["padding"] = "x" * 8192
                db.execute("UPDATE " + table + " SET data=? WHERE " + where, (json.dumps(value), owner))
        with patch.object(views, "MAX_DETAIL_BYTES", 4096), patch.object(views, "json", SimpleNamespace(loads=lambda *args: self.fail("Oversized authority decoded"))):
            for callback in (lambda: views.revision(self.store, "billing-policy", 1), lambda: views.bundle(self.store, "host-1", 1), lambda: views.rollout(self.store, "rollout-1")):
                with self.assertRaisesRegex(ValueError, "byte bound"):
                    callback()
            self.assertEqual(views.revisions(self.store, "billing-policy")["total"], 7)
            self.assertEqual(views.history(self.store, "host-1")["total"], 7)
            self.assertEqual(views.rollouts(self.store)["total"], 7)

    def test_exact_identity_and_summary_substitution_fail_closed(self):
        with self.store.meta() as db:
            row = db.execute("SELECT data FROM policy_revisions WHERE policy_id=? AND revision=1", ("billing-policy",)).fetchone()
            value = json.loads(row[0]); value["id"] = "other-policy"
            db.execute("UPDATE policy_revisions SET data=? WHERE policy_id=? AND revision=1", (json.dumps(value), "billing-policy"))
            self.store._put(db, "managed_rollouts", {"id": "summary-review", "summary_only": True})
        with self.assertRaisesRegex(ValueError, "identity mismatch"):
            views.revision(self.store, "billing-policy", 1)
        with self.assertRaisesRegex(ValueError, "authority is unavailable"):
            views.rollout(self.store, "summary-review")

    def test_exact_review_checks_live_binding_without_loading_full_server(self):
        server = {"id": "host-1", "ips": ["10.20.0.1"], "_compiled": {"version": 3, "digest": "f" * 64, "mode": "enforce"}, "protection": {"digest": "a" * 64}, "firewall_snapshot": {"padding": "x" * 50000}}
        binding = {**managed.baseline(server), "intent": "enforce"}
        plan = {"id": "exact-review", "status": "draft", "server_ids": ["host-1"], "bindings": {"host-1": binding}, "preview": {"targets": []}, "expires_at": stamp(now() + timedelta(minutes=5))}
        with self.store.meta() as db:
            self.store._put(db, "servers", server); self.store._put(db, "managed_rollouts", plan)
        with patch.object(self.store, "_get", side_effect=AssertionError("Exact review loaded the full server snapshot")):
            self.assertEqual(views.rollout(self.store, plan["id"])["status"], "draft")
            with self.store.meta() as db:
                self.store._put(db, "servers", {**server, "ips": ["10.20.0.2"]})
            self.assertEqual(views.rollout(self.store, plan["id"])["status"], "invalidated")

    def test_outcome_pages_are_explicit_complete_and_latest_counts_are_not_duplicates(self):
        with self.store.meta() as db:
            for index in range(5):
                value = {"id": "outcome-" + str(index), "server_id": "host-1", "version": 1, "status": "enforced" if index == 4 else "staging", "intent": "remove_managed_rules", "approval_id": "rollout-2", "updated_at": stamp(now() + timedelta(seconds=index)), "message": "readback"}
                db.execute("INSERT INTO managed_outcomes(id,server_id,version,approval_id,created_at,data) VALUES(?,?,?,?,?,?)", (value["id"], "host-1", 1, "rollout-2", value["updated_at"], json.dumps(value)))
        summary = views.history(self.store, "host-1", 1, 6)["items"][0]
        self.assertEqual(summary["outcome_total"], 5)
        self.assertEqual(summary["outcomes"][0]["status"], "enforced")
        outcome_page = views.outcomes(self.store, "host-1", 1, 2, 2)
        self.assertEqual(outcome_page["total"], 5)
        self.assertEqual([value["id"] for value in outcome_page["items"]], ["outcome-2", "outcome-1"])
        self.assertTrue(outcome_page["has_more"])
        summary = views.rollouts(self.store, server_ids=["host-1"], search="Billing_%")["items"][-1]
        self.assertEqual(summary["result_counts"], {"removed": 1})
        self.assertEqual(views.rollout(self.store, "rollout-2")["results"]["host-1"]["id"], "outcome-4")

    def test_large_canonical_histories_keep_public_python_memory_and_payload_bounded(self):
        self.seed(80, 1500)
        tracemalloc.start()
        try:
            with patch.object(views, "json", SimpleNamespace(loads=lambda *args: self.fail("Navigation decoded a large matrix"))):
                values = [views.revisions(self.store, "billing-policy", 10), views.history(self.store, "host-1", 10), views.rollouts(self.store, limit=10)]
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        self.assertLess(peak, 2 * 1024 * 1024)
        self.assertLess(len(json.dumps(values).encode()), 65536)
        self.assertTrue(all(value["total"] == 80 for value in values))

    def test_invalid_queries_are_bounded_and_empty_scope_never_broadens(self):
        for value in ({"limit": True}, {"offset": -1}, {"limit": 101}, {"server_ids": ["bad/id"]}, {"server_ids": ["host"] * 20001}, {"search": "x" * 257}, {"services": []}):
            with self.assertRaises(ValueError):
                views.rollout_options(value)
        self.assertEqual(views.rollouts(self.store, server_ids=[])["items"], [])
        self.assertEqual(views.rollouts(self.store, search="' OR 1=1 --")["total"], 0)

    def targets(self, count=3, source_count=3, snapshot=False):
        self.store.lab_approvals = True
        ids = ["target-" + str(index) for index in range(count)]
        with self.store.meta() as db:
            for server_id in ids:
                bundle = {"server_id": server_id, "mode": "enforce", "version": 1, "digest": "a" * 64, "services": [{"port": 8443, "protocol": "tcp", "sources": ["10.20." + str(index // 256) + "." + str(index % 256) + "/32" for index in range(source_count)]}]}
                server = {"id": server_id, "hostname": server_id, "ips": ["10.1.0.1"], "_compiled": bundle, "protection": {"ready": True, "digest": "b" * 64, "blockers": [], "management_sources": ["10.99.0.0/24"], "ssh_ports": [2022]}, "capabilities": ["signed_assignments_v1"], "_managed_rules_active": True}
                if snapshot:
                    server["firewall_snapshot"] = {"rules": [{"raw": "PRIVATE_UNRELATED_SNAPSHOT" * 10000}]}
                self.store._put(db, "servers", server)
        return ids

    def counts(self):
        with self.store.read_meta() as db:
            return {table: int(db.execute("SELECT COUNT(*) FROM " + table).fetchone()[0]) for table in ("managed_rollouts", "managed_approvals", "policy_revisions", "bundle_history", "audit")}

    def test_create_uses_selected_compact_endpoint_projection_without_unrelated_snapshots(self):
        ids = self.targets(snapshot=True)
        real_loads, real_get = json.loads, self.store._get
        def projection_only(raw):
            self.assertNotIn("PRIVATE_UNRELATED_SNAPSHOT", raw)
            return real_loads(raw)
        def no_snapshot_get(db, table, owner):
            if table == "servers":
                raise AssertionError("Review construction loaded a canonical server snapshot")
            return real_get(db, table, owner)
        with patch.object(managed, "json", SimpleNamespace(loads=projection_only)), patch.object(self.store, "_get", side_effect=no_snapshot_get):
            plan = self.store.create_managed_rollout({"name": "Exact small scope", "server_ids": ids}, "fixture")
        self.assertEqual(plan["server_ids"], ids)
        self.assertEqual(len(plan["preview"]["targets"][0]["bundle"]["services"][0]["sources"]), 3)
        self.assertEqual(plan["bindings"][ids[0]]["intent"], "enforce")
        self.assertLessEqual(managed._review_size(plan), managed.MAX_ROLLOUT_BYTES)

    def test_create_exact_byte_boundary_accepts_and_one_byte_less_leaves_no_side_effect(self):
        ids = self.targets(count=1)
        value = {"name": "Exact byte boundary", "server_ids": ids}
        first = self.store.create_managed_rollout(value, "fixture")
        size = managed._review_size(first)
        with patch.object(managed, "MAX_ROLLOUT_BYTES", size):
            exact = self.store.create_managed_rollout(value, "fixture")
        self.assertEqual(managed._review_size(exact), size)
        before = self.counts()
        with patch.object(managed, "MAX_ROLLOUT_BYTES", size - 1):
            with self.assertRaisesRegex(ValueError, "8 MiB bound"):
                self.store.create_managed_rollout(value, "fixture")
        self.assertEqual(self.counts(), before)

    def test_cumulative_preview_rejects_before_reading_remaining_targets_or_saving_anything(self):
        ids = self.targets()
        with self.store.read_meta() as db:
            bindings, targets = managed.rollout_preview(self.store, ids[:1], db)
        limit = managed._review_size({"bindings": bindings, "targets": targets}) + 100
        before = self.counts()
        with patch.object(managed, "MAX_ROLLOUT_BYTES", limit), patch.object(managed, "_rollout_server", wraps=managed._rollout_server) as selected:
            with self.assertRaisesRegex(ValueError, "8 MiB bound"):
                self.store.create_managed_rollout({"name": "Too dense", "server_ids": ids}, "fixture")
            self.assertEqual(selected.call_count, 2)
        self.assertEqual(self.counts(), before)

    def test_single_oversized_projection_is_rejected_before_canonical_decode_or_persist(self):
        ids = self.targets(count=1, source_count=400)
        before = self.counts()
        with patch.object(managed, "MAX_ROLLOUT_BYTES", 2048), patch.object(managed, "json", SimpleNamespace(loads=lambda raw: self.fail("Oversized endpoint projection decoded"))):
            with self.assertRaisesRegex(ValueError, "endpoint evidence exceeds"):
                self.store.create_managed_rollout({"name": "Oversized single target", "server_ids": ids}, "fixture")
        self.assertEqual(self.counts(), before)

    def test_confirmation_growth_cannot_save_unreviewable_authority_or_insert_approvals(self):
        ids = self.targets(count=1)
        first = self.store.create_managed_rollout({"name": "Bounded confirmation evidence", "server_ids": ids}, "fixture")
        before = self.counts()
        with patch.object(managed, "MAX_ROLLOUT_BYTES", managed._review_size(first)):
            with self.assertRaisesRegex(ValueError, "8 MiB bound"):
                self.store.confirm_managed_rollout(first["id"], {"confirmation_nonce": first["confirmation_nonce"]}, "fixture")
        self.assertEqual(self.counts(), before)
        self.assertEqual(self.store.get("managed_rollouts", first["id"]), first)

    def route(self, method, path, value=None, role="read_only"):
        app = App(self.store, tokens={role: "private-managed-reader"}, auth=SimpleNamespace(enabled=False), platform_manager=False, controller_id="managed-private", site="fixture")
        cls = handler_for(app); handler = cls.__new__(cls)
        handler.command = method; handler.path = "/api/v1" + path; handler.headers = {"Authorization": "Bearer private-managed-reader"}; handler.connection = object(); handler.client_address = ("127.0.0.1", 0); handler.close_connection = False
        handler.body = lambda: value
        result = {}; handler.response = lambda status, data=None, headers=None: result.update(status=status, data=data)
        handler.dispatch()
        return result

    def test_read_only_query_and_history_api_access_with_summary_mutation_rejection(self):
        result = self.route("POST", "/policy-rollouts/query", {"server_ids": ["host-1"], "limit": 1, "offset": 1})
        self.assertEqual(result["status"], 200, result)
        self.assertEqual(result["data"]["total"], 3)
        self.assertEqual(result["data"]["items"][0]["id"], "rollout-4")
        self.assertEqual(self.route("GET", "/policies/billing-policy/revisions?limit=1&offset=1")["data"]["items"][0]["revision"], 6)
        self.assertEqual(self.route("GET", "/servers/host-1/policy-history?limit=1&offset=1")["data"]["items"][0]["version"], 6)
        self.assertEqual(self.route("GET", "/policies/billing-policy/revisions/3")["data"]["services"][0]["sources"], views.revision(self.store, "billing-policy", 3)["services"][0]["sources"])
        for path in ("/policies/billing-policy/rollback", "/policy-rollouts/rollout-2/confirm"):
            self.assertEqual(self.route("POST", path, {"summary_only": True, "revision": 1}, "admin")["status"], 400)
            self.assertEqual(self.route("POST", path, {}, "read_only")["status"], 403)


@unittest.skipUnless(os.environ.get("PRTHAK_PLATFORM_PG_ACCEPTANCE") == "1", "Owner opt-in for disposable private PostgreSQL navigation cases")
class ManagedPublicViewsPostgresTests(ManagedPublicViewsTests):
    @classmethod
    def setUpClass(cls):
        import psycopg
        from psycopg import sql
        from psycopg.conninfo import make_conninfo
        root = Path(__file__).resolve().parents[2]
        cls.root, cls.driver, cls.sql = root, psycopg, sql
        cls.parameters = pg_fixture.parameters()
        suffix = uuid.uuid4().hex[:12]
        cls.names = {namespace: "prthak_test_managed_" + suffix + "_" + namespace for namespace in ("meta", "traffic")}
        with psycopg.connect(**cls.parameters, dbname="postgres", autocommit=True) as db:
            cls.verify(db, "postgres")
            for name in cls.names.values():
                db.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(name)))
        cls.dsns = {namespace: make_conninfo(**cls.parameters, dbname=name) for namespace, name in cls.names.items()}
        cls.addClassCleanup(cls.drop)

    @classmethod
    def verify(cls, db, expected):
        row = db.execute("SELECT current_user,current_setting('data_directory'),current_database()").fetchone()
        if row[0] != "prthak_test" or Path(row[1]).resolve() != pg_fixture.data_directory() or row[2] != expected:
            raise RuntimeError("Only this task's unique databases on the prepared private cluster may be used")

    @classmethod
    def drop(cls):
        with cls.driver.connect(**cls.parameters, dbname="postgres", autocommit=True) as db:
            cls.verify(db, "postgres")
            for name in cls.names.values():
                db.execute(cls.sql.SQL("DROP DATABASE {}").format(cls.sql.Identifier(name)))

    def make_store(self):
        from controller.postgres import PostgresStore
        for namespace, dsn in self.dsns.items():
            with self.driver.connect(dsn, autocommit=True) as db:
                self.verify(db, self.names[namespace]); db.execute("DROP SCHEMA public CASCADE"); db.execute("CREATE SCHEMA public")
        return PostgresStore(self.dsns["meta"], self.dsns["traffic"])


if __name__ == "__main__":
    unittest.main()
