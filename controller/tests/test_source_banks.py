"""GUI-only maintenance keeps exact authority, target scope and safe outcomes."""
import copy
from datetime import timedelta
from email.message import Message
import os
from pathlib import Path
import unittest
from unittest.mock import patch

from controller import source_banks as banks
from controller.app import App, handler_for
from controller.firewall import WorkflowConflict
from controller.store import now, stamp
from controller.tests import test_approvals as fixture
from controller.tests import private_pg


class SourceBankMaintenanceTests(unittest.TestCase):
    person = fixture.IndependentApprovalTests.person

    def setUp(self):
        fixture.IndependentApprovalTests.setUp(self)
        with self.store.meta() as db:
            host = self.store._get(db, "servers", "target")
            host["capabilities"].append(banks.CAPABILITY)
            host["configuration_state"] = {"digest": "d" * 64}
            self.store._put(db, "servers", host)

    def assess(self):
        return banks.assess(self.store, {"server_ids": ["target"]}, self.maker["actor"], self.maker)["items"][0]

    def receipt(self, status="assessed", **changes):
        host = self.store.get("servers", "target")
        job = host[banks.JOB]
        value = {"schema_version": 1, "id": job["id"], "operation": job["operation"], "plan_digest": job["plan_digest"],
                 "status": status, "checked_at": stamp(), "baseline_digest": "a" * 64, "protection_digest": host["protection_digest"],
                 "missing_banks": 256, "active_banks": 0, "permanent_banks": 0, "created_banks": 0,
                 "activation_required": True, "blockers": [], **changes}
        self.store.report("target", {"hostname": host["hostname"], "ips": host["ips"], "capabilities": host["capabilities"],
            "discovery_performed": False, "listeners": [], "firewalld_state": "running", "source_bank_preparation": value})
        return value

    def preview(self):
        self.assess(); self.receipt()
        return banks.preview(self.store, {"server_ids": ["target"]}, self.maker["actor"], self.maker)

    @staticmethod
    def payload(plan, **changes):
        return {"digest": plan["digest"], "confirmation_nonce": plan["confirmation_nonce"],
                "confirmation_phrase": banks.CHALLENGE, "acknowledge_downtime": True, **changes}

    def confirm(self, plan):
        return banks.confirm(self.store, plan["id"], self.payload(plan), self.maker["actor"], self.maker)

    def test_assessment_is_separate_auxiliary_intent_without_policy_or_opt_in_changes(self):
        before = self.store.assignment("target")[0]
        config = self.store.get("servers", "target")["configuration_state"]
        job = self.assess()
        after = self.store.assignment("target")[0]
        self.assertEqual((after["version"], after["digest"], after["services"]), (before["version"], before["digest"], before["services"]))
        self.assertEqual(after["source_bank_preparation"]["id"], job["id"])
        self.assertNotIn("approval_proof", after["source_bank_preparation"])
        self.assertEqual(self.store.get("servers", "target")["configuration_state"], config)
        self.receipt()
        self.assertNotIn("source_bank_preparation", self.store.assignment("target")[0])

    def test_prepare_requires_fresh_assessment_and_two_explicit_controls_by_same_admin(self):
        blocked = banks.preview(self.store, {"server_ids": ["target"]}, self.maker["actor"], self.maker)
        self.assertFalse(blocked["can_apply"])
        plan = self.preview()
        self.assertTrue(plan["can_apply"], plan["blockers"])
        self.assertEqual(plan["targets"][0]["baseline_digest"], "a" * 64)
        for change in ({"acknowledge_downtime": False}, {"acknowledge_downtime": "true"}, {"acknowledge_downtime": 1}, {"confirmation_phrase": ""}, {"digest": "f" * 64}, {"confirmation_nonce": "wrong"}):
            with self.subTest(change=change), self.assertRaises((ValueError, WorkflowConflict)):
                banks.confirm(self.store, plan["id"], self.payload(plan, **change), self.maker["actor"], self.maker)
        with self.assertRaises((PermissionError, WorkflowConflict)):
            banks.confirm(self.store, plan["id"], self.payload(plan), self.checker["actor"], self.checker)
        result = self.confirm(plan)
        self.assertEqual(result["count"], 1)
        assigned = self.store.assignment("target")[0]["source_bank_preparation"]
        self.assertEqual(assigned["operation"], "prepare_activate")
        proof = assigned["approval_proof"]
        self.assertEqual(proof["mode"], "single_admin")
        self.assertEqual(proof["requester"], proof["approved_by"])
        self.assertEqual(proof["scope"], {"kind": banks.KIND, "server_ids": ["target"]})
        with self.assertRaises(WorkflowConflict):
            self.confirm(plan)

    def test_changed_addresses_policy_or_configuration_invalidates_preview(self):
        for field, replacement in (("ips", ["10.70.0.2"]), ("configuration_state", {"digest": "e" * 64}), ("desired_version", 999)):
            plan = self.preview()
            with self.store.meta() as db:
                host = self.store._get(db, "servers", "target"); before = copy.deepcopy(host[field]); host[field] = replacement
                self.store._put(db, "servers", host)
            with self.subTest(field=field), self.assertRaises(WorkflowConflict):
                self.confirm(plan)
            with self.store.meta() as db:
                host = self.store._get(db, "servers", "target"); host[field] = before; self.store._put(db, "servers", host)

    def test_disabled_admin_and_expired_authority_stop_delivery_and_health(self):
        plan = self.preview(); self.confirm(plan)
        policy = self.store.assignment("target")[0]["source_bank_preparation"]
        request = {key: policy[key] for key in ("id", "plan_digest", "baseline_digest", "protection_digest")}
        request.update(nonce="b" * 32, ssh_ports=[2022])
        self.assertEqual(banks.verify(self.store, "target", request)["ips"], ["10.70.0.1"])
        with self.store.meta() as db:
            user = self.store._get(db, "auth_users", self.maker["user"]["id"]); user["enabled"] = False; self.store._put(db, "auth_users", user)
        self.assertNotIn("source_bank_preparation", self.store.assignment("target")[0])
        with self.assertRaises(PermissionError):
            banks.verify(self.store, "target", request)

    def test_no_second_admin_or_shared_token_can_manufacture_live_action(self):
        read_only = self.person("55555555-5555-5555-5555-555555555555", "read_only")
        for person in (read_only, {"auth_type": "token", "role": "admin", "actor": "token:admin"}):
            with self.subTest(person=person.get("auth_type")), self.assertRaises(PermissionError):
                banks.assess(self.store, {"server_ids": ["target"]}, person["actor"], person)

    def test_assessment_expiry_and_completed_banks_block_unneeded_reload(self):
        self.assess(); self.receipt(checked_at=stamp(now() - timedelta(minutes=4)))
        stale = banks.preview(self.store, {"server_ids": ["target"]}, self.maker["actor"], self.maker)
        self.assertFalse(stale["can_apply"])
        self.assess(); self.receipt(missing_banks=0, active_banks=256, permanent_banks=256, activation_required=False)
        ready = banks.preview(self.store, {"server_ids": ["target"]}, self.maker["actor"], self.maker)
        self.assertFalse(ready["can_apply"])
        self.assertTrue(any("already active" in message for message in ready["blockers"]))

    def test_prepared_receipt_is_terminal_and_late_progress_cannot_rearm_it(self):
        self.confirm(self.preview())
        self.receipt("preparing")
        prepared = self.receipt("prepared", active_banks=256, permanent_banks=256, missing_banks=0, created_banks=256, activation_required=False)
        self.assertNotIn("source_bank_preparation", self.store.assignment("target")[0])
        self.receipt("preparing")
        self.assertEqual(self.store.get("servers", "target")[banks.RECEIPT], prepared)
        self.assertNotIn("source_bank_preparation", self.store.assignment("target")[0])
        self.assertEqual(sum(row["action"] == "source_banks.prepared" for row in self.store.all("audit")), 1)

    def test_superseded_receipt_cannot_replace_new_job_and_errors_alert(self):
        first = self.assess(); old = self.receipt()
        second = self.assess()
        with self.store.meta() as db:
            host = self.store._get(db, "servers", "target")
            banks.report(self.store, db, host, old)
            self.store._put(db, "servers", host)
        self.assertEqual(self.store.assignment("target")[0]["source_bank_preparation"]["id"], second["id"])
        self.assertNotEqual(first["id"], second["id"])
        self.receipt("error", error="Assessment failed safely")
        self.assertTrue(any(row["kind"] == "source_bank_preparation_error" for row in self.store.all("alerts")))

    def test_shape_bounds_are_atomic_and_unknown_state_is_not_success(self):
        self.assess()
        good = self.receipt()
        for changes in ({"status": []}, {"created_banks": True}, {"active_banks": 257}, {"blockers": None}, {"error": "é" * 513}, {"checked_at": stamp(now() + timedelta(minutes=2))}, {"raw_config": "private"}):
            host = self.store.get("servers", "target")
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.store.report("target", {"hostname": "must-not-persist", "ips": host["ips"], "source_bank_preparation": {**good, **changes}})
            self.assertEqual(self.store.get("servers", "target"), host)

    def test_public_navigation_is_bounded_without_private_job_or_proof(self):
        self.assess(); self.receipt()
        response = banks.listing(self.store, {"server_ids": ["target"], "limit": 1})
        self.assertEqual((response["total"], len(response["items"])), (1, 1))
        self.assertTrue(response["items"][0]["capable"])
        self.assertNotIn("context", response["items"][0]["job"])
        self.assertNotIn(banks.JOB, self.store.server("target"))
        with self.store.meta() as db:
            host = self.store._get(db, "servers", "target")
            host[banks.JOB]["expires_at"] = stamp(now() - timedelta(seconds=1)); self.store._put(db, "servers", host)
        self.assertNotIn("source_bank_preparation", self.store.assignment("target")[0])

    def test_activation_receipts_cannot_change_reviewed_binding_or_terminal_outcome(self):
        self.confirm(self.preview())
        before = self.store.get("servers", "target")
        for changed in ({"baseline_digest": "b" * 64}, {"protection_digest": "e" * 64}):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                self.receipt("prepared", active_banks=256, permanent_banks=256, missing_banks=0, activation_required=False, **changed)
            self.assertEqual(self.store.get("servers", "target"), before)
        prepared = self.receipt("prepared", active_banks=256, permanent_banks=256, missing_banks=0, activation_required=False)
        self.receipt("error", checked_at=stamp(now() + timedelta(seconds=1)), error="Contradictory late replay")
        self.assertEqual(self.store.get("servers", "target")[banks.RECEIPT], prepared)
        self.assertNotIn("source_bank_preparation", self.store.assignment("target")[0])

    def test_admitted_uncertain_activation_cannot_be_erased_by_expiry_or_new_assessment(self):
        self.confirm(self.preview())
        job = self.store.assignment("target")[0]["source_bank_preparation"]
        request = {key: job[key] for key in ("id", "plan_digest", "baseline_digest", "protection_digest")}
        banks.verify(self.store, "target", {**request, "nonce": "b" * 32, "ssh_ports": [2022]})
        self.receipt("error", error="Rollback still uncertain")
        with self.store.meta() as db:
            host = self.store._get(db, "servers", "target")
            host[banks.JOB]["created_at"] = stamp(now() - timedelta(hours=1))
            host[banks.JOB]["expires_at"] = stamp(now() - timedelta(minutes=30))
            self.store._put(db, "servers", host)
        with self.assertRaises(WorkflowConflict):
            self.assess()
        self.assertEqual(self.store.get("servers", "target")[banks.JOB]["id"], job["id"])
        self.receipt("rolled_back")
        self.assess()
        self.assertNotEqual(self.store.get("servers", "target")[banks.JOB]["id"], job["id"])

    def test_read_only_http_navigation_cannot_request_or_activate_maintenance(self):
        self.assess(); self.receipt()
        app = App(self.store, tokens={"read_only": "reader", "admin": "lab-admin"})
        def request(path, body, token="reader"):
            handler = object.__new__(handler_for(app))
            handler.command, handler.path, handler.connection = "POST", "/api/v1" + path, object()
            handler.client_address, handler.headers = ("127.0.0.1", 12345), Message()
            if token:
                handler.headers["Authorization"] = "Bearer " + token
            handler.body = lambda: body
            captured = {}
            handler.response = lambda status, value=None, headers=None: captured.update(status=status, value=value)
            handler.dispatch()
            return captured
        page = request("/source-banks/query", {"server_ids": ["target"]})
        self.assertEqual((page["status"], page["value"]["total"]), (200, 1))
        self.assertNotIn("approval_proof", str(page["value"]))
        self.assertEqual(request("/source-banks/assess", {"server_ids": ["target"]})["status"], 403)
        self.assertEqual(request("/source-banks/example/confirm", {})["status"], 403)
        self.assertEqual(request("/source-banks/assess", {"server_ids": ["target"]}, "lab-admin")["status"], 403)
        self.assertEqual(request("/source-banks/query", {}, None)["status"], 401)
        self.assertEqual(request("/source-banks/query", {"limit": 100000})["status"], 400)


@unittest.skipUnless(os.environ.get("PRTHAK_PLATFORM_PG_ACCEPTANCE") == "1", "Owner opt-in for private PostgreSQL source-bank fixture")
class PostgreSQLSourceBankMaintenance(SourceBankMaintenanceTests):
    @classmethod
    def setUpClass(cls):
        import psycopg
        from psycopg import sql
        from psycopg.conninfo import make_conninfo
        cls.driver, cls.sql, cls.parameters = psycopg, sql, private_pg.parameters()
        cls.names = private_pg.names("source_banks")
        cls.created = []
        cls.addClassCleanup(cls.cleanup_databases)
        with psycopg.connect(**cls.parameters, dbname="postgres", autocommit=True) as db:
            cls.verify_cluster(db)
            for name in cls.names.values():
                if db.execute("SELECT 1 FROM pg_database WHERE datname=%s", (name,)).fetchone():
                    raise RuntimeError("Refusing to adopt an existing fixture database")
                db.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(name)))
                cls.created.append(name)
        cls.dsns = {key: make_conninfo(**cls.parameters, dbname=name) for key, name in cls.names.items()}

    @classmethod
    def verify_cluster(cls, db):
        user, directory = db.execute("SELECT current_user,current_setting('data_directory')").fetchone()
        if user != "prthak_test" or Path(directory).resolve() != private_pg.data_directory():
            raise RuntimeError("Only the project-owned private PostgreSQL test cluster is allowed")

    @classmethod
    def cleanup_databases(cls):
        with cls.driver.connect(**cls.parameters, dbname="postgres", autocommit=True) as db:
            cls.verify_cluster(db)
            for name in cls.created:
                db.execute(cls.sql.SQL("DROP DATABASE {} WITH (FORCE)").format(cls.sql.Identifier(name)))

    def make_store(self):
        from controller.postgres import PostgresStore
        for dsn in self.dsns.values():
            with self.driver.connect(dsn, autocommit=True) as db:
                self.verify_cluster(db)
                db.execute("DROP SCHEMA public CASCADE")
                db.execute("CREATE SCHEMA public")
        return PostgresStore(self.dsns["metadata"], self.dsns["traffic"])

    def setUp(self):
        with patch.object(fixture, "Store", side_effect=lambda _: self.make_store()):
            super().setUp()


if __name__ == "__main__":
    unittest.main()
