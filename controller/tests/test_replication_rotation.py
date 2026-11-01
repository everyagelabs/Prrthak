import copy
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from controller.tests import private_pg as pg_fixture

import importlib.util
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch

from controller import cluster_bootstrap as bootstrap
from controller import replication_rotation as rotation
from controller.firewall import WorkflowConflict
from controller.store import now, stamp
from controller.tests.test_cluster_bootstrap import BootstrapFixture


class RotationClient:
    """Only the fixed local actuator is simulated; metadata/vault/RSA are real."""
    def __init__(self, lab, node):
        self.lab, self.node = lab, node
        self.jobs, self.requests = {}, []
        self.revision = 7
        self.responses = {}
        self.disconnect_phase = None

    def status(self):
        return {"revision": self.revision, "health": {"status": "observed", "checked_at": self.lab["checked_at"] or now().timestamp(),
            "quorum_healthy": True, "all_voters_healthy": self.lab["healthy"], "primary_count": 1, "database_ready": True,
            "nodes": [{"id": "node-" + str(i), "ip": "10.70.0." + str(i), "etcd_healthy": self.lab["healthy"], "postgres_running": True,
                       "role": "primary" if "node-" + str(i) == self.lab["primary"] else "replica"} for i in range(1, 4)]}}

    def job(self, identifier):
        if identifier not in self.jobs:
            raise KeyError(identifier)
        return copy.deepcopy(self.jobs[identifier])

    def submit(self, request):
        self.requests.append(copy.deepcopy(request))
        phase = request["phase"]
        identifier = request["request_id"]
        if identifier in self.jobs:
            return self.job(identifier)
        result = {"rotation_id": request["rotation_id"]}
        if phase in self.responses:
            result.update(self.responses[phase])
        elif phase == "prepare":
            self.lab["prepared"].add(self.node)
            result.update(prepared=True, phase="prepared")
        elif phase == "change-role":
            assert len(self.lab["prepared"]) == 3, "SQL role change before all-three prepare barrier"
            if self.node != self.lab["primary"]:
                result.update(phase="not_primary", not_primary=True)
            else:
                self.lab["role_changes"] += 1
                result.update(phase="role_changed", role_change_ack=True)
        elif phase == "reload":
            assert self.lab["role_changes"] >= 1, "Reload before SQL role acknowledgement"
            self.lab["reloaded"].add(self.node)
            result.update(phase="reloaded", reload_ack=True)
        elif phase == "verify":
            assert len(self.lab["reloaded"]) == 3, "Verification before all-three reload barrier"
            self.lab["verified"].add(self.node)
            result.update(phase="verified", verified=True, new_connection=True)
        elif phase == "finalize":
            assert request["all_voters_verified"] is True and len(self.lab["verified"]) == 3
            self.lab["finalized"].add(self.node)
            self.revision += 1
            result.update(phase="finalized", verified=True)
        elif phase == "abort":
            assert self.lab["role_changes"] == 0
            result.update(phase="aborted")
        value = {"id": identifier, "status": "completed", "result": result}
        self.jobs[identifier] = value
        if self.disconnect_phase == phase:
            self.disconnect_phase = None
            raise OSError("Simulated lost reply after persisted actuator outcome")
        return copy.deepcopy(value)


class RotationFixture(BootstrapFixture):
    def setUp(self):
        super().setUp()
        self.nodes = [self.api]
        for i in range(2, 5):
            response, key, body = self.enroll(identifier="node-" + str(i), site="site-" + str(i), address="10.70.0." + str(i))
            self.nodes.append(self.install_joiner(response, identifier=body["node_id"], site=body["site"], key=key))
        bootstrap.manifest(self.api)
        self.lab = {"primary": "node-1", "healthy": True, "checked_at": None, "prepared": set(), "reloaded": set(), "verified": set(), "finalized": set(), "role_changes": 0}
        for api in self.nodes:
            api.app.store = self.api.app.store
            api.client = RotationClient(self.lab, api._identity()["id"])
        self.api.app.store.ha = True
        self.password = "new-live-replication-password-acceptance-123456"

    def queue(self, password=None):
        with self.api.app.store.lock, self.api.app.store.meta() as db:
            config = self.api._config(db)
            result = rotation.queue(self.api, db, config, password or self.password, "super_admin")
            self.api.app.store._put(db, "maintenance_settings", config)
            return result

    def step(self):
        for api in self.nodes:
            rotation.reconcile(api)

    def finish(self, phase="completed", passes=20):
        for i in range(passes):
            self.step()
            if rotation.status(self.api)["phase"] == phase:
                for api in self.nodes:
                    rotation.sync_completed_material(api)
                return rotation.status(self.api)
        self.fail("Rotation did not reach " + phase + ": " + json.dumps(rotation.status(self.api)))


@unittest.skipUnless(importlib.util.find_spec("cryptography"), "Rotation tests require actual cryptography and vault")
class ReplicationRotationTests(RotationFixture, unittest.TestCase):
    def test_full_barriers_sealed_shared_state_and_management_material_catchup(self):
        queued = self.queue()
        self.assertEqual(queued["phase"], "prepare")
        self.assertNotIn("recipients", queued)
        self.assertNotIn(self.password, json.dumps(self.api.app.store.all("maintenance_settings")))
        self.assertEqual(bootstrap._material(self.api)["secrets"]["replication"], self.replication_password)
        completed = self.finish()
        self.assertFalse(completed["pending"])
        self.assertEqual(self.lab["role_changes"], 1)
        self.assertEqual(len(self.lab["finalized"]), 3)
        self.assertEqual(self.nodes[3].client.requests, [])
        for api in self.nodes:
            self.assertEqual(bootstrap._material(api)["secrets"]["replication"], self.password)
        for path in self.directory.rglob("*"):
            if path.is_file():
                self.assertNotIn(self.password.encode(), path.read_bytes(), str(path))
        for client in (api.client for api in self.nodes):
            for request in client.requests:
                self.assertEqual("password" in request, request["phase"] == "prepare")

    def test_completed_job_without_exact_ack_cannot_cross_prepare_barrier(self):
        self.nodes[2].client.responses["prepare"] = {"phase": "prepared", "prepared": False}
        self.queue()
        for i in range(3):
            self.step()
        state = rotation.status(self.api)
        self.assertEqual(state["phase"], "prepare")
        self.assertEqual(self.lab["role_changes"], 0)
        self.assertTrue(state["errors"]["node-3"])

    def test_verify_requires_genuinely_new_connection_before_finalize(self):
        self.nodes[2].client.responses["verify"] = {"phase": "verified", "verified": True, "new_connection": False}
        self.queue()
        for i in range(8):
            self.step()
        self.assertEqual(rotation.status(self.api)["phase"], "verify")
        self.assertEqual(self.lab["finalized"], set())

    def test_verify_receipt_cannot_prematurely_acknowledge_finalize(self):
        self.nodes[2].client.responses["finalize"] = {"phase": "verified", "verified": True, "new_connection": True}
        self.queue()
        for i in range(10):
            self.step()
        self.assertEqual(rotation.status(self.api)["phase"], "finalize")
        self.assertEqual(bootstrap._material(self.api)["secrets"]["replication"], self.replication_password)

    def test_abort_before_role_intent_restores_without_changing_material(self):
        self.queue()
        rotation.reconcile(self.api)
        rotation.request_abort(self.nodes[1], "super_admin")
        self.finish("aborted")
        self.assertEqual(self.lab["role_changes"], 0)
        self.assertFalse(self.api.status()["cluster"]["replication_password_pending"])
        for api in self.nodes:
            self.assertEqual(bootstrap._material(api)["secrets"]["replication"], self.replication_password)

    def test_role_intent_forbids_abort_even_if_sql_reply_was_lost(self):
        self.api.client.disconnect_phase = "change-role"
        self.queue()
        for i in range(3):
            self.step()
            if rotation.status(self.api)["role_change_intent"]:
                break
        with self.assertRaises(WorkflowConflict):
            rotation.request_abort(self.api, "super_admin")
        self.finish()
        self.assertEqual(self.lab["role_changes"], 1)
        self.assertEqual(len([r for r in self.api.client.requests if r["phase"] == "change-role"]), 1)

    def test_failed_manager_job_resumes_with_new_durable_attempt_after_restart(self):
        self.api.client.responses["change-role"] = {"phase": "interrupted"}
        self.queue()
        for i in range(4):
            self.step()
        before = [r for r in self.api.client.requests if r["phase"] == "change-role"]
        self.assertEqual(len(before), 1)
        del self.api.client.responses["change-role"]
        with patch("controller.replication_rotation.now", return_value=now() + timedelta(seconds=10)):
            self.finish()
        after = [r for r in self.api.client.requests if r["phase"] == "change-role"]
        self.assertEqual(len(after), 2)
        self.assertNotEqual(before[0]["request_id"], after[1]["request_id"])

    def test_stale_health_missing_voter_key_and_bad_password_refuse_queue(self):
        self.lab["checked_at"] = (now() - timedelta(seconds=50)).timestamp()
        with self.assertRaises(ValueError):
            self.queue()
        self.lab["checked_at"] = None
        with self.api.app.store.meta() as db:
            config = self.api._config(db)
            config["members"][1].pop("transport_public_key")
            self.api.app.store._put(db, "maintenance_settings", config)
        with self.assertRaises(ValueError):
            self.queue()
        for value in ("x" * 129, "x" * 31, "é" * 40, "x" * 32 + "\n"):
            with self.subTest(length=len(value)), self.assertRaises(ValueError):
                self.queue(value)

    def test_health_loss_after_queue_blocks_prepare_and_membership_drift_blocks_sql(self):
        self.queue()
        self.lab["healthy"] = False
        self.step()
        self.assertTrue(all(not api.client.requests for api in self.nodes))
        self.lab["healthy"] = True
        with self.api.app.store.meta() as db:
            config = self.api._config(db)
            config["members"][1]["site"] = "changed-site"
            self.api.app.store._put(db, "maintenance_settings", config)
        self.step()
        self.assertEqual(self.lab["role_changes"], 0)
        self.assertIn("membership", json.dumps(rotation.status(self.api)["errors"]))

    def test_active_save_queues_and_status_is_public_without_local_pending_reference(self):
        result = self.save(self.api, cluster_password="", replication_password=self.password)
        self.assertTrue(result["cluster"]["replication_password_pending"])
        self.assertEqual(result["cluster"]["replication_rotation"]["phase"], "prepare")
        self.assertNotIn("recipients", json.dumps(result))
        self.assertNotIn(self.password, json.dumps(result))
        self.assertEqual(self.api.manager.vault.get(self.api._local()["pending_replication_ref"]), self.replication_password)
        self.finish()
        self.assertFalse(self.api.status()["cluster"]["replication_password_pending"])

    def test_same_pending_password_is_idempotent_different_password_refuses(self):
        first = self.queue()
        self.assertEqual(self.queue()["rotation_id"], first["rotation_id"])
        with self.assertRaises(WorkflowConflict):
            self.queue("different-live-replication-password-acceptance-123")

    def test_already_active_password_is_not_queued_forever_and_seed_key_is_registered(self):
        with self.assertRaisesRegex(ValueError, "already active"):
            self.queue(self.replication_password)
        with self.api.app.store.meta() as db:
            config = self.api._config(db)
            config["members"][0].pop("transport_public_key")
            self.api.app.store._put(db, "maintenance_settings", config)
        self.queue()
        self.assertTrue(self.api._config()["members"][0]["transport_public_key"].startswith("-----BEGIN PUBLIC KEY-----"))

    def test_new_controller_admission_waits_but_existing_retry_can_continue(self):
        self.queue()
        key, body = self.enrollment(identifier="node-5", site="site-5", address="10.70.0.5")
        with self.assertRaisesRegex(ValueError, "rotation"):
            bootstrap.enroll(self.api, body, "192.0.2.99")
        self.assertEqual(len(self.api._config()["members"]), 4)

    def test_enrollment_rechecks_completed_material_inside_locked_snapshot(self):
        self.queue()
        self.finish()
        old = bootstrap._material(self.api)
        old["secrets"]["replication"] = self.replication_password
        bootstrap._save_material(self.api, old)
        real_sync = rotation.sync_completed_material
        def skip_pre_transaction(api, material=None, db=None):
            return real_sync(api, material, db=db) if db is not None else None
        key, body = self.enrollment(identifier="node-5", site="site-5", address="10.70.0.5")
        with patch("controller.replication_rotation.sync_completed_material", side_effect=skip_pre_transaction):
            sealed = bootstrap.enroll(self.api, body, "192.0.2.99")
        result = self.api.manager._unseal(sealed, key, "node-5")
        self.assertEqual(result["material"]["secrets"]["replication"], self.password)


@unittest.skipUnless(os.environ.get("PRTHAK_ROTATION_PG_ACCEPTANCE") == "1", "Opt in to dedicated real-PG rotation coordinator tests")
class SharedPostgresRotationTests(RotationFixture, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import psycopg
        from psycopg import sql
        from psycopg.conninfo import make_conninfo
        cls.driver, cls.sql = psycopg, sql
        root = Path(__file__).resolve().parents[2]
        cls.names = pg_fixture.names("rotation")
        params = pg_fixture.parameters()
        with psycopg.connect(**params, dbname="postgres", autocommit=True) as db:
            user, path = db.execute("SELECT current_user,current_setting('data_directory')").fetchone()
            if user != "prthak_test" or Path(path).resolve() != pg_fixture.data_directory():
                raise RuntimeError("Only the prepared private PostgreSQL test cluster is allowed")
            for name in cls.names.values():
                if db.execute("SELECT 1 FROM pg_database WHERE datname=%s", (name,)).fetchone():
                    raise RuntimeError("Refusing to reuse a pre-existing private fixture database")
                db.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(name)))
        cls.dsns = {key: make_conninfo(**params, dbname=name) for key, name in cls.names.items()}

    def reset_targets(self):
        for key, dsn in self.dsns.items():
            with self.driver.connect(dsn, autocommit=True) as db:
                self.assertEqual(db.execute("SELECT current_database()").fetchone()[0], self.names[key])
                db.execute("DROP SCHEMA public CASCADE")
                db.execute("CREATE SCHEMA public")

    def setUp(self):
        from controller.platform_runtime import migrate_stopped_sqlite
        from controller.postgres import PostgresStore
        super().setUp()
        self.reset_targets()
        self.addCleanup(self.reset_targets)
        deployment = self.api._config()["deployment_id"]
        migrate_stopped_sqlite(self.api.app.store.path, self.dsns["metadata"], self.dsns["traffic"], deployment, 1)
        for api in self.nodes:
            # Separate adapters/locks exercise PG's transaction advisory lock.
            api.app.store = PostgresStore(self.dsns["metadata"], self.dsns["traffic"], deployment_id=deployment, epoch=1)

    def test_real_pg_parallel_barriers_and_sealed_management_catchup(self):
        self.queue()
        with ThreadPoolExecutor(max_workers=4) as pool:
            for i in range(24):
                list(pool.map(rotation.reconcile, self.nodes))
                if rotation.status(self.api)["phase"] == "completed":
                    break
        self.assertEqual(rotation.status(self.api)["phase"], "completed")
        self.assertEqual(self.lab["role_changes"], 1)
        for api in self.nodes:
            rotation.sync_completed_material(api)
            self.assertEqual(bootstrap._material(api)["secrets"]["replication"], self.password)
        with self.api.app.store.read_meta() as db:
            shared = db.execute("SELECT data FROM maintenance_settings").fetchall()
        self.assertNotIn(self.password, "".join(row[0] for row in shared))
        self.assertEqual(self.api.app.store.readiness(), {"metadata": True, "traffic": True})

    def test_real_pg_lost_sql_reply_recovers_without_duplicate_role_change(self):
        self.api.client.disconnect_phase = "change-role"
        self.queue()
        self.finish()
        self.assertEqual(self.lab["role_changes"], 1)
        self.assertFalse(rotation.status(self.nodes[2])["pending"])


if __name__ == "__main__":
    unittest.main()
