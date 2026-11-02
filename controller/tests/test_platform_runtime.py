from contextlib import closing
from datetime import timedelta
import fcntl
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import uuid

from controller import platform_runtime as runtime
from controller.postgres import DependencyUnavailable, PostgresStore, Row
from controller.store import Store, now, stamp


class Cursor:
    def __init__(self, rows=()):
        self.rows = list(rows)

    def fetchone(self):
        return self.rows[0] if self.rows else None

    def fetchall(self):
        return self.rows


class TargetConnection:
    def __init__(self, driver, namespace):
        self.driver, self.namespace = driver, namespace

    def __enter__(self):
        return self

    def __exit__(self, *_):
        pass

    def execute(self, query, parameters=()):
        self.driver.queries.append((self.namespace, query))
        state = self.driver.states[self.namespace]
        if "current_database()" in query:
            return Cursor([(self.namespace, "127.0.0.1", 5432)])
        if "pg_tables" in query:
            return Cursor([(table,) for table in state["tables"]])
        if "SELECT data FROM runtime_deployment" in query:
            return Cursor([(json.dumps(state["marker"]),)] if state.get("marker") else [])
        if "SELECT EXISTS" in query:
            return Cursor([(state.get("nonempty", False),)])
        return Cursor()

    def close(self):
        pass


class TargetDriver:
    def __init__(self, deployment):
        self.queries = []
        self.states = {namespace: {"tables": {"runtime_deployment"}, "marker": {"deployment_id": deployment, "epoch": 1, "state": "READY", "namespace": namespace, "import_id": "same-import", "source_fingerprint": "same-source"}} for namespace in ("metadata", "traffic")}

    def __call__(self, dsn, **_):
        return TargetConnection(self, dsn)


class Manager:
    def __init__(self, events):
        self.events, self.profile = events, None

    def runtime_job_update(self, identifier, status, details):
        self.events.append(("job", status))

    def commit_active_profile(self, profile):
        self.events.append(("commit", profile["active_revision"]))
        self.profile = profile

    def active_profile(self):
        return self.profile


class Child:
    def poll(self):
        return None


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name) / "store"
        self.store = Store(self.directory)
        self.deployment = str(uuid.uuid4())
        self.profile = {"deployment_id": self.deployment, "epoch": 1, "active_revision": 3, "metadata_dsn": "metadata", "traffic_dsn": "traffic"}

    def test_gui_provider_file_overrides_retained_profile_but_new_joins_receive_epoch(self):
        paths={name:str(self.directory/name) for name in ('cert','key','ca')}
        for path in paths.values():Path(path).write_text('private-fixture')
        profile={**self.profile,'controller_tls':paths,'controller_env':{'SEG_ENTRA_TENANT_ID':'old-tenant','SEG_ENTRA_CLIENT_SECRET':'old-secret','PRTHAK_PROVIDER_EPOCH':'old-epoch','SEG_MANAGEMENT_PROBE_SOURCE_IP':'10.1.2.3'}}
        source={'PRTHAK_GUI_PROVIDER_MANAGED':'1','PRTHAK_PROVIDER_EPOCH':'new-epoch','SEG_ENTRA_TENANT_ID':'new-tenant','SEG_ENTRA_CLIENT_SECRET':'new-secret'}
        with patch.dict(os.environ,source),patch.object(runtime.ssl,'SSLContext'):
            _,environment=runtime.child_launch([],profile)
        self.assertEqual(environment['SEG_ENTRA_TENANT_ID'],'new-tenant')
        self.assertEqual(environment['SEG_ENTRA_CLIENT_SECRET'],'new-secret')
        self.assertEqual(environment['PRTHAK_PROVIDER_EPOCH'],'new-epoch')
        self.assertEqual(environment['SEG_MANAGEMENT_PROBE_SOURCE_IP'],'10.1.2.3')
        with patch.dict(os.environ,{},clear=True),patch.object(runtime.ssl,'SSLContext'):
            _,environment=runtime.child_launch([],profile)
        self.assertEqual(environment['PRTHAK_PROVIDER_EPOCH'],'old-epoch')
        self.assertEqual(environment['SEG_ENTRA_CLIENT_SECRET'],'old-secret')

    def test_retired_source_cannot_reopen_or_write_from_existing_store(self):
        runtime.atomic_private_json(self.directory / runtime.FENCE_NAME, {"state": "RETIRED", "deployment_id": self.deployment})
        with self.assertRaises(runtime.RuntimeSafetyError):
            Store(self.directory)
        for context in (self.store.meta, self.store.traffic):
            with self.assertRaises(runtime.RuntimeSafetyError):
                with context():
                    self.fail("A fenced source transaction was opened")

    def test_existing_transaction_has_cross_process_shared_fence_until_closed(self):
        with self.store.meta():
            with (self.directory / ".prthak-storage.lock").open("a+") as lock:
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        with (self.directory / ".prthak-storage.lock").open("a+") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)

    def test_surviving_child_keeps_exclusive_supervisor_lease_after_parent_closes_it(self):
        platform = self.directory / "platform"
        child = None
        try:
            with runtime.supervisor_lease(platform) as descriptor:
                child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"], pass_fds=(descriptor,))
                with self.assertRaises(runtime.RuntimeSafetyError):
                    with runtime.supervisor_lease(platform):
                        self.fail("A concurrent supervisor was allowed")
            with self.assertRaises(runtime.RuntimeSafetyError):
                with runtime.supervisor_lease(platform):
                    self.fail("An orphaned controller's lease was ignored")
            child.terminate()
            child.wait(timeout=5)
            with runtime.supervisor_lease(platform):
                pass
        finally:
            if child is not None and child.poll() is None:
                child.kill()
                child.wait(timeout=5)

    def test_snapshot_preserves_all_fixed_state_and_canonical_json_hash(self):
        self.store.report("host", {"hostname": "host", "ips": ["10.1.0.1"], "listeners": []})
        with self.store.meta() as db:
            self.store._put(db, "auth_users", {"id": "account", "role": "SuperAdmin"})
            self.store._put(db, "learning_evidence_receipts", {"id": "receipt", "server_id": "host"})
            self.store._put(db, "sessions", {"id":"migrate-scope", "server_ids":["host"], "status":"active",
                "starts_at":stamp(), "expires_at":stamp(now()+timedelta(hours=1))})
        rows, proof, fingerprint, backup = runtime._snapshot_source(self.directory, self.deployment)
        self.assertEqual(proof["metadata"]["counts"]["servers"], 1)
        self.assertEqual(proof["metadata"]["counts"]["auth_users"], 1)
        self.assertEqual(proof["metadata"]["counts"]["learning_evidence_receipts"], 1)
        self.assertEqual(proof["metadata"]["counts"]["learning_session_targets"], 1)
        self.assertEqual(len(fingerprint), 64)
        self.assertTrue((backup / "manifest.json").is_file())
        self.assertEqual(json.loads(rows["metadata"]["servers"][0][1])["id"], "host")
        columns = ("id", "data")
        first = [("a", '{"one":1,"two":2}')]
        second = [Row(columns, ("a", '{"two":2,"one":1}'))]
        self.assertEqual(runtime._hash_rows(columns, first), runtime._hash_rows(columns, second))
        self.assertEqual(runtime._hash_rows(columns, [("a-b", "{}"), ("ab", "{}"), ("A", "{}")]),
                         runtime._hash_rows(columns, [("A", "{}"), ("ab", "{}"), ("a-b", "{}")]))

    def test_unknown_source_schema_is_rejected_without_silent_table_loss(self):
        with self.store.meta() as db:
            db.execute("CREATE TABLE future_sensitive_state(id TEXT PRIMARY KEY,data TEXT)")
        with self.assertRaises(runtime.RuntimeSafetyError):
            runtime._snapshot_source(self.directory, self.deployment)

    def test_foreign_or_nonempty_target_is_rejected_before_source_is_fenced(self):
        driver = TargetDriver(self.deployment)
        driver.states["metadata"]["marker"]["deployment_id"] = str(uuid.uuid4())
        with self.assertRaises(runtime.RuntimeSafetyError):
            runtime.migrate_stopped_sqlite(self.directory, "metadata", "traffic", self.deployment, 1, connector=driver)
        self.assertFalse((self.directory / runtime.FENCE_NAME).exists())
        driver.states["metadata"] = {"tables": {"servers"}, "nonempty": True}
        with self.assertRaises(runtime.RuntimeSafetyError):
            runtime.migrate_stopped_sqlite(self.directory, "metadata", "traffic", self.deployment, 1, connector=driver)
        self.assertFalse((self.directory / runtime.FENCE_NAME).exists())
        self.assertTrue(all(not query.startswith(("INSERT", "UPDATE", "DELETE", "CREATE")) for _, query in driver.queries))

    def test_snapshot_preflight_failure_does_not_retire_a_previously_usable_source(self):
        driver = TargetDriver(self.deployment)
        for state in driver.states.values():
            state.update(tables=set(), marker=None)
        with patch("controller.platform_runtime._snapshot_source", side_effect=runtime.RuntimeSafetyError("Synthetic snapshot capacity failure")):
            with self.assertRaises(runtime.RuntimeSafetyError):
                runtime.migrate_stopped_sqlite(self.directory, "metadata", "traffic", self.deployment, 1, connector=driver)
        self.assertFalse((self.directory / runtime.FENCE_NAME).exists())
        with self.store.meta() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM servers").fetchone()[0], 0)

    def test_both_ready_markers_must_share_exact_deployment_epoch_and_import(self):
        driver = TargetDriver(self.deployment)
        markers = runtime.verify_deployment("metadata", "traffic", self.deployment, 1, connector=driver)
        self.assertEqual(set(markers), {"metadata", "traffic"})
        for field, value in (("state", "VERIFIED"), ("epoch", 2), ("import_id", "different-import"), ("source_fingerprint", "different-source"), ("import_id", "")):
            with self.subTest(field=field):
                original = driver.states["traffic"]["marker"][field]
                driver.states["traffic"]["marker"][field] = value
                with self.assertRaises(runtime.RuntimeSafetyError):
                    runtime.verify_deployment("metadata", "traffic", self.deployment, 1, connector=driver)
                driver.states["traffic"]["marker"][field] = original

    def test_expected_postgres_identity_is_guarded_at_startup_and_subsequent_writes(self):
        driver = TargetDriver(self.deployment)
        target = PostgresStore("metadata", "traffic", initialize=False, connector=driver, deployment_id=self.deployment, epoch=1)
        with target.meta():
            pass
        driver.states["metadata"]["marker"]["state"] = "IMPORTING"
        with self.assertRaises(DependencyUnavailable):
            with target.meta():
                self.fail("A non-ready deployment transaction was opened")
        driver.states["metadata"]["marker"]["state"] = "READY"
        driver.states["metadata"]["marker"]["import_id"] = "different-import"
        with self.assertRaises(DependencyUnavailable):
            with target.meta():
                self.fail("A substituted import with a matching deployment UUID was accepted")

    def test_join_never_merges_populated_local_business_data(self):
        self.store.report("keep-local", {"hostname": "keep-local", "ips": [], "listeners": []})
        driver = TargetDriver(self.deployment)
        with self.assertRaises(runtime.RuntimeSafetyError):
            runtime.join_stopped_sqlite(self.directory, {**self.profile, "join_preserve_local_snapshot": True}, connector=driver)
        self.assertFalse((self.directory / runtime.FENCE_NAME).exists())
        with closing(sqlite3.connect(self.store.meta_path)) as db:
            self.assertEqual(db.execute("SELECT id FROM servers").fetchall(), [("keep-local",)])
        self.assertTrue(all(not query.startswith(("INSERT", "UPDATE", "DELETE", "CREATE")) for _, query in driver.queries))

    def test_join_blank_setup_preserves_snapshot_without_merging_accounts(self):
        with self.store.meta() as db:
            self.store._put(db, "auth_users", {"id": "local-only-bootstrap"})
        driver = TargetDriver(self.deployment)
        result = runtime.join_stopped_sqlite(self.directory, {**self.profile, "join_preserve_local_snapshot": True}, connector=driver)
        self.assertEqual(result["copied_rows"], 0)
        self.assertTrue((self.directory / result["backup_name"] / "inventory.sqlite3").is_file())
        self.assertTrue(all(not query.startswith(("INSERT", "UPDATE", "DELETE", "CREATE")) for _, query in driver.queries))

    def test_supervisor_never_snapshots_before_verified_complete_stop(self):
        events = []
        manager = Manager(events)
        migrated = []
        supervisor = runtime.RuntimeSupervisor(self.directory, manager, [], stop=lambda _: False, migrate=lambda *_: migrated.append(True))
        with patch("controller.platform_runtime.child_launch", return_value=([sys.executable, "-m", "controller"], {})):
            with self.assertRaises(runtime.RuntimeSafetyError):
                supervisor.activate({"id": "job", "operation": "activate", "profile": self.profile})
        self.assertEqual(migrated, [])
        self.assertIsNone(manager.profile)

    def test_supervisor_orders_stop_migrate_profile_commit_restart_and_exact_probe(self):
        events = []
        manager = Manager(events)
        def stop(_):
            events.append(("stop", True))
            return True
        def migrate(*_):
            events.append(("copy", True))
            return {"source_fingerprint": "verified-source", "backup_name": "private-snapshot"}
        def launch(command, environment):
            events.append(("launch", True))
            return Child()
        def probe(arguments, profile):
            events.append(("probe", profile["active_revision"]))
            return True
        supervisor = runtime.RuntimeSupervisor(self.directory, manager, [], launch=launch, stop=stop, probe=probe, migrate=migrate)
        with patch("controller.platform_runtime.child_launch", return_value=([sys.executable, "-m", "controller"], {})):
            supervisor.activate({"id": "job", "operation": "activate", "profile": self.profile})
        phases = [value[0] for value in events if value[0] != "job"]
        self.assertEqual(phases, ["stop", "copy", "commit", "launch", "probe"])
        self.assertEqual(events[-1], ("job", "applied"))

    def test_active_shared_controller_is_not_stopped_for_stale_sqlite_import(self):
        events = []
        manager = Manager(events)
        manager.profile = self.profile
        supervisor = runtime.RuntimeSupervisor(self.directory, manager, [], stop=lambda _: events.append(("stop", True)))
        with self.assertRaises(runtime.RuntimeSafetyError):
            supervisor.activate({"id": "job", "operation": "activate", "profile": {**self.profile, "active_revision": 4}})
        self.assertEqual(events, [])

    def test_recovering_committed_profile_never_reimports_sqlite_after_remote_writes(self):
        events = []
        manager = Manager(events)
        manager.profile = self.profile
        def must_not_copy(*_):
            self.fail("A committed profile was retried by importing stale SQLite")
        supervisor = runtime.RuntimeSupervisor(self.directory, manager, [], launch=lambda *_: Child(), stop=lambda _: True,
                                               probe=lambda *_: True, migrate=must_not_copy, join=must_not_copy)
        with patch("controller.platform_runtime.child_launch", return_value=([sys.executable, "-m", "controller"], {})):
            result = supervisor.activate({"id": "job", "operation": "activate", "profile": self.profile})
        self.assertTrue(result["recovered"])
        self.assertNotIn("commit", [event[0] for event in events])
        self.assertEqual(events[-1], ("job", "applied"))

    def test_argument_replacement_matches_argparse_equals_and_repeated_options(self):
        arguments = ["--listen=127.0.0.1:9898", "--site", "old", "--site=older", "--retention-hours", "24"]
        self.assertEqual(runtime._argument(arguments, "--listen"), "127.0.0.1:9898")
        updated = runtime._set_argument(arguments, "--site", "DR")
        self.assertEqual(runtime._argument(updated, "--site"), "DR")
        self.assertEqual(updated.count("--site"), 1)
        self.assertNotIn("--site=older", updated)

    def test_join_launch_keeps_credentials_in_environment_and_replaces_node_identity(self):
        material = {}
        for name in ("cert", "key", "ca"):
            path = self.directory / (name + ".pem")
            path.write_text("fixture: TLS parsing mocked independently")
            material[name] = str(path)
        secret = "role-secret-" * 4
        profile = {**self.profile, "metadata_dsn": "host=db user=admin password=private_metadata", "controller_tls": material,
                   "controller_id": "ctrl-dr", "site": "dr", "controller_env": {"SEG_SUPER_ADMIN_TOKEN": secret, "SEG_ENTRA_CLIENT_SECRET_FILE": "", "SEG_BOOTSTRAP_SUPER_ADMIN_OID": "", "SEG_MANAGEMENT_PROBE_SOURCE_IP": "10.1.0.9"}}
        with patch.dict(os.environ, {"SEG_ENTRA_CLIENT_SECRET_FILE": "/old/secret", "SEG_BOOTSTRAP_SUPER_ADMIN_OID": "old-bootstrap"}), patch("controller.platform_runtime.ssl.SSLContext"):
            command, environment = runtime.child_launch(["--demo", "--controller-id=old", "--site", "old", "--cert=old.pem"], profile)
        self.assertNotIn("--demo", command)
        self.assertEqual(runtime._argument(command, "--controller-id"), "ctrl-dr")
        self.assertEqual(runtime._argument(command, "--site"), "dr")
        self.assertEqual(runtime._argument(command, "--cert"), material["cert"])
        self.assertEqual(environment["SEG_ENTRA_CLIENT_SECRET_FILE"], "")
        self.assertEqual(environment["SEG_BOOTSTRAP_SUPER_ADMIN_OID"], "")
        self.assertEqual(environment["SEG_MANAGEMENT_PROBE_SOURCE_IP"], "10.1.0.9")
        self.assertEqual(environment["SEG_DATABASE_URL"], profile["metadata_dsn"])
        self.assertNotIn(secret, " ".join(command))
        self.assertNotIn("private_metadata", " ".join(command))

    def test_original_manual_ha_launch_is_never_migrated_from_unrelated_sqlite(self):
        events = []
        manager = Manager(events)
        supervisor = runtime.RuntimeSupervisor(self.directory, manager, ["--ha"], stop=lambda _: events.append(("stop", True)))
        with self.assertRaises(runtime.RuntimeSafetyError):
            supervisor.activate({"id": "job", "operation": "activate", "profile": self.profile})
        self.assertEqual(events, [])

    def test_real_child_process_group_exits_before_stop_returns(self):
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"], start_new_session=True)
        try:
            self.assertTrue(runtime.stop_process_group(child, timeout=2))
            self.assertIsNotNone(child.poll())
            with self.assertRaises(ProcessLookupError):
                os.killpg(child.pid, 0)
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=5)

    def test_probe_connection_failure_is_retryable_and_does_not_escape(self):
        with patch("controller.platform_runtime.socket.create_connection", side_effect=ConnectionRefusedError()):
            self.assertFalse(runtime.probe_readiness(["--listen", "127.0.0.1:1234", "--demo"]))


if __name__ == "__main__":
    unittest.main()
