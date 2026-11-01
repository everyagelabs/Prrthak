"""Opt-in, real PostgreSQL pool checks against the private local test cluster.

PRTHAK_POOL_PG_ACCEPTANCE=1 enables these cases. An optional
PRTHAK_TEST_PG_ADMIN_DSN is captured before any environment sanitizer. Only
fresh UUID databases and a newly created temporary role are altered/dropped.
No pre-existing role, deployment database or controller preview is modified.
"""
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import select
import secrets
import signal
import threading
import time
import unittest
import uuid

from controller.tests import private_pg as pg_fixture
from controller.postgres import DependencyUnavailable, PostgresStore


ROOT = Path(__file__).resolve().parents[1]
ADMIN_DSN = os.environ.get("PRTHAK_TEST_PG_ADMIN_DSN")
ENABLED = os.environ.get("PRTHAK_POOL_PG_ACCEPTANCE") == "1"


@unittest.skipUnless(ENABLED, "Set PRTHAK_POOL_PG_ACCEPTANCE=1 for real private PostgreSQL pool acceptance")
class PostgreSQLPoolIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import psycopg
        from psycopg import sql
        from psycopg.conninfo import conninfo_to_dict, make_conninfo
        cls.driver, cls.sql = psycopg, sql
        cls.admin_dsn = ADMIN_DSN or make_conninfo(**pg_fixture.parameters(), dbname="postgres")
        cls.created_databases, cls.created_role = [], False
        cls.suffix = uuid.uuid4().hex[:16]
        cls.role = "prthak_pool_" + cls.suffix
        cls.names = {namespace: "prthak_test_pool_" + cls.suffix + "_" + namespace for namespace in ("metadata", "traffic")}
        cls.password = secrets.token_urlsafe(40)
        cls.deployment, cls.import_id = str(uuid.uuid4()), uuid.uuid4().hex
        cls.evidence = []
        with psycopg.connect(cls.admin_dsn, autocommit=True) as connection:
            user, directory = connection.execute("SELECT current_user,current_setting('data_directory')").fetchone()
            if user != "prthak_test" or Path(directory).resolve() != pg_fixture.data_directory():
                raise RuntimeError("Pool acceptance requires the exact private local PostgreSQL test cluster")
            connection.execute(sql.SQL("CREATE ROLE {} LOGIN PASSWORD {}").format(sql.Identifier(cls.role), sql.Literal(cls.password)))
            cls.created_role = True
            cls.addClassCleanup(cls.cleanup_owned)
            for database in cls.names.values():
                connection.execute(sql.SQL("CREATE DATABASE {} OWNER {}").format(sql.Identifier(database), sql.Identifier(cls.role)))
                cls.created_databases.append(database)
        base = conninfo_to_dict(cls.admin_dsn)
        cls.dsns = {namespace: make_conninfo(**{**base, "dbname": database, "user": cls.role, "password": cls.password})
                    for namespace, database in cls.names.items()}
        PostgresStore(cls.dsns["metadata"], cls.dsns["traffic"])
        for namespace, dsn in cls.dsns.items():
            marker = cls.marker(namespace)
            with psycopg.connect(dsn) as connection:
                connection.execute("CREATE TABLE IF NOT EXISTS runtime_deployment(id TEXT PRIMARY KEY,data TEXT NOT NULL)")
                connection.execute("INSERT INTO runtime_deployment(id,data) VALUES('active',%s) ON CONFLICT(id) DO UPDATE SET data=excluded.data", (json.dumps(marker),))

    @classmethod
    def marker(cls, namespace):
        return {"deployment_id": cls.deployment, "epoch": 1, "namespace": namespace, "state": "READY",
                "import_id": cls.import_id, "source_fingerprint": "a" * 64}

    @classmethod
    def cleanup_owned(cls):
        with cls.driver.connect(cls.admin_dsn, autocommit=True) as connection:
            for database in cls.created_databases:
                if database != cls.names.get("metadata") and database != cls.names.get("traffic"):
                    raise RuntimeError("Refusing unowned fixture cleanup")
                connection.execute(cls.sql.SQL("DROP DATABASE {} WITH (FORCE)").format(cls.sql.Identifier(database)))
            if cls.created_role:
                connection.execute(cls.sql.SQL("DROP ROLE {}").format(cls.sql.Identifier(cls.role)))
            remaining_databases = connection.execute("SELECT COUNT(*) FROM pg_database WHERE datname=ANY(%s)", (list(cls.names.values()),)).fetchone()[0]
            remaining_roles = connection.execute("SELECT COUNT(*) FROM pg_roles WHERE rolname=%s", (cls.role,)).fetchone()[0]
        result = {"scope": "Fresh private PostgreSQL databases/role; real driver and sockets, no mocked DB",
                  "databases": cls.names, "temporary_role": cls.role, "evidence": cls.evidence,
                  "remaining_owned_databases": remaining_databases, "remaining_owned_roles": remaining_roles}
        destination = pg_fixture.evidence_path("pg-pool-integration-evidence.json")
        destination.write_text(json.dumps(result, indent=2) + "\n")
        destination.chmod(0o600)
        if remaining_databases or remaining_roles:
            raise RuntimeError("Owned pool fixtures did not clean up")

    def setUp(self):
        self.store = PostgresStore(self.dsns["metadata"], self.dsns["traffic"], initialize=False,
                                   deployment_id=self.deployment, epoch=1)
        self.addCleanup(self.store.close_worker_pool)
        with self.driver.connect(self.dsns["metadata"]) as connection:
            connection.execute("INSERT INTO maintenance_settings(id,data) VALUES('pool-probe',%s) ON CONFLICT(id) DO UPDATE SET data=excluded.data", (json.dumps({"id": "pool-probe", "value": 1}),))

    def enable(self, maximum=1):
        self.store.enable_worker_pool(metadata_max=maximum, traffic_max=1, wait_seconds=1)

    @staticmethod
    def pid(db):
        return db.execute("SELECT pg_backend_pid()").fetchone()[0]

    def test_same_socket_has_new_snapshot_after_external_commit(self):
        self.enable()
        with self.store.read_meta() as db:
            before = self.pid(db)
            self.assertEqual(self.store._get(db, "maintenance_settings", "pool-probe")["value"], 1)
            with self.driver.connect(self.dsns["metadata"]) as other:
                other.execute("UPDATE maintenance_settings SET data=%s WHERE id='pool-probe'", (json.dumps({"id": "pool-probe", "value": 2}),))
            self.assertEqual(self.store._get(db, "maintenance_settings", "pool-probe")["value"], 1)
        with self.store.read_meta() as db:
            self.assertEqual(self.pid(db), before)
            self.assertEqual(self.store._get(db, "maintenance_settings", "pool-probe")["value"], 2)
            self.assertEqual(db.execute("SHOW transaction_isolation").fetchone()[0], "repeatable read")
            self.assertEqual(db.execute("SHOW transaction_read_only").fetchone()[0], "on")
        self.evidence.append({"case": "fresh_snapshot_same_physical_socket", "backend_pid": before})

    def test_ready_to_fenced_between_borrows_blocks_both_namespaces(self):
        self.enable()
        for namespace, context in (("metadata", self.store.read_meta), ("traffic", self.store.read_traffic)):
            with context() as db:
                before = self.pid(db)
            try:
                with self.driver.connect(self.dsns[namespace]) as other:
                    other.execute("UPDATE runtime_deployment SET data=%s WHERE id='active'", (json.dumps({**self.marker(namespace), "state": "FENCED_RECOVERY", "recovery_id": uuid.uuid4().hex}),))
                with self.assertRaises(DependencyUnavailable):
                    with context():
                        self.fail("A reused socket bypassed the current deployment fence")
            finally:
                with self.driver.connect(self.dsns[namespace]) as other:
                    other.execute("UPDATE runtime_deployment SET data=%s WHERE id='active'", (json.dumps(self.marker(namespace)),))
            with context() as db:
                self.assertEqual(self.pid(db), before)
        self.evidence.append({"case": "both_namespace_fences_rechecked_before_reuse"})

    def test_sql_error_rolls_back_before_same_socket_is_reused(self):
        self.enable()
        with self.store.read_meta() as db:
            before = self.pid(db)
        with self.assertRaises(DependencyUnavailable):
            with self.store.meta() as db:
                self.assertEqual(self.pid(db), before)
                self.store._put(db, "maintenance_settings", {"id": "pool-probe", "value": 999})
                db.execute("SELECT 1/0")
        with self.store.read_meta() as db:
            self.assertEqual(self.pid(db), before)
            self.assertEqual(self.store._get(db, "maintenance_settings", "pool-probe")["value"], 1)
        self.evidence.append({"case": "sql_exception_rolled_back_same_socket", "backend_pid": before})

    def test_real_sockets_are_exclusive_and_bounded_under_threads(self):
        self.enable(2)
        active, observed, lock = set(), set(), threading.Lock()
        def operation(_):
            with self.store.read_meta() as db:
                backend = self.pid(db)
                with lock:
                    self.assertNotIn(backend, active)
                    active.add(backend)
                    observed.add(backend)
                db.execute("SELECT pg_sleep(0.01)")
                with lock:
                    active.remove(backend)
        with ThreadPoolExecutor(max_workers=8) as executor:
            list(executor.map(operation, range(24)))
        self.assertEqual(active, set())
        self.assertEqual(len(observed), 2)
        self.evidence.append({"case": "exclusive_bounded_actual_sockets", "threads": 8, "operations": 24, "physical_sockets": len(observed)})

    def test_saturation_times_out_then_release_restores_capacity(self):
        self.enable()
        with self.store.read_meta():
            started = time.monotonic()
            with self.assertRaises(DependencyUnavailable):
                with self.store.read_meta():
                    self.fail("Nested lease exceeded the one-socket capacity")
            elapsed = time.monotonic() - started
            self.assertGreaterEqual(elapsed, 0.9)
            self.assertLess(elapsed, 3)
        with self.store.read_meta() as db:
            self.assertEqual(db.execute("SELECT 42").fetchone()[0], 42)
        self.evidence.append({"case": "bounded_saturation_recovers", "seconds": round(elapsed, 3)})

    def test_current_role_and_database_disable_block_cached_sockets(self):
        self.enable()
        for kind in ("role", "database"):
            with self.store.read_meta() as db:
                before = self.pid(db)
            identifier = self.role if kind == "role" else self.names["metadata"]
            disable = "ALTER ROLE {} NOLOGIN" if kind == "role" else "ALTER DATABASE {} ALLOW_CONNECTIONS false"
            restore = "ALTER ROLE {} LOGIN" if kind == "role" else "ALTER DATABASE {} ALLOW_CONNECTIONS true"
            try:
                with self.driver.connect(self.admin_dsn, autocommit=True) as admin:
                    admin.execute(self.sql.SQL(disable).format(self.sql.Identifier(identifier)))
                with self.assertRaises(DependencyUnavailable):
                    with self.store.read_meta():
                        self.fail("Reused socket bypassed disabled role/database admission")
            finally:
                with self.driver.connect(self.admin_dsn, autocommit=True) as admin:
                    admin.execute(self.sql.SQL(restore).format(self.sql.Identifier(identifier)))
            with self.store.read_meta() as db:
                self.assertNotEqual(self.pid(db), before)
        self.evidence.append({"case": "current_temp_role_and_database_admission"})

    def test_changed_role_settings_force_new_login_without_weakening_timeouts(self):
        self.enable()
        with self.store.read_meta() as db:
            before = self.pid(db)
        try:
            with self.driver.connect(self.admin_dsn, autocommit=True) as admin:
                admin.execute(self.sql.SQL("ALTER ROLE {} SET statement_timeout='1234ms'").format(self.sql.Identifier(self.role)))
            with self.store.read_meta() as db:
                self.assertNotEqual(self.pid(db), before)
                self.assertEqual(db.execute("SHOW statement_timeout").fetchone()[0], "15s")
        finally:
            with self.driver.connect(self.admin_dsn, autocommit=True) as admin:
                admin.execute(self.sql.SQL("ALTER ROLE {} RESET statement_timeout").format(self.sql.Identifier(self.role)))
        self.evidence.append({"case": "changed_role_settings_relogin_with_required_timeout"})

    @unittest.skipUnless(hasattr(os, "fork"), "Requires a real process fork")
    def test_child_process_cannot_borrow_parent_socket_and_parent_remains_healthy(self):
        self.enable()
        with self.store.read_meta() as db:
            before = self.pid(db)
        read_fd, write_fd = os.pipe()
        child = os.fork()
        if child == 0:
            os.close(read_fd)
            try:
                with self.store.read_meta():
                    result = b"BYPASS"
            except DependencyUnavailable:
                result = b"BLOCKED"
            except BaseException:
                result = b"ERROR"
            os.write(write_fd, result)
            os._exit(0)
        os.close(write_fd)
        try:
            ready, _, _ = select.select([read_fd], [], [], 3)
            if not ready:
                os.kill(child, signal.SIGKILL)
            self.assertTrue(ready, "Forked admission failed to terminate promptly")
            self.assertEqual(os.read(read_fd, 32), b"BLOCKED")
        finally:
            os.close(read_fd)
            os.waitpid(child, 0)
        with self.store.read_meta() as db:
            self.assertEqual(self.pid(db), before)
        self.evidence.append({"case": "real_fork_refuses_inherited_socket_parent_still_healthy"})


if __name__ == "__main__":
    unittest.main()
