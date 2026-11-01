"""Owned-role/owned-database live PG acceptance; no shared fixture resets."""
from controller.tests import private_pg as pg_fixture

import json
import os
from pathlib import Path
import unittest
import uuid

from controller.postgres import PostgresStore, DependencyUnavailable

ROOT = Path(__file__).resolve().parents[2]


@unittest.skipUnless(os.environ.get("PRTHAK_PLATFORM_PG_ACCEPTANCE") == "1", "Private PostgreSQL owner opt-in")
class LiveWorkerPoolTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import psycopg
        from psycopg import sql
        from psycopg.conninfo import make_conninfo
        cls.driver, cls.sql = psycopg, sql
        cls.parameters = pg_fixture.parameters()
        suffix = uuid.uuid4().hex[:12]
        cls.role = "prthak_test_pool_" + suffix
        cls.names = {name: cls.role + "_" + name for name in ("metadata", "traffic")}
        cls.admin = make_conninfo(**cls.parameters, dbname="postgres")
        with psycopg.connect(cls.admin, autocommit=True) as db:
            cls.verify(db)
            db.execute(sql.SQL("CREATE ROLE {} LOGIN").format(sql.Identifier(cls.role)))
            for name in cls.names.values(): db.execute(sql.SQL("CREATE DATABASE {} OWNER {}").format(sql.Identifier(name), sql.Identifier(cls.role)))
        cls.dsns = {key: make_conninfo(**{**cls.parameters, "user": cls.role}, dbname=name) for key, name in cls.names.items()}
        cls.addClassCleanup(cls.cleanup)

    @classmethod
    def verify(cls, db):
        row = db.execute("SELECT current_user,current_database(),current_setting('data_directory')").fetchone()
        if row[0] != "prthak_test" or row[1] != "postgres" or Path(row[2]).resolve() != pg_fixture.data_directory():
            raise RuntimeError("Only the prepared private cluster is allowed")

    @classmethod
    def cleanup(cls):
        with cls.driver.connect(cls.admin, autocommit=True) as db:
            cls.verify(db)
            for name in cls.names.values(): db.execute(cls.sql.SQL("DROP DATABASE {}").format(cls.sql.Identifier(name)))
            db.execute(cls.sql.SQL("DROP ROLE {}").format(cls.sql.Identifier(cls.role)))

    def setUp(self):
        with self.driver.connect(self.admin, autocommit=True) as db:
            self.verify(db)
            db.execute(self.sql.SQL("ALTER ROLE {} LOGIN").format(self.sql.Identifier(self.role)))
            db.execute(self.sql.SQL("ALTER ROLE {} RESET ALL").format(self.sql.Identifier(self.role)))
            for name in self.names.values(): db.execute(self.sql.SQL("ALTER DATABASE {} ALLOW_CONNECTIONS true").format(self.sql.Identifier(name)))
        for dsn in self.dsns.values():
            with self.driver.connect(dsn, autocommit=True) as db:
                db.execute("DROP SCHEMA public CASCADE"); db.execute("CREATE SCHEMA public")
        self.store = PostgresStore(self.dsns["metadata"], self.dsns["traffic"])
        self.store.enable_worker_pool(2, 1, 1)
        self.addCleanup(self.store.close_worker_pool)

    def pid(self):
        with self.store.read_meta() as db:
            return db.execute("SELECT pg_backend_pid()").fetchone()[0]

    def test_reuse_has_fresh_snapshots_and_exception_rollback(self):
        first = self.pid()
        with self.store._borrow("metadata") as (connection, pooled):
            self.assertTrue(pooled)
            for name, expected in (("statement_timeout", "15s"), ("lock_timeout", "5s"), ("idle_in_transaction_session_timeout", "30s")):
                self.assertEqual(connection.execute("SELECT current_setting(%s)", (name,)).fetchone()[0], expected)
            self.assertEqual(int(connection.info.transaction_status), 0)
        with self.assertRaisesRegex(ValueError, "rollback"):
            with self.store.meta() as db:
                self.store._put(db, "groups", {"id": "must-rollback"})
                raise ValueError("rollback")
        self.assertEqual(self.pid(), first)
        with self.store._borrow("metadata") as (connection, _):
            self.assertEqual(int(connection.info.transaction_status), 0)
            self.assertEqual(connection.execute("SHOW statement_timeout").fetchone()[0], "15s")
        with self.store.read_meta() as db:
            self.assertIsNone(self.store._get(db, "groups", "must-rollback"))
        with self.driver.connect(self.dsns["metadata"], autocommit=True) as db:
            db.execute("INSERT INTO groups(id,data) VALUES(%s,%s)", ("fresh", json.dumps({"id": "fresh", "name": "new committed snapshot"})))
        with self.store.read_meta() as db:
            self.assertEqual(self.store._get(db, "groups", "fresh")["name"], "new committed snapshot")
            self.assertEqual(db.execute("SHOW transaction_read_only").fetchone()[0], "on")
        with self.store.meta() as db:
            self.assertEqual(db.execute("SHOW transaction_read_only").fetchone()[0], "off")
            self.assertEqual(db.execute("SHOW synchronous_commit").fetchone()[0], "on")

    def test_changed_role_settings_reconnect_and_nologin_cannot_reuse_authenticated_socket(self):
        first = self.pid()
        with self.driver.connect(self.admin, autocommit=True) as db:
            db.execute(self.sql.SQL("ALTER ROLE {} SET statement_timeout='2s'").format(self.sql.Identifier(self.role)))
        self.assertNotEqual(self.pid(), first)
        with self.driver.connect(self.admin, autocommit=True) as db:
            db.execute(self.sql.SQL("ALTER ROLE {} NOLOGIN").format(self.sql.Identifier(self.role)))
        with self.assertRaises(DependencyUnavailable): self.pid()
        with self.driver.connect(self.admin, autocommit=True) as db:
            db.execute(self.sql.SQL("ALTER ROLE {} LOGIN").format(self.sql.Identifier(self.role)))
        self.assertIsInstance(self.pid(), int)

    def test_disabled_database_and_readonly_role_refuse_reused_connections(self):
        self.pid()
        with self.driver.connect(self.admin, autocommit=True) as db:
            db.execute(self.sql.SQL("ALTER DATABASE {} ALLOW_CONNECTIONS false").format(self.sql.Identifier(self.names["metadata"])))
        with self.assertRaises(DependencyUnavailable): self.pid()
        with self.driver.connect(self.admin, autocommit=True) as db:
            db.execute(self.sql.SQL("ALTER DATABASE {} ALLOW_CONNECTIONS true").format(self.sql.Identifier(self.names["metadata"])))
        self.pid()
        with self.driver.connect(self.admin, autocommit=True) as db:
            db.execute(self.sql.SQL("ALTER ROLE {} SET default_transaction_read_only=on").format(self.sql.Identifier(self.role)))
        with self.assertRaises(DependencyUnavailable): self.pid()

    def test_same_socket_cannot_read_a_fenced_epoch(self):
        marker = {"id": "active", "state": "READY", "namespace": "metadata", "deployment_id": str(uuid.uuid4()), "epoch": 7, "import_id": "private-import", "source_fingerprint": "f" * 64}
        with self.store.meta() as db: self.store._put(db, "runtime_deployment", marker)
        self.store.expected_deployment_id = marker["deployment_id"]
        self.store.expected_deployment_epoch = marker["epoch"]
        self.store._expected_import_id = marker["import_id"]
        self.store._expected_source_fingerprint = marker["source_fingerprint"]
        self.pid()
        with self.driver.connect(self.dsns["metadata"], autocommit=True) as db:
            db.execute("UPDATE runtime_deployment SET data=%s WHERE id='active'", (json.dumps({**marker, "state": "FENCED"}),))
        with self.assertRaisesRegex(DependencyUnavailable, "exact ready identity/epoch"):
            self.pid()
