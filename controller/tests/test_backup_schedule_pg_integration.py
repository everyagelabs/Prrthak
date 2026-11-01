"""Opt-in real shared-PG scheduler tests; only literal dedicated test DBs."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from controller.tests import private_pg as pg_fixture

import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from controller import backup_schedule as schedule, maintenance
from controller.postgres import PostgresStore


ROOT = Path(__file__).resolve().parents[2]
NAMES = pg_fixture.names("schedule")


class Crash(BaseException):
    pass


@unittest.skipUnless(os.environ.get("PRTHAK_SCHEDULE_PG_ACCEPTANCE") == "1", "Opt in to private PostgreSQL scheduler acceptance")
class SchedulerPostgresTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import psycopg
        from psycopg import sql
        from psycopg.conninfo import make_conninfo
        cls.driver, cls.sql = psycopg, sql
        params = pg_fixture.parameters()
        with psycopg.connect(**params, dbname="postgres", autocommit=True) as db:
            user, path = db.execute("SELECT current_user,current_setting('data_directory')").fetchone()
            if user != "prthak_test" or Path(path).resolve() != pg_fixture.data_directory():
                raise RuntimeError("Only the prepared private test cluster is allowed")
            for name in NAMES.values():
                if db.execute("SELECT 1 FROM pg_database WHERE datname=%s", (name,)).fetchone():
                    raise RuntimeError("Refusing to reuse a pre-existing private fixture database")
                db.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(name)))
        cls.dsns = {key: make_conninfo(**params, dbname=name) for key, name in NAMES.items()}

    def reset(self):
        for key, dsn in self.dsns.items():
            with self.driver.connect(dsn, autocommit=True) as db:
                self.assertEqual(db.execute("SELECT current_database()").fetchone()[0], NAMES[key])
                db.execute("DROP SCHEMA public CASCADE")
                db.execute("CREATE SCHEMA public")

    def setUp(self):
        self.reset()
        self.addCleanup(self.reset)
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.path = Path(temp.name)
        self.a, self.b = (PostgresStore(self.dsns["metadata"], self.dsns["traffic"]) for _ in range(2))
        self.a.backup_dir, self.b.backup_dir = self.path / "a", self.path / "b"
        self.at = datetime(2026, 10, 30, 0, 0, tzinfo=timezone.utc)
        with patch("controller.backup_schedule.now", return_value=self.at):
            schedule.save(self.a, {"expected_revision": 0, "enabled": True, "frequency": "interval", "interval_hours": 1, "retention_count": 1}, "super_admin")

    def test_actual_two_node_leader_dedup_and_controller_local_retention(self):
        due = self.at + timedelta(hours=1)
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda store: schedule.run_due(store, due), (self.a, self.b)))
        self.assertEqual(sum(result["ran"] for result in results), 1)
        self.assertEqual(len(self.a.all("maintenance_backups")), 1)
        first = self.a.all("maintenance_backups")[0]
        first_owner, other = (self.a, self.b) if list(self.a.backup_dir.glob("*.zip")) else (self.b, self.a)
        with self.a._connect("metadata", autocommit=True) as leader:
            leader.execute("SELECT pg_advisory_lock(%s)", (self.a.JOB_KEYS["backup"],))
            try:
                self.assertEqual(schedule.run_due(other, due + timedelta(hours=1))["status"], "peer_running")
            finally:
                leader.execute("SELECT pg_advisory_unlock(%s)", (self.a.JOB_KEYS["backup"],))
        second = schedule.run_due(other, due + timedelta(hours=1))
        third = schedule.run_due(other, due + timedelta(hours=2))
        self.assertEqual((second["status"], third["status"]), ("complete", "complete"))
        self.assertTrue((first_owner.backup_dir / (first["id"] + ".zip")).exists())
        self.assertFalse((other.backup_dir / (second["backup_id"] + ".zip")).exists())
        self.assertTrue(maintenance.backup_inspect(other, third["backup_id"])["verified"])
        self.assertEqual(self.a.get("maintenance_backups", second["backup_id"])["status"], "pruned")
        self.assertFalse(schedule.run_due(first_owner, due + timedelta(hours=2))["ran"])

    def test_real_pg_crash_orphan_is_not_replayed_by_peer_and_owner_recovers_exact_bytes(self):
        original = maintenance._backup_create
        def orphan(*args, **kwargs):
            result = original(*args, **kwargs)
            with self.a.meta() as db:
                db.execute("DELETE FROM maintenance_backups WHERE id=?", (result["id"],))
            raise Crash()
        due = self.at + timedelta(hours=1)
        with patch("controller.maintenance._backup_create", side_effect=orphan), self.assertRaises(Crash):
            schedule.run_due(self.a, due)
        archive = list(self.a.backup_dir.glob("*.zip"))[0]
        content = archive.read_bytes()
        self.assertFalse(schedule.run_due(self.b, due + timedelta(seconds=30))["ran"])
        self.assertEqual(list(self.b.backup_dir.glob("*.zip")), [])
        restarted = PostgresStore(self.dsns["metadata"], self.dsns["traffic"])
        restarted.backup_dir = self.a.backup_dir
        self.assertFalse(schedule.run_due(restarted, due + timedelta(seconds=60))["ran"])
        self.assertEqual(archive.read_bytes(), content)
        self.assertEqual(len(restarted.all("maintenance_backups")), 1)
        self.assertEqual(schedule.get(self.b)["last_status"], "complete")
        self.assertTrue(maintenance.backup_inspect(restarted, archive.stem)["verified"])


if __name__ == "__main__":
    unittest.main()
