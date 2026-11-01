import json
import tempfile
import unittest
from email.message import Message
from unittest.mock import patch

from controller.app import App, handler_for
from controller.postgres import Connection, DependencyUnavailable, PostgresStore, Row, postgres_sql
from controller.store import Store


class FakeCursor:
    def __init__(self, rows=(), names=("result",)):
        self.rows = list(rows)
        self.description = [(name,) for name in names]

    def fetchone(self):
        return self.rows.pop(0) if self.rows else None

    def fetchall(self):
        result, self.rows = self.rows, []
        return result


class FakeDriver:
    def __init__(self):
        self.connections = []
        self.held_jobs = set()
        self.down = set()

    def __call__(self, dsn, **kwargs):
        if dsn in self.down:
            raise ConnectionError("private-password-must-not-appear")
        connection = FakeConnection(self, dsn, kwargs)
        self.connections.append(connection)
        return connection


class FakeConnection:
    def __init__(self, driver, dsn, options):
        self.driver, self.dsn, self.options = driver, dsn, options
        self.events = []
        self.closed = False
        self.jobs = set()

    def __enter__(self):
        self.events.append(("begin", ()))
        return self

    def __exit__(self, kind, value, traceback):
        self.events.append(("rollback" if kind else "commit", ()))

    def execute(self, query, parameters=()):
        self.events.append((query, parameters))
        if "pg_try_advisory_lock" in query:
            key = parameters[0]
            if key in self.driver.held_jobs:
                return FakeCursor([(False,)])
            self.driver.held_jobs.add(key)
            self.jobs.add(key)
            return FakeCursor([(True,)])
        if "pg_advisory_unlock" in query:
            self.driver.held_jobs.discard(parameters[0])
            self.jobs.discard(parameters[0])
            return FakeCursor([(True,)])
        return FakeCursor()

    def close(self):
        self.events.append(("close", ()))
        for key in self.jobs:
            self.driver.held_jobs.discard(key)
        self.jobs.clear()
        self.closed = True


class SQLAdapterTests(unittest.TestCase):
    def test_parameters_are_translated_without_interpolating_values_or_quoted_question_marks(self):
        sql = "SELECT '?' AS literal, data FROM servers WHERE id=? AND data <> 'it''s ?'"
        self.assertEqual(postgres_sql(sql), "SELECT '?' AS literal, data FROM servers WHERE id=%s AND data <> 'it''s ?'")
        driver = FakeDriver()
        raw = driver("metadata")
        Connection(raw).execute("SELECT data FROM servers WHERE id=?", ("name'); DROP TABLE servers; --",))
        query, values = raw.events[-1]
        self.assertEqual(query, "SELECT data FROM servers WHERE id=%s")
        self.assertEqual(values, ("name'); DROP TABLE servers; --",))
        self.assertNotIn("DROP", query)

    def test_sqlite_idempotent_insert_maps_to_postgres_conflict_clause(self):
        self.assertEqual(postgres_sql("INSERT OR IGNORE INTO flows(batch_key) VALUES(?);"), "INSERT INTO flows(batch_key) VALUES(%s) ON CONFLICT DO NOTHING")
        row = Row(["server_id", "count"], ["endpoint", 3])
        self.assertEqual(row[0], "endpoint")
        self.assertEqual(row["count"], 3)
        self.assertEqual(dict(row), {"server_id": "endpoint", "count": 3})

    def test_shared_schema_has_bigserial_and_no_sqlite_or_local_paths(self):
        driver = FakeDriver()
        store = PostgresStore("metadata", "traffic", connector=driver)
        queries = [query for connection in driver.connections for query, _ in connection.events]
        self.assertTrue(any("BIGSERIAL PRIMARY KEY" in query for query in queries))
        self.assertTrue(any("controller_nodes" in query for query in queries))
        self.assertFalse(any("PRAGMA" in query for query in queries))
        self.assertFalse(hasattr(store, "meta_path"))
        self.assertTrue(store.ha)

    def test_missing_either_shared_dsn_is_rejected(self):
        for metadata, traffic in (("", "traffic"), ("metadata", "")):
            with self.assertRaises(ValueError):
                PostgresStore(metadata, traffic, connector=FakeDriver())


class SharedTransactionTests(unittest.TestCase):
    def setUp(self):
        self.driver = FakeDriver()
        self.store = PostgresStore("metadata", "traffic", connector=self.driver, initialize=False)

    def test_metadata_lock_covers_the_entire_read_modify_write_transaction(self):
        with self.store.meta() as db:
            db.execute("SELECT data FROM servers WHERE id=?", ("host",))
            db.execute("UPDATE servers SET data=? WHERE id=?", ("{}", "host"))
            raw = self.driver.connections[-1]
            self.assertFalse(raw.closed)
            self.assertFalse(any(query == "commit" for query, _ in raw.events))
        events = raw.events
        lock_index = next(index for index, (query, _) in enumerate(events) if "pg_advisory_xact_lock" in query)
        read_index = next(index for index, (query, _) in enumerate(events) if "SELECT data" in query)
        write_index = next(index for index, (query, _) in enumerate(events) if "UPDATE servers" in query)
        commit_index = next(index for index, (query, _) in enumerate(events) if query == "commit")
        self.assertLess(lock_index, read_index)
        self.assertLess(read_index, write_index)
        self.assertLess(write_index, commit_index)
        self.assertEqual(events[lock_index][1], (self.store.META_LOCK,))
        self.assertTrue(raw.closed)

    def test_read_only_snapshot_does_not_take_exclusive_metadata_advisory_lock(self):
        with self.store.read_meta() as db:
            db.execute("SELECT data FROM servers WHERE id=?", ("host",))
        queries = [query for query, _ in self.driver.connections[-1].events]
        self.assertTrue(any("REPEATABLE READ READ ONLY" in query for query in queries))
        self.assertFalse(any("pg_advisory_xact_lock" in query for query in queries))

    def test_traffic_uses_distinct_lock_and_rolls_back_on_callback_failure(self):
        with self.assertRaises(ValueError):
            with self.store.traffic() as db:
                db.execute("UPDATE batches SET processed=1 WHERE batch_key=?", ("batch",))
                raise ValueError("abort")
        raw = self.driver.connections[-1]
        self.assertIn(("SELECT pg_advisory_xact_lock(%s)", (self.store.TRAFFIC_LOCK,)), raw.events)
        self.assertTrue(any(query == "rollback" for query, _ in raw.events))
        self.assertTrue(raw.closed)

    def test_job_leadership_connection_stays_open_until_callback_finishes(self):
        other = PostgresStore("metadata", "traffic", connector=self.driver, initialize=False)
        calls = []
        def job():
            raw = self.driver.connections[-1]
            self.assertFalse(raw.closed)
            self.assertIn(self.store.JOB_KEYS["health"], self.driver.held_jobs)
            self.assertIsNone(other.run_job("health", lambda: calls.append("second leader")))
            calls.append("first leader")
            return 7
        self.assertEqual(self.store.run_job("health", job), 7)
        self.assertEqual(calls, ["first leader"])
        self.assertNotIn(self.store.JOB_KEYS["health"], self.driver.held_jobs)
        self.assertEqual(other.run_job("health", lambda: 8), 8)

    def test_job_failure_releases_session_lock_for_another_node(self):
        def fail():
            raise ValueError("job failed")
        with self.assertRaises(ValueError):
            self.store.run_job("traffic", fail)
        self.assertEqual(self.store.run_job("traffic", lambda: "recovered"), "recovered")

    def test_dependency_failure_has_no_secret_and_never_uses_local_state(self):
        self.driver.down.add("metadata")
        with self.assertRaises(DependencyUnavailable) as caught:
            with self.store.meta():
                pass
        self.assertNotIn("private-password", str(caught.exception))
        self.assertTrue(caught.exception.__suppress_context__)
        self.assertEqual(self.store.readiness(), {"metadata": False, "traffic": True})
        self.assertFalse(hasattr(self.store, "meta_path"))


class ReadinessTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = Store(self.temp.name)
        self.app = App(self.store, tokens={"viewer": "reader"}, controller_id="ctrl-a", site="dc1")

    def request(self, path, token=None):
        handler = object.__new__(handler_for(self.app))
        handler.command, handler.path = "GET", path
        handler.connection = object()
        handler.client_address = ("127.0.0.1", 12345)
        handler.headers = Message()
        if token:
            handler.headers["Authorization"] = "Bearer " + token
        captured = {}
        handler.response = lambda status, value=None, headers=None: captured.update(status=status, value=value)
        handler.dispatch()
        return captured

    def test_readiness_is_public_dependency_based_and_liveness_stays_independent(self):
        self.assertEqual(self.request("/readyz")["status"], 200)
        with patch.object(self.store, "readiness", return_value={"metadata": True, "traffic": False}):
            response = self.request("/readyz")
            self.assertEqual(response["status"], 503)
            self.assertEqual(response["value"]["checks"], {"metadata": True, "traffic": False, "provider_authority": True})
            self.assertEqual(self.request("/healthz")["status"], 200)
        with patch.object(self.store, "readiness", side_effect=ConnectionError("password-secret")):
            response = self.request("/readyz")
            self.assertEqual(response["status"], 503)
            self.assertNotIn("password-secret", json.dumps(response))

    def test_cluster_requires_auth_and_local_mode_is_explicit(self):
        self.assertEqual(self.request("/api/v1/cluster")["status"], 401)
        response = self.request("/api/v1/cluster", "reader")
        self.assertEqual(response["status"], 200)
        self.assertEqual(response["value"]["mode"], "standalone")
        self.assertEqual(response["value"]["nodes"][0]["id"], "ctrl-a")
        self.assertEqual(response["value"]["nodes"][0]["site"], "dc1")
        self.assertFalse(response["value"]["ha"])

    def test_ha_cannot_use_demo_and_canonical_site_wins_alias(self):
        shared = PostgresStore("metadata", "traffic", connector=FakeDriver(), initialize=False)
        with self.assertRaises(ValueError):
            App(shared, demo=True)
        with patch.dict("os.environ", {"SEG_SITE": "dr", "SEG_CONTROLLER_SITE": "dc"}):
            self.assertEqual(App(self.store).site, "dc")
        with patch.dict("os.environ", {"SEG_SITE": "dr", "SEG_CONTROLLER_SITE": ""}):
            self.assertEqual(App(self.store).site, "dr")


if __name__ == "__main__":
    unittest.main()
