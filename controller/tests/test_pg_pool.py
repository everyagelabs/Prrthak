from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
import threading
import time
import unittest
from unittest.mock import patch

from controller.pg_pool import WorkerPool, PoolUnavailable


class WorkerConnectionPoolTests(unittest.TestCase):
    def setUp(self):
        self.connections = []
        def factory():
            connection = SimpleNamespace(closed=False, broken=False, info=SimpleNamespace(transaction_status=0), identifier=len(self.connections))
            connection.close = lambda: setattr(connection, "closed", True)
            self.connections.append(connection)
            return connection
        self.pool = WorkerPool(factory, 2, .1, lambda entry: None)
        self.addCleanup(self.pool.close)

    def test_threads_never_share_a_lease_and_physical_connections_remain_bounded(self):
        active, lock = set(), threading.Lock()
        def operation(_):
            with self.pool.connection() as connection:
                with lock:
                    self.assertNotIn(connection.identifier, active); active.add(connection.identifier)
                time.sleep(.002)
                with lock:
                    active.remove(connection.identifier)
        with ThreadPoolExecutor(max_workers=8) as executor:
            list(executor.map(operation, range(40)))
        self.assertEqual(active, set())
        self.assertLessEqual(len(self.connections), 2)

    def test_saturation_is_bounded_and_releasing_a_lease_restores_capacity(self):
        self.pool.maximum = 1
        with self.pool.connection():
            with self.assertRaisesRegex(PoolUnavailable, "busy"):
                with self.pool.connection():
                    self.fail("A saturated pool granted another lease")
        with self.pool.connection():
            pass
        self.assertEqual(len(self.connections), 1)

    def test_broken_or_nonidle_connections_never_return_to_another_request(self):
        for field in ("broken", "transaction_status"):
            with self.pool.connection() as connection:
                if field == "broken": connection.broken = True
                else: connection.info.transaction_status = 3
            self.assertTrue(connection.closed)
        with self.pool.connection() as healthy:
            self.assertFalse(healthy.closed)

    def test_expired_socket_and_changed_admission_are_replaced_before_borrow(self):
        with self.pool.connection() as first:
            pass
        self.pool.idle[0].created_at -= 61
        with self.pool.connection() as second:
            self.assertNotEqual(first.identifier, second.identifier)
        rejected = second.identifier
        def current(entry):
            if entry.connection.identifier == rejected:
                raise RuntimeError("Role settings/primary changed")
        self.pool.validate = current
        with self.pool.connection() as third:
            self.assertNotEqual(third.identifier, rejected)
        self.assertTrue(first.closed and second.closed)

    def test_sockets_are_not_leased_across_processes_and_stop_closes_idle(self):
        with self.pool.connection() as connection:
            pass
        with patch("controller.pg_pool.os.getpid", return_value=self.pool.pid + 1):
            with self.assertRaisesRegex(PoolUnavailable, "another process"):
                with self.pool.connection(): pass
        self.pool.close()
        self.assertTrue(connection.closed)
        with self.assertRaisesRegex(PoolUnavailable, "stopping"):
            with self.pool.connection(): pass

    def test_constructor_and_injected_connectors_never_enable_pre_fork_pooling(self):
        from controller.postgres import PostgresStore
        from controller.tests.test_postgres import FakeDriver
        store = PostgresStore("metadata", "traffic", connector=FakeDriver(), initialize=False)
        self.assertIsNone(store._worker_pools)
        store.enable_worker_pool()
        self.assertIsNone(store._worker_pools)
