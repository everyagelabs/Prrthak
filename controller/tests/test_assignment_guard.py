import tempfile
import threading
import unittest
from unittest.mock import patch

from controller.store import Store, digest, now, stamp
from datetime import timedelta


class AssignmentGuardTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.store = Store(self.temporary.name)
        self.store.report("endpoint", {"hostname": "endpoint", "ips": ["10.20.0.8"], "listeners": [], "firewalld_state": "running"})

    def test_complete_auxiliary_changes_advance_stable_generation_across_restart(self):
        original, etag = self.store.assignment("endpoint")
        self.assertEqual(original["assignment_generation"], 1)
        self.assertEqual(original["assignment_digest"], digest({key: value for key, value in original.items() if key not in ("assignment_generation", "assignment_digest")}))
        with patch.object(self.store, "meta", side_effect=AssertionError("unchanged poll wrote metadata")):
            self.assertEqual(self.store.assignment("endpoint"), (original, etag))
        session = {"id": "session-replay-123", "server_ids": ["endpoint"], "ports": [{"port": 443, "protocol": "tcp"}], "status": "active", "starts_at": stamp(now() - timedelta(minutes=1)), "expires_at": stamp(now() + timedelta(hours=1)), "selection_mode": "manual", "policy_action": "observe"}
        with self.store.meta() as db:
            self.store._put(db, "sessions", session)
        active, _ = self.store.assignment("endpoint")
        self.assertGreater(active["assignment_generation"], original["assignment_generation"])
        self.store.stop_session(session["id"], "admin")
        stopped, _ = self.store.assignment("endpoint")
        self.assertEqual(stopped["version"], original["version"])
        self.assertGreater(stopped["assignment_generation"], active["assignment_generation"])
        self.assertNotEqual(stopped["assignment_digest"], active["assignment_digest"])
        restarted = Store(self.temporary.name)
        self.assertEqual(restarted.assignment("endpoint")[0], stopped)

    def test_two_store_writers_publish_one_generation_for_same_content(self):
        peer = Store(self.temporary.name)
        gate = threading.Barrier(2)
        outputs, errors = [], []

        def poll(store):
            try:
                gate.wait(timeout=5)
                outputs.append(store.assignment("endpoint")[0])
            except Exception as error:
                errors.append(error)

        workers = [threading.Thread(target=poll, args=(store,)) for store in (self.store, peer)]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(timeout=10)
            self.assertFalse(worker.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(len(outputs), 2)
        self.assertEqual(outputs[0]["assignment_generation"], 1)
        self.assertEqual(outputs[0], outputs[1])

    def test_stale_reader_cannot_publish_old_active_session_with_newer_generation(self):
        session = {"id": "session-race-123", "server_ids": ["endpoint"], "ports": [{"port": 443, "protocol": "tcp"}], "status": "active", "starts_at": stamp(now() - timedelta(minutes=1)), "expires_at": stamp(now() + timedelta(hours=1)), "selection_mode": "manual", "policy_action": "observe"}
        with self.store.meta() as db:
            self.store._put(db, "sessions", session)
        initial = self.store.assignment("endpoint")[0]
        peer = Store(self.temporary.name)
        assembled, release = threading.Event(), threading.Event()
        original = peer._assignment_value
        outputs, errors = [], []
        paused = []

        def stale(identifier, db):
            result = original(identifier, db)
            if not paused:
                paused.append(True)
                assembled.set()
                if not release.wait(timeout=5):
                    raise AssertionError("stale reader was not released")
            return result

        def poll():
            try:
                outputs.append(peer.assignment("endpoint")[0])
            except Exception as error:
                errors.append(error)

        with patch.object(peer, "_assignment_value", side_effect=stale):
            worker = threading.Thread(target=poll)
            worker.start()
            self.assertTrue(assembled.wait(timeout=5))
            self.store.stop_session(session["id"], "admin")
            stopped = self.store.assignment("endpoint")[0]
            release.set()
            worker.join(timeout=10)
            self.assertFalse(worker.is_alive())
        self.assertEqual(errors, [])
        self.assertGreater(stopped["assignment_generation"], initial["assignment_generation"])
        self.assertEqual(outputs, [stopped])


if __name__ == "__main__":
    unittest.main()
