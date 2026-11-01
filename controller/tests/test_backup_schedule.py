from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from zoneinfo import ZoneInfo

from controller import backup_schedule as schedule, maintenance
from controller.firewall import WorkflowConflict
from controller.store import Store, parse_time, stamp


class InjectedCrash(BaseException):
    pass


class BackupScheduleTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / "controller"
        self.store = Store(self.path)
        self.at = datetime(2026, 10, 30, 0, 0, tzinfo=timezone.utc)

    def save(self, **body):
        payload = {"expected_revision": schedule.get(self.store)["revision"], **body}
        with patch("controller.backup_schedule.now", return_value=self.at):
            return schedule.save(self.store, payload, "super_admin")

    def interval(self, retention=7):
        return self.save(enabled=True, frequency="interval", interval_hours=1, retention_count=retention)

    def available(self):
        return [record for record in maintenance.backup_listing(self.store) if record["available"]]

    def test_defaults_are_disabled_without_mutating_storage(self):
        value = schedule.get(self.store)
        self.assertEqual((value["enabled"], value["timezone"], value["revision"], value["next_run_at"]), (False, "Asia/Kolkata", 0, None))
        self.assertEqual(value["retention_scope"], "local_scheduled_archives")
        self.assertEqual(self.store.all("maintenance_settings"), [])
        self.assertFalse(schedule.run_due(self.store, self.at)["ran"])

    def test_revision_and_configuration_bounds_reject_invalid_updates(self):
        for body in ({"enabled": "true"}, {"time": "24:00"}, {"timezone": "No/SuchZone"}, {"weekday": 7}, {"weekday": True}, {"interval_hours": 169}, {"retention_count": 0}, {"retention_count": 366}, {"backup_path": "/tmp/private"}):
            with self.subTest(body=body), self.assertRaises(ValueError):
                self.save(**body)
        self.interval()
        with self.assertRaises(WorkflowConflict):
            schedule.save(self.store, {"expected_revision": 0, "enabled": False}, "super_admin")

    def test_daily_timezone_and_weekday_have_exact_utc_occurrences(self):
        daily = self.save(enabled=True, frequency="daily", time="09:15")
        self.assertEqual(daily["next_run_at"], "2026-10-30T03:45:00Z")
        weekly = self.save(frequency="weekly", weekday=0, time="09:15")
        self.assertEqual(weekly["next_run_at"], "2026-11-02T03:45:00Z")

    def test_retention_only_edit_preserves_the_due_slot(self):
        first = self.interval()
        self.at += timedelta(minutes=59)
        updated = self.save(retention_count=2)
        self.assertEqual(updated["next_run_at"], first["next_run_at"])

    def test_dst_gap_moves_to_first_valid_minute_and_fold_occurs_only_once(self):
        config = {**schedule.DEFAULTS, "timezone": "America/New_York", "time": "02:30"}
        before = datetime(2026, 3, 8, 0, 0, tzinfo=timezone.utc)
        self.assertEqual(schedule._next(config, before), datetime(2026, 3, 8, 7, 0, tzinfo=timezone.utc))
        config["time"] = "01:30"
        before = datetime(2026, 11, 1, 0, 0, tzinfo=timezone.utc)
        first = schedule._next(config, before)
        self.assertEqual(first, datetime(2026, 11, 1, 5, 30, tzinfo=timezone.utc))
        self.assertEqual(schedule._next(config, first), datetime(2026, 11, 2, 6, 30, tzinfo=timezone.utc))

    def test_actual_sqlite_due_backup_persists_and_is_not_repeated_after_restart(self):
        value = self.interval()
        due = parse_time(value["next_run_at"])
        self.assertFalse(schedule.run_due(self.store, due - timedelta(seconds=1))["ran"])
        result = schedule.run_due(self.store, due)
        self.assertEqual(result["status"], "complete")
        self.assertTrue(maintenance.backup_inspect(self.store, result["backup_id"])["verified"])
        self.store = Store(self.path)
        self.assertFalse(schedule.run_due(self.store, due)["ran"])
        self.assertEqual(len(self.available()), 1)
        state = schedule.get(self.store)
        self.assertEqual(state["last_success_at"], stamp(due))
        self.assertEqual(state["last_backup_id"], result["backup_id"])

    def test_missed_intervals_catch_up_once_without_drifting_the_interval(self):
        self.interval()
        at = self.at + timedelta(hours=9, minutes=25)
        result = schedule.run_due(self.store, at)
        self.assertEqual(result["status"], "complete")
        self.assertEqual(schedule.get(self.store)["next_run_at"], "2026-10-30T10:00:00Z")
        self.assertFalse(schedule.run_due(self.store, at)["ran"])
        self.assertEqual(len(self.available()), 1)

    def test_production_last_success_records_completion_time(self):
        self.interval()
        due = self.at + timedelta(hours=1)
        with patch("controller.backup_schedule.now", side_effect=[due, due + timedelta(seconds=5)]):
            self.assertEqual(schedule.run_due(self.store)["status"], "complete")
        state = schedule.get(self.store)
        self.assertEqual(state["last_run_at"], stamp(due))
        self.assertEqual(state["last_success_at"], stamp(due + timedelta(seconds=5)))

    def test_missed_daily_slots_do_not_create_a_backup_storm(self):
        self.save(enabled=True, frequency="daily", time="09:15")
        at = self.at + timedelta(days=14, hours=10)
        self.assertTrue(schedule.run_due(self.store, at)["ran"])
        self.assertFalse(schedule.run_due(self.store, at)["ran"])
        self.assertEqual(len(self.available()), 1)

    def test_concurrent_store_instances_make_one_archive_for_one_due_slot(self):
        self.interval()
        other = Store(self.path)
        due = self.at + timedelta(hours=1)
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda store: schedule.run_due(store, due), (self.store, other)))
        self.assertEqual(sum(result["ran"] for result in results), 1)
        self.assertEqual(len(self.available()), 1)

    def test_manual_backup_operation_defers_schedule_without_claiming_the_slot(self):
        value = self.interval()
        due = parse_time(value["next_run_at"])
        with maintenance.backup_operation_lock(self.store):
            self.assertEqual(schedule.run_due(self.store, due)["status"], "busy")
            with self.assertRaises(maintenance.BackupBusy):
                maintenance.backup_create(self.store, "super_admin")
        self.assertEqual(schedule.get(self.store)["next_run_at"], value["next_run_at"])
        self.assertIsNone(schedule.get(self.store)["last_run_at"])
        self.assertTrue(schedule.run_due(self.store, due)["ran"])

    def test_failure_records_safe_error_and_never_prunes_previous_backups(self):
        self.interval(retention=1)
        first = schedule.run_due(self.store, self.at + timedelta(hours=1))
        with patch("controller.maintenance._backup_create", side_effect=RuntimeError("dsn=password=private-never-public")):
            result = schedule.run_due(self.store, self.at + timedelta(hours=2))
        self.assertEqual(result["status"], "failed")
        self.assertNotIn("private-never-public", json.dumps(schedule.get(self.store)))
        self.assertEqual([value["id"] for value in self.available()], [first["backup_id"]])

    def test_retention_removes_only_verified_owned_scheduled_archives_after_success(self):
        manual = maintenance.backup_create(self.store, "super_admin")
        cleanup = maintenance.backup_create(self.store, "super_admin", "before-demo-clear")
        unowned = maintenance.backup_create(self.store, "super_admin", "scheduled")
        self.interval(retention=2)
        runs = [schedule.run_due(self.store, self.at + timedelta(hours=hour)) for hour in (1, 2, 3)]
        available = {value["id"] for value in self.available()}
        self.assertNotIn(runs[0]["backup_id"], available)
        self.assertTrue({manual["id"], cleanup["id"], unowned["id"], runs[1]["backup_id"], runs[2]["backup_id"]} <= available)
        self.assertEqual(self.store.get("maintenance_backups", runs[0]["backup_id"])["status"], "pruned")

    def test_midflight_disable_is_preserved_when_backup_finishes(self):
        self.interval()
        original = maintenance._backup_create
        def disable_after_snapshot(*args, **kwargs):
            result = original(*args, **kwargs)
            self.save(enabled=False)
            return result
        with patch("controller.maintenance._backup_create", side_effect=disable_after_snapshot):
            self.assertEqual(schedule.run_due(self.store, self.at + timedelta(hours=1))["status"], "complete")
        state = schedule.get(self.store)
        self.assertFalse(state["enabled"])
        self.assertIsNone(state["next_run_at"])
        self.assertIsNotNone(state["last_success_at"])

    def test_crash_after_archive_publication_recovers_the_same_slot_without_new_bytes(self):
        self.interval()
        original = maintenance._backup_create
        def crash(*args, **kwargs):
            original(*args, **kwargs)
            raise InjectedCrash()
        due = self.at + timedelta(hours=1)
        with patch("controller.maintenance._backup_create", side_effect=crash), self.assertRaises(InjectedCrash):
            schedule.run_due(self.store, due)
        archives = list((self.path / "backups").glob("*.zip"))
        self.assertEqual(len(archives), 1)
        old_bytes = archives[0].read_bytes()
        self.store = Store(self.path)
        self.assertFalse(schedule.run_due(self.store, due + timedelta(seconds=30))["ran"])
        self.assertEqual(archives[0].read_bytes(), old_bytes)
        self.assertEqual(len(self.available()), 1)
        self.assertEqual(schedule.get(self.store)["last_status"], "complete")

    def test_crash_before_index_commit_adopts_verified_manifest_without_recreating_archive(self):
        self.interval()
        original = maintenance._backup_create
        def orphan(*args, **kwargs):
            result = original(*args, **kwargs)
            with self.store.meta() as db:
                db.execute("DELETE FROM maintenance_backups WHERE id=?", (result["id"],))
            raise InjectedCrash()
        due = self.at + timedelta(hours=1)
        with patch("controller.maintenance._backup_create", side_effect=orphan), self.assertRaises(InjectedCrash):
            schedule.run_due(self.store, due)
        archive = list((self.path / "backups").glob("*.zip"))[0]
        old_bytes = archive.read_bytes()
        self.store = Store(self.path)
        self.assertFalse(schedule.run_due(self.store, due + timedelta(seconds=30))["ran"])
        self.assertEqual(archive.read_bytes(), old_bytes)
        self.assertEqual(len(self.available()), 1)
        self.assertTrue(any(item["action"] == "maintenance.scheduled_backup_recovered" for item in self.store.all("audit")))


if __name__ == "__main__":
    unittest.main()
