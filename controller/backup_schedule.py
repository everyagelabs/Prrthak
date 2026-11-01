"""Durable product backup schedules; never an external task/cron automation.

PostgreSQL uses one session-locked leader and a durable due-slot ledger. Local
file locks also exclude manual/cleanup backups. Interrupted slots are never
re-executed blindly on another controller's private backup storage.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import re
import time
import uuid
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from . import maintenance
from .firewall import WorkflowConflict
from .platform_runtime import atomic_private_json
from .store import digest, now, parse_time, stamp

CONFIG_ID = "backup_schedule"
RUN_PREFIX = "backup_schedule_run:"
KIND = "prthak-backup-schedule-v1"
DEFAULTS = {"enabled": False, "frequency": "daily", "time": "02:00", "timezone": "Asia/Kolkata", "weekday": 0, "interval_hours": 24, "retention_count": 7, "revision": 0, "next_run_at": None, "last_run_at": None, "last_success_at": None, "last_error": "", "last_status": "never", "last_backup_id": None, "active_run": None}
FIELDS = ("enabled", "frequency", "time", "timezone", "weekday", "interval_hours", "retention_count")


def _at(value=None):
    value = now() if value is None else value
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ValueError("An aware scheduler timestamp is required")
    return value.astimezone(timezone.utc).replace(microsecond=0)


def _read(store, db):
    return {**DEFAULTS, **(store._get(db, "maintenance_settings", CONFIG_ID) or {}), "id": CONFIG_ID}


def _public(value):
    keys = FIELDS + ("revision", "next_run_at", "last_run_at", "last_success_at", "last_error", "last_status", "last_backup_id", "updated_at", "updated_by", "last_storage_id", "retention_error")
    result = {key: value.get(key) for key in keys}
    result.update(running=bool(value.get("active_run")), storage_scope="controller_local", retention_scope="local_scheduled_archives", weekday_convention="Monday=0; Sunday=6", dst_policy="Repeated times run once at the first occurrence; skipped times run at the first valid minute afterward", missed_run_policy="One most-recent due slot is caught up; interrupted attempts are recorded and never blindly replayed")
    return result


def get(store):
    with store.read_meta() as db:
        return _public(_read(store, db))


def _validate(body, previous):
    if not isinstance(body, dict) or set(body) - set(FIELDS) - {"expected_revision"}:
        raise ValueError("Provide only the supported backup schedule configuration")
    value = {key: body.get(key, previous[key]) for key in FIELDS}
    if not isinstance(value["enabled"], bool) or value["frequency"] not in ("daily", "weekly", "interval"):
        raise ValueError("Choose enabled true/false and daily, weekly or interval frequency")
    if not isinstance(value["time"], str) or not re.fullmatch(r"(?:[01]\d|2[0-3]):[0-5]\d", value["time"]):
        raise ValueError("Backup time must use HH:MM in the selected timezone")
    if not isinstance(value["timezone"], str) or len(value["timezone"]) > 100:
        raise ValueError("Choose a valid IANA timezone")
    try:
        ZoneInfo(value["timezone"])
    except (ZoneInfoNotFoundError, ValueError):
        raise ValueError("Choose an installed IANA timezone") from None
    for key, minimum, maximum in (("weekday", 0, 6), ("interval_hours", 1, 168), ("retention_count", 1, 365)):
        item = value[key]
        if isinstance(item, bool) or not isinstance(item, int) or not minimum <= item <= maximum:
            raise ValueError(f"{key} must be an integer from {minimum} to {maximum}")
    return value


def _wall(date, clock, zone):
    hour, minute = map(int, clock.split(":"))
    naive = datetime(date.year, date.month, date.day, hour, minute)
    # Bounded handling also covers a jurisdiction skipping an entire date.
    for offset in range(1441):
        candidate = naive + timedelta(minutes=offset)
        valid = []
        for fold in (0, 1):
            instant = candidate.replace(tzinfo=zone, fold=fold).astimezone(timezone.utc)
            if instant.astimezone(zone).replace(tzinfo=None) == candidate:
                valid.append(instant)
        if valid:
            return min(valid)
    raise ValueError("Timezone has no supported occurrence for the selected schedule")


def _next(value, after):
    if value["frequency"] == "interval":
        return after + timedelta(hours=value["interval_hours"])
    zone = ZoneInfo(value["timezone"])
    date = after.astimezone(zone).date()
    for offset in range(9):
        day = date + timedelta(days=offset)
        if value["frequency"] == "weekly" and day.weekday() != value["weekday"]:
            continue
        candidate = _wall(day, value["time"], zone)
        if candidate > after:
            return candidate
    raise ValueError("No next scheduled occurrence was found")


def _latest_due(value, at):
    first = parse_time(value["next_run_at"])
    if first > at:
        return None
    if value["frequency"] == "interval":
        seconds = value["interval_hours"] * 3600
        return first + timedelta(seconds=int((at - first).total_seconds() // seconds) * seconds)
    zone = ZoneInfo(value["timezone"])
    date = at.astimezone(zone).date()
    choices = [first]
    for offset in range(9):
        day = date - timedelta(days=offset)
        if value["frequency"] == "weekly" and day.weekday() != value["weekday"]:
            continue
        candidate = _wall(day, value["time"], zone)
        if first <= candidate <= at:
            choices.append(candidate)
    return max(choices)


def save(store, body, actor):
    at = _at()
    with store.lock, store.meta() as db:
        previous = _read(store, db)
        expected = body.get("expected_revision") if isinstance(body, dict) else None
        if isinstance(expected, bool) or not isinstance(expected, int) or expected != previous["revision"]:
            raise WorkflowConflict("Backup schedule changed; reload its current revision", _public(previous))
        config = _validate(body, previous)
        changed = any(config[key] != previous[key] for key in FIELDS if key != "retention_count")
        result = {**previous, **config, "revision": previous["revision"] + 1, "updated_at": stamp(at), "updated_by": actor}
        if not config["enabled"]:
            result["next_run_at"] = None
        elif changed or not result.get("next_run_at"):
            result["next_run_at"] = stamp(_next(config, at))
        store._put(db, "maintenance_settings", result)
        store.audit("maintenance.backup_schedule_updated", actor, {key: result[key] for key in FIELDS + ("revision", "next_run_at")}, db)
        return _public(result)


def _storage(directory):
    path = directory / ".backup-storage-id.json"
    if path.exists():
        if path.is_symlink():
            raise maintenance.MaintenanceError("Scheduled backup storage identity is invalid")
        try:
            value = json.loads(path.read_text())["id"]
            if not re.fullmatch(r"[a-f0-9]{32}", value):
                raise ValueError()
            return value
        except (OSError, ValueError, KeyError, TypeError):
            raise maintenance.MaintenanceError("Scheduled backup storage identity is invalid") from None
    value = uuid.uuid4().hex
    atomic_private_json(path, {"id": value})
    return value


def _run_record(store, identifier):
    with store.read_meta() as db:
        return store._get(db, "maintenance_settings", RUN_PREFIX + identifier)


def _finish(store, run, at, backup=None, error="", status=None):
    status = status or ("complete" if backup else "failed")
    with store.lock, store.meta() as db:
        current = store._get(db, "maintenance_settings", run["id"]) or run
        if current.get("status") == "complete":
            return current
        current.update(status=status, completed_at=stamp(at), backup_id=backup["id"] if backup else None, error=error)
        store._put(db, "maintenance_settings", current)
        config = _read(store, db)
        if config.get("active_run") == run["slot_id"]:
            config["active_run"] = None
        if run["due_at"] >= (config.get("last_run_due_at") or ""):
            config.update(last_status=status, last_error=error, last_storage_id=run["storage_id"])
        if backup and run["due_at"] >= (config.get("last_success_due_at") or ""):
            config.update(last_success_at=stamp(at), last_success_due_at=run["due_at"], last_backup_id=backup["id"])
        store._put(db, "maintenance_settings", config)
        store.audit("maintenance.scheduled_backup_" + status, "system:backup-scheduler", {"slot_id": run["slot_id"], "due_at": run["due_at"], "storage_id": run["storage_id"], "backup_id": current["backup_id"], "error": error}, db)
        return current


def _scheduled(run):
    return {"kind": KIND, "slot_id": run["slot_id"], "due_at": run["due_at"], "revision": run["schedule_revision"], "storage_id": run["storage_id"]}


def _recover_local(store, directory, storage, at):
    pending = directory / ".backup-schedule-pending.json"
    if not pending.exists():
        return
    try:
        if pending.is_symlink():
            raise ValueError()
        value = json.loads(pending.read_text())
        run = _run_record(store, value["slot_id"])
        if not run or run["storage_id"] != storage or value.get("storage_id") != storage:
            raise ValueError()
    except (OSError, ValueError, TypeError, KeyError):
        raise maintenance.MaintenanceError("Local scheduled-backup recovery state is invalid; no new backup was started") from None
    if run.get("status") != "complete":
        archive = directory / (run["slot_id"][:32] + ".zip")
        if archive.exists():
            try:
                backup = maintenance._backup_create(store, "system:backup-scheduler", "scheduled", scheduled=_scheduled(run))
                _finish(store, run, at, backup)
            except maintenance.MaintenanceError:
                _finish(store, run, at, error="An interrupted scheduled archive failed recovery verification; no replacement was made and previous backups were retained")
        else:
            _finish(store, run, at, error="Scheduled backup was interrupted before a verified archive was published; previous backups were retained", status="interrupted")
    pending.unlink(missing_ok=True)


def _resolve_previous(store, storage, at):
    with store.read_meta() as db:
        config = _read(store, db)
        run = store._get(db, "maintenance_settings", RUN_PREFIX + config["active_run"]) if config.get("active_run") else None
        backup = store._get(db, "maintenance_backups", run["slot_id"][:32]) if run else None
    if run:
        if backup and backup.get("status") == "complete" and backup.get("verified") is True and backup.get("scheduled") == _scheduled(run):
            _finish(store, run, at, backup)
        else:
            _finish(store, run, at, error="A scheduled backup was interrupted on its owning controller; inspect that controller's archive storage. Previous backups were retained", status="interrupted")


def _claim(store, storage, at):
    with store.lock, store.meta() as db:
        config = _read(store, db)
        if not config["enabled"] or not config.get("next_run_at"):
            return None
        due = _latest_due(config, at)
        if due is None:
            return None
        slot = digest({"kind": KIND, "revision": config["revision"], "due_at": stamp(due)})
        existing = store._get(db, "maintenance_settings", RUN_PREFIX + slot)
        if existing:
            config["next_run_at"] = stamp(due + timedelta(hours=config["interval_hours"]) if config["frequency"] == "interval" else _next(config, at))
            store._put(db, "maintenance_settings", config)
            return None
        run = {"id": RUN_PREFIX + slot, "slot_id": slot, "storage_id": storage, "schedule_revision": config["revision"], "due_at": stamp(due), "started_at": stamp(at), "status": "running", "retention_count": config["retention_count"]}
        store._put(db, "maintenance_settings", run)
        following = due + timedelta(hours=config["interval_hours"]) if config["frequency"] == "interval" else _next(config, at)
        config.update(active_run=slot, next_run_at=stamp(following), last_run_at=stamp(at), last_run_due_at=stamp(due), last_status="running", last_error="", last_storage_id=storage)
        store._put(db, "maintenance_settings", config)
        return run


def _prune(store, directory, storage, count, at):
    records = [record for record in store.all("maintenance_backups") if record.get("reason") == "scheduled" and record.get("status") == "complete" and record.get("verified") is True and record.get("scheduled", {}).get("kind") == KIND and record.get("scheduled", {}).get("storage_id") == storage and record.get("id") == record.get("scheduled", {}).get("slot_id", "")[:32]]
    records = [record for record in records if (directory / (record["id"] + ".zip")).is_file() and not (directory / (record["id"] + ".zip")).is_symlink()]
    records.sort(key=lambda item: (item["scheduled"]["due_at"], item["id"]), reverse=True)
    removed, deadline = 0, time.monotonic() + 30
    for record in records[count:count + 50]:
        if time.monotonic() >= deadline:
            break
        path = directory / (record["id"] + ".zip")
        maintenance._inspect_record(record, path)
        path.unlink()
        with store.lock, store.meta() as db:
            current = store._get(db, "maintenance_backups", record["id"])
            if current and current.get("scheduled") == record["scheduled"]:
                current.update(status="pruned", pruned_at=stamp(at))
                store._put(db, "maintenance_backups", current)
                store.audit("maintenance.scheduled_backup_pruned", "system:backup-scheduler", {"backup_id": record["id"], "storage_id": storage}, db)
        removed += 1
    return removed


def _owned(store, at, actor, completed):
    try:
        with maintenance.backup_operation_lock(store) as directory:
            storage = _storage(directory)
            _recover_local(store, directory, storage, at)
            _resolve_previous(store, storage, at)
            run = _claim(store, storage, at)
            if not run:
                return {"ran": False, "status": "not_due"}
            pending = directory / ".backup-schedule-pending.json"
            atomic_private_json(pending, {"slot_id": run["slot_id"], "storage_id": storage})
            try:
                backup = maintenance._backup_create(store, actor, "scheduled", scheduled=_scheduled(run))
            except Exception as error:
                public = str(error) if type(error) is maintenance.MaintenanceError else "Scheduled database backup failed; private credentials were not logged and previous backups were retained"
                _finish(store, run, completed(), error=public)
                if not (directory / (run["slot_id"][:32] + ".zip")).exists():
                    pending.unlink(missing_ok=True)
                return {"ran": True, "status": "failed", "slot_id": run["slot_id"], "error": public}
            finished_at = completed()
            _finish(store, run, finished_at, backup)
            pending.unlink(missing_ok=True)
            pruned, retention_error = 0, ""
            try:
                pruned = _prune(store, directory, storage, run["retention_count"], finished_at)
            except Exception:
                retention_error = "Backup succeeded; local scheduled retention could not finish. Existing unverified archives were retained"
            with store.lock, store.meta() as db:
                config = _read(store, db)
                config["retention_error"] = retention_error
                if retention_error:
                    config["last_error"] = retention_error
                store._put(db, "maintenance_settings", config)
            return {"ran": True, "status": "complete", "slot_id": run["slot_id"], "backup_id": backup["id"], "pruned_count": pruned, "retention_error": retention_error}
    except maintenance.BackupBusy:
        return {"ran": False, "status": "busy"}


def run_due(store, at=None, actor="system:backup-scheduler"):
    """Call from the product background service, never inside an HTTP handler."""
    injected_clock = at is not None
    at = _at(at)
    completed = (lambda: at) if injected_clock else _at
    try:
        if store.ha:
            result = store.run_job("backup", lambda: _owned(store, at, actor, completed))
            return result if result is not None else {"ran": False, "status": "peer_running"}
        return _owned(store, at, actor, completed)
    except Exception as error:
        public = str(error) if type(error) is maintenance.MaintenanceError else "Scheduled backup service could not complete; private credentials were not logged"
        try:
            with store.lock, store.meta() as db:
                config = _read(store, db)
                config.update(last_error=public, last_status="error")
                store._put(db, "maintenance_settings", config)
        except Exception:
            pass  # A failed metadata dependency cannot durably record its error.
        return {"ran": False, "status": "error", "error": public}
