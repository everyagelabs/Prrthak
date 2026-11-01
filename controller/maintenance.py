"""Private database-only backups and reviewed, provenance-bound demo cleanup.

Archives never contain PKI files, environment files, or the backup directory.
Restore validation does not overwrite a running database or execute SQL dumps.
"""
from __future__ import annotations

import hashlib
import fcntl
import json
import os
import re
import secrets
import shutil
import sqlite3
import subprocess
import tempfile
import time
import uuid
import zipfile
from contextlib import closing, contextmanager
from datetime import timedelta
from pathlib import Path

from .firewall import WorkflowConflict
from .store import digest, now, parse_time, stamp

from . import __version__ as VERSION
FORMAT_VERSION = 1
MAX_COMPONENT_BYTES = 512 * 1024 * 1024
MAX_ARCHIVE_BYTES = 1024 * 1024 * 1024
TIMEOUT_SECONDS = 180
PHRASE = "CLEAR DEFAULT DEMO DATA"
IDENTIFIER = re.compile(r"[a-f0-9]{32}")
TABLES = ("maintenance_backups", "maintenance_plans", "maintenance_settings")


class MaintenanceError(RuntimeError):
    pass


class BackupBusy(MaintenanceError):
    pass


@contextmanager
def backup_operation_lock(store):
    """One local backup operation, including across processes/Store instances."""
    directory = _directory(store)
    descriptor = os.open(directory / ".backup-operation.lock", os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise BackupBusy("Another database backup is running on this controller; retry after it completes") from None
        yield directory
    finally:
        os.close(descriptor)


def initialize(db):
    for table in TABLES:
        db.execute(f"CREATE TABLE IF NOT EXISTS {table} (id TEXT PRIMARY KEY, data TEXT NOT NULL)")


def seed_disabled(store):
    with store.read_meta() as db:
        marker = store._get(db, "maintenance_settings", "demo_seed_disabled")
        return bool(marker and marker.get("disabled"))


def _directory(store):
    configured = getattr(store, "backup_dir", None)
    if configured is None:
        base = getattr(store, "path", None)
        if base is None:
            raise MaintenanceError("Configure a private local backup directory on this controller")
        configured = Path(base) / "backups"
    path = Path(configured)
    if not path.is_absolute():
        path = path.absolute()
    if path.is_symlink():
        raise MaintenanceError("The backup directory must not be a symlink")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if not path.is_dir() or path.stat().st_uid != os.geteuid():
        raise MaintenanceError("The backup directory must be owned by the controller service")
    path.chmod(0o700)
    return path.resolve()


def _check(deadline, path=None, maximum=MAX_COMPONENT_BYTES):
    if time.monotonic() > deadline:
        raise MaintenanceError("Database backup or validation exceeded its bounded deadline")
    if path is not None and Path(path).exists() and Path(path).stat().st_size > maximum:
        raise MaintenanceError("Database backup exceeds the configured component size limit")


def _sha(path, deadline):
    value = hashlib.sha256()
    with Path(path).open("rb") as source:
        while data := source.read(1024 * 1024):
            _check(deadline, path)
            value.update(data)
    return value.hexdigest()


def _sqlite_description(path):
    with closing(sqlite3.connect(Path(path).resolve().as_uri() + "?mode=ro&immutable=1", uri=True)) as db:
        if db.execute("PRAGMA quick_check").fetchall() != [("ok",)]:
            raise MaintenanceError("A database snapshot did not pass SQLite integrity validation")
        schema = db.execute("SELECT type,name,tbl_name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name").fetchall()
        tables = [row[1] for row in schema if row[0] == "table"]
        counts = {}
        for name in tables:
            if not re.fullmatch(r"[a-z_][a-z0-9_]*", name):
                raise MaintenanceError("Unexpected database schema identifier")
            counts[name] = db.execute(f'SELECT COUNT(*) FROM "{name}"').fetchone()[0]
    return {"schema_digest": digest(schema), "tables": counts}


def _sqlite_copy(source, destination, deadline):
    with closing(sqlite3.connect(Path(source).resolve().as_uri() + "?mode=ro", uri=True)) as incoming:
        with closing(sqlite3.connect(destination)) as outgoing:
            incoming.backup(outgoing, pages=256, progress=lambda *_: _check(deadline, destination), sleep=0.02)
            outgoing.execute("PRAGMA journal_mode=DELETE")
            outgoing.commit()
    Path(destination).chmod(0o600)
    return _sqlite_description(destination)


def _pg_environment(dsn):
    try:
        from psycopg.conninfo import conninfo_to_dict
        values = conninfo_to_dict(dsn)
    except Exception:
        raise MaintenanceError("PostgreSQL connection configuration could not be prepared for backup") from None
    names = {"host": "PGHOST", "hostaddr": "PGHOSTADDR", "port": "PGPORT", "dbname": "PGDATABASE", "user": "PGUSER", "password": "PGPASSWORD", "passfile": "PGPASSFILE", "sslmode": "PGSSLMODE", "sslrootcert": "PGSSLROOTCERT", "sslcert": "PGSSLCERT", "sslkey": "PGSSLKEY", "sslcrl": "PGSSLCRL", "sslcrldir": "PGSSLCRLDIR", "options": "PGOPTIONS", "service": "PGSERVICE", "channel_binding": "PGCHANNELBINDING", "target_session_attrs": "PGTARGETSESSIONATTRS"}
    environment = {key: os.environ[key] for key in ("PATH", "LANG", "LC_ALL", "TZ", "TMPDIR") if key in os.environ}
    environment.update({names[key]: str(value) for key, value in values.items() if key in names})
    environment.update({"PGCONNECT_TIMEOUT": "5", "PGAPPNAME": "prthak-private-backup"})
    return environment


def _program(store, name):
    executable = getattr(store, name + "_path", None) or shutil.which(name)
    if not executable:
        raise MaintenanceError(f"Install the matching PostgreSQL {name} client on this controller")
    return str(executable)


def _bounded_command(arguments, environment, output, deadline):
    process = None
    try:
        with Path(output).open("wb") as target:
            os.chmod(output, 0o600)
            process = subprocess.Popen(arguments, stdin=subprocess.DEVNULL, stdout=target, stderr=subprocess.DEVNULL, env=environment, close_fds=True)
            while process.poll() is None:
                _check(deadline, output)
                time.sleep(0.05)
            _check(deadline, output)
            if process.returncode:
                raise MaintenanceError("PostgreSQL backup/validation client failed; database credentials were not logged")
    except (OSError, subprocess.SubprocessError):
        raise MaintenanceError("PostgreSQL backup/validation client could not complete") from None
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait(timeout=5)


def _pg_description(db, canonical_hashes=False, deadline=None):
    schema = [[row[index] for index in range(5)] for row in db.execute("SELECT table_name,column_name,data_type,is_nullable,column_default FROM information_schema.columns WHERE table_schema='public' ORDER BY table_name,ordinal_position").fetchall()]
    tables = {}
    for name in sorted({row[0] for row in schema}):
        if not re.fullmatch(r"[a-z_][a-z0-9_]*", name):
            raise MaintenanceError("Unexpected database schema identifier")
        tables[name] = db.execute(f'SELECT COUNT(*) FROM "{name}"').fetchone()[0]
    result = {"schema_digest": digest(schema), "tables": tables}
    if canonical_hashes:
        result["data_hashes"] = _pg_data_hashes(db, tables, deadline=deadline)
    return result


def _pg_data_hashes(db, tables, deadline=None):
    """Stream fixed scalar tables in locale-independent primary-key order."""
    from .platform_runtime import META_TABLES, TRAFFIC_TABLES, _columns
    if set(tables) - set(META_TABLES) - set(TRAFFIC_TABLES) - {"runtime_deployment"}:
        raise MaintenanceError("Database schema contains unknown tables; review a supported backup migration")
    results, deadline = {}, deadline or time.monotonic() + TIMEOUT_SECONDS
    raw = getattr(db, "connection", None)
    for table in sorted(set(tables) - {"runtime_deployment"}):
        columns = _columns(table)
        order = columns[0] if table == "flows" else columns[0] + ' COLLATE "C"'
        sql = f'SELECT {",".join(columns)} FROM "{table}" ORDER BY {order}'
        checksum = hashlib.sha256()
        with raw.cursor(name="prthak_backup_hash_" + uuid.uuid4().hex) as cursor:
            cursor.execute(sql)
            while rows := cursor.fetchmany(256):
                _check(deadline)
                for row in rows:
                    values = [json.loads(row[index]) if column == "data" and isinstance(row[index], str) else row[index] for index, column in enumerate(columns)]
                    checksum.update(json.dumps(values, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode())
                    checksum.update(b"\n")
        results[table] = checksum.hexdigest()
    return results


def _public(record, store=None):
    keys = ("id", "created_at", "created_by", "reason", "backend", "status", "size_bytes", "verified", "format_version", "members", "consistency")
    result = {key: record[key] for key in keys if key in record}
    result["controller_local"] = True
    if store is not None:
        path = _directory(store) / (record["id"] + ".zip")
        result["available"] = path.is_file() and not path.is_symlink()
    return result


def backup_create(store, actor, reason="manual"):
    with backup_operation_lock(store):
        return _backup_create(store, actor, reason)


def _backup_create(store, actor, reason="manual", *, scheduled=None):
    """Internal caller must hold backup_operation_lock for the entire operation."""
    directory = _directory(store)
    if scheduled is not None:
        if reason != "scheduled" or scheduled.get("kind") != "prthak-backup-schedule-v1" or not re.fullmatch(r"[a-f0-9]{64}", scheduled.get("slot_id", "")) or not IDENTIFIER.fullmatch(scheduled.get("storage_id", "")):
            raise MaintenanceError("Invalid internal scheduled-backup identity")
    identifier = scheduled["slot_id"][:32] if scheduled else uuid.uuid4().hex
    destination = directory / (identifier + ".zip")
    deadline = time.monotonic() + TIMEOUT_SECONDS
    if scheduled:
        with store.read_meta() as db:
            existing = store._get(db, "maintenance_backups", identifier)
        if existing:
            if existing.get("scheduled") != scheduled or existing.get("status") != "complete":
                raise MaintenanceError("Scheduled backup identity is already occupied")
            _inspect_record(existing, destination)
            return _public(existing, store)
        if destination.exists():
            return _recover_scheduled(store, destination, scheduled, actor)
    backend = "postgresql" if store.ha else "sqlite"
    record = {"id": identifier, "created_at": stamp(), "created_by": actor, "reason": str(reason)[:120], "backend": backend, "status": "complete", "verified": True, "format_version": FORMAT_VERSION}
    if scheduled:
        record["scheduled"] = scheduled
    try:
        with tempfile.TemporaryDirectory(prefix=".backup-", dir=directory) as temporary:
            work = Path(temporary)
            members = []
            with store.lock, store.flow_lock:
                if store.ha:
                    # Hold both shared application writer fences while pg_dump
                    # takes its own consistent per-database snapshots.
                    with store.meta() as metadata, store.traffic() as traffic:
                        metadata.execute("SET LOCAL idle_in_transaction_session_timeout = '0'")
                        traffic.execute("SET LOCAL idle_in_transaction_session_timeout = '0'")
                        for kind, db, dsn in (("metadata", metadata, store._metadata_dsn), ("traffic", traffic, store._traffic_dsn)):
                            path = work / (kind + ".dump")
                            environment = _pg_environment(dsn)
                            try:
                                _bounded_command([_program(store, "pg_dump"), "--format=custom", "--no-owner", "--no-privileges", "--no-password"], environment, path, deadline)
                            finally:
                                environment.clear()
                            members.append({"name": path.name, "kind": kind, "size_bytes": path.stat().st_size, "sha256": _sha(path, deadline), **_pg_description(db, canonical_hashes=True, deadline=deadline)})
                    consistency = "Both shared Prṛthak application writer locks held across the two PostgreSQL snapshots; independent administrative/database writers are outside this fence"
                else:
                    for kind, source in (("metadata", store.meta_path), ("traffic", store.traffic_path)):
                        path = work / (kind + ".sqlite3")
                        description = _sqlite_copy(source, path, deadline)
                        members.append({"name": path.name, "kind": kind, "size_bytes": path.stat().st_size, "sha256": _sha(path, deadline), **description})
                    consistency = "Both local Prṛthak application writer locks held; each SQLite online-backup snapshot is internally consistent"
            manifest = {"product": "Prṛthak", "version": VERSION, "format_version": FORMAT_VERSION, "backend": backend, "created_at": record["created_at"], "consistency": consistency, "members": members, "excludes": ["PKI private keys", "environment", "backup directory"], "sensitive": "Contains database accounts, identities, policy history and traffic; Super Admin access only"}
            manifest.update(backup_id=identifier, created_by=actor, reason=record["reason"])
            if scheduled:
                manifest["scheduled"] = scheduled
            archive = work / "archive.zip"
            with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as output:
                for member in members:
                    _check(deadline)
                    output.write(work / member["name"], member["name"])
                output.writestr("manifest.json", json.dumps(manifest, sort_keys=True, indent=2).encode())
            archive.chmod(0o600)
            _check(deadline, archive, MAX_ARCHIVE_BYTES)
            record.update({"size_bytes": archive.stat().st_size, "archive_sha256": _sha(archive, deadline), "members": members, "consistency": consistency})
            with archive.open("rb") as incoming:
                os.fsync(incoming.fileno())
            os.replace(archive, destination)
            descriptor = os.open(directory, os.O_RDONLY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        _inspect_record(record, destination)
        with store.lock, store.meta() as db:
            store._put(db, "maintenance_backups", record)
            store.audit("maintenance.backup_created", actor, {"backup_id": identifier, "backend": backend, "reason": record["reason"]}, db)
        return _public(record, store)
    except MaintenanceError:
        if not scheduled:
            destination.unlink(missing_ok=True)
        raise
    except Exception:
        if not scheduled:
            destination.unlink(missing_ok=True)
        raise MaintenanceError("Database backup failed; no cleanup was performed") from None


def _recover_scheduled(store, path, scheduled, actor):
    """Adopt an already durable archive after a crash before index publication."""
    deadline = time.monotonic() + TIMEOUT_SECONDS
    try:
        if path.is_symlink() or not path.is_file():
            raise ValueError()
        with zipfile.ZipFile(path) as archive:
            if archive.getinfo("manifest.json").file_size > 1024 * 1024:
                raise ValueError()
            manifest = json.loads(archive.read("manifest.json"))
        if manifest.get("backup_id") != scheduled["slot_id"][:32] or manifest.get("scheduled") != scheduled or manifest.get("reason") != "scheduled":
            raise ValueError()
        record = {"id": manifest["backup_id"], "created_at": manifest["created_at"], "created_by": manifest["created_by"], "reason": "scheduled", "backend": manifest["backend"], "status": "complete", "verified": True, "format_version": manifest["format_version"], "members": manifest["members"], "consistency": manifest["consistency"], "scheduled": scheduled, "size_bytes": path.stat().st_size, "archive_sha256": _sha(path, deadline)}
        _inspect_record(record, path)
        with store.lock, store.meta() as db:
            store._put(db, "maintenance_backups", record)
            store.audit("maintenance.scheduled_backup_recovered", actor, {"backup_id": record["id"], "slot_id": scheduled["slot_id"]}, db)
        return _public(record, store)
    except MaintenanceError:
        raise
    except Exception:
        raise MaintenanceError("An interrupted scheduled archive could not be safely recovered; no replacement was made") from None


def backup_listing(store):
    return [_public(record, store) for record in sorted(store.all("maintenance_backups"), key=lambda row: (row["created_at"], row["id"]), reverse=True)]


def _archive(store, identifier):
    if not isinstance(identifier, str) or not IDENTIFIER.fullmatch(identifier):
        raise ValueError("Invalid backup identifier")
    record = store.get("maintenance_backups", identifier)
    path = _directory(store) / (identifier + ".zip")
    if path.is_symlink() or not path.is_file():
        raise MaintenanceError("Backup bytes are unavailable on this controller; use the controller/storage that owns this archive")
    return record, path


def _inspect(store, identifier, extract_to=None):
    record, path = _archive(store, identifier)
    return _inspect_record(record, path, extract_to)


def _inspect_record(record, path, extract_to=None):
    deadline = time.monotonic() + TIMEOUT_SECONDS
    if path.stat().st_size > MAX_ARCHIVE_BYTES or _sha(path, deadline) != record["archive_sha256"]:
        raise MaintenanceError("Backup archive checksum does not match its immutable manifest record")
    expected = {member["name"] for member in record["members"]}
    if expected != ({"metadata.sqlite3", "traffic.sqlite3"} if record["backend"] == "sqlite" else {"metadata.dump", "traffic.dump"}):
        raise MaintenanceError("Backup member names do not match the supported database-only format")
    try:
        with zipfile.ZipFile(path, "r") as archive:
            infos = archive.infolist()
            if len(infos) != 3 or {info.filename for info in infos} != expected | {"manifest.json"}:
                raise MaintenanceError("Backup contains unexpected or duplicate archive members")
            if sum(info.file_size for info in infos) > MAX_ARCHIVE_BYTES or any(info.file_size > MAX_COMPONENT_BYTES for info in infos) or archive.getinfo("manifest.json").file_size > 1024 * 1024:
                raise MaintenanceError("Backup exceeds its bounded extracted size")
            manifest = json.loads(archive.read("manifest.json"))
            if manifest.get("format_version") != FORMAT_VERSION or manifest.get("backend") != record["backend"] or manifest.get("members") != record["members"]:
                raise MaintenanceError("Backup manifest differs from its recorded database snapshots")
            if record.get("scheduled") and (manifest.get("scheduled") != record["scheduled"] or manifest.get("backup_id") != record["id"] or manifest.get("reason") != "scheduled"):
                raise MaintenanceError("Scheduled archive provenance differs from its immutable index")
            for member in record["members"]:
                checksum = hashlib.sha256()
                size = 0
                output = (Path(extract_to) / member["name"]).open("xb") if extract_to else None
                try:
                    if output:
                        os.chmod(output.name, 0o600)
                    with archive.open(member["name"], "r") as incoming:
                        while data := incoming.read(1024 * 1024):
                            _check(deadline)
                            size += len(data)
                            if size > MAX_COMPONENT_BYTES:
                                raise MaintenanceError("Backup component exceeds its size bound")
                            checksum.update(data)
                            if output:
                                output.write(data)
                finally:
                    if output:
                        output.close()
                if size != member["size_bytes"] or checksum.hexdigest() != member["sha256"]:
                    raise MaintenanceError("Backup component checksum verification failed")
            return record, manifest
    except (zipfile.BadZipFile, json.JSONDecodeError, KeyError, OSError):
        raise MaintenanceError("Backup archive could not be safely verified") from None


def backup_inspect(store, identifier):
    record, manifest = _inspect(store, identifier)
    return {"backup": _public(record, store), "manifest": manifest, "verified": True, "checks": ["Archive SHA-256 verified", "Exact database-only member list verified", "Both component SHA-256 digests and byte counts verified"]}


def backup_download(store, identifier):
    _inspect(store, identifier)
    return _archive(store, identifier)[1]


def restore_validate(store, identifier, actor):
    directory = _directory(store)
    with tempfile.TemporaryDirectory(prefix=".validate-", dir=directory) as temporary:
        record, manifest = _inspect(store, identifier, temporary)
        checks = ["Archive and component hashes verified"]
        for member in record["members"]:
            path = Path(temporary) / member["name"]
            if record["backend"] == "sqlite":
                description = _sqlite_description(path)
                if description["schema_digest"] != member["schema_digest"]:
                    raise MaintenanceError("Restored SQLite schema digest differs from its backup manifest")
                required = {"servers", "policies", "sessions", "audit"} if member["kind"] == "metadata" else {"flows", "batches"}
                if not required <= set(description["tables"]):
                    raise MaintenanceError("Backup is missing required Prṛthak database tables")
                checks.append(member["kind"] + " SQLite integrity and schema verified in isolated staging")
            else:
                listing = Path(temporary) / (member["kind"] + ".toc")
                _bounded_command([_program(store, "pg_restore"), "--list", str(path)], {key: os.environ[key] for key in ("PATH", "LANG", "LC_ALL") if key in os.environ}, listing, time.monotonic() + TIMEOUT_SECONDS)
                if not listing.stat().st_size:
                    raise MaintenanceError("PostgreSQL backup archive catalogue is empty")
                checks.append(member["kind"] + " PostgreSQL custom archive catalogue parsed by pg_restore; no database was overwritten")
    store.audit("maintenance.backup_restore_validated", actor, {"backup_id": identifier, "backend": record["backend"]})
    return {"backup_id": identifier, "backend": record["backend"], "valid": True, "verified": True, "schema_compatible": record["backend"] == ("postgresql" if store.ha else "sqlite") and manifest.get("version") == VERSION, "can_restore_live": False, "requires_offline_restore": True, "checks": checks, "requirements": ["Stop/fence every controller writer and preserve this backup before a separately reviewed restore", "Restore metadata and traffic together to compatible recovery points", "Restore matching PKI/secrets separately; this archive contains no PKI private keys", "Validate migrations, identity/token state and endpoint policy epochs before admitting agents", "PostgreSQL catalogue validation is not a full restore/failover drill"]}


def _same_policy(policy, original):
    return all(policy.get(key) == original.get(key) for key in ("name", "selector", "group_ids", "mode", "services"))


def _state(store, db, traffic):
    from .seed import SEEDED_SERVER_IDS, DEMO_LOCATIONS
    from .service_groups import effective_bundles
    from .application_groups import managed
    servers = store._all(db, "servers")
    fixtures = {server["id"] for server in servers if server["id"] in SEEDED_SERVER_IDS and server.get("synthetic") is True}
    retained = [server for server in servers if server["id"] not in fixtures]
    policies = store._all(db, "policies")
    compiled = effective_bundles(store, db, servers=servers, policies=policies)
    defaults, preserved_policies, blockers = set(), [], []
    for policy in policies:
        row = db.execute("SELECT data FROM policy_revisions WHERE policy_id=? AND revision=1", (policy["id"],)).fetchone()
        original = json.loads(row[0]) if row else {}
        if original.get("actor") == "demo.seed" and policy.get("revision") == 1 and _same_policy(policy, original):
            if compiled["targets"].get(policy["id"], set()) - fixtures:
                preserved_policies.append(policy["id"])
            else:
                defaults.add(policy["id"])
    retained_policies = [policy for policy in policies if policy["id"] not in defaults]
    future = effective_bundles(store, db, servers=retained, policies=retained_policies)
    for server in retained:
        if digest(future["payloads"][server["id"]]) != digest(compiled["payloads"][server["id"]]):
            blockers.append("A retained endpoint's effective policy depends on default fixtures: " + server["hostname"])
    groups, locations = set(), set()
    group_rows = store._all(db, "groups")
    for group in group_rows:
        refs = [policy for policy in retained_policies if group["id"] in policy.get("group_ids", []) or any(group["id"] in service.get("source_group_ids", []) for service in policy["services"])]
        if group.get("type") == "static" and set(group.get("server_ids", [])) & fixtures:
            blockers.append("A manual/static group still references default endpoints: " + group["name"])
        if managed(group) and group.get("application") in {"payments", "billing", "orders", "platform"} and not refs and not any(server.get("tags", {}).get("application") == group.get("application") for server in retained):
            groups.add(group["id"])
    for location in store._all(db, "locations"):
        original = next((value for value in DEMO_LOCATIONS.values() if value["id"] == location["id"]), None)
        if original and location.get("synthetic") is True and all(location.get(key) == original.get(key) for key in ("name", "location", "type", "provider", "region")):
            referenced = any(server.get("location_id") == location["id"] for server in retained) or any(row.get("location_id") == location["id"] for table in ("metadata_ip_profiles", "metadata_subnets") for row in store._all(db, table))
            referenced |= any(policy.get("selector", {}).get("location_id") == location["id"] or any(service.get("source_selector", {}).get("location_id") == location["id"] for service in policy["services"]) for policy in retained_policies)
            referenced |= any(group["id"] not in groups and group.get("selector", {}).get("location_id") == location["id"] for group in group_rows)
            if not referenced:
                locations.add(location["id"])
    selected = {"servers": fixtures, "policies": defaults, "groups": groups, "locations": locations}
    for table in ("sessions", "firewall_changes", "managed_rollouts"):
        chosen = set()
        for item in store._all(db, table):
            ids = set(item.get("server_ids", [])) | set(item.get("operations_by_server", {}))
            if ids & fixtures and ids - fixtures:
                blockers.append("Mixed real/default endpoint references require separate review: " + table + "/" + item["id"])
            elif ids and ids <= fixtures:
                if table != "sessions" and item.get("status") == "queued":
                    blockers.append("An authorized firewall operation is unresolved: " + item["id"])
                elif table == "sessions" and item.get("policy_action") == "auto_allow" and item.get("status") == "active":
                    blockers.append("An automatic allow grant is active: " + item["id"])
                else:
                    chosen.add(item["id"])
        selected[table] = chosen
    for table in ("learning_allow_policies", "learning_allow_hosts"):
        for item in store._all(db, table):
            if item.get("server_id", item["id"]) in fixtures and (item.get("services") or item.get("applied_services") or item.get("removal_pending") or (table == "learning_allow_policies" and not item.get("removed"))):
                blockers.append("A learning-owned grant or cleanup remains active/uncertain: " + item["id"])
    for item in db.execute("SELECT server_id,data FROM managed_approvals WHERE active=1").fetchall():
        if item[0] in fixtures and parse_time(json.loads(item[1])["expires_at"]) > now():
            blockers.append("A managed approval remains active for a default endpoint: " + item[0])
    for token in store._all(db, "tokens"):
        if token.get("server_id") in fixtures and not token.get("used") and not token.get("revoked") and parse_time(token["expires_at"]) > now():
            blockers.append("An unconsumed enrollment authority references a default endpoint")
    for table in ("alerts", "learning_evidence_receipts", "learning_allow_policies", "learning_allow_hosts", "learning_allow_history", "server_lifecycle_plans", "security_alert_windows"):
        selected[table] = {item["id"] for item in store._all(db, table) if item.get("server_id") in fixtures}
    special = {"bundle_history": "server_id", "managed_outcomes": "server_id", "managed_approvals": "server_id", "security_event_receipts": "server_id", "learning_evidence": "server_id", "policy_revisions": "policy_id"}
    for table, field in special.items():
        ids = defaults if field == "policy_id" else fixtures
        selected[table] = {row[0] for row in db.execute(f"SELECT id,{field} FROM {table}").fetchall() if row[1] in ids}
    flow_ids = {row[0] for row in traffic.execute("SELECT id,server_id FROM flows").fetchall() if row[1] in fixtures}
    batch_ids = {row[0] for row in traffic.execute("SELECT batch_key,server_id FROM batches").fetchall() if row[1] in fixtures}
    selected["flows"], selected["batches"] = flow_ids, batch_ids
    # Report clocks are deliberately absent; business state and authorities are not.
    server_fields = ("id", "synthetic", "hostname", "ips", "tags", "location_id", "_metadata_overrides", "protection_digest", "_managed_rules_active")
    state = {"servers": [{key: server.get(key) for key in server_fields} for server in sorted(servers, key=lambda row: row["id"])], "selected": {table: sorted(ids) for table, ids in selected.items()},
             "references": {table: sorted(store._all(db, table), key=lambda row: row["id"]) for table in ("policies", "groups", "locations", "metadata_ip_profiles", "metadata_subnets", "sessions", "firewall_changes", "managed_rollouts", "learning_allow_policies", "learning_allow_hosts", "tokens")}, "blockers": sorted(set(blockers))}
    retained_policy_review = [{"id": policy["id"], "name": policy["name"], "reason": "Used by retained endpoints" if policy["id"] in preserved_policies else "Edited, manually created or lacking unambiguous demo provenance"} for policy in retained_policies]
    return {"selected": selected, "counts": {table: len(ids) for table, ids in selected.items()}, "blockers": sorted(set(blockers)), "fingerprint": digest(state), "preserved": {"real_endpoints": len(retained), "shared_policy_ids": preserved_policies, "retained_policies": retained_policy_review, "service_groups": len(store._all(db, "service_groups")), "audit_and_accounts": True, "manual_groups_and_custom_catalogues": True}}


def clear_preview(store, actor):
    with store.lock, store.flow_lock, store.meta() as db, store.traffic() as traffic:
        state = _state(store, db, traffic)
        plan = {"id": uuid.uuid4().hex, "counts": state["counts"], "preserved": state["preserved"], "blockers": state["blockers"], "can_clear": not state["blockers"], "fingerprint": state["fingerprint"], "confirmation_phrase": PHRASE, "confirmation_nonce": secrets.token_urlsafe(24), "expires_at": stamp(now() + timedelta(minutes=10)), "created_at": stamp(), "created_by": actor, "status": "preview", "selected": {table: sorted(ids) for table, ids in state["selected"].items()}}
        store._put(db, "maintenance_plans", plan)
        return {key: value for key, value in plan.items() if key != "selected"}


def clear_confirm(store, value, actor):
    if not isinstance(value, dict) or value.get("confirmation_phrase") != PHRASE:
        raise ValueError("Type the exact default-data removal confirmation phrase")
    identifier = value.get("preview_id")
    if not isinstance(identifier, str) or not IDENTIFIER.fullmatch(identifier):
        raise ValueError("A reviewed default-data preview is required")
    plan = store.get("maintenance_plans", identifier)
    if not isinstance(value.get("confirmation_nonce"), str) or not secrets.compare_digest(value["confirmation_nonce"], plan.get("confirmation_nonce", "")):
        raise WorkflowConflict("Default-data review confirmation does not match", {})
    if plan["status"] == "applied":
        return {"backup_id": plan["backup_id"], "counts": plan["counts"], "seed_disabled": True, "duplicate": True}
    if plan["status"] not in ("preview", "applying") or parse_time(plan["expires_at"]) <= now() or not plan["can_clear"]:
        raise WorkflowConflict("Default-data preview is blocked or expired; preview again", {})
    # The verified archive is created before either database is modified.
    backup = backup_create(store, actor, "before-default-data-clear") if not plan.get("backup_id") else {"id": plan["backup_id"]}
    backup_inspect(store, backup["id"])
    with store.lock, store.flow_lock, store.meta() as db, store.traffic() as traffic:
        current = store._get(db, "maintenance_plans", identifier)
        state = _state(store, db, traffic)
        if current["status"] == "applied":
            return {"backup_id": current["backup_id"], "counts": current["counts"], "seed_disabled": True, "duplicate": True}
        if state["blockers"] or state["fingerprint"] != plan["fingerprint"]:
            raise WorkflowConflict("Default data or real endpoint dependencies changed; preview again", {"backup_id": backup["id"]})
        # Traffic commits first. A crash can leave default-only traffic removed;
        # the metadata intent and verified archive remain available for review.
        for table in ("flows", "batches"):
            column = "id" if table == "flows" else "batch_key"
            for row_id in plan["selected"][table]:
                traffic.execute(f"DELETE FROM {table} WHERE {column}=?", (row_id,))
        for table, ids in plan["selected"].items():
            if table not in ("flows", "batches"):
                for row_id in ids:
                    db.execute(f"DELETE FROM {table} WHERE id=?", (row_id,))
        store._put(db, "maintenance_settings", {"id": "demo_seed_disabled", "disabled": True, "updated_at": stamp(), "updated_by": actor, "backup_id": backup["id"]})
        store.compile_all(db)
        current.update({"status": "applied", "backup_id": backup["id"], "applied_at": stamp(), "applied_by": actor})
        store._put(db, "maintenance_plans", current)
        store.audit("maintenance.default_data_cleared", actor, {"preview_id": identifier, "counts": plan["counts"], "backup_id": backup["id"], "seed_disabled": True}, db)
        return {"backup_id": backup["id"], "counts": plan["counts"], "seed_disabled": True, "duplicate": False}
