"""Stopped-source migration and a fixed-operation controller child supervisor.

Only the supervisor changes the active database profile. Request handlers queue
reviewed work; they never hot-swap a live App.store or merge another node's data.
"""
from __future__ import annotations

from contextlib import closing, contextmanager
import copy
import fcntl
import hashlib
import http.client
import json
import os
from pathlib import Path
import signal
import socket
import sqlite3
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from urllib.parse import urlsplit

from .store import digest, stamp

FENCE_NAME = ".prthak-storage-fence.json"
MARKER_TABLE = "runtime_deployment"
META_TABLES = (
    "agent_polling_settings", "agent_polling_revisions",
    "endpoint_configuration_reviews",
    "hit_monitors", "hit_monitor_targets", "hit_monitor_reviews",
    "notification_settings", "notification_revisions", "notification_reviews", "notification_deliveries",
    "alerts", "audit", "auth_sessions", "auth_states", "auth_users", "auth_local_attempts", "bundle_history",
    "controller_nodes", "firewall_changes", "groups", "learning_allow_history",
    "learning_allow_hosts", "learning_allow_policies", "learning_evidence",
    "learning_evidence_receipts", "learning_policy_previews", "locations",
    "maintenance_backups", "maintenance_plans", "maintenance_settings",
    "managed_approvals", "managed_outcomes", "managed_rollouts", "metadata_ip_profiles",
    "metadata_plans", "metadata_subnets", "policies", "policy_intent_headers", "policy_revisions", "retired_endpoints",
    "policy_deployments", "policy_deployment_targets",
    "security_alert_windows", "security_event_receipts", "server_lifecycle_plans",
    "server_reservations", "servers", "service_group_revisions", "service_groups", "sessions", "learning_session_targets", "tokens",
)
TRAFFIC_TABLES = ("batches", "flows", "hit_batches", "hit_events", "hit_limits")
SPECIAL_COLUMNS = {
    "learning_session_targets": ("id", "session_id", "server_id", "status", "starts_at", "expires_at", "cutoff_at", "state_digest"),
    "policy_deployments": ("id", "created_at", "deadline_at", "data"),
    "policy_deployment_targets": ("id", "deployment_id", "server_id", "created_at", "deadline_at", "apply_status", "traffic_status", "data"),
    "hit_monitor_targets": ("id", "monitor_id", "server_id", "enabled", "data"),
    "hit_batches": ("batch_key", "server_id", "monitor_id", "data", "received_at", "processed"),
    "hit_events": ("id", "server_id", "monitor_id", "batch_key", "event_digest", "source_ip", "port", "protocol", "event_time", "expires_at", "data", "processed", "capture_kind", "capture_backend", "count_unit", "address_family", "verdict"),
    "notification_deliveries": ("id", "event_id", "channel_id", "status", "next_attempt_at", "lease_until", "created_at", "data"),
    "bundle_history": ("id", "server_id", "version", "digest", "created_at", "data"),
    "learning_allow_policies": ("id", "data", "server_id", "session_id"),
    "learning_evidence": ("id", "session_id", "server_id", "data"),
    "managed_approvals": ("id", "server_id", "version", "digest", "protection_digest", "approval_id", "expires_at", "active", "data"),
    "managed_outcomes": ("id", "server_id", "version", "approval_id", "created_at", "data"),
    "policy_revisions": ("id", "policy_id", "revision", "created_at", "data"),
    "security_alert_windows": ("id", "expires_at", "data"),
    "security_event_receipts": ("id", "server_id", "source_ip", "event_time", "received_at", "data"),
    "service_group_revisions": ("id", "service_group_id", "revision", "created_at", "data"),
    "batches": ("batch_key", "server_id", "session_id", "data", "received_at", "processed", "evidence_processed"),
    "flows": ("id", "batch_key", "event_index", "server_id", "session_id", "source_ip", "port", "protocol", "verdict", "count", "first_seen", "last_seen", "capture_kind", "capture_backend", "count_unit", "address_family", "event_id", "event_digest", "capture_processed", "capture_expires_at"),
}


class RuntimeSafetyError(RuntimeError):
    pass


def atomic_private_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary = tempfile.mkstemp(prefix=".runtime-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as output:
            os.chmod(temporary, 0o600)
            json.dump(value, output, sort_keys=True)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        descriptor = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def assert_sqlite_writable(directory):
    path = Path(directory) / FENCE_NAME
    if path.exists():
        from .recovery import sqlite_admitted
        try:
            if sqlite_admitted(directory, json.loads(path.read_text())):
                return
        except (ValueError, OSError):
            pass
        raise RuntimeSafetyError("SQLite storage is fenced for a reviewed deployment transition; use the configured deployment profile, never an automatic local fallback")


@contextmanager
def sqlite_storage_guard(directory):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(directory / ".prthak-storage.lock", os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_SH)
        assert_sqlite_writable(directory)
        yield
    finally:
        os.close(fd)


@contextmanager
def supervisor_lease(directory):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(directory / "runtime-supervisor.lock", os.O_RDWR | os.O_CREAT, 0o600)
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeSafetyError("Another supervisor or its surviving controller child still owns this platform directory") from None
        yield descriptor
    finally:
        os.close(descriptor)


def _profile(value):
    if not isinstance(value, dict):
        raise RuntimeSafetyError("A private reviewed deployment profile is required")
    try:
        deployment = str(uuid.UUID(value["deployment_id"]))
    except (ValueError, KeyError, TypeError, AttributeError):
        raise RuntimeSafetyError("Deployment identity must be a valid UUID") from None
    epoch = value.get("epoch")
    if isinstance(epoch, bool) or not isinstance(epoch, int) or epoch < 1:
        raise RuntimeSafetyError("Deployment epoch must be a positive integer")
    if any(not isinstance(value.get(key), str) or not value[key].strip() for key in ("metadata_dsn", "traffic_dsn")):
        raise RuntimeSafetyError("Both private PostgreSQL connection profiles are required")
    if "active_revision" in value and (isinstance(value["active_revision"], bool) or not isinstance(value["active_revision"], int) or value["active_revision"] < 1):
        raise RuntimeSafetyError("Active configuration revision must be a positive integer")
    return {**value, "deployment_id": deployment, "epoch": epoch}


def _connector(connector=None):
    if connector is not None:
        return connector
    try:
        import psycopg
    except ImportError:
        raise RuntimeSafetyError("Install the PostgreSQL controller driver before database activation") from None
    return psycopg.connect


def _raw_connection(connector, dsn):
    return connector(dsn, autocommit=True, connect_timeout=5, target_session_attrs="read-write", application_name="prthak-runtime-migration")


def _target_preflight(profile, connector):
    markers, identities = {}, []
    for namespace, dsn in (("metadata", profile["metadata_dsn"]), ("traffic", profile["traffic_dsn"])):
        with closing(_raw_connection(connector, dsn)) as connection:
            connection.execute("SET statement_timeout='15s'")
            identities.append(tuple(connection.execute("SELECT current_database(),COALESCE(inet_server_addr()::text,'local'),inet_server_port()").fetchone()))
            tables = {row[0] for row in connection.execute("SELECT tablename FROM pg_tables WHERE schemaname='public'").fetchall()}
            allowed = set(META_TABLES if namespace == "metadata" else TRAFFIC_TABLES) | {MARKER_TABLE}
            if tables - allowed:
                raise RuntimeSafetyError("Target database contains an unrecognized schema; foreign databases are never overwritten")
            marker = None
            if MARKER_TABLE in tables:
                row = connection.execute("SELECT data FROM runtime_deployment WHERE id='active'").fetchone()
                marker = json.loads(row[0]) if row else None
            if marker:
                if marker.get("deployment_id") != profile["deployment_id"] or marker.get("epoch") != profile["epoch"] or marker.get("namespace") != namespace:
                    raise RuntimeSafetyError("Target database belongs to another deployment or epoch")
                markers[namespace] = marker
            elif any(connection.execute(f'SELECT EXISTS(SELECT 1 FROM "{table}" LIMIT 1)').fetchone()[0] for table in sorted(tables - {MARKER_TABLE})):
                raise RuntimeSafetyError("Target database is not empty and has no matching deployment identity")
    if identities[0] == identities[1]:
        raise RuntimeSafetyError("Metadata and traffic must use separate target databases")
    return markers


def _columns(table):
    return SPECIAL_COLUMNS.get(table, ("id", "data"))


def _hash_rows(columns, rows):
    result = hashlib.sha256()
    # PostgreSQL's database collation can order textual IDs differently from
    # SQLite BINARY. Canonical verification must depend on content, not locale.
    for row in sorted(rows, key=lambda value: value[0]):
        values = [json.loads(row[index]) if name == "data" and isinstance(row[index], str) else row[index] for index, name in enumerate(columns)]
        result.update(json.dumps(values, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode())
        result.update(b"\n")
    return result.hexdigest()


def _source_rows(path, namespace):
    allowed = META_TABLES if namespace == "metadata" else TRAFFIC_TABLES
    with closing(sqlite3.connect(Path(path).resolve().as_uri() + "?mode=ro&immutable=1", uri=True)) as db:
        tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")}
        if tables - set(allowed):
            raise RuntimeSafetyError("Source schema contains unknown tables; review a supported migration before continuing")
        result = {}
        for table in allowed:
            if table not in tables:
                result[table] = []
                continue
            columns = _columns(table)
            if {row[1] for row in db.execute(f'PRAGMA table_info("{table}")')} != set(columns):
                raise RuntimeSafetyError("Source table columns do not match this controller migration version")
            result[table] = db.execute(f'SELECT {",".join(columns)} FROM "{table}" ORDER BY {columns[0]}').fetchall()
    return result


def _statistics(rows):
    return {"counts": {table: len(values) for table, values in rows.items()}, "hashes": {table: _hash_rows(_columns(table), values) for table, values in rows.items()}}


def _snapshot_source(source_dir, deployment):
    from .maintenance import _sqlite_copy
    directory = Path(source_dir).resolve()
    work = directory / ("migration-backup-" + uuid.uuid4().hex)
    work.mkdir(mode=0o700)
    rows, files = {}, {}
    deadline = time.monotonic() + 180
    for namespace, filename in (("metadata", "inventory.sqlite3"), ("traffic", "traffic.sqlite3")):
        source, destination = directory / filename, work / filename
        if not source.is_file() or source.is_symlink():
            raise RuntimeSafetyError("Both stopped SQLite database files must exist and be regular files")
        files[namespace] = _sqlite_copy(source, destination, deadline)
        rows[namespace] = _source_rows(destination, namespace)
    proof = {namespace: _statistics(value) for namespace, value in rows.items()}
    fingerprint = digest(proof)
    atomic_private_json(work / "manifest.json", {"deployment_id": deployment, "source_fingerprint": fingerprint, "snapshots": files, "proof": proof, "created_at": stamp()})
    return rows, proof, fingerprint, work


def _write_marker(store, namespace, marker):
    context = store.meta if namespace == "metadata" else store.traffic
    with context() as db:
        db.execute("INSERT INTO runtime_deployment(id,data) VALUES(?,?) ON CONFLICT(id) DO UPDATE SET data=excluded.data", ("active", json.dumps(marker, sort_keys=True)))


def _verify_namespace(db, source, proof):
    for table, expected in source.items():
        columns = _columns(table)
        actual = db.execute(f'SELECT {",".join(columns)} FROM "{table}" ORDER BY {columns[0]}').fetchall()
        if len(actual) != proof["counts"][table] or _hash_rows(columns, actual) != proof["hashes"][table]:
            raise RuntimeSafetyError("Target database count/canonical-content verification failed")


def migrate_stopped_sqlite(source_dir, metadata_dsn, traffic_dsn, deployment_id, epoch, *, connector=None):
    """Call only after the supervisor has proved its entire child group stopped."""
    profile = _profile({"metadata_dsn": metadata_dsn, "traffic_dsn": traffic_dsn, "deployment_id": deployment_id, "epoch": epoch})
    connect = _connector(connector)
    directory = Path(source_dir).resolve()
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    lock = (directory / ".prthak-storage.lock").open("a+")
    try:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        previous = _target_preflight(profile, connect)
        fence_path = directory / FENCE_NAME
        if fence_path.exists():
            try:
                fence = json.loads(fence_path.read_text())
            except (ValueError, OSError):
                raise RuntimeSafetyError("Source storage fence is invalid; automatic recovery is refused") from None
            if fence.get("deployment_id") != profile["deployment_id"] or fence.get("epoch") != epoch:
                raise RuntimeSafetyError("Source storage is already fenced for another deployment")
        rows, proof, fingerprint, backup = _snapshot_source(directory, profile["deployment_id"])
        import_ids = {marker.get("import_id") for marker in previous.values()}
        if len(import_ids) > 1 or any(marker.get("source_fingerprint") != fingerprint for marker in previous.values()):
            raise RuntimeSafetyError("Partial target import does not match the exact stopped source snapshot")
        import_id = next(iter(import_ids)) if import_ids else uuid.uuid4().hex
        if not isinstance(import_id, str) or not import_id:
            raise RuntimeSafetyError("Target import identity is missing")
        # Snapshot/schema/capacity failures have not touched the target. Keep a
        # previously unfenced source usable until target mutation can begin.
        atomic_private_json(fence_path, {"state": "MIGRATING", "deployment_id": profile["deployment_id"], "epoch": epoch, "updated_at": stamp()})
        from .postgres import PostgresStore
        migration_context = {"deployment_id": profile["deployment_id"], "epoch": epoch, "import_id": import_id, "source_fingerprint": fingerprint}
        target = PostgresStore(metadata_dsn, traffic_dsn, connector=connect, _migration_context=migration_context)
        for namespace in ("metadata", "traffic"):
            marker = {"deployment_id": profile["deployment_id"], "epoch": epoch, "namespace": namespace, "import_id": import_id, "source_fingerprint": fingerprint, "state": "IMPORTING", **proof[namespace]}
            old = previous.get(namespace)
            context = target.meta if namespace == "metadata" else target.traffic
            if old and old.get("state") in ("VERIFIED", "READY"):
                with context() as db:
                    _verify_namespace(db, rows[namespace], proof[namespace])
                continue
            if old and old.get("state") != "IMPORTING":
                raise RuntimeSafetyError("Target import is not in a recognized resumable state")
            _write_marker(target, namespace, marker)
            with context() as db:
                db.execute("SET LOCAL idle_in_transaction_session_timeout='0'")
                for table, values in rows[namespace].items():
                    if db.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0]:
                        raise RuntimeSafetyError("Target import table is unexpectedly populated; no existing data was overwritten")
                    if values:
                        columns = _columns(table)
                        query = f'INSERT INTO "{table}" ({",".join(columns)}) VALUES ({",".join("?" for _ in columns)})'
                        for offset in range(0, len(values), 500):
                            db.executemany(query, values[offset:offset + 500])
                if namespace == "traffic":
                    db.execute("SELECT setval(pg_get_serial_sequence('flows','id'),COALESCE((SELECT MAX(id) FROM flows),1),EXISTS(SELECT 1 FROM flows))")
                _verify_namespace(db, rows[namespace], proof[namespace])
                marker["state"] = "VERIFIED"
                db.execute("UPDATE runtime_deployment SET data=? WHERE id='active'", (json.dumps(marker, sort_keys=True),))
        for namespace in ("metadata", "traffic"):
            marker = {"deployment_id": profile["deployment_id"], "epoch": epoch, "namespace": namespace, "import_id": import_id, "source_fingerprint": fingerprint, "state": "READY", **proof[namespace]}
            _write_marker(target, namespace, marker)
        verify_deployment(metadata_dsn, traffic_dsn, profile["deployment_id"], epoch, connector=connect)
        atomic_private_json(fence_path, {"state": "RETIRED", "deployment_id": profile["deployment_id"], "epoch": epoch, "source_fingerprint": fingerprint, "import_id": import_id, "backup_name": backup.name, "updated_at": stamp()})
        return {"deployment_id": profile["deployment_id"], "epoch": epoch, "import_id": import_id, "source_fingerprint": fingerprint, "backup_name": backup.name, "proof": proof, "verified": True}
    except RuntimeSafetyError:
        raise
    except Exception:
        raise RuntimeSafetyError("Stopped-source database migration failed; private connection details were not logged and no local fallback is permitted after fencing") from None
    finally:
        lock.close()


def verify_deployment(metadata_dsn, traffic_dsn, deployment_id, epoch, *, connector=None):
    profile = _profile({"metadata_dsn": metadata_dsn, "traffic_dsn": traffic_dsn, "deployment_id": deployment_id, "epoch": epoch})
    try:
        markers = _target_preflight(profile, _connector(connector))
        if set(markers) != {"metadata", "traffic"} or any(marker.get("state") != "READY" or any(not isinstance(marker.get(key), str) or not marker[key] for key in ("import_id", "source_fingerprint")) for marker in markers.values()) or len({marker.get("import_id") for marker in markers.values()}) != 1 or len({marker.get("source_fingerprint") for marker in markers.values()}) != 1:
            raise RuntimeSafetyError("Both target databases must be READY for the same deployment, epoch and verified import")
        return markers
    except RuntimeSafetyError:
        raise
    except Exception:
        raise RuntimeSafetyError("Expected deployment identity could not be verified in both PostgreSQL databases") from None


def join_stopped_sqlite(source_dir, profile, *, connector=None):
    directory = Path(source_dir).resolve()
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    with (directory / ".prthak-storage.lock").open("a+") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        return _join_locked(source_dir, profile, connector=connector)


def _join_locked(source_dir, profile, *, connector=None):
    profile = _profile(profile)
    verify_deployment(profile["metadata_dsn"], profile["traffic_dsn"], profile["deployment_id"], profile["epoch"], connector=connector)
    directory = Path(source_dir).resolve()
    if (directory / FENCE_NAME).exists():
        try:
            prior = json.loads((directory / FENCE_NAME).read_text())
        except (ValueError, OSError):
            raise RuntimeSafetyError("Local storage fence is invalid; joining is refused") from None
        if prior.get("deployment_id") != profile["deployment_id"] or prior.get("epoch") != profile["epoch"]:
            raise RuntimeSafetyError("Local storage is already fenced for another deployment")
    rows, proof, fingerprint, backup = _snapshot_source(directory, profile["deployment_id"])
    setup_only = {"audit", "auth_users", "auth_sessions", "auth_states", "auth_local_attempts", "maintenance_backups", "maintenance_plans", "maintenance_settings"}
    if any(values for table, values in rows["metadata"].items() if table not in setup_only) or any(rows["traffic"].values()):
        raise RuntimeSafetyError("Joining nodes must have no local inventory, policy, traffic or firewall authority; local data is never merged")
    if any(rows["metadata"].values()) and profile.get("join_preserve_local_snapshot") is not True:
        raise RuntimeSafetyError("Explicit preservation review is required for a blank node's local setup/account snapshot")
    atomic_private_json(directory / FENCE_NAME, {"state": "RETIRED", "deployment_id": profile["deployment_id"], "epoch": profile["epoch"], "join_only": True, "source_fingerprint": fingerprint, "backup_name": backup.name, "updated_at": stamp()})
    return {"deployment_id": profile["deployment_id"], "epoch": profile["epoch"], "source_fingerprint": fingerprint, "backup_name": backup.name, "copied_rows": 0, "verified": True}


def _argument(arguments, option, default=None):
    result = default
    for index, value in enumerate(arguments):
        if value == option and index + 1 < len(arguments):
            result = arguments[index + 1]
        elif value.startswith(option + "="):
            result = value[len(option) + 1:]
    return result


def _set_argument(arguments, option, value):
    output, index = [], 0
    while index < len(arguments):
        argument = arguments[index]
        if argument == option:
            index += 2
            continue
        if not argument.startswith(option + "="):
            output.append(argument)
        index += 1
    return output + [option, value]


def child_launch(arguments, profile=None):
    args, environment = list(arguments), dict(os.environ)
    environment["PRTHAK_SUPERVISED_CHILD"] = "1"
    if profile:
        profile = _profile(profile)
        args = [arg for arg in args if arg not in ("--demo", "--ha")]
        args.append("--ha")
        tls = profile.get("controller_tls", {})
        for key, option in (("cert", "--cert"), ("key", "--key"), ("ca", "--ca"), ("ca_key", "--ca-key")):
            if tls.get(key):
                args = _set_argument(args, option, tls[key])
        for key, option in (("controller_id", "--controller-id"), ("site", "--site")):
            if key in profile:
                if not isinstance(profile[key], str) or not profile[key].strip():
                    raise RuntimeSafetyError("Controller node identity and site must be nonempty text")
                args = _set_argument(args, option, profile[key])
        allowed = {"PRTHAK_PROVIDER_EPOCH", "SEG_SUPER_ADMIN_TOKEN", "SEG_ADMIN_TOKEN", "SEG_READ_ONLY_TOKEN", "SEG_ENTRA_TENANT_ID", "SEG_ENTRA_CLIENT_ID", "SEG_ENTRA_REDIRECT_URI", "SEG_ENTRA_CLIENT_SECRET", "SEG_ENTRA_CLIENT_SECRET_FILE", "SEG_BOOTSTRAP_SUPER_ADMIN_OID", "SEG_MANAGEMENT_PROBE_SOURCE_IP"}
        values = profile.get("controller_env", {})
        if not isinstance(values, dict) or set(values) - allowed or any(not isinstance(value, str) for value in values.values()):
            raise RuntimeSafetyError("Controller profile contains unsupported environment overrides")
        if environment.get("PRTHAK_GUI_PROVIDER_MANAGED") == "1":
            # The reviewed protected file becomes authoritative for provider
            # values; retained encrypted profiles remain available for rollback.
            provider = {key for key in allowed if key.startswith("SEG_ENTRA_") or key in ("PRTHAK_PROVIDER_EPOCH", "SEG_BOOTSTRAP_SUPER_ADMIN_OID", "SEG_SUPER_ADMIN_TOKEN", "SEG_ADMIN_TOKEN", "SEG_READ_ONLY_TOKEN")}
            values = {key: value for key, value in values.items() if key not in provider}
        environment.update(values)
        environment.update({"SEG_DATABASE_URL": profile["metadata_dsn"], "SEG_TRAFFIC_DATABASE_URL": profile["traffic_dsn"], "SEG_EXPECTED_DEPLOYMENT_ID": profile["deployment_id"], "SEG_EXPECTED_DEPLOYMENT_EPOCH": str(profile["epoch"]), "SEG_ACTIVE_REVISION": str(profile.get("active_revision", ""))})
        for key in ("cert", "key", "ca"):
            value = _argument(args, "--" + key)
            if not value or not Path(value).is_file():
                raise RuntimeSafetyError("Controller TLS certificate, key and CA must be configured before database activation")
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        try:
            context.load_cert_chain(_argument(args, "--cert"), _argument(args, "--key"))
            context.load_verify_locations(_argument(args, "--ca"))
        except (OSError, ssl.SSLError):
            raise RuntimeSafetyError("Controller TLS identity is invalid; current controller was not stopped") from None
        if not environment.get("SEG_ENTRA_TENANT_ID") and not any(len(environment.get(key, "")) >= 32 for key in ("SEG_SUPER_ADMIN_TOKEN", "SEG_ADMIN_TOKEN")):
            raise RuntimeSafetyError("Production controller authentication must be configured before database activation")
    return [sys.executable, "-m", "controller", *args], environment


def stop_process_group(process, timeout=20):
    if process is None:
        return True
    group = process.pid
    try:
        os.killpg(group, signal.SIGTERM)
    except ProcessLookupError:
        pass
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        process.poll()
        try:
            os.killpg(group, 0)
        except ProcessLookupError:
            process.wait(timeout=1)
            return True
        except PermissionError:
            # A just-exited, not-yet-reaped child can briefly give EPERM on
            # Darwin. It never proves absence: keep draining until ESRCH.
            pass
        time.sleep(0.05)
    try:
        os.killpg(group, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait(timeout=5)
    for _ in range(40):
        try:
            os.killpg(group, 0)
        except ProcessLookupError:
            return True
        except PermissionError:
            pass
        time.sleep(0.05)
    raise RuntimeSafetyError("The complete controller child process group did not exit; migration was refused")


def probe_readiness(arguments, profile=None, tls_hostname=None, recovery_nonce=None):
    host, port = _argument(arguments, "--listen", "127.0.0.1:8787").rsplit(":", 1)
    host = "127.0.0.1" if host in ("0.0.0.0", "localhost") else host
    connection = None
    try:
        connection = socket.create_connection((host, int(port)), timeout=2)
        if "--demo" not in arguments or profile:
            context = ssl.create_default_context(cafile=_argument(arguments, "--ca"))
            certificate = _argument(arguments, "--cert")
            if certificate:
                context.load_verify_locations(cafile=certificate)
                context.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
            server_name = tls_hostname or (profile or {}).get("controller_server_name") or urlsplit((profile or {}).get("controller_origin", "")).hostname or host
            connection = context.wrap_socket(connection, server_hostname=server_name)
        admission = ""
        if recovery_nonce is not None:
            if not isinstance(recovery_nonce, str) or len(recovery_nonce) != 64 or any(char not in "0123456789abcdef" for char in recovery_nonce):
                return False
            admission = "X-Prthak-Recovery-Admission: " + recovery_nonce + "\r\n"
        connection.sendall(f"GET /readyz HTTP/1.1\r\nHost: {host}\r\n{admission}Connection: close\r\n\r\n".encode())
        response = http.client.HTTPResponse(connection)
        response.begin()
        result = json.loads(response.read(65537))
        if response.status != 200 or result.get("status") != "ready":
            return False
        if profile and (result.get("deployment_id") != profile["deployment_id"] or result.get("deployment_epoch") != profile["epoch"] or str(result.get("active_revision")) != str(profile.get("active_revision", ""))):
            return False
        return True
    except (OSError, ValueError, ssl.SSLError, http.client.HTTPException):
        return False
    finally:
        if connection is not None:
            connection.close()


class RuntimeSupervisor:
    def __init__(self, source_dir, manager, arguments, *, launch=None, stop=None, probe=None, migrate=None, join=None):
        self.source_dir, self.manager, self.arguments = Path(source_dir).resolve(), manager, list(arguments)
        self._lease_descriptor = None
        self.launch = launch or self._launch
        self.stop = stop or stop_process_group
        self.probe = probe or probe_readiness
        self.migrate, self.join = migrate or migrate_stopped_sqlite, join or join_stopped_sqlite
        self.child = None
        self.current_profile = None
        self.stopping = threading.Event()
        if hasattr(manager, "root"):
            from .application_port import record_context
            record_context(manager, self.arguments)

    def _launch(self, command, environment):
        # A surviving child retains the lease if its parent is killed. A second
        # supervisor cannot assume it has drained that unknown live controller.
        descriptors = () if self._lease_descriptor is None else (self._lease_descriptor,)
        return subprocess.Popen(command, env=environment, start_new_session=True, pass_fds=descriptors)

    def start_child(self, profile=None, arguments=None, *, application_port_override=None):
        from . import recovery
        if hasattr(self.manager, "root"):
            recovery.assert_start_allowed(self.manager, profile)
        admission = recovery.child_environment(self.manager) if hasattr(self.manager, "root") else {}
        if profile is None and not admission:
            assert_sqlite_writable(self.source_dir)
        args = list(self.arguments if arguments is None else arguments)
        if arguments is None and hasattr(self.manager, "launch_tls"):
            overlay = self.manager.launch_tls()
            for field, option in (("cert", "--cert"), ("key", "--key")):
                value = overlay.get(field)
                if value:
                    args = _set_argument(args, option, value)
            if profile is not None and overlay.get("cert") and overlay.get("key"):
                profile = copy.deepcopy(profile)
                profile.setdefault("controller_tls", {}).update(cert=overlay["cert"], key=overlay["key"])
                profile["controller_server_name"] = overlay["hostname"]
        elif arguments is not None and profile is not None:
            # Certificate staging/rollback provides an explicit reviewed pair.
            # A database profile's older bootstrap TLS paths cannot override it.
            profile = copy.deepcopy(profile)
            certificate, key = _argument(args, "--cert"), _argument(args, "--key")
            if certificate and key:
                profile.setdefault("controller_tls", {}).update(cert=certificate, key=key)
        if hasattr(self.manager, "root"):
            from .application_port import launch_arguments
            args = launch_arguments(self.manager, args, override=application_port_override)
        command, environment = child_launch(args, profile)
        environment.update(admission)
        self.child = self.launch(command, environment)
        self.current_profile = profile
        self.last_launch_arguments = command[3:]
        return command[3:]

    def activate(self, job):
        if job.get("operation") == "application-port":
            from .application_port import execute
            return execute(self, job)
        if job.get("operation") == "certificate":
            return self.rotate_certificate(job)
        profile = _profile(job["profile"])
        if job.get("operation") not in ("activate", "join"):
            raise RuntimeSafetyError("Unsupported runtime operation")
        active = self.manager.active_profile() or self.current_profile
        if active is not None:
            if active != profile:
                raise RuntimeSafetyError("Shared storage is already active; SQLite re-import or deployment replacement is refused before interrupting the current controller")
            # Recover the narrow crash window after active.json commit. The
            # remote child has already been allowed to write: never reimport
            # the older SQLite snapshot to 'retry' this same reviewed job.
            command, _ = child_launch(self.arguments, profile)
            if self.child is not None and (self.child.poll() is not None or self.current_profile != profile):
                if self.stop(self.child) is not True:
                    raise RuntimeSafetyError("Previous controller process group did not drain before recovery")
                self.child = None
            arguments = self.start_child(profile) if self.child is None else command[3:]
            result = {"deployment_id": profile["deployment_id"], "epoch": profile["epoch"], "recovered": True}
            self.manager.runtime_job_update(job["id"], "verified", {"phase": "active_profile_recovered", "result": result})
            return self._verify_active_child(job, profile, arguments, result)
        if "--ha" in self.arguments or os.environ.get("SEG_DATABASE_URL") or os.environ.get("SEG_TRAFFIC_DATABASE_URL"):
            raise RuntimeSafetyError("This controller already uses configured PostgreSQL storage; importing an unrelated local SQLite directory is refused")
        # Validate all launch prerequisites before interrupting a healthy child.
        child_launch(self.arguments, profile)
        self.manager.runtime_job_update(job["id"], "stopping", {"phase": "draining", "result": {"message": "Draining the complete controller process group before database migration"}})
        if self.stop(self.child) is not True:
            raise RuntimeSafetyError("Controller stop was not verified; no database snapshot or import was attempted")
        self.child = None
        if job["operation"] == "activate":
            result = self.migrate(self.source_dir, profile["metadata_dsn"], profile["traffic_dsn"], profile["deployment_id"], profile["epoch"])
        elif job["operation"] == "join":
            result = self.join(self.source_dir, profile)
        else:
            raise RuntimeSafetyError("Unsupported runtime operation")
        self.manager.runtime_job_update(job["id"], "verified", {"phase": "storage_verified", "result": {"deployment_id": profile["deployment_id"], "epoch": profile["epoch"], "source_fingerprint": result["source_fingerprint"], "backup_name": result["backup_name"]}})
        self.manager.commit_active_profile(profile)
        arguments = self.start_child(profile)
        return self._verify_active_child(job, profile, arguments, result)

    def rotate_certificate(self, job):
        from .certificates import _binding, revalidate_activation
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        private, material = job["private"], job["material"]
        old_profile = self.manager.active_profile() or self.current_profile
        context = self.manager.certificate_context()
        revalidate_activation(material, private["expected_fingerprint"], context)
        committed = self.manager.launch_tls()
        if committed.get("fingerprint_sha256") == private["expected_fingerprint"]:
            arguments = self.start_child(old_profile) if self.child is None else child_launch(_set_argument(_set_argument(self.arguments, "--cert", committed["cert"]), "--key", committed["key"]), self.current_profile)[0][3:]
            if not self._wait_certificate(arguments, self.current_profile, material["hostname"], private["expected_fingerprint"]):
                raise RuntimeSafetyError("The committed HTTPS identity has not recovered exact readiness")
            self._router_certificate(job["id"], "activate", material["certificate_pem"], material["hostname"], private["expected_fingerprint"], fresh=True)
            self.manager.runtime_job_update(job["id"], "applied", {"phase": "active", "result": {"fingerprint_sha256": private["expected_fingerprint"], "recovered": True}})
            return {"recovered": True}
        # A killed staging child may have published its context before the one
        # authoritative TLS pointer committed. Recover the committed old pair.
        baseline_tls = (old_profile or {}).get("controller_tls", {})
        baseline_cert = committed.get("cert") or baseline_tls.get("cert") or _argument(self.arguments, "--cert")
        baseline_key = committed.get("key") or baseline_tls.get("key") or _argument(self.arguments, "--key")
        if baseline_cert and context.get("cert_path") != baseline_cert:
            context.update(cert_path=baseline_cert, key_path=baseline_key, hostname=private["expected_hostname"])
            context["current_fingerprint"] = x509.load_pem_x509_certificate(Path(baseline_cert).read_bytes()).fingerprint(hashes.SHA256()).hex()
        binding = _binding(self.manager, context)
        current = context.get("current_fingerprint")
        if digest(binding) != private["expected_context_digest"] or current != private["expected_current_fingerprint"]:
            raise RuntimeSafetyError("The active certificate or deployment changed after review; no controller was stopped")
        directory = self.manager.root / "tls-revisions" / job["id"]
        certificate, key = directory / "certificate.pem", directory / "private-key.pem"
        self.manager._private_text(certificate, material["certificate_pem"])
        self.manager._private_text(key, material["private_key_pem"])
        check = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        check.load_cert_chain(str(certificate), str(key))
        old_args = _set_argument(_set_argument(self.arguments, "--cert", context["cert_path"]), "--key", context["key_path"])
        args = _set_argument(_set_argument(self.arguments, "--cert", str(certificate)), "--key", str(key))
        profile = copy.deepcopy(old_profile)
        if profile is not None:
            profile.setdefault("controller_tls", {}).update(cert=str(certificate), key=str(key))
            profile["controller_server_name"] = material["hostname"]
        child_launch(args, profile)
        self.manager.runtime_job_update(job["id"], "stopping", {"phase": "certificate_restart"})
        if self.stop(self.child) is not True:
            raise RuntimeSafetyError("The controller did not drain; certificate activation was refused")
        self.child = None
        try:
            actual_args = self.start_child(profile, arguments=args)
            ready = self._wait_certificate(actual_args, profile, material["hostname"], private["expected_fingerprint"])
            if not ready:
                raise RuntimeSafetyError("Replacement HTTPS identity did not pass readiness and fingerprint validation")
            self._router_certificate(job["id"], "activate", material["certificate_pem"], material["hostname"], private["expected_fingerprint"])
            # TLS has its own atomic pointer. Database profiles/epochs are not
            # rewritten by a certificate operation.
            self.manager.commit_launch_tls({"cert": str(certificate), "key": str(key), "hostname": material["hostname"], "fingerprint_sha256": private["expected_fingerprint"], "previous_cert": context["cert_path"], "previous_key": context["key_path"]})
            self.manager.runtime_job_update(job["id"], "applied", {"phase": "active", "result": {"fingerprint_sha256": private["expected_fingerprint"], "previous_pair_preserved": True}})
            return {"verified": True}
        except Exception:
            if self.manager.launch_tls().get("fingerprint_sha256") == private["expected_fingerprint"]:
                raise RuntimeSafetyError("The verified HTTPS identity committed; its completion receipt needs recovery, so the committed pair was retained") from None
            if self.child is not None:
                self.stop(self.child)
            self.child = None
            restored_args = self.start_child(old_profile, arguments=old_args)
            if not self._wait_certificate(restored_args, old_profile, private["expected_hostname"], private["expected_current_fingerprint"]):
                raise RuntimeSafetyError("Replacement HTTPS verification failed; the previous pair was selected but its readiness could not be confirmed") from None
            self._router_certificate(job["id"], "restore", Path(context["cert_path"]).read_text(), private["expected_hostname"], private["expected_current_fingerprint"])
            self.manager.runtime_job_update(job["id"], "rolled_back", {"phase": "previous_certificate_restored", "error": "Replacement HTTPS verification failed; the previous certificate and database profile were restored"})
            return {"rolled_back": True}

    def _router_certificate(self, identifier, phase, chain, hostname, fingerprint, *, fresh=False):
        """Commit local router trust only after its exact routed HTTPS proof.

        The fixed manager action receives public certificates only. Persist its
        exact request before submitting so supervisor recovery can safely replay
        a durable host operation despite intervening manager revisions.
        """
        if os.environ.get("PRTHAK_APPLIANCE") != "1":
            return
        from .appliance import NodeClient
        from .cluster_bootstrap import _public_bundle
        chain = _public_bundle(chain)
        if not chain:
            raise RuntimeSafetyError("Managed router verification requires public HTTPS certificate material")
        client = NodeClient()
        path = self.manager.root / "tls-revisions" / identifier / ("router-" + phase + ".json")
        request = None
        if path.exists():
            request = json.loads(path.read_text())
            if fresh:
                # A completed receipt proves a past operation. Recovery needs
                # a new live proof, while an uncertain in-flight reply must
                # retain the original idempotency key.
                try:
                    previous = client.job(request["request_id"])
                except KeyError:
                    previous = {"status": "unknown"}
                if previous.get("status") not in ("queued", "running"):
                    request = None
        if request is None:
            request = {"action": "web-tls", "request_id": uuid.uuid4().hex, "expected_revision": client.status()["revision"],
                       "certificate_chain": chain, "server_name": hostname}
            atomic_private_json(path, request)
        operation = client.submit(request)
        deadline = time.monotonic() + 180
        while operation.get("status") in ("queued", "running") and time.monotonic() < deadline:
            time.sleep(.5)
            operation = client.job(operation["id"])
        result = operation.get("result") or {}
        if operation.get("status") != "completed" or result.get("phase") != "web_tls_verified" or result.get("verified") is not True or result.get("router_ready") is not True or result.get("fingerprint_sha256") != fingerprint or result.get("server_name") != hostname:
            raise RuntimeSafetyError("Managed router did not verify the exact HTTPS identity; certificate activation was not committed")

    def _wait_certificate(self, arguments, profile, hostname, fingerprint):
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline and self.child.poll() is None:
            ready = probe_readiness(arguments, profile, tls_hostname=hostname) if self.probe is probe_readiness else self.probe(arguments, profile)
            if ready and self._certificate_matches(arguments, hostname, fingerprint):
                return True
            if self.stopping.wait(0.25):
                break
        return False

    @staticmethod
    def _certificate_matches(arguments, hostname, expected):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        host, port = _argument(arguments, "--listen", "127.0.0.1:8787").rsplit(":", 1)
        host = "127.0.0.1" if host in ("0.0.0.0", "localhost") else host
        try:
            context = ssl.create_default_context(cafile=_argument(arguments, "--cert"))
            context.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
            with socket.create_connection((host, int(port)), timeout=2) as connection:
                with context.wrap_socket(connection, server_hostname=hostname) as tls:
                    return x509.load_der_x509_certificate(tls.getpeercert(binary_form=True)).fingerprint(hashes.SHA256()).hex() == expected
        except (OSError, ValueError, ssl.SSLError):
            return False

    def _verify_active_child(self, job, profile, arguments, result):
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if self.child.poll() is not None:
                break
            if self.probe(arguments, profile):
                self.manager.runtime_job_update(job["id"], "applied", {"phase": "active", "result": {"deployment_id": profile["deployment_id"], "epoch": profile["epoch"], "active_revision": profile.get("active_revision"), "message": "New controller child verified against the exact active deployment profile"}})
                return result
            if self.stopping.wait(0.25):
                break
        self.stop(self.child)
        self.child = None
        raise RuntimeSafetyError("New controller failed exact deployment/revision readiness; SQLite fallback remains fenced")

    def run(self):
        directory = getattr(self.manager, "root", self.source_dir / "platform")
        with supervisor_lease(directory) as descriptor:
            self._lease_descriptor = descriptor
            try:
                if hasattr(self.manager, "recover_runtime_jobs"):
                    self.manager.recover_runtime_jobs()
                self._run_owned()
            finally:
                self._lease_descriptor = None

    def _run_owned(self):
        previous = {}
        for sig in (signal.SIGTERM, signal.SIGINT):
            previous[sig] = signal.signal(sig, lambda *_: self.stopping.set())
        try:
            while not self.stopping.is_set():
                try:
                    from .recovery import supervisor_tick
                    if hasattr(self.manager, "root") and supervisor_tick(self):
                        self.stopping.wait(.25)
                        continue
                    if hasattr(self.manager, "run_pending_provisioning"):
                        self.manager.run_pending_provisioning()
                    if hasattr(self.manager, "run_pending_appliance"):
                        self.manager.run_pending_appliance()
                    if hasattr(self.manager, "root"):
                        from .application_port import recover_incomplete
                        recover_incomplete(self.manager)
                    job = self.manager.claim_runtime_job()
                    if job:
                        try:
                            self.activate(job)
                        except Exception as error:
                            message = str(error) if isinstance(error, RuntimeSafetyError) else "Runtime activation failed; private connection details were not logged"
                            self.manager.runtime_job_update(job["id"], "failed", {"error": message})
                    if self.child is None or self.child.poll() is not None:
                        if self.child is not None:
                            if self.stop(self.child) is not True:
                                raise RuntimeSafetyError("Previous controller process group did not drain before restart")
                            self.child = None
                        profile = self.manager.active_profile()
                        self.start_child(profile)
                except Exception:
                    # Remain as the stable supervisor; never reopen a fenced
                    # SQLite source just because a remote dependency is down.
                    self.stopping.wait(2)
                self.stopping.wait(0.25)
        finally:
            try:
                if self.child is not None:
                    self.stop(self.child)
            finally:
                for sig, handler in previous.items():
                    signal.signal(sig, handler)
