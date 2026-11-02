"""Optional shared PostgreSQL persistence for multiple Prṛthak controller nodes.

All JSON read/modify/write transactions use database advisory transaction locks.
The existing Store methods never fall back to local SQLite when this adapter is used.
"""
from __future__ import annotations

import threading
import os
from collections.abc import Mapping
from contextlib import contextmanager
from datetime import timedelta

from .store import Store, now, parse_time


class DependencyUnavailable(RuntimeError):
    """Public-safe dependency failure; never include a DSN or driver error text."""


class Row(Mapping):
    """SQLite-compatible named and numeric row access, backed by driver tuples."""
    def __init__(self, names, values):
        self.names = tuple(names)
        self.values = tuple(values)
        self.named = dict(zip(self.names, self.values))

    def __getitem__(self, key):
        return self.values[key] if isinstance(key, int) else self.named[key]

    def __iter__(self):
        return iter(self.names)

    def __len__(self):
        return len(self.names)


class Cursor:
    def __init__(self, cursor):
        self.cursor = cursor
        self.names = [getattr(column, "name", None) or column[0] for column in (cursor.description or ())]

    def fetchone(self):
        values = self.cursor.fetchone()
        return None if values is None else Row(self.names, values)

    def fetchall(self):
        return [Row(self.names, values) for values in self.cursor.fetchall()]

    def __iter__(self):
        return iter(self.fetchall())


def postgres_sql(sql):
    """Translate the Store's small, fixed SQL subset without interpolating values."""
    import re
    ignore = bool(re.match(r"\s*INSERT\s+OR\s+IGNORE\s+INTO\b", sql, re.IGNORECASE))
    if ignore:
        sql = re.sub(r"INSERT\s+OR\s+IGNORE\s+INTO", "INSERT INTO", sql, count=1, flags=re.IGNORECASE)
    output, quote, index = [], None, 0
    while index < len(sql):
        char = sql[index]
        if quote:
            output.append(char)
            if char == quote:
                if index + 1 < len(sql) and sql[index + 1] == quote:
                    output.append(sql[index + 1])
                    index += 1
                else:
                    quote = None
        elif char in ("'", '"'):
            quote = char
            output.append(char)
        else:
            output.append("%s" if char == "?" else char)
        index += 1
    result = "".join(output)
    if ignore:
        result = result.rstrip().rstrip(";") + " ON CONFLICT DO NOTHING"
    return result


class Connection:
    dialect = "postgresql"

    def __init__(self, connection):
        self.connection = connection

    def execute(self, sql, parameters=()):
        return Cursor(self.connection.execute(postgres_sql(sql), tuple(parameters)))

    def executemany(self, sql, parameters):
        if hasattr(self.connection, "cursor"):
            with self.connection.cursor() as cursor:
                cursor.executemany(postgres_sql(sql), parameters)
        else:
            for row in parameters:
                self.execute(sql, row)

    def executescript(self, sql):
        # Only constant schema DDL passes here; no user text or quoted semicolons.
        for statement in sql.split(";"):
            if statement.strip():
                self.execute(statement)


class PostgresStore(Store):
    ha = True
    storage_kind = "postgresql"
    META_LOCK = 0x50525448414B0001
    TRAFFIC_LOCK = 0x50525448414B0002
    JOB_KEYS = {"health": 0x50525448414B0101, "traffic": 0x50525448414B0102, "backup": 0x50525448414B0103}

    def __init__(self, metadata_dsn, traffic_dsn, retention_hours=24, connector=None, initialize=True, deployment_id=None, epoch=None, _migration_context=None):
        if not isinstance(metadata_dsn, str) or not metadata_dsn.strip() or not isinstance(traffic_dsn, str) or not traffic_dsn.strip():
            raise ValueError("HA mode requires both shared PostgreSQL metadata and traffic DSNs")
        self._metadata_dsn = metadata_dsn
        self._traffic_dsn = traffic_dsn
        self.expected_deployment_id = deployment_id
        self.expected_deployment_epoch = epoch
        self._expected_import_id = None
        self._expected_source_fingerprint = None
        self._migration_context = _migration_context
        self.retention_hours = retention_hours
        self.lock = threading.RLock()
        self.flow_lock = threading.RLock()
        self._worker_pools = None
        self._worker_pool_pid = None
        self._worker_pool_supported = connector is None
        if connector is None:
            try:
                import psycopg
            except ImportError:
                raise RuntimeError("HA mode requires psycopg 3; install controller/requirements.txt") from None
            connector = psycopg.connect
            self._driver_errors = (psycopg.Error,)
        else:
            self._driver_errors = (ConnectionError, OSError)
        self._connector = connector
        if deployment_id is not None or epoch is not None:
            from .platform_runtime import verify_deployment
            markers = verify_deployment(metadata_dsn, traffic_dsn, deployment_id, epoch, connector=connector)
            self._expected_import_id = markers["metadata"]["import_id"]
            self._expected_source_fingerprint = markers["metadata"]["source_fingerprint"]
        elif _migration_context is None:
            # A legacy process may continue using genuinely unmanaged databases,
            # but cannot silently attach to an installed managed deployment.
            for namespace in ("metadata", "traffic"):
                connection = self._connect(namespace, autocommit=True)
                try:
                    self._verify_namespace(connection, namespace)
                finally:
                    connection.close()
        if initialize:
            self.initialize_schema()

    def enable_worker_pool(self, metadata_max=16, traffic_max=4, wait_seconds=5):
        """Called in a worker after fork; master/schema initialization stays direct."""
        if any(isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high for value, low, high in ((metadata_max, 1, 64), (traffic_max, 1, 16), (wait_seconds, 1, 15))):
            raise ValueError("Database worker pool bounds are invalid")
        if not self._worker_pool_supported:
            return
        if self._worker_pools is not None:
            if self._worker_pool_pid != os.getpid():
                raise RuntimeError("Database pools must be created after the worker fork")
            return
        from .pg_pool import WorkerPool
        def factory(namespace):
            return self._connect(namespace, autocommit=True, pool_limits=True)
        self._worker_pool_pid = os.getpid()
        self._worker_pools = {namespace: WorkerPool(lambda namespace=namespace: factory(namespace), maximum, wait_seconds, self._validate_pool_connection) for namespace, maximum in (("metadata", metadata_max), ("traffic", traffic_max))}

    @staticmethod
    def _validate_pool_connection(entry):
        # Reusing a socket must not bypass primary routing, disabled/expired
        # login, disabled database, or changed per-role/database GUC admission.
        connection = entry.connection
        row = connection.execute("SELECT NOT pg_is_in_recovery() AND r.rolcanlogin AND (r.rolvaliduntil IS NULL OR r.rolvaliduntil>clock_timestamp()) AND d.datallowconn AND current_setting('default_transaction_read_only')='off',COALESCE((SELECT md5(string_agg(s.setrole::text||':'||s.setdatabase::text||':'||s.setconfig::text,'|' ORDER BY s.setrole,s.setdatabase)) FROM pg_db_role_setting s WHERE s.setrole IN (0,r.oid) AND s.setdatabase IN (0,d.oid)),'') FROM pg_roles r JOIN pg_database d ON d.datname=current_database() WHERE r.rolname=session_user").fetchone()
        if not row or row[0] is not True or entry.settings_fingerprint is not None and row[1] != entry.settings_fingerprint:
            raise DependencyUnavailable("The pooled database session requires fresh primary/login admission")
        entry.settings_fingerprint = row[1]

    def close_worker_pool(self):
        if self._worker_pools is not None:
            for pool in self._worker_pools.values():
                pool.close()

    @contextmanager
    def _borrow(self, namespace):
        if self._worker_pools is None:
            connection = self._connect(namespace)
            try:
                yield connection, False
            finally:
                connection.close()
        else:
            from .pg_pool import PoolUnavailable
            if self._worker_pool_pid != os.getpid():
                raise DependencyUnavailable("Database connections cannot cross worker process boundaries")
            try:
                with self._worker_pools[namespace].connection() as connection:
                    yield connection, True
            except PoolUnavailable:
                raise DependencyUnavailable("Shared PostgreSQL " + namespace + " connection capacity is unavailable; retry") from None

    def _verify_namespace(self, connection, namespace):
        try:
            if self.expected_deployment_id is None:
                exists = connection.execute("SELECT to_regclass('public.runtime_deployment')").fetchone()
                if not exists or not exists[0]:
                    return
                if self._migration_context is None:
                    if connection.execute("SELECT 1 FROM runtime_deployment LIMIT 1").fetchone():
                        raise ValueError()
                    return
            row = connection.execute("SELECT data FROM runtime_deployment WHERE id='active'").fetchone()
            import json
            marker = json.loads(row[0]) if row else {}
            if self._migration_context is not None:
                if not marker:
                    if connection.execute("SELECT 1 FROM runtime_deployment LIMIT 1").fetchone():
                        raise ValueError()
                    return
                if marker.get("namespace") != namespace or marker.get("state") not in ("IMPORTING", "VERIFIED", "READY") or any(marker.get(key) != self._migration_context.get(key) for key in ("deployment_id", "epoch", "import_id", "source_fingerprint")):
                    raise ValueError()
                return
            if marker.get("state") != "READY" or marker.get("namespace") != namespace or marker.get("deployment_id") != self.expected_deployment_id or marker.get("epoch") != self.expected_deployment_epoch or marker.get("import_id") != self._expected_import_id or marker.get("source_fingerprint") != self._expected_source_fingerprint:
                raise ValueError()
        except Exception:
            raise DependencyUnavailable("Shared PostgreSQL deployment requires its exact ready identity/epoch; unbound access and local fallback are forbidden") from None

    def _connect(self, namespace, autocommit=False, *, pool_limits=False):
        dsn = self._metadata_dsn if namespace == "metadata" else self._traffic_dsn
        try:
            options = {}
            if pool_limits:
                # Startup GUCs bound even the very first role/primary admission
                # query, before a handler transaction can SET LOCAL its limits.
                from psycopg.conninfo import conninfo_to_dict
                previous = conninfo_to_dict(dsn).get("options", "")
                options["options"] = previous + " -c statement_timeout=15000 -c lock_timeout=5000 -c idle_in_transaction_session_timeout=30000"
            return self._connector(dsn, autocommit=autocommit, connect_timeout=3, target_session_attrs="read-write", application_name="prthak-controller", **options)
        except Exception:
            raise DependencyUnavailable(f"Shared PostgreSQL {namespace} dependency unavailable") from None

    @contextmanager
    def _transaction(self, namespace, lock_key):
        try:
            with self._borrow(namespace) as (connection, pooled), connection.transaction() if pooled else connection:
                connection.execute("SET LOCAL statement_timeout = '15s'")
                connection.execute("SET LOCAL lock_timeout = '5s'")
                connection.execute("SET LOCAL idle_in_transaction_session_timeout = '30s'")
                connection.execute("SET LOCAL synchronous_commit = on")
                connection.execute("SELECT pg_advisory_xact_lock(%s)", (lock_key,))
                self._verify_namespace(connection, namespace)
                yield Connection(connection)
        except self._driver_errors:
            raise DependencyUnavailable(f"Shared PostgreSQL {namespace} transaction unavailable") from None

    def meta(self):
        return self._transaction("metadata", self.META_LOCK)

    def traffic(self):
        return self._transaction("traffic", self.TRAFFIC_LOCK)

    @contextmanager
    def _read_transaction(self, namespace):
        try:
            with self._borrow(namespace) as (connection, pooled), connection.transaction() if pooled else connection:
                connection.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
                connection.execute("SET LOCAL statement_timeout = '15s'")
                self._verify_namespace(connection, namespace)
                yield Connection(connection)
        except self._driver_errors:
            raise DependencyUnavailable(f"Shared PostgreSQL {namespace} read unavailable") from None

    def read_meta(self):
        return self._read_transaction("metadata")

    def read_traffic(self):
        return self._read_transaction("traffic")

    def initialize_schema(self):
        with self.meta() as db:
            db.execute("CREATE TABLE IF NOT EXISTS runtime_deployment (id TEXT PRIMARY KEY, data TEXT NOT NULL)")
            for table in ("servers", "policies", "groups", "sessions", "alerts", "audit", "tokens", "controller_nodes", "firewall_changes"):
                db.execute(f"CREATE TABLE IF NOT EXISTS {table} (id TEXT PRIMARY KEY, data TEXT NOT NULL)")
            from .locations import initialize as initialize_locations
            initialize_locations(db)
            from .security import initialize
            initialize(db)
            from .service_groups import initialize as initialize_service_groups
            initialize_service_groups(db)
            from .policy_deployments import initialize as initialize_policy_deployments
            initialize_policy_deployments(db)
            from .learning_policies import initialize as initialize_learning_policies
            initialize_learning_policies(db)
            from .maintenance import initialize as initialize_maintenance
            initialize_maintenance(db)
            from .learning_targets import initialize as initialize_learning_targets
            initialize_learning_targets(self, db)
            from .agent_settings import initialize as initialize_agent_settings
            initialize_agent_settings(db)
            from .endpoint_configuration import initialize as initialize_endpoint_configuration
            initialize_endpoint_configuration(db)
            from .hit_monitoring import initialize as initialize_hit_monitoring
            initialize_hit_monitoring(db)
            from .notifications import initialize as initialize_notifications
            initialize_notifications(db)
            from .auth import initialize as initialize_auth
            initialize_auth(db)
            from .server_management import initialize as initialize_server_management
            initialize_server_management(db)
            from .managed import initialize as initialize_managed, backfill
            initialize_managed(db)
            backfill(self, db)
            from .metadata import initialize as initialize_metadata, reconcile_all
            initialize_metadata(db)
            reconcile_all(self, db)
            from .application_groups import sync as sync_application_groups
            sync_application_groups(self, db)
        with self.traffic() as db:
            db.execute("CREATE TABLE IF NOT EXISTS runtime_deployment (id TEXT PRIMARY KEY, data TEXT NOT NULL)")
            db.executescript("""
                CREATE TABLE IF NOT EXISTS batches (
                    batch_key TEXT PRIMARY KEY, server_id TEXT NOT NULL,
                    session_id TEXT NOT NULL, data TEXT NOT NULL,
                    received_at TEXT NOT NULL, processed INTEGER NOT NULL DEFAULT 0
                );
                CREATE INDEX IF NOT EXISTS batches_pending ON batches(processed);
                CREATE TABLE IF NOT EXISTS flows (
                    id BIGSERIAL PRIMARY KEY, batch_key TEXT NOT NULL, event_index INTEGER NOT NULL,
                    server_id TEXT NOT NULL, session_id TEXT NOT NULL, source_ip TEXT NOT NULL,
                    port INTEGER NOT NULL, protocol TEXT NOT NULL, verdict TEXT NOT NULL,
                    count INTEGER NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
                    UNIQUE(batch_key, event_index)
                );
                CREATE INDEX IF NOT EXISTS flows_time ON flows(last_seen);
                CREATE INDEX IF NOT EXISTS flows_server ON flows(server_id, last_seen);
            """)
            from .learning_policies import initialize_traffic as initialize_learning_traffic
            initialize_learning_traffic(db)
            from .hit_monitoring import initialize_traffic as initialize_hit_traffic
            initialize_hit_traffic(db)
            from .traffic_capture import initialize as initialize_traffic_capture
            initialize_traffic_capture(db)

    def readiness(self):
        checks = {}
        for namespace, table in (("metadata", "servers"), ("traffic", "batches")):
            connection = None
            try:
                connection = self._connect(namespace, autocommit=True)
                connection.execute("SET statement_timeout = '3s'")
                self._verify_namespace(connection, namespace)
                connection.execute(f"SELECT 1 FROM {table} LIMIT 0")
                if namespace == "metadata":
                    for required in ("hit_monitors", "hit_monitor_targets", "hit_monitor_reviews"):
                        connection.execute(f"SELECT 1 FROM {required} LIMIT 0")
                    for required in ("maintenance_backups", "maintenance_plans", "maintenance_settings"):
                        connection.execute(f"SELECT 1 FROM {required} LIMIT 0")
                    for required in ("policy_deployments", "policy_deployment_targets"):
                        connection.execute(f"SELECT 1 FROM {required} LIMIT 0")
                    for required in ("learning_evidence", "learning_evidence_receipts", "learning_allow_policies", "learning_allow_hosts", "learning_allow_history", "learning_policy_previews"):
                        connection.execute(f"SELECT 1 FROM {required} LIMIT 0")
                    for required in ("service_groups", "service_group_revisions", "auth_users", "auth_sessions", "auth_states", "server_reservations", "retired_endpoints", "server_lifecycle_plans", "metadata_subnets", "metadata_ip_profiles", "metadata_plans", "locations", "firewall_changes", "security_event_receipts", "security_alert_windows", "controller_nodes", "policy_revisions", "bundle_history", "managed_rollouts", "managed_approvals", "managed_outcomes"):
                        connection.execute(f"SELECT 1 FROM {required} LIMIT 0")
                else:
                    for required in ("hit_batches", "hit_events", "hit_limits"):
                        connection.execute(f"SELECT 1 FROM {required} LIMIT 0")
                checks[namespace] = True
            except Exception:
                checks[namespace] = False
            finally:
                if connection is not None:
                    connection.close()
        return checks

    def run_job(self, name, callback):
        """Hold a real PostgreSQL session lock throughout the entire callback.

        A crashed controller's connection releases its lock. RMW transaction locks
        and idempotent batches also guard every actual write if leadership changes.
        """
        if name not in self.JOB_KEYS:
            raise ValueError("Unknown background job")
        connection = self._connect("metadata", autocommit=True)
        acquired = False
        try:
            connection.execute("SET statement_timeout = '5s'")
            self._verify_namespace(connection, "metadata")
            acquired = bool(connection.execute("SELECT pg_try_advisory_lock(%s)", (self.JOB_KEYS[name],)).fetchone()[0])
            if not acquired:
                return None
            return callback()
        except self._driver_errors:
            raise DependencyUnavailable("Shared PostgreSQL background job dependency unavailable") from None
        finally:
            try:
                if acquired and not connection.closed:
                    connection.execute("SELECT pg_advisory_unlock(%s)", (self.JOB_KEYS[name],))
            except Exception:
                pass
            connection.close()

    def register_node(self, node):
        with self.lock, self.meta() as db:
            self._put(db, "controller_nodes", node)

    def cluster_nodes(self):
        nodes = self.all("controller_nodes")
        result = []
        for node in nodes:
            stale = now() - parse_time(node["last_seen"]) > timedelta(seconds=30)
            ready = bool(node.get("ready")) and not stale
            result.append({**node, "status": "offline" if stale else "healthy" if ready else "unavailable", "role": "active" if ready else "unavailable", "ready": ready})
        return sorted(result, key=lambda node: node["id"])
