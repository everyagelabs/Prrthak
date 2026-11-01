from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import secrets
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path


def now():
    return datetime.now(timezone.utc)


def stamp(value=None):
    return (value or now()).isoformat(timespec="seconds").replace("+00:00", "Z")


def parse_time(value):
    if not isinstance(value, str) or len(value) > 40:
        raise ValueError("Invalid timestamp")
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None:
        raise ValueError("Timestamp must include timezone")
    return result.astimezone(timezone.utc)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def matches(tags, selector):
    return all(tags.get(key) == value for key, value in selector.items())


def validate_tags(value):
    if not isinstance(value, dict) or len(value) > 32:
        raise ValueError("Tags and selectors must be objects with at most 32 entries")
    for key, val in value.items():
        if not isinstance(key, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,63}", key):
            raise ValueError("Invalid tag key")
        if not isinstance(val, str) or not val or len(val) > 128:
            raise ValueError("Invalid tag value")
    return dict(value)


def validate_port(value):
    if not isinstance(value, dict):
        raise ValueError("Service must be an object")
    port = value.get("port")
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError("Port must be an integer from 1 to 65535")
    protocol = value.get("protocol", "tcp")
    if protocol not in ("tcp", "udp"):
        raise ValueError("Protocol must be tcp or udp")
    return {"port": port, "protocol": protocol}


def validate_policy(value):
    if not isinstance(value, dict):
        raise ValueError("Policy must be an object")
    if value.get("summary_only") or any(isinstance(service,dict) and service.get("sources_omitted") for service in (value.get("services") if isinstance(value.get("services"),list) else [])):
        raise ValueError("Policy navigation is not exact source data; fetch canonical detail before editing")
    name = value.get("name", "")
    if not isinstance(name, str) or not name.strip() or len(name) > 120:
        raise ValueError("Policy name is required (max 120 characters)")
    mode = value.get("mode", "monitor")
    if mode not in ("monitor", "enforce"):
        raise ValueError("Mode must be monitor or enforce")
    services = value.get("services", [])
    if not isinstance(services, list) or not services or len(services) > 100:
        raise ValueError("Provide between 1 and 100 services")
    normalized = []
    for service in services:
        if not isinstance(service, dict):
            raise ValueError("Service must be an object")
        if "service_group_id" in service:
            identifier = service["service_group_id"]
            if not isinstance(identifier, str) or not identifier or len(identifier) > 100:
                raise ValueError("service_group_id must identify an existing saved service group")
            if "port" in service or "protocol" in service:
                raise ValueError("Choose a service group or a single port/protocol for each service row")
            item = {"service_group_id": identifier}
        else:
            item = validate_port(service)
        sources = service.get("sources", [])
        if not isinstance(sources, list) or len(sources) > 1000:
            raise ValueError("Invalid sources list")
        try:
            if any(not isinstance(source, str) for source in sources):
                raise ValueError("Sources must be IP or CIDR strings")
            item["sources"] = sorted({str(ipaddress.ip_network(source, strict=False)) for source in sources})
        except (ValueError, TypeError):
            raise ValueError("Every source must be an IP address or CIDR")
        item["source_selector"] = validate_tags(service.get("source_selector", {}))
        source_group_ids = service.get("source_group_ids", [])
        if not isinstance(source_group_ids, list) or len(source_group_ids) > 100 or any(not isinstance(identifier, str) or not identifier or len(identifier) > 100 for identifier in source_group_ids):
            raise ValueError("source_group_ids must be a list of up to 100 saved server group IDs")
        item["source_group_ids"] = sorted(set(source_group_ids))
        normalized.append(item)
    selector = validate_tags(value.get("selector", {}))
    group_ids = value.get("group_ids", [])
    if not isinstance(group_ids, list) or len(group_ids) > 100 or any(not isinstance(identifier, str) or not identifier or len(identifier) > 100 for identifier in group_ids):
        raise ValueError("group_ids must be a list of up to 100 saved group IDs")
    if group_ids and selector:
        raise ValueError("Choose saved groups or a tag selector, not both")
    return {"name": name.strip(), "selector": selector, "group_ids": sorted(set(group_ids)), "mode": mode, "services": normalized}


class LearningExpired(ValueError):
    """The durable upload grace period for a learning session has elapsed."""


class Store:
    ha = False
    storage_kind = "sqlite"
    lab_approvals = False
    approval_production = False
    approval_demo = False

    def __init__(self, data_dir, retention_hours=24):
        from .platform_runtime import assert_sqlite_writable
        assert_sqlite_writable(data_dir)
        self.path = Path(data_dir)
        self.path.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.meta_path = self.path / "inventory.sqlite3"
        self.traffic_path = self.path / "traffic.sqlite3"
        self.retention_hours = retention_hours
        self.lock = threading.RLock()
        self.flow_lock = threading.RLock()
        with self.meta() as db:
            for table in ("servers", "policies", "groups", "sessions", "alerts", "audit", "tokens", "firewall_changes"):
                db.execute(f"CREATE TABLE IF NOT EXISTS {table} (id TEXT PRIMARY KEY, data TEXT NOT NULL)")
            from .locations import initialize as initialize_locations
            initialize_locations(db)
            from .security import initialize
            initialize(db)
            from .service_groups import initialize as initialize_service_groups
            initialize_service_groups(db)
            from .learning_policies import initialize as initialize_learning_policies
            initialize_learning_policies(db)
            from .maintenance import initialize as initialize_maintenance
            initialize_maintenance(db)
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
            db.executescript("""
                CREATE TABLE IF NOT EXISTS batches (
                    batch_key TEXT PRIMARY KEY, server_id TEXT NOT NULL,
                    session_id TEXT NOT NULL, data TEXT NOT NULL,
                    received_at TEXT NOT NULL, processed INTEGER NOT NULL DEFAULT 0
                );
                CREATE INDEX IF NOT EXISTS batches_pending ON batches(processed);
                CREATE TABLE IF NOT EXISTS flows (
                    id INTEGER PRIMARY KEY, batch_key TEXT NOT NULL, event_index INTEGER NOT NULL,
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
        self.meta_path.chmod(0o600)
        self.traffic_path.chmod(0o600)

    @contextmanager
    def meta(self):
        from .platform_runtime import sqlite_storage_guard
        with sqlite_storage_guard(self.path):
            db = sqlite3.connect(self.meta_path, timeout=20)
            try:
                db.execute("PRAGMA journal_mode=WAL")
                db.execute("PRAGMA busy_timeout=20000")
                with db:
                    yield db
            finally:
                db.close()

    @contextmanager
    def traffic(self):
        from .platform_runtime import sqlite_storage_guard
        with sqlite_storage_guard(self.path):
            db = sqlite3.connect(self.traffic_path, timeout=20)
            db.row_factory = sqlite3.Row
            try:
                db.execute("PRAGMA journal_mode=WAL")
                db.execute("PRAGMA synchronous=FULL")
                db.execute("PRAGMA busy_timeout=20000")
                with db:
                    yield db
            finally:
                db.close()

    @contextmanager
    def read_meta(self):
        from .platform_runtime import sqlite_storage_guard
        with sqlite_storage_guard(self.path):
            db=sqlite3.connect(self.meta_path.resolve().as_uri()+"?mode=ro",uri=True,timeout=20)
            try:
                db.execute("PRAGMA query_only=ON")
                db.execute("PRAGMA busy_timeout=20000")
                yield db
            finally:
                db.close()

    def read_traffic(self):
        return self.traffic()

    def readiness(self):
        checks = {}
        for name, context in (("metadata", self.meta), ("traffic", self.traffic)):
            try:
                with context() as db:
                    db.execute("SELECT 1").fetchone()
                    required = ("hit_monitors", "hit_monitor_targets", "hit_monitor_reviews") if name == "metadata" else ("hit_batches", "hit_events", "hit_limits")
                    for table in required:
                        db.execute(f"SELECT 1 FROM {table} LIMIT 0")
                checks[name] = True
            except Exception:
                checks[name] = False
        return checks

    @staticmethod
    def run_job(name, callback):
        return callback()

    @staticmethod
    def _all(db, table):
        return [json.loads(row[0]) for row in db.execute(f"SELECT data FROM {table}")]

    @staticmethod
    def _get(db, table, identifier):
        row = db.execute(f"SELECT data FROM {table} WHERE id=?", (identifier,)).fetchone()
        return json.loads(row[0]) if row else None

    @staticmethod
    def _put(db, table, value):
        if table=="policies":
            from .policy_views import encoded_policy
            encoded=encoded_policy(value)
        else:
            if table=="learning_policy_previews":
                from .review_limits import encoded_size
                encoded_size(value)
            encoded=json.dumps(value,separators=(",",":"))
        db.execute(f"INSERT INTO {table}(id,data) VALUES(?,?) ON CONFLICT(id) DO UPDATE SET data=excluded.data", (value["id"], encoded))

    def all(self, table):
        with self.read_meta() as db:
            return self._all(db, table)

    def get(self, table, identifier):
        with self.read_meta() as db:
            value = self._get(db, table, identifier)
            if value is None:
                raise KeyError(identifier)
            return value

    def audit(self, action, actor, details, db=None):
        value = {"id": str(uuid.uuid4()), "action": action, "actor": actor, "details": details, "created_at": stamp()}
        if db is not None:
            self._put(db, "audit", value)
        else:
            with self.lock, self.meta() as connection:
                self._put(connection, "audit", value)

    @staticmethod
    def public(server):
        result = {key: value for key, value in server.items() if not key.startswith("_")}
        Store._heartbeat_timeout(result)
        result["listeners"] = [dict(listener) for listener in server.get("listeners", [])]
        result["discovery_changes"] = [dict(change) for change in server.get("discovery_changes", [])]
        for listener in result["listeners"] + result["discovery_changes"]:
            if listener.get("is_new") and listener.get("new_until") and parse_time(listener["new_until"]) <= now():
                listener["is_new"] = False
        return result

    @staticmethod
    def _heartbeat_timeout(server):
        interval = server.get("control_interval_seconds", 60)
        # Legacy/corrupt records retain the established default; reported values
        # are validated separately and cannot extend this bound arbitrarily.
        if isinstance(interval, bool) or not isinstance(interval, int) or not 5 <= interval <= 3600:
            interval = 60
        server["control_interval_seconds"] = interval
        server["heartbeat_timeout_seconds"] = max(180, 3 * interval)
        return server["heartbeat_timeout_seconds"]

    @staticmethod
    def _heartbeat_stale(server, at=None):
        return ((at or now()) - parse_time(server["last_seen"])).total_seconds() > Store._heartbeat_timeout(server)

    @staticmethod
    def _listener_key(listener):
        return digest([listener["protocol"], listener["port"], listener.get("address", "")])

    @staticmethod
    def _listener_metadata(listener):
        # Process restarts change PIDs routinely; they do not imply a new service.
        return tuple(listener.get(key, "") for key in ("process", "service", "application", "systemd_unit"))

    @staticmethod
    def _discovery_state(server, at=None):
        at = at or now()
        scanned = server.get("last_discovery_at")
        interval = server.get("discovery_interval_seconds", 900)
        stale = not scanned or (at - parse_time(scanned)).total_seconds() > interval
        server["discovery_status"] = "error" if server.get("discovery_error") else ("unknown" if not scanned else "stale" if stale else "current")
        server["discovery_stale"] = stale
        server["next_discovery_at"] = stamp(parse_time(scanned) + timedelta(seconds=interval)) if scanned else None
        heartbeat_stale = Store._heartbeat_stale(server, at)
        from .service_health import expectations, ready as policy_health_ready
        server["policy_expectation_pending"] = not policy_health_ready(server)
        if server["discovery_status"] != "current" or heartbeat_stale:
            server["service_health_status"] = "unknown"
        else:
            current = {(item["protocol"], item["port"]) for item in server.get("listeners", [])}
            missing = any((service["protocol"], service["port"]) not in current for service in expectations(server))
            server["service_health_status"] = "degraded" if missing else "unknown" if server["policy_expectation_pending"] else "healthy"
        for listener in server.get("listeners", []) + server.get("discovery_changes", []):
            if listener.get("is_new") and listener.get("new_until") and parse_time(listener["new_until"]) <= at:
                listener["is_new"] = False

    def _record_discovery(self, db, server, listeners, scanned_at):
        """Only a fresh successful scan may replace inventory or generate events."""
        identifier, hostname = server["id"], server["hostname"]
        baselined = server.get("_baselined", False)
        previous = {self._listener_key(listener): listener for listener in server.get("listeners", [])}
        current = {}
        changes = []
        # Reuse-port sockets/workers may produce repeated endpoint rows. Canonicalize
        # one stable endpoint record so PID ordering cannot create duplicate events.
        canonical = {}
        for listener in listeners:
            key = self._listener_key(listener)
            rank = (sum(bool(listener.get(field)) for field in ("process", "service", "application", "systemd_unit")), self._listener_metadata(listener), -listener.get("pid", 0))
            previous_choice = canonical.get(key)
            if previous_choice is None or rank > previous_choice[0]:
                canonical[key] = (rank, listener)
        for _, listener in canonical.values():
            key = self._listener_key(listener)
            old = previous.get(key)
            item = dict(listener)
            item["first_seen"] = old.get("first_seen", server.get("last_discovery_at", scanned_at)) if old else scanned_at
            item["last_seen"] = scanned_at
            item["is_new"] = bool(old and old.get("is_new"))
            for field in ("new_until", "change_kind", "change_detected_at", "discovery_alert_id"):
                if old and field in old:
                    item[field] = old[field]
            change = "new" if old is None else "changed" if self._listener_metadata(old) != self._listener_metadata(item) else None
            if change:
                alert_id = f"discovery:{identifier}:{key[:16]}:{uuid.uuid4()}"
                item.update({"is_new": True, "new_until": stamp(parse_time(scanned_at) + timedelta(hours=24)), "change_kind": change, "change_detected_at": scanned_at, "discovery_alert_id": alert_id})
                details = {**item, "listener_key": key, "detected_at": scanned_at, "initial_inventory": not baselined}
                label = item.get("service") or item.get("application") or item.get("process") or "unidentified service"
                event_kind = "service_discovered" if change == "new" else "service_changed"
                message = f"{'Discovered' if change == 'new' else 'Service changed:'} {label} on {hostname} · {item['port']}/{item['protocol']}"
                self._event(db, alert_id, event_kind, "info" if not baselined else "warning", identifier, message, details)
                changes.append({"kind": change, **item, "detected_at": scanned_at})
            self._resolve(db, f"listener:{identifier}:{key}", identifier, f"Listener recovered: {hostname} · {item['port']}/{item['protocol']}")
            self._resolve(db, f"listener:{identifier}:{item['protocol']}:{item['port']}", identifier, f"Listener recovered: {hostname} · {item['port']}/{item['protocol']}")
            current[key] = item
        for key, listener in previous.items():
            if key not in current:
                details = {**listener, "listener_key": key, "detected_at": scanned_at}
                self._event(db, f"listener:{identifier}:{key}", "service_down", "warning", identifier, f"Previously observed listener disappeared: {hostname} · {listener['port']}/{listener['protocol']}", details)
                changes.append({"kind": "removed", **listener, "is_new": False, "detected_at": scanned_at})
        server["listeners"] = sorted(current.values(), key=lambda item: (item["protocol"], item["port"], item.get("address", "")))
        server["discovery_changes"] = changes
        previous_scan = server.get("last_discovery_at")
        # Retried unacknowledged inventory (including an agent clock slightly
        # ahead of ours) is not a new post-policy discovery sequence.
        if not previous_scan or parse_time(scanned_at) > parse_time(previous_scan):
            server["_discovery_revision"] = server.get("_discovery_revision", 0) + 1
        server["last_discovery_at"] = scanned_at
        server["discovered_at"] = scanned_at
        server["discovery_error"] = ""
        server["_baselined"] = True


    @staticmethod
    def _collector_state(server, sessions, at=None):
        """Keep requested collection distinct from the endpoint's last acknowledgement."""
        from .learning import collector_state
        collector_state(Store, server, sessions, at or now())

    def servers(self):
        from .locations import decorate
        from .inventory_views import server_rows
        with self.read_meta() as db:
            locations = self._all(db, "locations")
            return sorted((self.public(decorate(server, locations)) for server in server_rows(db)), key=lambda item: item["hostname"])

    def server(self, identifier):
        from .locations import decorate
        with self.read_meta() as db:
            server = self._get(db, "servers", identifier)
            if not server:
                raise KeyError(identifier)
            return self.public(decorate(server, self._all(db, "locations")))

    @staticmethod
    def _group_members(group, servers, locations=()):
        if group["type"] == "dynamic":
            # Never treat a malformed/empty dynamic selector as a fleet-wide selector.
            from .locations import reserved, selector as normalize_selector
            selector = normalize_selector(group.get("selector", {}), locations, strict=False)
            valid_ids = {record["id"] for record in locations}
            return {server["id"] for server in servers if selector and matches({**{key: val for key, val in server.get("tags", {}).items() if not reserved(key)}, **({"location_id": server["location_id"]} if server.get("location_id") in valid_ids else {})}, selector)}
        selected = set(group.get("server_ids", []))
        return {server["id"] for server in servers if server["id"] in selected}

    def _public_group(self, group, servers, locations=()):
        from .application_groups import public as public_application_group
        members = sorted(self._group_members(group, servers, locations))
        return {**public_application_group(group), "member_ids": members, "member_count": len(members)}

    def groups(self):
        from .inventory_views import server_rows
        with self.read_meta() as db:
            servers = list(server_rows(db))
            return sorted((self._public_group(group, servers, self._all(db, "locations")) for group in self._all(db, "groups")), key=lambda group: group["name"].casefold())

    def save_group(self, value, actor, identifier=None):
        name = value.get("name", "")
        if not isinstance(name, str) or not name.strip() or len(name) > 120:
            raise ValueError("Group name is required (max 120 characters)")
        group_type = value.get("type")
        if group_type not in ("dynamic", "static"):
            raise ValueError("Group type must be dynamic or static")
        selector = validate_tags(value.get("selector", {}))
        server_ids = value.get("server_ids", [])
        if not isinstance(server_ids, list) or len(server_ids) > 20000 or any(not isinstance(server_id, str) or not server_id or len(server_id) > 100 for server_id in server_ids):
            raise ValueError("server_ids must be a list of enrolled server IDs")
        if group_type == "dynamic" and (not selector or server_ids):
            raise ValueError("Dynamic groups require a nonempty tag selector and no static server IDs")
        if group_type == "static" and selector:
            raise ValueError("Static groups use server IDs and cannot have a tag selector")
        with self.lock, self.meta() as db:
            old = self._get(db, "groups", identifier) if identifier else None
            if identifier and not old:
                raise KeyError(identifier)
            for server_id in server_ids:
                if not self._get(db, "servers", server_id):
                    raise ValueError("Static group contains an unknown enrolled server")
            from .locations import selector as normalize_selector
            selector = normalize_selector(selector, self._all(db, "locations"))
            from .application_groups import equivalent_group, managed as managed_application_group
            if old is None:
                old = equivalent_group(self._all(db, "groups"), selector) if group_type == "dynamic" else None
                if old:
                    identifier = old["id"]
            if old and managed_application_group(old) and (group_type != "dynamic" or selector != old["selector"] or server_ids):
                raise ValueError("Application group membership follows its application tag; create a custom group for a different scope")
            group = {"id": identifier or str(uuid.uuid4()), "name": name.strip(), "type": group_type, "selector": selector, "server_ids": sorted(set(server_ids)), "created_at": old["created_at"] if old else stamp(), "updated_at": stamp()}
            if old and managed_application_group(old):
                group.update({key: old[key] for key in ("origin", "managed", "application")})
            self._put(db, "groups", group)
            self.compile_all(db)
            self.audit("group.updated" if old else "group.created", actor, {"group_id": group["id"], "name": group["name"], "type": group_type}, db)
            return self._public_group(group, self._all(db, "servers"), self._all(db, "locations"))

    def delete_group(self, identifier, actor):
        with self.lock, self.meta() as db:
            group = self._get(db, "groups", identifier)
            if not group:
                raise KeyError(identifier)
            from .application_groups import managed as managed_application_group
            if managed_application_group(group):
                raise ValueError("Application groups are maintained from server application tags and cannot be deleted")
            if any(identifier in policy.get("group_ids", []) or any(identifier in service.get("source_group_ids", []) for service in policy.get("services", [])) for policy in self._all(db, "policies")):
                raise ValueError("Group is referenced by a policy; remove that policy reference before deleting the group")
            db.execute("DELETE FROM groups WHERE id=?", (identifier,))
            self.compile_all(db)
            self.audit("group.deleted", actor, {"group_id": identifier}, db)

    def compile_all(self, db):
        from .managed import record_bundle
        servers = self._all(db, "servers")
        from .application_groups import sync as sync_application_groups
        sync_application_groups(self, db, servers)
        from .service_groups import effective_bundles
        compiled = effective_bundles(self, db, servers=servers)
        matched = compiled["matched"]
        maximums = {row[0]: row[1] for row in db.execute("SELECT server_id,MAX(version) FROM bundle_history GROUP BY server_id").fetchall()}
        writes, histories = [], []
        direct_policies = {policy["id"]:policy for policy in self._all(db,"policies")}
        direct_validity = {}
        for server in servers:
            payload = compiled["payloads"][server["id"]]
            from .service_health import sync as sync_service_expectations
            health_changed = sync_service_expectations(server, payload["services"], "ordinary")
            compiled_digest = digest(payload)
            old = server.get("_compiled", {})
            recovery_floor = server.get("_recovery_version_floor", 0)
            if isinstance(recovery_floor, bool) or not isinstance(recovery_floor, int) or recovery_floor < 0:
                raise ValueError("Recovery policy version floor is invalid")
            # A restored database can contain an older desired snapshot while
            # retaining newer immutable safety history. Reissue intent above
            # that floor; never ask endpoints to replay a lower version.
            changed = compiled_digest != old.get("digest") or maximums.get(server["id"], 0) > old.get("version", 0) or bool(recovery_floor and recovery_floor >= old.get("version", 0))
            matches_changed = server.get("matched_policy_ids", []) != matched.get(server["id"], [])
            if changed:
                if old and maximums.get(server["id"], 0) < old["version"]:
                    record_bundle(db, old)
                version = max(old.get("version", 0), maximums.get(server["id"], 0), recovery_floor) + 1
                server["_compiled"] = {**payload, "server_id": server["id"], "version": version, "digest": compiled_digest, "generated_at": stamp(), "service_group_snapshots": compiled["snapshots"].get(server["id"], [])}
                historical = {**server["_compiled"], "actor": "compiler", "reason": "Effective policy changed", "created_at": server["_compiled"]["generated_at"]}
                histories.append((server["id"] + ":" + str(version), server["id"], version, compiled_digest, historical["created_at"], json.dumps(historical, sort_keys=True)))
                server["desired_version"] = version
                if server.get("apply_status") not in ("error", "rolled_back"):
                    server["apply_status"] = "pending" if server.get("applied_version") != version else "synced"
            server["matched_policy_ids"] = matched.get(server["id"], [])
            from .managed import reconcile_direct
            authority_changed = reconcile_direct(self, db, server, direct_policies, direct_validity)
            if changed or matches_changed or health_changed or authority_changed:
                writes.append((server["id"], json.dumps(server, separators=(",", ":"))))
        if histories:
            sql = "INSERT INTO bundle_history(id,server_id,version,digest,created_at,data) VALUES(?,?,?,?,?,?)"
            if hasattr(db, "executemany"):
                db.executemany(sql, histories)
            else:
                for values in histories:
                    db.execute(sql, values)
        if writes:
            sql = "INSERT INTO servers(id,data) VALUES(?,?) ON CONFLICT(id) DO UPDATE SET data=excluded.data"
            if hasattr(db, "executemany"):
                db.executemany(sql, writes)
            else:
                for values in writes:
                    db.execute(sql, values)

    def save_policy(self, value, actor, identifier=None, reason="Policy configuration changed", allow_restore=False, *, principal=None):
        policy = validate_policy(value)
        with self.lock, self.meta() as db:
            if getattr(db,"dialect","sqlite")=="sqlite":
                db.execute("BEGIN IMMEDIATE")
            old = self._get(db, "policies", identifier) if identifier else None
            if "expected_revision" in value:
                expected=value["expected_revision"]
                if isinstance(expected,bool) or not isinstance(expected,int) or expected<1:
                    raise ValueError("Expected policy revision must be a positive integer")
                if not old or expected!=old.get("revision"):
                    from .firewall import WorkflowConflict
                    raise WorkflowConflict("Policy changed; fetch exact detail and review again",{})
            if identifier and not old:
                if not allow_restore:
                    raise KeyError(identifier)
                historical = db.execute("SELECT data FROM policy_revisions WHERE policy_id=? ORDER BY revision DESC LIMIT 1", (identifier,)).fetchone()
                if not historical:
                    raise KeyError(identifier)
                previous = json.loads(historical[0])
                old = {"revision": previous["revision"], "created_at": previous.get("policy_created_at", previous["created_at"])}
            from .locations import selector as normalize_selector
            locations = self._all(db, "locations")
            policy["selector"] = normalize_selector(policy["selector"], locations)
            from .service_groups import snapshot
            groups = {group["id"] for group in self._all(db, "groups")}
            service_groups = {group["id"]: group for group in self._all(db, "service_groups")}
            for service in policy["services"]:
                service["source_selector"] = normalize_selector(service["source_selector"], locations)
                if any(identifier not in groups for identifier in service["source_group_ids"]):
                    raise ValueError("Policy references an unknown saved source server group")
                if "service_group_id" in service:
                    group = service_groups.get(service["service_group_id"])
                    if group is None:
                        raise ValueError("Policy references an unknown saved service group")
                    service["service_group_snapshot"] = snapshot(group)
            for group_id in policy["group_ids"]:
                if group_id not in groups:
                    raise ValueError("Policy references an unknown saved group")
            policy.update({"id": identifier or str(uuid.uuid4()), "revision": old.get("revision", 0) + 1 if old else 1, "created_at": old["created_at"] if old else stamp(), "updated_at": stamp()})
            if principal is not None:
                from .managed import authorize_policy
                authorize_policy(self, db, policy, actor, principal)
            from .policy_views import encoded_policy
            encoded_policy(policy)
            from .managed import record_revision
            record_revision(db, policy, actor, reason)
            self._put(db, "policies", policy)
            self.compile_all(db)
            self.audit("policy.updated" if old else "policy.created", actor, {"policy_id": policy["id"], "name": policy["name"], "mode": policy["mode"]}, db)
        return policy

    def delete_policy(self, identifier, actor, expected_revision=None):
        with self.lock, self.meta() as db:
            if getattr(db,"dialect","sqlite")=="sqlite":
                db.execute("BEGIN IMMEDIATE")
            old=self._get(db,"policies",identifier)
            if not old:
                raise KeyError(identifier)
            if expected_revision is not None:
                if isinstance(expected_revision,bool) or not isinstance(expected_revision,int) or expected_revision<1:
                    raise ValueError("Expected policy revision must be a positive integer")
                if expected_revision!=old.get("revision"):
                    from .firewall import WorkflowConflict
                    raise WorkflowConflict("Policy changed; fetch exact detail before deleting",{})
            from .managed import record_revision
            record_revision(db, self._get(db, "policies", identifier), actor, "Policy removed from active configuration")
            db.execute("DELETE FROM policies WHERE id=?", (identifier,))
            self.compile_all(db)
            self.audit("policy.deleted", actor, {"policy_id": identifier}, db)

    def update_server(self, identifier, value, actor):
        with self.lock, self.meta() as db:
            server = self._get(db, "servers", identifier)
            if not server:
                raise KeyError(identifier)
            from .metadata import apply_manual, reconcile_all
            metadata_fields = {"tags", "tag_updates", "reset_tag_keys", "location_id", "location_mode"}
            if set(value) & metadata_fields:
                apply_manual(self, db, server, value)
            if "expected_services" in value:
                services = value["expected_services"]
                if not isinstance(services, list) or len(services) > 100:
                    raise ValueError("Invalid expected services")
                server["expected_services"] = [validate_port(service) for service in services]
            self._put(db, "servers", server)
            reconcile_all(self, db)
            self.compile_all(db)
            self.audit("server.updated", actor, {"server_id": identifier, "fields": sorted(set(value) & (metadata_fields | {"expected_services"}))}, db)
            from .locations import decorate
            return self.public(decorate(self._get(db, "servers", identifier), self._all(db, "locations")))

    def report(self, identifier, value):
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", identifier or ""):
            raise ValueError("Invalid endpoint identity")
        hostname = value.get("hostname", "")
        if not isinstance(hostname, str) or not hostname or len(hostname) > 253:
            raise ValueError("Hostname is required")
        ips = value.get("ips", [])
        if not isinstance(ips, list) or len(ips) > 100:
            raise ValueError("Invalid IP addresses")
        try:
            if any(not isinstance(address, str) for address in ips):
                raise ValueError("IP addresses must be strings")
            ips = sorted({str(ipaddress.ip_address(address)) for address in ips})
        except (ValueError, TypeError):
            raise ValueError("Invalid endpoint address")
        listeners = value.get("listeners", [])
        if not isinstance(listeners, list) or len(listeners) > 2000:
            raise ValueError("Invalid listeners")
        normalized = []
        for listener in listeners:
            item = validate_port(listener)
            for key in ("address", "process", "service", "application", "systemd_unit"):
                text = listener.get(key, "")
                if not isinstance(text, str) or len(text) > 512:
                    raise ValueError("Invalid listener metadata")
                item[key] = text
            if "pid" in listener:
                pid = listener["pid"]
                if isinstance(pid, bool) or not isinstance(pid, int) or not 0 <= pid <= 2147483647:
                    raise ValueError("Invalid listener PID")
                item["pid"] = pid
            normalized.append(item)
        discovery_error = value.get("discovery_error", "")
        if not isinstance(discovery_error, str) or len(discovery_error) > 4096:
            raise ValueError("Invalid discovery error")
        discovery_performed = value.get("discovery_performed", True)
        if not isinstance(discovery_performed, bool):
            raise ValueError("discovery_performed must be a boolean")
        interval = value.get("discovery_interval_seconds")
        if interval is not None and (isinstance(interval, bool) or not isinstance(interval, int) or not 60 <= interval <= 86400):
            raise ValueError("Discovery interval must be 60 to 86400 seconds")
        scanned_at = None
        if discovery_performed and not discovery_error:
            scanned_time = parse_time(value["discovered_at"]) if value.get("discovered_at") else now()
            if scanned_time > now() + timedelta(seconds=60):
                raise ValueError("Discovery timestamp is too far in the future")
            scanned_at = stamp(scanned_time)
        control_interval = value.get("control_interval_seconds", 60)
        if isinstance(control_interval, bool) or not isinstance(control_interval, int) or not 5 <= control_interval <= 3600:
            raise ValueError("Control interval must be 5 to 3600 seconds")
        applied_version = value.get("applied_version", 0)
        if isinstance(applied_version, bool) or not isinstance(applied_version, int) or applied_version < 0:
            raise ValueError("Invalid applied version")
        apply_status = value.get("apply_status", "preview")
        if apply_status not in ("synced", "pending", "error", "preview", "rolled_back", "applying"):
            raise ValueError("Invalid apply status")
        collector_status = value.get("collector_status", "off")
        if collector_status not in ("off", "learning"):
            raise ValueError("Invalid collector status")
        from .learning import report_fields, acknowledge_discovery
        agent_version, capabilities, learning_discovery_ids = report_fields(value)
        with self.lock, self.meta() as db:
            if getattr(db, "dialect", "sqlite") != "postgresql":
                # Separate controller/store instances must serialize before
                # reading retire state or the centrally owned policy/tags.
                db.execute("BEGIN IMMEDIATE")
            from .server_management import assert_report_allowed
            assert_report_allowed(self, db, identifier)
            server = self._get(db, "servers", identifier)
            new = server is None
            server = server or {"id": identifier, "tags": {}, "_metadata_overrides": {"tags": {}}, "expected_services": [], "desired_version": 0, "status": "healthy", "created_at": stamp()}
            changed_addresses = ips != server.get("ips")
            previous_applied_version = server.get("applied_version", 0)
            previous_apply_status = server.get("apply_status", "preview")
            server.update({"hostname": hostname, "ips": ips, "last_seen": stamp(), "applied_version": applied_version, "apply_status": apply_status, "collector_status": collector_status, "ufw_active": bool(value.get("ufw_active", False)), "discovery_performed": discovery_performed, "control_interval_seconds": control_interval})
            server.update({"agent_version": agent_version, "capabilities": capabilities})
            from .hit_monitoring import report_status as report_hit_status
            report_hit_status(self, db, server, value)
            if value.get("configuration_state") is not None:
                from .endpoint_configuration import report as configuration_receipt
                server["configuration_state"] = configuration_receipt(value["configuration_state"])
            server["discovery_interval_seconds"] = interval if interval is not None else server.get("discovery_interval_seconds", 900)
            server.setdefault("listeners", [])
            if discovery_performed:
                server["last_discovery_attempt_at"] = stamp()
                if discovery_error:
                    server["discovery_error"] = discovery_error
                elif not server.get("last_discovery_at") or parse_time(scanned_at) >= parse_time(server["last_discovery_at"]):
                    self._record_discovery(db, server, normalized, scanned_at)
                    from .risky_ports import refresh_cache as refresh_risk_cache
                    refresh_risk_cache(self, db, server)
            acknowledge_discovery(self, db, server, value, learning_discovery_ids, normalized, scanned_at, now())
            # Cached reports may refresh agent health, never scan freshness or listener metadata.
            self._discovery_state(server)
            for key in ("os", "os_version", "firewalld_version", "firewall_backend", "firewalld_state", "apply_error"):
                field = value.get(key, "")
                if not isinstance(field, str) or len(field) > 4096:
                    raise ValueError("Invalid endpoint metadata")
                server[key] = field
            coverage = value.get("learning_coverage")
            if coverage:
                if not isinstance(coverage, dict):
                    raise ValueError("Invalid learning coverage")
                session = self._get(db, "sessions", coverage.get("session_id"))
                if not session or identifier not in session["server_ids"]:
                    raise ValueError("Learning coverage does not belong to endpoint")
                normalized_coverage = {"session_id": session["id"]}
                for key in ("started_at", "ended_at"):
                    if coverage.get(key):
                        normalized_coverage[key] = stamp(parse_time(coverage[key]))
                dropped = coverage.get("dropped_events", 0)
                if not isinstance(dropped, int) or isinstance(dropped, bool) or dropped < 0:
                    raise ValueError("Invalid dropped count")
                normalized_coverage["dropped_events"] = dropped
                rate_limited = coverage.get("rate_limited", False)
                error = coverage.get("error", "")
                if not isinstance(rate_limited, bool) or not isinstance(error, str) or len(error) > 4096:
                    raise ValueError("Invalid learning coverage metadata")
                normalized_coverage["rate_limited"] = rate_limited
                normalized_coverage["error"] = error
                server["learning_coverage"] = normalized_coverage
                server["last_learning_at"] = normalized_coverage.get("ended_at", normalized_coverage.get("started_at"))
            from .managed import protection, report_outcome
            if "protection" in value:
                protected = protection(value["protection"])
                server["protection"] = protected
                server["protection_digest"] = protected["digest"]
                server["protection_reported_at"] = stamp()
                server["management_protection"] = {**protected, "controller_origin": protected["controller_url"], "blocking_reasons": protected["blockers"]}
            if "managed_enforcement" in value:
                if report_outcome(self, db, server, value["managed_enforcement"]) is False:
                    applied_version=previous_applied_version;apply_status=previous_apply_status
                    server["applied_version"]=applied_version;server["apply_status"]=apply_status
            from .firewall import ingest_snapshot, ingest_results
            from .security import ingest_events, monitor
            if "firewall_snapshot" in value:
                ingest_snapshot(server, value["firewall_snapshot"])
            if "security_monitor" in value:
                server["security_monitor"] = monitor(value["security_monitor"])
            security_ack = ingest_events(self, db, server, value.get("security_events", []))
            firewall_ack = ingest_results(self, db, identifier, value.get("firewall_change_results", []))
            self._collector_state(server, self._all(db, "sessions"))
            from .learning_policies import refresh_host as refresh_learning_host, report_outcome as report_learning_outcome
            if "learning_allow_outcome" in value:
                report_learning_outcome(self, db, server, value["learning_allow_outcome"])
            refresh_learning_host(self, db, server)
            from .agent_settings import report as report_agent_settings
            report_agent_settings(self, db, server, value)
            host_default_deny_recompile = server.pop("_host_default_deny_recompile", False)
            if new or changed_addresses or host_default_deny_recompile:
                self._put(db, "servers", server)
                from .metadata import reconcile_all
                reconcile_all(self, db)
                self.compile_all(db)
                result = self._get(db, "servers", identifier)
            else:
                server["apply_status"] = "pending" if apply_status == "synced" and applied_version != server.get("desired_version") else apply_status
                result = server
            persist_result = not (new or changed_addresses)
            outcome = result.get("managed_enforcement", {})
            managed_scope = result.get("_compiled", {}).get("mode") == "enforce" or result.get("_managed_rules_active") or bool(result.get("_last_managed_applied_version"))
            if managed_scope:
                valid_applied = outcome.get("status") == "enforced" and outcome.get("version") == applied_version and outcome.get("digest") == result.get("_compiled", {}).get("digest") and outcome.get("protection_digest") == result.get("protection_digest") and outcome.get("approved_ips") == sorted(result.get("ips", [])) and bool(outcome.get("approval_id"))
                if outcome.get("status") == "rolled_back":
                    result["applied_version"] = outcome.get("last_good_version", previous_applied_version)
                    result["apply_status"] = "rolled_back"
                elif not valid_applied:
                    result["applied_version"] = previous_applied_version
                    if result.get("apply_status") == "synced":
                        result["apply_status"] = "pending"
                elif applied_version != result.get("desired_version"):
                    result["apply_status"] = "pending"
                persist_result = True
            from .managed import reconcile_direct
            if reconcile_direct(self, db, result):persist_result = True
            if persist_result:
                self._put(db, "servers", result)
            from .approvals import activate_learning
            for active_session in self._all(db, "sessions"):
                if identifier in active_session["server_ids"]:activate_learning(self, db, active_session)
            return {"server_id": identifier, "desired_version": result["desired_version"], "ack_security_event_ids": security_ack, "ack_firewall_change_ids": firewall_ack}

    def create_session(self, value, actor, *, principal=None):
        from .learning import create_session
        return create_session(self, value, actor, principal=principal)

    def stop_session(self, identifier, actor):
        with self.lock, self.meta() as db:
            session = self._get(db, "sessions", identifier)
            if not session:
                raise KeyError(identifier)
            if session["status"] == "active":
                cutoff = min(now(), parse_time(session["expires_at"]))
                session.update({"status": "stopped" if cutoff < parse_time(session["expires_at"]) else "expired", "stopped_at": stamp(cutoff)})
                self._put(db, "sessions", session)
                self.audit("learning.stopped", actor, {"session_id": identifier}, db)
            all_sessions = self._all(db, "sessions")
            for server_id in session["server_ids"]:
                server = self._get(db, "servers", server_id)
                if server:
                    self._collector_state(server, all_sessions)
                    self._put(db, "servers", server)
            return session

    def _assignment_value(self, identifier, db):
        from .learning import CAPABILITY, assignment as learning_assignment
        server = self._get(db, "servers", identifier)
        if not server:
            raise KeyError(identifier)
        result = dict(server.get("_compiled", {"server_id": identifier, "version": 0, "digest": digest({}), "mode": "monitor", "services": [], "generated_at": "1970-01-01T00:00:00Z"}))
        current = now()
        sessions = [session for session in self._all(db, "sessions") if identifier in session["server_ids"] and (session.get("selection_mode") != "discovered" or CAPABILITY in server.get("capabilities", []))]
        result["learning_sessions"] = sorted((learning_assignment(session, identifier) for session in sessions if session["status"] == "active" and parse_time(session["starts_at"]) <= current < parse_time(session["expires_at"])), key=lambda item: item["id"])
        tombstones = []
        for session in sessions:
            expiry = parse_time(session["expires_at"])
            cutoff = min(expiry, parse_time(session.get("stopped_at", session["expires_at"])))
            if cutoff <= current <= cutoff + timedelta(minutes=5):
                tombstones.append({**learning_assignment(session, identifier), "status": "stopped" if session["status"] == "stopped" else "expired", "stopped_at": stamp(cutoff)})
        result["learning_tombstones"] = sorted(tombstones, key=lambda item: item["id"])
        from .firewall import assignments
        result["firewall_changes"] = assignments(self, db, identifier)
        from .managed import authorization
        result["enforcement"] = authorization(self, db, server)
        from .learning_policies import assignment as learning_allow_assignment
        result["learning_allow"] = learning_allow_assignment(self, db, server)
        from .agent_settings import assignment as polling_assignment
        result["polling_settings"] = polling_assignment(self, identifier, db)
        from .hit_monitoring import CAPABILITY as hit_capability, assignments as hit_assignments
        if hit_capability in server.get("capabilities", []):
            result["hit_monitors"] = hit_assignments(self, db, server)
        return result

    def assignment(self, identifier):
        """Publish auxiliary intent with a durable endpoint-specific replay floor.

        Unchanged polls remain read-only. A changed snapshot is rebuilt under
        the same writer serialization as its generation publication, so an old
        concurrent read can never receive a newer generation than a stop.
        """
        key = "assignment_guard:" + identifier
        with self.read_meta() as db:
            result = self._assignment_value(identifier, db)
            guard = self._get(db, "maintenance_settings", key)
            content = digest(result)
            if guard and guard["digest"] == content:
                result.update(assignment_generation=guard["generation"], assignment_digest=content)
                return result, digest(result)
        with self.lock, self.meta() as db:
            if getattr(db, "dialect", "sqlite") != "postgresql":
                db.execute("BEGIN IMMEDIATE")
            result = self._assignment_value(identifier, db)
            content = digest(result)
            guard = self._get(db, "maintenance_settings", key)
            if not guard or guard["digest"] != content:
                guard = {"id": key, "server_id": identifier, "generation": (guard or {}).get("generation", 0) + 1, "digest": content}
                self._put(db, "maintenance_settings", guard)
            result.update(assignment_generation=guard["generation"], assignment_digest=content)
            return result, digest(result)

    def enqueue_flows(self, identifier, value):
        batch_id, session_id = value.get("batch_id"), value.get("session_id")
        if not isinstance(batch_id, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", batch_id):
            raise ValueError("Invalid batch ID")
        if not isinstance(session_id, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", session_id):
            raise ValueError("Invalid session ID")
        events = value.get("events", [])
        if not isinstance(events, list) or not events or len(events) > 2000:
            raise ValueError("Provide 1 to 2000 flow events")
        session = self.get("sessions", session_id)
        if identifier not in session["server_ids"]:
            raise PermissionError("Session is not assigned to this endpoint")
        cutoff = min(parse_time(session["expires_at"]), parse_time(session.get("stopped_at", session["expires_at"])))
        from .learning import ports_for
        ports = {(port["protocol"], port["port"]) for port in ports_for(session, identifier)}
        normalized = []
        for event in events:
            item = validate_port(event)
            if (item["protocol"], item["port"]) not in ports:
                raise ValueError("Flow port was not selected for learning")
            item["source_ip"] = str(ipaddress.ip_address(event.get("source_ip", "")))
            verdict = event.get("verdict", "observed")
            if verdict not in ("observed", "allowed", "denied"):
                raise ValueError("Invalid flow verdict")
            count = event.get("count", 1)
            if isinstance(count, bool) or not isinstance(count, int) or not 1 <= count <= 100000000:
                raise ValueError("Invalid observed count")
            first, last = parse_time(event.get("first_seen")), parse_time(event.get("last_seen"))
            if first > last or first < parse_time(session["starts_at"]) or last > cutoff or last > now() + timedelta(seconds=30):
                raise ValueError("Flow timestamps must be within actual learning window")
            item.update({"verdict": verdict, "count": count, "first_seen": stamp(first), "last_seen": stamp(last)})
            normalized.append(item)
        key = f"{identifier}:{batch_id}"
        encoded = json.dumps(normalized, sort_keys=True)
        with self.flow_lock, self.traffic() as db:
            existing = db.execute("SELECT data,session_id FROM batches WHERE batch_key=?", (key,)).fetchone()
            if existing:
                if existing["data"] != encoded or existing["session_id"] != session_id:
                    raise ValueError("Batch ID reused for different data")
                return {"accepted": len(normalized), "duplicate": True}
            if now() > cutoff + timedelta(minutes=5):
                raise LearningExpired("Learning upload grace period expired")
            pending = db.execute("SELECT COUNT(*) FROM batches WHERE processed=0").fetchone()[0]
            if pending > 10000:
                raise RuntimeError("Traffic queue is full; retry later")
            db.execute("INSERT INTO batches(batch_key,server_id,session_id,data,received_at) VALUES(?,?,?,?,?)", (key, identifier, session_id, encoded, stamp()))
        return {"accepted": len(normalized), "duplicate": False}

    def process_flows(self, limit=100):
        with self.flow_lock, self.traffic() as db:
            batches = db.execute("SELECT * FROM batches WHERE processed=0 ORDER BY received_at LIMIT ?", (limit,)).fetchall()
            for batch in batches:
                for index, event in enumerate(json.loads(batch["data"])):
                    db.execute("INSERT OR IGNORE INTO flows(batch_key,event_index,server_id,session_id,source_ip,port,protocol,verdict,count,first_seen,last_seen) VALUES(?,?,?,?,?,?,?,?,?,?,?)", (batch["batch_key"], index, batch["server_id"], batch["session_id"], event["source_ip"], event["port"], event["protocol"], event["verdict"], event["count"], event["first_seen"], event["last_seen"]))
                db.execute("UPDATE batches SET processed=1 WHERE batch_key=?", (batch["batch_key"],))
        from .learning_policies import reconcile as reconcile_learning_evidence
        reconcile_learning_evidence(self, limit)
        from .hit_monitoring import process as process_hits
        return len(batches) + process_hits(self, limit)

    def flows(self, window=3600, server_id=None):
        if not 60 <= window <= self.retention_hours * 3600:
            raise ValueError("Window is outside traffic retention")
        clause, params = "last_seen >= ?", [stamp(now() - timedelta(seconds=window))]
        if server_id:
            clause += " AND server_id = ?"
            params.append(server_id)
        with self.flow_lock, self.traffic() as db:
            rows = db.execute(f"SELECT server_id,session_id,source_ip,port,protocol,verdict,SUM(count) AS count,MIN(first_seen) AS first_seen,MAX(last_seen) AS last_seen FROM flows WHERE {clause} GROUP BY server_id,session_id,source_ip,port,protocol,verdict ORDER BY last_seen DESC LIMIT 500", params).fetchall()
            return [dict(row) for row in rows]

    def prune(self):
        from .hit_monitoring import prune as prune_hits
        prune_hits(self)
        from .security import prune
        with self.lock, self.meta() as db:
            prune(db)
        cutoff = stamp(now() - timedelta(hours=self.retention_hours))
        with self.flow_lock, self.traffic() as db:
            db.execute("DELETE FROM flows WHERE last_seen < ?", (cutoff,))
            db.execute("DELETE FROM batches WHERE processed=1 AND evidence_processed=1 AND received_at < ?", (cutoff,))

    def _event(self, db, key, kind, severity, server_id, message, details=None):
        alert = self._get(db, "alerts", key)
        if alert and alert.get("status") in ("open", "acknowledged"):
            return
        self._put(db, "alerts", {"id": key, "occurrence_id": uuid.uuid4().hex, "kind": kind, "severity": severity, "server_id": server_id, "message": message, "details": details or {}, "status": "open", "created_at": stamp(), "updated_at": stamp()})

    def _resolve(self, db, key, server_id, message):
        alert = self._get(db, "alerts", key)
        if alert and alert["status"] in ("open", "acknowledged"):
            alert.update({"status": "resolved", "resolved_at": stamp(), "updated_at": stamp()})
            self._put(db, "alerts", alert)
            recovery_id = f"recovery:{key}:{uuid.uuid4()}"
            self._put(db, "alerts", {"id": recovery_id, "kind": "recovered", "severity": "info", "server_id": server_id, "message": message, "status": "resolved", "created_at": stamp(), "updated_at": stamp()})

    def evaluate_health(self, at=None):
        at = at or now()
        with self.lock, self.meta() as db:
            if getattr(db, "dialect", "sqlite") != "postgresql":
                db.execute("BEGIN IMMEDIATE")
            from .firewall import refresh_plans
            refresh_plans(self, db)
            for session in self._all(db, "sessions"):
                if session["status"] == "active" and parse_time(session["expires_at"]) <= at:
                    session["status"] = "expired"
                    session["stopped_at"] = session["expires_at"]
                    self._put(db, "sessions", session)
                    self.audit("learning.expired", "system", {"session_id": session["id"]}, db)
            all_sessions = self._all(db, "sessions")
            from . import risky_ports
            risk_catalog = risky_ports.configuration(self, db)
            for server in self._all(db, "servers"):
                before = self._owned_health_state(server)
                from .service_health import sync as sync_service_expectations
                sync_service_expectations(server, server.get("_compiled", {}).get("services", []), "ordinary")
                identifier, hostname = server["id"], server["hostname"]
                self._collector_state(server, all_sessions, at)
                self._discovery_state(server, at)
                stale = Store._heartbeat_stale(server, at)
                if stale:
                    server["status"] = "offline"
                    server["service_health_status"] = "unknown"
                    self._event(db, f"offline:{identifier}", "agent_offline", "critical", identifier, f"Agent heartbeat missing: {hostname}")
                else:
                    self._resolve(db, f"offline:{identifier}", identifier, f"Agent recovered: {hostname}")
                    firewall_key = f"firewall-service:{identifier}"
                    firewall_state = str(server.get("firewalld_state") or "unknown").strip().lower()
                    if firewall_state in ("running", "active"):
                        if server.pop("_firewall_service_unavailable", False):
                            self._resolve(db, firewall_key, identifier, f"firewalld reports running: {hostname}")
                    elif firewall_state not in ("unknown", ""):
                        self._event(db, firewall_key, "firewall_service_unavailable", "critical", identifier,
                            f"firewalld is not verified running: {hostname}",
                            {"reported_state": firewall_state, "last_discovery_at": server.get("last_discovery_at"),
                             "rule_state": "unverified", "basis": "agent_report"})
                        server["_firewall_service_unavailable"] = True
                    missing = False
                    if server.get("discovery_status") == "current":
                        from .service_health import evaluate as evaluate_service_expectations
                        missing = evaluate_service_expectations(self, db, server)
                    server["service_health_status"] = "degraded" if missing else "unknown" if server.get("discovery_status") != "current" or server.get("policy_expectation_pending") else "healthy"
                    error = server.get("discovery_status") != "current" or server.get("policy_expectation_pending") or server.get("apply_status") == "error" or server.get("ufw_active") or server.get("firewalld_state") not in ("running", "active")
                    drift = server.get("applied_version", 0) != server.get("desired_version", 0)
                    if server.get("apply_status") == "error":
                        self._event(db, f"drift:{identifier}", "policy_drift", "warning", identifier, f"Policy apply failed: {hostname}", {"error": server.get("apply_error", "")})
                    elif not drift:
                        self._resolve(db, f"drift:{identifier}", identifier, f"Policy synchronized: {hostname}")
                    server["status"] = "warning" if missing or error or drift else "healthy"
                risk_changed = risky_ports.sync(self, db, server, risk_catalog)
                if risk_changed or self._owned_health_state(server) != before:
                    self._put(db, "servers", server)

    @staticmethod
    def _owned_health_state(server):
        # Include every field changed by collector/discovery/health evaluation,
        # including expiry of visible new-listener/change badges. Policy/source
        # matrices and unrelated snapshot data need no copying or hashing here.
        fields = ("status", "service_health_status", "policy_expectation_pending", "discovery_status", "discovery_stale", "next_discovery_at", "_firewall_service_unavailable", "collector_desired_status", "learning_stop_pending", "collector_status_stale", "collector_state", "learning_discovery_pending", "learning_discovery_status", "learning_discovery_error")
        return tuple(server.get(field) for field in fields) + (tuple(tuple(row) for row in server.get("_expected_alert_ports", [])), tuple(item.get("is_new") for item in server.get("listeners", [])), tuple(item.get("is_new") for item in server.get("discovery_changes", [])))

    def acknowledge(self, identifier, actor):
        with self.lock, self.meta() as db:
            alert = self._get(db, "alerts", identifier)
            if not alert:
                raise KeyError(identifier)
            if alert["status"] == "open":
                alert.update({"status": "acknowledged", "acknowledged_by": actor, "updated_at": stamp()})
                self._put(db, "alerts", alert)
                self.audit("alert.acknowledged", actor, {"alert_id": identifier}, db)
            if alert.get("kind") in ("service_discovered", "service_changed"):
                server = self._get(db, "servers", alert.get("server_id"))
                if server:
                    for listener in server.get("listeners", []):
                        if listener.get("discovery_alert_id") == identifier:
                            listener["is_new"] = False
                    for change in server.get("discovery_changes", []):
                        if change.get("discovery_alert_id") == identifier:
                            change["is_new"] = False
                    self._put(db, "servers", server)
            return alert

    def create_token(self, name, actor, tags=None, location_id=None, server_id=None):
        if not isinstance(name, str) or not name or len(name) > 120:
            raise ValueError("Token name required")
        if tags not in (None, {}) or location_id is not None:
            raise ValueError("Enrollment is identity-only; assign tags and DC centrally from the dashboard, CSV import or subnet mapping")
        token = secrets.token_urlsafe(32)
        expires = stamp(now() + timedelta(minutes=15))
        with self.lock, self.meta() as db:
            if server_id is not None:
                from .server_management import validate_binding
                validate_binding(self, db, {"server_id": server_id})
            self._put(db, "tokens", {"id": hashlib.sha256(token.encode()).hexdigest(), "name": name, "tags": {}, "location_id": None, "server_id": server_id, "expires_at": expires, "used": False})
            self.audit("enrollment_token.created", actor, {"name": name, "server_id": server_id, "expires_at": expires}, db)
        return {"token": token, "expires_at": expires}

    def enroll(self, token, hostname, csr, signer):
        if not isinstance(token, str) or len(token) > 256 or not isinstance(hostname, str) or not hostname or len(hostname) > 253:
            raise ValueError("Invalid enrollment request")
        if not isinstance(csr, str) or len(csr) > 16384 or "BEGIN CERTIFICATE REQUEST" not in csr:
            raise ValueError("Valid PEM CSR required")
        token_id = hashlib.sha256(token.encode()).hexdigest()
        with self.lock, self.meta() as db:
            record = self._get(db, "tokens", token_id)
            if not record or parse_time(record["expires_at"]) <= now():
                raise PermissionError("Enrollment token is invalid, expired or already used")
            csr_digest = hashlib.sha256(csr.encode()).hexdigest()
            if record.get("used"):
                previous_digest = record.get("csr_digest")
                response = record.get("response")
                if not isinstance(previous_digest, str) or not secrets.compare_digest(previous_digest, csr_digest) or record.get("hostname") != hostname or not isinstance(response, dict) or not all(response.get(key) for key in ("server_id", "certificate", "ca_certificate")):
                    raise PermissionError("Enrollment token is already bound to a different request")
                from .server_management import assert_report_allowed
                assert_report_allowed(self, db, response["server_id"])
                return dict(response)
            from .server_management import validate_binding, consume_reservation
            reservation = validate_binding(self, db, record, hostname)
            identifier = reservation["id"] if reservation else str(uuid.uuid4())
            certificate, ca_certificate = signer(identifier, csr)
            response = {"server_id": identifier, "certificate": certificate, "ca_certificate": ca_certificate}
            record.update({"used": True, "csr_digest": csr_digest, "hostname": hostname, "response": response})
            self._put(db, "tokens", record)
            server = {"id": identifier, "hostname": hostname, "ips": [], "tags": {}, "_metadata_overrides": {"tags": {}}, "location_id": None, "location_source": {"type": "unassigned"}, "tag_sources": {}, "metadata_conflicts": [], "expected_services": [], "listeners": [], "os": "unknown", "os_version": "", "firewalld_version": "", "firewall_backend": "", "firewalld_state": "unknown", "ufw_active": False, "last_seen": stamp(), "status": "warning", "desired_version": 0, "applied_version": 0, "apply_status": "pending", "apply_error": "", "collector_status": "off", "created_at": stamp()}
            self._collector_state(server, self._all(db, "sessions"))
            from .endpoint_certificates import record_issued
            record_issued(self, db, server, certificate)
            self._put(db, "servers", server)
            if reservation:
                consume_reservation(self, db, identifier)
            self.compile_all(db)
            self.audit("agent.enrolled", "enrollment", {"server_id": identifier, "hostname": hostname}, db)
        return response

    def overview(self, demo=False):
        from .policy_views import listing as public_policies,service_groups as service_group_listing
        servers = self.servers()
        from .session_views import listing as public_sessions
        session_page = public_sessions(self)
        sessions = session_page.pop("items")
        policy_page=public_policies(self,"managed")
        policies=policy_page.pop("items")
        alerts = sorted(self.all("alerts"), key=lambda item: item["created_at"], reverse=True)
        flows = self.flows()
        total = len(servers)
        # Reuse this compact fleet projection for catalogue/group counts. Do not
        # decode every canonical firewall snapshot again for each overview panel.
        catalog=self.all("locations")
        location_counts={}
        for server in servers:
            identifier=server.get("location_id")
            location_counts[identifier]=location_counts.get(identifier,0)+1
        locations=sorted(({**location,"server_count":location_counts.get(location["id"],0)} for location in catalog),key=lambda item:item["name"].casefold())
        groups=sorted((self._public_group(group,servers,catalog) for group in self.all("groups")),key=lambda item:item["name"].casefold())
        stats = {"total_servers": total, "healthy_servers": sum(server["status"] == "healthy" for server in servers), "offline_servers": sum(server["status"] == "offline" for server in servers), "warning_servers": sum(server["status"] == "warning" for server in servers), "active_learning": session_page["active_total"], "active_alerts": sum(alert["status"] == "open" for alert in alerts), "policy_count": policy_page["total"], "observed_events": sum(flow["count"] for flow in flows), "discovered_services": sum(len(server.get("listeners", [])) for server in servers), "synced_servers": sum(server.get("apply_status") == "synced" and server.get("applied_version") == server.get("desired_version") for server in servers)}
        learned_page=public_policies(self,"learned")
        learned_policies=learned_page.pop("items")
        from . import __version__
        return {"servers": servers, "policies": policies, "policy_pagination": policy_page, "learning_policies": learned_policies, "learning_policy_pagination": learned_page, "groups": groups, "service_groups": service_group_listing(self), "locations": locations, "learning_sessions": sessions, "learning_session_pagination": session_page, "alerts": alerts[:500], "flows": flows, "stats": stats, "meta": {"demo": demo, "synthetic": demo, "version": __version__, "traffic_retention_hours": self.retention_hours, "storage": "Shared PostgreSQL HA baseline" if self.ha else "SQLite development baseline", "ha": self.ha, "generated_at": stamp()}}


    def firewall_inventory(self, selected=None, **options):
        from .firewall import inventory
        return inventory(self, selected, **options)

    def create_firewall_change(self, value, actor, *, principal=None):
        from .firewall import create_change
        return create_change(self, value, actor, principal=principal)

    def confirm_firewall_change(self, identifier, value, actor, *, principal=None):
        from .firewall import confirm_change
        return confirm_change(self, identifier, value, actor, principal=principal)

    def cancel_firewall_change(self, identifier, actor):
        from .firewall import cancel_change
        return cancel_change(self, identifier, actor)


    def policy_revisions(self, identifier, revision=None):
        from .managed import revisions
        return revisions(self, identifier, revision)

    def policy_history(self, identifier, version=None):
        from .managed import history
        return history(self, identifier, version)

    def rollback_policy(self, identifier, revision, reason, actor, *, principal=None):
        if isinstance(revision, bool) or not isinstance(revision, int) or revision < 1 or not isinstance(reason, str) or not reason.strip() or len(reason) > 500:
            raise ValueError("Historical revision and an explicit rollback reason are required")
        historical = self.policy_revisions(identifier, revision)
        restored = self.save_policy(historical, actor, identifier, "Restore revision " + str(revision) + ": " + reason, allow_restore=True, principal=principal)
        self.audit("policy.restored_as_new_revision", actor, {"policy_id": identifier, "from_revision": revision, "new_revision": restored["revision"], "reason": reason})
        return restored

    def managed_rollouts(self, identifier=None):
        from .managed import rollouts
        return rollouts(self, identifier)

    def create_managed_rollout(self, value, actor, *, principal=None):
        from .managed import rollout
        return rollout(self, value, actor, principal=principal)

    def confirm_managed_rollout(self, identifier, value, actor, *, principal=None):
        from .managed import confirm
        return confirm(self, identifier, value, actor, principal=principal)

    def cancel_managed_rollout(self, identifier, actor):
        from .managed import cancel
        return cancel(self, identifier, actor)

    def verify_managed_enforcement(self, identifier, value):
        from .managed import authorization
        with self.read_meta() as db:
            server = self._get(db, "servers", identifier)
            if not server:
                raise PermissionError("Endpoint is not enrolled")
            approved = authorization(self, db, server)
            if not approved["authorized"] or value.get("approval_id") != approved["approval_id"] or value.get("version") != approved["approved_version"] or value.get("digest") != approved["approved_digest"] or value.get("protection_digest") != approved["protection_digest"] or value.get("binding_digest") != approved["binding_digest"]:
                raise PermissionError("Current exact policy, protected configuration and target IPs are not authorized")
            protection = server["protection"]
            return {"server_id": identifier, "hostname": server["hostname"], "ips": approved["approved_ips"], "ssh_ports": protection["ssh_ports"], "management_sources": protection["management_sources"], "controller_origin": protection["controller_url"], "controller_addresses": protection.get("controller_addresses", []), "approval_id": approved["approval_id"], "version": approved["approved_version"], "digest": approved["approved_digest"], "protection_digest": approved["protection_digest"], "binding_digest": approved["binding_digest"], "expires_at": approved["expires_at"], "intent": approved.get("intent", "enforce"), "approval_proof": approved.get("approval_proof"), **{key: approved[key] for key in ("host_default_deny_ack", "host_default_deny_revision", "host_default_deny_configuration_digest") if key in approved}}

    def locations(self):
        from .locations import listing
        return listing(self)

    def save_location(self, value, actor, identifier=None):
        from .locations import save
        return save(self, value, actor, identifier)

    def delete_location(self, identifier, actor):
        from .locations import delete
        return delete(self, identifier, actor)
