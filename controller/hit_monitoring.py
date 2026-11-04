"""Optional, source/port hit observations. Never learning or access authority.

An enabled central scope grants only short signed endpoint leases. Logs are
rate-limited observations, not complete flows or proof of allow/deny/success.
"""
from contextlib import contextmanager
from datetime import timedelta
import csv
import io
import ipaddress
import json
import re
import secrets
import tempfile
import uuid

from .firewall import WorkflowConflict
from .store import digest, now, parse_time, stamp, validate_port, validate_tags

CAPABILITY = "port_hit_monitor_v1"
LEASE_SECONDS = 120
BUCKET_SECONDS = 60
UPLOAD_GRACE_SECONDS = 300
MAX_PORTS = 64
MAX_PER_HOST = 8
MAX_TARGETS = 20000
MAX_REVIEW_BYTES = 8 * 1024 * 1024
MAX_STORED_EVENTS = 2000000
MAX_STORED_BATCHES = 1000000
META_TABLES = ("hit_monitors", "hit_monitor_targets", "hit_monitor_reviews")
TRAFFIC_TABLES = ("hit_batches", "hit_events", "hit_limits")
ID = re.compile(r"[A-Za-z0-9_.:-]{1,128}\Z")


class MonitoringExpired(ValueError):
    pass


def initialize(db):
    for table in ("hit_monitors", "hit_monitor_reviews"):
        db.execute("CREATE TABLE IF NOT EXISTS " + table + "(id TEXT PRIMARY KEY,data TEXT NOT NULL)")
    db.execute("CREATE TABLE IF NOT EXISTS hit_monitor_targets(id TEXT PRIMARY KEY,monitor_id TEXT NOT NULL,server_id TEXT NOT NULL,enabled INTEGER NOT NULL DEFAULT 1,data TEXT NOT NULL)")
    db.execute("CREATE INDEX IF NOT EXISTS hit_targets_server ON hit_monitor_targets(server_id,enabled,monitor_id)")
    db.execute("CREATE INDEX IF NOT EXISTS hit_targets_monitor ON hit_monitor_targets(monitor_id,server_id)")
    from .approval_views import _expression
    db.execute("CREATE INDEX IF NOT EXISTS hit_reviews_expiry ON hit_monitor_reviews((" + _expression(db, ("expires_at",)) + "))")


def initialize_traffic(db):
    db.executescript("""
    CREATE TABLE IF NOT EXISTS hit_batches(batch_key TEXT PRIMARY KEY,server_id TEXT NOT NULL,monitor_id TEXT NOT NULL,data TEXT NOT NULL,received_at TEXT NOT NULL,processed INTEGER NOT NULL DEFAULT 0);
    CREATE INDEX IF NOT EXISTS hit_batches_pending ON hit_batches(processed,received_at);
    CREATE TABLE IF NOT EXISTS hit_events(id TEXT PRIMARY KEY,server_id TEXT NOT NULL,monitor_id TEXT NOT NULL,batch_key TEXT NOT NULL,event_digest TEXT NOT NULL,source_ip TEXT NOT NULL,port INTEGER NOT NULL,protocol TEXT NOT NULL,event_time TEXT NOT NULL,expires_at TEXT NOT NULL,data TEXT NOT NULL,processed INTEGER NOT NULL DEFAULT 0);
    CREATE INDEX IF NOT EXISTS hit_events_monitor ON hit_events(monitor_id,processed,event_time,server_id);
    CREATE INDEX IF NOT EXISTS hit_events_retention ON hit_events(expires_at);
    CREATE INDEX IF NOT EXISTS hit_events_batch ON hit_events(batch_key);
    CREATE TABLE IF NOT EXISTS hit_limits(id TEXT PRIMARY KEY,data TEXT NOT NULL);
    """)
    # A new deployment must have genuinely empty traffic tables. The quota
    # ledger is sparse, created only by actual accepted ingestion. Normalize
    # the unreleased zero singleton only when no hit data/receipts exist.
    row = db.execute("SELECT data FROM hit_limits WHERE id='usage'").fetchone()
    if row and json.loads(row[0]) == {"id": "usage", "events": 0, "batches": 0}:
        db.execute("DELETE FROM hit_limits WHERE id='usage' AND data=? AND NOT EXISTS(SELECT 1 FROM hit_events) AND NOT EXISTS(SELECT 1 FROM hit_batches)", (row[0],))


def _usage(db):
    row = db.execute("SELECT data FROM hit_limits WHERE id='usage'").fetchone()
    return json.loads(row[0]) if row else {"id": "usage", "events": 0, "batches": 0}


def _monitor_column(db, alias=""):
    # Code-owned navigation projection only. Frozen target membership lives in
    # hit_monitor_targets; historical selection IDs are never capture authority.
    data = (alias + "." if alias else "") + "data"
    return "(" + data + "::jsonb #- '{selection_summary,group_ids}')::text" if getattr(db, "dialect", "sqlite") == "postgresql" else "json_remove(" + data + ",'$.selection_summary.group_ids')"


def _monitor(db, identifier):
    row = db.execute("SELECT " + _monitor_column(db) + " FROM hit_monitors WHERE id=?", (identifier,)).fetchone()
    return json.loads(row[0]) if row else None


def _write(db):
    if getattr(db, "dialect", "sqlite") == "sqlite":
        db.execute("BEGIN IMMEDIATE")


def _ports(value):
    if not isinstance(value, list) or not 1 <= len(value) <= MAX_PORTS:
        raise ValueError("Choose 1..64 exact TCP/UDP port pairs")
    if any(not isinstance(item, dict) or set(item) != {"port", "protocol"} for item in value):
        raise ValueError("Only exact port/protocol pairs may be monitored")
    values = {tuple(validate_port(item)[key] for key in ("protocol", "port")) for item in value}
    return [{"protocol": protocol, "port": port} for protocol, port in sorted(values)]


def _authority(store, db):
    value = store._get(db, "maintenance_settings", "controller_provider_authority")
    return {key: value.get(key, "") for key in ("fingerprint", "epoch")} if value else {"fingerprint": getattr(store, "approval_auth_fingerprint", "") or "bootstrap", "epoch": ""}


def _servers(db):
    from .inventory_views import rows
    fields = ("id", "hostname", "ips", "tags", "location_id", "capabilities", "configuration_state", "firewalld_state", "ufw_active", "last_seen", "control_interval_seconds", "last_discovery_at", "retired_at")
    if getattr(db, "dialect", "sqlite") == "postgresql":
        pairs = ",".join("'" + field + "',document->'" + field + "'" for field in fields)
        sql = "SELECT jsonb_build_object(" + pairs + ")::text FROM servers CROSS JOIN LATERAL (SELECT data::jsonb AS document OFFSET 0) projected"
    else:
        pairs = ",".join("'" + field + "',json_extract(data,'$." + field + "')" for field in fields)
        sql = "SELECT json_object(" + pairs + ") FROM servers"
    result = {}
    for row in rows(db, sql):
        server = json.loads(row[0])
        if not server.get("retired_at"):
            server["tags"] = server.get("tags") or {}
            server["capabilities"] = server.get("capabilities") or []
            result[server["id"]] = server
    return result


def _service_snapshot(db, identifier, ports):
    # Fetch only one host's bounded listener array, never every host's canonical
    # firewall/compiled bundle or every fleet listener in a review request.
    expression = "(data::jsonb->'listeners')::text" if getattr(db, "dialect", "sqlite") == "postgresql" else "json_extract(data,'$.listeners')"
    row = db.execute("SELECT " + expression + " FROM servers WHERE id=?", (identifier,)).fetchone()
    selected = {(item["protocol"], item["port"]) for item in ports}
    result = {}
    for listener in json.loads(row[0] or "[]"):
        pair = (listener["protocol"], listener["port"])
        if pair in selected:
            result.setdefault(f"{pair[0]}:{pair[1]}", {key: listener.get(key, "") for key in ("service", "application", "process", "systemd_unit")})
    return result


def _select(store, db, selection, servers):
    from .locations import selector as normalize_selector
    if not isinstance(selection, dict) or set(selection) - {"server_ids", "group_ids", "selector"}:
        raise ValueError("Choose servers, saved groups or target tags")
    ids, group_ids = selection.get("server_ids", []), selection.get("group_ids", [])
    if any(not isinstance(items, list) or len(items) > MAX_TARGETS or any(not isinstance(item, str) or not ID.fullmatch(item) for item in items) for items in (ids, group_ids)):
        raise ValueError("Target IDs must be bounded enrolled server/group IDs")
    if set(ids) - set(servers):
        raise ValueError("A selected endpoint no longer exists")
    selector = normalize_selector(validate_tags(selection.get("selector", {})), store._all(db, "locations"), strict=True)
    from .store import matches
    chosen, groups = set(ids), {}
    for identifier in set(group_ids):
        group = store._get(db, "groups", identifier)
        if not group:
            raise ValueError("A selected saved group no longer exists")
        members = {server["id"] for server in servers.values() if matches(server.get("tags", {}) | {"location_id": server.get("location_id")}, group.get("selector", {}))} if group.get("type") == "dynamic" and group.get("selector") else set(group.get("server_ids", [])) & set(servers)
        if group.get("type") == "dynamic" and not group.get("selector"):
            members = set()
        chosen.update(members)
        groups[identifier] = digest({"group": group, "members": sorted(members)})
    if selector:
        chosen.update(server["id"] for server in servers.values() if matches(server.get("tags", {}) | {"location_id": server.get("location_id")}, selector))
    if not chosen or len(chosen) > MAX_TARGETS:
        raise ValueError("Choose 1..20000 existing endpoints; scope is frozen at review")
    return sorted(chosen), groups, {"group_ids": sorted(set(group_ids)), "selector": selector, "explicit_server_count": len(set(ids))}


def _binding(server):
    return digest({key: server.get(key) for key in ("id", "hostname", "ips", "tags", "location_id", "capabilities", "configuration_state", "firewalld_state", "ufw_active")})


def _compatible(server, at, *, typed=False):
    if not {CAPABILITY, "signed_assignments_v1"} <= set(server.get("capabilities", [])):
        raise ValueError("Upgrade selected endpoints to signed port_hit_monitor_v1")
    if typed and 'traffic_capture_v1' not in server.get('capabilities',[]):
        raise ValueError('New monitored capture scopes require traffic_capture_v1; upgrade selected endpoints')
    if server.get("firewalld_state") != "running" or server.get("ufw_active"):
        raise ValueError("Selected endpoints need running firewalld without active UFW coexistence")
    if not server.get("last_seen") or parse_time(server["last_seen"]) < at - timedelta(seconds=max(180, 3 * server.get("control_interval_seconds", 30))):
        raise ValueError("Selected endpoints need fresh authenticated reports")


def _capacity(store, db, identifier, ports):
    rows = db.execute("SELECT " + _monitor_column(db, "m") + " FROM hit_monitor_targets t JOIN hit_monitors m ON m.id=t.monitor_id WHERE t.server_id=? AND t.enabled=1 LIMIT 9", (identifier,)).fetchall()
    active = [json.loads(row[0]) for row in rows if json.loads(row[0]).get("enabled")]
    total_scopes = sum(len(monitor["ports"]) for monitor in active) + len(ports)
    if len(active) >= MAX_PER_HOST or total_scopes > MAX_PORTS:
        raise ValueError("Each endpoint supports at most 8 active monitors / 64 total monitored port pairs")


def preview(store, value, actor):
    if not isinstance(value, dict) or set(value)-{"name", "selection", "ports", "retention_hours", "observation_kinds"} or not {"name", "selection", "ports", "retention_hours"}<=set(value):
        raise ValueError("Provide name, selection, exact ports and 1..24 hour retention")
    from .traffic_capture import observation_kinds
    kinds=observation_kinds(value.get("observation_kinds"))
    name, retention, ports = value["name"], value["retention_hours"], _ports(value["ports"])
    if not isinstance(name, str) or not name.strip() or len(name) > 120 or isinstance(retention, bool) or not isinstance(retention, int) or not 1 <= retention <= 24:
        raise ValueError("Name is required and retention must be 1..24 hours")
    with store.lock, store.meta() as db:
        _write(db)
        servers = _servers(db)
        ids, groups, summary = _select(store, db, value["selection"], servers)
        for identifier in ids:
            _compatible(servers[identifier], now(),typed=True)
            _capacity(store, db, identifier, ports)
        plan = {"id": uuid.uuid4().hex, "operation": "enable", "name": name.strip(), "selection": value["selection"], "selection_summary": summary,
                "server_ids": ids, "target_bindings": {identifier: _binding(servers[identifier]) for identifier in ids}, "group_bindings": groups,
                "ports": ports, "observation_kinds":kinds, "legacy_capture_target_count":sum('traffic_capture_v1' not in servers[identifier].get('capabilities',[]) for identifier in ids), "retention_hours": retention, "created_by": actor, "created_at": stamp(), "expires_at": stamp(now() + timedelta(minutes=10)),
                "authority": _authority(store, db), "status": "draft", "confirmation_nonce": secrets.token_urlsafe(24)}
        plan["digest"] = digest(plan)
        plan["confirmation_phrase"] = "START HIT MONITOR " + plan["id"][:8].upper()
        from .review_limits import encoded_size
        encoded_size(plan)
        store._put(db, "hit_monitor_reviews", plan)
        return {**plan, "target_count": len(ids), "duration": "until_stopped", "capture_lease_seconds": LEASE_SECONDS, "automatic_policy": False,
                "coverage": "Accepted transport connections and denied packets have separate counts; loss and unsupported backends can leave gaps. Legacy journal records remain labelled."}


def stop_preview(store, identifier, value, actor):
    if not isinstance(value, dict) or set(value) != {"expected_revision"}:
        raise ValueError("Review the exact current monitor revision")
    with store.lock, store.meta() as db:
        _write(db)
        monitor = store._get(db, "hit_monitors", identifier)
        if not monitor or not monitor["enabled"] or monitor["revision"] != value["expected_revision"]:
            raise WorkflowConflict("Monitor changed or is already disabled", {})
        plan = {"id": uuid.uuid4().hex, "operation": "disable", "monitor_id": identifier, "expected_revision": monitor["revision"],
                "created_by": actor, "created_at": stamp(), "expires_at": stamp(now() + timedelta(minutes=10)), "authority": _authority(store, db),
                "status": "draft", "confirmation_nonce": secrets.token_urlsafe(24)}
        plan["digest"] = digest(plan)
        plan["confirmation_phrase"] = "STOP HIT MONITOR " + plan["id"][:8].upper()
        store._put(db, "hit_monitor_reviews", plan)
        return {**plan, "target_count": monitor["target_count"], "name": monitor["name"], "ports": monitor["ports"], **({"observation_kinds":monitor["observation_kinds"]} if "observation_kinds" in monitor else {}), "capture_lease_seconds": LEASE_SECONDS}


def apply(store, value, actor):
    if not isinstance(value, dict) or set(value) != {"preview_id", "digest", "confirmation_nonce", "confirmation_phrase"}:
        raise ValueError("Confirm the exact monitor preview")
    with store.lock, store.meta() as db:
        _write(db)
        plan = store._get(db, "hit_monitor_reviews", value["preview_id"])
        if not plan or plan["created_by"] != actor or plan["authority"] != _authority(store, db) or any(not isinstance(value[key], str) or not secrets.compare_digest(value[key], plan[key]) for key in ("digest", "confirmation_nonce", "confirmation_phrase")):
            raise PermissionError("Monitor review is not current or belongs to another authenticated actor")
        if plan["status"] == "applied":
            return store._get(db, "hit_monitors", plan["monitor_id"])
        if parse_time(plan["expires_at"]) <= now():
            raise WorkflowConflict("Monitor review expired", {})
        if plan["operation"] == "disable":
            monitor = store._get(db, "hit_monitors", plan["monitor_id"])
            if not monitor or monitor["revision"] != plan["expected_revision"] or not monitor["enabled"]:
                raise WorkflowConflict("Monitor changed; review again", {})
            db.execute("UPDATE hit_monitor_targets SET enabled=0 WHERE monitor_id=?", (monitor["id"],))
            monitor.update(enabled=False, revision=monitor["revision"] + 1, stopped_at=stamp(), updated_at=stamp(), updated_by=actor)
        else:
            servers = _servers(db)
            ids, groups, _ = _select(store, db, plan["selection"], servers)
            if ids != plan["server_ids"] or groups != plan["group_bindings"] or any(_binding(servers[identifier]) != plan["target_bindings"][identifier] for identifier in ids):
                raise WorkflowConflict("Endpoint, group or tag membership changed; preview again", {})
            for identifier in ids:
                _compatible(servers[identifier], now(),typed='observation_kinds' in plan)
                _capacity(store, db, identifier, plan["ports"])
            summary = {key: item for key, item in plan["selection_summary"].items() if key != "group_ids"}
            summary["group_count"] = len(plan["selection_summary"].get("group_ids", []))
            monitor = {"id": str(uuid.uuid4()), "name": plan["name"], "ports": plan["ports"], **({"observation_kinds":plan["observation_kinds"]} if 'observation_kinds' in plan else {}), "legacy_capture_target_count":plan.get("legacy_capture_target_count",0), "retention_hours": plan["retention_hours"], "enabled": True,
                       "revision": 1, "review_id": plan["id"], "review_digest": plan["digest"], "target_count": len(ids), "selection_summary": summary, "created_by": actor, "created_at": stamp(), "started_at": stamp(), "updated_at": stamp()}
            for identifier in ids:
                server = servers[identifier]
                service = _service_snapshot(db, identifier, monitor["ports"])
                data = {"server_id": identifier, "hostname": server["hostname"], "target_binding": plan["target_bindings"][identifier], "service_snapshot": service, "service_basis": "inventory_at_monitor_enable", "inventory_at": server.get("last_discovery_at")}
                db.execute("INSERT INTO hit_monitor_targets(id,monitor_id,server_id,enabled,data) VALUES(?,?,?,1,?)", (monitor["id"] + ":" + identifier, monitor["id"], identifier, json.dumps(data, separators=(",", ":"))))
        store._put(db, "hit_monitors", monitor)
        plan.update(status="applied", monitor_id=monitor["id"], applied_at=stamp())
        store._put(db, "hit_monitor_reviews", plan)
        store.audit("hit_monitor." + plan["operation"], actor, {"monitor_id": monitor["id"], "target_count": monitor["target_count"], "ports": monitor["ports"], "automatic_policy": False}, db)
        return monitor


def listing(store, limit=20, offset=0):
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100 or isinstance(offset, bool) or not isinstance(offset, int) or not 0 <= offset <= 1000000:
        raise ValueError("Choose a bounded monitor page")
    with store.read_meta() as db:
        total = db.execute("SELECT COUNT(*) FROM hit_monitors").fetchone()[0]
        rows = db.execute("SELECT " + _monitor_column(db) + " FROM hit_monitors ORDER BY id LIMIT ? OFFSET ?", (limit, offset)).fetchall()
        items = [json.loads(row[0]) for row in rows]
        from .approval_views import _expression
        status = _expression(db, ("last_outcome", "status"))
        for item in items:
            counts = db.execute("SELECT COALESCE(" + status + ",'unreported'),COUNT(*) FROM hit_monitor_targets WHERE monitor_id=? GROUP BY COALESCE(" + status + ",'unreported')", (item["id"],)).fetchall()
            item["status_counts"] = {row[0]: row[1] for row in counts}
    with store.read_traffic() as db:
        usage = _usage(db)
        pending = db.execute("SELECT COUNT(*) FROM hit_batches WHERE processed=0").fetchone()[0]
    return {"items": items, "total": total, "limit": limit, "offset": offset, "has_more": offset + len(items) < total,
            "default_enabled": False, "automatic_policy": False, "capture_lease_seconds": LEASE_SECONDS,
            "storage_budget": {"event_count": usage["events"], "max_events": MAX_STORED_EVENTS, "batch_count": usage["batches"], "max_batches": MAX_STORED_BATCHES}, "pending_batches": pending,
            "coverage": "Rate-limited logged packets; storage/backpressure can cause gaps; not complete flows"}


def assignments(store, db, server, at=None):
    if not {CAPABILITY, "signed_assignments_v1"} <= set(server.get("capabilities", [])):
        return []
    at = at or now()
    issued = at.fromtimestamp(int(at.timestamp()) // BUCKET_SECONDS * BUCKET_SECONDS, at.tzinfo)
    rows = db.execute("SELECT " + _monitor_column(db, "m") + " FROM hit_monitor_targets t JOIN hit_monitors m ON m.id=t.monitor_id WHERE t.server_id=? AND t.enabled=1 ORDER BY m.id LIMIT ?", (server["id"], MAX_PER_HOST + 1)).fetchall()
    values = [json.loads(row[0]) for row in rows]
    active = [value for value in values if value["enabled"]]
    if len(active) > MAX_PER_HOST:
        raise ValueError("Endpoint monitor capacity exceeded")
    return [{"id": value["id"], "server_id": server["id"], "starts_at": stamp(issued), "expires_at": stamp(issued + timedelta(seconds=LEASE_SECONDS)), "ports": value["ports"], **({"observation_kinds":value["observation_kinds"]} if "observation_kinds" in value else {})} for value in active]


def enqueue(store, identifier, value):
    if not isinstance(value, dict) or set(value) != {"batch_id", "monitor_id", "lease_starts_at", "lease_expires_at", "events"}:
        raise ValueError("Provide an exact monitor batch and its signed lease window")
    batch_id, monitor_id = value["batch_id"], value["monitor_id"]
    if any(not isinstance(item, str) or not ID.fullmatch(item) for item in (batch_id, monitor_id)):
        raise ValueError("Invalid monitor/batch identity")
    issued, expiry = parse_time(value["lease_starts_at"]), parse_time(value["lease_expires_at"])
    if issued.microsecond or int(issued.timestamp()) % BUCKET_SECONDS or expiry != issued + timedelta(seconds=LEASE_SECONDS) or issued > now() + timedelta(seconds=30):
        raise ValueError("Monitor lease must be a current 60-second bucket with a 120-second maximum")
    if now() > expiry + timedelta(seconds=UPLOAD_GRACE_SECONDS):
        raise MonitoringExpired("Monitor lease upload grace expired")
    with store.read_meta() as db:
        monitor = _monitor(db, monitor_id)
        row = db.execute("SELECT data FROM hit_monitor_targets WHERE monitor_id=? AND server_id=?", (monitor_id, identifier)).fetchone()
        if not monitor or row is None:
            raise PermissionError("Monitor is not assigned to this enrolled endpoint")
        target = json.loads(row[0])
        from .approval_views import _expression
        capabilities_row=db.execute('SELECT '+_expression(db,('capabilities',))+' FROM servers WHERE id=?',(identifier,)).fetchone()
        capabilities=json.loads(capabilities_row[0]) if capabilities_row and capabilities_row[0] else []
    started = parse_time(monitor["started_at"])
    if expiry <= started or monitor.get("stopped_at") and issued > parse_time(monitor["stopped_at"]):
        raise MonitoringExpired("No monitor lease was permitted in this window")
    # A lease already issued before Stop can finish for at most120s. This is
    # bounded residual collection, not a promise of instantaneous remote stop.
    ports = {(row["protocol"], row["port"]) for row in monitor["ports"]}
    events = value["events"]
    if not isinstance(events, list) or not 1 <= len(events) <= 2000:
        raise ValueError("Provide 1..2000 logged packet observations")
    normalized = []
    for event in events:
        from .traffic_capture import FIELDS as capture_fields, metadata as capture_metadata
        if not isinstance(event, dict) or set(event) - {"event_id", "source_ip", "port", "protocol", "verdict", "count", "first_seen", "last_seen", *capture_fields} or not isinstance(event.get("event_id"), str) or not re.fullmatch(r"[a-f0-9]{64}", event["event_id"]):
            raise ValueError("A stable kernel-cursor event identity is required")
        port = validate_port(event)
        if (port["protocol"], port["port"]) not in ports:
            raise PermissionError("The observed port was not approved for this monitor")
        typed=any(field in event for field in capture_fields)
        if (not typed and event.get("verdict")!="observed") or type(event.get("count")) is not int or event["count"] != 1:
            raise ValueError("Hit monitoring accepts individual typed capture events or legacy observed logs")
        first, last = parse_time(event.get("first_seen")), parse_time(event.get("last_seen"))
        if first != last or first < max(issued, started) or last >= expiry or last > now() + timedelta(seconds=30):
            raise ValueError("Observation is outside its actual approved lease window")
        source = str(ipaddress.ip_address(event.get("source_ip", "")))
        capture=capture_metadata(event,source,capabilities=capabilities,kinds=monitor.get("observation_kinds"))
        item = {**port, "event_id": event["event_id"], "source_ip": source, "verdict": event["verdict"], "count": 1, "first_seen": stamp(first), "last_seen": stamp(last)}
        if typed:item.update(capture)
        normalized.append(item)
    encoded = json.dumps({"monitor_id": monitor_id, "lease_starts_at": stamp(issued), "lease_expires_at": stamp(expiry), "events": normalized}, sort_keys=True, separators=(",", ":"))
    key = identifier + ":" + batch_id
    with store.flow_lock, store.traffic() as db:
        _write(db)
        request_digest = digest(encoded)
        existing = db.execute("SELECT data FROM hit_batches WHERE batch_key=?", (key,)).fetchone()
        if existing:
            if json.loads(existing[0])["request_digest"] != request_digest:
                raise ValueError("Monitor batch identity reused for different observations")
            return {"accepted": len(normalized), "duplicate": True, "queued": True}
        pending = db.execute("SELECT COUNT(*) FROM hit_batches WHERE processed=0").fetchone()[0]
        if pending >= 10000:
            raise RuntimeError("Hit ingestion queue is full; retry later")
        usage = _usage(db)
        if usage["batches"] >= MAX_STORED_BATCHES:
            raise RuntimeError("Hit receipt storage budget is full; retry after retention cleanup")
        inserted = 0
        for event in normalized:
            event_key = identifier + ":" + event["event_id"]
            fingerprint = digest({"monitor_id": monitor_id, **event})
            old = db.execute("SELECT event_digest FROM hit_events WHERE id=?", (event_key,)).fetchone()
            if old:
                if old[0] != fingerprint:
                    raise ValueError("Monitor event identity reused for different data")
                continue
            metadata = target.get("service_snapshot", {}).get(f"{event['protocol']}:{event['port']}", {})
            record = {**event, "hostname": target["hostname"], **metadata, "service_basis": target.get("service_basis", "inventory_at_monitor_enable"), "inventory_at": target.get("inventory_at")}
            expires = stamp(parse_time(event["last_seen"]) + timedelta(hours=monitor["retention_hours"]))
            capture=capture_metadata(event,event["source_ip"])
            db.execute("INSERT INTO hit_events(id,server_id,monitor_id,batch_key,event_digest,source_ip,port,protocol,event_time,expires_at,data,processed,capture_kind,capture_backend,count_unit,address_family,verdict) VALUES(?,?,?,?,?,?,?,?,?,?,?,0,?,?,?,?,?)",
                (event_key, identifier, monitor_id, key, fingerprint, event["source_ip"], event["port"], event["protocol"], event["last_seen"], expires, json.dumps(record, separators=(",", ":")), *(capture[field] for field in capture_fields),event["verdict"]))
            inserted += 1
        if usage["events"] + inserted > MAX_STORED_EVENTS:
            raise RuntimeError("Hit observation storage budget is full; retry after retention cleanup")
        receipt = json.dumps({"request_digest": request_digest, "event_count": len(normalized), "inserted_count": inserted}, separators=(",", ":"))
        db.execute("INSERT INTO hit_batches(batch_key,server_id,monitor_id,data,received_at,processed) VALUES(?,?,?,?,?,0)", (key, identifier, monitor_id, receipt, stamp()))
        usage.update(events=usage["events"] + inserted, batches=usage["batches"] + 1)
        store._put(db, "hit_limits", usage)
        return {"accepted": inserted, "duplicate_events": len(normalized) - inserted, "duplicate": False, "queued": True}


def process(store, limit=100):
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 1000:
        raise ValueError("Choose a bounded ingestion batch count")
    from .traffic_capture import BURST_FRESHNESS, BURST_THRESHOLD, record_burst

    alerts = []
    cutoff = stamp(now() - BURST_FRESHNESS)
    with store.flow_lock, store.traffic() as db:
        _write(db)
        batches = db.execute("SELECT batch_key,server_id,monitor_id FROM hit_batches WHERE processed=0 ORDER BY received_at,batch_key LIMIT ?", (limit,)).fetchall()
        for batch in batches:
            db.execute("UPDATE hit_events SET processed=1 WHERE batch_key=? AND processed=0", (batch[0],))
        for batch in batches:
            key, server, monitor = batch[0], batch[1], batch[2]
            rows = db.execute("""WITH changed AS (
              SELECT DISTINCT source_ip,protocol,port,capture_kind,event_time FROM hit_events
              WHERE batch_key=? AND event_time>=? AND capture_kind IN ('accepted_connection','denied_packet')
            ) SELECT f.source_ip,f.protocol,f.port,f.capture_kind,f.event_time,COUNT(*) AS count
              FROM changed JOIN hit_events f ON f.source_ip=changed.source_ip AND f.protocol=changed.protocol
                AND f.port=changed.port AND f.capture_kind=changed.capture_kind AND f.event_time=changed.event_time
              WHERE f.server_id=? AND f.monitor_id=? AND f.processed=1
              GROUP BY f.source_ip,f.protocol,f.port,f.capture_kind,f.event_time HAVING COUNT(*)>=?
              ORDER BY count DESC,f.event_time,f.source_ip,f.protocol,f.port,f.capture_kind""",
                              (key, cutoff, server, monitor, BURST_THRESHOLD)).fetchall()
            if rows:
                alerts.append((key, server, rows))
            else:
                db.execute("UPDATE hit_batches SET processed=1 WHERE batch_key=?", (key,))
    if alerts:
        # Persist alerts after committing validated traffic. A metadata failure leaves
        # the affected batches pending and the alert IDs make retries idempotent.
        with store.lock, store.meta() as db:
            _write(db)
            for _, identifier, rows in alerts:
                server = store._get(db, "servers", identifier)
                if server and not server.get("retired_at"):
                    for row in rows:
                        record_burst(store, db, server, row[0], row[1], row[2], row[3], row[4], row[5])
        with store.flow_lock, store.traffic() as db:
            _write(db)
            for key, _, _ in alerts:
                db.execute("UPDATE hit_batches SET processed=1 WHERE batch_key=?", (key,))
    return len(batches)


def prune(store):
    at = now()
    with store.flow_lock, store.traffic() as db:
        _write(db)
        removed_events = getattr(db.execute("DELETE FROM hit_events WHERE expires_at<?", (stamp(at),)), "cursor", None)
        removed_events = removed_events.rowcount if removed_events is not None else db.execute("SELECT changes()").fetchone()[0]
        removed_batches = getattr(db.execute("DELETE FROM hit_batches WHERE processed=1 AND received_at<?", (stamp(at - timedelta(hours=1)),)), "cursor", None)
        removed_batches = removed_batches.rowcount if removed_batches is not None else db.execute("SELECT changes()").fetchone()[0]
        usage = _usage(db)
        usage.update(events=max(0, usage["events"] - removed_events), batches=max(0, usage["batches"] - removed_batches))
        if usage["events"] or usage["batches"]:
            store._put(db, "hit_limits", usage)
        else:
            db.execute("DELETE FROM hit_limits WHERE id='usage'")
    with store.lock, store.meta() as db:
        from .approval_views import _expression
        expiry = _expression(db, ("expires_at",))
        rows = db.execute("SELECT id FROM hit_monitor_reviews WHERE " + expiry + "<=? ORDER BY " + expiry + " LIMIT 100", (stamp(at),)).fetchall()
        for row in rows:
            db.execute("DELETE FROM hit_monitor_reviews WHERE id=?", (row[0],))


def hits(store, identifier, window_hours=1, limit=100, offset=0, server_id=None):
    if type(window_hours) is not int or not 1 <= window_hours <= 24 or type(limit) is not int or not 1 <= limit <= 200 or type(offset) is not int or not 0 <= offset <= 1000000:
        raise ValueError("Choose 1..24 hours and a bounded hit page")
    with store.read_meta() as db:
        monitor = _monitor(db, identifier)
        if not monitor:
            raise KeyError(identifier)
    if window_hours > monitor["retention_hours"]:
        raise ValueError("Requested window exceeds this monitor's retained history")
    clause, params = "monitor_id=? AND processed=1 AND event_time>=? AND expires_at>=?", [identifier, stamp(now() - timedelta(hours=window_hours)), stamp()]
    if server_id:
        if not isinstance(server_id, str) or not ID.fullmatch(server_id):
            raise ValueError("Invalid endpoint filter")
        clause += " AND server_id=?"
        params.append(server_id)
    grouped = "SELECT server_id,source_ip,port,protocol,verdict,capture_kind,capture_backend,count_unit,address_family,COUNT(*) AS count,MIN(event_time) AS first_seen,MAX(event_time) AS last_seen FROM hit_events WHERE " + clause + " GROUP BY server_id,source_ip,port,protocol,verdict,capture_kind,capture_backend,count_unit,address_family"
    with store.read_traffic() as db:
        total = db.execute("SELECT COUNT(*) FROM (" + grouped + ") hit_groups", params).fetchone()[0]
        rows = db.execute(grouped + " ORDER BY last_seen DESC,server_id,source_ip,port,protocol LIMIT ? OFFSET ?", (*params, limit, offset)).fetchall()
    result = []
    with store.read_meta() as db:
        for row in rows:
            item = dict(row)
            target = db.execute("SELECT data FROM hit_monitor_targets WHERE monitor_id=? AND server_id=?", (identifier, item["server_id"])).fetchone()
            context = json.loads(target[0]) if target else {}
            item.update(hostname=context.get("hostname", item["server_id"]), **context.get("service_snapshot", {}).get(f"{item['protocol']}:{item['port']}", {}))
            item.update(monitor_id=identifier, service_basis="inventory_at_monitor_enable")
            item["count"] = int(item["count"])
            from .traffic_capture import public as capture_public
            result.append(capture_public(item))
    return {"items": result, "total": total, "limit": limit, "offset": offset, "has_more": offset + len(result) < total, "window_hours": window_hours,
            "monitor": monitor, "coverage": "Transport connections, denied packets and legacy logs use distinct units. Loss, backend support and limited windows prevent a complete ledger or application-success claim.", "automatic_policy": False}


def _cell(value):
    text = str(value if value is not None else "")
    return "'" + text if text.startswith(("=", "+", "-", "@", "\t", "\r")) else text


@contextmanager
def csv_spool(store, identifier, window_hours=1, server_id=None):
    # Validate scope before creating a private anonymous file. Export individual
    # log records in one read snapshot, never OFFSET across a changing stream.
    if type(window_hours) is not int or not 1 <= window_hours <= 24:
        raise ValueError("Choose a 1..24 hour export window")
    with store.read_meta() as db:
        monitor = _monitor(db, identifier)
    if not monitor:
        raise KeyError(identifier)
    if window_hours > monitor["retention_hours"]:
        raise ValueError("Export window exceeds retained history")
    clause = "monitor_id=? AND processed=1 AND event_time>=? AND expires_at>=?"
    params = [identifier, stamp(now() - timedelta(hours=window_hours)), stamp()]
    if server_id:
        if not isinstance(server_id, str) or not ID.fullmatch(server_id):
            raise ValueError("Invalid endpoint export filter")
        clause += " AND server_id=?"
        params.append(server_id)
    source = tempfile.TemporaryFile(mode="w+b")
    try:
        source.write(b"\xef\xbb\xbf")
        fields = ("monitor_id", "server_id", "hostname", "source_ip", "port", "protocol", "service", "process", "count", "first_seen", "last_seen", "verdict", "service_basis", "count_unit", "capture_kind", "capture_backend", "address_family")
        def write(row):
            buffer = io.StringIO()
            csv.writer(buffer).writerow([_cell(value) for value in row])
            source.write(buffer.getvalue().encode())
            if source.tell() > 64 * 1024 * 1024:
                raise ValueError("Hit export exceeds64MiB; narrow the endpoint/time window")
        write(fields)
        from .inventory_views import rows
        with store.read_traffic() as db:
            for row in rows(db, "SELECT server_id,data FROM hit_events WHERE " + clause + " ORDER BY event_time,id", params, batch_size=64):
                from .traffic_capture import public as capture_public
                record = capture_public({**json.loads(row[1]), "server_id": row[0], "monitor_id": identifier})
                write(record.get(field) for field in fields)
        size = source.tell()
        source.seek(0)
        yield source, size
    finally:
        source.close()


def report_status(store, db, server, value):
    """Telemetry never authorizes capture; remember exact cleanup ACKs per target."""
    entries = value.get('hit_monitoring')
    if entries is None:
        return
    if not isinstance(entries, list) or len(entries) > 16:
        raise ValueError('Invalid bounded hit monitoring status')
    normalized, seen = [], set()
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get('id'), str) or not ID.fullmatch(entry['id']) or entry['id'] in seen:
            raise ValueError('Invalid hit monitoring identity')
        seen.add(entry['id'])
        if entry.get('status') not in ('observing', 'off', 'expired', 'error'):
            raise ValueError('Invalid hit monitoring state')
        checked = parse_time(entry.get('checked_at', ''))
        if checked > now() + timedelta(seconds=60):
            raise ValueError('Future hit monitoring status')
        error = entry.get('error', '')
        if not isinstance(error, str) or len(error) > 4096:
            raise ValueError('Invalid hit monitoring error')
        item = {'id': entry['id'], 'status': entry['status'], 'checked_at': stamp(checked), 'received_at': stamp(), 'error': error}
        from .traffic_capture import coverage as capture_coverage
        item.update(capture_coverage(entry))
        if entry.get('lease_expires_at'):
            item['lease_expires_at'] = stamp(parse_time(entry['lease_expires_at']))
        key = entry['id'] + ':' + server['id']
        row = db.execute('SELECT data FROM hit_monitor_targets WHERE id=?', (key,)).fetchone()
        if not row:
            continue  # An old/pruned local identity is no longer central scope.
        target = json.loads(row[0])
        prior = target.get('last_outcome', {})
        if not prior or parse_time(prior['checked_at']) <= checked:
            target['last_outcome'] = item
            db.execute('UPDATE hit_monitor_targets SET data=? WHERE id=?', (json.dumps(target, separators=(',', ':')), key))
        normalized.append(item)
    server['hit_monitoring'] = normalized


def retirement_blockers(store, db, server):
    if db.execute('SELECT 1 FROM hit_monitor_targets WHERE server_id=? AND enabled=1 LIMIT 1', (server['id'],)).fetchone():
        return ['Stop continuous hit monitoring before retiring this endpoint.']
    # A previous signed lease can survive a requested stop for up to120 seconds.
    # Require the endpoint actual rule cleanup receipt; central desired off is
    # deliberately not equated with a verified absence of capture rules.
    from .approval_views import _expression
    status = _expression(db, ('last_outcome', 'status'), 't')
    checked = _expression(db, ('last_outcome', 'checked_at'), 't')
    stopped = _expression(db, ('stopped_at',), 'm')
    if db.execute('SELECT 1 FROM hit_monitor_targets t JOIN hit_monitors m ON m.id=t.monitor_id WHERE t.server_id=? AND (COALESCE(' + status + ",'') NOT IN ('off','expired') OR COALESCE(" + checked + ",'')<COALESCE(" + stopped + ",'')) LIMIT 1", (server['id'],)).fetchone():
        return ['Continuous hit monitor cleanup is not yet acknowledged by the endpoint.']
    return []


def target_page(store, identifier, limit=50, offset=0):
    if type(limit) is not int or not 1 <= limit <= 50 or type(offset) is not int or not 0 <= offset <= 1000000:
        raise ValueError('Choose a bounded monitoring target page')
    with store.read_meta() as db:
        monitor = _monitor(db, identifier)
        if not monitor:
            raise KeyError(identifier)
        from .approval_views import _expression
        fields = ('hostname', 'last_outcome')
        projection = ','.join(_expression(db, (field,)) for field in fields)
        # last_outcome is an object; ->> returns its JSON representation on PG.
        rows = db.execute('SELECT server_id,' + projection + ' FROM hit_monitor_targets WHERE monitor_id=? ORDER BY server_id LIMIT ? OFFSET ?', (identifier, limit, offset)).fetchall()
        items = [{'server_id': row[0], 'hostname': row[1], 'last_outcome': json.loads(row[2]) if row[2] else None} for row in rows]
        return {'items': items, 'total': monitor['target_count'], 'limit': limit, 'offset': offset, 'has_more': offset + len(items) < monitor['target_count'], 'summary_only': True}
