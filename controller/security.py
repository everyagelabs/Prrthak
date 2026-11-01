"""Bounded, opt-in closed-port observations; alerts never assert a compromise."""
import hashlib
import ipaddress
import json
import re
import uuid
from datetime import timedelta

from .store import now, parse_time, stamp, validate_port


def initialize(db):
    db.execute("CREATE TABLE IF NOT EXISTS security_event_receipts (id TEXT PRIMARY KEY, server_id TEXT NOT NULL, source_ip TEXT NOT NULL, event_time TEXT NOT NULL, received_at TEXT NOT NULL, data TEXT NOT NULL)")
    db.execute("CREATE INDEX IF NOT EXISTS security_event_window ON security_event_receipts(server_id,source_ip,event_time)")
    db.execute("CREATE INDEX IF NOT EXISTS security_event_retention ON security_event_receipts(received_at)")
    db.execute("CREATE TABLE IF NOT EXISTS security_alert_windows (id TEXT PRIMARY KEY, expires_at TEXT NOT NULL, data TEXT NOT NULL)")
    db.execute("CREATE INDEX IF NOT EXISTS security_alert_expiry ON security_alert_windows(expires_at)")


def monitor(value):
    if not isinstance(value, dict):
        raise ValueError("security_monitor must be an object")
    enabled, status = value.get("enabled", False), value.get("status", "off")
    if not isinstance(enabled, bool) or status not in ("off", "active", "error", "degraded"):
        raise ValueError("Invalid security monitor state")
    error, limited, dropped = value.get("error", ""), value.get("rate_limited", True), value.get("dropped_events", 0)
    if not isinstance(error, str) or len(error) > 4096 or not isinstance(limited, bool) or isinstance(dropped, bool) or not isinstance(dropped, int) or not 0 <= dropped <= 1000000000000:
        raise ValueError("Invalid security monitor coverage")
    result = {"enabled": enabled, "status": status if enabled else "off", "error": error, "rate_limited": limited, "dropped_events": dropped}
    for key in ("started_at", "last_checked_at"):
        if value.get(key):
            point = parse_time(value[key])
            if point > now() + timedelta(seconds=60):
                raise ValueError("Security monitor timestamp is in the future")
            result[key] = stamp(point)
    return result


def normalize(value):
    if not isinstance(value, dict):
        raise ValueError("Invalid security observation")
    event_id = value.get("event_id")
    if not isinstance(event_id, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", event_id):
        raise ValueError("Security event_id is required")
    item = validate_port(value)
    for key in ("source_ip", "destination_ip"):
        if not isinstance(value.get(key), str):
            raise ValueError("Security observations require source and destination IPs")
        item[key] = str(ipaddress.ip_address(value[key]))
    count = value.get("count", 1)
    if isinstance(count, bool) or not isinstance(count, int) or not 1 <= count <= 100000000:
        raise ValueError("Invalid security observed count")
    if value.get("kind", "unexpected_port_hit") not in ("unexpected_port_hit", "multi_port_probe") or value.get("listening") is not False:
        raise ValueError("Only explicitly checked non-listening-port observations are supported")
    first, last, checked = (parse_time(value.get(key)) for key in ("first_seen", "last_seen", "inventory_checked_at"))
    if first > last or first < now() - timedelta(hours=24) or last > now() + timedelta(seconds=60):
        raise ValueError("Security observation timestamps must be ordered and within 24 hours")
    observed_while_monitoring = value.get("observed_while_monitoring", False)
    if not isinstance(observed_while_monitoring, bool):
        raise ValueError("observed_while_monitoring must be a boolean")
    item.update({"observed_while_monitoring": observed_while_monitoring, "event_id": event_id, "kind": value.get("kind", "unexpected_port_hit"), "listening": False, "count": count, "first_seen": stamp(first), "last_seen": stamp(last), "inventory_checked_at": stamp(checked)})
    return item


def alert_window(store, db, kind, server, event, details):
    point = parse_time(event["last_seen"])
    key_parts = [kind, server["id"], event["source_ip"]]
    if kind == "unexpected_port_hit":
        key_parts += [event["protocol"], str(event["port"])]
    pointer_id = hashlib.sha256("\0".join(key_parts).encode()).hexdigest()
    pointer_row = db.execute("SELECT data FROM security_alert_windows WHERE id=?", (pointer_id,)).fetchone()
    pointer = json.loads(pointer_row[0]) if pointer_row else None
    existing = None
    if pointer and parse_time(pointer["expires_at"]) > now():
        existing = store._get(db, "alerts", pointer["alert_id"])
    candidates = [existing] if existing else []
    if candidates:
        alert = max(candidates, key=lambda item: item["created_at"])
        old = alert["details"]
        old["count"] = old.get("count", 0) + event["count"] if kind == "unexpected_port_hit" else max(old.get("count", 0), details.get("count", 0))
        old["first_seen"] = min(old.get("first_seen", event["first_seen"]), details.get("first_seen", event["first_seen"]))
        old["last_seen"] = max(old.get("last_seen", event["last_seen"]), event["last_seen"])
        if kind == "possible_scan":
            old["ports"] = sorted(set(old.get("ports", [])) | set(details["ports"]))
            old["port_count"] = len(old["ports"])
        alert["updated_at"] = stamp()
        store._put(db, "alerts", alert)
        return
    key = f"security:{kind}:{server['id']}:{uuid.uuid4()}"
    metadata = {**details, "source_ip": event["source_ip"], "destination_ip": event["destination_ip"], "count": details.get("count", event["count"]), "first_seen": details.get("first_seen", event["first_seen"]), "last_seen": event["last_seen"], "window_started_at": event["last_seen"], "assessment": "Observed attempts only; possible probing does not establish lateral movement or compromise"}
    message = (f"Possible multi-port probe from {event['source_ip']} toward {server['hostname']} ({len(details['ports'])} distinct ports)" if kind == "possible_scan" else f"Unexpected-port attempt from {event['source_ip']} toward {server['hostname']} · {event['port']}/{event['protocol']}")
    store._event(db, key, kind, "warning", server["id"], message, metadata)
    expiry = stamp(now() + timedelta(hours=1))
    pointer = {"id": pointer_id, "alert_id": key, "expires_at": expiry}
    db.execute("INSERT INTO security_alert_windows(id,expires_at,data) VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET expires_at=excluded.expires_at,data=excluded.data", (pointer_id, expiry, json.dumps(pointer)))


def ingest_events(store, db, server, values):
    if not isinstance(values, list) or len(values) > 100:
        raise ValueError("At most 100 security observations may be attached to a report")
    acknowledged, correlation_events = [], []
    for value in values:
        event = normalize(value)
        event_id = event["event_id"]
        key = server["id"] + ":" + event_id
        existing = db.execute("SELECT data FROM security_event_receipts WHERE id=?", (key,)).fetchone()
        if existing:
            original = json.loads(existing[0])
            if original["event"] != event:
                raise ValueError("Security event_id was reused for different data")
            acknowledged.append(event_id)
            continue
        point, checked = parse_time(event["last_seen"]), parse_time(event["inventory_checked_at"])
        coverage = server.get("security_monitor", {})
        cached_scan = server.get("last_discovery_at")
        cache_can_override = cached_scan and parse_time(cached_scan) >= checked and not server.get("discovery_error")
        listening = bool(cache_can_override) and any(listener["port"] == event["port"] and listener["protocol"] == event["protocol"] for listener in server.get("listeners", []))
        reason = ""
        if listening:
            reason = "Known listening service; excluded from unexpected-port alerts"
        elif not event["observed_while_monitoring"] and (not coverage.get("enabled") or coverage.get("status") not in ("active", "degraded")):
            reason = "Security monitoring is not active"
        elif abs((point - checked).total_seconds()) > 180:
            reason = "No fresh listener inventory at observation time"
        elif event["destination_ip"] not in server.get("ips", []):
            reason = "Observation destination is not an enrolled local endpoint address"
        receipt = {"event": event, "accepted": not bool(reason), "ignored_reason": reason}
        db.execute("INSERT INTO security_event_receipts(id,server_id,source_ip,event_time,received_at,data) VALUES(?,?,?,?,?,?)", (key, server["id"], event["source_ip"], event["last_seen"], stamp(), json.dumps(receipt, sort_keys=True)))
        acknowledged.append(event_id)
        if reason:
            continue
        correlation_events.append(event)
        alert_window(store, db, "unexpected_port_hit", server, event, {"port": event["port"], "protocol": event["protocol"]})
        # Evaluate candidate windows from event times, including out-of-order spool delivery.
        lower, upper = stamp(point - timedelta(minutes=5)), stamp(point + timedelta(minutes=5))
        rows = db.execute("SELECT data FROM security_event_receipts WHERE server_id=? AND source_ip=? AND event_time>=? AND event_time<=?", (server["id"], event["source_ip"], lower, upper)).fetchall()
        accepted = [json.loads(row[0])["event"] for row in rows if json.loads(row[0])["accepted"]]
        for anchor in sorted({candidate["last_seen"] for candidate in accepted if candidate["last_seen"] >= event["last_seen"]}):
            window_start = parse_time(anchor) - timedelta(minutes=5)
            window = [candidate for candidate in accepted if window_start <= parse_time(candidate["last_seen"]) <= parse_time(anchor)]
            ports = sorted({candidate["port"] for candidate in window})
            if len(ports) >= 5:
                observed = {**event, "last_seen": anchor}
                alert_window(store, db, "possible_scan", server, observed, {"ports": ports, "port_count": len(ports), "count": sum(candidate["count"] for candidate in window), "first_seen": min(candidate["first_seen"] for candidate in window)})
                break
    if correlation_events:
        from .traffic_correlation import observe
        observe(store, db, server, correlation_events)
    return acknowledged


def prune(db):
    db.execute("DELETE FROM security_alert_windows WHERE expires_at < ?", (stamp(),))
    db.execute("DELETE FROM security_event_receipts WHERE received_at < ?", (stamp(now() - timedelta(hours=24)),))
