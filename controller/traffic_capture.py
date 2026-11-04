"""Typed capture evidence, separate from access authority and application health.

Legacy journal records stay legacy records, including old reported verdicts.
Conntrack transport observations and terminal NFLOG packet observations must
never be aggregated into one count with different units.
"""
from __future__ import annotations

import ipaddress
import json
import re
from datetime import timedelta

CAPABILITY = "traffic_capture_v1"
KINDS = ("accepted_connection", "denied_packet")
FIELDS = ("capture_kind", "capture_backend", "count_unit", "address_family")
SAMPLE_UNIT = "sample_minutes"
COUNT_UNITS = ("connections", "packets", "log_records", SAMPLE_UNIT)
TYPED = {
    "accepted_connection": ("conntrack", "connections", "allowed"),
    "denied_packet": ("nflog", "packets", "denied"),
}
FLOW_COLUMNS = (
    ("capture_kind", "TEXT NOT NULL DEFAULT 'legacy_log'"),
    ("capture_backend", "TEXT NOT NULL DEFAULT 'journal'"),
    ("count_unit", "TEXT NOT NULL DEFAULT 'log_records'"),
    ("address_family", "TEXT NOT NULL DEFAULT ''"),
    ("event_id", "TEXT NOT NULL DEFAULT ''"),
    ("event_digest", "TEXT NOT NULL DEFAULT ''"),
    ("capture_processed", "INTEGER NOT NULL DEFAULT 1"),
    ("capture_expires_at", "TEXT NOT NULL DEFAULT ''"),
)
HIT_COLUMNS = FLOW_COLUMNS[:4] + (("verdict", "TEXT NOT NULL DEFAULT 'observed'"),)
_UNSCOPED = object()
BURST_THRESHOLD = 100
BURST_FRESHNESS = timedelta(minutes=10)


def record_burst(store, db, server, source, protocol, port, kind, second, count):
    from .store import digest, now, parse_time

    if kind not in TYPED or count < BURST_THRESHOLD:
        return
    point = parse_time(second)
    if point < now() - BURST_FRESHNESS:
        return
    window = int(point.timestamp()) // (15 * 60)
    identifier = "burst:" + digest([server["id"], protocol, port, kind, window])
    if store._get(db, "alerts", identifier):
        return
    unit = TYPED[kind][1]
    store._event(db, identifier, "traffic_burst", "warning", server["id"],
                 f"At least {count} {unit} from {source} hit {server['hostname']} on {port}/{protocol} in one second.",
                 {"source_ip": source, "port": port, "protocol": protocol, "capture_kind": kind,
                  "count_unit": unit, "count": count, "observed_at": second, "rate_is_lower_bound": True})


def observation_kinds(value):
    """Missing means both kinds: the user's explicit any-hit learning choice."""
    if value is None:
        return list(KINDS)
    if not isinstance(value, list) or not 1 <= len(value) <= 2 or any(kind not in KINDS for kind in value):
        raise ValueError("Select accepted_connection, denied_packet, or both observation kinds")
    return sorted(set(value))


def initialize(db):
    postgres = getattr(db, "dialect", "sqlite") == "postgresql"
    for table, fields in (("flows", FLOW_COLUMNS), ("hit_events", HIT_COLUMNS)):
        columns = set() if postgres else {row[1] for row in db.execute("PRAGMA table_info(" + table + ")")}
        for name, definition in fields:
            if postgres:
                db.execute("ALTER TABLE " + table + " ADD COLUMN IF NOT EXISTS " + name + " " + definition)
            elif name not in columns:
                db.execute("ALTER TABLE " + table + " ADD COLUMN " + name + " " + definition)
    db.execute("CREATE UNIQUE INDEX IF NOT EXISTS flows_capture_identity ON flows(server_id,session_id,event_id) WHERE event_id<>''")
    db.execute("CREATE INDEX IF NOT EXISTS flows_capture_second ON flows(server_id,session_id,source_ip,protocol,port,capture_kind,first_seen) WHERE capture_processed=1 AND event_id<>''")
    db.execute("CREATE INDEX IF NOT EXISTS hit_events_burst ON hit_events(server_id,monitor_id,source_ip,protocol,port,capture_kind,event_time) WHERE processed=1")


def batch_peaks(db, batch):
    """Count fixed UTC seconds over unique typed events from all processed batches."""
    peaks = {}
    sql = """WITH changed AS (
        SELECT DISTINCT source_ip,protocol,port,capture_kind,first_seen
        FROM flows WHERE batch_key=? AND capture_processed=1 AND event_id<>''
          AND count_unit IN ('connections','packets')
    ) SELECT f.source_ip,f.protocol,f.port,f.capture_kind,f.first_seen,SUM(f.count)
    FROM changed JOIN flows f ON f.source_ip=changed.source_ip AND f.protocol=changed.protocol
        AND f.port=changed.port AND f.capture_kind=changed.capture_kind AND f.first_seen=changed.first_seen
    JOIN batches b ON b.batch_key=f.batch_key
    WHERE f.server_id=? AND f.session_id=? AND f.capture_processed=1 AND f.event_id<>''
        AND f.count_unit IN ('connections','packets')
        AND (b.evidence_processed=1 OR b.received_at<? OR (b.received_at=? AND b.batch_key<=?))
    GROUP BY f.source_ip,f.protocol,f.port,f.capture_kind,f.first_seen"""
    # Use the same batch order as reconciliation so a report can never show
    # a burst from a future batch before its observations are published.
    args = (batch["batch_key"], batch["server_id"], batch["session_id"], batch["received_at"], batch["received_at"], batch["batch_key"])
    for row in db.execute(sql, args):
        key = (row[0], row[1], row[2], row[3])
        second, count = row[4], int(row[5])
        previous = peaks.get(key)
        if previous is None or count > previous[0] or (count == previous[0] and second < previous[1]):
            peaks[key] = (count, second)
    return peaks



def metadata(event, source=None, *, capabilities=None, kinds=_UNSCOPED):
    source = ipaddress.ip_address(source if source is not None else event["source_ip"])
    family = "ipv4" if source.version == 4 else "ipv6"
    typed = any(key in event for key in FIELDS)
    if not typed:
        if kinds is not _UNSCOPED and kinds is not None:
            raise ValueError("This reviewed scope requires typed capture; legacy logs cannot substitute for selected observation kinds")
        return {"capture_kind": "legacy_log", "capture_backend": "journal", "count_unit": "log_records", "address_family": family}
    if kinds is None:
        raise ValueError("Historical journal-only scope cannot receive unreviewed typed capture")
    if getattr(source,"scope_id",None) or getattr(source,"ipv4_mapped",None) is not None:
        raise ValueError("Typed capture requires native unscoped IPv4 or IPv6 addresses")
    if any(key not in event for key in FIELDS):
        raise ValueError("Typed capture requires kind, backend, count unit and address family together")
    kind = event["capture_kind"]
    if kind not in TYPED or tuple(event[key] for key in ("capture_backend", "count_unit", "verdict")) != TYPED[kind]:
        raise ValueError("Capture kind/backend/unit/verdict do not identify supported evidence")
    if capabilities is not None and CAPABILITY not in capabilities:
        raise ValueError("Typed evidence requires traffic_capture_v1")
    if kinds is not _UNSCOPED and kind not in observation_kinds(kinds):
        raise ValueError("Observation kind was not selected for this capture scope")
    if event["address_family"] != family:
        raise ValueError("Capture address family does not match the observed source")
    if not isinstance(event.get("event_id"), str) or not re.fullmatch(r"[a-f0-9]{64}", event["event_id"]):
        raise ValueError("Typed capture requires a stable 64-hex event_id")
    if type(event.get("count")) is not int or event["count"] != 1:
        raise ValueError("Typed capture admits individual lifecycle/packet events with count one")
    return {key: event[key] for key in FIELDS}


def public(event):
    """Do not upgrade a historical verdict string into verified capture evidence."""
    result = dict(event)
    if not result.get("capture_kind") or result.get("capture_kind") == "legacy_log":
        result.update(capture_kind="legacy_log", capture_backend="journal", count_unit="log_records")
    if not result.get("address_family"):
        result["address_family"] = "ipv4" if ipaddress.ip_address(result["source_ip"]).version == 4 else "ipv6"
    return result


def sampled_evidence(event, observed_at):
    """Make the source/service/minute identity independent of batch and backend."""
    from .store import digest, stamp
    minute = stamp(observed_at.replace(second=0, microsecond=0))
    event["event_id"] = digest(["traffic-minute-v1", event["source_ip"], event["port"], event["protocol"], minute])
    event["count_unit"] = SAMPLE_UNIT


def reserve_flows(db, batch_key, server_id, session_id, events, expires_at):
    """Reserve typed identities before ACK, without publishing unprocessed data."""
    from .store import digest
    duplicates, seen = 0, set()
    for index, event in enumerate(events):
        if event.get("capture_kind") not in TYPED:
            continue
        event_id = event["event_id"]
        if event_id in seen:
            raise ValueError("A typed capture event may occur only once in a batch")
        seen.add(event_id)
        fingerprint = digest(event)
        old = db.execute("SELECT event_digest FROM flows WHERE server_id=? AND session_id=? AND event_id=?", (server_id, session_id, event_id)).fetchone()
        if old:
            # The first observation wins for a sampled slot, even when an
            # agent restarts and the next observation has another timestamp or verdict.
            if event["count_unit"] != SAMPLE_UNIT and old[0] != fingerprint:
                raise ValueError("Capture event identity reused for different evidence")
            duplicates += 1
            continue
        db.execute("INSERT INTO flows(batch_key,event_index,server_id,session_id,source_ip,port,protocol,verdict,count,first_seen,last_seen,capture_kind,capture_backend,count_unit,address_family,event_id,event_digest,capture_processed,capture_expires_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,0,?)",
                   (batch_key,index,server_id,session_id,event["source_ip"],event["port"],event["protocol"],event["verdict"],event["count"],event["first_seen"],event["last_seen"],*(event[key] for key in FIELDS),event_id,fingerprint,expires_at))
    return duplicates


def process_batch(db, batch):
    for index, event in enumerate(json.loads(batch["data"])):
        if event.get("capture_kind") in TYPED:
            db.execute("UPDATE flows SET capture_processed=1 WHERE batch_key=? AND event_id=? AND capture_processed=0", (batch["batch_key"],event["event_id"]))
        else:
            db.execute("INSERT OR IGNORE INTO flows(batch_key,event_index,server_id,session_id,source_ip,port,protocol,verdict,count,first_seen,last_seen) VALUES(?,?,?,?,?,?,?,?,?,?,?)", (batch["batch_key"],index,batch["server_id"],batch["session_id"],event["source_ip"],event["port"],event["protocol"],event["verdict"],event["count"],event["first_seen"],event["last_seen"]))


def prune(db, cutoff, at):
    # Keep only a hash/identity tombstone until the original session's final
    # upload deadline. Otherwise a long session could replay an event after
    # raw retention and count it a second time. Tombstones cannot be published.
    ready="last_seen<? AND capture_processed=1 AND NOT EXISTS(SELECT 1 FROM batches b WHERE b.batch_key=flows.batch_key AND b.evidence_processed=0)"
    db.execute("UPDATE flows SET capture_processed=2,source_ip='',port=0,protocol='',verdict='',count=0,first_seen='',last_seen='' WHERE "+ready+" AND event_id<>''",(cutoff,))
    db.execute("DELETE FROM flows WHERE "+ready+" AND event_id=''",(cutoff,))
    db.execute("DELETE FROM flows WHERE capture_processed=2 AND capture_expires_at<?",(at,))


def coverage(value):
    """Bounded backend/family/loss facts; unknown losses are never coerced to 0."""
    result = {}
    if "capture_backends" in value:
        entries = value["capture_backends"]
        if not isinstance(entries, list) or len(entries) > 3:
            raise ValueError("Capture backend coverage must be bounded")
        normalized, seen = [], set()
        for entry in entries:
            if not isinstance(entry, dict) or set(entry) - {"backend", "status", "ipv4", "ipv6", "lost_events", "error"}:
                raise ValueError("Invalid capture backend coverage")
            backend = entry.get("backend")
            if backend not in ("conntrack", "nflog", "journal") or backend in seen or entry.get("status") not in ("active", "off", "unsupported", "error") or any(type(entry.get(key)) is not bool for key in ("ipv4", "ipv6")):
                raise ValueError("Invalid capture backend/family status")
            seen.add(backend)
            lost = entry.get("lost_events")
            error = entry.get("error", "")
            if lost is not None and (type(lost) is not int or not 0 <= lost <= 1000000000000) or not isinstance(error, str) or len(error) > 4096:
                raise ValueError("Invalid capture loss/error status")
            normalized.append({"backend": backend, "status": entry["status"], "ipv4": entry["ipv4"], "ipv6": entry["ipv6"], "lost_events": lost, "error": error})
        result["capture_backends"] = normalized
    if "capture_gaps" in value:
        gaps = value["capture_gaps"]
        if not isinstance(gaps, list) or len(gaps) > 16 or any(not isinstance(reason, str) or not reason or len(reason) > 512 for reason in gaps):
            raise ValueError("Capture gap reasons must be bounded text")
        result["capture_gaps"] = list(dict.fromkeys(gaps))
    return result
