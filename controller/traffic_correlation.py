"""Bounded advisory fan-out of admitted closed-port observations.

Only security.ingest_events' NEW, accepted observations enter this module. Its
receipt, this state and any alert commit in the caller's metadata transaction.
This never changes policy or establishes connection success or compromise.
"""
from copy import deepcopy
from dataclasses import dataclass
from datetime import timedelta
import hashlib
import ipaddress
import json
import re

from .store import now, parse_time, stamp

STATE_ID = "r18:multi-host:v1"
KIND = "possible_lateral_movement"


@dataclass(frozen=True)
class Limits:
    # Code-owned settings, deliberately absent from endpoint reports/settings.
    window_seconds: int = 300
    distinct_hosts: int = 3
    cooldown_seconds: int = 900
    max_sources: int = 64
    max_groups: int = 256
    max_groups_per_source: int = 8
    max_destinations: int = 16
    max_alerts_per_batch: int = 10
    max_state_bytes: int = 2 * 1024 * 1024

    def __post_init__(self):
        bounds = {"window_seconds": (30, 3600), "distinct_hosts": (2, 64),
                  "cooldown_seconds": (30, 7200), "max_sources": (1, 1024),
                  "max_groups": (1, 2048), "max_groups_per_source": (1, 32),
                  "max_destinations": (2, 64), "max_alerts_per_batch": (1, 100),
                  "max_state_bytes": (1024, 2 * 1024 * 1024)}
        for field, (lower, upper) in bounds.items():
            value = getattr(self, field)
            if isinstance(value, bool) or not isinstance(value, int) or not lower <= value <= upper:
                raise ValueError("Invalid correlation limit: " + field)
        if self.distinct_hosts > self.max_destinations or self.cooldown_seconds < self.window_seconds:
            raise ValueError("Correlation threshold/cooldown cannot exceed destination/window bounds")


DEFAULT_LIMITS = Limits()


def _encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _key(source, protocol, port):
    return hashlib.sha256(f"{source}\0{protocol}\0{port}".encode()).hexdigest()


def _source(value):
    address = ipaddress.ip_address(value)
    if address.is_unspecified or address.is_multicast or address.is_loopback or address.is_link_local or getattr(address, "scope_id", None):
        raise ValueError("An unambiguous unicast source is required")
    return str(address)


def _empty(at, limited=False):
    return {"id": STATE_ID, "version": 1, "groups": {}, "coverage_limited": limited,
            "dropped_observations": 0, "expires_at": stamp(at)}


def _load(db, at, limits):
    # The database byte fence precedes transfer and JSON decoding, including for
    # malformed/legacy rows. Syntax is fixed for the two supported dialects.
    size = "octet_length(data)" if getattr(db, "dialect", "sqlite") == "postgresql" else "length(CAST(data AS BLOB))"
    row = db.execute("SELECT CASE WHEN " + size + "<=? THEN data ELSE NULL END FROM security_alert_windows WHERE id=?", (limits.max_state_bytes, STATE_ID)).fetchone()
    if not row:
        return _empty(at)
    if row[0] is None:
        return _empty(at, limited=True)
    try:
        state = json.loads(row[0])
        groups = state["groups"]
        if state["id"] != STATE_ID or state["version"] != 1 or not isinstance(groups, dict) or len(groups) > limits.max_groups or not isinstance(state["coverage_limited"], bool) or type(state["dropped_observations"]) is not int or not 0 <= state["dropped_observations"] <= 1000000000:
            raise ValueError("Invalid correlation state")
        sources = {}
        for key, group in groups.items():
            source = _source(group["source_ip"])
            if source != group["source_ip"] or group["protocol"] not in ("tcp", "udp") or type(group["port"]) is not int or not 1 <= group["port"] <= 65535 or key != _key(source, group["protocol"], group["port"]):
                raise ValueError("Invalid correlation tuple")
            sources[source] = sources.get(source, 0) + 1
            if len(sources) > limits.max_sources or sources[source] > limits.max_groups_per_source or not isinstance(group["hosts"], dict) or len(group["hosts"]) > limits.max_destinations:
                raise ValueError("Invalid correlation cardinality")
            latest = parse_time(group["latest_seen"])
            if latest > at + timedelta(seconds=60):
                raise ValueError("Invalid correlation clock")
            for field in ("last_alerted_at", "last_alert_anchor"):
                if group[field] is not None:
                    if parse_time(group[field]) > at + timedelta(seconds=60):
                        raise ValueError("Invalid correlation clock")
            for identifier, host in group["hosts"].items():
                if not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", identifier) or not isinstance(host["hostname"], str) or len(host["hostname"]) > 253:
                    raise ValueError("Invalid destination host")
                ipaddress.ip_address(host["destination_ip"])
                if parse_time(host["last_seen"]) > latest:
                    raise ValueError("Invalid destination clock")
        # Discard unknown legacy fields; only this fixed bounded shape persists.
        normalized = {"id": STATE_ID, "version": 1, "coverage_limited": state["coverage_limited"],
                      "dropped_observations": state["dropped_observations"], "expires_at": stamp(at),
                      "groups": {key: {**{field: group[field] for field in ("source_ip", "protocol", "port")},
                                        **{field: stamp(parse_time(group[field])) if group[field] else None for field in ("latest_seen", "last_alerted_at", "last_alert_anchor")},
                                        "hosts": {identifier: {"hostname": host["hostname"], "destination_ip": host["destination_ip"], "last_seen": stamp(parse_time(host["last_seen"]))} for identifier, host in group["hosts"].items()}} for key, group in groups.items()}}
        if len(_encode(normalized)) + 256 > limits.max_state_bytes:
            raise ValueError("Legacy state exceeds the canonical encoding budget")
        return normalized
    except (ValueError, TypeError, KeyError, RecursionError, OverflowError):
        # Correlation is advisory: a corrupt/oversized row must not prevent a
        # heartbeat or its existing per-host security observations from landing.
        return _empty(at, limited=True)


def _active(group, at, limits):
    anchor = max(at, parse_time(group["latest_seen"]))
    lower = anchor - timedelta(seconds=limits.window_seconds)
    return {key: host for key, host in group["hosts"].items() if lower <= parse_time(host["last_seen"]) <= anchor}


def observe(store, db, server, accepted_events, *, at=None, limits=None):
    """Consume <=100 already-admitted events in the caller's metadata txn.

    Membership uses observation time, never receipt time/count. Endpoint IDs are
    distinct destinations even when IPs are shared; IP ownership is not inferred.
    Expiry also runs on empty reports. Active saturated keys are not evicted,
    preserving deduplication; coverage loss is explicit and state stays bounded.
    """
    at, limits = at or now(), limits or DEFAULT_LIMITS
    if not isinstance(accepted_events, list) or len(accepted_events) > 100:
        raise ValueError("At most 100 admitted correlation events are supported")
    state = _load(db, at, limits)
    groups, changed = state["groups"], set()
    retention = timedelta(seconds=max(limits.window_seconds, limits.cooldown_seconds) + 60)
    for key, group in list(groups.items()):
        last = max(parse_time(group["latest_seen"]), parse_time(group["last_alerted_at"]) if group["last_alerted_at"] else at - retention)
        if last + retention < at:
            del groups[key]
        else:
            group["hosts"] = _active(group, at, limits)
    sizes = {key: len(_encode(group)) for key, group in groups.items()}
    used = len(_encode(state))
    sources = {}
    for group in groups.values():
        sources[group["source_ip"]] = sources.get(group["source_ip"], 0) + 1
    result = {"alerts": 0, "ignored": 0, "dropped": 0, "deferred_alerts": 0, "groups": 0, "coverage_limited": state["coverage_limited"]}

    def dropped():
        state["coverage_limited"] = True
        state["dropped_observations"] = min(1000000000, state["dropped_observations"] + 1)
        result["dropped"] += 1

    for event in accepted_events:
        point = parse_time(event["last_seen"])
        try:
            source = _source(event["source_ip"])
        except ValueError:
            result["ignored"] += 1
            continue
        if point < at - timedelta(seconds=limits.window_seconds) or point > at + timedelta(seconds=60):
            result["ignored"] += 1
            continue
        key = _key(source, event["protocol"], event["port"])
        original = groups.get(key)
        if original is None and (len(groups) >= limits.max_groups or (source not in sources and len(sources) >= limits.max_sources) or sources.get(source, 0) >= limits.max_groups_per_source):
            dropped()
            continue
        group = deepcopy(original) if original else {"source_ip": source, "protocol": event["protocol"], "port": event["port"], "hosts": {}, "latest_seen": event["last_seen"], "last_alerted_at": None, "last_alert_anchor": None}
        group["latest_seen"] = max(group["latest_seen"], event["last_seen"])
        group["hosts"] = _active(group, at, limits)
        previous = group["hosts"].get(server["id"])
        if previous is None and len(group["hosts"]) >= limits.max_destinations:
            dropped()
            continue
        if previous is None or point > parse_time(previous["last_seen"]):
            group["hosts"][server["id"]] = {"hostname": server["hostname"], "destination_ip": event["destination_ip"], "last_seen": event["last_seen"]}
        size = len(_encode(group))
        delta = size - sizes[key] if original else len(_encode(key)) + 1 + size + bool(groups)
        # Reserve room for timestamps, counters and the expiry field. Checking
        # each small group avoids repeatedly serializing the entire state.
        if used + delta + 256 + 64 * (len(changed) + 1) > limits.max_state_bytes:
            dropped()
            continue
        groups[key], sizes[key], used = group, size, used + delta
        if original is None:
            sources[source] = sources.get(source, 0) + 1
        changed.add(key)

    eligible = []
    for key in sorted(changed):
        group = groups[key]
        hosts = _active(group, at, limits)
        anchor = max(host["last_seen"] for host in hosts.values()) if hosts else ""
        if len(hosts) < limits.distinct_hosts or (group["last_alert_anchor"] and anchor <= group["last_alert_anchor"]) or (group["last_alerted_at"] and parse_time(group["last_alerted_at"]) + timedelta(seconds=limits.cooldown_seconds) > at):
            continue
        eligible.append((key, group, hosts, anchor))
    if len(eligible) > limits.max_alerts_per_batch:
        state["coverage_limited"] = True
        result["deferred_alerts"] = len(eligible) - limits.max_alerts_per_batch
    for key, group, hosts, anchor in eligible[:limits.max_alerts_per_batch]:
        destinations = [{"server_id": identifier, **host} for identifier, host in sorted(hosts.items())]
        details = {"source_ip": group["source_ip"], "protocol": group["protocol"], "port": group["port"],
                   "destination_count": len(destinations), "destinations": destinations, "target_server_ids": sorted(hosts), "snapshot": True,
                   "window_seconds": limits.window_seconds, "window_started_at": stamp(parse_time(anchor) - timedelta(seconds=limits.window_seconds)), "last_seen": anchor,
                   "shared_destination_address": len({host["destination_ip"] for host in destinations}) < len(destinations),
                   "coverage_limited": state["coverage_limited"], "destination_count_is_lower_bound": state["coverage_limited"],
                   "basis": "admitted_unexpected_port_observations", "verdict": "observed", "connection_success": "unknown", "automatic_action": "none",
                   "assessment": "Possible scan/lateral movement pattern only. Authorized scanners, monitoring and NAT/shared addresses can produce this pattern. Observed attempts do not establish successful connections, lateral movement or compromise; no automatic denial."}
        identifier = "security:" + KIND + ":" + key + ":" + anchor
        store._event(db, identifier, KIND, "warning", server["id"], f"Possible multi-host scan/lateral-movement pattern from {group['source_ip']} toward {len(destinations)} destination hosts · {group['port']}/{group['protocol']}", details)
        group["last_alerted_at"], group["last_alert_anchor"] = stamp(at), anchor
        result["alerts"] += 1
    expiry = max([at] + [max(parse_time(group["latest_seen"]), parse_time(group["last_alerted_at"]) if group["last_alerted_at"] else at - retention) + retention for group in groups.values()])
    state["expires_at"] = stamp(expiry)
    if groups or state["coverage_limited"]:
        encoded = _encode(state)
        if len(encoded) > limits.max_state_bytes:
            raise ValueError("Correlation state exceeded its code-owned byte bound")
        db.execute("INSERT INTO security_alert_windows(id,expires_at,data) VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET expires_at=excluded.expires_at,data=excluded.data", (STATE_ID, state["expires_at"], encoded))
    else:
        db.execute("DELETE FROM security_alert_windows WHERE id=?", (STATE_ID,))
    result.update(groups=len(groups), coverage_limited=state["coverage_limited"])
    return result
