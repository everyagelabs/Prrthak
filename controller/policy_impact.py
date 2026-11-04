"""Read-only, bounded what-if analysis of managed new-ingress intent.

This does not authorize, publish, probe or prove a firewall/application outcome.
Learning and monitoring evidence retain their origin, scope and count units.
"""
from collections import Counter
from contextlib import closing
from datetime import timedelta
import json
import re

from .firewall import WorkflowConflict
from .inventory_views import rows
from .network_addresses import address, network
from .service_groups import effective_bundles
from .store import digest, exact_policy_endpoints, now, parse_time, stamp, validate_policy
from .traffic_capture import SAMPLE_UNIT, public as capture_public
from .traffic_views import DIMENSIONS, _grouped, _ids

MAX_SERVERS = 10000
MAX_DOCUMENTS = 1000
MAX_METADATA_BYTES = 32 * 1024 * 1024
MAX_RELATIONSHIPS = 20000
MAX_SOURCE_EXPANSIONS = 2000000
MAX_RULE_EXPANSIONS = 250000
OUTCOMES = ("would_allow", "would_block", "unverified")
ID = re.compile(r"[A-Za-z0-9_.:-]{1,128}\Z")
LIMITATIONS = [
    "Models new inbound TCP/UDP intent only. Established connections may survive a rule change; outbound, forwarded and container traffic are not evaluated.",
    "This preview changes no policy, assignment, firewall, approval or capture session and sends no probes. It does not prove live enforcement or application success.",
    "Only retained processed learning and monitoring observations are evaluated. No observations never means no dependencies or safe to block. Collection gaps, delayed uploads, retention and unmonitored ports leave unknown traffic.",
    "Connection, packet, sampled minute and legacy log counts remain separate by origin and capture scope. Overlapping sessions or monitors can observe the same traffic, so their counts cannot establish a unique-connection total.",
    "Reported SSH management exceptions and whole-host DHCP client exceptions are included. Learned overlays, stale protection, pending host-deny removal and unmanaged ports remain unverified when they can change a predicted rejection.",
    "Unmanaged/direct rules, NAT, routing and actual endpoint adapter readiness require agent checks. A modeled allow/block is not an installed or traffic-verified result.",
]


def _options(store, value, proposed):
    value = {} if value is None else value
    allowed = {"window_seconds", "server_ids", "ports", "source_ip", "outcome", "limit", "offset", "as_of", "context_digest"}
    if proposed:
        allowed |= {"policy", "policy_id", "expected_revision"}
    if not isinstance(value, dict) or set(value) - allowed:
        raise ValueError("Provide supported policy impact fields only")
    result = {"window_seconds": 3600, "server_ids": None, "ports": [], "source_ip": "", "outcome": "all", "limit": 50, "offset": 0, **value}
    if type(result["window_seconds"]) is not int or not 60 <= result["window_seconds"] <= min(86400, store.retention_hours * 3600):
        raise ValueError("Impact window must be within retained history, from 60 seconds to 24 hours")
    if type(result["limit"]) is not int or not 1 <= result["limit"] <= 100 or type(result["offset"]) is not int or not 0 <= result["offset"] <= MAX_RELATIONSHIPS:
        raise ValueError("Impact pagination requires limit 1..100 and a bounded offset")
    ids = result["server_ids"]
    if ids is not None and (not isinstance(ids, list) or len(ids) > MAX_SERVERS or any(not isinstance(item, str) or not ID.fullmatch(item) for item in ids)):
        raise ValueError("Select at most 10000 exact endpoint IDs")
    result["server_ids"] = None if ids is None else sorted(set(ids))
    ports = result["ports"]
    if not isinstance(ports, list) or len(ports) > 100 or any(not isinstance(p, str) or not re.fullmatch(r"[1-9]\d{0,4}(?:/(?:tcp|udp))?", p) or int(p.split('/')[0]) > 65535 for p in ports):
        raise ValueError("Impact ports must be exact port numbers, optionally /tcp or /udp")
    result["ports"] = sorted(set(ports))
    if result["outcome"] not in ("all", *OUTCOMES):
        raise ValueError("Choose an impact outcome filter")
    if not isinstance(result["source_ip"], str) or len(result["source_ip"]) > 64:
        raise ValueError("Impact source must be a native IP or CIDR")
    if result["source_ip"]:
        result["source_ip"] = str(network(result["source_ip"]))
    at = now()
    selected = parse_time(result["as_of"]) if "as_of" in result else at
    if selected > at + timedelta(seconds=5) or selected < at - timedelta(hours=store.retention_hours):
        raise ValueError("Impact query time must be recent and not in the future")
    result["as_of"] = stamp(selected)
    result["from_time"] = stamp(max(selected - timedelta(seconds=result["window_seconds"]), at - timedelta(hours=store.retention_hours)))
    if "context_digest" in result and (not isinstance(result["context_digest"], str) or not re.fullmatch(r"[a-f0-9]{64}", result["context_digest"])):
        raise ValueError("Invalid impact context digest")
    return result


def _documents(db, table, *, maximum=MAX_DOCUMENTS):
    # Table names are internal constants. LIMIT and a read budget fence precede
    # decoding, so this never materializes an unlimited canonical catalogue.
    result, total = [], 0
    with closing(rows(db, "SELECT data FROM " + table + " ORDER BY id LIMIT ?", (maximum + 1,))) as records:
        for row in records:
            total += len(row[0].encode("utf-8"))
            if len(result) >= maximum or total > MAX_METADATA_BYTES:
                raise ValueError("Policy impact metadata budget exceeded; reduce the policy catalogue before previewing")
            result.append(json.loads(row[0]))
    return result


def _servers(db):
    fields = ("hostname", "ips", "tags", "location_id", "last_seen", "protection", "protection_reported_at", "learning_coverage", "hit_monitoring", "host_default_deny_state", "_host_default_deny_active")
    postgres = getattr(db, "dialect", "sqlite") == "postgresql"
    projection = ["id"] + [("(data::jsonb->'" + field + "')::text" if postgres else "json_extract(data,'$." + field + "')") for field in fields]
    result, total = [], 0
    with closing(rows(db, "SELECT " + ",".join(projection) + " FROM servers ORDER BY id LIMIT ?", (MAX_SERVERS + 1,))) as records:
        for row in records:
            total += sum(len(item.encode("utf-8")) for item in row if isinstance(item, str))
            if len(result) >= MAX_SERVERS or total > MAX_METADATA_BYTES:
                raise ValueError("Policy impact endpoint metadata exceeds the bounded fleet size")
            server = {"id": row[0]}
            for index, field in enumerate(fields, 1):
                raw = row[index]
                if raw is None:
                    continue
                structured = field in ("ips", "tags", "protection", "learning_coverage", "hit_monitoring", "host_default_deny_state")
                server[field] = json.loads(raw) if postgres or structured else raw
            result.append(server)
    return result


class _Context:
    def __init__(self, tables):
        self.tables = tables

    def _all(self, db, table):
        return self.tables[table]


def _compilation_budget(tables, servers, policies):
    """Fence expansion using indexed actual membership, not fleet-wide guesses."""
    from .locations import reserved, selector as normalize
    index, selector_cache = {}, {}
    by_id = {server["id"]: server for server in servers}
    all_ids = set(by_id)
    locations = {location["id"] for location in tables["locations"]}
    for server in servers:
        for key, value in server.get("tags", {}).items():
            if not reserved(key):
                index.setdefault((key, value), set()).add(server["id"])
        if server.get("location_id") in locations:
            index.setdefault(("location_id", server["location_id"]), set()).add(server["id"])

    def selected(selector):
        key = tuple(sorted(selector.items()))
        if key not in selector_cache:
            parts = sorted((index.get(pair, set()) for pair in normalize(selector, tables["locations"], strict=False).items()), key=len)
            selector_cache[key] = set.intersection(*parts) if parts else all_ids
        return selector_cache[key]

    members = {group["id"]: (selected(group["selector"]) if group.get("selector") else set()) if group["type"] == "dynamic" else set(group.get("server_ids", [])) & all_ids for group in tables["groups"]}
    catalogues = {group["id"]: group for group in tables["service_groups"]}
    source_work = rule_work = 0
    for policy in policies:
        exact = exact_policy_endpoints(policy)
        targets = (exact & all_ids if exact is not None else
                   set().union(*(members.get(identifier, set()) for identifier in policy["group_ids"])) if policy.get("group_ids")
                   else selected(policy.get("selector", {})))
        for service in policy["services"]:
            ports = catalogues.get(service.get("service_group_id"), {}).get("ports", []) if "service_group_id" in service else [service]
            source_ids = set(selected(service["source_selector"])) if service.get("source_selector") else set()
            for identifier in service.get("source_group_ids", []):
                source_ids.update(members.get(identifier, set()))
            sources = len(service.get("sources", [])) + sum(len(by_id[identifier].get("ips", [])) for identifier in source_ids)
            source_work += len(targets) * len(ports) * max(1, sources)
            rule_work += len(targets) * len(ports)
            if source_work > MAX_SOURCE_EXPANSIONS or rule_work > MAX_RULE_EXPANSIONS:
                raise ValueError("Policy impact compilation exceeds its bounded analysis budget; simplify the policy/source catalogue")


def _fresh(value, at):
    try:
        return at - timedelta(seconds=180) <= parse_time(value) <= at + timedelta(seconds=60)
    except (ValueError, TypeError, OverflowError):
        return False


def _decision(server, bundle, observation, overlays, at, cache):
    try:
        source = address(observation["source_ip"])
    except (ValueError, TypeError):
        return "unverified", "Observed source has an unsupported or unknown address family"
    if observation.get("address_family") != ("ipv4" if source.version == 4 else "ipv6"):
        return "unverified", "Capture address family does not match the source"
    protected = server.get("protection") or {}
    if not _fresh(server.get("last_seen"), at) or not _fresh(server.get("protection_reported_at"), at) or protected.get("ready") is not True:
        return "unverified", "Fresh authenticated endpoint and ready SSH/controller protection are unavailable"
    if (server.get("host_default_deny_state") or {}).get("removal_pending"):
        return "unverified", "Whole-server default-deny removal is pending"
    host_deny = bundle.get("host_default_deny") is True
    port, protocol = observation["port"], observation["protocol"]
    if host_deny and protocol == "udp" and port == (68 if source.version == 4 else 546):
        return "would_allow", "Declared whole-server DHCP client control exception"
    service = next((item for item in bundle["services"] if item["port"] == port and item["protocol"] == protocol and item.get("mode", bundle["mode"]) == "enforce"), None)
    ssh = protocol == "tcp" and port in protected.get("ssh_ports", [])
    if not service and not host_deny:
        return "unverified", "This port is monitor-only or outside managed enforcement; existing firewall behavior is not inferred"
    sources = list(service["sources"]) if service else []
    if ssh:
        management = protected.get("management_sources", [])
        if not management:
            return "unverified", "Protected SSH management sources are unknown"
        sources += management
    for text in sources:
        if text not in cache:
            cache[text] = network(text)
        subnet = cache[text]
        if source.version == subnet.version and source in subnet:
            return "would_allow", "Protected SSH management exception" if ssh and text in protected.get("management_sources", []) else "Matches the compiled enforced source allowlist"
    if server["id"] in overlays:
        return "unverified", "A retained or pending learned-access overlay can allow this source independently"
    return "would_block", "Whole-server default-deny fallback" if host_deny else "Outside the compiled enforced allowlist for this exact port/protocol"


def _coverage(server, row, at):
    if row["origin"] == "learning":
        candidate = server.get("learning_coverage") or {}
        reported = candidate if candidate.get("session_id") == row["capture_scope_id"] else {}
    else:
        reported = next((entry for entry in server.get("hit_monitoring") or [] if entry.get("id") == row["capture_scope_id"]), {})
    return {"complete_window": False, "receipt_available": bool(reported), "endpoint_stale": not _fresh(server.get("last_seen"), at),
            "legacy_sampled_logs": row["capture_kind"] == "legacy_log", "sampled_minutes": row["count_unit"] == SAMPLE_UNIT,
            "dropped_events": reported.get("dropped_events"),
            "rate_limited": reported.get("rate_limited"), "capture_backends": reported.get("capture_backends", []),
            "capture_gaps": reported.get("capture_gaps", []), "error": reported.get("error", "")}


def _observations(db, value, selected):
    scope = {**value, "server_ids": sorted(selected), "search": "", "search_server_ids": []}
    learning, learning_args = _grouped(db, scope)
    fields = ",".join(field if field != "session_id" else "session_id AS capture_scope_id" for field in (*DIMENSIONS, "count", "first_seen", "last_seen"))
    learning = "SELECT 'learning' AS origin," + fields + " FROM (" + learning + ") learned"
    ids, id_args = _ids(db, "server_id", sorted(selected))
    clauses = ["processed=1", "event_time>=?", "event_time<=?", "expires_at>=?", ids]
    args = [value["from_time"], value["as_of"], stamp(), *id_args]
    source = network(value["source_ip"]) if value["source_ip"] else None
    if source is not None and source.prefixlen == source.max_prefixlen:
        # Exact source filters can reduce SQL work before the relationship
        # fence. CIDR membership remains a native-family Python comparison.
        learning += " WHERE source_ip=?"
        learning_args += (str(source.network_address),)
        clauses.append("source_ip=?")
        args.append(str(source.network_address))
    if value["ports"]:
        conditions = []
        for selection in value["ports"]:
            port, _, protocol = selection.partition('/')
            conditions.append("(port=?" + (" AND protocol=?" if protocol else "") + ")")
            args += [int(port)] + ([protocol] if protocol else [])
        clauses.append("(" + " OR ".join(conditions) + ")")
    dimensions = "server_id,monitor_id,source_ip,port,protocol,verdict,capture_kind,capture_backend,count_unit,address_family"
    monitoring = "SELECT 'monitoring' AS origin,server_id,monitor_id AS capture_scope_id,source_ip,port,protocol,verdict,capture_kind,capture_backend,count_unit,address_family,COUNT(*) AS count,MIN(event_time) AS first_seen,MAX(event_time) AS last_seen FROM hit_events WHERE " + " AND ".join(clauses) + " GROUP BY " + dimensions
    sql = "SELECT * FROM (" + learning + " UNION ALL " + monitoring + ") evidence ORDER BY last_seen DESC,origin,server_id,capture_scope_id,source_ip,port,protocol,capture_kind,capture_backend,count_unit,address_family,verdict LIMIT ?"
    return db.execute(sql, (*learning_args, *args, MAX_RELATIONSHIPS + 1))


def preview(store, value=None, *, policy_id=None, proposed=False):
    """RBAC belongs to the HTTP boundary; this function only reads projections."""
    value = _options(store, value, proposed)
    if proposed:
        if policy_id is not None:
            raise ValueError("Proposed impact carries its policy_id in the request")
        policy_id = value.get("policy_id")
    if policy_id is not None and (not isinstance(policy_id, str) or not ID.fullmatch(policy_id)):
        raise ValueError("Invalid exact policy identity")
    if not proposed and policy_id is None:
        raise ValueError("Choose an existing policy for a read-only preview")
    at = now()
    with store.read_meta() as db:
        if getattr(db, "dialect", "sqlite") == "sqlite":
            db.execute("BEGIN")
        tables = {table: _documents(db, table) for table in ("policies", "groups", "locations", "service_groups")}
        servers = _servers(db)
        old = next((policy for policy in tables["policies"] if policy["id"] == policy_id), None)
        if policy_id is not None and old is None:
            raise KeyError(policy_id)
        if proposed:
            candidate = validate_policy(value.get("policy"))
            if policy_id is None and "expected_revision" in value:
                raise ValueError("expected_revision applies only to an existing policy")
            if policy_id is not None and (type(value.get("expected_revision")) is not int or value["expected_revision"] != old.get("revision")):
                raise WorkflowConflict("Policy changed; reload its exact revision before impact preview", {})
            from .locations import selector
            candidate["selector"] = selector(candidate["selector"], tables["locations"])
            group_ids = {group["id"] for group in tables["groups"]}
            if any(identifier not in group_ids for identifier in candidate["group_ids"]):
                raise ValueError("Policy references an unknown saved target group")
            server_ids = {server["id"] for server in servers}
            if set(candidate.get("endpoint_ids", [])) - server_ids:
                raise ValueError("Policy references an unknown enrolled endpoint")
            if (old and "endpoint_ids" in old and "endpoint_ids" not in candidate
                    and not candidate["selector"] and not candidate["group_ids"]
                    and value["policy"].get("match_all") is not True):
                raise ValueError("Explicitly confirm changing this policy to all endpoints")
            for service in candidate["services"]:
                service["source_selector"] = selector(service["source_selector"], tables["locations"])
                if any(identifier not in group_ids for identifier in service["source_group_ids"]):
                    raise ValueError("Policy references an unknown saved source group")
            candidate.update(id=policy_id or "__unsaved_impact_policy__", revision=old["revision"] if old else 0)
        else:
            candidate = old
        context = _Context(tables)
        after = [policy for policy in tables["policies"] if policy["id"] != candidate["id"]] + [candidate]
        # This budget bounds allocation, never changes policy authority/scope.
        _compilation_budget(tables, servers, tables["policies"] + [candidate])
        before = effective_bundles(context, db, servers=servers, policies=tables["policies"])
        compiled = effective_bundles(context, db, servers=servers, policies=after)
        selected = before["targets"].get(candidate["id"], set()) | compiled["targets"].get(candidate["id"], set())
        if value["server_ids"] is not None:
            selected &= set(value["server_ids"])
        # Learned overlays are independently owned. Their desired/applied
        # generations are not interchangeable, so a possible acceptance makes
        # a predicted rejection unknown instead of guessing at live authority.
        postgres = getattr(db, "dialect", "sqlite") == "postgresql"
        removed = "data::jsonb->>'removed'" if postgres else "json_extract(data,'$.removed')"
        pending = "data::jsonb->>'removal_pending'" if postgres else "json_extract(data,'$.removal_pending')"
        overlays = {row[0] for row in db.execute("SELECT DISTINCT server_id FROM learning_allow_policies WHERE COALESCE(CAST(" + removed + " AS TEXT),'0') NOT IN ('true','1') OR COALESCE(CAST(" + pending + " AS TEXT),'0') IN ('true','1')")}
    by_id = {server["id"]: server for server in servers}
    changed = {identifier for identifier in selected if before["payloads"][identifier] != compiled["payloads"][identifier]}
    context_digest = digest({"candidate": candidate, "before": {identifier: before["payloads"][identifier] for identifier in sorted(selected)}, "after": {identifier: compiled["payloads"][identifier] for identifier in sorted(selected)}, "protections": {identifier: by_id[identifier].get("protection") for identifier in sorted(selected)}})
    if value.get("context_digest") and value["context_digest"] != context_digest:
        raise WorkflowConflict("Impact policy or endpoint context changed; refresh the preview", {})
    counts, units, seen_servers = Counter(), Counter(), set()
    items, total, evaluated, truncated, networks = [], 0, 0, False, {}
    source_filter = network(value["source_ip"]) if value["source_ip"] else None
    with store.read_traffic() as db:
        if getattr(db, "dialect", "sqlite") == "sqlite":
            db.execute("BEGIN")
        if selected:
            for raw in _observations(db, value, selected):
                if evaluated >= MAX_RELATIONSHIPS:
                    truncated = True
                    break
                evaluated += 1
                row = capture_public(dict(raw))
                if source_filter:
                    try:
                        source = address(row["source_ip"])
                        if source.version != source_filter.version or source not in source_filter:
                            continue
                    except (ValueError, TypeError):
                        continue
                server = by_id[row["server_id"]]
                current, current_reason = _decision(server, before["payloads"][server["id"]], row, overlays, at, networks)
                decision, reason = _decision(server, compiled["payloads"][server["id"]], row, overlays, at, networks)
                counts[decision] += 1
                units[(row["origin"], row["capture_scope_id"], row["capture_kind"], row["count_unit"])] += int(row["count"])
                seen_servers.add(server["id"])
                if value["outcome"] != "all" and value["outcome"] != decision:
                    continue
                if value["offset"] <= total < value["offset"] + value["limit"]:
                    items.append({**row, "hostname": server.get("hostname") or server["id"], "current_decision": current, "current_reason": current_reason, "proposed_decision": decision, "reason": reason, "intent_changed": current != decision, "coverage": _coverage(server, row, at)})
                total += 1
    target_ids = sorted(selected, key=lambda identifier: ((by_id[identifier].get("hostname") or identifier).casefold(), identifier))
    targets = [{"server_id": identifier, "hostname": by_id[identifier].get("hostname") or identifier, "effective_intent_changed": identifier in changed, "has_observations": identifier in seen_servers, "observation_status": "observed" if identifier in seen_servers else "unknown" if truncated else "no_retained_observations", "current_service_count": len(before["payloads"][identifier]["services"]), "proposed_service_count": len(compiled["payloads"][identifier]["services"])} for identifier in target_ids[:100]]
    return {"read_only": True, "model": "compiled_ingress_intent", "context_digest": context_digest,
            "policy": {"id": policy_id, "name": candidate["name"], "revision": candidate["revision"], "proposed": proposed},
            "as_of": value["as_of"], "from_time": value["from_time"], "window_seconds": value["window_seconds"],
            "summary": {"scope": "server_source_port_window_before_outcome_filter", "target_servers": len(selected), "effective_changed_servers": len(changed), "relationships": sum(counts.values()), "by_outcome": {key: counts[key] for key in OUTCOMES}, "counts_by_origin_unit": [{"origin": origin, "capture_scope_id": scope, "capture_kind": kind, "count_unit": unit, "count": count} for (origin, scope, kind, unit), count in sorted(units.items())][:100], "counts_by_origin_unit_truncated": len(units) > 100, "servers_with_observations": len(seen_servers), "servers_without_observations": None if truncated else len(selected - seen_servers)},
            "items": items, "total": total, "total_is_lower_bound": truncated, "limit": value["limit"], "offset": value["offset"], "next_offset": value["offset"] + len(items), "has_more": value["offset"] + len(items) < total,
            "targets": {"items": targets, "total": len(selected), "has_more": len(selected) > len(targets)},
            "coverage": {"complete_window": False, "evaluation_limit_reached": truncated, "evaluated_relationships": evaluated, "relationship_limit": MAX_RELATIONSHIPS, "filter_before_pagination": True, "late_uploads_can_change_pages": True, "unknown_dependencies": True}, "limitations": list(LIMITATIONS)}
