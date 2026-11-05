"""Bounded alert navigation with fleet-wide counts independent of page size."""
import json
import re

from .approval_views import _expression
from .store import stamp

FIELDS = ("id", "kind", "type", "severity", "server_id", "title", "message", "status", "created_at", "updated_at", "resolved_at", "resolution_reason", "acknowledged_at", "acknowledged_by", "occurrence_id")


def _validate(value):
    if value is None:
        value = {}
    allowed = {"limit", "offset", "include_resolved", "server_ids", "listener_server_ids", "search_server_ids", "ports", "search"}
    if not isinstance(value, dict) or set(value) - allowed:
        raise ValueError("Provide supported alert navigation fields only")
    result = {"limit": 50, "offset": 0, "include_resolved": False, "server_ids": None, "listener_server_ids": [], "search_server_ids": [], "ports": [], "search": "", **value}
    if type(result["limit"]) is not int or not 1 <= result["limit"] <= 100 or type(result["offset"]) is not int or not 0 <= result["offset"] <= 10000000:
        raise ValueError("Alert pagination requires limit 1..100 and a nonnegative bounded offset")
    if type(result["include_resolved"]) is not bool or not isinstance(result["search"], str) or len(result["search"]) > 256:
        raise ValueError("Use a boolean recovered-alert option and search of at most 256 characters")
    for key in ("server_ids", "listener_server_ids", "search_server_ids"):
        ids = result[key]
        if ids is None and key == "server_ids":
            continue
        if not isinstance(ids, list) or len(ids) > 10000 or any(not isinstance(item, str) or not 1 <= len(item) <= 128 for item in ids):
            raise ValueError("Alert endpoint scopes must contain at most 10000 bounded IDs")
        result[key] = sorted(set(ids))
    if not isinstance(result["ports"], list) or len(result["ports"]) > 128 or any(not isinstance(item, str) or not re.fullmatch(r"(?:[1-9]\d{0,4})(?:/(?:tcp|udp))?", item) or int(item.split('/')[0]) > 65535 for item in result["ports"]):
        raise ValueError("Choose at most 128 valid alert port/protocol pairs")
    result["ports"] = sorted(set(result["ports"]))
    return result


def _ids(db, expression, ids):
    source = "SELECT jsonb_array_elements_text(?::jsonb)" if getattr(db, "dialect", "sqlite") == "postgresql" else "SELECT value FROM json_each(?)"
    return expression + " IN (" + source + ")", [json.dumps(ids)]


def _array(db, expression, sqlite_type=None):
    if getattr(db, "dialect", "sqlite") == "postgresql":
        return "CASE WHEN jsonb_typeof(" + expression + ")='array' THEN " + expression + " ELSE '[]'::jsonb END"
    return "CASE WHEN " + (sqlite_type or "json_type(" + expression + ")") + "='array' THEN " + expression + " ELSE '[]' END"


def _where(db, value):
    field = lambda *path: _expression(db, path, "a")
    postgres = getattr(db, "dialect", "sqlite") == "postgresql"
    targets = "jsonb_array_elements_text(" + _array(db, "a.data::jsonb#>'{details,target_server_ids}'") + ") targets(value)" if postgres else "json_each(" + _array(db, "json_extract(a.data,'$.details.target_server_ids')", "json_type(a.data,'$.details.target_server_ids')") + ") targets"
    belongs = "(" + field("server_id") + "=s.id OR (" + field("kind") + "='possible_lateral_movement' AND EXISTS(SELECT 1 FROM " + targets + " WHERE targets.value=s.id)))"
    eligible, args = [], []
    if value["server_ids"] is not None:
        clause, parameters = _ids(db, "s.id", value["server_ids"])
        eligible.append(clause); args += parameters
    if value["search"]:
        ids, parameters = _ids(db, "s.id", value["search_server_ids"])
        # instr/strpos gives literal search: %, _ and backslashes never become wildcards.
        text = "lower(COALESCE(" + field("message") + ",'') || ' ' || COALESCE(" + field("details") + ",''))"
        contains = ("strpos(" + text + ",?)>0") if postgres else ("instr(" + text + ",?)>0")
        eligible.append("(" + ids + " OR " + contains + ")"); args += parameters + [value["search"].lower()]
    # Known alert ports override historical listener ports; host-wide events use
    # the matching endpoint's last reported listeners, exactly as the GUI filter.
    if value["ports"]:
        if postgres:
            chosen = "COALESCE(a.data::jsonb#>'{details,listener}',a.data::jsonb#>'{details,service_details}',a.data::jsonb->'details',a.data::jsonb->'detail','{}'::jsonb)"
            details = "CASE WHEN jsonb_typeof(" + chosen + ")='object' THEN " + chosen + " ELSE '{}'::jsonb END"
        else:
            paths = ("$.details.listener", "$.details.service_details", "$.details", "$.detail")
            details = "CASE " + " ".join("WHEN json_type(a.data,'" + path + "')='object' THEN json_extract(a.data,'" + path + "')" for path in paths) + " ELSE '{}' END"
        port = "d.value->>'port'" if postgres else "json_extract(d.value,'$.port')"
        protocol = "d.value->>'protocol'" if postgres else "json_extract(d.value,'$.protocol')"
        ports = "jsonb_array_elements_text(" + _array(db, "d.value->'ports'") + ") p(value)" if postgres else "json_each(" + _array(db, "json_extract(d.value,'$.ports')", "json_type(d.value,'$.ports')") + ") p"
        valid = "CASE WHEN CAST(p.value AS TEXT) ~ '^[0-9]{1,5}$' THEN CAST(p.value AS INTEGER) BETWEEN 1 AND 65535 ELSE false END" if postgres else "CAST(p.value AS TEXT) NOT GLOB '*[^0-9]*' AND length(CAST(p.value AS TEXT)) BETWEEN 1 AND 5 AND CAST(p.value AS INTEGER) BETWEEN 1 AND 65535"
        known_array = "EXISTS(SELECT 1 FROM " + ports + " WHERE " + valid + ")"
        direct_valid = "CASE WHEN COALESCE(" + port + ",'') ~ '^[0-9]{1,5}$' THEN CAST(" + port + " AS INTEGER) BETWEEN 1 AND 65535 ELSE false END" if postgres else "CAST(" + port + " AS TEXT) NOT GLOB '*[^0-9]*' AND length(CAST(" + port + " AS TEXT)) BETWEEN 1 AND 5 AND CAST(" + port + " AS INTEGER) BETWEEN 1 AND 65535"
        direct, array, port_args, array_args = [], [], [], []
        safe_port = "CASE WHEN COALESCE(" + port + ",'') ~ '^[0-9]{1,5}$' THEN CAST(" + port + " AS INTEGER) ELSE 0 END" if postgres else "CAST(" + port + " AS INTEGER)"
        safe_array_port = "CASE WHEN CAST(p.value AS TEXT) ~ '^[0-9]{1,5}$' THEN CAST(p.value AS INTEGER) ELSE 0 END" if postgres else "CAST(p.value AS INTEGER)"
        for selection in value["ports"]:
            number, _, proto = selection.partition('/')
            tail = " AND (" + protocol + " IS NULL OR " + protocol + "=?)" if proto else ""
            direct.append("(" + safe_port + "=?" + tail + ")")
            array.append("(" + safe_array_port + "=?" + tail + ")")
            port_args += [int(number)] + ([proto] if proto else [])
            array_args += [int(number)] + ([proto] if proto else [])
        host, host_args = _ids(db, "s.id", value["listener_server_ids"])
        match = "CASE WHEN " + known_array + " THEN EXISTS(SELECT 1 FROM " + ports + " WHERE " + valid + " AND (" + " OR ".join(array) + ")) WHEN " + direct_valid + " THEN (" + " OR ".join(direct) + ") ELSE " + host + " END"
        source = "(SELECT " + details + " AS value) d"
        eligible.append("EXISTS(SELECT 1 FROM " + source + " WHERE " + match + ")")
        args += array_args + port_args + host_args
    return "EXISTS(SELECT 1 FROM servers s WHERE " + belongs + (" AND " + " AND ".join(eligible) if eligible else "") + ")", tuple(args)


def listing(store, value=None):
    value = _validate(value)
    with store.read_meta() as db:
        field = lambda key: _expression(db, (key,), "a")
        where, args = _where(db, value)
        unresolved = "(" + field("resolved_at") + " IS NULL AND COALESCE(" + field("status") + ",'')<>'resolved')"
        live = lambda condition: "SUM(CASE WHEN " + unresolved + " AND (" + condition + ") THEN 1 ELSE 0 END)"
        summary = db.execute("SELECT COUNT(*)," + live("1=1") + "," + live(field("severity") + " IN ('critical','high','error')") + "," + live("COALESCE(" + field("status") + ",'')<>'acknowledged'") + "," + live(field("status") + "='open'") + " FROM alerts a WHERE " + where, args).fetchone()
        counts = {key: int(summary[index] or 0) for index, key in enumerate(("all_count", "unresolved_count", "critical_count", "unacknowledged_count", "open_count"))}
        total = counts["all_count"] if value["include_resolved"] else counts["unresolved_count"]
        clauses = where if value["include_resolved"] else where + " AND " + unresolved
        projection = ",".join("substr(CAST(" + field(key) + " AS TEXT),1,2048)" for key in FIELDS)
        projection += ",substr(CAST(" + field("details") + " AS TEXT),1,32769)"
        rows = db.execute("SELECT " + projection + " FROM alerts a WHERE " + clauses + " ORDER BY " + field("created_at") + " DESC,a.id DESC LIMIT ? OFFSET ?", args + (value["limit"], value["offset"]))
        items = []
        for row in rows:
            item = {key: row[index] for index, key in enumerate(FIELDS) if row[index] is not None}
            raw = row[len(FIELDS)] or "{}"
            try:
                details = json.loads(raw) if len(raw) <= 32768 else None
            except (ValueError, TypeError):
                details = None
            item["details"] = details if isinstance(details, dict) else {"omitted": True, "reason": "Alert detail exceeds the bounded navigation page"}
            items.append(item)
    return {"items": items, "total": total, **counts, "limit": value["limit"], "offset": value["offset"], "has_more": value["offset"] + len(items) < total, "include_resolved": value["include_resolved"], "summary_only": True}


def _acknowledgement_scope(value):
    if not isinstance(value, dict) or value.get("scope") not in ("all", "filtered"):
        raise ValueError("Choose all alerts or the current filtered alert scope")
    if value["scope"] == "all":
        if set(value) != {"scope"}:
            raise ValueError("All-alert acknowledgement does not accept a filtered query")
        return "all", None
    if set(value) != {"scope", "query"} or not isinstance(value["query"], dict):
        raise ValueError("Filtered acknowledgement requires the current alert query")
    query = _validate(value["query"])
    # A navigation page is not acknowledgement scope. Reuse its exact filters,
    # while recovered records remain untouched even when visible in that page.
    return "filtered", {key: item for key, item in query.items() if key not in ("limit", "offset", "include_resolved")}


def acknowledge(store, value, actor):
    scope, query = _acknowledgement_scope(value)
    acknowledged_at = stamp()
    changed = 0
    with store.lock, store.meta() as db:
        if getattr(db, "dialect", "sqlite") == "sqlite":
            db.execute("BEGIN IMMEDIATE")
        field = lambda key: _expression(db, (key,), "a")
        where, args = ("1=1", ()) if scope == "all" else _where(db, query)
        eligible = "(" + where + ") AND " + field("resolved_at") + " IS NULL AND COALESCE(" + field("status") + ",'') NOT IN ('resolved','acknowledged')"
        # Read bounded keyset batches inside the same write transaction. The
        # all-alert path never loads endpoint inventory and includes system or
        # orphan alerts that have no currently registered server.
        after = None
        while True:
            tail = " AND a.id>?" if after is not None else ""
            rows = db.execute("SELECT a.id,a.data FROM alerts a WHERE " + eligible + tail + " ORDER BY a.id LIMIT 100",
                              args + ((after,) if after is not None else ())).fetchall()
            if not rows:
                break
            discovery = {}
            for row in rows:
                identifier, encoded = row[0], row[1]
                alert = json.loads(encoded)
                alert.update(status="acknowledged", acknowledged_at=acknowledged_at, acknowledged_by=actor, updated_at=acknowledged_at)
                store._put(db, "alerts", alert)
                changed += 1
                if alert.get("kind") in ("service_discovered", "service_changed") and isinstance(alert.get("server_id"), str):
                    discovery.setdefault(alert["server_id"], set()).add(identifier)
            for server_id, identifiers in discovery.items():
                server = store._get(db, "servers", server_id)
                if server is None:
                    continue
                updated = False
                for listener in [*server.get("listeners", []), *server.get("discovery_changes", [])]:
                    if listener.get("discovery_alert_id") in identifiers and listener.get("is_new"):
                        listener["is_new"] = False
                        updated = True
                if updated:
                    store._put(db, "servers", server)
            after = rows[-1][0]
        if changed:
            details = {"scope": scope, "acknowledged_count": changed, "acknowledged_at": acknowledged_at}
            if query is not None:
                details["query"] = query
            store.audit("alerts.bulk_acknowledged", actor, details, db)
    return {"scope": scope, "acknowledged_count": changed, "acknowledged_at": acknowledged_at}
