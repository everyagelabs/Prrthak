"""Paged public learning telemetry; canonical sessions remain private to workflows."""
import json
import re

from .approval_views import _expression
from .store import stamp, validate_port

MAX_IDS_BYTES = 3 * 1024 * 1024
MAX_PORT_BYTES = 16384
MAX_DETAIL_BYTES = 8 * 1024 * 1024
FIELDS = ("name", "status", "starts_at", "expires_at", "ended_at", "stopped_at", "selection_mode", "policy_action", "initial_approval_state", "created_by", "evidence_revision", "observation_kinds", "purpose", "evidence_expires_at", "traffic_collection_mode")


def initialize(db):
    db.execute("CREATE INDEX IF NOT EXISTS public_learning_session_purpose ON sessions ((" + _expression(db, ("purpose",)) + "),(" + _expression(db, ("evidence_expires_at",)) + "),id)")
    db.execute("CREATE INDEX IF NOT EXISTS public_learning_session_start ON sessions ((" + _expression(db, ("starts_at",)) + "),id)")
    db.execute("CREATE INDEX IF NOT EXISTS public_learning_session_active ON sessions ((" + _expression(db, ("status",)) + "),(" + _expression(db, ("starts_at",)) + "),(" + _expression(db, ("expires_at",)) + "),id)")


def _array(db, path):
    if getattr(db, "dialect", "sqlite") == "postgresql":
        return "(data::jsonb#>'{" + ",".join(path) + "}')::text"
    return "json_extract(data,'$." + ".".join(path) + "')"


def _count(db, path):
    if getattr(db, "dialect", "sqlite") == "postgresql":
        return "COALESCE(jsonb_array_length(data::jsonb#>'{" + ",".join(path) + "}'),0)"
    return "COALESCE(json_array_length(data,'$." + ".".join(path) + "'),0)"


def _discovery_count(db, status):
    # status is a code-owned enum literal; it never comes from a request.
    if getattr(db, "dialect", "sqlite") == "postgresql":
        return "(SELECT COUNT(*) FROM jsonb_each(COALESCE(data::jsonb->'discovery_results','{}'::jsonb)) result WHERE result.value->>'status'='" + status + "')"
    return "(SELECT COUNT(*) FROM json_each(data,'$.discovery_results') result WHERE json_extract(result.value,'$.status')='" + status + "')"


def _projection(db):
    values = ["id"] + ["substr(CAST(" + _expression(db, (field,)) + " AS TEXT),1,512)" for field in FIELDS]
    values += [_array(db, ("server_ids",)), "CASE WHEN " + _expression(db, ("selection_mode",)) + "='discovered' THEN '[]' ELSE " + _array(db, ("ports",)) + " END", _array(db, ("port_filter",)), _count(db, ("discovery_pending_server_ids",)), _discovery_count(db, "error"), _discovery_count(db, "no_listeners")]
    # Navigation hints only. Neither proof, scope nor nonce leaves this path.
    values += [_expression(db, ("initial_approval_plan", field)) for field in ("id", "status", "created_at", "expires_at", "digest", "plan_digest")]
    return ",".join(values)


def _bounded_array(value, maximum, count):
    if value is None:
        return []
    if not isinstance(value, str) or len(value.encode("utf-8")) > maximum:
        raise ValueError("Public learning projection exceeds its supported bound; inspect a smaller scope")
    result = json.loads(value)
    if not isinstance(result, list) or len(result) > count:
        raise ValueError("Invalid bounded public learning array")
    return result


def _summary(row):
    result = {"id": row[0], **{field: row[index + 1] for index, field in enumerate(FIELDS)}}
    start = 1 + len(FIELDS)
    ids = _bounded_array(row[start], MAX_IDS_BYTES, 20000)
    if any(not isinstance(identifier, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", identifier) for identifier in ids):
        raise ValueError("Invalid public learning membership")
    result.update(summary_only=True, server_ids=ids, server_count=len(ids), ports=[validate_port(port) for port in _bounded_array(row[start + 1], MAX_PORT_BYTES, 100)], port_filter=[validate_port(port) for port in _bounded_array(row[start + 2], MAX_PORT_BYTES, 100)], discovery_pending_count=int(row[start + 3]), discovery_error_count=int(row[start + 4]), discovery_no_listeners_count=int(row[start + 5]))
    result["evidence_revision"] = int(result["evidence_revision"] or 0)
    from .traffic_capture import observation_kinds
    if result["observation_kinds"]:result["observation_kinds"] = observation_kinds(json.loads(result["observation_kinds"]))
    else:result.pop('observation_kinds',None)
    if not result["traffic_collection_mode"]:
        result.pop("traffic_collection_mode")
    for field, fallback in (("selection_mode", "manual"), ("policy_action", "observe"), ("purpose", "policy")):
        result[field] = result[field] or fallback
    if row[start + 6]:
        fields = ("id", "status", "created_at", "expires_at", "digest", "plan_digest")
        result["initial_approval_plan"] = {field: row[start + 6 + index] for index, field in enumerate(fields)}
        result["initial_approval_plan"].update(session_id=result["id"], kind="initial_learning", summary_only=True)
    return result


def _where(db, server_id):
    if server_id is None:
        return "1=1", ()
    if not isinstance(server_id, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", server_id):
        raise ValueError("Invalid learning server identifier")
    if getattr(db, "dialect", "sqlite") == "postgresql":
        return "jsonb_exists(COALESCE(data::jsonb->'server_ids','[]'::jsonb),?)", (server_id,)
    return "EXISTS(SELECT 1 FROM json_each(sessions.data,'$.server_ids') member WHERE member.value=?)", (server_id,)


def listing(store, limit=6, offset=0, server_id=None, purpose=None):
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 20 or isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
        raise ValueError("Learning pagination requires limit 1..20 and nonnegative offset")
    with store.read_meta() as db:
        if getattr(db, "dialect", "sqlite") == "sqlite":
            db.execute("BEGIN")
        where, args = _where(db, server_id)
        if purpose is not None:
            from .learning import purpose_for
            purpose_for({"purpose": purpose})
            field = _expression(db, ("purpose",))
            where += " AND " + ("COALESCE(" + field + ",'policy')" if purpose == "policy" else field) + "=?"
            args += (purpose,)
        total = int(db.execute("SELECT COUNT(*) FROM sessions WHERE " + where, args).fetchone()[0])
        active = _expression(db, ("status",)) + "='active' AND " + _expression(db, ("starts_at",)) + "<=? AND " + _expression(db, ("expires_at",)) + ">?"
        current = stamp()
        active_total = int(db.execute("SELECT COUNT(*) FROM sessions WHERE " + where + " AND " + active, args + (current, current)).fetchone()[0])
        order = _expression(db, ("starts_at",)) + " DESC,id DESC"
        # LIMIT is below the scalar/array projection, never after Python decode.
        sql = "SELECT " + _projection(db) + " FROM (SELECT id,data FROM sessions WHERE " + where + " ORDER BY " + order + " LIMIT ? OFFSET ?) sessions"
        items = [_summary(row) for row in db.execute(sql, args + (limit, offset))]
        return {"items": items, "total": total, "active_total": active_total, "limit": limit, "offset": offset, "has_more": offset + limit < total, "server_id": server_id, "summary_only": True, **({"purpose": purpose} if purpose is not None else {})}


def header(db, identifier):
    row = db.execute("SELECT " + _projection(db) + " FROM sessions WHERE id=?", (identifier,)).fetchone()
    if row is None:
        raise KeyError(identifier)
    return _summary(row)


def hosts(store, identifier, limit=50, offset=0):
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100 or isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
        raise ValueError("Host scope pagination requires limit 1..100 and nonnegative offset")
    with store.read_meta() as db:
        if getattr(db, "dialect", "sqlite") == "sqlite":
            db.execute("BEGIN")
        row = db.execute("SELECT " + _count(db, ("server_ids",)) + " FROM sessions WHERE id=?", (identifier,)).fetchone()
        if row is None:
            raise KeyError(identifier)
        total = int(row[0])
        if total > 20000:
            raise ValueError("Learning membership exceeds the supported scope")
        # Read only this page of exact membership. Dynamic keys are SQL values
        # or JSON-path components escaped by the database, never SQL syntax.
        if getattr(db, "dialect", "sqlite") == "postgresql":
            members = "SELECT member.value AS server_id,member.ordinality FROM sessions CROSS JOIN LATERAL jsonb_array_elements_text(data::jsonb->'server_ids') WITH ORDINALITY member(value,ordinality) WHERE id=? ORDER BY member.ordinality LIMIT ? OFFSET ?"
            ports = "CASE WHEN data::jsonb->>'selection_mode'='discovered' THEN (data::jsonb->'server_ports'->selected.server_id)::text ELSE (data::jsonb->'ports')::text END"
            field = lambda key: "data::jsonb->'discovery_results'->selected.server_id->>'" + key + "'"
            pending = "jsonb_exists(COALESCE(data::jsonb->'discovery_pending_server_ids','[]'::jsonb),selected.server_id)"
        else:
            members = "SELECT member.value AS server_id,CAST(member.key AS INTEGER) AS ordinality FROM sessions,json_each(data,'$.server_ids') member WHERE sessions.id=? ORDER BY CAST(member.key AS INTEGER) LIMIT ? OFFSET ?"
            ports = "CASE WHEN json_extract(data,'$.selection_mode')='discovered' THEN json_extract(data,'$.server_ports.'||json_quote(selected.server_id)) ELSE json_extract(data,'$.ports') END"
            field = lambda key: "json_extract(data,'$.discovery_results.'||json_quote(selected.server_id)||'." + key + "')"
            pending = "EXISTS(SELECT 1 FROM json_each(data,'$.discovery_pending_server_ids') waiting WHERE waiting.value=selected.server_id)"
        sql = "WITH selected AS (" + members + ") SELECT selected.server_id," + ports + "," + field("status") + ",substr(" + field("error") + ",1,4096)," + field("discovered_at") + "," + pending + " FROM selected CROSS JOIN sessions WHERE sessions.id=? ORDER BY selected.ordinality"
        items = []
        for value in db.execute(sql, (identifier, limit, offset, identifier)):
            items.append({"server_id": value[0], "ports": [validate_port(port) for port in _bounded_array(value[1], MAX_PORT_BYTES, 100)], "status": value[2] or "manual", "error": value[3] or "", "discovered_at": value[4], "pending": bool(value[5])})
        return {"session_id": identifier, "items": items, "total": total, "offset": offset, "limit": limit, "has_more": offset + limit < total}


def compiled_policy(store, identifier):
    """Public intent detail is not an agent assignment or enforcement authority."""
    with store.read_meta() as db:
        if getattr(db, "dialect", "sqlite") == "sqlite":
            db.execute("BEGIN")
        expression = _array(db, ("_compiled",))
        size = "octet_length(" + expression + ")" if getattr(db, "dialect", "sqlite") == "postgresql" else "length(CAST(" + expression + " AS BLOB))"
        row = db.execute("SELECT " + size + " FROM servers WHERE id=?", (identifier,)).fetchone()
        if row is None:
            raise KeyError(identifier)
        if row[0] is None:
            return None
        if row[0] > MAX_DETAIL_BYTES:
            raise ValueError("Compiled policy exceeds the public detail size bound")
        raw = db.execute("SELECT " + expression + " FROM servers WHERE id=?", (identifier,)).fetchone()[0]
        if len(raw.encode("utf-8")) > MAX_DETAIL_BYTES:
            raise ValueError("Compiled policy exceeds the public detail size bound")
        return json.loads(raw)


def discovery_statuses(db, identifier, server_ids):
    if not server_ids:
        return {}
    if len(server_ids) > 2000:
        raise ValueError("Discovery status projection exceeds its page bound")
    markers = ",".join("?" for _ in server_ids)
    if getattr(db, "dialect", "sqlite") == "postgresql":
        sql = "SELECT result.key,result.value->>'status' FROM sessions CROSS JOIN LATERAL jsonb_each(COALESCE(data::jsonb->'discovery_results','{}'::jsonb)) result WHERE id=? AND result.key IN (" + markers + ")"
    else:
        sql = "SELECT result.key,json_extract(result.value,'$.status') FROM sessions,json_each(data,'$.discovery_results') result WHERE sessions.id=? AND result.key IN (" + markers + ")"
    return {row[0]: row[1] for row in db.execute(sql, (identifier, *server_ids))}
