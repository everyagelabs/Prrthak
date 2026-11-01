"""Bounded navigation for immutable learning reviews; exact authority is detail-only."""
import json
import re

from .store import stamp

MAX_REVIEW_BYTES = 8 * 1024 * 1024
SUMMARY_TEXT = 512
FIELDS = (
    ("id", ("id",)), ("session_id", ("session_id",)), ("kind", ("kind",)),
    ("name", ("name",)), ("change_name", ("change", "name")),
    ("status", ("status",)), ("created_at", ("created_at",)),
    ("expires_at", ("expires_at",)), ("digest", ("digest",)),
    ("plan_digest", ("plan_digest",)), ("created_by", ("created_by",)),
    ("confirmation_count", ("confirmation_count",)),
    ("mode", ("approval", "mode")), ("stage", ("approval", "stage")),
    ("user_id", ("approval", "requester", "user_id")),
    ("tenant_id", ("approval", "requester", "tenant_id")),
    ("actor", ("approval", "requester", "actor")),
    ("display_name", ("approval", "requester", "display_name")),
    ("role", ("approval", "requester", "role")),
)


def _expression(db, path, alias=""):
    # All callers supply code-owned field tuples/aliases, never request paths.
    data = (alias + "." if alias else "") + "data"
    if getattr(db, "dialect", "sqlite") == "postgresql":
        return data + "::jsonb#>>'{" + ",".join(path) + "}'"
    return "json_extract(" + data + ",'$." + ".".join(path) + "')"


def initialize(db):
    # Indexed fixed scalars avoid reparsing every historical authority matrix
    # for the status/expiry/session filters or an initial-review ID lookup.
    status = _expression(db, ("status",))
    expires = _expression(db, ("expires_at",))
    session = _expression(db, ("session_id",))
    created = _expression(db, ("created_at",))
    db.execute("CREATE INDEX IF NOT EXISTS learning_review_queue ON learning_policy_previews ((" + status + "),(" + expires + "),(" + created + "),id)")
    db.execute("CREATE INDEX IF NOT EXISTS learning_review_session ON learning_policy_previews ((" + session + "),(" + status + "),(" + expires + "),(" + created + "),id)")
    initial = lambda field: _expression(db, ("initial_approval_plan", field))
    db.execute("CREATE INDEX IF NOT EXISTS initial_learning_review_id ON sessions ((" + initial("id") + "))")
    db.execute("CREATE INDEX IF NOT EXISTS initial_learning_review_queue ON sessions ((" + status + "),(" + initial("status") + "),(" + initial("expires_at") + "),(" + initial("created_at") + "),id)")


def _keys(db, session_id, cutoff):
    status = _expression(db, ("status",))
    initial = lambda field: _expression(db, ("initial_approval_plan", field))
    preview_where = status + " IN ('reviewed','awaiting_second_confirmation') AND " + _expression(db, ("expires_at",)) + ">?"
    initial_where = status + "='active' AND " + initial("status") + " IN ('draft','awaiting_second_confirmation') AND " + initial("expires_at") + ">?"
    first, second = [cutoff], [cutoff]
    if session_id is not None:
        preview_where += " AND " + _expression(db, ("session_id",)) + "=?"
        initial_where += " AND id=?"
        first.append(session_id); second.append(session_id)
    sql = "SELECT id AS review_id,id AS owner_id,'preview' AS source," + _expression(db, ("created_at",)) + " AS created_at FROM learning_policy_previews WHERE " + preview_where
    sql += " UNION ALL SELECT " + initial("id") + ",id,'initial'," + initial("created_at") + " FROM sessions WHERE " + initial_where
    return sql, tuple(first + second)


def _projection(db, initial):
    prefix = ("initial_approval_plan",) if initial else ()
    return ",".join("substr(CAST(" + _expression(db, prefix + path, "p") + " AS TEXT),1," + str(SUMMARY_TEXT) + ")" for _, path in FIELDS)


def listing(store, session_id=None, limit=200, offset=0):
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 500 or isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
        raise ValueError("Approval queue limit must be 1 to 500 and offset nonnegative")
    if session_id is not None and (not isinstance(session_id, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", session_id)):
        raise ValueError("Invalid learning session identifier")
    with store.read_meta() as db:
        if getattr(db, "dialect", "sqlite") == "sqlite":
            db.execute("BEGIN")
        keys, args = _keys(db, session_id, stamp())
        total = int(db.execute("SELECT COUNT(*) FROM (" + keys + ") counted", args).fetchone()[0])
        # The LIMIT in this key-only CTE is a projection barrier: full scalar
        # summary fields are extracted only for the selected bounded page.
        selected = keys + " ORDER BY created_at DESC,review_id DESC LIMIT ? OFFSET ?"
        query = "WITH selected AS (" + selected + ") SELECT " + _projection(db, False) + ",'preview' FROM selected JOIN learning_policy_previews p ON selected.source='preview' AND p.id=selected.owner_id"
        query += " UNION ALL SELECT " + _projection(db, True) + ",'initial' FROM selected JOIN sessions p ON selected.source='initial' AND p.id=selected.owner_id"
        items = []
        for row in db.execute(query, args + (limit, offset)):
            value = {field: row[index] for index, (field, _) in enumerate(FIELDS)}
            item = {field: value[field] for field in ("id", "session_id", "status", "created_at", "expires_at", "digest", "plan_digest", "created_by")}
            item.update(name=value["name"] or value["change_name"], kind="initial_learning" if row[-1] == "initial" else value["kind"] or "recommendation", confirmation_count=int(value["confirmation_count"] or 0), summary_only=True)
            item["approval"] = {"mode": value["mode"], "stage": value["stage"], "requester": {field: value[field] for field in ("user_id", "tenant_id", "actor", "display_name", "role")}}
            items.append(item)
        items.sort(key=lambda item: (item["created_at"] or "", item["id"]), reverse=True)
        return {"items": items, "total": total, "limit": limit, "offset": offset, "has_more": offset + limit < total, "summary_only": True}


def detail(store, identifier):
    if not isinstance(identifier, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", identifier):
        raise ValueError("Invalid learning review identifier")
    with store.read_meta() as db:
        if getattr(db, "dialect", "sqlite") == "sqlite":
            db.execute("BEGIN")
        size = "octet_length(data)" if getattr(db, "dialect", "sqlite") == "postgresql" else "length(CAST(data AS BLOB))"
        initial_id = _expression(db, ("initial_approval_plan", "id"))
        found = list(db.execute("SELECT id," + size + ",'preview' FROM learning_policy_previews WHERE id=? UNION ALL SELECT id," + size + ",'initial' FROM sessions WHERE " + initial_id + "=? LIMIT 2", (identifier, identifier)))
        if not found:
            raise KeyError(identifier)
        if len(found) != 1:
            raise ValueError("Learning review identity is ambiguous; prepare a new exact review")
        owner, encoded_size, source = (found[0][index] for index in range(3))
        # Check stored bytes before retrieving or decoding any canonical JSON.
        # For initial reviews the enclosing frozen session must also fit; this
        # prevents an otherwise-small subdocument forcing huge session parsing.
        if encoded_size > MAX_REVIEW_BYTES:
            raise ValueError("Exact learning review exceeds the 8 MiB detail limit; prepare a smaller frozen review")
        if source == "preview":
            raw = db.execute("SELECT data FROM learning_policy_previews WHERE id=?", (owner,)).fetchone()[0]
        elif getattr(db, "dialect", "sqlite") == "postgresql":
            raw = db.execute("SELECT (data::jsonb->'initial_approval_plan')::text FROM sessions WHERE id=?", (owner,)).fetchone()[0]
        else:
            raw = db.execute("SELECT json_extract(data,'$.initial_approval_plan') FROM sessions WHERE id=?", (owner,)).fetchone()[0]
        if len(raw.encode("utf-8")) > MAX_REVIEW_BYTES:
            raise ValueError("Exact learning review exceeds the 8 MiB detail limit; prepare a smaller frozen review")
        plan = json.loads(raw)
        if plan.get("id") != identifier:
            raise ValueError("Stored learning review identity changed")
        return {**plan, "kind": "initial_learning"} if source == "initial" else plan
