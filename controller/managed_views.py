"""Bounded public navigation; managed authority stays in canonical workflows."""
from contextlib import contextmanager
import json
import re

from .approval_views import _expression
from .managed import MAX_ROLLOUT_BYTES
from .store import parse_time, now

MAX_DETAIL_BYTES = MAX_ROLLOUT_BYTES
MAX_OUTCOME_BYTES = 64 * 1024
IDENTIFIER = re.compile(r"[A-Za-z0-9_.:-]{1,128}\Z")


def identifier(value):
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value):
        raise ValueError("Invalid managed history identifier")
    return value


def version(value):
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 9223372036854775807:
        raise ValueError("A positive immutable version is required")
    return value


def page(limit, offset):
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100 or isinstance(offset, bool) or not isinstance(offset, int) or not 0 <= offset <= 1000000000:
        raise ValueError("Managed navigation requires limit 1..100 and offset 0..1000000000")


@contextmanager
def snapshot(store):
    with store.read_meta() as db:
        if getattr(db, "dialect", "sqlite") == "sqlite":
            db.execute("BEGIN")
        yield db


def _size(db, expression="data"):
    return "octet_length(" + expression + ")" if getattr(db, "dialect", "sqlite") == "postgresql" else "length(CAST(" + expression + " AS BLOB))"


def _scalar(db, field, alias="", bound=512):
    return "substr(CAST(" + _expression(db, tuple(field.split(".")), alias) + " AS TEXT),1," + str(bound) + ")"


def _array(db, field):
    return "(data::jsonb->'" + field + "')::text" if getattr(db, "dialect", "sqlite") == "postgresql" else "json_extract(data,'$." + field + "')"


def _array_count(db, field):
    return "COALESCE(jsonb_array_length(data::jsonb->'" + field + "'),0)" if getattr(db, "dialect", "sqlite") == "postgresql" else "COALESCE(json_array_length(data,'$." + field + "'),0)"


def _exact(db, table, where, args, budget=MAX_DETAIL_BYTES):
    # Table and WHERE syntax are code-owned at every call site; IDs are values.
    row = db.execute("SELECT " + _size(db) + " FROM " + table + " WHERE " + where, args).fetchone()
    if row is None:
        raise KeyError(args[0])
    if row[0] > budget:
        raise ValueError("Exact managed detail exceeds its supported byte bound; use a smaller reviewed scope")
    raw = db.execute("SELECT data FROM " + table + " WHERE " + where, args).fetchone()[0]
    if len(raw.encode("utf-8")) > budget:
        raise ValueError("Exact managed detail exceeds its supported byte bound")
    value = json.loads(raw)
    if not isinstance(value, dict) or value.get("summary_only") is True:
        raise ValueError("Exact managed authority is unavailable")
    return value, len(raw.encode("utf-8"))


def rollout_options(value):
    if not isinstance(value, dict) or set(value) - {"limit", "offset", "server_ids", "search"}:
        raise ValueError("Managed rollout query accepts pagination, selected endpoint IDs and search only")
    limit, offset, ids, search = value.get("limit", 20), value.get("offset", 0), value.get("server_ids"), value.get("search", "")
    page(limit, offset)
    if ids is not None and (not isinstance(ids, list) or len(ids) > 20000 or any(not isinstance(item, str) or not IDENTIFIER.fullmatch(item) for item in ids)):
        raise ValueError("Choose at most 20000 endpoint identifiers")
    if not isinstance(search, str) or len(search) > 256:
        raise ValueError("Managed rollout search is limited to 256 characters")
    return {"limit": limit, "offset": offset, "server_ids": sorted(set(ids)) if ids is not None else None, "search": search}


def _scope(db, ids):
    if ids is None:
        return "1=1", (), _array_count(db, "server_ids")
    if not ids:
        return "1=0", (), "0"
    placeholders = ",".join("?" for _ in ids)
    if getattr(db, "dialect", "sqlite") == "postgresql":
        members = "SELECT COUNT(*) FROM jsonb_array_elements_text(COALESCE(data::jsonb->'server_ids','[]'::jsonb)) member(value) WHERE member.value IN (" + placeholders + ")"
    else:
        members = "SELECT COUNT(*) FROM json_each(data,'$.server_ids') member WHERE member.value IN (" + placeholders + ")"
    return "(" + members + ")>0", tuple(ids), "(" + members + ")"


def _outcome_counts(db, approval_id):
    status = _expression(db, ("status",))
    intent = _expression(db, ("intent",))
    state = "CASE WHEN " + status + "='enforced' AND " + intent + "='remove_managed_rules' THEN 'removed' ELSE " + status + " END"
    sql = "SELECT " + state + ",COUNT(*) FROM (SELECT data,ROW_NUMBER() OVER(PARTITION BY server_id ORDER BY created_at DESC,id DESC) AS rn FROM managed_outcomes WHERE approval_id=? AND " + _current_evidence(db) + ") latest WHERE rn=1 GROUP BY " + state + " ORDER BY 1 LIMIT 33"
    rows = list(db.execute(sql, (approval_id,)))
    if len(rows) > 32:
        raise ValueError("Managed outcome status catalogue exceeds its supported bound")
    return {row[0] or "unknown": int(row[1]) for row in rows}


def _current_evidence(db):
    return "COALESCE(CAST(" + _expression(db,("history_only",)) + " AS TEXT),'false') NOT IN ('true','1')"


def rollouts(store, limit=20, offset=0, server_ids=None, search=""):
    checked = rollout_options({"limit": limit, "offset": offset, "server_ids": server_ids, "search": search})
    ids = checked["server_ids"]
    fields = ("name", "status", "created_at", "expires_at", "created_by", "plan_digest", "confirmation_count", "requires_double_confirmation", "approval.mode", "approval.stage", "approval.requester.user_id", "approval.requester.tenant_id", "approval.requester.display_name", "kind")
    with snapshot(store) as db:
        where, args, matching = _scope(db, ids)
        if search:
            where += " AND lower(COALESCE(" + _expression(db, ("name",)) + ",'')) LIKE ? ESCAPE '\\'"
            args += ("%" + search.lower().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%",)
        total = int(db.execute("SELECT COUNT(*) FROM managed_rollouts WHERE " + where, args).fetchone()[0])
        selected = "SELECT id,data FROM managed_rollouts WHERE " + where + " ORDER BY " + _expression(db, ("created_at",)) + " DESC,id DESC LIMIT ? OFFSET ?"
        # Selected IDs are bounded before any summary/scoped count extraction.
        sql = "SELECT id," + ",".join(_scalar(db, field) for field in fields) + "," + _array_count(db, "server_ids") + "," + matching + " FROM (" + selected + ") page"
        parameters = tuple(ids or ()) + args + (limit, offset) if ids else args + (limit, offset)
        items = []
        for row in db.execute(sql, parameters):
            values = {field: row[index + 1] for index, field in enumerate(fields)}
            item = {field: values[field] for field in fields[:6]}
            if values["kind"]:item["kind"] = values["kind"]
            item.update(id=row[0], confirmation_count=int(values["confirmation_count"] or 0), requires_double_confirmation=values["requires_double_confirmation"] in ("1", "true", 1, True), target_count=int(row[-2]), matching_target_count=int(row[-1]), summary_only=True, requires_exact_review=True)
            if item["status"] in ("draft", "awaiting_second_confirmation", "queued") and item["expires_at"] and parse_time(item["expires_at"]) <= now():
                item["status"] = "expired"
            item["approval"] = {"mode": values["approval.mode"], "stage": values["approval.stage"], "requester": {key: values["approval.requester." + key] for key in ("user_id", "tenant_id", "display_name")}}
            item["result_counts"] = _outcome_counts(db, row[0])
            items.append(item)
        return {"items": items, "total": total, "limit": limit, "offset": offset, "has_more": offset + limit < total, "summary_only": True, "scope_semantics": "Selected endpoints; frozen complete bundles are never truncated by navigation filters"}


def _bindings_match(db, ids, expected):
    from .managed import baseline
    if not isinstance(expected, dict) or set(ids) != set(expected):
        return False
    fields = ("_compiled.version", "_compiled.digest", "protection.digest", "_compiled.mode", "_managed_rules_active")
    for start in range(0, len(ids), 200):
        selected = ids[start:start + 200]
        sql = "SELECT id," + ",".join(_scalar(db, field) for field in fields) + ",substr(" + _array(db, "ips") + ",1,16385) FROM servers WHERE id IN (" + ",".join("?" for _ in selected) + ")"
        seen = set()
        for row in db.execute(sql, tuple(selected)):
            server_id = row[0]
            seen.add(server_id)
            raw = row[-1] or "[]"
            if len(raw.encode("utf-8")) > 16384:
                raise ValueError("Endpoint address projection exceeds its supported bound")
            ips = json.loads(raw)
            if not isinstance(ips, list) or len(ips) > 256:
                raise ValueError("Endpoint address projection exceeds its supported bound")
            server = {"id": server_id, "ips": ips, "_compiled": {"version": int(row[1] or 0), "digest": row[2] or ""}, "protection": {"digest": row[3] or ""}}
            current = baseline(server)
            current["intent"] = "remove_managed_rules" if row[4] != "enforce" and row[5] in (True, 1, "1", "true") else "enforce"
            if current != expected[server_id]:
                return False
        if seen != set(selected):
            return False
    return True


def rollout(store, plan_id):
    identifier(plan_id)
    with snapshot(store) as db:
        value, used = _exact(db, "managed_rollouts", "id=?", (plan_id,), MAX_DETAIL_BYTES)
        if value.get("id") != plan_id:
            raise ValueError("Exact managed review identity mismatch")
        if value.get("kind") == "host_default_deny":
            from .host_default_deny import _public
            return _public(value)
        ids = value.get("server_ids")
        rollout_options({"server_ids": ids})
        if not ids:
            raise ValueError("Exact managed review has no endpoint scope")
        if value.get("status") in ("draft", "awaiting_second_confirmation", "queued"):
            if parse_time(value["expires_at"]) <= now():
                value["status"] = "expired"
            elif not _bindings_match(db, ids, value.get("bindings")):
                value.update(status="invalidated", error="Desired policy, protected baseline or exact target IPs changed")
        source = "SELECT server_id,data FROM (SELECT server_id,data,ROW_NUMBER() OVER(PARTITION BY server_id ORDER BY created_at DESC,id DESC) AS rn FROM managed_outcomes WHERE approval_id=? AND " + _current_evidence(db) + ") latest WHERE rn=1"
        metadata = db.execute("SELECT COUNT(*),COALESCE(SUM(" + _size(db) + "+" + _size(db, "server_id") + "+4),0) FROM (" + source + ") counted", (plan_id,)).fetchone()
        count, size = metadata[0], metadata[1]
        if int(count) > 20000 or used + int(size) + 4096 > MAX_DETAIL_BYTES:
            raise ValueError("Exact managed review and outcomes exceed the supported byte bound")
        results = {}
        for row in db.execute(source, (plan_id,)):
            outcome = json.loads(row[1])
            if outcome.get("server_id") != row[0] or row[0] not in ids:
                raise ValueError("Managed outcome identity does not belong to this frozen review")
            results[row[0]] = outcome
        return {**value, "results": results}


def _history_page(store, table, owner_field, owner, number_field, fields, limit, offset):
    identifier(owner); page(limit, offset)
    with snapshot(store) as db:
        total = int(db.execute("SELECT COUNT(*) FROM " + table + " WHERE " + owner_field + "=?", (owner,)).fetchone()[0])
        selected = "SELECT id,data," + number_field + " FROM " + table + " WHERE " + owner_field + "=? ORDER BY " + number_field + " DESC LIMIT ? OFFSET ?"
        sql = "SELECT " + number_field + "," + ",".join(_scalar(db, field) for field in fields) + " FROM (" + selected + ") page"
        items = []
        for row in db.execute(sql, (owner, limit, offset)):
            item = {field: row[index + 1] for index, field in enumerate(fields)}
            item.update({number_field: int(row[0]), "summary_only": True, "id" if owner_field == "policy_id" else "server_id": owner})
            if table == "bundle_history":
                count = int(db.execute("SELECT COUNT(*) FROM managed_outcomes WHERE server_id=? AND version=?", (owner, item["version"])).fetchone()[0])
                outcome_fields = ("status", "intent", "error", "rollback_reason", "message", "updated_at")
                latest = db.execute("SELECT " + ",".join(_scalar(db, field) for field in outcome_fields) + " FROM (SELECT data FROM managed_outcomes WHERE server_id=? AND version=? AND " + _current_evidence(db) + " ORDER BY created_at DESC,id DESC LIMIT 1) latest", (owner, item["version"])).fetchone()
                item["outcome_total"] = count
                item["outcomes"] = [{**{field: latest[index] for index, field in enumerate(outcome_fields)}, "version": item["version"], "summary_only": True}] if latest else []
            items.append(item)
        return {"items": items, "total": total, "limit": limit, "offset": offset, "has_more": offset + limit < total, "summary_only": True, owner_field: owner}


def revisions(store, policy_id, limit=20, offset=0):
    return _history_page(store, "policy_revisions", "policy_id", policy_id, "revision", ("name", "mode", "created_at", "updated_at", "actor", "reason", "digest"), limit, offset)


def history(store, server_id, limit=20, offset=0):
    return _history_page(store, "bundle_history", "server_id", server_id, "version", ("digest", "mode", "created_at", "generated_at", "actor", "reason"), limit, offset)


def _revision(db, policy_id, revision):
    value, _ = _exact(db, "policy_revisions", "policy_id=? AND revision=?", (policy_id, revision), MAX_DETAIL_BYTES)
    if value.get("id") != policy_id or value.get("revision") != revision:
        raise ValueError("Exact policy revision identity mismatch")
    return value


def revision(store, policy_id, number):
    identifier(policy_id); version(number)
    with snapshot(store) as db:
        return _revision(db, policy_id, number)


def bundle(store, server_id, number):
    identifier(server_id); version(number)
    with snapshot(store) as db:
        value, _ = _exact(db, "bundle_history", "server_id=? AND version=?", (server_id, number), MAX_DETAIL_BYTES)
        if value.get("server_id") != server_id or value.get("version") != number:
            raise ValueError("Exact endpoint bundle identity mismatch")
        return value


def outcomes(store, server_id, number, limit=20, offset=0):
    identifier(server_id); version(number); page(limit, offset)
    with snapshot(store) as db:
        args = (server_id, number)
        total = int(db.execute("SELECT COUNT(*) FROM managed_outcomes WHERE server_id=? AND version=?", args).fetchone()[0])
        selected = "SELECT data FROM managed_outcomes WHERE server_id=? AND version=? ORDER BY created_at DESC,id DESC LIMIT ? OFFSET ?"
        parameters = args + (limit, offset)
        bound = db.execute("SELECT COALESCE(MAX(" + _size(db) + "),0),COALESCE(SUM(" + _size(db) + "),0) FROM (" + selected + ") selected", parameters).fetchone()
        if int(bound[0]) > MAX_OUTCOME_BYTES or int(bound[1]) + 4096 > MAX_DETAIL_BYTES:
            raise ValueError("Managed outcome detail exceeds its supported byte bound")
        items = []
        for row in db.execute(selected, parameters):
            value = json.loads(row[0])
            if value.get("server_id") != server_id or value.get("version") != number:
                raise ValueError("Exact managed outcome identity mismatch")
            items.append(value)
        return {"server_id": server_id, "version": number, "items": items, "total": total, "limit": limit, "offset": offset, "has_more": offset + limit < total, "scope": "Agent telemetry; no authorization is granted"}


def revision_diff(store, policy_id, before, after):
    identifier(policy_id); version(before); version(after)
    from .managed import difference
    with snapshot(store) as db:
        # Two independently bounded exact records; no historical catalogue load.
        return difference(_revision(db, policy_id, before), _revision(db, policy_id, after))


def bundle_diff(store, server_id, before, after):
    identifier(server_id); version(before); version(after)
    from .managed import difference
    with snapshot(store) as db:
        def selected(number):
            value, _ = _exact(db, "bundle_history", "server_id=? AND version=?", (server_id, number), MAX_DETAIL_BYTES)
            if value.get("server_id") != server_id or value.get("version") != number:
                raise ValueError("Exact endpoint bundle identity mismatch")
            return value
        return difference(selected(before), selected(after))
