"""Bounded public source catalogues. Navigation never supplies grant/edit authority."""
from collections import OrderedDict
from contextlib import closing
import json
import re

from .approval_views import _expression
from .inventory_views import rows
from .store import digest, exact_policy_endpoints

TABLES = {"managed": "policies", "learned": "learning_allow_policies"}
MAX_DETAIL_BYTES = 8 * 1024 * 1024
MAX_PAGE_BYTES = 8 * 1024 * 1024
MAX_META_BYTES = 65536
SCALARS = ("name", "mode", "revision", "created_at", "updated_at", "server_id", "hostname", "session_id", "status", "error", "origin", "removed", "removal_pending", "auto_updates", "applied_revision", "authority_expires_at")


def _json(db, path, data="data"):
    if getattr(db, "dialect", "sqlite") == "postgresql":
        return "(" + data + "::jsonb#>'{" + ",".join(path) + "}')::text"
    return "json_extract(" + data + ",'$." + ".".join(path) + "')"


def _endpoint_ids(db):
    if getattr(db, "dialect", "sqlite") == "postgresql":
        return _json(db, ("endpoint_ids",))
    # Distinguish a missing key (legacy) from explicit JSON null (invalid).
    return "CASE WHEN json_type(data,'$.endpoint_ids') IS NOT NULL THEN json_quote(json_extract(data,'$.endpoint_ids')) END"


def initialize(db):
    for kind, table in TABLES.items():
        for field in (("name", "mode") if kind == "managed" else ("created_at", "status")):
            db.execute("CREATE INDEX IF NOT EXISTS public_" + table + "_" + field + " ON " + table + " ((" + _expression(db, (field,)) + "),id)")


def encoded_policy(policy):
    """Use the storage encoding, including escaped Unicode, for the read fence."""
    if policy.get("summary_only") or any(isinstance(service,dict) and service.get("sources_omitted") for service in (policy.get("services") if isinstance(policy.get("services"),list) else [])):
        raise ValueError("Policy navigation omits exact sources and cannot be stored as canonical authority")
    encoded = json.dumps(policy, separators=(",", ":"))
    if len(encoded.encode("utf-8")) > MAX_DETAIL_BYTES:
        raise ValueError("Normalized policy exceeds the 8 MiB exact-detail limit; use a smaller policy")
    return encoded


def options(value=None):
    value = {} if value is None else value
    allowed = {"limit", "offset", "server_ids", "search_server_ids", "ports", "search", "mode", "session_id", "server_id", "status"}
    if not isinstance(value, dict) or set(value) - allowed:
        raise ValueError("Provide a supported compact policy scope query")
    result = {"limit": value.get("limit", 20), "offset": value.get("offset", 0), "search": value.get("search", ""), "ports": value.get("ports", [])}
    if isinstance(result["limit"], bool) or not isinstance(result["limit"], int) or not 1 <= result["limit"] <= 100 or isinstance(result["offset"], bool) or not isinstance(result["offset"], int) or result["offset"] < 0:
        raise ValueError("Policy pagination requires limit 1..100 and nonnegative offset")
    if not isinstance(result["search"], str) or len(result["search"]) > 256:
        raise ValueError("Policy search must be at most 256 characters")
    for key in ("server_ids", "search_server_ids"):
        ids = value.get(key)
        if ids is not None and (not isinstance(ids, list) or len(ids) > 20000 or any(not isinstance(identifier, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", identifier) for identifier in ids)):
            raise ValueError("Policy scope requires at most 20000 exact endpoint IDs")
        result[key] = None if ids is None else sorted(set(ids))
    ports = result["ports"]
    if not isinstance(ports, list) or len(ports) > 100 or any(not isinstance(port, str) or not re.fullmatch(r"[0-9]{1,5}(?:/(?:tcp|udp))?", port) or not 1 <= int(port.split('/')[0]) <= 65535 for port in ports):
        raise ValueError("Policy port filters must be exact ports, optionally /tcp or /udp")
    result["ports"] = sorted(set(ports))
    for field in ("session_id", "server_id"):
        item = value.get(field)
        if item is not None and (not isinstance(item, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", item)):
            raise ValueError("Invalid policy " + field)
        result[field] = item
    for field, choices in (("mode", ("monitor", "enforce")), ("status", ("preview", "generated", "pending", "applied", "blocked", "rolled_back", "error", "removed"))):
        item = value.get(field)
        if item is not None and item not in choices:
            raise ValueError("Invalid policy " + field)
        result[field] = item
    return result


def _services(db):
    if getattr(db, "dialect", "sqlite") == "postgresql":
        fields = "'port',service.value->'port','protocol',service.value->'protocol','service_group_id',service.value->'service_group_id','source_selector',COALESCE(service.value->'source_selector','{}'::jsonb),'source_group_ids',COALESCE(service.value->'source_group_ids','[]'::jsonb),'source_count',COALESCE(jsonb_array_length(service.value->'sources'),0),'sources_omitted',true,'service_group_snapshot',CASE WHEN service.value->>'service_group_id' IS NULL THEN NULL ELSE jsonb_build_object('id',service.value#>'{service_group_snapshot,id}','name',service.value#>'{service_group_snapshot,name}','revision',service.value#>'{service_group_snapshot,revision}','ports',COALESCE(service.value#>'{service_group_snapshot,ports}','[]'::jsonb)) END"
        return "(SELECT COALESCE(jsonb_agg(jsonb_build_object(" + fields + ") ORDER BY service.ordinality),'[]'::jsonb)::text FROM jsonb_array_elements(COALESCE(data::jsonb->'services','[]'::jsonb)) WITH ORDINALITY service(value,ordinality))"
    fields = "'port',json_extract(service.value,'$.port'),'protocol',json_extract(service.value,'$.protocol'),'service_group_id',json_extract(service.value,'$.service_group_id'),'source_selector',json(COALESCE(json_extract(service.value,'$.source_selector'),'{}')),'source_group_ids',json(COALESCE(json_extract(service.value,'$.source_group_ids'),'[]')),'source_count',COALESCE(json_array_length(service.value,'$.sources'),0),'sources_omitted',json('true'),'service_group_snapshot',CASE WHEN json_extract(service.value,'$.service_group_id') IS NULL THEN NULL ELSE json_object('id',json_extract(service.value,'$.service_group_snapshot.id'),'name',json_extract(service.value,'$.service_group_snapshot.name'),'revision',json_extract(service.value,'$.service_group_snapshot.revision'),'ports',json(COALESCE(json_extract(service.value,'$.service_group_snapshot.ports'),'[]'))) END"
    return "(SELECT COALESCE(json_group_array(json_object(" + fields + ")),'[]') FROM json_each(data,'$.services') service)"


def _ports(db, selections):
    if not selections:
        return "1=1", ()
    postgres = getattr(db, "dialect", "sqlite") == "postgresql"
    def condition(alias):
        port = "CAST(" + alias + ".value->>'port' AS INTEGER)" if postgres else "json_extract(" + alias + ".value,'$.port')"
        protocol = "COALESCE(" + alias + ".value->>'protocol','tcp')" if postgres else "COALESCE(json_extract(" + alias + ".value,'$.protocol'),'tcp')"
        fragments, args = [], []
        for selection in selections:
            number, _, proto = selection.partition('/')
            fragments.append("(" + port + "=?" + (" AND " + protocol + "=?" if proto else "") + ")")
            args.append(int(number))
            if proto: args.append(proto)
        return "(" + " OR ".join(fragments) + ")", args
    direct, first = condition("service")
    grouped, second = condition("port")
    if postgres:
        source = "jsonb_array_elements(COALESCE(data::jsonb->'services','[]'::jsonb)) service(value)"
        group = "service.value->>'service_group_id'"
        nested = "jsonb_array_elements(COALESCE(service.value#>'{service_group_snapshot,ports}','[]'::jsonb)) port(value)"
    else:
        source = "json_each(data,'$.services') service"
        group = "json_extract(service.value,'$.service_group_id')"
        nested = "json_each(service.value,'$.service_group_snapshot.ports') port"
    return "EXISTS(SELECT 1 FROM " + source + " WHERE (" + group + " IS NULL AND " + direct + ") OR (" + group + " IS NOT NULL AND EXISTS(SELECT 1 FROM " + nested + " WHERE " + grouped + ")))", tuple(first + second)


def _where(db, kind, value):
    clauses, args = [], []
    if kind == "learned":
        removed = "COALESCE(CAST(" + _expression(db, ("removed",)) + " AS TEXT),'0')"
        pending = "COALESCE(CAST(" + _expression(db, ("removal_pending",)) + " AS TEXT),'0')"
        clauses.append("(" + removed + " NOT IN ('true','1') OR " + pending + " IN ('true','1'))")
    for field in (("mode",) if kind == "managed" else ("session_id", "server_id", "status")):
        if value[field] is not None:
            clauses.append((field if field in ("session_id", "server_id") else _expression(db, (field,))) + "=?")
            args.append(value[field])
    ports, port_args = _ports(db, value["ports"])
    clauses.append(ports); args.extend(port_args)
    return " AND ".join(clauses), tuple(args)


def _decoded(value, default, maximum=MAX_META_BYTES):
    if value is None:
        return default
    if not isinstance(value, str) or len(value.encode("utf-8")) > maximum:
        raise ValueError("Public policy metadata exceeds its navigation bound; fetch exact detail")
    return json.loads(value)


class Targets:
    def __init__(self, store, db, value):
        self.store, self.db, self.groups = store, db, OrderedDict()
        self.servers = []
        selected = set(value["server_ids"] or []) | set(value["search_server_ids"] or [])
        # Only candidate endpoint metadata is needed, not listeners, compiled
        # policies or snapshots. A bounded chunk avoids oversized IN clauses.
        ids = sorted(selected)
        for start in range(0, len(ids), 500):
            chunk = ids[start:start + 500]
            sql = "SELECT id," + _json(db, ("tags",)) + "," + _expression(db, ("location_id",)) + " FROM servers WHERE id IN (" + ",".join("?" for _ in chunk) + ")"
            self.servers.extend({"id": row[0], "tags": _decoded(row[1], {}), "location_id": row[2]} for row in db.execute(sql, chunk))
        self.locations = store._all(db, "locations") if selected else []
        self.valid_locations = {item["id"] for item in self.locations}

    def matches(self, selector, group_ids, raw_endpoints, selected):
        if selected is None:
            return True
        if not selected:
            return False
        if raw_endpoints is not None:
            endpoints = exact_policy_endpoints({"endpoint_ids": _decoded(raw_endpoints, None), "selector": selector, "group_ids": group_ids})
            return bool(endpoints & selected)
        if group_ids:
            for identifier in group_ids:
                if identifier not in self.groups:
                    group = self.store._get(self.db, "groups", identifier)
                    self.groups[identifier] = self.store._group_members(group, self.servers, self.locations) if group else set()
                    if len(self.groups) > 8: self.groups.popitem(last=False)
                if self.groups[identifier] & selected: return True
            return False
        from .locations import reserved, selector as normalize
        from .store import matches
        selector = normalize(selector, self.locations, strict=False)
        return any(server["id"] in selected and matches({**{key: val for key, val in server["tags"].items() if not reserved(key)}, **({"location_id": server["location_id"]} if server["location_id"] in self.valid_locations else {})}, selector) for server in self.servers)


def _summaries(db, table, selected):
    if not selected:
        return
    projection = ["id"] + ["substr(CAST(" + _expression(db, (field,)) + " AS TEXT),1," + ("4096" if field == "error" else "512") + ")" for field in SCALARS]
    projection += [_json(db, ("selector",)), _json(db, ("group_ids",)), _endpoint_ids(db), _services(db)]
    wanted = ",".join("(?," + str(index) + ")" for index in range(len(selected)))
    sql = "WITH wanted(wanted_id,position) AS (VALUES " + wanted + ") SELECT " + ",".join(projection) + " FROM " + table + " JOIN wanted ON wanted.wanted_id=" + table + ".id ORDER BY wanted.position"
    remaining = MAX_PAGE_BYTES
    for row in rows(db, sql, selected, batch_size=1):
        raw_size = sum(len(row[index].encode("utf-8")) for index in range(len(row)) if isinstance(row[index], str))
        if raw_size > MAX_PAGE_BYTES:
            raise ValueError("Policy navigation exceeds its page bound; fetch exact detail")
        if raw_size > remaining:
            yield None
            return
        item = {"id": row[0], **{field: row[index + 1] for index, field in enumerate(SCALARS)}}
        start = 1 + len(SCALARS)
        item.update(selector=_decoded(row[start], {}), group_ids=_decoded(row[start + 1], []), services=_decoded(row[start + 3], [], MAX_PAGE_BYTES), summary_only=True, source_count_kind="literal_entries")
        if row[start + 2] is not None:
            item["endpoint_ids"] = sorted(exact_policy_endpoints({**item, "endpoint_ids": _decoded(row[start + 2], None)}))
        if not isinstance(item["services"], list) or len(item["services"]) > 100:
            raise ValueError("Invalid public policy service projection")
        for field in ("revision", "applied_revision"):
            if item[field] is not None: item[field] = int(item[field])
        if item["applied_revision"] is None:
            item.pop("applied_revision")
        for field in ("removed", "removal_pending", "auto_updates"):
            item[field] = str(item[field]).lower() in ("true", "1")
        item.update(service_count=len(item["services"]), source_count=sum(int(service["source_count"]) for service in item["services"]))
        size = len(json.dumps(item, separators=(",", ":")).encode("utf-8"))
        if size > MAX_PAGE_BYTES:
            raise ValueError("Policy navigation exceeds its page bound; fetch exact detail")
        if size > remaining:
            yield None
            return
        remaining -= size
        yield item


def listing(store, kind="managed", value=None):
    if kind not in TABLES: raise ValueError("Invalid policy catalogue")
    value = options(value)
    if kind=="managed" and any(value[field] is not None for field in ("session_id","status")) or kind=="learned" and value["mode"] is not None:
        raise ValueError("This policy catalogue does not support that filter category")
    if kind == "managed" and value["server_id"] is not None:
        value["server_ids"] = [value["server_id"]] if value["server_ids"] is None else sorted(set(value["server_ids"]) & {value["server_id"]})
    scope = set(value["server_ids"]) if value["server_ids"] is not None else None
    search_ids = set(value["search_server_ids"] or [])
    if scope is not None: search_ids &= scope
    needle = value["search"].lower()
    with store.read_meta() as db:
        if getattr(db, "dialect", "sqlite") == "sqlite": db.execute("BEGIN")
        where, args = _where(db, kind, value)
        if kind == "managed":
            projection = "id," + _expression(db, ("name",)) + "," + _json(db, ("selector",)) + "," + _json(db, ("group_ids",)) + "," + _endpoint_ids(db)
            order = _expression(db, ("name",)) + (" COLLATE \"C\"" if getattr(db, "dialect", "sqlite") == "postgresql" else " COLLATE BINARY") + ",id"
            targets = Targets(store, db, value) if scope is not None or needle else None
        else:
            # Source search occurs in the DB; source values never enter a list
            # header. A scalar boolean is all the count/filter loop receives.
            search_text = "COALESCE(" + _expression(db, ("name",)) + ",'')||' '||COALESCE(" + _expression(db, ("hostname",)) + ",'')||' '||COALESCE(" + _json(db, ("services",)) + ",'')"
            projection = "id,server_id,CASE WHEN instr(lower(" + search_text + "),?)>0 THEN 1 ELSE 0 END" if getattr(db, "dialect", "sqlite") == "sqlite" else "id,server_id,CASE WHEN strpos(lower(" + search_text + "),?)>0 THEN 1 ELSE 0 END"
            args = (needle,) + args
            order = _expression(db, ("created_at",)) + " DESC,id DESC"
        selected, total = [], 0
        if scope is None and not needle:
            # The common overview/unfiltered page has an indexed count/key
            # query; it does not stream every target selector unnecessarily.
            count_args = args[1:] if kind == "learned" else args
            total = int(db.execute("SELECT COUNT(*) FROM " + TABLES[kind] + " WHERE " + where, count_args).fetchone()[0])
            selected = [row[0] for row in db.execute("SELECT id FROM " + TABLES[kind] + " WHERE " + where + " ORDER BY " + order + " LIMIT ? OFFSET ?", count_args + (value["limit"], value["offset"]))]
        else:
            with closing(rows(db, "SELECT " + projection + " FROM " + TABLES[kind] + " WHERE " + where + " ORDER BY " + order, args)) as headers:
                for row in headers:
                    if kind == "managed":
                        name_match = bool(needle) and needle in (row[1] or "").lower()
                        if scope is not None or needle and not name_match:
                            selector, groups = _decoded(row[2], {}), _decoded(row[3], [])
                            wanted = scope if not needle or name_match else search_ids
                            if not targets.matches(selector, groups, row[4], wanted): continue
                    else:
                        if scope is not None and row[1] not in scope: continue
                        if needle and not row[2] and row[1] not in search_ids: continue
                    if value["offset"] <= total < value["offset"] + value["limit"]: selected.append(row[0])
                    total += 1
        items, byte_limited = [], False
        with closing(_summaries(db, TABLES[kind], selected)) as summaries:
            for item in summaries:
                if item is None:
                    byte_limited = True; break
                items.append(item)
        scoped = {key: val for key, val in value.items() if key not in ("limit", "offset", "server_ids", "search_server_ids")}
        scoped.update(server_count=None if scope is None else len(scope), search_server_count=len(search_ids))
        return {"items": items, "total": total, "limit": value["limit"], "offset": value["offset"], "next_offset": value["offset"] + len(items), "has_more": value["offset"] + len(items) < total, "summary_only": True, "scope_digest": digest({key: val for key, val in value.items() if key not in ("limit", "offset")}), "filters": scoped, "byte_limited": byte_limited}


def detail(store, kind, identifier):
    if kind not in TABLES or not isinstance(identifier, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", identifier):
        raise ValueError("Invalid exact policy identity")
    with store.read_meta() as db:
        if getattr(db, "dialect", "sqlite") == "sqlite": db.execute("BEGIN")
        size = "octet_length(data)" if getattr(db, "dialect", "sqlite") == "postgresql" else "length(CAST(data AS BLOB))"
        row = db.execute("SELECT " + size + " FROM " + TABLES[kind] + " WHERE id=?", (identifier,)).fetchone()
        if row is None: raise KeyError(identifier)
        if row[0] > MAX_DETAIL_BYTES: raise ValueError("Exact policy exceeds the 8 MiB detail limit; use a smaller policy")
        raw = db.execute("SELECT data FROM " + TABLES[kind] + " WHERE id=?", (identifier,)).fetchone()[0]
        if len(raw.encode("utf-8")) > MAX_DETAIL_BYTES: raise ValueError("Exact policy exceeds the 8 MiB detail limit")
        policy = json.loads(raw)
        if policy.get("id") != identifier or policy.get("summary_only") or any(service.get("sources_omitted") or not isinstance(service.get("sources"), list) for service in policy.get("services", [])):
            raise ValueError("Exact canonical policy source data is unavailable; navigation cannot authorize an edit")
        return policy


def _service_group_refs(db, identifier):
    if getattr(db, "dialect", "sqlite") == "postgresql":
        where = "EXISTS(SELECT 1 FROM jsonb_array_elements(COALESCE(data::jsonb->'services','[]'::jsonb)) service(value) WHERE service.value->>'service_group_id'=?)"
    else:
        where = "EXISTS(SELECT 1 FROM json_each(data,'$.services') service WHERE json_extract(service.value,'$.service_group_id')=?)"
    total = int(db.execute("SELECT COUNT(*) FROM policies WHERE " + where, (identifier,)).fetchone()[0])
    ids = [row[0] for row in db.execute("SELECT id FROM policies WHERE " + where + " ORDER BY id LIMIT 100", (identifier,))]
    return {"policy_ids": ids, "policy_count": total, "policy_ids_has_more": total > len(ids), "policy_ids_limit": 100}


def service_groups(store, identifier=None):
    with store.read_meta() as db:
        if getattr(db, "dialect", "sqlite") == "sqlite": db.execute("BEGIN")
        groups = [store._get(db, "service_groups", identifier)] if identifier is not None else store._all(db, "service_groups")
        if identifier is not None and groups[0] is None: raise KeyError(identifier)
        result = [{**group, **_service_group_refs(db, group["id"])} for group in groups]
        return result[0] if identifier is not None else sorted(result, key=lambda group: group["name"].casefold())
