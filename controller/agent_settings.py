"""Versioned endpoint polling intent, independent of firewall/security policy.

Higher priority wins per interval. Equal priority prefers an explicit server,
then a group, then a tag selector (more tags first), then the stable rule ID.
Targets inside one rule are a union; selector constraints themselves are ANDed.
"""
from __future__ import annotations

import copy
import re
from contextlib import nullcontext

from .firewall import WorkflowConflict
from .store import digest, matches, stamp, validate_tags

CAPABILITY = "agent_polling_config_v1"
FIELDS = ("control_interval_seconds", "discovery_interval_seconds")
BOUNDS = {FIELDS[0]: (5, 3600), FIELDS[1]: (60, 86400)}
DEFAULTS = {FIELDS[0]: 30, FIELDS[1]: 900}
IDENTIFIER = re.compile(r"[A-Za-z0-9_.:-]{1,100}\Z")


def initialize(db):
    db.executescript("""
    CREATE TABLE IF NOT EXISTS agent_polling_settings (id TEXT PRIMARY KEY,data TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS agent_polling_revisions (id TEXT PRIMARY KEY,data TEXT NOT NULL);
    """)


def _config(store, db):
    return store._get(db, "agent_polling_settings", "settings") or {"id": "settings", "revision": 0, "defaults": dict(DEFAULTS), "rules": []}


def _interval(value, field):
    low, high = BOUNDS[field]
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise ValueError(f"{field} must be an integer from {low} to {high}")
    return value


def _ids(value, allowed, label):
    if not isinstance(value, list) or len(value) > 20000 or any(not isinstance(item, str) or item not in allowed for item in value):
        raise ValueError(f"Choose existing {label}")
    return sorted(set(value))


def _normalize(store, db, value):
    from .locations import selector as normalize_selector
    if not isinstance(value, dict) or set(value) - {"expected_revision", "defaults", "rules"}:
        raise ValueError("Provide expected_revision, defaults and polling rules only")
    defaults = value.get("defaults")
    if not isinstance(defaults, dict) or set(defaults) != set(FIELDS):
        raise ValueError("Provide both global polling intervals")
    defaults = {field: _interval(defaults[field], field) for field in FIELDS}
    rules = value.get("rules", [])
    if not isinstance(rules, list) or len(rules) > 500:
        raise ValueError("Provide at most 500 polling override rules")
    servers, groups = store._all(db, "servers"), store._all(db, "groups")
    server_ids, group_ids = {server["id"] for server in servers}, {group["id"] for group in groups}
    locations = store._all(db, "locations")
    result, seen = [], set()
    for raw in rules:
        if not isinstance(raw, dict) or set(raw) - {"id", "name", "enabled", "priority", "server_ids", "group_ids", "selector", *FIELDS}:
            raise ValueError("Polling rules accept targets, priority and polling intervals only; security settings cannot be changed")
        name = raw.get("name", "")
        if not isinstance(name, str) or not name.strip() or len(name) > 120:
            raise ValueError("Polling rule name is required (maximum 120 characters)")
        priority, enabled = raw.get("priority", 0), raw.get("enabled", True)
        if isinstance(priority, bool) or not isinstance(priority, int) or not -10000 <= priority <= 10000:
            raise ValueError("Rule priority must be an integer from -10000 to 10000")
        if not isinstance(enabled, bool):
            raise ValueError("Rule enabled must be true or false")
        rule = {"name": name.strip(), "enabled": enabled, "priority": priority,
                "server_ids": _ids(raw.get("server_ids", []), server_ids, "servers"),
                "group_ids": _ids(raw.get("group_ids", []), group_ids, "server groups"),
                "selector": normalize_selector(validate_tags(raw.get("selector", {})), locations, strict=True)}
        if not rule["server_ids"] and not rule["group_ids"] and not rule["selector"]:
            raise ValueError("Choose explicit servers, server groups or nonempty target tags; global intervals belong in defaults")
        for field in FIELDS:
            if raw.get(field) is not None:
                rule[field] = _interval(raw[field], field)
        if not any(field in rule for field in FIELDS):
            raise ValueError("An override needs at least one polling interval")
        identifier = raw.get("id") or "rule-" + digest({key: rule[key] for key in ("name", "server_ids", "group_ids", "selector")})[:24]
        if not isinstance(identifier, str) or not IDENTIFIER.fullmatch(identifier) or identifier in seen:
            raise ValueError("Polling rule IDs must be valid and distinct")
        seen.add(identifier)
        result.append({"id": identifier, **rule})
    return {"defaults": defaults, "rules": sorted(result, key=lambda rule: rule["id"])}


def _context(store, db, servers=None):
    servers = store._all(db, "servers") if servers is None else servers
    groups, locations = store._all(db, "groups"), store._all(db, "locations")
    memberships = {group["id"]: store._group_members(group, servers, locations) for group in groups}
    return servers, memberships


def _desired(config, server, memberships):
    def specificity(rule):
        if server["id"] in rule["server_ids"]:
            return (3, 0)
        if any(server["id"] in memberships.get(identifier, set()) for identifier in rule["group_ids"]):
            return (2, 0)
        tags = {**server.get("tags", {}), "location_id": server.get("location_id")}
        if rule["selector"] and matches(tags, rule["selector"]):
            return (1, len(rule["selector"]))
        return (0, 0)
    ranked = [(rule, specificity(rule)) for rule in config["rules"] if rule["enabled"]]
    ranked = sorted(((rule, rank) for rule, rank in ranked if rank[0]), key=lambda item: (-item[0]["priority"], -item[1][0], -item[1][1], item[0]["id"]))
    intervals, field_rules = dict(config["defaults"]), {}
    for field in FIELDS:
        for rule, _ in ranked:
            if field in rule:
                intervals[field], field_rules[field] = rule[field], rule["id"]
                break
    return {"version": config["revision"], "digest": digest(intervals), **intervals,
            "matched_rule_ids": sorted(set(field_rules.values())), "field_rules": field_rules}


def _status(server, desired):
    supported = CAPABILITY in server.get("capabilities", [])
    observed = server.get("agent_polling_observed")
    state = "unsupported" if not supported else "ahead_of_controller" if observed and observed.get("version", 0) > desired["version"] else "error" if observed and observed.get("status") == "error" else "current" if observed and observed.get("status") == "applied" and observed.get("version") == desired["version"] and observed.get("digest") == desired["digest"] else "pending"
    return {"desired": desired, "observed": copy.deepcopy(observed), "supported": supported, "status": state}


def get(store):
    with store.read_meta() as db:
        config = _config(store, db)
        servers, memberships = _context(store, db)
        return {**config, "capability": CAPABILITY, "precedence": "Higher priority, then explicit server, group, more-specific tags, stable rule ID; intervals resolve independently",
                "servers": [{"server_id": server["id"], "hostname": server["hostname"], "last_seen": server.get("last_seen"), "reported_control_interval_seconds": server.get("control_interval_seconds"), "reported_discovery_interval_seconds": server.get("discovery_interval_seconds"), **_status(server, _desired(config, server, memberships))} for server in sorted(servers, key=lambda item: (item["hostname"].casefold(), item["id"]))]}


def assignment(store, server_id, db=None):
    with nullcontext(db) if db is not None else store.read_meta() as connection:
        server = store._get(connection, "servers", server_id)
        if server is None:
            raise KeyError(server_id)
        _, memberships = _context(store, connection, [server])
        return _desired(_config(store, connection), server, memberships)


def decorate(store, server, db=None):
    return {**server, "agent_settings": _status(server, assignment(store, server["id"], db))}


def _proposal(store, db, value):
    current = _config(store, db)
    if isinstance(value.get("expected_revision"), bool) or not isinstance(value.get("expected_revision"), int) or value.get("expected_revision") != current["revision"]:
        raise WorkflowConflict("Agent polling settings changed; reload and review the current revision", {"current_revision": current["revision"]})
    normalized = _normalize(store, db, value)
    changed = any(normalized[key] != current[key] for key in ("defaults", "rules"))
    return current, {**current, **normalized, "revision": current["revision"] + int(changed)}, changed


def preview(store, value):
    if not isinstance(value, dict):
        raise ValueError("Polling settings must be an object")
    with store.read_meta() as db:
        before, after, changed = _proposal(store, db, value)
        servers, memberships = _context(store, db)
        impacts = []
        for server in servers:
            prior, proposed = _desired(before, server, memberships), _desired(after, server, memberships)
            if prior["digest"] != proposed["digest"]:
                impacts.append({"server_id": server["id"], "hostname": server["hostname"], "before": prior, "after": proposed, "supported": CAPABILITY in server.get("capabilities", [])})
        return {"before": before, "after": after, "changed": changed, "affected_servers": impacts, "effective_change_count": len(impacts), "target_server_count": len(servers)}


def save(store, value, actor):
    if not isinstance(value, dict):
        raise ValueError("Polling settings must be an object")
    with store.lock, store.meta() as db:
        if getattr(db, "dialect", "sqlite") == "sqlite":
            db.execute("BEGIN IMMEDIATE")
        _, proposed, changed = _proposal(store, db, value)
        if changed:
            proposed.update(updated_at=stamp(), updated_by=actor)
            store._put(db, "agent_polling_settings", proposed)
            store._put(db, "agent_polling_revisions", {**proposed, "id": "revision:" + str(proposed["revision"])})
            store.audit("agent_polling.updated", actor, {"revision": proposed["revision"], "defaults": proposed["defaults"], "rule_ids": [rule["id"] for rule in proposed["rules"]]}, db)
    return get(store)


def report(store, db, server, value):
    receipt = value.get("polling_settings")
    if receipt is None:
        return
    if not isinstance(receipt, dict) or set(receipt) - {"version", "digest", "status", "error"}:
        raise ValueError("Invalid polling settings report")
    version, checksum, status, error = receipt.get("version"), receipt.get("digest"), receipt.get("status"), receipt.get("error", "")
    if isinstance(version, bool) or not isinstance(version, int) or version < 0 or not isinstance(checksum, str) or not re.fullmatch(r"[a-f0-9]{64}", checksum) or status not in ("applied", "error") or not isinstance(error, str) or len(error) > 1000:
        raise ValueError("Invalid polling settings version, digest or outcome")
    server["agent_polling_observed"] = {"version": version, "digest": checksum, "status": status, "error": error, "reported_at": stamp()}
