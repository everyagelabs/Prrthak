"""Reusable exact-port catalogues and shared, indexed policy compilation.

Catalogue edits revise active policy snapshots in the same transaction as the
effective bundles. Nothing in this module grants managed firewall approval.
"""
from __future__ import annotations

import ipaddress
import json
import uuid

from .firewall import WorkflowConflict
from .store import digest, exact_policy_endpoints, stamp, validate_port


def initialize(db):
    db.executescript("""
      CREATE TABLE IF NOT EXISTS service_groups (id TEXT PRIMARY KEY, data TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS service_group_revisions (id TEXT PRIMARY KEY, service_group_id TEXT NOT NULL, revision INTEGER NOT NULL, created_at TEXT NOT NULL, data TEXT NOT NULL, UNIQUE(service_group_id,revision));
      CREATE INDEX IF NOT EXISTS service_group_revision_lookup ON service_group_revisions(service_group_id,revision);
    """)


def validate(value):
    if not isinstance(value, dict):
        raise ValueError("Service group must be an object")
    name = value.get("name", "")
    if not isinstance(name, str) or not name.strip() or len(name) > 120:
        raise ValueError("Service group name is required (max 120 characters)")
    description = value.get("description", "")
    if not isinstance(description, str) or len(description) > 2000:
        raise ValueError("Service group description must be text (max 2000 characters)")
    ports = value.get("ports")
    if not isinstance(ports, list) or not ports or len(ports) > 1000:
        raise ValueError("Provide between 1 and 100 distinct exact service ports")
    normalized = set()
    for port in ports:
        if not isinstance(port, dict) or set(port) - {"port", "protocol"}:
            raise ValueError("Service groups contain only exact port/protocol entries; nested groups and ranges are not supported")
        item = validate_port(port)
        normalized.add((item["protocol"], item["port"]))
    if len(normalized) > 100:
        raise ValueError("A service group can contain at most 100 distinct ports")
    return {"name": name.strip(), "description": description.strip(), "ports": [{"port": port, "protocol": protocol} for protocol, port in sorted(normalized)]}


def snapshot(group):
    return {"id": group["id"], "revision": group["revision"], "name": group["name"], "ports": [dict(port) for port in group["ports"]]}


def references(policies, identifier):
    return sorted((policy for policy in policies if any(service.get("service_group_id") == identifier for service in policy.get("services", []))), key=lambda policy: (policy["name"].casefold(), policy["id"]))


def public(group, policies):
    policies = references(policies, group["id"])
    return {**group, "policy_ids": [policy["id"] for policy in policies], "policy_count": len(policies)}


def listing(store):
    with store.read_meta() as db:
        policies = store._all(db, "policies")
        return sorted((public(group, policies) for group in store._all(db, "service_groups")), key=lambda group: (group["name"].casefold(), group["id"]))


def get(store, identifier):
    with store.read_meta() as db:
        group = store._get(db, "service_groups", identifier)
        if group is None:
            raise KeyError(identifier)
        return public(group, store._all(db, "policies"))


def revisions(store, identifier, revision=None):
    with store.read_meta() as db:
        if revision is None:
            rows = db.execute("SELECT data FROM service_group_revisions WHERE service_group_id=? ORDER BY revision DESC LIMIT 500", (identifier,)).fetchall()
            if not rows and store._get(db, "service_groups", identifier) is None:
                raise KeyError(identifier)
            return [json.loads(row[0]) for row in rows]
        row = db.execute("SELECT data FROM service_group_revisions WHERE service_group_id=? AND revision=?", (identifier, revision)).fetchone()
        if row is None:
            raise KeyError(identifier)
        return json.loads(row[0])


def _record_revision(db, group, actor, reason):
    value = {**group, "actor": actor, "reason": reason}
    db.execute("INSERT INTO service_group_revisions(id,service_group_id,revision,created_at,data) VALUES(?,?,?,?,?)", (group["id"] + ":" + str(group["revision"]), group["id"], group["revision"], group["updated_at"], json.dumps(value, sort_keys=True)))


def _proposed(store, db, value, identifier=None):
    normalized = validate(value)
    old = store._get(db, "service_groups", identifier) if identifier else None
    if identifier and old is None:
        raise KeyError(identifier)
    if value.get("id") is not None and value["id"] != identifier:
        raise ValueError("Service group identity is immutable and assigned by the catalogue")
    if old:
        expected = value.get("expected_revision")
        if isinstance(expected, bool) or not isinstance(expected, int) or expected < 1:
            raise ValueError("expected_revision is required when editing a service group")
        if expected != old["revision"]:
            raise WorkflowConflict("Service group changed since it was loaded; reload and preview again", {"current_revision": old["revision"]})
    elif value.get("expected_revision") is not None:
        raise ValueError("expected_revision applies only to an existing service group")
    changed = old is None or any(old.get(field) != normalized[field] for field in ("name", "description", "ports"))
    group = {**normalized, "id": identifier or str(uuid.uuid4()), "revision": old["revision"] + int(changed) if old else 1,
             "created_at": old["created_at"] if old else stamp(), "updated_at": stamp() if changed else old["updated_at"]}
    return old, group, changed


def preview(store, value, identifier=None):
    """Calculate exact host impact without catalogue, audit or bundle writes."""
    if not isinstance(value, dict):
        raise ValueError("Service group must be an object")
    identifier = identifier or value.get("id")
    if identifier is not None and (not isinstance(identifier, str) or not identifier or len(identifier) > 100):
        raise ValueError("Invalid service group identity")
    with store.read_meta() as db:
        old, group, changed = _proposed(store, db, value, identifier)
        policies = store._all(db, "policies")
        affected = references(policies, group["id"])
        compiled = effective_bundles(store, db, policies=policies, service_group_overrides={group["id"]: group})
        target_ids = set().union(*(compiled["targets"].get(policy["id"], set()) for policy in affected)) if affected else set()
        changed_servers = []
        for server in compiled["servers"]:
            if server["id"] in target_ids and digest(compiled["payloads"][server["id"]]) != server.get("_compiled", {}).get("digest"):
                changed_servers.append({"id": server["id"], "hostname": server.get("hostname", server["id"]), "current_version": server.get("_compiled", {}).get("version", 0)})
        changed_servers.sort(key=lambda server: (server["hostname"].casefold(), server["id"]))
        return {"before": public(old, policies) if old else None, "after": public(group, policies), "changed": changed,
                "ports_changed": old is None or old["ports"] != group["ports"],
                "affected_policy_ids": [policy["id"] for policy in affected],
                "affected_policies": [{"id": policy["id"], "name": policy["name"], "mode": policy["mode"], "revision": policy["revision"]} for policy in affected],
                "target_server_ids": sorted(target_ids), "target_server_count": len(target_ids),
                "affected_server_ids": [server["id"] for server in changed_servers], "affected_servers": changed_servers,
                "effective_change_count": len(changed_servers), "requires_managed_review": bool(changed_servers)}


def save(store, value, actor, identifier=None):
    with store.lock, store.meta() as db:
        old, group, changed = _proposed(store, db, value, identifier)
        policies = store._all(db, "policies")
        if not changed:
            return public(old, policies)
        store._put(db, "service_groups", group)
        _record_revision(db, group, actor, "Service group configuration changed" if old else "Service group created")
        from .managed import record_revision
        for policy in references(policies, group["id"]):
            # Replacement creates new row dictionaries; historical objects keep
            # the exact ports and catalogue revision used at that time.
            policy["services"] = [{**service, "service_group_snapshot": snapshot(group)} if service.get("service_group_id") == group["id"] else service for service in policy["services"]]
            policy["revision"] += 1
            policy["updated_at"] = stamp()
            record_revision(db, policy, actor, "Referenced service group changed: " + group["name"])
            store._put(db, "policies", policy)
        store.compile_all(db)
        store.audit("service_group.updated" if old else "service_group.created", actor, {"service_group_id": group["id"], "name": group["name"], "revision": group["revision"], "ports_changed": old is None or old["ports"] != group["ports"]}, db)
        return public(group, policies)


def delete(store, identifier, actor):
    with store.lock, store.meta() as db:
        group = store._get(db, "service_groups", identifier)
        if group is None:
            raise KeyError(identifier)
        if references(store._all(db, "policies"), identifier):
            raise ValueError("Service group is referenced by an active policy; remove its references before deleting")
        db.execute("DELETE FROM service_groups WHERE id=?", (identifier,))
        store.audit("service_group.deleted", actor, {"service_group_id": identifier, "name": group["name"], "revision": group["revision"]}, db)


def effective_bundles(store, db, *, servers=None, policies=None, service_group_overrides=None):
    """Resolve each selector/source group once per fleet compilation or preview."""
    from .locations import reserved, selector as normalize_selector
    servers = store._all(db, "servers") if servers is None else servers
    policies = store._all(db, "policies") if policies is None else policies
    by_id = {server["id"]: server for server in servers}
    all_ids = set(by_id)
    locations = store._all(db, "locations")
    valid_locations = {record["id"] for record in locations}
    tag_index = {}
    for server in servers:
        for key, value in server.get("tags", {}).items():
            if not reserved(key):
                tag_index.setdefault((key, value), set()).add(server["id"])
        if server.get("location_id") in valid_locations:
            tag_index.setdefault(("location_id", server["location_id"]), set()).add(server["id"])
    selector_cache = {}

    def selected(selector):
        key = tuple(sorted(selector.items()))
        if key not in selector_cache:
            canonical = normalize_selector(selector, locations, strict=False)
            sets = sorted((tag_index.get(item, set()) for item in canonical.items()), key=len)
            selector_cache[key] = set.intersection(*sets) if sets else set(all_ids)
        return selector_cache[key]

    group_members = {}
    for group in store._all(db, "groups"):
        group_members[group["id"]] = (selected(group["selector"]) if group.get("selector") else set()) if group["type"] == "dynamic" else set(group.get("server_ids", [])) & all_ids
    service_groups = {group["id"]: group for group in store._all(db, "service_groups")}
    service_groups.update(service_group_overrides or {})
    address_cache, source_cache = {}, {}

    def addresses(identifiers):
        sources = set()
        for identifier in identifiers:
            if identifier not in address_cache:
                from .network_addresses import network
                address_cache[identifier] = {str(network(address)) for address in by_id[identifier].get("ips", [])}
            sources.update(address_cache[identifier])
        return sources

    rules_by_host, matched, targets_by_policy, snapshots_by_host = {}, {}, {}, {}
    for policy in sorted(policies, key=lambda item: item["id"]):
        exact = exact_policy_endpoints(policy)
        group_ids = policy.get("group_ids", [])
        targets = (exact & all_ids if exact is not None else
                   set().union(*(group_members.get(identifier, set()) for identifier in group_ids)) if group_ids
                   else selected(policy.get("selector", {})))
        targets_by_policy[policy["id"]] = targets
        resolved, used_groups = [], {}
        for service in policy["services"]:
            group_id = service.get("service_group_id")
            if group_id is not None:
                group = service_groups.get(group_id)
                if group is None:
                    # Refuse the whole transaction rather than silently
                    # removing an enforced port or requesting managed cleanup.
                    raise ValueError("Policy references an unknown saved service group")
                ports = group["ports"]
                used_groups[group_id] = snapshot(group)
            else:
                ports = [{"port": service["port"], "protocol": service["protocol"]}]
            sources = set(service.get("sources", []))
            selector = service.get("source_selector", {})
            if selector:
                key = ("selector", tuple(sorted(selector.items())))
                if key not in source_cache:
                    source_cache[key] = addresses(selected(selector))
                sources.update(source_cache[key])
            for source_group_id in service.get("source_group_ids", []):
                if source_group_id not in group_members:
                    raise ValueError("Policy references an unknown saved source server group")
                key = ("group", source_group_id)
                if key not in source_cache:
                    source_cache[key] = addresses(group_members.get(source_group_id, set()))
                sources.update(source_cache[key])
            resolved.extend((port, sources) for port in ports)
        for identifier in targets:
            matched.setdefault(identifier, []).append(policy["id"])
            snapshots_by_host.setdefault(identifier, {}).update(used_groups)
            rules = rules_by_host.setdefault(identifier, {})
            for port, sources in resolved:
                key = (port["protocol"], port["port"])
                rule = rules.setdefault(key, {"port": port["port"], "protocol": port["protocol"], "monitor": set(), "enforce": set(), "modes": set()})
                rule["modes"].add(policy["mode"])
                rule[policy["mode"]].update(sources)
    payloads = {}
    for server in servers:
        services = []
        for _, rule in sorted(rules_by_host.get(server["id"], {}).items()):
            mode = "enforce" if "enforce" in rule["modes"] else "monitor"
            services.append({"port": rule["port"], "protocol": rule["protocol"], "mode": mode, "sources": sorted(rule[mode])})
        payloads[server["id"]] = {"mode": "enforce" if any(rule["mode"] == "enforce" for rule in services) else "monitor", "services": services}
        from .host_default_deny import payload as host_default_deny_payload
        payloads[server["id"]] = host_default_deny_payload(server, payloads[server["id"]])
    return {"servers": servers, "payloads": payloads, "matched": matched, "targets": targets_by_policy,
            "snapshots": {identifier: [groups[key] for key in sorted(groups)] for identifier, groups in snapshots_by_host.items()}}
