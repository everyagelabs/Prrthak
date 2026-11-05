"""Dashboard-owned metadata, explicit overrides and reviewed subnet assignment."""
from __future__ import annotations

import copy
import ipaddress
import secrets
import uuid
from datetime import timedelta
from functools import lru_cache

from .store import digest, now, parse_time, stamp
from .locations import assignment, reserved, tags as validate_custom_tags
from .firewall import WorkflowConflict


def initialize(db):
    for table in ("metadata_ip_profiles", "metadata_subnets", "metadata_plans"):
        db.execute(f"CREATE TABLE IF NOT EXISTS {table} (id TEXT PRIMARY KEY, data TEXT NOT NULL)")
    from .tag_catalogue import seed_existing
    seed_existing(db)


def ensure_overrides(server):
    legacy = {key: value for key, value in server.get("tags", {}).items() if reserved(key)}
    if legacy:
        server["_legacy_location_tags"] = {**server.get("_legacy_location_tags", {}), **legacy}
    if "_metadata_overrides" not in server:
        override = {"tags": {key: value for key, value in server.get("tags", {}).items() if not reserved(key)}}
        if server.get("location_id") is not None:
            override["location_id"] = server["location_id"]
        server["_metadata_overrides"] = override
    server["_metadata_overrides"].setdefault("tags", {})
    return server["_metadata_overrides"]


def ownership(servers):
    result = {}
    for server in servers:
        for address in server.get("ips", []):
            result.setdefault(address, set()).add(server["id"])
    return result


@lru_cache(maxsize=8192)
def network(value):
    return ipaddress.ip_network(value)


def profile_index(profiles):
    return profiles if isinstance(profiles, dict) else {(profile["ip"] if "ip" in profile else profile["id"]): profile for profile in profiles}


def reconcile_server(server, rules, profiles, owners=None):
    """Resolve trusted central records; never inspect agent-supplied tag fields."""
    fields = ("tags", "location_id", "location_source", "tag_sources", "metadata_conflicts", "_metadata_overrides", "metadata_manual_tag_keys", "metadata_removed_tag_keys", "metadata_manual_location")
    before = digest({key: server.get(key) for key in fields})
    override = ensure_overrides(server)
    profile_map = profile_index(profiles)
    matched = []
    conflicts = []
    for address in server.get("ips", []):
        profile = profile_map.get(address)
        if profile:
            if owners is not None and len(owners.get(address, set())) != 1:
                conflicts.append({"field": "ip", "ip": address, "reason": "IP is reported by multiple enrolled servers; CSV assignment is ambiguous"})
            else:
                matched.append((address, profile))
    tags, tag_sources = {}, {}
    for key in sorted({key for _, profile in matched for key in profile.get("tags", {})}):
        values = {profile["tags"][key] for _, profile in matched if key in profile.get("tags", {})}
        if len(values) == 1:
            tags[key] = values.pop()
            tag_sources[key] = {"type": "csv", "ips": sorted(address for address, profile in matched if key in profile.get("tags", {}))}
        elif key not in override["tags"]:
            conflicts.append({"field": "tag:" + key, "reason": "Different CSV values match this server's IPs"})
    for key, value in override["tags"].items():
        if value is None:
            tags.pop(key, None)
            tag_sources[key] = {"type": "manual", "removed": True}
        else:
            tags[key] = value
            tag_sources[key] = {"type": "manual"}
    if len(tags) > 32:
        # Valid profiles can overlap a valid manual baseline after an IP change.
        # Telemetry must remain writable; withhold the automatic tag layer as a
        # whole instead of choosing an arbitrary 32-key subset or rejecting reports.
        tags = {key: field for key, field in override["tags"].items() if field is not None}
        tag_sources = {key: {"type": "manual", **({"removed": True} if field is None else {})} for key, field in override["tags"].items()}
        conflicts.append({"field": "tags", "reason": "Combined defaults exceed 32 tags; CSV tag defaults are withheld until metadata is resolved"})
    validate_custom_tags(tags)
    location = None
    source = {"type": "unassigned"}
    if "location_id" in override:
        location = override["location_id"]
        source = {"type": "manual", "cleared": location is None}
    else:
        locations = {profile["location_id"] for _, profile in matched if "location_id" in profile}
        if len(locations) == 1:
            location = locations.pop()
            source = {"type": "csv", "ips": sorted(address for address, profile in matched if "location_id" in profile)}
        elif len(locations) > 1:
            source = {"type": "conflict"}
            conflicts.append({"field": "location_id", "reason": "Different CSV locations match this server's IPs"})
        else:
            winners = []
            for address in server.get("ips", []):
                parsed = ipaddress.ip_address(address)
                matches = [rule for rule in rules if parsed.version == network(rule["cidr"]).version and parsed in network(rule["cidr"])]
                if matches:
                    winners.append((address, max(matches, key=lambda rule: network(rule["cidr"]).prefixlen)))
            distinct = {rule["location_id"] for _, rule in winners}
            if len(distinct) == 1:
                location = distinct.pop()
                address, rule = sorted(winners, key=lambda item: (-network(item[1]["cidr"]).prefixlen, item[1]["id"], item[0]))[0]
                source = {"type": "subnet", "rule_id": rule["id"], "cidr": rule["cidr"], "ip": address}
            elif len(distinct) > 1:
                source = {"type": "conflict"}
                conflicts.append({"field": "location_id", "reason": "This server's IPs match different subnet locations", "rule_ids": sorted({rule["id"] for _, rule in winners})})
    server.update({"tags": tags, "location_id": location, "tag_sources": tag_sources,
        "location_source": source, "metadata_conflicts": conflicts,
        "metadata_manual_tag_keys": sorted(override["tags"]),
        "metadata_removed_tag_keys": sorted(key for key, field in override["tags"].items() if field is None),
        "metadata_manual_location": "location_id" in override})
    after = digest({key: server.get(key) for key in fields})
    return before != after


def reconcile_all(store, db):
    servers = store._all(db, "servers")
    rules, profiles = store._all(db, "metadata_subnets"), profile_index(store._all(db, "metadata_ip_profiles"))
    owners, changed = ownership(servers), []
    before = {server["id"]: digest(server) for server in servers}
    for server in servers:
        reconcile_server(server, rules, profiles, owners)
    enforce_location_ownership(servers)
    for server in servers:
        if digest(server) != before[server["id"]]:
            store._put(db, "servers", server)
            changed.append(server["id"])
        conflicts = [row for row in server.get("metadata_conflicts", []) if row.get("field") == "location_id"]
        event_id = "metadata-location-ownership:" + server["id"]
        if conflicts:
            store._event(db, event_id, "metadata_location_conflict", "critical", server["id"],
                         "Endpoint addresses have conflicting DC assignments; automatic grouping is withheld", {"conflicts": conflicts})
        else:
            store._resolve(db, event_id, server["id"], "IP/DC ownership conflict resolved")
    return changed


def enforce_location_ownership(servers):
    """One effective location per reported IP, including manual overrides.

    Duplicate addresses inside the same DC are permitted (for example a VIP).
    Conflicting DC claims are withheld on every owner instead of arbitrarily
    assigning the address to one controller record.
    """
    by_id = {server["id"]: server for server in servers}
    # Evaluate every address against the same claims. Withholding the first
    # collision must not erase evidence needed to detect a second collision.
    claims = {identifier: server.get("location_id") for identifier, server in by_id.items()}
    for address, identifiers in ownership(servers).items():
        locations = {claims[identifier] for identifier in identifiers} - {None}
        if len(locations) <= 1:
            continue
        conflict = {"field": "location_id", "ip": address, "reason": "The same IP cannot belong to different DCs; resolve its conflicting manual or automatic assignments", "server_ids": sorted(identifiers)[:50], "server_count": len(identifiers), "location_ids": sorted(locations)[:50], "location_count": len(locations), "details_truncated": len(identifiers) > 50 or len(locations) > 50}
        for identifier in identifiers:
            server = by_id[identifier]
            server["location_id"] = None
            server["location_source"] = {"type": "conflict"}
            if conflict not in server.setdefault("metadata_conflicts", []):
                server["metadata_conflicts"].append(conflict)


def validate_patch(value):
    if not isinstance(value, dict):
        raise ValueError("Metadata update must be an object")
    if "tags" in value:
        validate_custom_tags(value["tags"])
    updates = value.get("tag_updates", {})
    reset = value.get("reset_tag_keys", [])
    if not isinstance(updates, dict) or len(updates) > 32 or not isinstance(reset, list) or len(reset) > 32:
        raise ValueError("Tag updates and reset keys are limited to 32 entries")
    for key, field in updates.items():
        validate_custom_tags({key: "validation" if field is None else field})
    for key in reset:
        validate_custom_tags({key: "validation"})
    if set(reset) & set(updates):
        raise ValueError("A tag cannot be updated and reset in the same operation")
    if "tags" in value and "tag_updates" in value:
        raise ValueError("Choose a full tags map or tag_updates, not both")
    if value.get("location_mode") not in (None, "manual", "automatic"):
        raise ValueError("location_mode must be manual or automatic")
    if value.get("location_mode") == "automatic" and "location_id" in value:
        raise ValueError("Automatic location mode cannot also pin a location")
    return value


def apply_manual(store, db, server, value, *, excluded_ids=()):
    validate_patch(value)
    override = ensure_overrides(server)
    intended = dict(server.get("tags", {}))
    for key, field in value.get("tag_updates", {}).items():
        if field is None:
            intended.pop(key, None)
        else:
            intended[key] = field
    validate_custom_tags(intended)
    if "tags" in value:
        desired = value["tags"]
        current = server.get("tags", {})
        for key in set(current) | set(desired):
            if current.get(key) != desired.get(key):
                override["tags"][key] = desired.get(key)
    for key, field in value.get("tag_updates", {}).items():
        override["tags"][key] = field
    for key in value.get("reset_tag_keys", []):
        override["tags"].pop(key, None)
    if value.get("location_mode") == "automatic":
        override.pop("location_id", None)
    elif "location_id" in value:
        override["location_id"] = assignment(store, db, value["location_id"])
    elif value.get("location_mode") == "manual":
        override["location_id"] = server.get("location_id")
    server["_metadata_overrides"] = override
    if override.get("location_id") is not None and ("location_id" in value or value.get("location_mode") == "manual"):
        addresses = set(server.get("ips", []))
        for peer in store._all(db, "servers"):
            if peer["id"] != server["id"] and peer["id"] not in excluded_ids and addresses.intersection(peer.get("ips", [])) and peer.get("location_id") not in (None, override["location_id"]):
                raise ValueError("An IP on this server is assigned to another DC; resolve that ownership before changing its location")
    validate_custom_tags({key: field for key, field in override["tags"].items() if field is not None})
    return server


def snapshot(store, db):
    servers = [{key: server.get(key) for key in ("id", "ips", "tags", "location_id", "_metadata_overrides")} for server in store._all(db, "servers")]
    return digest({"servers": sorted(servers, key=lambda row: row["id"]),
        "profiles": sorted(store._all(db, "metadata_ip_profiles"), key=lambda row: row["id"]),
        "subnets": sorted(store._all(db, "metadata_subnets"), key=lambda row: row["id"]),
        "locations": sorted(store._all(db, "locations"), key=lambda row: row["id"])})


def plan(store, db, kind, payload, items, summary, errors=None):
    value = {"id": str(uuid.uuid4()), "kind": kind, "payload": payload, "items": items,
        "summary": summary, "errors": errors or [], "status": "draft", "confirmation_nonce": secrets.token_urlsafe(24),
        "snapshot_digest": snapshot(store, db), "created_at": stamp(), "expires_at": stamp(now() + timedelta(minutes=10))}
    store._put(db, "metadata_plans", value)
    return value


def load_plan(store, db, identifier, body, expected_kind):
    value = store._get(db, "metadata_plans", identifier)
    if value is None:
        raise KeyError(identifier)
    expected = (expected_kind,) if isinstance(expected_kind, str) else expected_kind
    if value["kind"] not in expected or value["status"] != "draft" or value["errors"] or parse_time(value["expires_at"]) <= now():
        raise WorkflowConflict("Metadata preview is expired, invalid or already applied", value)
    if not isinstance(body.get("confirmation_nonce"), str) or not secrets.compare_digest(body["confirmation_nonce"], value["confirmation_nonce"]):
        raise WorkflowConflict("Metadata preview confirmation does not match", value)
    if snapshot(store, db) != value["snapshot_digest"]:
        raise WorkflowConflict("Server metadata, IPs, mappings or locations changed; preview again", value)
    return value


def consume_plan(store, db, value, actor):
    value.update({"status": "applied", "applied_at": stamp(), "applied_by": actor})
    value.pop("confirmation_nonce", None)
    store._put(db, "metadata_plans", value)
    store.audit("metadata." + value["kind"] + ".applied", actor, {"plan_id": value["id"], "summary": value["summary"]}, db)
    return value


def item(before, after):
    fields = ("tags", "location_id")
    return {"server_id": before["id"], "hostname": before.get("hostname", before["id"]), "ips": list(before.get("ips") or []),
        "before": {key: before.get(key) for key in fields}, "after": {key: after.get(key) for key in fields},
        "conflicts": after.get("metadata_conflicts", []), "changed": any(before.get(key) != after.get(key) for key in (*fields, "location_source", "tag_sources")),
        "location_source": after.get("location_source"), "tag_sources": after.get("tag_sources", {})}


def bulk_preview(store, value):
    ids = value.get("server_ids")
    if not isinstance(ids, list) or not ids or len(ids) > 20000 or any(not isinstance(identifier, str) or not identifier or len(identifier) > 100 for identifier in ids):
        raise ValueError("Select explicit server IDs for bulk metadata assignment")
    ids = sorted(set(ids))
    patch = {key: value[key] for key in ("tags", "tag_updates", "reset_tag_keys", "location_id", "location_mode") if key in value}
    validate_patch(patch)
    if not patch:
        raise ValueError("Choose metadata fields to update")
    with store.lock, store.meta() as db:
        servers = store._all(db, "servers")
        selected = {server["id"]: server for server in servers if server["id"] in ids}
        if len(selected) != len(ids):
            raise ValueError("A selected server no longer exists")
        rules, profiles, owners = store._all(db, "metadata_subnets"), profile_index(store._all(db, "metadata_ip_profiles")), ownership(servers)
        prospective = {server["id"]: copy.deepcopy(server) for server in servers}
        for identifier, after in prospective.items():
            if identifier in selected:
                apply_manual(store, db, after, patch, excluded_ids=ids)
            reconcile_server(after, rules, profiles, owners)
        enforce_location_ownership(list(prospective.values()))
        items = [item(selected[identifier], prospective[identifier]) for identifier in ids]
        return plan(store, db, "bulk", {"server_ids": ids, "patch": patch}, items,
            {"matched_servers": len(items), "changed_servers": sum(row["changed"] for row in items)})


def bulk_apply(store, identifier, body, actor):
    with store.lock, store.meta() as db:
        value = load_plan(store, db, identifier, body, "bulk")
        for server_id in value["payload"]["server_ids"]:
            server = store._get(db, "servers", server_id)
            apply_manual(store, db, server, value["payload"]["patch"], excluded_ids=value["payload"]["server_ids"])
            store._put(db, "servers", server)
        reconcile_all(store, db)
        from .tag_catalogue import register
        register(db, ((store._get(db, "servers", identifier) or {}).get("tags", {})
                      for identifier in value["payload"]["server_ids"]), actor, "central_assignment")
        store.compile_all(db)
        return consume_plan(store, db, value, actor)


def subnet_listing(store):
    with store.read_meta() as db:
        rules = store._all(db, "metadata_subnets")
        locations = {location["id"]: location for location in store._all(db, "locations")}
        servers = store._all(db, "servers")
        return [{**rule, "location": locations.get(rule["location_id"]),
            "matched_servers": sum(any(ipaddress.ip_address(address).version == network(rule["cidr"]).version and ipaddress.ip_address(address) in network(rule["cidr"]) for address in server.get("ips", [])) for server in servers)} for rule in sorted(rules, key=lambda rule: rule["cidr"])]


def subnet_preview(store, value, remove_id=None):
    if not isinstance(value, dict):
        raise ValueError("Subnet mapping must be an object")
    if remove_id is not None and (not isinstance(remove_id, str) or not remove_id or len(remove_id) > 100):
        raise ValueError("Invalid subnet mapping identity")
    with store.lock, store.meta() as db:
        rules = store._all(db, "metadata_subnets")
        if remove_id:
            existing = store._get(db, "metadata_subnets", remove_id)
            if existing is None:
                raise KeyError(remove_id)
            prospective = [rule for rule in rules if rule["id"] != remove_id]
            payload, kind = {"rule_id": remove_id, "rule": existing}, "subnet_delete"
        else:
            if not isinstance(value.get("cidr"), str) or len(value["cidr"]) > 100:
                raise ValueError("Provide a subnet CIDR string")
            try:
                network = ipaddress.ip_network(value.get("cidr", ""), strict=False)
            except (ValueError, TypeError):
                raise ValueError("Provide a valid subnet CIDR")
            if network.prefixlen == 0:
                raise ValueError("Subnet mapping must be scoped; /0 is not permitted")
            location_id = assignment(store, db, value.get("location_id"))
            if location_id is None:
                raise ValueError("Select an existing saved location")
            name = value.get("name", "")
            if not isinstance(name, str) or len(name) > 120:
                raise ValueError("Subnet rule name must be at most 120 characters")
            if "id" in value and (not isinstance(value["id"], str) or not value["id"] or len(value["id"]) > 100):
                raise ValueError("Invalid subnet mapping identity")
            identifier = value.get("id") or str(uuid.uuid4())
            existing = store._get(db, "metadata_subnets", identifier)
            if value.get("id") and not existing:
                raise KeyError(identifier)
            if any(rule["id"] != identifier and rule["cidr"] == str(network) for rule in rules):
                raise ValueError("This CIDR already has a mapping; edit the existing rule")
            rule = {"id": identifier, "name": name.strip(), "cidr": str(network), "location_id": location_id,
                "created_at": existing["created_at"] if existing else stamp(), "updated_at": stamp()}
            prospective = [row for row in rules if row["id"] != identifier] + [rule]
            payload, kind = {"rule": rule}, "subnet"
        servers, profiles = store._all(db, "servers"), profile_index(store._all(db, "metadata_ip_profiles"))
        owners, items = ownership(servers), []
        candidates = []
        for before in servers:
            after = copy.deepcopy(before)
            reconcile_server(after, prospective, profiles, owners)
            candidates.append(after)
        enforce_location_ownership(candidates)
        for before, after in zip(servers, candidates):
            if before.get("location_id") != after.get("location_id") or before.get("location_source") != after.get("location_source") or after.get("metadata_conflicts"):
                items.append(item(before, after))
        return plan(store, db, kind, payload, items, {"matched_servers": len(items), "changed_servers": sum(row["changed"] for row in items), "conflicted_servers": sum(bool(row["conflicts"]) for row in items)})


def subnet_apply(store, identifier, body, actor):
    with store.lock, store.meta() as db:
        value = load_plan(store, db, identifier, body, ("subnet", "subnet_delete"))
        if value["kind"] == "subnet":
            store._put(db, "metadata_subnets", value["payload"]["rule"])
        else:
            db.execute("DELETE FROM metadata_subnets WHERE id=?", (value["payload"]["rule_id"],))
        reconcile_all(store, db)
        store.compile_all(db)
        return consume_plan(store, db, value, actor)
