"""Administrator-created location identities, independent of arbitrary server tags."""
import uuid

from .store import now, parse_time, stamp, validate_tags


RESERVED = frozenset({"dc", "dc_id", "datacenter", "datacenter_id", "data_center", "data_centre", "location", "location_id", "location_type"})
LOCATION_ALIASES = RESERVED - {"location_type"}


def reserved(key):
    return key.casefold().replace("-", "_") in RESERVED


def initialize(db):
    db.execute("CREATE TABLE IF NOT EXISTS locations (id TEXT PRIMARY KEY, data TEXT NOT NULL)")


def tags(value):
    value = validate_tags(value)
    if any(reserved(key) for key in value):
        raise ValueError("DC/location tags are reserved; create a location first and assign its location_id separately")
    return value


def index(records):
    result = {}
    for record in records:
        for alias in [record["id"], record["key"], record["name"], *record.get("aliases", [])]:
            result[alias.casefold()] = record["id"]
    return result


def selector(value, records, strict=True):
    """Legacy aliases bind to a catalogue identity; unknown legacy values never match all."""
    result, chosen = {}, None
    lookup = index(records)
    for key, val in value.items():
        normalized = key.casefold().replace("-", "_")
        if normalized in LOCATION_ALIASES:
            selected = lookup.get(val.casefold())
            # Canonical selectors must name an actual UUID identity, rather than a
            # name which might later be reused in another catalogue.
            if normalized == "location_id":
                selected = val if any(record["id"] == val for record in records) else None
            if not selected or (chosen is not None and chosen != selected):
                if strict:
                    raise ValueError("Location selector must resolve to one existing catalogue location_id")
                return {**{key: val for key, val in value.items() if not reserved(key)}, "location_id": "__unknown_location__"}
            chosen = selected
        elif normalized == "location_type":
            if strict:
                raise ValueError("Use a saved location_id for location selection")
            return {"location_id": "__unknown_location__"}
        else:
            result[key] = val
    if chosen is not None:
        result["location_id"] = chosen
    return result


def assignment(store, db, identifier):
    if identifier is None:
        return None
    if not isinstance(identifier, str) or len(identifier) > 100 or not store._get(db, "locations", identifier):
        raise ValueError("Create the location catalogue record before assigning its location_id")
    return identifier


def decorate(server, records):
    locations = {record["id"]: record for record in records}
    legacy = {**server.get("_legacy_location_tags", {}), **{key: val for key, val in server.get("tags", {}).items() if reserved(key)}}
    identifier = server.get("location_id")
    return {**server, "location_id": identifier, "location": locations.get(identifier), "legacy_location_tags": legacy, "location_migration_candidates": legacy if not identifier else {}}


def listing(store):
    from .inventory_views import server_rows
    with store.read_meta() as db:
        counts = {}
        for server in server_rows(db):
            identifier = server.get("location_id")
            counts[identifier] = counts.get(identifier, 0) + 1
        return sorted(({**record, "server_count": counts.get(record["id"], 0)} for record in store._all(db, "locations")), key=lambda item: item["name"].casefold())


def save(store, value, actor, identifier=None):
    if not isinstance(value, dict):
        raise ValueError("Location must be an object")
    name, place, kind = value.get("name"), value.get("location"), value.get("type")
    if not isinstance(name, str) or not name.strip() or len(name) > 120:
        raise ValueError("Location name is required (max 120 characters)")
    if not isinstance(place, str) or not place.strip() or len(place) > 200:
        raise ValueError("Geographic location is required (max 200 characters)")
    if kind not in ("datacenter", "cloud"):
        raise ValueError("Location type must be datacenter or cloud")
    for field in ("provider", "region"):
        if not isinstance(value.get(field, ""), str) or len(value.get(field, "")) > 120:
            raise ValueError("Invalid location " + field)
    with store.lock, store.meta() as db:
        old = store._get(db, "locations", identifier) if identifier else None
        if identifier and not old:
            raise KeyError(identifier)
        if old and any(field in value and value[field] != old[field] for field in ("id", "key")):
            raise ValueError("Location identity and canonical key are immutable")
        identifier = identifier or str(uuid.uuid4())
        aliases = sorted(set([name.strip(), *(old.get("aliases", []) if old else []), *([old["name"]] if old else [])]))
        for record in store._all(db, "locations"):
            if record["id"] != identifier and set(index([record])) & {alias.casefold() for alias in aliases}:
                raise ValueError("Location name is already assigned or reserved by a historical name")
        result = {"id": identifier, "key": old["key"] if old else "location:" + identifier, "name": name.strip(), "location": place.strip(), "type": kind, "provider": value.get("provider", "").strip(), "region": value.get("region", "").strip(), "aliases": aliases, "created_at": old["created_at"] if old else stamp(), "updated_at": stamp()}
        if old and old.get("synthetic"):
            result["synthetic"] = True
        store._put(db, "locations", result)
        store.compile_all(db)
        store.audit("location.updated" if old else "location.created", actor, {"location_id": identifier, "name": result["name"], "type": kind}, db)
        return result


def delete(store, identifier, actor):
    with store.lock, store.meta() as db:
        record = store._get(db, "locations", identifier)
        if not record:
            raise KeyError(identifier)
        if any(server.get("location_id") == identifier for server in store._all(db, "servers")):
            raise ValueError("Location is assigned to servers; reassign or clear them before deleting")
        if any(rule.get("location_id") == identifier for rule in store._all(db, "metadata_subnets")):
            raise ValueError("Location is referenced by a subnet mapping; remove the mapping first")
        if any(profile.get("location_id") == identifier for profile in store._all(db, "metadata_ip_profiles")):
            raise ValueError("Location is referenced by an IP/CSV profile; update the profile first")
        records = store._all(db, "locations")
        for policy in store._all(db, "policies"):
            selectors = [policy.get("selector", {}), *(service.get("source_selector", {}) for service in policy.get("services", []))]
            if any(selector(value, records, strict=False).get("location_id") == identifier for value in selectors):
                raise ValueError("Location is referenced by an active policy")
        if any(selector(group.get("selector", {}), records, strict=False).get("location_id") == identifier for group in store._all(db, "groups")):
            raise ValueError("Location is referenced by a saved group")
        db.execute("DELETE FROM locations WHERE id=?", (identifier,))
        store.audit("location.deleted", actor, {"location_id": identifier, "name": record["name"]}, db)
