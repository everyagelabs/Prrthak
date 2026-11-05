"""Reviewed exact-IP metadata imports. CSV never changes endpoint identity.

Profiles are central defaults for current or future enrolled addresses. Explicit
manual overrides remain authoritative, and ambiguous address ownership fails
closed before any profile is written.
"""
from __future__ import annotations

import copy
import csv
import io
import ipaddress
import re

from . import metadata
from .locations import reserved, tags as validate_custom_tags
from .store import stamp


MAX_BYTES = 1024 * 1024
MAX_ROWS = 10000
TEMPLATE = "ip,application,dc,network_zone,criticality,tag.owner\n10.241.1.10,billing,Noida 81 DC,production,high,finance\n"


def template():
    return TEMPLATE


def _column(value):
    original = value.strip()
    normalized = re.sub(r"[\s_-]+", "", original.casefold())
    aliases = {
        "ip": "ip", "ipaddress": "ip", "address": "ip",
        "application": "tag:application", "applicationname": "tag:application", "app": "tag:application",
        "dc": "location_id", "dcname": "location_id", "datacenter": "location_id",
        "datacentre": "location_id", "location": "location_id", "locationid": "location_id",
        "locationname": "location_id", "zone": "tag:network_zone", "networkzone": "tag:network_zone",
        "criticality": "tag:criticality", "owner": "tag:owner", "environment": "tag:environment",
        "hostname": "hostname_hint", "servername": "hostname_hint",
    }
    if normalized in aliases:
        return aliases[normalized]
    if original.casefold().startswith("tag."):
        key = original[4:]
        validate_custom_tags({key: "validation"})
        return "tag:" + key
    raise ValueError("Unknown column; use the template or tag.<custom-key>")


def _location_index(locations):
    lookup = {}
    for location in locations:
        for value in (location["id"], location.get("key", ""), location["name"], *location.get("aliases", [])):
            if value:
                lookup.setdefault(value.casefold(), set()).add(location["id"])
    return lookup


def parse_csv(value, locations):
    if not isinstance(value, str):
        raise ValueError("CSV text is required")
    try:
        size = len(value.encode("utf-8"))
    except UnicodeError:
        raise ValueError("CSV must contain valid UTF-8 text") from None
    if size > MAX_BYTES:
        raise ValueError("CSV is limited to 1 MiB")
    if "\0" in value:
        raise ValueError("CSV cannot contain NUL characters")
    errors, warnings, rows = [], [], []
    reader = csv.reader(io.StringIO(value.lstrip("\ufeff"), newline=""), strict=True)
    try:
        headers = next(reader)
    except StopIteration:
        return {"rows": [], "errors": [{"line": 1, "field": "headers", "message": "CSV header row is required"}], "warnings": []}
    except csv.Error:
        return {"rows": [], "errors": [{"line": 1, "field": "csv", "message": "Malformed CSV header"}], "warnings": []}
    columns = []
    for header in headers:
        try:
            column = _column(header)
            if column in columns:
                raise ValueError("Duplicate or equivalent column header")
            columns.append(column)
        except ValueError as error:
            errors.append({"line": 1, "field": header[:128], "message": str(error)})
    if "ip" not in columns:
        errors.append({"line": 1, "field": "ip", "message": "An ip column is required"})
    if errors:
        return {"rows": [], "errors": errors, "warnings": []}
    locations_by_name = _location_index(locations)
    seen, previous_line = set(), reader.line_num
    try:
        for cells in reader:
            line = previous_line + 1
            previous_line = reader.line_num
            if not cells or not any(cell.strip() for cell in cells):
                continue
            if len(rows) >= MAX_ROWS:
                errors.append({"line": line, "field": "csv", "message": "CSV is limited to 10,000 data rows"})
                break
            row = {"line": line, "ip": "", "tags": {}, "warnings": []}
            rows.append(row)
            if len(cells) != len(columns):
                errors.append({"line": line, "field": "csv", "message": "Data column count does not match the header"})
                continue
            values = dict(zip(columns, (cell.strip() for cell in cells)))
            raw_ip = values.pop("ip")
            try:
                if "/" in raw_ip or "%" in raw_ip:
                    raise ValueError()
                address = str(ipaddress.ip_address(raw_ip))
                row["ip"] = address
                if address in seen:
                    raise ValueError("Duplicate IP address in this CSV; combine its metadata into one row")
                seen.add(address)
            except ValueError as error:
                errors.append({"line": line, "field": "ip", "message": str(error) if str(error).startswith("Duplicate") else "Use one numeric IPv4 or IPv6 address, without CIDR or interface scope"})
            for column, field in values.items():
                if not field:
                    continue  # Empty cells never remove a prior/default value.
                try:
                    if column.startswith("tag:"):
                        key = column[4:]
                        validate_custom_tags({key: field})
                        row["tags"][key] = field
                    elif column == "location_id":
                        matches = locations_by_name.get(field.casefold(), set())
                        if len(matches) != 1:
                            raise ValueError("Create this DC/location in the catalogue first, or use its exact saved ID")
                        row["location_id"] = next(iter(matches))
                    elif column == "hostname_hint":
                        if len(field) > 253:
                            raise ValueError("Hostname hint is limited to 253 characters")
                        row["hostname_hint"] = field
                        row["warnings"].append("CSV hostname is informational; agent-reported hostname is preserved")
                except ValueError as error:
                    errors.append({"line": line, "field": column, "message": str(error)})
            try:
                validate_custom_tags(row["tags"])
            except ValueError as error:
                errors.append({"line": line, "field": "tags", "message": str(error)})
            if not row["tags"] and "location_id" not in row:
                errors.append({"line": line, "field": "metadata", "message": "Provide at least one nonblank tag or saved DC; hostname is informational only"})
    except csv.Error:
        errors.append({"line": max(2, reader.line_num), "field": "csv", "message": "Malformed CSV quoting or an oversized field"})
    if not rows and not errors:
        errors.append({"line": 2, "field": "csv", "message": "At least one data row is required"})
    return {"rows": rows, "errors": errors, "warnings": warnings}


def _state(server):
    return {"server_id": server["id"], **{key: copy.deepcopy(server.get(key)) for key in (
        "id", "hostname", "tags", "location_id", "location_source", "tag_sources", "metadata_conflicts")}}


def _changed(before, after):
    return any(before.get(key) != after.get(key) for key in (
        "tags", "location_id", "location_source", "tag_sources", "metadata_conflicts"))


def _response(value):
    result = {key: copy.deepcopy(field) for key, field in value.items() if key not in ("payload", "items")}
    result["rows"] = copy.deepcopy(value["items"])
    return result


def listing(store, limit=100, offset=0):
    if type(limit) is not int or not 1 <= limit <= 500 or type(offset) is not int or offset < 0:
        raise ValueError("Profile pagination needs a limit from 1 to 500 and a nonnegative offset")
    with store.read_meta() as db:
        profiles = sorted(store._all(db, "metadata_ip_profiles"), key=lambda profile: (
            ipaddress.ip_address(profile["ip"]).version, int(ipaddress.ip_address(profile["ip"]))))
        owners = metadata.ownership(store._all(db, "servers"))
        items = []
        for profile in profiles[offset:offset + limit]:
            identifiers = sorted(owners.get(profile["ip"], set()))
            items.append({**profile, "server_ids": identifiers, "server_count": len(identifiers),
                "binding_status": "conflict" if len(identifiers) > 1 else "current" if identifiers else "future"})
        return {"items": items, "total": len(profiles), "limit": limit, "offset": offset}


def delete_preview(store, address, actor):
    if not isinstance(address, str) or "/" in address or "%" in address:
        raise ValueError("Use one numeric IPv4 or IPv6 address, without CIDR or interface scope")
    try:
        address = str(ipaddress.ip_address(address))
    except ValueError:
        raise ValueError("Use one numeric IPv4 or IPv6 address, without CIDR or interface scope") from None
    with store.lock, store.meta() as db:
        profile = store._get(db, "metadata_ip_profiles", address)
        if profile is None:
            raise KeyError(address)
        servers = store._all(db, "servers")
        owners = metadata.ownership(servers)
        identifiers = owners.get(address, set())
        rules = store._all(db, "metadata_subnets")
        profiles = {record["id"]: record for record in store._all(db, "metadata_ip_profiles") if record["id"] != address}
        rows, changed = [], 0
        for before in sorted((server for server in servers if server["id"] in identifiers), key=lambda server: server["id"]):
            after = copy.deepcopy(before)
            metadata.reconcile_server(after, rules, profiles, owners)
            overrides = metadata.ensure_overrides(copy.deepcopy(before))
            overridden = [key for key in profile.get("tags", {}) if key in overrides["tags"]]
            if "location_id" in profile and "location_id" in overrides:
                overridden.append("location_id")
            different = _changed(before, after)
            changed += different
            warnings = ["Manual overrides are preserved; remaining exact-IP defaults and subnet DC mappings apply"]
            warnings.extend(conflict.get("reason", "Metadata needs review") for conflict in after.get("metadata_conflicts", []))
            rows.append({"line": len(rows) + 1, "ip": address, "status": "ready" if different else "unchanged",
                "server_ids": [before["id"]], "before": _state(before), "after": _state(after),
                "profile_before": profile, "profile_after": None, "overridden_fields": overridden, "warnings": warnings})
        if not rows:
            rows.append({"line": 1, "ip": address, "status": "future", "server_ids": [], "before": None, "after": None,
                "profile_before": profile, "profile_after": None, "overridden_fields": [],
                "warnings": ["The pending exact-IP profile will be removed; future servers use manual assignments or subnet DC mappings"]})
        summary = {"rows": len(rows), "profiles": 1, "current_servers": len(identifiers), "future_ips": int(not identifiers),
            "changed_servers": changed, "overridden_fields": sum(len(row["overridden_fields"]) for row in rows)}
        value = metadata.plan(store, db, "csv_profile_delete", {"ip": address}, rows, summary)
        store.audit("metadata.csv_profile_delete.previewed", actor, {"plan_id": value["id"], "ip": address, "summary": summary}, db)
        return _response(value)


def preview(store, value, actor):
    if not isinstance(value, dict):
        raise ValueError("CSV preview must be a JSON object")
    with store.lock, store.meta() as db:
        parsed = parse_csv(value.get("csv"), store._all(db, "locations"))
        servers = store._all(db, "servers")
        by_id = {server["id"]: server for server in servers}
        owners = metadata.ownership(servers)
        rules = store._all(db, "metadata_subnets")
        old_profiles = {profile["id"]: profile for profile in store._all(db, "metadata_ip_profiles")}
        profiles = copy.deepcopy(old_profiles)
        errors = parsed["errors"]
        invalid_lines = {error["line"] for error in errors}
        updates = {}
        for row in parsed["rows"]:
            if row["line"] in invalid_lines or not row["ip"]:
                continue
            old = profiles.get(row["ip"], {"id": row["ip"], "ip": row["ip"], "tags": {}})
            profile = copy.deepcopy(old)
            profile.setdefault("tags", {}).update(row["tags"])
            if "location_id" in row:
                profile["location_id"] = row["location_id"]
            if row.get("hostname_hint"):
                profile["hostname_hint"] = row["hostname_hint"]
            try:
                validate_custom_tags(profile["tags"])
            except ValueError as error:
                errors.append({"line": row["line"], "field": "tags", "message": str(error)})
                continue
            if profile["tags"] or "location_id" in profile:
                profiles[row["ip"]] = profile
                updates[row["ip"]] = profile
        after_by_id = {}
        affected_ids = {identifier for address in updates for identifier in owners.get(address, set())}
        for identifier in affected_ids:
            after = copy.deepcopy(by_id[identifier])
            try:
                metadata.reconcile_server(after, rules, profiles, owners)
                after_by_id[identifier] = after
            except ValueError as error:
                for row in parsed["rows"]:
                    if identifier in owners.get(row["ip"], set()):
                        errors.append({"line": row["line"], "field": "metadata", "message": str(error)})
        rows, changed, matched, future = [], set(), set(), set()
        for row in parsed["rows"]:
            result = copy.deepcopy(row)
            identifiers = sorted(owners.get(row["ip"], set()))
            matched.update(identifiers)
            result.update({"server_ids": identifiers, "before": None, "after": None,
                "overridden_fields": [], "profile_before": old_profiles.get(row["ip"]),
                "profile_after": profiles.get(row["ip"])})
            if len(identifiers) > 1:
                errors.append({"line": row["line"], "field": "ip", "message": "IP is reported by multiple enrolled servers; resolve ownership before importing"})
            elif identifiers:
                identifier = identifiers[0]
                before, after = by_id[identifier], after_by_id.get(identifier, by_id[identifier])
                result["before"], result["after"] = _state(before), _state(after)
                overrides = metadata.ensure_overrides(copy.deepcopy(before))
                result["overridden_fields"] = [key for key in row["tags"] if key in overrides["tags"]]
                if "location_id" in row and "location_id" in overrides:
                    result["overridden_fields"].append("location_id")
                if result["overridden_fields"]:
                    result["warnings"].append("Manual overrides retained for: " + ", ".join(result["overridden_fields"]))
                for conflict in after.get("metadata_conflicts", []):
                    field = conflict.get("field", "metadata")
                    resolved = field.startswith("tag:") and field[4:] in overrides["tags"]
                    if resolved:
                        result["warnings"].append("Conflicting CSV defaults are superseded by a manual override")
                    else:
                        errors.append({"line": row["line"], "field": field, "message": conflict.get("reason", "Ambiguous metadata assignment")})
                if _changed(before, after):
                    changed.add(identifier)
            elif row["ip"] in updates:
                future.add(row["ip"])
            result["status"] = ("invalid" if any(error["line"] == row["line"] for error in errors) else
                "future" if not identifiers and row["ip"] in updates else
                "ready" if identifiers and identifiers[0] in changed else
                "overridden" if result["overridden_fields"] else "unchanged")
            rows.append(result)
        # A later row can reveal a conflict shared with an earlier row.
        invalid_lines = {error["line"] for error in errors}
        for row in rows:
            if row["line"] in invalid_lines:
                row["status"] = "invalid"
        summary = {"rows": len(rows), "current_servers": len(matched), "future_ips": len(future),
            "changed_servers": len(changed), "overridden_fields": sum(len(row["overridden_fields"]) for row in rows)}
        value = metadata.plan(store, db, "csv_import", {"profiles": list(updates.values())}, rows, summary, errors)
        value["warnings"] = parsed["warnings"]
        if errors:
            value["status"] = "invalid"
            value.pop("confirmation_nonce", None)
        store._put(db, "metadata_plans", value)
        store.audit("metadata.csv_import.previewed", actor, {"plan_id": value["id"], "summary": summary, "errors": len(errors)}, db)
        return _response(value)


def apply(store, identifier, value, actor):
    with store.lock, store.meta() as db:
        plan = metadata.load_plan(store, db, identifier, value, ("csv_import", "csv_profile_delete"))
        if plan["kind"] == "csv_profile_delete":
            db.execute("DELETE FROM metadata_ip_profiles WHERE id=?", (plan["payload"]["ip"],))
        else:
            for profile in plan["payload"]["profiles"]:
                store._put(db, "metadata_ip_profiles", {**profile, "updated_at": stamp(), "updated_by": actor})
            from .tag_catalogue import register
            register(db, (profile.get("tags", {}) for profile in plan["payload"]["profiles"]), actor, "csv_assignment")
        metadata.reconcile_all(store, db)
        store.compile_all(db)
        metadata.consume_plan(store, db, plan, actor)
        return _response(plan)
