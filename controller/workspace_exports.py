"""Complete, scoped CSV exports of the inventory and policy catalogue."""
from contextlib import closing, contextmanager
import csv
from functools import lru_cache
import io
import json
import tempfile

from . import firewall_views, policy_views
from .evidence_views import EXPORT_SLOTS, MAX_EXPORT_BYTES, ExportBusy, csv_values
from .inventory_views import canonical_servers, endpoint_labels

MAX_EXPORT_ROWS = 250000
SERVER_FIELDS = (
    "endpoint_id", "hostname", "agent_reported_ips", "os", "os_version",
    "location", "tags", "status", "last_seen", "listening_port", "protocol",
    "bind_address", "service", "process",
)
POLICY_FIELDS = (
    "policy_id", "policy_name", "origin", "revision", "action", "status",
    "source", "source_tags", "source_group_ids", "destination_scope",
    "destination_endpoint_ids", "destination_hostnames", "destination_reported_ips", "destination_tags",
    "destination_group_ids", "destination_port", "protocol", "service_group",
)
DISCOVERED_FIELDS = (
    "rule_id", "source", "destination", "destination_endpoint_id",
    "destination_hostname", "destination_reported_ips", "destination_port",
    "zone", "action", "zone_use", "configuration", "snapshot_status",
)


def _server_rows(store, value):
    if not isinstance(value, dict) or set(value) != {"server_ids"} or value["server_ids"] is None:
        raise ValueError("Provide the exact inventory export scope")
    selected = firewall_views.options(value)["server_ids"]
    if not selected:
        return
    for server in store.servers():
        if server["id"] not in selected:
            continue
        common = {
            "endpoint_id": server["id"],
            "hostname": server["hostname"],
            "agent_reported_ips": "; ".join(server.get("ips", [])),
            "os": server.get("os"),
            "os_version": server.get("os_version"),
            "location": (server.get("location") or {}).get("name"),
            "tags": json.dumps(server.get("tags", {}), ensure_ascii=False, sort_keys=True),
            "status": server.get("status"),
            "last_seen": server.get("last_seen"),
        }
        for listener in server.get("listeners") or [{}]:
            yield {
                **common,
                "listening_port": listener.get("port"),
                "protocol": listener.get("protocol"),
                "bind_address": listener.get("address"),
                "service": listener.get("service"),
                "process": listener.get("process"),
            }


def _configured_rows(store, db, kind, value):
    value, scope, search_ids = policy_views.scope_options(kind, value)
    destinations = endpoint_labels(db)
    selected_ports = set(value["ports"])
    with closing(policy_views.matching_headers(store, db, kind, value, scope, search_ids)) as identifiers:
        for identifier in identifiers:
            policy = policy_views.exact_detail(db, kind, identifier)
            endpoint_ids = policy.get("endpoint_ids") or ([policy["server_id"]] if kind == "learned" else [])
            endpoint_details = [destinations.get(item, (item, "")) for item in endpoint_ids]
            target_groups = policy.get("group_ids", [])
            target_tags = policy.get("selector", {})
            scope_type = "endpoint" if endpoint_ids else "server_group" if target_groups else "tags_or_location" if target_tags else "all_endpoints"
            common = {
                "policy_id": identifier,
                "policy_name": policy.get("name"),
                "origin": policy.get("origin", kind),
                "revision": policy.get("revision"),
                "action": "allow",
                "status": policy.get("status") if kind == "learned" else policy.get("mode"),
                "destination_scope": scope_type,
                "destination_endpoint_ids": "; ".join(endpoint_ids),
                "destination_hostnames": "; ".join(hostname for hostname, _ in endpoint_details),
                "destination_reported_ips": "; ".join(addresses for _, addresses in endpoint_details if addresses),
                "destination_tags": json.dumps(target_tags, ensure_ascii=False, sort_keys=True) if target_tags else "",
                "destination_group_ids": "; ".join(target_groups),
            }
            for service in policy.get("services", []):
                service_group = service.get("service_group_snapshot") or {}
                source_tags = service.get("source_selector", {})
                source_groups = service.get("source_group_ids", [])
                for entry in service_group.get("ports", []) if service.get("service_group_id") else [service]:
                    port = entry["port"]
                    protocol = entry.get("protocol", "tcp")
                    if selected_ports and str(port) not in selected_ports and f"{port}/{protocol}" not in selected_ports:
                        continue
                    for source in service["sources"] or [""]:
                        yield {
                            **common, "source": source,
                            "source_tags": json.dumps(source_tags, ensure_ascii=False, sort_keys=True) if source_tags else "",
                            "source_group_ids": "; ".join(source_groups),
                            "destination_port": port, "protocol": protocol,
                            "service_group": service_group.get("name"),
                        }


def _discovered_rows(db, value):
    from .firewall import snapshot_view

    value = firewall_views.options({**value, "view": "access"})
    describe = lru_cache(maxsize=512)(firewall_views.access_description)
    with closing(canonical_servers(db, value["server_ids"])) as servers:
        for server in servers:
            snapshot = snapshot_view(server)
            for key, _, rules, usage in firewall_views.matching_rules(
                snapshot, server["id"], value["ports"], value["search"],
                value["search_server_ids"], describe, value["zone_usage"],
            ):
                for rule in rules:
                    ports = rule.get("ports", [])
                    fields = firewall_views.access_fields({
                        "ports": ports, "action": rule["action"], "_zone_usage": {usage: 1},
                        "port_resolution": "consistent" if ports else "unresolved",
                    }, describe(rule["kind"], rule["value"]))
                    yield {
                        "rule_id": key,
                        "source": fields["source"],
                        "destination": fields["destination"],
                        "destination_endpoint_id": server["id"],
                        "destination_hostname": server["hostname"],
                        "destination_reported_ips": "; ".join(server.get("ips", [])),
                        "destination_port": fields["destination_port"],
                        "zone": rule.get("zone"),
                        "action": fields["decision"],
                        "zone_use": usage,
                        "configuration": rule["scope"],
                        "snapshot_status": "stale" if snapshot.get("stale") else snapshot.get("status"),
                    }


@contextmanager
def csv_spool(store, resource, value):
    if not isinstance(value, dict) or {"limit", "offset", "after"} & value.keys():
        raise ValueError("CSV export requires an unpaginated scope")
    if resource == "servers":
        fields = SERVER_FIELDS
    elif resource == "policies":
        value = dict(value)
        kind = value.pop("kind", None)
        if kind not in ("managed", "learned", "discovered"):
            raise ValueError("Choose managed, learned or discovered policies to export")
        fields = DISCOVERED_FIELDS if kind == "discovered" else POLICY_FIELDS
        if kind == "discovered" and set(value) - {"server_ids", "search_server_ids", "ports", "search", "zone_usage"}:
            raise ValueError("Provide a supported discovered policy scope")
    else:
        raise ValueError("Unsupported CSV export")

    if not EXPORT_SLOTS.acquire(blocking=False):
        raise ExportBusy("CSV export capacity is busy; retry shortly")
    try:
        with tempfile.TemporaryFile(mode="w+b", dir=getattr(store, "path", None)) as output:
            output.write(b"\xef\xbb\xbf")

            def write(values):
                line = io.StringIO(newline="")
                csv.writer(line).writerow(values)
                raw = line.getvalue().encode("utf-8")
                if output.tell() + len(raw) > MAX_EXPORT_BYTES:
                    raise ValueError("Complete CSV exceeds 64 MiB; narrow the scope and try again")
                output.write(raw)

            def write_rows(records):
                with closing(records):
                    for number, row in enumerate(records, 1):
                        if number > MAX_EXPORT_ROWS:
                            raise ValueError("Complete CSV exceeds 250,000 rows; narrow the scope and try again")
                        write(csv_values(row, fields))

            write(fields)
            if resource == "servers":
                write_rows(_server_rows(store, value))
            else:
                with store.read_meta() as db:
                    if getattr(db, "dialect", "sqlite") == "sqlite":
                        db.execute("BEGIN")
                    records = _discovered_rows(db, value) if kind == "discovered" else _configured_rows(store, db, kind, value)
                    write_rows(records)
            size = output.tell()
            output.flush()
            output.seek(0)
            yield output, size
    finally:
        EXPORT_SLOTS.release()
