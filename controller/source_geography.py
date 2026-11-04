"""Attribute overview traffic sources using locally managed inventory only."""

import json

from .inventory_views import rows
from .metadata import network
from .network_addresses import address as native_address


def endpoint_locations(db):
    fields = ("ips", "location_id", "location_source")
    if getattr(db, "dialect", "sqlite") == "postgresql":
        columns = ", ".join(f"(document->'{field}')::text" for field in fields)
        source = "servers CROSS JOIN LATERAL (SELECT data::jsonb AS document OFFSET 0) projected"
    else:
        columns = ", ".join(f"json_quote(json_extract(data,'$.{field}'))" for field in fields)
        source = "servers"
    for row in rows(db, f"SELECT {columns} FROM {source}", batch_size=128):
        yield {field: json.loads(value) for field, value in zip(fields, row) if value is not None}


def _subnet_locations(rules):
    by_family = {4: {}, 6: {}}
    for rule in rules:
        subnet = network(rule["cidr"])
        shift = subnet.max_prefixlen - subnet.prefixlen
        prefixes = by_family[subnet.version].setdefault(shift, {})
        prefixes.setdefault(int(subnet.network_address) >> shift, set()).add(rule["location_id"])
    return {family: sorted(prefixes.items()) for family, prefixes in by_family.items()}


def annotate(flows, servers, locations, load_subnets):
    """Use exact ownership first, then the most specific configured internal subnet."""
    if not flows:
        return flows

    location_ids = {location["id"] for location in locations}
    sources = {}
    for source in {flow["source_ip"] for flow in flows}:
        try:
            sources[source] = native_address(source)
        except ValueError:
            # Older traffic records can use address formats inventory rejects.
            sources[source] = None

    claims = {str(address): set() for address in sources.values() if address is not None}
    ambiguous = set()
    for server in servers:
        evidence = server.get("location_source") or {}
        for ip in server.get("ips") or ():
            if ip in claims:
                claims[ip].add(server.get("location_id"))
                if evidence.get("type") == "conflict" or evidence.get("cleared"):
                    ambiguous.add(ip)

    origins = {}
    subnet_locations = None
    for source, address in sources.items():
        internal = address is not None and not address.is_global
        origins[source] = {"kind": "private" if internal else "external"}
        ip = str(address)
        owners = claims.get(ip, ())
        if ip in ambiguous or len(owners) > 1:
            continue
        location_id = next(iter(owners), None)
        if location_id is None and internal:
            if subnet_locations is None:
                subnet_locations = _subnet_locations(load_subnets())
            ip_number = int(address)
            for shift, prefixes in subnet_locations[address.version]:
                match = prefixes.get(ip_number >> shift)
                if match:
                    # Conflicting most-specific entries must not fall back to a broader site.
                    if len(match) == 1:
                        location_id = next(iter(match))
                    break
        if location_id in location_ids:
            origins[source] = {"kind": "location", "location_id": location_id}

    return [{**flow, "source_origin": origins[flow["source_ip"]]} for flow in flows]
