"""Read-only endpoint rules backed by installation receipts or runtime inventory."""
from collections import Counter, defaultdict
from itertools import islice
import json

from .approval_views import _expression
from .managed_views import _current_evidence, identifier, snapshot


MAX_ATTRIBUTION_BYTES = 64 * 1024
SOURCES_PER_ROW = 100
SECTIONS = ("managed", "learned", "discovered")


def freeze_contributors(rows):
    """Keep optional historical attribution separate from signed effective rules."""
    counts = Counter((port["protocol"], port["port"]) for row in rows for port in row["ports"])
    frozen = []
    size = 0
    for row in rows:
        if all(counts[port["protocol"], port["port"]] == 1 for port in row["ports"]):
            row = {**row, "sources": None}  # The effective service already stores the exact sources.
        size += len(json.dumps(row)) + 2
        if size > MAX_ATTRIBUTION_BYTES:
            return None
        frozen.append(row)
    return frozen


def _bundle(db, server_id, version, digest):
    row = db.execute("SELECT data FROM bundle_history WHERE server_id=? AND version=? AND digest=?", (server_id, version, digest)).fetchone()
    return json.loads(row[0]) if row else None


def _installed_receipt(db, server_id, version):
    status = _expression(db, ("status",))
    row = db.execute("SELECT data FROM managed_outcomes WHERE server_id=? AND version=? AND " + status + "='enforced' AND "
                     + _current_evidence(db) + " ORDER BY created_at DESC,id DESC LIMIT 1", (server_id, version)).fetchone()
    return json.loads(row[0]) if row else {}


def _section(state, rows=(), *, observed_at=None, version=None, reason=None):
    return {"state": state, "rows": rows, "observed_at": observed_at, "version": version, "reason": reason}


def _row(name, destination_port, sources, *, action="allow", protocol=None, groups=(), policy_id=None, zone=None, **extra):
    return {"policy_name": name, "policy_id": policy_id, "destination_port": destination_port, "protocol": protocol,
            "sources": list(sources), "source_groups": list(groups), "action": action, "zone": zone, **extra}


def _port_row(name, service, sources, **kwargs):
    return _row(name, f"{service['port']}/{service['protocol']}", sources, protocol=service["protocol"], **kwargs)


def _runtime_known(store, server):
    return (server.get("firewalld_state") in ("running", "active") and bool(server.get("last_seen"))
            and not store._heartbeat_stale(server) and not server.get("recovery_reconciliation_required")
            and not server.get("recovery_unverified_outcome"))


def _managed(db, server, runtime_known):
    receipt = server.get("managed_enforcement") or {}
    version, digest = server.get("_last_managed_applied_version"), server.get("last_good_digest")
    if not version:
        return _section("unverified" if receipt and receipt.get("status") not in ("preview", "pending_approval", "rolled_back") else "none",
                        reason="No applied managed policy is confirmed for this endpoint.")
    bundle = _bundle(db, server["id"], version, digest)
    if not bundle:
        return _section("unverified", version=version, reason="The exact applied bundle could not be matched to immutable history.")
    approvals = db.execute("SELECT protection_digest FROM managed_approvals WHERE server_id=? AND version=? AND digest=?",
                           (server["id"], version, digest)).fetchall()
    if not approvals:
        return _section("unverified", version=version, reason="The reported bundle has no matching historical authorization.")
    active = server.get("_managed_rules_active") is True
    outcome_matches = ((receipt.get("status") == "enforced" and receipt.get("version") == version and receipt.get("digest") == digest)
                       or (receipt.get("status") == "rolled_back" and receipt.get("last_good_version") == version and receipt.get("last_good_digest") == digest))
    confirmed = runtime_known and outcome_matches and server.get("apply_status") != "error"
    recorded = receipt if outcome_matches else _installed_receipt(db, server["id"], version)
    observed_at = recorded.get("verification_readback_at") or recorded.get("updated_at")
    if outcome_matches and server.get("_managed_rules_active") is False:
        return _section("none", observed_at=observed_at, version=version, reason="The agent reported that managed rules were removed.")
    if not active:
        return _section("unverified", observed_at=observed_at, version=version, reason="The endpoint has no confirmed active managed rules.")

    protection = server.get("protection") or {}
    # A rollback receipt refers to the failed attempt's protection. It cannot
    # attribute the retained SSH/zone context unless every binding agrees.
    protection_digests = {row[0] for row in approvals}
    if recorded.get("status") == "enforced":
        protection_digests = {recorded.get("protection_digest")} & protection_digests
    if protection_digests != {protection.get("digest")}:
        protection = {}
    confirmed = confirmed and bool(protection)
    if receipt.get("status") == "enforced":
        confirmed = confirmed and receipt.get("approved_ips") == sorted(server.get("ips", []))
    zone = protection.get("zone")
    ssh_ports = set(protection.get("ssh_ports", ()))
    management_sources = protection.get("management_sources", [])
    host_deny = bundle.get("host_default_deny") is True
    # Removal changes only the global fallbacks. The remaining SSH/control
    # accepts and any older per-port rejects depend on the prior live plan.
    # Use the runtime inventory for those rules when the prior plan is unknown.
    removed_host_deny = recorded.get("intent") == "remove_host_default_deny" and recorded.get("status") == "enforced"
    contributors = defaultdict(list)
    for item in bundle.get("policy_contributors", []):
        for port in item["ports"]:
            contributors[port["protocol"], port["port"]].append(item)

    rows = []
    covered_ssh_ports = set()
    for service in bundle["services"]:
        if service.get("mode", bundle["mode"]) != "enforce":
            continue
        key = service["protocol"], service["port"]
        sources = set(service["sources"])
        attributed = [(item, service["sources"] if item["sources"] is None else item["sources"]) for item in contributors[key]]
        if attributed and set().union(*(set(addresses) for _, addresses in attributed)) == sources:
            for item, addresses in attributed:
                rows.append(_port_row(item["policy_name"], service, addresses, groups=item["source_groups"],
                                      policy_id=item["policy_id"], zone=zone))
        elif sources:
            rows.append(_port_row("Managed bundle", service, service["sources"], zone=zone,
                                  note="Policy names were not recorded for this bundle version."))
        if key[0] == "tcp" and key[1] in ssh_ports and management_sources:
            covered_ssh_ports.add(key[1])
            rows.append(_port_row("Protected SSH access", service, management_sources, zone=zone))
        if not host_deny and not removed_host_deny:
            rows.append(_port_row("Managed port fallback", service, ["Sources not matched by earlier allow rules"], action="deny", zone=zone))

    if host_deny:
        for port in sorted(ssh_ports - covered_ssh_ports):
            if management_sources:
                rows.append(_port_row("Protected SSH access", {"port": port, "protocol": "tcp"}, management_sources, zone=zone))
        for family, port, protocol, cidr in (("IPv4", 68, "ICMP", "0.0.0.0/0"), ("IPv6", 546, "IPv6 ICMP", "::/0")):
            rows.append(_port_row(f"{family} DHCP client exception", {"port": port, "protocol": "udp"}, [cidr], zone=zone))
            rows.append(_row("Network control exception", protocol, [cidr], zone=zone))
    if host_deny:
        rows.append(_row("Whole-server default deny", "Other inbound traffic", ["Sources not matched by earlier allow rules"], action="deny", zone=zone))

    notes = []
    if not confirmed:
        notes.append("Showing the last confirmed bundle. Current runtime enforcement has not been confirmed.")
    if not protection:
        notes.append("The exact historical zone and protected SSH source list are unavailable.")
    if removed_host_deny:
        notes.append("After removal of whole-server default deny, see Reported firewall rules for retained SSH, control and fallback rules.")
    return _section("confirmed" if confirmed else "last_confirmed", rows, observed_at=observed_at, version=version,
                    reason=" ".join(notes) or None)


def _learned(store, db, server, runtime_known):
    from .learning_policies import _bindings, _triples

    receipt = server.get("learning_allow_outcome") or {}
    generation, digest = receipt.get("applied_generation"), receipt.get("applied_digest")
    if not generation:
        state = "unverified" if receipt.get("status") in ("blocked", "error") else "none"
        return _section(state, reason="No applied learned allow rules are confirmed for this endpoint.")
    historical = store._get(db, "learning_allow_history", f"{server['id']}:{generation}")
    if not historical or historical.get("digest") != digest or historical.get("server_id") != server["id"]:
        return _section("unverified", version=generation, reason="The exact applied learning generation could not be matched to immutable history.")
    current_bindings = all(historical.get(field) == value for field, value in _bindings(server).items())
    confirmed = runtime_known and current_bindings and receipt.get("status") in ("applied", "rolled_back")
    names = historical.get("policy_names", {})
    rows, attributed = [], set()
    policy_ids = set(historical["policy_ids"])
    for authority in historical.get("authorities", []):
        policy_id = authority["policy_id"]
        if policy_id not in policy_ids:
            continue
        name = names.get(policy_id)
        note = None if name else "This historical generation does not record the original policy name."
        attributed.update(_triples(authority["services"]))
        for service in authority["services"]:
            if service["sources"]:
                rows.append(_port_row(name or "Learned policy", service, service["sources"], policy_id=policy_id, note=note))
    # Old assignments may carry only an aggregate source set.
    if attributed != _triples(historical["services"]):
        rows = [_port_row("Learned allow bundle", service, service["sources"],
                          note="Policy names were not recorded for this generation.")
                for service in historical["services"] if service["sources"]]
    return _section("confirmed" if confirmed else "last_confirmed", rows, observed_at=receipt.get("updated_at"), version=generation,
                    reason=None if confirmed else "Showing the last reported learning generation. Current runtime enforcement has not been confirmed.")


def _page(section, offset, limit):
    statuses = {"confirmed": "Agent confirmed", "last_confirmed": "Last confirmed"}

    def chunks():
        for row in section["rows"]:
            sources = row["sources"]
            for start in range(0, max(1, len(sources)), SOURCES_PER_ROW):
                yield {"status": statuses.get(section["state"], "Reported runtime"), **row,
                       "sources": sources[start:start + SOURCES_PER_ROW], "source_offset": start, "source_count": len(sources)}

    total = sum(max(1, (len(row["sources"]) + SOURCES_PER_ROW - 1) // SOURCES_PER_ROW) for row in section["rows"])
    return {**section, "rows": list(islice(chunks(), offset, offset + limit)), "total": total,
            "offset": offset, "limit": limit, "has_more": offset + limit < total}


def listing(store, server_id, *, limit=20, managed_offset=0, learned_offset=0, discovered_offset=0):
    from .firewall_views import endpoint_access_snapshot

    identifier(server_id)
    offsets = (managed_offset, learned_offset, discovered_offset)
    if not 1 <= limit <= 50 or any(not 0 <= offset <= 1000000 for offset in offsets):
        raise ValueError("Choose a policy page size of 1..50 and a bounded offset")
    with snapshot(store) as db:
        server = store._get(db, "servers", server_id)
        if server is None:
            raise KeyError(server_id)
        runtime_known = _runtime_known(store, server)
        sections = (_managed(db, server, runtime_known), _learned(store, db, server, runtime_known), endpoint_access_snapshot(server))
    return {"server_id": server_id, **{name: _page(section, offset, limit) for name, section, offset in zip(SECTIONS, sections, offsets)}}
