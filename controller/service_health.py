"""Listener expectations derived from access intent, never kernel apply receipts.

Only port/protocol metadata is retained here. Source grants and approvals remain
in their existing namespaces. A newly changed policy expectation requires an
actual successful discovery after that change before an outage or recovery can
be inferred.
"""
from .store import now, parse_time, stamp


def _ports(services):
    return sorted({(row["protocol"], row["port"]) for row in services if row.get("sources")})


def sync(server, services, origin, at=None):
    if origin not in ("ordinary", "learned"):
        raise ValueError("Unknown service expectation origin")
    state = server.setdefault("_policy_health", {})
    ports = [[protocol, port] for protocol, port in _ports(services)]
    if state.get(origin, []) == ports:
        return False
    state[origin] = ports
    state["changed_at"] = stamp(at or now())
    state["after_discovery_revision"] = server.get("_discovery_revision", 0)
    union = sorted({tuple(row) for key in ("ordinary", "learned") for row in state.get(key, [])})
    server["policy_expected_services"] = [{"protocol": protocol, "port": port} for protocol, port in union]
    return True


def ready(server):
    state = server.get("_policy_health", {})
    if not state.get("changed_at"):
        return True
    scanned = server.get("last_discovery_at")
    return bool(scanned and server.get("_discovery_revision", 0) > state.get("after_discovery_revision", 0)
                and parse_time(scanned) > parse_time(state["changed_at"]))


def expectations(server):
    result = {(row["protocol"], row["port"]): {**row, "basis": "explicit_expectation"}
              for row in server.get("expected_services", [])}
    if ready(server):
        for row in server.get("policy_expected_services", []):
            result.setdefault((row["protocol"], row["port"]), {**row, "basis": "effective_policy_intent"})
    return [result[key] for key in sorted(result)]


def evaluate(store, db, server):
    """Called only for a live endpoint with current successful discovery."""
    services = expectations(server)
    current = {(row["protocol"], row["port"]) for row in server.get("listeners", [])}
    expected = {(row["protocol"], row["port"]) for row in services}
    missing = False
    for service in services:
        key = f"service:{server['id']}:{service['protocol']}:{service['port']}"
        if (service["protocol"], service["port"]) not in current:
            missing = True
            store._event(db, key, "service_down", "critical", server["id"],
                         f"Expected listener missing: {server['hostname']} · {service['port']}/{service['protocol']}",
                         {**service, "last_discovery_at": server["last_discovery_at"],
                          "policy_version": server.get("desired_version", 0), "application_health": "unverified"})
        else:
            store._resolve(db, key, server["id"],
                           f"Service recovered: {server['hostname']} · {service['port']}/{service['protocol']}")
    # Withdrawing access intent is not evidence that a service recovered. Keep
    # the old alert until a post-change scan, then close with a truthful reason.
    if ready(server):
        for protocol, port in server.get("_expected_alert_ports", []):
            if (protocol, port) in expected:
                continue
            key = f"service:{server['id']}:{protocol}:{port}"
            alert = store._get(db, "alerts", key)
            if alert and alert.get("status") in ("open", "acknowledged"):
                alert.update({"status": "resolved", "resolution_reason": "expectation_withdrawn",
                              "resolved_at": stamp(), "updated_at": stamp()})
                store._put(db, "alerts", alert)
                store._event(db, "expectation-withdrawn:" + key + ":" + alert.get("occurrence_id", "legacy"),
                             "service_expectation_withdrawn", "info", server["id"],
                             f"Listener expectation withdrawn: {server['hostname']} · {port}/{protocol}",
                             {"port": port, "protocol": protocol, "service_recovery_verified": False})
        server["_expected_alert_ports"] = [list(row) for row in sorted(expected)]
    return missing
