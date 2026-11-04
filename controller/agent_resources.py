"""Evaluate bounded, authenticated endpoint resource measurements."""
from datetime import timedelta

from .store import now, parse_time, stamp


CAPABILITY = "agent_resource_usage_v1"
EVENT = "agent_resource_pressure"
LIMITS = {
    "cpu_basis_points": ("CPU", 500, 400, 10000),
    "memory_bytes": ("memory", 2_000_000_000, 1_600_000_000, (1 << 63) - 1),
    "storage_bytes": ("state storage", 10_000_000_000, 8_000_000_000, (1 << 63) - 1),
}


def _display(metric, value):
    if metric == "cpu_basis_points":
        return f"{value / 100:g}% of whole-host CPU capacity"
    return f"{value / 1_000_000_000:g} GB"


def report(store, db, server, value, at=None):
    if CAPABILITY not in server.get("capabilities", []) or not isinstance(value, dict):
        server.pop("resource_usage", None)
        return
    at = at or now()
    samples = {}
    seen = server.setdefault("_resource_usage_seen", {})
    for metric, (label, limit, threshold, ceiling) in LIMITS.items():
        measurement = value.get(metric)
        if not isinstance(measurement, dict) or set(measurement) != {"value", "observed_at"}:
            continue
        count = measurement["value"]
        if type(count) is not int or not 0 <= count <= ceiling:
            continue
        try:
            observed_at = parse_time(measurement["observed_at"])
        except (TypeError, ValueError, OverflowError):
            continue
        if not at - timedelta(hours=2) <= observed_at <= at + timedelta(seconds=60):
            continue
        previous = seen.get(metric)
        if previous and observed_at <= parse_time(previous["observed_at"]):
            if observed_at == parse_time(previous["observed_at"]) and count == previous["value"]:
                samples[metric] = {"value": count, "observed_at": stamp(observed_at)}
            continue
        samples[metric] = {"value": count, "observed_at": stamp(observed_at)}
        was_breached = bool(previous and previous["breached"])
        rearm = limit * 3 // 4
        breached = count >= (rearm if was_breached else threshold)
        key = f"agent-resource:{server['id']}:{metric}"
        if breached and not was_breached:
            store._event(db, key, EVENT, "warning", server["id"],
                         f"Agent {label} on {server['hostname']} reached {_display(metric, count)}. "
                         f"The warning threshold is {_display(metric, threshold)}.",
                         {"metric": metric, "value": count, "threshold": threshold, "limit": limit,
                          "observed_at": samples[metric]["observed_at"]})
        elif not breached and was_breached:
            store._resolve(db, key, server["id"],
                           f"Agent {label} on {server['hostname']} returned below {_display(metric, rearm)}.")
        seen[metric] = {**samples[metric], "breached": breached}
    server["resource_usage"] = samples
