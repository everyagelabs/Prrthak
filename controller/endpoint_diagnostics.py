"""Bounded endpoint diagnostics; receipts are observations, never authority."""
from .store import now, parse_time, stamp

UFW_EXPORT = "/var/lib/seg-agent/host-preparation/ufw-export.json"


def _object(value, required, optional=()):
    if not isinstance(value, dict) or not set(required) <= value.keys() or set(value) - set(required) - set(optional):
        raise ValueError("Invalid endpoint diagnostic fields")
    return dict(value)


def _boolean(value):
    if not isinstance(value, bool):
        raise ValueError("Endpoint diagnostic flags must be booleans")
    return value


def _time(value):
    if not isinstance(value, str) or not 1 <= len(value) <= 64:
        raise ValueError("Endpoint diagnostic timestamp required")
    try:
        parsed = parse_time(value)
        if (parsed - now()).total_seconds() > 60:
            raise ValueError()
    except (ValueError, TypeError, OverflowError):
        raise ValueError("Invalid endpoint diagnostic timestamp") from None
    return stamp(parsed)


def _error(value):
    if not isinstance(value, str) or len(value.encode("utf-8")) > 1024:
        raise ValueError("Endpoint diagnostic error exceeds its bound")
    return value


def fast_discovery(value):
    result = _object(value, ("backend", "status", "interval_seconds", "checked_at"), ("last_change_at", "error"))
    if result["backend"] != "inet_diag" or not isinstance(result["status"], str) or result["status"] not in ("active", "unsupported", "error", "off"):
        raise ValueError("Invalid fast discovery backend or state")
    if type(result["interval_seconds"]) is not int or result["interval_seconds"] != 5:
        raise ValueError("Invalid fast discovery check interval")
    result["checked_at"] = _time(result["checked_at"])
    if "last_change_at" in result:
        result["last_change_at"] = _time(result["last_change_at"])
        if parse_time(result["last_change_at"]) > parse_time(result["checked_at"]):
            raise ValueError("Fast discovery change is newer than its check")
    if "error" in result:
        result["error"] = _error(result["error"])
    return result


def preparation_status(value):
    result = _object(value, ("schema_version", "status", "checked_at", "install_dependencies", "dependencies_changed", "ufw", "firewalld"), ("error",))
    if type(result["schema_version"]) is not int or result["schema_version"] != 1 or not isinstance(result["status"], str) or result["status"] not in ("prepared", "assessment_only", "error", "blocked"):
        raise ValueError("Invalid endpoint preparation state")
    result["checked_at"] = _time(result["checked_at"])
    for key in ("install_dependencies", "dependencies_changed"):
        result[key] = _boolean(result[key])
    ufw = _object(result["ufw"], ("installed", "assessment", "migration_required", "export_path"), ("active",))
    for key in ("installed", "migration_required"):
        ufw[key] = _boolean(ufw[key])
    if "active" in ufw:
        ufw["active"] = _boolean(ufw["active"])
    if not isinstance(ufw["assessment"], str) or ufw["assessment"] not in ("not_requested", "exported", "unavailable", "error"):
        raise ValueError("Invalid UFW assessment state")
    if ufw["export_path"] not in ("", UFW_EXPORT) or (ufw["assessment"] == "exported") != (ufw["export_path"] == UFW_EXPORT):
        raise ValueError("Invalid private UFW export reference")
    firewall = _object(result["firewalld"], ("installed",), ("active",))
    firewall["installed"] = _boolean(firewall["installed"])
    if "active" in firewall:
        firewall["active"] = _boolean(firewall["active"])
    result.update(ufw=ufw, firewalld=firewall)
    if "error" in result:
        result["error"] = _error(result["error"])
    return result
