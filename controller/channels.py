"""Listener isolation uses the accepted TLS socket, never a caller header.

Legacy development deployments can retain one combined listener. Installed
appliances expose separate management, control and discovery TLS ports.
"""
from urllib.parse import urlsplit, urlunsplit
import os
import re

CONTROL = {
    "/api/v1/agent/network-control/check": "POST",
    "/api/v1/agent/firewall-activation/check": "POST",
    "/api/v1/agent/policy": "GET",
    "/api/v1/agent/certificates/renew": "POST",
    "/api/v1/agent/firewall/check": "POST",
    "/api/v1/agent/learning-allow/check": "POST",
    "/api/v1/agent/enforcement/check": "POST",
    "/api/v1/agent/configuration/check": "POST",
    "/api/v1/agent/source-banks/check": "POST",
}
DISCOVERY = {path: "POST" for path in (
    "/api/v1/agent/enroll", "/api/v1/agent/certificates/recover",
    "/api/v1/agent/report", "/api/v1/agent/flows", "/api/v1/agent/hits",
)}
AGENT_UPGRADE = re.compile(r"/api/v1/agent/upgrade/([a-f0-9]{32})/(archive|signature)")


def protected_origins(server):
    """All reported controller channels, without inventing network identity."""
    protection = server.get("protection", {})
    state = server.get("configuration_state", {})
    return sorted({value for value in (protection.get("controller_url"),
                  state.get("controller_url"), state.get("control_url"), state.get("discovery_url"))
                  if isinstance(value, str) and value})


def listeners(management, control=None, discovery=None):
    if bool(control) != bool(discovery):
        raise ValueError("Configure both control and discovery listeners, or neither")
    result = {}
    for channel, address in (("management", management), ("control", control), ("discovery", discovery)):
        if address is None:
            continue
        try:
            from .listener_address import split_listener
            host, port = split_listener(address)
            if port in result:
                raise ValueError()
        except (AttributeError, TypeError, ValueError):
            raise ValueError("Use distinct host:port listeners with ports from 1 to 65535") from None
        result[port] = channel if control else "combined"
    return result


def admitted(channel, method, path):
    if channel == "combined":
        return True
    if channel not in ("management", "control", "discovery"):
        return False
    if method == "GET" and path in ("/healthz", "/readyz"):
        return True
    if channel == "management":
        return not path.startswith("/api/v1/agent/")
    if channel == "control" and method == "GET" and AGENT_UPGRADE.fullmatch(path):
        return True
    return (CONTROL if channel == "control" else DISCOVERY).get(path) == method


def request_channel(app, connection):
    mapping = getattr(app, "listener_channels", None)
    if not mapping:
        return "combined"
    try:
        return mapping.get(connection.getsockname()[1], "unknown")
    except (OSError, AttributeError, IndexError):
        return "unknown"


def public_status(app):
    mapping = getattr(app, "listener_channels", {})
    separated = "control" in mapping.values()
    base = getattr(app.auth.config, "redirect_uri", "") or os.environ.get("PRTHAK_CONTROLLER_ORIGIN", "")
    if not base and getattr(app, "platform", None):
        from .platform import _read_json
        base = _read_json(app.platform.root / "appliance-local.json", {}).get("controller_origin", "")
    urls = {}
    if base:
        parsed = urlsplit(base)
        if parsed.scheme == "https" and parsed.hostname and not parsed.username and not parsed.password:
            hostname = "[" + parsed.hostname + "]" if ":" in parsed.hostname else parsed.hostname
            urls["controller_url"] = urlunsplit(("https", parsed.netloc, "", "", ""))
            for name, default in (("control", 8788), ("discovery", 8789)):
                if separated:
                    default = next((port for port, channel in mapping.items() if channel == name), default)
                    port = int(os.environ.get("SEG_" + name.upper() + "_PORT", str(default)))
                    urls[name + "_url"] = "https://" + hostname + (":" + str(port) if port != 443 else "")
                else:
                    urls[name + "_url"] = urls["controller_url"]
    return {"mode": "separated" if separated else "combined", **urls,
            "identity": "verified_endpoint_mtls", "listener_ports": {v: k for k, v in mapping.items()}}
