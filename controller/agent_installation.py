"""Private data-only bootstrap downloads; executable release code stays separate."""
from __future__ import annotations

import re
import ipaddress
from datetime import timedelta
from urllib.parse import urlsplit
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.verification import PolicyBuilder, Store as TrustStore, VerificationError

from .appliance import origin
from .store import now, stamp, parse_time


def _public_ca(value, valid_until=None):
    if not isinstance(value, str) or not 1 <= len(value) <= 128 * 1024 or "PRIVATE KEY" in value:
        raise ValueError("Provide public PEM CA certificates only")
    try:
        certs = x509.load_pem_x509_certificates(value.encode())
        if not certs or len(certs) > 16:
            raise ValueError()
        for cert in certs:
            if not cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
                raise ValueError()
            if not cert.not_valid_before_utc <= now() or cert.not_valid_after_utc < (valid_until or now() + timedelta(minutes=15, seconds=1)):
                raise ValueError()
    except (ValueError, x509.ExtensionNotFound):
        raise ValueError("Use at most 16 public CA certificates valid through the setup file's full lifetime") from None
    return "".join(cert.public_bytes(serialization.Encoding.PEM).decode() for cert in certs)


def _interval(value, low, high, name):
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise ValueError(f"{name} must be between {low} and {high} seconds")
    return value


KIT_FIELDS = {"family", "architecture", "controller_url", "control_url", "discovery_url", "interval_seconds", "discovery_interval_seconds", "controller_ca_pem", "installation_options", "management_sources"}


def _management_sources(body):
    values = body.get("management_sources", [])
    if not isinstance(values, list) or len(values) > 100 or any(not isinstance(value, str) or not 1 <= len(value) <= 128 for value in values):
        raise ValueError("Choose at most100 restricted management source addresses or canonical CIDRs")
    from .network_addresses import network
    result = []
    for value in values:
        try:
            source = network(value)
            if source.prefixlen == 0 or value != (str(source) if '/' in value else str(source.network_address)):
                raise ValueError()
        except ValueError:
            raise ValueError("Management sources must be native canonical IPs/CIDRs with /0 forbidden; specify the network address explicitly") from None
        result.append(str(source))
    return sorted(set(result))


def _installation_options(body):
    if "installation_options" not in body:
        if body.get("family") == "auto":
            return {"install_dependencies": True, "ufw_action": "preserve"}
        return None
    value = body["installation_options"]
    if not isinstance(value, dict) or set(value) != {"install_dependencies", "ufw_action"}:
        raise ValueError("Select supported endpoint preparation options only")
    if type(value["install_dependencies"]) is not bool or not isinstance(value["ufw_action"], str) or value["ufw_action"] not in ("preserve", "assess"):
        raise ValueError("Use a dependency-install boolean and preserve or assess UFW")
    if not value["install_dependencies"] and value["ufw_action"] == "preserve":
        raise ValueError("Choose a preparation action or omit installation_options")
    if body.get("family") == "auto" and not value["install_dependencies"]:
        raise ValueError("The automatic installer always prepares required OS dependencies")
    return {"install_dependencies": value["install_dependencies"], "ufw_action": value["ufw_action"]}


def _validated(app, body, valid_until=None):
    if app.demo or not app.signer or not app.controller_certificate:
        raise ValueError("Agent setup downloads require an installed HTTPS controller with endpoint issuance enabled")
    if body.get("family") not in ("auto", "rhel", "ubuntu") or body.get("architecture") not in ("amd64", "arm64"):
        raise ValueError("Choose automatic OS detection or a supported legacy family and the matching amd64 or arm64 package")
    management_sources = _management_sources(body)
    url = origin(body.get("controller_url", ""))
    channels = {key: origin(body[key]) if body.get(key) else "" for key in ("control_url", "discovery_url")}
    endpoint_ca = _public_ca(app.signer.ca.read_text(), valid_until)
    supplied = body.get("controller_ca_pem", "")
    if supplied:
        web_ca = _public_ca(supplied, valid_until)
    else:
        # An endpoint issuer cannot silently become trust for an unrelated web CA.
        leaf = x509.load_pem_x509_certificates(app.controller_certificate.read_bytes())[0]
        issuers = x509.load_pem_x509_certificates(endpoint_ca.encode())
        try:
            if len(issuers) != 1:
                raise ValueError()
            leaf.verify_directly_issued_by(issuers[0])
        except (ValueError, TypeError):
            raise ValueError("Upload the public HTTPS CA chain because web TLS and endpoint issuance use different CAs") from None
        web_ca = endpoint_ca
    # Verify the actual active certificate, its chain and the requested name;
    # accepting a syntactically valid unrelated CA would create a broken kit.
    try:
        chain = x509.load_pem_x509_certificates(app.controller_certificate.read_bytes())
        anchors = x509.load_pem_x509_certificates(web_ca.encode())
        for endpoint in (url, *channels.values()):
            if not endpoint:
                continue
            controller_hostname = urlsplit(endpoint).hostname
            try:
                subject = x509.IPAddress(ipaddress.ip_address(controller_hostname))
            except ValueError:
                subject = x509.DNSName(controller_hostname)
            PolicyBuilder().store(TrustStore(anchors)).time(now()).build_server_verifier(subject).verify(chain[0], chain[1:] + anchors)
    except (ValueError, TypeError, VerificationError):
        raise ValueError("The public HTTPS CA chain and controller URL must verify the current controller certificate and hostname") from None
    interval = _interval(body.get("interval_seconds", 30), 5, 3600, "Control interval")
    discovery = _interval(body.get("discovery_interval_seconds", 900), 60, 86400, "Discovery interval")
    separate = web_ca != endpoint_ca
    return {"controller_ca_pem": web_ca, "endpoint_ca_pem": endpoint_ca if separate else "",
            "config": {"controller_url": url, **{key: value for key, value in channels.items() if value}, "state_dir": "/var/lib/seg-agent",
                "ca_cert": "/etc/seg-agent/controller-ca.crt", "endpoint_ca_cert": "/etc/seg-agent/endpoint-ca.crt" if separate else "",
                "certificate": "/var/lib/seg-agent/agent.crt", "private_key": "/var/lib/seg-agent/agent.key",
                "enrollment_token_file": "/etc/seg-agent/enrollment-token", "interval_seconds": interval,
                "request_timeout_seconds": 15, "zone": "", "enforce": False, "management_sources": management_sources,
                "max_spool_batches": 500, "discovery_interval_seconds": discovery, "allow_firewall_changes": False,
                "unexpected_port_monitor_enabled": False, "allow_single_admin_pilot": False, "probe_log_rate_per_second": 5, "learning_auto_allow": False}}


def create_kit(app, body, actor):
    if not isinstance(body, dict) or set(body) - KIT_FIELDS - {"expected_hostname"}:
        raise ValueError("Provide supported agent setup fields only")
    hostname = body.get("expected_hostname", "")
    if not isinstance(hostname, str) or len(hostname) > 253 or hostname and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", hostname):
        raise ValueError("Use the endpoint's exact hostname or leave it empty for automatic enrollment")
    options = _installation_options(body)
    validated = _validated(app, body)
    # Finish all validation before minting the one-use credential.
    token = app.store.create_token(("GUI setup " + (hostname or "endpoint"))[:120], actor)
    issued = stamp(parse_time(token["expires_at"]) - timedelta(minutes=15))
    return {"schema_version": 3 if options else 1, "issued_at": issued, "expires_at": token["expires_at"],
            "expected_hostname": hostname, "enrollment_token": token["token"], **validated,
            **({"installation_options": options} if options else {})}


def create_fleet_kit(app, body, actor):
    if not isinstance(body, dict) or set(body) - KIT_FIELDS - {"name", "validity_hours"}:
        raise ValueError("Provide shared fleet settings only; no per-server hostname or tags")
    options = _installation_options(body)
    validity_hours = body.get("validity_hours", 24)
    if isinstance(validity_hours, bool) or not isinstance(validity_hours, int) or not 1 <= validity_hours <= 720:
        raise ValueError("Fleet enrollment validity must be 1 to 720 hours")
    issued = stamp()
    valid_until = parse_time(issued) + timedelta(hours=validity_hours, seconds=1)
    validated = _validated(app, body, valid_until)
    from .fleet_enrollment import create
    profile, token = create(app.store, body.get("name", "Fleet enrollment"), validity_hours, actor, issued_at=issued)
    kit = {"schema_version": 3 if options else 2, "enrollment_profile_id": profile["id"], "expected_hostname": "",
           "issued_at": issued, "expires_at": profile["expires_at"], "enrollment_token": token, **validated,
           **({"installation_options": options} if options else {})}
    return {"profile": profile, "kit": kit}
