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


def _public_ca(value):
    if not isinstance(value, str) or not 1 <= len(value) <= 128 * 1024 or "PRIVATE KEY" in value:
        raise ValueError("Provide public PEM CA certificates only")
    try:
        certs = x509.load_pem_x509_certificates(value.encode())
        if not certs or len(certs) > 16:
            raise ValueError()
        for cert in certs:
            if not cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
                raise ValueError()
            if not cert.not_valid_before_utc <= now() or cert.not_valid_after_utc < now() + timedelta(minutes=15, seconds=1):
                raise ValueError()
    except (ValueError, x509.ExtensionNotFound):
        raise ValueError("Use at most 16 public CA certificates valid through the next 15 minutes") from None
    return "".join(cert.public_bytes(serialization.Encoding.PEM).decode() for cert in certs)


def _interval(value, low, high, name):
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise ValueError(f"{name} must be between {low} and {high} seconds")
    return value


def create_kit(app, body, actor):
    if app.demo or not app.signer or not app.controller_certificate:
        raise ValueError("Agent setup downloads require an installed HTTPS controller with endpoint issuance enabled")
    if not isinstance(body, dict) or set(body) - {"family", "architecture", "expected_hostname", "controller_url", "control_url", "discovery_url", "interval_seconds", "discovery_interval_seconds", "controller_ca_pem"}:
        raise ValueError("Provide supported agent setup fields only")
    if body.get("family") not in ("rhel", "ubuntu") or body.get("architecture") not in ("amd64", "arm64"):
        raise ValueError("Choose RHEL or Ubuntu and the matching amd64 or arm64 package")
    hostname = body.get("expected_hostname", "")
    if not isinstance(hostname, str) or len(hostname) > 253 or hostname and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", hostname):
        raise ValueError("Use the endpoint's exact hostname or leave it empty for automatic enrollment")
    url = origin(body.get("controller_url", ""))
    channels = {key: origin(body[key]) if body.get(key) else "" for key in ("control_url", "discovery_url")}
    endpoint_ca = _public_ca(app.signer.ca.read_text())
    supplied = body.get("controller_ca_pem", "")
    if supplied:
        web_ca = _public_ca(supplied)
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
    # Finish all validation before minting the one-use credential.
    token = app.store.create_token(("GUI setup " + (hostname or "endpoint"))[:120], actor)
    issued = stamp(parse_time(token["expires_at"]) - timedelta(minutes=15))
    separate = web_ca != endpoint_ca
    return {"schema_version": 1, "issued_at": issued, "expires_at": token["expires_at"],
            "expected_hostname": hostname, "controller_ca_pem": web_ca,
            "endpoint_ca_pem": endpoint_ca if separate else "", "enrollment_token": token["token"],
            "config": {"controller_url": url, **{key: value for key, value in channels.items() if value}, "state_dir": "/var/lib/seg-agent",
                "ca_cert": "/etc/seg-agent/controller-ca.crt", "endpoint_ca_cert": "/etc/seg-agent/endpoint-ca.crt" if separate else "",
                "certificate": "/var/lib/seg-agent/agent.crt", "private_key": "/var/lib/seg-agent/agent.key",
                "enrollment_token_file": "/etc/seg-agent/enrollment-token", "interval_seconds": interval,
                "request_timeout_seconds": 15, "zone": "", "enforce": False, "management_sources": [],
                "max_spool_batches": 500, "discovery_interval_seconds": discovery, "allow_firewall_changes": False,
                "unexpected_port_monitor_enabled": False, "allow_single_admin_pilot": False, "probe_log_rate_per_second": 5, "learning_auto_allow": False}}
