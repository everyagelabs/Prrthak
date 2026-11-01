"""Reviewed controller HTTPS material; activation belongs to the supervisor.

Private keys are canonicalized only in memory and encrypted in the private vault.
No PKCS#12/key password, key bytes or certificate bundle appears in public plans,
jobs or audit. Endpoint issuing trust is never silently replaced.
"""
from __future__ import annotations

import base64
from datetime import timedelta
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import secrets
from urllib.parse import urlsplit

from .firewall import WorkflowConflict
from .platform_runtime import atomic_private_json
from .store import digest, now, parse_time, stamp

MAX_BYTES = 2 * 1024 * 1024
IDENTIFIER = re.compile(r"[a-f0-9]{32}\Z")


def _context(manager):
    if manager is None:
        return {}
    callback = getattr(manager, "certificate_context", None)
    context = callback() if callback else {}
    context = dict(context) if isinstance(context, dict) else {}
    profile = manager.active_profile()
    if profile:
        context.setdefault("hostname", profile.get("controller_server_name") or urlsplit(profile.get("controller_origin", "")).hostname)
        for key, field in (("cert_path", "cert"), ("key_path", "key"), ("ca_path", "ca")):
            context.setdefault(key, profile.get("controller_tls", {}).get(field))
    app = getattr(manager, "app", None)
    signer = getattr(app, "signer", None)
    if signer:
        context.setdefault("issuer_cert_path", str(signer.ca))
        context.setdefault("issuer_key_path", str(signer.ca_key))
    return context


def _certificates(value):
    from cryptography import x509
    return x509.load_pem_x509_certificates(value)


def _read_certificates(path):
    if not path:
        return []
    data = Path(path).read_bytes()
    if len(data) > MAX_BYTES:
        raise ValueError("Certificate bundle exceeds its size bound")
    return _certificates(data)


def _fp(certificate):
    from cryptography.hazmat.primitives import hashes
    return certificate.fingerprint(hashes.SHA256()).hex()


def _summary(certificate):
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import rsa, ec
    public = certificate.public_key()
    algorithm = "RSA " + str(public.key_size) if isinstance(public, rsa.RSAPublicKey) else "ECDSA " + public.curve.name if isinstance(public, ec.EllipticCurvePublicKey) else type(public).__name__
    try:
        extension = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        sans = [str(value) for value in extension.get_values_for_type(x509.DNSName)] + [str(value) for value in extension.get_values_for_type(x509.IPAddress)]
    except x509.ExtensionNotFound:
        sans = []
    return {"subject": certificate.subject.rfc4514_string(), "issuer": certificate.issuer.rfc4514_string(), "sans": sans, "not_before": stamp(certificate.not_valid_before_utc), "not_after": stamp(certificate.not_valid_after_utc), "fingerprint_sha256": _fp(certificate), "serial_number": str(certificate.serial_number), "key_algorithm": algorithm}


def status(manager):
    result = {"current": None, "hostname": None, "configured": False, "demo": bool(getattr(getattr(manager, "app", None), "demo", False)), "warnings": [], "capabilities": {"pem": True, "pkcs12": True, "self_signed": True}}
    if manager is None:
        result["warnings"] = ["A private platform state directory is required for certificate management"]
        return result
    try:
        context = _context(manager)
        result["hostname"] = context.get("hostname")
        chain = _read_certificates(context.get("cert_path"))
        if chain:
            result.update(current=_summary(chain[0]), configured=True)
        else:
            result["warnings"].append("No current HTTPS certificate is configured")
    except ImportError:
        result["warnings"].append("Install the controller requirements to inspect or manage certificates")
    except Exception:
        result["warnings"].append("The current HTTPS certificate could not be inspected")
    return result


def _name(value, wildcard=False):
    if not isinstance(value, str) or not value.strip() or len(value) > 253:
        raise ValueError("Provide a valid DNS hostname or IP address")
    value = value.strip().rstrip(".")
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        try:
            ascii_name = value.encode("idna").decode("ascii").lower()
        except UnicodeError:
            raise ValueError("Provide a valid DNS hostname") from None
        labels = ascii_name.split(".")
        if wildcard and labels[0] == "*":
            labels = labels[1:]
            if len(labels) < 2:
                raise ValueError("Wildcard names require a qualified suffix")
        if not labels or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels):
            raise ValueError("Provide a valid DNS hostname")
        return ascii_name, False
    if address.is_multicast or address.is_unspecified or "%" in value:
        raise ValueError("Certificate IP names cannot be unspecified or multicast")
    return str(address), True


def _matches(certificate, hostname):
    from cryptography import x509
    hostname, is_ip = _name(hostname)
    try:
        sans = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return False
    if is_ip:
        return ipaddress.ip_address(hostname) in sans.get_values_for_type(x509.IPAddress)
    for value in sans.get_values_for_type(x509.DNSName):
        try:
            name, _ = _name(value, wildcard=True)
        except ValueError:
            continue
        if name == hostname or name.startswith("*.") and hostname.endswith(name[1:]) and len(hostname.split(".")) == len(name.split(".")):
            return True
    return False


def _password(value):
    if value is None or value == "":
        return None
    if not isinstance(value, str) or len(value) > 4096:
        raise ValueError("Certificate password must be text within its size bound")
    return value.encode()


def _text(value, label):
    if not isinstance(value, str) or not value or len(value.encode()) > MAX_BYTES:
        raise ValueError(f"Provide {label} no larger than 2 MiB")
    return value.encode()


def _validate(certificate, key, names):
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, ec
    from cryptography.x509.oid import ExtendedKeyUsageOID
    if not isinstance(key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey)):
        raise ValueError("Use an RSA key of at least 2048 bits or a supported NIST ECDSA key")
    if isinstance(key, rsa.RSAPrivateKey) and (key.key_size < 2048 or key.public_key().public_numbers().e < 65537):
        raise ValueError("RSA TLS keys require at least 2048 bits and exponent 65537 or greater")
    if isinstance(key, ec.EllipticCurvePrivateKey) and not isinstance(key.curve, (ec.SECP256R1, ec.SECP384R1, ec.SECP521R1)):
        raise ValueError("Use NIST P-256, P-384 or P-521 for an ECDSA TLS key")
    encoding, form = serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    if certificate.public_key().public_bytes(encoding, form) != key.public_key().public_bytes(encoding, form):
        raise ValueError("The certificate does not match the supplied private key")
    at = now()
    if certificate.not_valid_before_utc > at or certificate.not_valid_after_utc <= at:
        raise ValueError("The TLS certificate is expired or not yet valid")
    try:
        if certificate.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
            raise ValueError("A CA certificate cannot be installed as the server leaf")
        eku = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        if ExtendedKeyUsageOID.SERVER_AUTH not in eku:
            raise ValueError("Certificate extended usage must include TLS server authentication")
    except x509.ExtensionNotFound:
        raise ValueError("Server certificates require leaf Basic Constraints and a TLS server-auth EKU") from None
    try:
        usage = certificate.extensions.get_extension_for_class(x509.KeyUsage).value
        if not usage.digital_signature or usage.key_cert_sign:
            raise ValueError("Certificate key usage is unsuitable for this TLS server")
    except x509.ExtensionNotFound:
        pass
    for name in names:
        if not _matches(certificate, name):
            raise ValueError("Certificate SANs do not cover the requested hostname and current controller origin")


def _signed_by(certificate, issuer):
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448, padding
    if certificate.issuer != issuer.subject:
        return False
    try:
        key = issuer.public_key()
        if isinstance(key, rsa.RSAPublicKey):
            key.verify(certificate.signature, certificate.tbs_certificate_bytes, certificate.signature_algorithm_parameters or padding.PKCS1v15(), certificate.signature_hash_algorithm)
        elif isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(certificate.signature, certificate.tbs_certificate_bytes, ec.ECDSA(certificate.signature_hash_algorithm))
        elif isinstance(key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            key.verify(certificate.signature, certificate.tbs_certificate_bytes)
        else:
            return False
        return True
    except Exception:
        return False


def _chain(leaf, additional):
    from cryptography import x509
    result, remaining = [leaf], list(additional)
    if len(remaining) > 10 or len({_fp(value) for value in result + remaining}) != len(result + remaining):
        raise ValueError("Certificate chains require at most ten unique issuer certificates")
    while remaining:
        issuer = next((value for value in remaining if _signed_by(result[-1], value)), None)
        if issuer is None:
            raise ValueError("The supplied certificate chain is disconnected or has an invalid signature")
        try:
            if not issuer.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
                raise ValueError("Issuer certificates must have CA Basic Constraints")
        except x509.ExtensionNotFound:
            raise ValueError("Issuer certificates require CA Basic Constraints") from None
        try:
            if not issuer.extensions.get_extension_for_class(x509.KeyUsage).value.key_cert_sign:
                raise ValueError("Issuer key usage does not permit certificate signing")
        except x509.ExtensionNotFound:
            pass
        if not issuer.not_valid_before_utc <= now() < issuer.not_valid_after_utc:
            raise ValueError("An issuer certificate is expired or not yet valid")
        result.append(issuer)
        remaining.remove(issuer)
    return result


def _trusts(chain, anchors):
    from cryptography import x509
    def visit(certificate, remaining, depth):
        if depth > 11:
            return False
        if any(_fp(certificate) == _fp(anchor) for anchor in anchors):
            return True
        for issuer in remaining + anchors:
            if _fp(issuer) != _fp(certificate) and _signed_by(certificate, issuer):
                try:
                    if not issuer.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
                        continue
                    if not issuer.not_valid_before_utc <= now() < issuer.not_valid_after_utc:
                        continue
                    try:
                        if not issuer.extensions.get_extension_for_class(x509.KeyUsage).value.key_cert_sign:
                            continue
                    except x509.ExtensionNotFound:
                        pass
                except x509.ExtensionNotFound:
                    continue
                if visit(issuer, [value for value in remaining if _fp(value) != _fp(issuer)], depth + 1):
                    return True
        return False
    return visit(chain[0], chain[1:], 0)


def _anchors(context):
    values = []
    for field in ("trust_ca_path", "ca_path", "issuer_cert_path"):
        try:
            values.extend(_read_certificates(context.get(field)))
        except Exception:
            pass
    return list({_fp(value): value for value in values}.values())


def _managed_chain(chain, anchors, current):
    """Complete a router-verifiable chain using only supplied/public material."""
    from cryptography import x509
    candidates = list({_fp(value): value for value in anchors + current}.values())

    def complete(path):
        for index, issuer in enumerate(path[1:], 1):
            constraints = issuer.extensions.get_extension_for_class(x509.BasicConstraints).value
            subordinate_cas = sum(value.subject != value.issuer for value in path[1:index])
            if constraints.path_length is not None and subordinate_cas > constraints.path_length:
                return None
        if _signed_by(path[-1], path[-1]):
            return path
        if len(path) >= 11:
            return None
        fingerprints = {_fp(value) for value in path}
        for issuer in candidates:
            if _fp(issuer) in fingerprints or not _signed_by(path[-1], issuer):
                continue
            try:
                checked = _chain(path[0], path[1:] + [issuer])
            except ValueError:
                continue
            result = complete(checked)
            if result:
                return result
        return None

    result = complete(chain)
    if result is None:
        raise ValueError("Managed appliance HTTPS requires a complete, verifiable issuer chain. Include the issuing intermediate certificates and root CA in the PEM or PKCS#12 bundle.")
    return result


def _binding(manager, context):
    chain = _read_certificates(context.get("cert_path"))
    fingerprint = _fp(chain[0]) if chain else context.get("current_fingerprint")
    profile = manager.active_profile()
    return {"hostname": context.get("hostname"), "current_fingerprint": fingerprint, "active_revision": profile.get("active_revision") if profile else None, "deployment_id": profile.get("deployment_id") if profile else None, "profile_digest": digest(profile), "trust_fingerprints": sorted(_fp(value) for value in _anchors(context))}


def _generate(body, context, hostname):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
    days = body.get("days", 90)
    if isinstance(days, bool) or not isinstance(days, int) or not 1 <= days <= 825:
        raise ValueError("Certificate validity must be from 1 to 825 days")
    arrays = [body.get(field, []) for field in ("sans", "san_dns", "san_ips")]
    if any(not isinstance(values, list) for values in arrays) or sum(len(values) for values in arrays) > 100:
        raise ValueError("Provide at most 100 DNS/IP SAN names")
    values = [value for values in arrays for value in values]
    names = {hostname}
    if context.get("hostname"):
        names.add(_name(context["hostname"])[0])
    names.update(_name(value, wildcard=True)[0] for value in values)
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname[:64])])
    issuer, issuer_key, mode = None, key, "literal_self_signed"
    if context.get("issuer_cert_path") and context.get("issuer_key_path"):
        try:
            issuer = _read_certificates(context["issuer_cert_path"])[0]
            issuer_key = serialization.load_pem_private_key(Path(context["issuer_key_path"]).read_bytes(), password=None)
            encoding, form = serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
            if issuer_key.public_key().public_bytes(encoding, form) != issuer.public_key().public_bytes(encoding, form) or not issuer.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
                raise ValueError()
            if not issuer.not_valid_before_utc <= now() < issuer.not_valid_after_utc:
                raise ValueError()
            mode = "existing_local_issuer"
        except Exception:
            raise ValueError("The configured local issuing CA/key is unavailable or invalid; no new trust root was generated") from None
    at = now()
    expiry = min(at + timedelta(days=days), issuer.not_valid_after_utc) if issuer else at + timedelta(days=days)
    sans = []
    for name in sorted(names):
        normalized, is_ip = _name(name, wildcard=True)
        sans.append(x509.IPAddress(ipaddress.ip_address(normalized)) if is_ip else x509.DNSName(normalized))
    certificate = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer.subject if issuer else subject).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(at - timedelta(minutes=1)).not_valid_after(expiry).add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True).add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=True, data_encipherment=False, key_agreement=False, key_cert_sign=False, crl_sign=False, encipher_only=None, decipher_only=None), critical=True).add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False).add_extension(x509.SubjectAlternativeName(sans), critical=False).add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False).add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), critical=False).sign(issuer_key, hashes.SHA256())
    return certificate, key, ([issuer] if issuer else []), mode


def _material(body, context):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.serialization import pkcs12
    if not isinstance(body, dict):
        raise ValueError("Provide certificate import or generation fields")
    if set(body) - {"source", "mode", "hostname", "certificate_pem", "private_key_pem", "key_password", "pkcs12_bytes", "pkcs12_base64", "password", "sans", "san_dns", "san_ips", "days"}:
        raise ValueError("Unsupported certificate field; endpoint issuing trust is managed separately")
    source = body.get("source", body.get("mode", "pem"))
    if source not in ("pem", "pkcs12", "self_signed"):
        raise ValueError("Choose PEM, PKCS#12 or self-signed generation")
    hostname = _name(body.get("hostname") or context.get("hostname"))[0]
    mode = "imported"
    if source == "self_signed":
        certificate, key, additional, mode = _generate(body, context, hostname)
    else:
        try:
            if source == "pem":
                certificates = _certificates(_text(body.get("certificate_pem"), "a PEM certificate chain"))
                certificate, additional = certificates[0], certificates[1:]
                key = serialization.load_pem_private_key(_text(body.get("private_key_pem"), "a PEM private key"), password=_password(body.get("key_password")))
            else:
                raw = body.get("pkcs12_bytes")
                if raw is None:
                    encoded = body.get("pkcs12_base64")
                    if not isinstance(encoded, str) or len(encoded) > 3 * MAX_BYTES:
                        raise ValueError()
                    raw = base64.b64decode("".join(encoded.split()), validate=True)
                if not isinstance(raw, bytes) or not raw or len(raw) > MAX_BYTES:
                    raise ValueError()
                key, certificate, additional = pkcs12.load_key_and_certificates(raw, _password(body.get("password")))
                if certificate is None or key is None:
                    raise ValueError()
        except Exception:
            raise ValueError("Certificate material could not be parsed; verify its format and private-key/PKCS#12 password") from None
    names = [hostname] + ([context["hostname"]] if context.get("hostname") else [])
    _validate(certificate, key, names)
    chain = _chain(certificate, additional)
    anchors = _anchors(context)
    current = _read_certificates(context.get("cert_path"))
    if context.get("managed_appliance") is True:
        chain = _managed_chain(chain, anchors, current)
    # An endpoint issuing CA can differ from the web CA. Do not assume every
    # configured issuer is already a trusted web anchor merely because one is.
    established = [anchor for anchor in anchors if current and _trusts(current, [anchor])]
    same_leaf = bool(current and _fp(current[0]) == _fp(certificate))
    trust_change = not (same_leaf or established and _trusts(chain, established))
    certificate_pem = b"".join(value.public_bytes(serialization.Encoding.PEM) for value in chain).decode()
    key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
    return {"certificate_pem": certificate_pem, "private_key_pem": key_pem, "hostname": hostname, "fingerprint_sha256": _fp(certificate), "trust_change": trust_change, "source": mode if source == "self_signed" else source}, _summary(certificate)


def _public_plan(plan):
    return {key: plan[key] for key in ("id", "digest", "confirmation_nonce", "confirmation_phrase", "expires_at", "summary", "warnings", "blockers")}


def preview(manager, body, actor):
    if manager is None:
        raise ValueError("A private platform state directory is required")
    try:
        context = _context(manager)
        material, certificate = _material(body, context)
        binding = _binding(manager, context)
    except ImportError:
        raise ValueError("Install the controller cryptography requirements before managing certificates") from None
    except ValueError:
        raise
    except Exception:
        raise ValueError("Current controller certificate or deployment context could not be validated") from None
    identifier = secrets.token_hex(16)
    warnings = []
    if material["trust_change"]:
        warnings.append("Client trust continuity is not proven. Update browser, agent and load-balancer trust before activation; a self-signed or new-issuer certificate can disconnect them. No trust is distributed automatically.")
    if material["source"] == "existing_local_issuer":
        warnings.append("The new server leaf uses the existing local issuing CA; the endpoint issuing CA/key is not rotated.")
    if parse_time(certificate["not_after"]) < now() + timedelta(days=7):
        warnings.append("This certificate expires in less than seven days.")
    phrase = "REPLACE HTTPS CERTIFICATE " + certificate["fingerprint_sha256"][:12].upper()
    if material["trust_change"]:
        phrase += " AND UPDATE CLIENT TRUST"
    summary = {"hostname": material["hostname"], "source": material["source"], "trust_change": material["trust_change"], "certificate": certificate, "endpoint_issuer_changed": False}
    plan = {"id": identifier, "created_by": actor, "expires_at": stamp(now() + timedelta(minutes=10)), "confirmation_nonce": secrets.token_urlsafe(24), "confirmation_phrase": phrase, "summary": summary, "warnings": warnings, "blockers": [], "binding": binding, "material_ref": manager.vault.put(json.dumps(material))}
    plan["digest"] = digest({key: value for key, value in plan.items() if key != "material_ref"})
    with manager.lock:
        atomic_private_json(manager.root / "certificate-plans" / (identifier + ".json"), plan)
        manager._audit("platform.certificate_previewed", actor, {"preview_id": identifier, "fingerprint_sha256": certificate["fingerprint_sha256"], "hostname": material["hostname"], "trust_change": material["trust_change"]})
    return _public_plan(plan)


def apply(manager, body, actor):
    if manager is None or getattr(getattr(manager, "app", None), "demo", False):
        raise ValueError("Certificate activation requires a production HTTPS controller and private platform state")
    identifier = body.get("preview_id") if isinstance(body, dict) else None
    if not isinstance(identifier, str) or not IDENTIFIER.fullmatch(identifier):
        raise ValueError("Review certificate activation before applying")
    with manager.lock:
        path = manager.root / "certificate-plans" / (identifier + ".json")
        try:
            plan = json.loads(path.read_text())
        except (OSError, ValueError):
            raise ValueError("The certificate review is unavailable") from None
        if any(body.get(key) != plan[key] for key in ("digest", "confirmation_nonce", "confirmation_phrase")):
            raise WorkflowConflict("Confirm the exact certificate review and trust warning", {})
        if plan.get("job_id"):
            return manager.job(plan["job_id"])
        context = _context(manager)
        try:
            binding_matches = _binding(manager, context) == plan["binding"]
        except Exception:
            binding_matches = False
        if parse_time(plan["expires_at"]) <= now() or not binding_matches:
            raise WorkflowConflict("Certificate or deployment state changed, or the review expired; review again", {})
        if not context.get("cert_path") or not context.get("key_path"):
            raise ValueError("A current recoverable HTTPS certificate/key pair is required before replacement")
        try:
            material = json.loads(manager.vault.get(plan["material_ref"]))
            checked, certificate = _material({"source": "pem", "hostname": material["hostname"], "certificate_pem": material["certificate_pem"], "private_key_pem": material["private_key_pem"]}, context)
            if checked["fingerprint_sha256"] != plan["summary"]["certificate"]["fingerprint_sha256"]:
                raise ValueError()
        except Exception:
            raise ValueError("The reviewed encrypted certificate material is unavailable or no longer valid") from None
        binding = plan["binding"]
        job = manager._queue("certificate", {"material_ref": plan["material_ref"], "expected_fingerprint": certificate["fingerprint_sha256"], "expected_current_fingerprint": binding["current_fingerprint"], "preview_id": identifier, "expected_active_revision": binding["active_revision"], "expected_deployment_id": binding["deployment_id"], "expected_profile_digest": binding["profile_digest"], "expected_context_digest": digest(binding), "expected_hostname": binding["hostname"]}, actor)
        plan["job_id"] = job["id"]
        atomic_private_json(path, plan)
        return job
