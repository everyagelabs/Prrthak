"""Renewable endpoint identities with durable, immediate API revocation."""
from __future__ import annotations

import hashlib
import secrets
from datetime import timedelta

from .firewall import WorkflowConflict
from .store import now, parse_time, stamp, digest

PREFIX = "endpoint_certificate:"


def certificate(pem):
    from cryptography import x509
    value = x509.load_pem_x509_certificate(pem.encode() if isinstance(pem, str) else pem)
    return value, _identity(value)


def _identity(value):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
    names = value.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if len(names) != 1 or ExtendedKeyUsageOID.CLIENT_AUTH not in value.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value:
        raise ValueError("An endpoint client identity is required")
    fingerprint = value.fingerprint(hashes.SHA256()).hex()
    return {"id": PREFIX + fingerprint, "fingerprint_sha256": fingerprint,
                   "server_id": names[0].value, "serial_number": format(value.serial_number, "x"), "not_before": stamp(value.not_valid_before_utc), "not_after": stamp(value.not_valid_after_utc)}


def record_issued(store, db, server, pem):
    # Private Store test signers can return placeholders; they cannot produce a
    # usable TLS credential. Real certificates always enter the exact registry.
    if not isinstance(pem, str) or "BEGIN CERTIFICATE" not in pem:
        return
    _, value = certificate(pem)
    if value["server_id"] != server["id"]:
        raise ValueError("Issued endpoint identity does not match the enrolled server")
    existing = store._get(db, "maintenance_settings", value["id"])
    if existing and existing.get("status") == "revoked":
        raise PermissionError("A revoked endpoint certificate cannot be reactivated")
    if not existing:
        store._put(db, "maintenance_settings", {**value, "status": "active", "issued_at": stamp()})
    server["certificate_registry"] = True
    server["certificate_not_after"] = value["not_after"]
    server["certificate_fingerprint"] = value["fingerprint_sha256"]


def authorize(store, identity, der):
    from cryptography import x509
    leaf = x509.load_der_x509_certificate(der)
    value = _identity(leaf)
    if value["server_id"] != identity:
        raise PermissionError("Endpoint certificate identity mismatch")
    # A TLS connection can outlive the certificate checked at its handshake.
    # Check every API admission, including before legacy registry migration.
    at=now()
    if at < leaf.not_valid_before_utc or at >= leaf.not_valid_after_utc:
        raise PermissionError("Endpoint certificate is expired or not yet valid")
    with store.read_meta() as db:
        # Admission needs enrollment existence and the exact current leaf row;
        # never decode a server's full firewall/source snapshot for this check.
        row = db.execute("SELECT c.data FROM servers s LEFT JOIN maintenance_settings c ON c.id=? WHERE s.id=?", (value["id"], identity)).fetchone()
        if row is None:
            raise PermissionError("Endpoint certificate is not enrolled")
        import json
        current = json.loads(row[0]) if row[0] is not None else None
        if current is not None:
            if current.get("server_id") != identity or current.get("status") not in ("active", "retiring") or current.get("retire_at") and parse_time(current["retire_at"]) <= now():
                raise PermissionError("Endpoint certificate is revoked or superseded")
            return current
    with store.lock, store.meta() as db:
        if getattr(db, "dialect", "sqlite") != "postgresql":
            db.execute("BEGIN IMMEDIATE")
        server = store._get(db, "servers", identity)
        if not server:
            raise PermissionError("Endpoint certificate is not enrolled")
        current = store._get(db, "maintenance_settings", value["id"])
        if current is None:
            if server.get("certificate_registry"):
                raise PermissionError("Endpoint certificate is not registered")
            # Existing 0.5 endpoints migrate only after an actual verified mTLS
            # handshake. No report/header may introduce a certificate record.
            from cryptography.hazmat.primitives import serialization
            pem = leaf.public_bytes(serialization.Encoding.PEM).decode()
            if not leaf.not_valid_before_utc <= now() < leaf.not_valid_after_utc:
                raise PermissionError("Endpoint certificate is expired or not yet valid")
            record_issued(store, db, server, pem)
            store._put(db, "servers", server)
            current = store._get(db, "maintenance_settings", value["id"])
        if current.get("status") not in ("active", "retiring") or current.get("retire_at") and parse_time(current["retire_at"]) <= now():
            raise PermissionError("Endpoint certificate is revoked or superseded")
        return current


def renew(store, identity, der, body, signer):
    current = authorize(store, identity, der)
    if not signer:
        raise RuntimeError("The endpoint issuing service is unavailable")
    csr = body.get("csr")
    if not isinstance(csr, str) or not 32 <= len(csr) <= 16384:
        raise ValueError("Provide a bounded PEM certificate request")
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    request = x509.load_pem_x509_csr(csr.encode())
    if not request.is_signature_valid:
        raise ValueError("The certificate request signature is invalid")
    public_key = request.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    request_id = "endpoint_renewal:" + digest([identity, current["fingerprint_sha256"], hashlib.sha256(public_key).hexdigest()])
    with store.lock, store.meta() as db:
        current = store._get(db, "maintenance_settings", current["id"])
        if not current or current.get("status") not in ("active", "retiring") or current.get("retire_at") and parse_time(current["retire_at"]) <= now():
            raise PermissionError("Endpoint identity changed before renewal")
        previous = store._get(db, "maintenance_settings", request_id)
        if previous:
            issued = store._get(db, "maintenance_settings", previous["certificate_id"])
            if not issued or issued.get("status") != "active":
                raise PermissionError("The renewed certificate is no longer active")
            return previous["response"]
        if parse_time(current["not_after"]) - now() > timedelta(days=30):
            return {"renewed": False, "renew_after": stamp(parse_time(current["not_after"]) - timedelta(days=30)), "not_after": current["not_after"]}
        server = store._get(db, "servers", identity)
        # Signing occurs inside the serialized transaction; a revocation cannot
        # race a successful renewal and leave a credential outside the registry.
        issued_pem, ca = signer(identity, csr)
        record_issued(store, db, server, issued_pem)
        _, issued = certificate(issued_pem)
        current.update(status="retiring", retire_at=stamp(min(parse_time(current["not_after"]), now() + timedelta(hours=24))))
        store._put(db, "maintenance_settings", current)
        store._put(db, "servers", server)
        response = {"renewed": True, "server_id": identity, "certificate": issued_pem, "ca_certificate": ca, "not_after": issued["not_after"]}
        store._put(db, "maintenance_settings", {"id": request_id, "certificate_id": issued["id"], "response": response, "created_at": stamp()})
        store.audit("endpoint.certificate_renewed", "agent:" + identity, {"server_id": identity, "fingerprint": issued["fingerprint_sha256"]}, db)
        return response


def listing(store):
    with store.read_meta() as db:
        rows = [value for value in store._all(db, "maintenance_settings") if value["id"].startswith(PREFIX)]
        servers = {value["id"]: value for value in store._all(db, "servers")}
        return {"items": [{**row, "hostname": servers.get(row["server_id"], {}).get("hostname", row["server_id"])} for row in sorted(rows, key=lambda row: (row["server_id"], row["not_after"]))], "renewal_window_days": 30, "old_certificate_overlap_hours": 24}


def revoke_preview(store, body, actor):
    identity = body.get("server_id")
    with store.lock, store.meta() as db:
        server = store._get(db, "servers", identity)
        if not server:
            raise ValueError("Select an enrolled server")
        records = [row for row in store._all(db, "maintenance_settings") if row["id"].startswith(PREFIX) and row["server_id"] == identity and row["status"] != "revoked"]
        plan = {"id": "endpoint_revoke:" + secrets.token_hex(16), "server_id": identity, "certificate_ids": sorted(row["id"] for row in records), "status": "draft", "created_by": actor,
                "confirmation_nonce": secrets.token_urlsafe(32), "confirmation_phrase": "REVOKE " + server["hostname"], "expires_at": stamp(now() + timedelta(minutes=10)),
                "message": "All registered identities for this server will stop authenticating. Existing firewall rules remain in force; recovery requires a new one-time certificate recovery token."}
        plan["digest"] = digest({key: plan[key] for key in ("server_id", "certificate_ids", "expires_at")})
        store._put(db, "maintenance_settings", plan)
        return plan


def revoke_apply(store, body, actor):
    with store.lock, store.meta() as db:
        plan = store._get(db, "maintenance_settings", body.get("preview_id", ""))
        if not plan or plan.get("status") != "draft" or parse_time(plan["expires_at"]) <= now() or any(not isinstance(body.get(key), str) or not secrets.compare_digest(body[key], plan[key]) for key in ("digest", "confirmation_nonce", "confirmation_phrase")):
            raise WorkflowConflict("Certificate revocation review expired or changed", {})
        active = sorted(row["id"] for row in store._all(db, "maintenance_settings") if row["id"].startswith(PREFIX) and row["server_id"] == plan["server_id"] and row["status"] != "revoked")
        if active != plan["certificate_ids"]:
            raise WorkflowConflict("Endpoint identities changed; review revocation again", {})
        server = store._get(db, "servers", plan["server_id"])
        if not server:
            raise ValueError("The endpoint is no longer enrolled")
        for identifier in active:
            row = store._get(db, "maintenance_settings", identifier)
            row.update(status="revoked", revoked_at=stamp(), revoked_by=actor)
            store._put(db, "maintenance_settings", row)
        server.update(certificate_registry=True, certificate_revoked=True)
        store._put(db, "servers", server)
        plan.update(status="applied", applied_by=actor, applied_at=stamp())
        plan.pop("confirmation_nonce", None)
        store._put(db, "maintenance_settings", plan)
        store.audit("endpoint.certificates_revoked", actor, {"server_id": server["id"], "count": len(active)}, db)
        return {"status": "revoked", "server_id": server["id"], "revoked_count": len(active)}


def recovery_token(store, identity, actor):
    with store.lock, store.meta() as db:
        server = store._get(db, "servers", identity)
        if not server:
            raise ValueError("Select an existing enrolled server")
        token = secrets.token_urlsafe(48)
        value = {"id": "endpoint_recovery:" + hashlib.sha256(token.encode()).hexdigest(), "server_id": identity,
                 "expires_at": stamp(now() + timedelta(minutes=15)), "used": False, "created_by": actor}
        store._put(db, "maintenance_settings", value)
        store.audit("endpoint.certificate_recovery_created", actor, {"server_id": identity, "expires_at": value["expires_at"]}, db)
        return {"token": token, "server_id": identity, "hostname": server["hostname"], "expires_at": value["expires_at"], "one_time": True}


def recover(store, body, signer):
    token, csr = body.get("token"), body.get("csr")
    if not signer or not isinstance(token, str) or not 32 <= len(token) <= 256 or not isinstance(csr, str) or not 32 <= len(csr) <= 16384:
        raise PermissionError("A valid recovery token and CSR are required")
    with store.lock, store.meta() as db:
        value = store._get(db, "maintenance_settings", "endpoint_recovery:" + hashlib.sha256(token.encode()).hexdigest())
        if not value or parse_time(value["expires_at"]) <= now():
            raise PermissionError("Certificate recovery credentials expired or are invalid")
        csr_hash = hashlib.sha256(csr.encode()).hexdigest()
        if value["used"]:
            if value.get("csr_hash") != csr_hash:
                raise PermissionError("The recovery token is bound to a different key")
            _, issued = certificate(value["response"]["certificate"])
            existing = store._get(db, "maintenance_settings", issued["id"])
            if not existing or existing.get("status") != "active":
                raise PermissionError("The recovered certificate is no longer active")
            return value["response"]
        server = store._get(db, "servers", value["server_id"])
        if not server:
            raise PermissionError("The endpoint is no longer enrolled")
        if body.get("hostname") != server["hostname"]:
            raise PermissionError("This recovery token belongs to a different hostname")
        pem, ca = signer(server["id"], csr)
        record_issued(store, db, server, pem)
        _, issued = certificate(pem)
        for previous in store._all(db, "maintenance_settings"):
            if previous["id"].startswith(PREFIX) and previous["id"] != issued["id"] and previous["server_id"] == server["id"] and previous["status"] != "revoked":
                previous.update(status="revoked", revoked_at=stamp(), revoked_by="identity-recovery")
                store._put(db, "maintenance_settings", previous)
        server["certificate_revoked"] = False
        store._put(db, "servers", server)
        response = {"server_id": server["id"], "certificate": pem, "ca_certificate": ca}
        value.update(used=True, csr_hash=csr_hash, response=response)
        store._put(db, "maintenance_settings", value)
        store.audit("endpoint.certificate_recovered", "recovery:" + server["id"], {"server_id": server["id"]}, db)
        return response
