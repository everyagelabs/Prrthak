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


def _write_start(db):
    from .fleet_enrollment import _transaction_start
    _transaction_start(db)


def record_issued(store, db, server, pem, *, csr=None):
    # Private Store test signers can return placeholders; they cannot produce a
    # usable TLS credential. Real certificates always enter the exact registry.
    if not isinstance(pem, str) or "BEGIN CERTIFICATE" not in pem:
        return
    _write_start(db)
    _, value = certificate(pem)
    if value["server_id"] != server["id"]:
        raise ValueError("Issued endpoint identity does not match the enrolled server")
    existing = store._get(db, "maintenance_settings", value["id"])
    if existing and existing.get("status") == "revoked":
        raise PermissionError("A revoked endpoint certificate cannot be reactivated")
    from .fleet_enrollment import register_issued_key, _csr_key, _certificate_key
    key = _certificate_key(pem)
    if csr is not None and _csr_key(csr) != key:
        raise ValueError("The endpoint certificate does not match its requested key")
    register_issued_key(store, db, server, pem)
    value["public_key_sha256"] = key
    if not existing:
        store._put(db, "maintenance_settings", {**value, "status": "active", "issued_at": stamp()})
    elif existing.get("public_key_sha256") != key:
        if existing.get("public_key_sha256") is not None:
            raise ValueError("Endpoint certificate public-key metadata changed unexpectedly")
        existing["public_key_sha256"] = key
        store._put(db, "maintenance_settings", existing)
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
            if current.get("public_key_sha256"):
                return current
    with store.lock, store.meta() as db:
        _write_start(db)
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
        if not current.get("public_key_sha256"):
            # A verified live mTLS leaf can complete a pre-0.10 key census.
            # Preserve server latest-certificate fields and retirement state.
            from cryptography.hazmat.primitives import serialization
            from .fleet_enrollment import register_issued_key
            key = register_issued_key(store, db, server, leaf.public_bytes(serialization.Encoding.PEM).decode())
            current["public_key_sha256"] = key
            store._put(db, "maintenance_settings", current)
        return current


def renew(store, identity, der, body, signer):
    current = authorize(store, identity, der)
    rollout_id = body.get("renewal_id")
    action = body.get("action", "issue")
    if action not in ("issue", "probe", "confirm") or (action != "issue" or rollout_id is not None) and (not isinstance(rollout_id, str) or len(rollout_id) != 32):
        raise ValueError("Provide a valid endpoint certificate renewal action and identifier")
    if action != "issue":
        return _prove_renewal(store, identity, current, rollout_id, action, split_channels=body.get("split_channels") == "true")
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
    key_fingerprint = hashlib.sha256(public_key).hexdigest()
    request_key = [identity, current["fingerprint_sha256"], key_fingerprint]
    if rollout_id:
        request_key.append(rollout_id)
    request_id = "endpoint_renewal:" + digest(request_key)
    with store.lock, store.meta() as db:
        _write_start(db)
        current = store._get(db, "maintenance_settings", current["id"])
        at = now()
        if (not current or current.get("status") not in ("active", "retiring") or parse_time(current["not_after"]) <= at
                or current.get("retire_at") and parse_time(current["retire_at"]) <= at):
            raise PermissionError("Endpoint identity changed before renewal")
        server = store._get(db, "servers", identity)
        if not server:
            raise PermissionError("The endpoint is no longer enrolled")
        from .server_management import assert_report_allowed
        from .endpoint_renewal import job, permitted_job, reserve_issuance
        assert_report_allowed(store, db, identity)
        scheduled = None
        if rollout_id:
            scheduled = permitted_job(store, db, server, rollout_id)
            if (current["fingerprint_sha256"] != scheduled["old_fingerprint"] or current["status"] != "active"
                    or current["public_key_sha256"] != key_fingerprint):
                raise PermissionError("Scheduled renewal requires the current endpoint certificate and its existing key")
        else:
            scheduled_job = job(store, db, identity)
            if (scheduled_job and not scheduled_job.get("confirmed_at")
                    and scheduled_job["old_fingerprint"] == current["fingerprint_sha256"]
                    and parse_time(scheduled_job["not_before"]) <= now() < parse_time(scheduled_job["expires_at"])
                    and server.get("certificate_fingerprint") in (scheduled_job["old_fingerprint"], scheduled_job.get("new_fingerprint"))):
                return {"renewed": False, "not_after": current["not_after"]}
        previous = store._get(db, "maintenance_settings", request_id)
        if previous:
            issued = store._get(db, "maintenance_settings", previous["certificate_id"])
            if not issued or issued.get("status") != "active":
                raise PermissionError("The renewed certificate is no longer active")
            return previous["response"]
        if not scheduled and parse_time(current["not_after"]) - now() > timedelta(days=30):
            return {"renewed": False, "renew_after": stamp(parse_time(current["not_after"]) - timedelta(days=30)), "not_after": current["not_after"]}
        if scheduled:
            reserve_issuance(store, db, rollout_id)
        # Signing occurs inside the serialized transaction; a revocation cannot
        # race a successful renewal and leave a credential outside the registry.
        issued_pem, ca = signer(identity, csr)
        issued_leaf, issued = certificate(issued_pem)
        if scheduled and parse_time(issued["not_after"]) <= parse_time(current["not_after"]):
            raise WorkflowConflict("The issuer must extend the endpoint certificate validity", {})
        if scheduled:
            presented = x509.load_der_x509_certificate(der)
            issuer = x509.load_pem_x509_certificate(ca.encode())
            from cryptography.exceptions import InvalidSignature
            try:
                presented.verify_directly_issued_by(issuer)
                issued_leaf.verify_directly_issued_by(issuer)
            except (ValueError, TypeError, InvalidSignature) as error:
                raise WorkflowConflict("Scheduled renewal requires the existing endpoint certificate issuer", {}) from error
        record_issued(store, db, server, issued_pem, csr=csr)
        if scheduled:
            scheduled.update(new_fingerprint=issued["fingerprint_sha256"], issued_at=stamp())
            store._put(db, "maintenance_settings", scheduled)
        else:
            current.update(status="retiring", retire_at=stamp(min(parse_time(current["not_after"]), now() + timedelta(hours=24))))
            store._put(db, "maintenance_settings", current)
        store._put(db, "servers", server)
        response = {"renewed": True, "server_id": identity, "certificate": issued_pem, "ca_certificate": ca, "not_after": issued["not_after"]}
        store._put(db, "maintenance_settings", {"id": request_id, "certificate_id": issued["id"], "response": response, "created_at": stamp()})
        store.audit("endpoint.certificate_renewed", "agent:" + identity, {"server_id": identity, "fingerprint": issued["fingerprint_sha256"]}, db)
        return response


def probe_discovery(store, identity, der, body):
    rollout_id = body.get("certificate_renewal_probe")
    if set(body) != {"certificate_renewal_probe"} or not isinstance(rollout_id, str) or len(rollout_id) != 32:
        raise ValueError("Provide only the endpoint certificate renewal identifier")
    return _prove_renewal(store, identity, authorize(store, identity, der), rollout_id, "probe-discovery")


def _prove_renewal(store, identity, current, rollout_id, action, *, split_channels=False):
    from .endpoint_renewal import permitted_job
    from .server_management import assert_report_allowed
    with store.lock, store.meta() as db:
        _write_start(db)
        assert_report_allowed(store, db, identity)
        server = store._get(db, "servers", identity)
        if not server:
            raise PermissionError("The endpoint is no longer enrolled")
        value = permitted_job(store, db, server, rollout_id)
        candidate = store._get(db, "maintenance_settings", current["id"])
        if (not candidate or candidate["status"] != "active" or parse_time(candidate["not_after"]) <= now()
                or value.get("new_fingerprint") != candidate["fingerprint_sha256"]):
            raise PermissionError("Proof requires the exact renewed endpoint certificate")
        if action == "probe" and (not value.get("probed_at") or split_channels and not value.get("split_channels")):
            value.update(probed_at=stamp(), split_channels=split_channels)
            store._put(db, "maintenance_settings", value)
        if action == "probe-discovery" and not value.get("discovery_probed_at"):
            value["discovery_probed_at"] = stamp()
            store._put(db, "maintenance_settings", value)
        if action == "confirm" and not value.get("confirmed_at"):
            if not value.get("probed_at") or value.get("split_channels") and not value.get("discovery_probed_at"):
                raise PermissionError("Prove the renewed endpoint certificate on the required listeners before confirming activation")
            previous = store._get(db, "maintenance_settings", PREFIX + value["old_fingerprint"])
            if previous and previous["status"] == "active":
                previous.update(status="retiring", retire_at=stamp(min(parse_time(previous["not_after"]), now() + timedelta(hours=24))))
                store._put(db, "maintenance_settings", previous)
            value["confirmed_at"] = stamp()
            store._put(db, "maintenance_settings", value)
            store.audit("endpoint.certificate_renewal_confirmed", "agent:" + identity,
                        {"server_id": identity, "rollout_id": rollout_id, "fingerprint": candidate["fingerprint_sha256"]}, db)
        return {"action": action, "renewal_id": rollout_id, "fingerprint": candidate["fingerprint_sha256"]}


def listing(store, *, renewal_available=False):
    from .endpoint_renewal import registry, listing as renewal_listing
    with store.read_meta() as db:
        certificates, jobs, rollout = registry(db)
        servers = {value["id"]: value for value in store._all(db, "servers")}
        renewal = renewal_listing(servers, certificates, jobs, rollout, renewal_available)
        details = renewal.pop("renewal_details")
        return {"items": [{**row, **details.get(row["server_id"], {}),
                          "hostname": servers.get(row["server_id"], {}).get("hostname", row["server_id"])}
                         for row in sorted(certificates.values(), key=lambda row: (row["server_id"], row["not_after"]))],
                "renewal_window_days": 30, "old_certificate_overlap_hours": 24, **renewal}


def revoke_preview(store, body, actor):
    identity = body.get("server_id")
    with store.lock, store.meta() as db:
        _write_start(db)
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
        _write_start(db)
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
        _write_start(db)
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
        _write_start(db)
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
        record_issued(store, db, server, pem, csr=csr)
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
