"""Revocable, bounded-lifetime fleet bootstrap with per-key endpoint identities.

Profiles, hashed credential lookups and immutable public-key receipts use separate
indexed namespaces in the existing token table. No private endpoint key is sent
to the controller, and restoring a database discards profile bootstrap authority
while retaining used key receipts through the existing recovery safety merge.
"""
from __future__ import annotations

import hashlib
import json
import re
import secrets
import uuid
from datetime import timedelta

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization

from .store import now, parse_time, stamp

PROFILE = "fleet_profile:"
CREDENTIAL = "fleet_credential:"
KEY = "enrollment_key:"


def _profile_id(value):
    try:
        if not isinstance(value, str) or str(uuid.UUID(value)) != value:
            raise ValueError()
    except (ValueError, AttributeError):
        raise ValueError("Select a valid fleet enrollment profile") from None
    return value


def _public(value):
    result = {key: value[key] for key in ("name", "created_at", "created_by", "expires_at", "enrollment_count")}
    result["id"] = value["profile_id"]
    for key in ("revoked_at", "revoked_by"):
        if value.get(key):
            result[key] = value[key]
    result["status"] = "revoked" if value.get("revoked") else "expired" if parse_time(value["expires_at"]) <= now() else "active"
    return result


def listing(store, *, limit=50, offset=0):
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 200 or isinstance(offset, bool) or not isinstance(offset, int) or not 0 <= offset <= 1_000_000:
        raise ValueError("Use a fleet-profile page size of 1 to 200 and a valid offset")
    with store.read_meta() as db:
        total = db.execute("SELECT COUNT(*) FROM tokens WHERE id LIKE ?", (PROFILE + "%",)).fetchone()[0]
        created = "(data::jsonb->>'created_at')" if getattr(db, "dialect", "sqlite") == "postgresql" else "json_extract(data,'$.created_at')"
        rows = db.execute("SELECT data FROM tokens WHERE id LIKE ? ORDER BY " + created + " DESC,id DESC LIMIT ? OFFSET ?", (PROFILE + "%", limit, offset)).fetchall()
        items = [_public(json.loads(row[0])) for row in rows]
    return {"items": items, "total": total, "limit": limit, "offset": offset}


def _transaction_start(db):
    # PostgresStore.meta already holds its cross-controller advisory lock.
    # SQLite must acquire its writer before the first read, including separate
    # Store instances/processes sharing the same database.
    if getattr(db, "dialect", "sqlite") != "postgresql" and not db.in_transaction:
        db.execute("BEGIN IMMEDIATE")


def create(store, name, validity_hours, actor, *, issued_at=None):
    if not isinstance(name, str) or not name.strip() or len(name) > 120 or any(ord(char) < 32 for char in name):
        raise ValueError("Provide a fleet profile name of up to 120 printable characters")
    if isinstance(validity_hours, bool) or not isinstance(validity_hours, int) or not 1 <= validity_hours <= 720:
        raise ValueError("Fleet enrollment validity must be 1 to 720 hours")
    at = parse_time(issued_at) if issued_at else parse_time(stamp())
    identifier = str(uuid.uuid4())
    token = secrets.token_urlsafe(48)
    expires = stamp(at + timedelta(hours=validity_hours))
    value = {"id": PROFILE + identifier, "kind": "fleet_profile", "profile_id": identifier,
             "name": name.strip(), "created_at": stamp(at), "created_by": actor,
             "expires_at": expires, "enrollment_count": 0, "revoked": False, "used": False}
    credential = {"id": CREDENTIAL + hashlib.sha256(token.encode()).hexdigest(), "kind": "fleet_credential",
                  "profile_id": identifier, "expires_at": expires, "used": False}
    with store.lock, store.meta() as db:
        _transaction_start(db)
        _backfill_legacy_keys(store, db)
        store._put(db, "tokens", value)
        store._put(db, "tokens", credential)
        store.audit("fleet_enrollment.created", actor, {"profile_id": identifier, "name": value["name"], "expires_at": expires}, db)
    return _public(value), token


def revoke(store, identifier, actor):
    identifier = _profile_id(identifier)
    with store.lock, store.meta() as db:
        _transaction_start(db)
        record = store._get(db, "tokens", PROFILE + identifier)
        if not record or record.get("kind") != "fleet_profile":
            raise KeyError(identifier)
        if not record.get("revoked"):
            record.update(revoked=True, revoked_at=stamp(), revoked_by=actor)
            store._put(db, "tokens", record)
            store.audit("fleet_enrollment.revoked", actor, {"profile_id": identifier, "enrollment_count": record["enrollment_count"]}, db)
        return _public(record)


def _csr_key(csr):
    try:
        request = x509.load_pem_x509_csr(csr.encode())
        if not request.is_signature_valid:
            raise ValueError()
        encoded = request.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    except (ValueError, TypeError, UnsupportedAlgorithm):
        raise ValueError("Provide a valid signed endpoint certificate request") from None
    return hashlib.sha256(encoded).hexdigest()


def _certificate_key(pem):
    try:
        leaf = x509.load_pem_x509_certificate(pem.encode())
        encoded = leaf.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    except (ValueError, TypeError, AttributeError, UnsupportedAlgorithm):
        raise ValueError("The endpoint issuer did not return a valid certificate") from None
    return hashlib.sha256(encoded).hexdigest()


def _store_key(store, db, key, *, hostname, response, profile_id=None, token_id=None):
    previous = store._get(db, "tokens", KEY + key)
    record = {"id": KEY + key, "kind": "enrollment_key", "used": True,
              "hostname": hostname, "server_id": response["server_id"], "response": dict(response),
              "profile_id": profile_id, "origin_token_id": token_id, "created_at": stamp(),
              "expires_at": "9999-12-31T23:59:59Z"}
    if previous:
        if previous.get("origin_kind") == "certificate_issuance" and previous.get("server_id") == response["server_id"] and token_id is not None and profile_id is None:
            # A legacy mTLS census may have indexed the public key before its
            # retained one-use enrollment receipt is migrated. That trusted
            # receipt can add its original bootstrap provenance for the SAME
            # identity; it cannot move the key to another server.
            store._put(db, "tokens", record)
            return
        if any(previous.get(field) != record.get(field) for field in ("hostname", "server_id", "profile_id", "origin_token_id")):
            raise PermissionError("This endpoint key is already bound to another enrollment identity")
        return
    store._put(db, "tokens", record)


def register_issued_key(store, db, server, pem):
    """Bind EVERY issued/censused endpoint key, including renewals/recovery.

    A certificate-issuance claim is not bootstrap retry authority. Existing
    enrollment provenance is retained unchanged for same-identity renewals.
    """
    key = _certificate_key(pem)
    previous = store._get(db, "tokens", KEY + key)
    if previous:
        if previous.get("kind") != "enrollment_key" or previous.get("server_id") != server["id"] or previous.get("used") is not True:
            raise PermissionError("This endpoint key is already bound to another enrollment identity")
        return key
    record = {"id": KEY + key, "kind": "enrollment_key", "origin_kind": "certificate_issuance",
              "used": True, "server_id": server["id"], "hostname": server.get("hostname", server["id"]),
              "profile_id": None, "origin_token_id": None, "created_at": stamp(),
              "expires_at": "9999-12-31T23:59:59Z"}
    store._put(db, "tokens", record)
    return key


def register_legacy_key(store, db, token_id, hostname, csr, response):
    # Existing unit-test signers can return placeholders, which can never be an
    # actual TLS identity. Real issuance always gets a global public-key claim.
    if not isinstance(response.get("certificate"), str) or "BEGIN CERTIFICATE" not in response["certificate"]:
        return
    key = _csr_key(csr)
    if _certificate_key(response["certificate"]) != key:
        raise ValueError("The endpoint certificate does not match its requested key")
    _store_key(store, db, key, hostname=hostname, response=response, token_id=token_id)


def _backfill_legacy_keys(store, db):
    # One-time per historical used token. Fixed indexed namespaces avoid
    # decoding fleet profiles/receipts or repeatedly parsing their certificates.
    rows = db.execute("SELECT data FROM tokens WHERE id NOT LIKE ? AND id NOT LIKE ? AND id NOT LIKE ?", (PROFILE + "%", CREDENTIAL + "%", KEY + "%")).fetchall()
    for row in rows:
        value = json.loads(row[0])
        response = value.get("response")
        if not value.get("used") or value.get("fleet_key_indexed") or not isinstance(response, dict):
            continue
        pem = response.get("certificate")
        if not isinstance(pem, str) or "BEGIN CERTIFICATE" not in pem:
            continue
        key = _certificate_key(pem)
        _store_key(store, db, key, hostname=value.get("hostname"), response=response, token_id=value["id"])
        value["fleet_key_indexed"] = True
        store._put(db, "tokens", value)
    _backfill_issued_keys(store, db)


def _backfill_issued_keys(store, db):
    from .endpoint_certificates import certificate
    known_by_certificate = {}
    rows = db.execute("SELECT data FROM maintenance_settings WHERE id LIKE ? OR id LIKE ?", ("endpoint_renewal:%", "endpoint_recovery:%")).fetchall()
    for row in rows:
        receipt = json.loads(row[0])
        response = receipt.get("response")
        if not isinstance(response, dict) or not isinstance(response.get("certificate"), str):
            continue
        _, identity = certificate(response["certificate"])
        if response.get("server_id") != identity["server_id"] or receipt.get("certificate_id", identity["id"]) != identity["id"] or receipt.get("server_id", identity["server_id"]) != identity["server_id"]:
            raise ValueError("Endpoint certificate key history has inconsistent identity receipts")
        server = store._get(db, "servers", identity["server_id"]) or {"id": identity["server_id"]}
        key = register_issued_key(store, db, server, response["certificate"])
        known_by_certificate[identity["id"]] = key
        registry = store._get(db, "maintenance_settings", identity["id"])
        if registry and registry.get("server_id") == identity["server_id"]:
            if registry.get("public_key_sha256") not in (None, key):
                raise ValueError("Endpoint certificate key history has conflicting public-key metadata")
            registry["public_key_sha256"] = key
            store._put(db, "maintenance_settings", registry)
    # Decode retained bootstrap receipts once, not once per registry row. The
    # first legacy census remains linear in retained public certificate history.
    claims = {}
    for claim_row in db.execute("SELECT data FROM tokens WHERE id LIKE ?", (KEY + "%",)).fetchall():
        claim = json.loads(claim_row[0])
        claims[claim["id"]] = claim
        response = claim.get("response")
        if isinstance(response, dict) and isinstance(response.get("certificate"), str):
            _, identity = certificate(response["certificate"])
            known_by_certificate[identity["id"]] = _certificate_key(response["certificate"])
    unknown = 0
    for row in db.execute("SELECT data FROM maintenance_settings WHERE id LIKE ?", ("endpoint_certificate:%",)).fetchall():
        registry = json.loads(row[0])
        key = registry.get("public_key_sha256")
        if not isinstance(key, str) or re.fullmatch(r"[a-f0-9]{64}", key) is None:
            # A retained one-use response supplies this certificate's key even
            # when the old registry predates explicit SPKI fields.
            found = known_by_certificate.get(registry["id"])
            if found is None:
                unknown += 1
                continue
            key = found
            registry["public_key_sha256"] = key
            store._put(db, "maintenance_settings", registry)
        previous = claims.get(KEY + key)
        if previous:
            if previous.get("server_id") != registry.get("server_id"):
                raise PermissionError("A historical endpoint key is bound to conflicting identities")
        else:
            claim = {"id": KEY + key, "kind": "enrollment_key", "origin_kind": "certificate_issuance",
                "used": True, "server_id": registry["server_id"], "hostname": registry["server_id"], "profile_id": None,
                "origin_token_id": None, "created_at": stamp(), "expires_at": "9999-12-31T23:59:59Z"}
            store._put(db, "tokens", claim)
            claims[claim["id"]] = claim
    if unknown:
        raise ValueError("Endpoint certificate key history is incomplete for " + str(unknown) + " identity records; allow upgraded endpoints to synchronize over mTLS or complete a reviewed public-certificate census before creating fleet enrollment")


def _active_profile(store, db, token_id):
    credential = store._get(db, "tokens", CREDENTIAL + token_id)
    if not credential or credential.get("kind") != "fleet_credential":
        raise PermissionError("Enrollment token is invalid, expired or revoked")
    record = store._get(db, "tokens", PROFILE + credential.get("profile_id", ""))
    if not record or record.get("kind") != "fleet_profile" or record.get("revoked") or parse_time(record["expires_at"]) <= now() or parse_time(credential["expires_at"]) <= now():
        raise PermissionError("Fleet enrollment is expired or revoked")
    return record


def _retry_response(store, db, record, hostname, profile):
    response = record.get("response")
    if record.get("profile_id") != profile["profile_id"] or record.get("hostname") != hostname or not isinstance(response, dict):
        raise PermissionError("This endpoint key is already bound to another enrollment identity")
    from .server_management import assert_report_allowed
    assert_report_allowed(store, db, response["server_id"])
    server = store._get(db, "servers", response["server_id"])
    if not server or server.get("certificate_revoked"):
        raise PermissionError("The enrolled endpoint identity is unavailable or revoked")
    from .endpoint_certificates import certificate
    leaf, identity = certificate(response["certificate"])
    registry = store._get(db, "maintenance_settings", identity["id"])
    if not registry or registry.get("server_id") != response["server_id"] or registry.get("status") not in ("active", "retiring") or not leaf.not_valid_before_utc <= now() < leaf.not_valid_after_utc or registry.get("retire_at") and parse_time(registry["retire_at"]) <= now():
        raise PermissionError("The issued endpoint certificate is revoked, expired or superseded")
    return dict(response)


def enroll(store, db, token_id, hostname, csr, signer):
    """Called inside the same mutation transaction as enrollment/revocation."""
    profile = _active_profile(store, db, token_id)
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,252}", hostname):
        raise ValueError("Provide the server's valid hostname")
    key = _csr_key(csr)
    previous = store._get(db, "tokens", KEY + key)
    if previous:
        return _retry_response(store, db, previous, hostname, profile)
    identifier = str(uuid.uuid4())
    certificate, ca_certificate = signer(identifier, csr)
    if _certificate_key(certificate) != key:
        raise ValueError("The endpoint certificate does not match its requested key")
    response = {"server_id": identifier, "certificate": certificate, "ca_certificate": ca_certificate}
    server = store._new_enrollment_server(identifier, hostname)
    store._collector_state(server, store._all(db, "sessions"))
    _store_key(store, db, key, hostname=hostname, response=response, profile_id=profile["profile_id"])
    from .endpoint_certificates import record_issued
    record_issued(store, db, server, certificate)
    store._put(db, "servers", server)
    profile["enrollment_count"] += 1
    store._put(db, "tokens", profile)
    store.compile_all(db)
    store.audit("agent.enrolled", "enrollment", {"server_id": identifier, "hostname": hostname, "enrollment_profile_id": profile["profile_id"]}, db)
    return response
