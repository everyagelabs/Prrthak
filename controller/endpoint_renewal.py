"""Staggered renewal of enrolled endpoint identities under the existing issuer."""
from collections import Counter
from datetime import timedelta
import json
import os
import secrets

from .endpoint_certificates import PREFIX, _write_start
from .firewall import WorkflowConflict
from .server_management import assert_report_allowed
from .store import digest, now, parse_time, stamp


CAPABILITY = "endpoint_certificate_renewal_v1"
BATCH_SIZE = 20
INTERVAL_SECONDS = 60
ROLLOUT = "endpoint_certificate_renewal_rollout"
JOB_PREFIX = "endpoint_certificate_renewal_job:"
REVIEW_PREFIX = "endpoint_certificate_renewal_review:"


def available(app):
    return bool(app.platform and app.signer and not app.demo
                and not (os.environ.get("SEG_POLICY_SIGNED_BUNDLES_DIR") or os.environ.get("SEG_POLICY_SIGNING_TRUST_FILE")))


def _require_super(app, db, principal):
    if (not available(app) or not isinstance(principal, dict)
            or principal.get("role") != "super_admin" or principal.get("auth_type") != "session"):
        raise PermissionError("An installed controller and a named Super Admin session are required for endpoint certificate renewal")
    app.auth._require_super(principal, db)


def _certificate_is_active(row, at):
    return row and row.get("status") == "active" and parse_time(row["not_after"]) > at


def _eligible(server, cert, at):
    return (CAPABILITY in server.get("capabilities", []) and not server.get("certificate_revoked")
            and _certificate_is_active(cert, at) and cert["server_id"] == server["id"]
            and cert.get("public_key_sha256"))


def job(store, db, server_id):
    return store._get(db, "maintenance_settings", JOB_PREFIX + server_id)


def _job_status(value, server, certificates, at):
    if value.get("confirmed_at"):
        return "confirmed"
    if parse_time(value["expires_at"]) <= at:
        return "expired"
    expected = value.get("new_fingerprint") or value["old_fingerprint"]
    if (not server or server.get("certificate_revoked") or server.get("certificate_fingerprint") != expected
            or not _certificate_is_active(certificates.get(PREFIX + expected), at)):
        return "superseded"
    if value.get("new_fingerprint"):
        return "issued"
    return "scheduled" if parse_time(value["not_before"]) > at else "pending"


def _rollout_state(rollout, jobs, servers, certificates, at):
    if not rollout:
        return None, {}
    statuses = {value["server_id"]: _job_status(value, servers.get(value["server_id"]), certificates, at)
                for value in jobs if value["rollout_id"] == rollout["rollout_id"]}
    totals = Counter(statuses.values())
    counts = {status: totals[status] for status in ("scheduled", "pending", "issued", "confirmed", "expired", "superseded")}
    status = ("running" if any(counts[state] for state in ("scheduled", "pending", "issued"))
              else "expired" if counts["expired"] else "complete")
    return {**{key: rollout[key] for key in ("target_count", "scheduled_at", "expires_at")},
            "id": rollout["rollout_id"], "status": status, "counts": counts}, statuses


def registry(db):
    rows = (json.loads(row[0]) for row in db.execute(
        "SELECT data FROM maintenance_settings WHERE id=? OR id LIKE ? OR id LIKE ?",
        (ROLLOUT, PREFIX + "%", JOB_PREFIX + "%")))
    rows = list(rows)
    return ({row["id"]: row for row in rows if row["id"].startswith(PREFIX)},
            [row for row in rows if row["id"].startswith(JOB_PREFIX)],
            next((row for row in rows if row["id"] == ROLLOUT), None))


def listing(servers, certificates, jobs, rollout, available):
    at = now()
    state, statuses = _rollout_state(rollout, jobs, servers, certificates, at)
    details = {value["server_id"]: value for value in jobs if value["server_id"] in statuses}
    return {
        "renewal_available": available,
        "renewal_eligible": sum(bool(_eligible(server, certificates.get(PREFIX + (server.get("certificate_fingerprint") or "")), at))
                                for server in servers.values()),
        "renewal_rollout": state,
        "renewal_details": {identifier: {"renewal_status": status, "renewal_not_before": details[identifier]["not_before"]}
                            for identifier, status in statuses.items()},
    }


def preview(app, body, principal):
    if set(body) - {"server_ids"}:
        raise ValueError("Choose explicit endpoint IDs or leave the selection empty")
    selected = body.get("server_ids")
    if selected is not None and (not isinstance(selected, list) or not 1 <= len(selected) <= 20000
                                 or any(not isinstance(item, str) or not 1 <= len(item) <= 100 for item in selected)):
        raise ValueError("Select enrolled endpoints or leave the selection empty to renew all eligible endpoints")
    selected = set(selected) if selected is not None else None
    store = app.store
    with store.lock, store.meta() as db:
        _write_start(db)
        _require_super(app, db, principal)
        at = now()
        expiry = "data::jsonb->>'expires_at'" if getattr(db, "dialect", "sqlite") == "postgresql" else "json_extract(data,'$.expires_at')"
        db.execute(f"DELETE FROM maintenance_settings WHERE substr(id,1,?)=? AND ({expiry})<=?",
                   (len(REVIEW_PREFIX), REVIEW_PREFIX, stamp(at)))
        certificates, jobs, rollout = registry(db)
        servers = {server["id"]: server for server in store._all(db, "servers")}
        state, _ = _rollout_state(rollout, jobs, servers, certificates, at)
        if state and state["status"] == "running":
            raise WorkflowConflict("An endpoint certificate renewal is already running", {})
        identifiers = sorted(servers if selected is None else selected)
        targets = {identifier: fingerprint for identifier in identifiers
                   if (server := servers.get(identifier)) and (fingerprint := server.get("certificate_fingerprint"))
                   and _eligible(server, certificates.get(PREFIX + fingerprint), at)}
        if not targets:
            raise ValueError("No selected endpoint has an active certificate and a compatible agent")
        review = {"id": REVIEW_PREFIX + secrets.token_hex(16), "targets": targets, "status": "draft",
                  "created_by": principal["actor"], "confirmation_phrase": "RENEW ENDPOINT CERTIFICATES",
                  "confirmation_nonce": secrets.token_urlsafe(32), "expires_at": stamp(at + timedelta(minutes=10)),
                  "target_count": len(targets), "skipped_count": len(identifiers) - len(targets),
                  "batch_size": BATCH_SIZE, "interval_seconds": INTERVAL_SECONDS}
        review["digest"] = digest({key: review[key] for key in ("id", "targets", "expires_at", "batch_size", "interval_seconds")})
        store._put(db, "maintenance_settings", review)
        return {key: value for key, value in review.items() if key not in ("created_by", "targets")}


def apply(app, body, principal):
    if set(body) != {"preview_id", "digest", "confirmation_nonce", "confirmation_phrase"}:
        raise ValueError("Confirm the exact reviewed renewal targets")
    store = app.store
    with store.lock, store.meta() as db:
        _write_start(db)
        _require_super(app, db, principal)
        at = now()
        identifier = body.get("preview_id")
        review = store._get(db, "maintenance_settings", identifier) if isinstance(identifier, str) and identifier.startswith(REVIEW_PREFIX) else None
        if (not review or review["status"] != "draft" or review["created_by"] != principal["actor"] or parse_time(review["expires_at"]) <= at
                or any(not isinstance(body.get(key), str) or not secrets.compare_digest(body[key].encode(), review[key].encode())
                       for key in ("digest", "confirmation_nonce", "confirmation_phrase"))):
            raise WorkflowConflict("Endpoint certificate renewal review expired or changed", {})
        certificates, jobs, previous = registry(db)
        servers = {server["id"]: server for server in store._all(db, "servers")}
        state, _ = _rollout_state(previous, jobs, servers, certificates, at)
        if state and state["status"] == "running":
            raise WorkflowConflict("An endpoint certificate renewal is already running", {})
        expires_at = stamp(at + timedelta(days=3))
        rollout = {"id": ROLLOUT, "rollout_id": secrets.token_hex(16), "target_count": len(review["targets"]),
                   "scheduled_at": stamp(at), "expires_at": expires_at}
        new_jobs = []
        for index, (server_id, fingerprint) in enumerate(sorted(review["targets"].items())):
            server = servers.get(server_id)
            if (not server or server.get("certificate_fingerprint") != fingerprint
                    or not _eligible(server, certificates.get(PREFIX + fingerprint), at)):
                raise WorkflowConflict("Endpoint identities changed; review renewal again", {})
            assert_report_allowed(store, db, server_id)
            value = {"id": JOB_PREFIX + server_id, "server_id": server_id, "rollout_id": rollout["rollout_id"],
                     "old_fingerprint": fingerprint, "expires_at": expires_at,
                     "not_before": stamp(at + timedelta(seconds=index * INTERVAL_SECONDS // BATCH_SIZE))}
            new_jobs.append(value)
            store._put(db, "maintenance_settings", value)
        store._put(db, "maintenance_settings", rollout)
        review["status"] = "applied"
        review.pop("confirmation_nonce", None)
        review.pop("targets", None)
        store._put(db, "maintenance_settings", review)
        store.audit("endpoint.certificate_renewal_scheduled", principal["actor"],
                    {"rollout_id": rollout["rollout_id"], "target_count": rollout["target_count"]}, db)
        state, _ = _rollout_state(rollout, new_jobs, servers, certificates, at)
        return state


def assignment(store, db, server):
    if CAPABILITY not in server.get("capabilities", []) or server.get("certificate_revoked"):
        return None
    value = job(store, db, server["id"])
    at = now()
    if not value or value.get("confirmed_at") or not parse_time(value["not_before"]) <= at < parse_time(value["expires_at"]):
        return None
    if server.get("certificate_fingerprint") != (value.get("new_fingerprint") or value["old_fingerprint"]):
        return None
    return {"id": value["rollout_id"], **{key: value[key] for key in ("server_id", "old_fingerprint", "not_before", "expires_at")},
            "new_fingerprint": value.get("new_fingerprint", "")}


def permitted_job(store, db, server, rollout_id):
    value = job(store, db, server["id"])
    at = now()
    if (not value or value["rollout_id"] != rollout_id
            or not parse_time(value["not_before"]) <= at < parse_time(value["expires_at"])
            or server.get("certificate_revoked")
            or server.get("certificate_fingerprint") != (value.get("new_fingerprint") or value["old_fingerprint"])):
        raise PermissionError("This endpoint certificate renewal is not scheduled for the presented identity")
    return value


def reserve_issuance(store, db, rollout_id):
    rollout = store._get(db, "maintenance_settings", ROLLOUT)
    if not rollout or rollout["rollout_id"] != rollout_id:
        raise PermissionError("This endpoint certificate renewal rollout is no longer current")
    bucket = int(now().timestamp()) // INTERVAL_SECONDS
    count = rollout.get("issuance_count", 0) if rollout.get("issuance_bucket") == bucket else 0
    if count >= BATCH_SIZE:
        raise WorkflowConflict("The endpoint certificate issuance limit is reached; retry shortly", {})
    rollout.update(issuance_bucket=bucket, issuance_count=count + 1)
    store._put(db, "maintenance_settings", rollout)


def invalidate_after_recovery(db):
    prefix = "endpoint_certificate_renewal_"
    db.execute("DELETE FROM maintenance_settings WHERE substr(id,1,?)=?", (len(prefix), prefix))
