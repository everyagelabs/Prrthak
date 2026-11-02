"""Recipient-sealed, all-controller barriers for reviewed provider changes.

The shared database contains public authority epochs and encrypted recipient
payloads. A candidate login never provisions a person. Only the independently
approved cutover grants the reviewed new-tenant Super Admin and invalidates
old sessions/unfinished firewall authority. Local fixed managers retain exact
rollback state; a failed member holds or rolls back the entire transition.
"""
from __future__ import annotations

import copy
import hashlib
import hmac
import json
import os
import secrets

from .appliance import Appliance, NodeClient
from .auth import AuthDenied, EntraAuth, EntraConfig
from .firewall import WorkflowConflict
from .store import digest, now, stamp, parse_time

AUTHORITY = "controller_provider_authority"
CONTROL = "controller_provider_transition"
PLAN_PREFIX = "controller_provider_plan:"
TERMINAL = {"completed", "rolled_back"}
AUTH_KEYS = ("SEG_ENTRA_TENANT_ID", "SEG_ENTRA_CLIENT_ID", "SEG_ENTRA_REDIRECT_URI", "SEG_BOOTSTRAP_SUPER_ADMIN_OID")


def authority_binding(app, db):
    value = app.store._get(db, "maintenance_settings", AUTHORITY)
    return {"fingerprint": value["fingerprint"], "epoch": value.get("epoch", "")} if value else {
        "fingerprint": app.auth.config.fingerprint, "epoch": os.environ.get("PRTHAK_PROVIDER_EPOCH", "")}


def assert_review_current(app, db, plan):
    if plan.get("provider_authority") != authority_binding(app, db):
        raise WorkflowConflict("Sign-in authority changed; create a fresh setup review and candidate verification", {})


def permitted(app, db=None):
    if getattr(app, "demo", False):
        return True
    if db is None:
        with app.store.read_meta() as connection:
            return permitted(app, connection)
    value = app.store._get(db, "maintenance_settings", AUTHORITY)
    if not value:
        return True
    config = app.auth.config
    return bool(config.enabled and hmac.compare_digest(value["fingerprint"], config.fingerprint)
                and hmac.compare_digest(value.get("epoch", ""), os.environ.get("PRTHAK_PROVIDER_EPOCH", "")))


def assert_current(app, db=None):
    if not permitted(app, db):
        raise AuthDenied("This controller is converging to the reviewed sign-in authority; use a current controller")


def assert_join_current(app, db):
    assert_current(app, db)
    transition = app.store._get(db, "maintenance_settings", CONTROL)
    if transition and transition.get("phase") not in TERMINAL:
        raise AuthDenied("Finish the reviewed provider transition before admitting another controller")


def assert_auth_current(auth, db):
    value = auth.store._get(db, "maintenance_settings", AUTHORITY)
    if value and (value["fingerprint"] != auth.config.fingerprint or value.get("epoch", "") != os.environ.get("PRTHAK_PROVIDER_EPOCH", "")):
        raise AuthDenied("This controller has a superseded sign-in authority")


def _approved(store, db, proof, fingerprint):
    from . import approvals
    if not approvals.authorized(store, db, proof) or proof.get("mode") != "single_admin":return False
    subject = proof.get("requester", {})
    user = store._get(db, "auth_users", subject.get("user_id", ""))
    return bool(user and user.get("enabled") is True and user.get("role") == "super_admin"
                and subject.get("role") == "super_admin"
                and (subject.get("auth_provider", "entra") != "entra" or subject.get("auth_config") == fingerprint))


def members(manager):
    api = Appliance(manager)
    if not manager.app.store.ha:
        return [{"id": manager.app.controller_id, "ip": "local", "site": manager.app.site}]
    values = api._config().get("members", [])
    if not values or any(not member.get("transport_public_key") for member in values):
        raise ValueError("Every registered controller needs its persistent transport identity before provider migration")
    return [{key: member[key] for key in ("id", "ip", "site", "transport_public_key")} for member in values]


def sealed(manager, value, targets=None):
    targets = targets or members(manager)
    if not manager.app.store.ha:
        return {targets[0]["id"]: {"local_ref": manager.vault.put(json.dumps(value))}}
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from .cluster_bootstrap import _seal
    result = {}
    for member in targets:
        try:
            public = serialization.load_pem_public_key(member["transport_public_key"].encode())
            if not isinstance(public, rsa.RSAPublicKey) or public.key_size < 3072:
                raise ValueError()
        except (ValueError, TypeError, KeyError):
            raise ValueError("Registered controller transport keys must be strong RSA identities") from None
        result[member["id"]] = _seal(value, public, member["id"])
    return result


def unseal(manager, recipients):
    node = manager.app.controller_id
    envelope = recipients.get(node)
    if not envelope:
        raise ValueError("This controller is outside the reviewed provider membership")
    if "local_ref" in envelope:
        if manager.app.store.ha:
            raise ValueError("A local secret reference cannot cross controllers")
        return json.loads(manager.vault.get(envelope["local_ref"]))
    from .cluster_bootstrap import _keys
    return manager._unseal(envelope, _keys(Appliance(manager)), node)


def publish_plan(manager, plan, request):
    if not manager.app.store.ha:
        return
    payload = {"plan": {key: value for key, value in plan.items() if key != "request_ref"}, "request": request}
    with manager.app.store.lock, manager.app.store.meta() as db:
        manager.app.store._put(db, "maintenance_settings", {"id": PLAN_PREFIX + plan["id"],
            "recipients": sealed(manager, payload), "updates": {}, "created_at": plan["created_at"]})


def shared_plan(manager, identifier):
    if not manager.app.store.ha:
        return None
    with manager.app.store.read_meta() as db:
        record = manager.app.store._get(db, "maintenance_settings", PLAN_PREFIX + identifier)
    if not record:
        return None
    value = unseal(manager, record["recipients"])
    plan = value["plan"]
    if plan.get("id") != identifier:
        raise ValueError("Sealed provider review belongs to another identity")
    plan.update(record.get("updates", {}))
    if parse_time(plan["expires_at"]) <= now():
        raise WorkflowConflict("Setup review expired; create a fresh review", {})
    from .platform import _private_json, _read_json
    local_path = manager.root / "setup-plans" / (identifier + ".json")
    local = _read_json(local_path) or {}
    reference = local.get("request_ref")
    try:
        if not reference or json.loads(manager.vault.get(reference)) != value["request"]:
            reference = None
    except (KeyError, ValueError, OSError):
        reference = None
    plan["request_ref"] = reference or manager.vault.put(json.dumps(value["request"]))
    _private_json(local_path, plan)
    return plan


def update_plan(manager, plan):
    if not manager.app.store.ha:
        return
    with manager.app.store.lock, manager.app.store.meta() as db:
        record = manager.app.store._get(db, "maintenance_settings", PLAN_PREFIX + plan["id"])
        if not record:
            raise ValueError("The shared provider proposal is missing")
        record["updates"] = {key: plan[key] for key in ("candidate_login_verified", "candidate_verified_at", "candidate_identity", "approval", "job_id") if key in plan}
        manager.app.store._put(db, "maintenance_settings", record)


def public(record):
    if not record:
        return None
    return {key: copy.deepcopy(record.get(key)) for key in ("id", "phase", "members", "acks", "errors", "created_at", "created_by", "updated_at", "completed_at", "review_id")}


def get(manager):
    with manager.app.store.read_meta() as db:
        return public(manager.app.store._get(db, "maintenance_settings", CONTROL))


def queue(manager, plan, request):
    from .approvals import proof
    approval = proof(plan)
    targets = members(manager)
    epoch = secrets.token_hex(16)
    request = copy.deepcopy(request)
    request.update(provider_change=True, provider_epoch=epoch, candidate_login_verified=True)
    with manager.app.store.lock, manager.app.store.meta() as db:
        if getattr(db, "dialect", "sqlite") == "sqlite":
            db.execute("BEGIN IMMEDIATE")
        recovery=manager.app.store._get(db,'maintenance_settings','recovery_control:active')
        if recovery and recovery.get('phase') not in ('completed','cancelled'):
            raise WorkflowConflict('Finish the current database recovery before changing sign-in authority',{})
        assert_current(manager.app, db)
        assert_review_current(manager.app, db, plan)
        previous = manager.app.store._get(db, "maintenance_settings", CONTROL)
        if previous and previous["phase"] not in TERMINAL:
            if previous["review_id"] == plan["id"]:
                return public(previous)
            raise WorkflowConflict("Complete or roll back the current provider transition first", {})
        if not _approved(manager.app.store, db, approval, plan["previous_auth_fingerprint"]):
            raise PermissionError("The current enabled Super Admin must apply this exact verified provider review")
        authority = manager.app.store._get(db, "maintenance_settings", AUTHORITY)
        old = authority or {"id": AUTHORITY, "fingerprint": manager.app.auth.config.fingerprint,
                            "epoch": os.environ.get("PRTHAK_PROVIDER_EPOCH", "")}
        record = {"id": CONTROL, "review_id": plan["id"], "phase": "prepare", "members": targets,
                  "membership_digest": digest(targets), "approval_proof": approval, "previous_fingerprint": plan["previous_auth_fingerprint"], "expires_at": plan["expires_at"], "recipients": sealed(manager, {"request": request, "candidate": plan["candidate_identity"], "runtime_node": plan["summary"]["runtime_controller"]}, targets),
                  "previous_authority": old, "desired_epoch": epoch, "acks": {}, "actions": {}, "errors": {},
                  "created_at": stamp(), "updated_at": stamp(), "created_by": plan["created_by"]}
        manager.app.store._put(db, "maintenance_settings", old)
        manager.app.store._put(db, "maintenance_settings", record)
        manager.app.store.audit("platform.provider.transition_requested", plan["created_by"], {"review_id": plan["id"], "controller_ids": [item["id"] for item in targets]}, db)
    return public(record)


def invalidate(store, db, transition):
    for table in ("auth_sessions", "auth_states", "learning_policy_previews", "notification_reviews"):
        db.execute('DELETE FROM "' + table + '"')
    db.execute("UPDATE managed_approvals SET active=0")
    # Unconsumed administrator-created bearer credentials cannot outlive an
    # authority cutover. Keep completed exact-CSR retries and registered leaves.
    for value in store._all(db, "tokens"):
        if value.get("used") is not True:
            db.execute("DELETE FROM tokens WHERE id=?", (value["id"],))
    from .inventory_views import rows
    for row in rows(db, "SELECT id,data FROM maintenance_settings WHERE id LIKE ?", ("endpoint_recovery:%",)):
        if row[0].startswith("endpoint_recovery:") and json.loads(row[1]).get("used") is not True:
            db.execute("DELETE FROM maintenance_settings WHERE id=?", (row[0],))
    for row in rows(db, "SELECT id,data FROM maintenance_settings WHERE id LIKE ?", ("platform_join:%",)):
        if row[0].startswith("platform_join:") and json.loads(row[1]).get("consumed") is not True:
            db.execute("DELETE FROM maintenance_settings WHERE id=?", (row[0],))
    for value in store._all(db, "firewall_changes"):
        if value.get("status") in ("draft", "awaiting_second_confirmation", "queued"):
            value.update(status="invalidated", confirmation_nonce="", invalidated_at=stamp(),
                         invalidation_reason="Sign-in authority changed; fresh independent review required")
            store._put(db, "firewall_changes", value)
    for value in store._all(db, "learning_allow_policies"):
        proof = value.get("approval_proof") or {}
        if proof.get("binding_digest") and proof.get("stage") == "approved":
            # Preserve the exact original proof without growing a policy that
            # may already be at its canonical detail byte limit. Replacing the
            # stage with the shorter 'revoked' marker grants no new authority;
            # normal fresh independent review replaces it with a new proof.
            history = {"id": "provider_revoked_learning_proof:" + value["id"] + ":" + proof["binding_digest"],
                       "policy_id": value["id"], "approval_proof": copy.deepcopy(proof), "revoked_at": stamp(),
                       "review_id": transition["review_id"], "reason": "Sign-in authority changed; fresh independent review required"}
            previous = store._get(db, "maintenance_settings", history["id"])
            if previous and (previous.get("policy_id") != value["id"] or previous.get("approval_proof") != proof):
                raise ValueError("Historical learning approval conflicts with its immutable identity")
            if previous is None:
                store._put(db, "maintenance_settings", history)
            value["approval_proof"] = {**proof, "stage": "revoked"}
            store._put(db, "learning_allow_policies", value)
    for value in store._all(db, "endpoint_configuration_reviews"):
        if value.get("status") != "revoked":
            value.update(status="revoked", revoked_at=stamp(), revoked_by="provider-transition",
                         revocation_reason="Sign-in authority changed; fresh independent review required")
            store._put(db, "endpoint_configuration_reviews", value)
    for value in store._all(db, "managed_rollouts"):
        if value.get("status") not in ("completed", "invalidated", "cancelled"):
            value.update(status="invalidated", invalidated_at=stamp(), invalidation_reason="Reviewed sign-in authority changed; fresh independent review required")
            store._put(db, "managed_rollouts", value)
    for value in store._all(db, "sessions"):
        if value.get("status") == "active" and value.get("policy_action") == "auto_allow":
            value.update(status="stopped", stopped_at=stamp(), initial_approval_state="invalidated")
            store._put(db, "sessions", value)
    store.audit("platform.provider.authority_changed", transition["created_by"], {"review_id": transition["review_id"], "sessions_revoked": True, "fresh_approvals_required": True}, db)


def _grant(store, db, payload, record):
    request = payload["request"]
    env = request["environment"]
    candidate = payload["candidate"]
    config = EntraConfig(*(env[key] for key in AUTH_KEYS[:3]), request["client_secret"], "")
    if candidate.split(":", 1)[0] != config.tenant_id:
        raise ValueError("The candidate identity differs from the reviewed tenant")
    existing = store._get(db, "auth_users", candidate)
    previous_tenant = record["approval_proof"]["requester"]["tenant_id"]
    if existing and previous_tenant == config.tenant_id and (not existing.get("enabled") or existing.get("role") != "super_admin"):
        raise ValueError("The current-tenant reviewing Super Admin is no longer authorized")
    if not existing or not existing.get("enabled") or existing.get("role") != "super_admin":
        user = EntraAuth(store, config)._user({"object_id": candidate.split(":", 1)[1], "role": "super_admin"})
        store._put(db, "auth_users", user)
        store.audit("access.provider_migration_super_granted", record["created_by"], {"user_id": candidate, "review_id": record["review_id"]}, db)
    if previous_tenant != config.tenant_id:
        for user in store._all(db, "auth_users"):
            if user.get("provider", "entra") == "entra" and user.get("tenant_id") != config.tenant_id and user.get("enabled"):
                user.update(enabled=False, updated_at=stamp())
                store._put(db, "auth_users", user)
                store.audit("access.provider_authority_user_retired", record["created_by"], {"user_id": user["id"], "review_id": record["review_id"]}, db)
    return config


def reconcile(manager, client=None):
    """One durable local action per pass; all nodes coordinate through shared rows."""
    if not manager or not manager.app or manager.app.demo:
        return
    store = manager.app.store
    client = client or NodeClient()
    with store.read_meta() as db:
        record = store._get(db, "maintenance_settings", CONTROL)
    if not record or record["phase"] in TERMINAL:
        return
    if record["phase"] in ("prepare", "apply") and parse_time(record["expires_at"]) <= now():
        with store.lock, store.meta() as db:
            current = store._get(db, "maintenance_settings", CONTROL)
            if current["phase"] in ("prepare", "apply"):
                current.update(phase="rollback", updated_at=stamp())
                store._put(db, "maintenance_settings", current)
        return
    node = manager.app.controller_id
    if node not in {item["id"] for item in record["members"]}:
        return
    payload = unseal(manager, record["recipients"])
    if digest(members(manager)) != record["membership_digest"]:
        with store.lock, store.meta() as db:
            current = store._get(db, "maintenance_settings", CONTROL)
            current.update(phase="rollback", updated_at=stamp())
            current["errors"][node] = "Registered membership changed during provider review"
            store._put(db, "maintenance_settings", current)
        return
    phase = record["phase"]
    result = None
    try:
        if phase == "prepare":
            state = client.status()["controller_configuration"]
            result = {"revision": state["expected_revision"], "digest": state["digest"], "environment": state.get("environment", {})}
        elif phase in ("apply", "rollback"):
            operation = hashlib.sha256((record["review_id"] + ":" + node).encode()).hexdigest()[:32]
            if phase == "rollback":
                body = {"action": "controller-config", "operation_id": operation, "rollback_operation": True,
                        "expected_revision": 0, "expected_config_digest": "0" * 64, "environment": {}}
            else:
                body = copy.deepcopy(payload["request"])
                prepared = record["acks"]["prepare"][node]
                body.update(operation_id=operation, expected_revision=prepared["revision"], expected_config_digest=prepared["digest"])
                if node != payload["runtime_node"]:
                    from .gui_setup import RUNTIME
                    body["environment"] = {**{key: value for key, value in prepared["environment"].items() if key in RUNTIME},
                                           **{key: body["environment"][key] for key in AUTH_KEYS}}
                from .gui_setup import binding
                body["candidate_binding_digest"] = binding(body)
            request_id = hashlib.sha256((operation + ":" + phase).encode()).hexdigest()[:32]
            body["request_id"] = request_id
            submitted = client.submit(body)
            identifier = submitted.get("id") or submitted.get("job_id")
            if not identifier:
                raise ValueError("The fixed manager did not return a durable operation")
            job = client.job(identifier)
            if job.get("status") in ("queued", "running"):
                return
            if job.get("status") != "completed" or not job.get("result", {}).get("verified"):
                raise ValueError("The fixed provider operation has no verified result")
            result = job["result"]
            if phase == "apply" and result.get("binding_digest") != body["candidate_binding_digest"]:
                raise ValueError("The fixed manager returned a different provider binding")
            if phase == "rollback" and result.get("rolled_back") is not True:
                raise ValueError("The fixed manager did not verify exact rollback")
            if phase == "apply" and result.get("applied") is not True:
                raise ValueError("A controller rolled back the candidate provider")
        else:
            return
    except Exception:
        with store.lock, store.meta() as db:
            current = store._get(db, "maintenance_settings", CONTROL)
            current["errors"][node] = "The reviewed provider operation is incomplete; retained recovery context is required"
            if current["phase"] == "apply":
                current["phase"] = "rollback"
            current["updated_at"] = stamp()
            store._put(db, "maintenance_settings", current)
        return
    with store.lock, store.meta() as db:
        current = store._get(db, "maintenance_settings", CONTROL)
        if current["phase"] != phase:
            return
        current.setdefault("acks", {}).setdefault(phase, {})[node] = result
        expected = {item["id"] for item in current["members"]}
        if expected <= set(current["acks"][phase]):
            if phase == "prepare":
                current["phase"] = "apply"
            elif phase == "apply":
                if not _approved(store, db, current["approval_proof"], current["previous_fingerprint"]):
                    current.update(phase="rollback", updated_at=stamp())
                    store._put(db, "maintenance_settings", current)
                    return
                try:
                    config = _grant(store, db, payload, current)
                except (ValueError, AuthDenied):
                    current.update(phase="rollback", updated_at=stamp())
                    current["errors"][node]="The exact reviewed candidate can no longer receive Super Admin access"
                    store._put(db, "maintenance_settings", current)
                    return
                invalidate(store, db, current)
                store._put(db, "maintenance_settings", {"id": AUTHORITY, "fingerprint": config.fingerprint,
                            "epoch": current["desired_epoch"], "review_id": current["review_id"]})
                current.update(phase="completed", completed_at=stamp())
            else:
                store._put(db, "maintenance_settings", current["previous_authority"])
                current.update(phase="rolled_back", completed_at=stamp())
        current["updated_at"] = stamp()
        store._put(db, "maintenance_settings", current)
