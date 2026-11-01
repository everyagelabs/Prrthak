"""Fresh per-operation authorization for imported firewall changes."""
import re
from datetime import timedelta

from . import approvals
from .firewall import target_digest, snapshot_view
from .store import now, parse_time, stamp


def check(store, identity, body):
    nonce = body.get("nonce")
    if not isinstance(nonce, str) or not re.fullmatch(r"[a-f0-9]{32}", nonce):
        raise ValueError("A fresh firewall authorization nonce is required")
    with store.read_meta() as db:
        plan = store._get(db, "firewall_changes", body.get("plan_id", ""))
        if not plan or plan.get("plan_digest") != body.get("plan_digest") or plan.get("status") != "queued" or identity not in plan.get("operations_by_server", {}) or identity in plan.get("results", {}) or parse_time(plan["expires_at"]) <= now():
            raise PermissionError("The reviewed firewall change is no longer authorized")
        required = 2 if plan["requires_double_confirmation"] else 1
        if plan.get("confirmation_count", 0) < required or not approvals.authorized(store, db, plan.get("approval_proof"), plan_id=plan["id"], plan_digest=plan["plan_digest"], server_id=identity):
            raise PermissionError("Current Admin firewall authorization is missing or revoked")
        server = store._get(db, "servers", identity)
        from .host_default_deny import guarded
        if server and guarded(server):raise PermissionError("Imported-rule mutations are held while whole-server deny is enabled or being removed")
        snapshot = snapshot_view(server) if server else {}
        if not server or target_digest(server) != plan["target_digests"][identity] or snapshot.get("status") != "ok" or snapshot.get("stale"):
            raise PermissionError("Endpoint protection or firewall inventory is no longer current")
        at = now()
        return {"status": "authorized", "server_id": identity, "plan_id": plan["id"], "plan_digest": plan["plan_digest"], "nonce": nonce,
                "checked_at": stamp(at), "approval_proof": approvals.delivery(plan.get("approval_proof")), "expires_at": stamp(min(parse_time(plan["expires_at"]), at + timedelta(seconds=20)))}
