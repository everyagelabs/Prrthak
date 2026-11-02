"""Immutable managed-policy history and exact-bundle administrative authorization."""
import hashlib
import ipaddress
import json
import re
import secrets
import uuid
from datetime import timedelta
from urllib.parse import urlsplit

from .store import digest, now, parse_time, stamp
from .firewall import WorkflowConflict
from .review_limits import MAX_REVIEW_BYTES as MAX_ROLLOUT_BYTES, encoded_size as _review_size


def initialize(db):
    db.executescript("""
      CREATE TABLE IF NOT EXISTS policy_revisions (id TEXT PRIMARY KEY, policy_id TEXT NOT NULL, revision INTEGER NOT NULL, created_at TEXT NOT NULL, data TEXT NOT NULL, UNIQUE(policy_id,revision));
      CREATE TABLE IF NOT EXISTS policy_intent_headers (id TEXT PRIMARY KEY, data TEXT NOT NULL);
      CREATE INDEX IF NOT EXISTS policy_revision_lookup ON policy_revisions(policy_id,revision);
      CREATE TABLE IF NOT EXISTS bundle_history (id TEXT PRIMARY KEY, server_id TEXT NOT NULL, version INTEGER NOT NULL, digest TEXT NOT NULL, created_at TEXT NOT NULL, data TEXT NOT NULL, UNIQUE(server_id,version));
      CREATE INDEX IF NOT EXISTS bundle_history_lookup ON bundle_history(server_id,version);
      CREATE TABLE IF NOT EXISTS managed_rollouts (id TEXT PRIMARY KEY, data TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS managed_approvals (id TEXT PRIMARY KEY, server_id TEXT NOT NULL, version INTEGER NOT NULL, digest TEXT NOT NULL, protection_digest TEXT NOT NULL, approval_id TEXT NOT NULL, expires_at TEXT NOT NULL, active INTEGER NOT NULL, data TEXT NOT NULL);
      CREATE INDEX IF NOT EXISTS managed_approval_lookup ON managed_approvals(server_id,version,digest,protection_digest,active,expires_at);
      CREATE INDEX IF NOT EXISTS managed_approval_active ON managed_approvals(server_id,active);
      CREATE TABLE IF NOT EXISTS managed_outcomes (id TEXT PRIMARY KEY, server_id TEXT NOT NULL, version INTEGER NOT NULL, approval_id TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, data TEXT NOT NULL);
      CREATE INDEX IF NOT EXISTS managed_outcome_lookup ON managed_outcomes(server_id,version,created_at);
    """)
    if getattr(db, "dialect", "sqlite") == "postgresql":
        db.execute("ALTER TABLE managed_outcomes ADD COLUMN IF NOT EXISTS approval_id TEXT NOT NULL DEFAULT ''")
    else:
        columns = {row[1] for row in db.execute("PRAGMA table_info(managed_outcomes)").fetchall()}
        if "approval_id" not in columns:
            db.execute("ALTER TABLE managed_outcomes ADD COLUMN approval_id TEXT NOT NULL DEFAULT ''")
    db.execute("CREATE INDEX IF NOT EXISTS managed_outcome_approval ON managed_outcomes(approval_id,server_id,created_at)")
    from .approval_views import _expression
    db.execute("CREATE INDEX IF NOT EXISTS managed_rollout_public_created ON managed_rollouts ((" + _expression(db, ("created_at",)) + "),id)")
    for row in db.execute("SELECT id,data FROM managed_outcomes WHERE approval_id='' ").fetchall():
        old = json.loads(row[1])
        if old.get("approval_id"):
            db.execute("UPDATE managed_outcomes SET approval_id=? WHERE id=?", (old["approval_id"], row[0]))


def binding_digest(server_id, version, policy_digest, protection_digest):
    return hashlib.sha256("\0".join(("prthak-managed-v1", server_id, str(version), policy_digest, protection_digest)).encode()).hexdigest()


def record_revision(db, policy, actor, reason="Policy configuration changed"):
    value = {**policy, "actor": actor, "reason": reason, "policy_created_at": policy["created_at"], "created_at": policy.get("updated_at", stamp())}
    existing = db.execute("SELECT data FROM policy_revisions WHERE policy_id=? AND revision=?", (policy["id"], policy["revision"])).fetchone()
    if existing:
        saved = json.loads(existing[0])
        if any(saved.get(key) != policy.get(key) for key in ("name", "selector", "group_ids", "mode", "services")):
            raise RuntimeError("Immutable policy revision collision")
        return
    db.execute("INSERT INTO policy_revisions(id,policy_id,revision,created_at,data) VALUES(?,?,?,?,?)", (policy["id"] + ":" + str(policy["revision"]), policy["id"], policy["revision"], value["created_at"], json.dumps(value, sort_keys=True)))


def record_bundle(db, bundle, actor="compiler", reason="Effective policy changed"):
    existing = db.execute("SELECT data FROM bundle_history WHERE server_id=? AND version=?", (bundle["server_id"], bundle["version"])).fetchone()
    if existing:
        if json.loads(existing[0])["digest"] != bundle["digest"]:
            raise RuntimeError("Immutable effective-bundle version collision")
        return
    value = {**bundle, "actor": actor, "reason": reason, "created_at": bundle.get("generated_at", stamp())}
    db.execute("INSERT INTO bundle_history(id,server_id,version,digest,created_at,data) VALUES(?,?,?,?,?,?)", (bundle["server_id"] + ":" + str(bundle["version"]), bundle["server_id"], bundle["version"], bundle["digest"], value["created_at"], json.dumps(value, sort_keys=True)))


def backfill(store, db):
    for policy in store._all(db, "policies"):
        record_revision(db, policy, "migration", "Existing active policy imported into immutable history")
        # A canonical writer-derived scalar binds the small authority
        # projection to symbolic intent without decoding source matrices on
        # every endpoint poll. This also upgrades pre-index policy rows.
        if (store._get(db, "policy_intent_headers", policy["id"]) or {}).get("digest") != digest(policy_intent(policy)):
            store._put(db, "policies", policy)
    for server in store._all(db, "servers"):
        if server.get("_compiled"):
            record_bundle(db, server["_compiled"], "migration", "Existing effective bundle imported into immutable history")


def revisions(store, identifier, revision=None):
    with store.read_meta() as db:
        if revision is None:
            rows = db.execute("SELECT data FROM policy_revisions WHERE policy_id=? ORDER BY revision DESC LIMIT 500", (identifier,)).fetchall()
            return [json.loads(row[0]) for row in rows]
        row = db.execute("SELECT data FROM policy_revisions WHERE policy_id=? AND revision=?", (identifier, revision)).fetchone()
        if not row:
            raise KeyError(identifier)
        return json.loads(row[0])


def difference(before, after):
    fields = ("name", "selector", "group_ids", "mode", "services", "host_default_deny")
    return {"before": before, "after": after, "from_revision": before.get("revision", before.get("version")), "to_revision": after.get("revision", after.get("version")), "changes": [{"field": field, "before": before.get(field), "after": after.get(field)} for field in fields if before.get(field) != after.get(field)]}


def history(store, identifier, version=None):
    with store.read_meta() as db:
        rows = db.execute("SELECT data FROM bundle_history WHERE server_id=?" + (" AND version=?" if version is not None else "") + " ORDER BY version DESC LIMIT 100", (identifier, version) if version is not None else (identifier,)).fetchall()
        items = [json.loads(row[0]) for row in rows]
        if version is not None and not items:
            raise KeyError(identifier)
        outcomes = db.execute("SELECT data FROM managed_outcomes WHERE server_id=? ORDER BY created_at DESC LIMIT 1000", (identifier,)).fetchall()
        outcomes = [json.loads(row[0]) for row in outcomes]
        for item in items:
            item["outcomes"] = [outcome for outcome in outcomes if outcome["version"] == item["version"]]
        return items[0] if version is not None else items


def protection(value):
    if not isinstance(value, dict):
        raise ValueError("protection must be an object")
    sources, ports = value.get("management_sources", []), value.get("ssh_ports", [])
    if not isinstance(sources, list) or len(sources) > 100 or any(not isinstance(source, str) for source in sources) or not isinstance(ports, list) or len(ports) > 100:
        raise ValueError("Invalid protected management baseline")
    normalized_sources = []
    unsafe_sources = False
    for source in sources:
        from .network_addresses import network as source_network
        network = source_network(source)
        if network.prefixlen == 0:
            unsafe_sources = True
        normalized_sources.append(str(network))
    if any(isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535 for port in ports):
        raise ValueError("Invalid protected SSH listener")
    controller, probe, zone = value.get("controller_url", ""), value.get("management_probe_url", ""), value.get("zone", "")
    if any(not isinstance(item, str) or len(item) > 2048 for item in (controller, probe, zone)) or (zone and not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", zone)):
        raise ValueError("Invalid protected controller/zone identity")
    controller_url, probe_url = urlsplit(controller), urlsplit(probe)
    if controller and (controller_url.scheme != "https" or not controller_url.netloc or controller_url.username or controller_url.query or controller_url.fragment):
        raise ValueError("Protected controller origin must use HTTPS")
    if probe and (probe_url.scheme != "https" or (probe_url.scheme, probe_url.netloc) != (controller_url.scheme, controller_url.netloc) or probe_url.username or probe_url.fragment):
        raise ValueError("Management witness must use the same authenticated controller origin")
    baseline = {"management_sources": sorted(set(normalized_sources)), "ssh_ports": sorted(set(ports)), "controller_url": controller, "management_probe_url": probe, "zone": zone}
    context, profile = value.get("host_default_deny_context_digest"), value.get("host_default_deny_control_profile")
    if context is not None or profile is not None:
        if not isinstance(context, str) or not re.fullmatch(r"[a-f0-9]{64}", context) or profile != "host-inbound-control-v1":
            raise ValueError("Whole-host inbound protection requires its exact paired context digest and control profile")
        baseline.update(host_default_deny_context_digest=context, host_default_deny_control_profile=profile)
    expected = digest(baseline)
    if value.get("digest") != expected:
        raise ValueError("Protected configuration digest does not match its exact reported baseline")
    blockers = value.get("blockers", [])
    if not isinstance(blockers, list) or len(blockers) > 32 or any(not isinstance(item, str) or len(item) > 512 for item in blockers) or not isinstance(value.get("ready", False), bool):
        raise ValueError("Invalid protection readiness metadata")
    blockers = list(blockers)
    if unsafe_sources:
        blockers.append("Unrestricted management CIDRs cannot authorize enforcement")
    for condition, message in ((not baseline["management_sources"], "Restricted management CIDRs are missing"), (not ports, "Actual SSH listeners are unknown"), (not controller or not probe, "Controller management witness is not configured"), (not zone, "Managed firewall zone is unknown")):
        if condition and message not in blockers:
            blockers.append(message)
    result = {**baseline, "digest": expected, "ready": value.get("ready", False) and not blockers, "blockers": blockers}
    if "host_default_deny_ready" in value or "host_default_deny_blockers" in value:
        deny_blockers=value.get("host_default_deny_blockers", [])
        if not isinstance(value.get("host_default_deny_ready", False), bool) or not isinstance(deny_blockers,list) or len(deny_blockers)>32 or any(not isinstance(reason,str) or len(reason)>512 for reason in deny_blockers):
            raise ValueError("Invalid whole-host inbound readiness report")
        result.update(host_default_deny_ready=value.get("host_default_deny_ready",False),host_default_deny_blockers=deny_blockers)
    return result


def _recovery_missing_receipt(db, server, result):
    """Admit bounded unknown cache evidence, never an applied rule receipt."""
    floor = server.get("_recovery_version_floor")
    if server.get("recovery_reconciliation_required") is not True or isinstance(floor, bool) or not isinstance(floor, int) or floor < 1:
        return False
    versions = (result["version"], result["last_good_version"])
    if max(versions) < 1 or any(version > floor for version in versions):
        return False
    for version, body_digest in ((result["version"], result["digest"]), (result["last_good_version"], result["last_good_digest"])):
        if version and not re.fullmatch(r"[a-f0-9]{64}", body_digest):
            return False
        if version:
            row = db.execute("SELECT data FROM bundle_history WHERE server_id=? AND version=?", (server["id"], version)).fetchone()
            if row and json.loads(row[0])["digest"] != body_digest:
                return False  # A known identity with different content is invalid.
    approval_id = result["approval_id"]
    if approval_id:
        known = db.execute("SELECT server_id,version,digest FROM managed_approvals WHERE approval_id=?", (approval_id,)).fetchall()
        own = [row for row in known if row[0] == server["id"]]
        if known and not own or any(row[1] != result["version"] or row[2] != result["digest"] for row in own):
            return False
    exact = db.execute("SELECT 1 FROM managed_approvals WHERE server_id=? AND approval_id=? AND version=? AND digest=? LIMIT 1", (server["id"], approval_id, result["version"], result["digest"])).fetchone() if approval_id else None
    missing = bool(approval_id and not exact) or result["status"] in ("staging", "runtime_healthchecking", "committing", "enforced", "rolled_back") and not exact
    if result["last_good_version"]:
        history = db.execute("SELECT 1 FROM bundle_history WHERE server_id=? AND version=? LIMIT 1", (server["id"], result["last_good_version"])).fetchone()
        authorized = db.execute("SELECT 1 FROM managed_approvals WHERE server_id=? AND version=? AND digest=? LIMIT 1", (server["id"], result["last_good_version"], result["last_good_digest"])).fetchone()
        missing = missing or not history or not authorized
    if result["status"] == "enforced":
        missing = missing or not db.execute("SELECT 1 FROM bundle_history WHERE server_id=? AND version=? LIMIT 1", (server["id"], result["version"])).fetchone()
    if not missing:
        return False
    server["recovery_unverified_outcome"] = {**result, "original_status": result["status"], "status": "unverified", "received_at": stamp(), "evidence_only": True, "authorized": False, "reason": "Historical endpoint cache receipt is below the captured recovery floor but lacks complete immutable authorization; fresh approved read-back is required"}
    server["apply_error"] = "Unverified retained firewall baseline after recovery; fresh approved read-back is required"
    return True


def _receipt_is_current(db, server, result, approval):
    """Order authenticated attempt evidence; older receipts remain history only."""
    cursor=server.get("_managed_receipt_cursor") or {}
    if not cursor:
        previous=server.get("managed_enforcement") or {}
        version=max(server.get("_last_managed_applied_version",0), previous.get("version",0) if previous.get("approval_id") else 0)
        cursor={"version":version,"approval_id":previous.get("approval_id","") if previous.get("version")==version else "",
                "updated_at":previous.get("updated_at","1970-01-01T00:00:00Z"),"status":previous.get("status","")}
    version=result["version"]
    if version<cursor.get("version",0):return False
    if not approval or result["status"] in ("preview", "pending_approval"):
        return True
    row=db.execute("SELECT active FROM managed_approvals WHERE server_id=? AND approval_id=? AND version=? AND digest=? LIMIT 1",
        (server["id"],result["approval_id"],version,result["digest"])).fetchone()
    active=bool(row and row[0])
    if version==cursor.get("version",0):
        if result["approval_id"]!=cursor.get("approval_id"):
            if not active:return False
        else:
            if not active and db.execute("SELECT 1 FROM managed_approvals WHERE server_id=? AND version=? AND digest=? AND active=1 AND approval_id<>? LIMIT 1",(server["id"],version,result["digest"],result["approval_id"])).fetchone():return False
            before=parse_time(cursor.get("updated_at") or "1970-01-01T00:00:00Z")
            after=parse_time(result["updated_at"])
            if after<before:return False
            if approval.get("host_default_deny_ack") and not active and cursor.get("status") in ("error","rolled_back"):
                if cursor.get("status")=="rolled_back" or result["status"]!="rolled_back":return False
            if after==before:
                ranks={"preview":0,"pending_approval":0,"staging":1,"runtime_healthchecking":2,"committing":3,"enforced":4,"error":5,"rolled_back":6}
                old_rank,new_rank=ranks.get(cursor.get("status"),0),ranks[result["status"]]
                if new_rank<old_rank:return False
                if new_rank==old_rank and cursor.get("receipt_digest") and cursor["receipt_digest"]!=digest(result):return False
    server["_managed_receipt_cursor"]={"version":version,"approval_id":result["approval_id"],"updated_at":result["updated_at"],"status":result["status"],"receipt_digest":digest(result)}
    return True


def _record_outcome(store, db, server, result, current=True):
    old=server.get("managed_enforcement",{})
    if current and not any(old.get(key)!=result.get(key) for key in result if key!="updated_at"):return
    identifier=str(uuid.uuid4()) if current else "historical:"+digest({"server_id":server["id"],**result})
    evidence={**result,"server_id":server["id"],**({"history_only":True} if not current else {})}
    db.execute("INSERT INTO managed_outcomes(id,server_id,version,approval_id,created_at,data) VALUES(?,?,?,?,?,?) ON CONFLICT(id) DO NOTHING",
        (identifier,server["id"],result["version"],result["approval_id"],now().isoformat(timespec="microseconds").replace("+00:00","Z"),json.dumps(evidence)))
    if current:store.audit("managed_enforcement."+result["status"],"agent:"+server["id"],{"version":result["version"],"digest":result["digest"],"approval_id":result["approval_id"],"rollback_reason":result["rollback_reason"]},db)


def report_outcome(store, db, server, value):
    if not isinstance(value, dict):
        raise ValueError("managed_enforcement must be an object")
    status = value.get("status")
    allowed = ("preview", "pending_approval", "staging", "runtime_healthchecking", "committing", "enforced", "rolled_back", "error")
    version = value.get("version", 0)
    if status not in allowed or isinstance(version, bool) or not isinstance(version, int) or version < 0:
        raise ValueError("Invalid managed enforcement outcome")
    result = {"status": status, "version": version}
    for field in ("managed_rules_present", "host_default_deny_active", "already_present"):
        if field in value:
            if not isinstance(value[field],bool):raise ValueError("Managed ownership receipt flags must be booleans")
            result[field]=value[field]
    for key in ("digest", "approval_id", "rollback_reason", "error", "last_good_digest"):
        field = value.get(key, "")
        if not isinstance(field, str) or len(field) > (4096 if key in ("error", "rollback_reason") else 128):
            raise ValueError("Invalid managed enforcement result metadata")
        result[key] = field
    last_good = value.get("last_good_version", 0)
    if isinstance(last_good, bool) or not isinstance(last_good, int) or last_good < 0:
        raise ValueError("Invalid last-good policy version")
    if status == "rolled_back":
        if "last_good_version" not in value or "last_good_digest" not in value:
            raise ValueError("Rolled-back outcomes require explicit last_good_version and last_good_digest")
        if not last_good and (server.get("_managed_rules_active") or server.get("_last_managed_applied_version", 0) or server.get("last_good_version", 0)):
            raise ValueError("A previously applied managed baseline cannot be replaced with an unknown last-good version")
    result["last_good_version"] = last_good
    timestamp = parse_time(value["updated_at"]) if value.get("updated_at") else now()
    if timestamp > now() + timedelta(seconds=60):
        raise ValueError("Managed outcome timestamp is in the future")
    result["updated_at"] = value.get("updated_at") or stamp(timestamp)
    if value.get("generation") is not None:
        generation = value["generation"]
        if not isinstance(generation, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", generation):
            raise ValueError("Invalid managed transaction generation")
        result["generation"] = generation
    if value.get("committed_at") is not None:
        committed = parse_time(value["committed_at"])
        if committed > timestamp or not result.get("generation"):
            raise ValueError("Managed commit boundary requires its generation and a valid timestamp")
        # Keep the validated fractional boundary. The ordinary second-precision
        # report timestamp cannot replace native traffic provenance.
        result["committed_at"] = value["committed_at"]
    verification_fields = ("verification_id", "verification_readback_at")
    if any(key in value for key in verification_fields):
        verification_id = value.get("verification_id")
        if not isinstance(verification_id, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", verification_id) or "verification_readback_at" not in value:
            raise ValueError("Verification readback requires its paired observation identity")
        verified_at = parse_time(value["verification_readback_at"])
        if verified_at > timestamp or not result.get("generation"):
            raise ValueError("Verification readback must belong to the reported applied generation and precede its update")
        result.update(verification_id=verification_id, verification_readback_at=value["verification_readback_at"])
    if _recovery_missing_receipt(db, server, result):
        return
    approval = None
    if result["approval_id"]:
        row = db.execute("SELECT data FROM managed_approvals WHERE server_id=? AND approval_id=? AND version=? AND digest=? LIMIT 1", (server["id"], result["approval_id"], version, result["digest"])).fetchone()
        approval = json.loads(row[0]) if row else None
        if not approval:
            raise PermissionError("Managed outcome does not belong to this endpoint and approved historical bundle")
    if status in ("staging", "runtime_healthchecking", "committing", "enforced", "rolled_back") and not approval:
        raise PermissionError("Applied or transitional managed outcome requires a historical approved bundle")
    if last_good:
        historical = db.execute("SELECT data FROM bundle_history WHERE server_id=? AND version=?", (server["id"], last_good)).fetchone()
        if not historical or json.loads(historical[0])["digest"] != result["last_good_digest"]:
            raise ValueError("Last-good managed outcome does not match immutable host bundle history")
        historical_approval = db.execute("SELECT data FROM managed_approvals WHERE server_id=? AND version=? AND digest=? LIMIT 1", (server["id"], last_good, result["last_good_digest"])).fetchone()
        if not historical_approval:
            raise PermissionError("Last-good version has no historical managed authorization")
    result["intent"] = approval.get("intent", "enforce") if approval else "preview"
    result["protection_digest"] = approval.get("protection_digest", "") if approval else ""
    result["approved_ips"] = approval.get("approved_ips", []) if approval else []
    applied_bundle=None
    if status == "enforced":
        historical=db.execute("SELECT data FROM bundle_history WHERE server_id=? AND version=?",(server["id"],version)).fetchone()
        if not historical or json.loads(historical[0])["digest"]!=result["digest"]:
            raise ValueError("Enforced outcome does not match immutable effective history")
        applied_bundle=json.loads(historical[0])
    elif status=="rolled_back" and last_good:
        applied_bundle=json.loads(db.execute("SELECT data FROM bundle_history WHERE server_id=? AND version=?",(server["id"],last_good)).fetchone()[0])
    if status in ("enforced","rolled_back") and "host_default_deny_active" in result and result["host_default_deny_active"]!=bool((applied_bundle or {}).get("host_default_deny")):
        raise ValueError("Whole-host active receipt does not match its authenticated applied/rollback bundle")
    if status in ("enforced","rolled_back") and (applied_bundle or {}).get("host_default_deny") is True and result.get("managed_rules_present") is False:
        raise ValueError("An active whole-host fallback cannot report absent owned rules")
    current=_receipt_is_current(db,server,result,approval)
    _record_outcome(store,db,server,result,current)
    if not current:return False
    if status=="enforced":
        server["_managed_rules_active"]=result.get("managed_rules_present",result["intent"]!="remove_managed_rules")
        server["_last_managed_applied_version"]=version
        server["last_good_version"]=version;server["last_good_digest"]=result["digest"]
        floor=server.get("_recovery_version_floor",0)
        if server.get("recovery_reconciliation_required") is True and isinstance(floor,int) and not isinstance(floor,bool) and version>floor:
            server.pop("recovery_reconciliation_required",None);server.pop("recovery_unverified_outcome",None)
        if not approval.get("host_default_deny_ack"):
            server.pop("_host_default_deny_owned_cleanup_required",None)
    elif status=="rolled_back":
        server["_managed_rules_active"]=result.get("managed_rules_present",bool(applied_bundle and applied_bundle["mode"]=="enforce"))
        server["_last_managed_applied_version"]=last_good
        server["last_good_version"],server["last_good_digest"]=last_good,result["last_good_digest"]
        server["rollback_reason"]=result["rollback_reason"]
    from .host_default_deny import outcome as host_default_deny_outcome
    host_default_deny_outcome(store, db, server, result, approval)
    server["managed_enforcement"] = result
    from .policy_deployments import outcome as deployment_outcome
    deployment_outcome(store, db, server, result)
    return True


def baseline(server):
    bundle, protected = server.get("_compiled", {}), server.get("protection", {})
    return {"version": bundle.get("version", 0), "digest": bundle.get("digest", ""), "protection_digest": protected.get("digest", ""), "binding_digest": binding_digest(server["id"], bundle.get("version", 0), bundle.get("digest", ""), protected.get("digest", "")), "ips": sorted(server.get("ips", [])), "target_digest": digest({"server_id": server["id"], "ips": sorted(server.get("ips", []))})}


def policy_intent(policy):
    # Catalogue snapshots and source/target membership are resolved values;
    # the saved symbolic policy explicitly authorizes their later resolution.
    return {key: ([{k: v for k, v in item.items() if k != "service_group_snapshot"} for item in policy[key]] if key == "services" else policy.get(key))
            for key in ("id", "name", "selector", "group_ids", "mode", "services")}


def authorize_policy(store, db, policy, actor, principal):
    from . import approvals
    plan = {"id": str(uuid.uuid4()), "plan_digest": digest(policy_intent(policy))}
    approvals.request(store, db, plan, actor, principal, scope_kind="managed_policy")
    plan["approval"]["scope"].update(policy_ids=[policy["id"]], intent_digest=plan["plan_digest"])
    policy["direct_authorization"] = approvals.decide(store, db, plan, actor, principal)


def direct_authorities_valid(store, db, server, approval):
    """Revalidate every saved contributor by primary key, never fleet scans.

    Explicit exact rollouts have their own current human authorization. Only
    automatically resolved approvals carry the contributing intent manifest.
    """
    expected = approval.get("intent_authorities")
    if expected is None or approval.get("intent") == "remove_managed_rules":
        return True
    identifiers = server.get("matched_policy_ids", [])
    if (not isinstance(expected, list) or not expected or len(expected) > 20000
            or any(not isinstance(item, str) or not re.fullmatch(r"[a-f0-9]{64}", item) for item in expected)
            or not isinstance(identifiers, list) or len(identifiers) > 20000):
        return False
    from . import approvals
    from .approval_views import _expression
    hashes = []
    identifiers = sorted(set(identifiers))
    for start in range(0, len(identifiers), 100):
        ids = identifiers[start:start + 100]
        fields = ",".join([_expression(db, ("mode",), "p"), _expression(db, ("direct_authorization",), "p"), _expression(db, ("digest",), "h")])
        rows = db.execute("SELECT " + fields + " FROM policies p LEFT JOIN policy_intent_headers h ON h.id=p.id WHERE p.id IN (" + ",".join("?" for _ in ids) + ")", tuple(ids))
        for row in rows:
            if row[0] != "enforce":
                continue
            value = json.loads(row[1]) if row[1] else None
            if (not isinstance(value, dict) or value.get("mode") != "single_admin"
                    or not isinstance(row[2], str) or not re.fullmatch(r"[a-f0-9]{64}", row[2])
                    or value.get("scope", {}).get("intent_digest") != row[2]
                    or not approvals.authorized(store, db, value)):
                return False
            hashes.append(value["binding_digest"])
    return sorted(hashes) == sorted(expected)


def retire_invalid_direct_approvals(store, db, server):
    """Writer-only retirement; read admission already fails closed."""
    for row in db.execute("SELECT id,data FROM managed_approvals WHERE server_id=? AND active=1", (server["id"],)).fetchall():
        approval = json.loads(row[1])
        if approval.get("intent_authorities") is not None and not direct_authorities_valid(store, db, server, approval):
            db.execute("UPDATE managed_approvals SET active=0 WHERE id=? AND active=1", (row[0],))
            store.audit("managed_policy.authority_invalidated", "system", {"server_id": server["id"], "approval_id": approval.get("approval_id")}, db)


def authorize_cleanup(store, db, server, actor, principal):
    """Bind this Admin's deletion to exact ordinary managed-rule removal.

    Whole-host fallback ownership is deliberately excluded; its dedicated
    downtime acknowledgement remains mandatory.
    """
    from . import approvals
    from .host_default_deny import guarded
    if guarded(server) or server.get("_host_default_deny_owned_cleanup_required"):
        return False
    if server.get("_compiled", {}).get("mode") == "enforce" or not server.get("_managed_rules_active"):
        return False
    if not server.get("protection", {}).get("ready") or not approvals.signed_target(store, server):
        return False
    current = baseline(server)
    identifier = str(uuid.uuid4())
    plan = {"id": identifier, "plan_digest": digest({"action": "remove_managed_rules", "baseline": current})}
    approvals.request(store, db, plan, actor, principal, endpoint_ids=[server["id"]], scope_kind="managed_rollout")
    decision = approvals.decide(store, db, plan, actor, principal)
    normalized = {"authorized": True, "approval_id": identifier, "approved_digest": current["digest"], "approved_version": current["version"],
        "protection_digest": current["protection_digest"], "binding_digest": current["binding_digest"], "digest": current["binding_digest"],
        "approved_ips": current["ips"], "target_digest": current["target_digest"], "intent": "remove_managed_rules", "confirmation_count": 1,
        "expires_at": "9999-12-31T23:59:59Z", "approval_proof": decision}
    db.execute("UPDATE managed_approvals SET active=0 WHERE server_id=? AND active=1", (server["id"],))
    db.execute("INSERT INTO managed_approvals(id,server_id,version,digest,protection_digest,approval_id,expires_at,active,data) VALUES(?,?,?,?,?,?,?,?,?)",
        (identifier + ":" + server["id"], server["id"], current["version"], current["digest"], current["protection_digest"], identifier, normalized["expires_at"], 1, json.dumps(normalized)))
    server["_managed_intent_proof"] = decision
    store._put(db, "servers", server)
    store.audit("managed_policy.cleanup_authorized", actor, {"server_id": server["id"], "version": current["version"], "approval_id": identifier}, db)
    return True


def reconcile_direct(store, db, server, policies=None, validity=None):
    """Bind saved, live Admin intent to the newly resolved exact host bundle."""
    from . import approvals
    from .host_default_deny import guarded
    if guarded(server) or server.get("_host_default_deny_owned_cleanup_required") and server.get("_compiled",{}).get("mode")!="enforce":return False
    if not server.get("protection", {}).get("ready") or not approvals.signed_target(store, server):return False
    current = baseline(server)
    enforcing = server.get("_compiled", {}).get("mode") == "enforce"
    selected = server.get("matched_policy_ids", [])
    proofs = []
    if enforcing:
        for identifier in selected:
            policy = policies.get(identifier) if policies is not None else store._get(db, "policies", identifier)
            if policy and policy.get("mode") != "enforce":continue
            value = (policy or {}).get("direct_authorization")
            if not policy or (value or {}).get("mode") != "single_admin":
                retire_invalid_direct_approvals(store, db, server)
                return False
            key = (identifier, (value or {}).get("binding_digest"))
            valid = validity.get(key) if validity is not None else None
            if valid is None:
                valid = bool(approvals.authorized(store, db, value) and value.get("scope", {}).get("intent_digest") == digest(policy_intent(policy)))
                if validity is not None:validity[key] = valid
            if not valid:
                retire_invalid_direct_approvals(store, db, server)
                return False
            proofs.append(value)
        if not proofs:return False
    elif server.get("_managed_rules_active"):
        for row in db.execute("SELECT data FROM managed_approvals WHERE server_id=? AND version=? AND digest=? AND protection_digest=? AND active=1", (server["id"],current["version"],current["digest"],current["protection_digest"])).fetchall():
            retained=json.loads(row[0])
            if retained.get("intent")=="remove_managed_rules" and retained.get("approved_ips")==current["ips"] and approvals.authorized(store,db,retained.get("approval_proof"),server_id=server["id"]):return False
        value = server.get("_managed_intent_proof")
        if not approvals.authorized(store, db, value, server_id=server["id"]):return False
        proofs = [value]
    else:return False
    sources = sorted(value["binding_digest"] for value in proofs)
    identifier = str(uuid.uuid5(uuid.NAMESPACE_URL, "prthak-direct:" + digest({"server":server["id"],"baseline":current,"sources":sources})))
    existing = db.execute("SELECT 1 FROM managed_approvals WHERE id=?", (identifier + ":" + server["id"],)).fetchone()
    if existing:return False
    source = proofs[-1]
    plan = {"id": identifier, "plan_digest": digest({"baseline":current,"intent_proofs":sources}), "created_at":stamp()}
    proof = approvals.derived(store, db, plan, source["requester"],
        {"kind":"managed_policy", "server_ids":[server["id"]], "intent_digest":digest(sources)}, source["provider_authority"])
    decision = {"authorized":True,"approval_id":identifier,"approved_digest":current["digest"],"approved_version":current["version"],
        "protection_digest":current["protection_digest"],"binding_digest":current["binding_digest"],"digest":current["binding_digest"],
        "approved_ips":current["ips"],"target_digest":current["target_digest"],"intent":"enforce" if enforcing else "remove_managed_rules",
        "confirmation_count":1,"expires_at":"9999-12-31T23:59:59Z","approval_proof":proof,**({"intent_authorities":sources} if enforcing else {})}
    db.execute("UPDATE managed_approvals SET active=0 WHERE server_id=? AND active=1", (server["id"],))
    db.execute("INSERT INTO managed_approvals(id,server_id,version,digest,protection_digest,approval_id,expires_at,active,data) VALUES(?,?,?,?,?,?,?,?,?)",
        (identifier+":"+server["id"],server["id"],current["version"],current["digest"],current["protection_digest"],identifier,decision["expires_at"],1,json.dumps(decision)))
    server["_managed_intent_proof"] = proof
    store.audit("managed_policy.intent_resolved", source["requester"]["actor"], {"server_id":server["id"],"version":current["version"],"approval_id":identifier,"intent_authorities":sources}, db)
    return True


def authorization(store, db, server):
    from . import approvals
    from .host_default_deny import guarded, valid_authority
    whole_host=guarded(server)
    current = baseline(server)
    result = {"authorized": False, "approval_id": "", "approved_digest": current["digest"], "approved_version": current["version"], "protection_digest": current["protection_digest"], "binding_digest": current["binding_digest"], "digest": current["binding_digest"], "confirmation_count": 0, "expires_at": "1970-01-01T00:00:00Z", "reason": "Explicit administrative review is required for this exact effective bundle"}
    cleanup = server.get("_compiled", {}).get("mode") != "enforce" and server.get("_managed_rules_active") is True
    result["intent"] = "remove_managed_rules" if cleanup else "enforce"
    if whole_host:result["reason"] = "A fresh exact whole-server deny review and manual downtime acknowledgement are required"
    if server.get("_compiled", {}).get("mode") != "enforce" and not cleanup and not whole_host:
        result["reason"] = "Monitor policy remains a preview; no managed rules need approved cleanup"
        return result
    if not server.get("protection", {}).get("ready"):
        result["reason"] = "Protected management configuration is incomplete"
        return result
    if not approvals.signed_target(store, server):
        result["reason"] = "Upgrade the endpoint to signed_assignments_v1 before live enforcement"
        return result
    rows = db.execute("SELECT data FROM managed_approvals WHERE server_id=? AND version=? AND digest=? AND protection_digest=? AND active=1 AND expires_at>? ORDER BY expires_at DESC LIMIT 10", (server["id"], current["version"], current["digest"], current["protection_digest"], stamp(now()))).fetchall()
    for row in rows:
        approval = json.loads(row[0])
        if not whole_host and approval.get("host_default_deny_ack"):continue
        if whole_host and not valid_authority(store,db,server,approval):continue
        from . import approvals
        # Confirm inserts normalized approvals only in the same transaction that
        # queues the rollout; cancel atomically deactivates these rows. Never load
        # a whole-fleet preview JSON on an individual endpoint polling path.
        if not direct_authorities_valid(store, db, server, approval):
            result["reason"] = "A contributing saved policy authority was revoked or changed"
            continue
        if approval["confirmation_count"] >= (1 if approval.get("approval_proof", {}).get("mode") == "single_admin" else 2) and approval.get("approved_ips") == current["ips"] and approvals.authorized(store, db, approval.get("approval_proof"), plan_id=approval["approval_id"], server_id=server["id"]):
            return {**result, **approval, "approval_proof": approvals.delivery(approval.get("approval_proof")), "authorized": True, "reason": "Exact bundle and protected baseline explicitly reviewed"}
    return result


def _rollout_server(db, identifier):
    # Project one selected endpoint in SQL, excluding unrelated snapshots,
    # telemetry and learning history. Check bytes before decoding the result.
    fields = ("id", "hostname", "ips", "_compiled", "protection", "_managed_rules_active", "capabilities", "configuration_state", "host_default_deny_state", "_host_default_deny_active", "_recovery_version_floor", "last_good_version", "_last_managed_applied_version", "last_seen", "protection_reported_at")
    if getattr(db, "dialect", "sqlite") == "postgresql":
        projection = "jsonb_build_object(" + ",".join("'" + field + "',document->'" + field + "'" for field in fields) + ")::text"
        selected = "SELECT " + projection + " AS projected FROM servers CROSS JOIN LATERAL (SELECT data::jsonb AS document OFFSET 0) parsed WHERE id=?"
        length = "octet_length(projected)"
    else:
        def expression(field):
            if field in ("_managed_rules_active", "_host_default_deny_active"):
                return "json(CASE json_type(data,'$."+field+"') WHEN 'true' THEN 'true' WHEN 'false' THEN 'false' ELSE 'null' END)"
            return "json_extract(data,'$." + field + "')"
        projection = "json_object(" + ",".join("'" + field + "'," + expression(field) for field in fields) + ")"
        selected = "SELECT " + projection + " AS projected FROM servers WHERE id=?"
        length = "length(CAST(projected AS BLOB))"
    row = db.execute("SELECT " + length + " FROM (" + selected + ") selected", (identifier,)).fetchone()
    if row is None:
        raise ValueError("Selected endpoint does not exist")
    if row[0] > MAX_ROLLOUT_BYTES:
        raise ValueError("Exact managed endpoint evidence exceeds the 8 MiB bound; use a smaller policy")
    raw = db.execute(selected, (identifier,)).fetchone()[0]
    if len(raw.encode("utf-8")) > MAX_ROLLOUT_BYTES:
        raise ValueError("Exact managed endpoint evidence exceeds the 8 MiB bound")
    server = {key: value for key, value in json.loads(raw).items() if value is not None}
    if server.get("id") != identifier or not isinstance(server.get("_compiled", {}), dict) or not isinstance(server.get("protection", {}), dict) or not isinstance(server.get("ips", []), list) or not isinstance(server.get("capabilities", []), list):
        raise ValueError("Selected endpoint evidence is malformed or has a different identity")
    return server


def rollout_preview(store, ids, db):
    bindings, targets = {}, []
    preview_size = len(b'{"bindings":{},"targets":[]}')
    for identifier in ids:
        server = _rollout_server(db, identifier)
        current = baseline(server)
        blockers = list(server.get("protection", {}).get("blockers", []))
        if not server.get("protection", {}).get("ready") and not blockers:
            blockers.append("Protected management configuration has not been reported ready")
        from . import approvals
        if not approvals.signed_target(store, server):
            blockers.append("Upgrade the endpoint to signed_assignments_v1 before live enforcement")
        from .host_default_deny import guarded
        if guarded(server):blockers.append("Use the dedicated whole-server deny preview and manually acknowledge downtime for this push")
        cleanup = server.get("_compiled", {}).get("mode") != "enforce" and server.get("_managed_rules_active") is True
        intent = "remove_managed_rules" if cleanup else "enforce"
        current["intent"] = intent
        if server.get("_compiled", {}).get("mode") != "enforce" and not cleanup:
            blockers.append("Monitor-only endpoint has no validated managed rules requiring cleanup")
        target = {"server_id": identifier, "hostname": server["hostname"], **current, "protection_status": "ready" if not blockers else "incomplete", "blockers": blockers, "bundle": server.get("_compiled", {}), "services": server.get("_compiled", {}).get("services", []), "protection": server.get("protection", {}), "intent": intent}
        extra = _review_size(current, MAX_ROLLOUT_BYTES - preview_size) + _review_size(identifier) + 1 + (2 if targets else 0)
        extra += _review_size(target, MAX_ROLLOUT_BYTES - preview_size - extra)
        if preview_size + extra > MAX_ROLLOUT_BYTES:
            raise ValueError("Exact managed review exceeds the 8 MiB bound; select a smaller endpoint scope")
        preview_size += extra
        bindings[identifier] = current
        targets.append(target)
    return bindings, targets


def rollout(store, value, actor, *, principal=None):
    name, ids = value.get("name", ""), value.get("server_ids", [])
    if not isinstance(name, str) or not name.strip() or len(name) > 120 or not isinstance(ids, list) or not ids or len(ids) > 20000 or any(not isinstance(identifier, str) or not identifier for identifier in ids):
        raise ValueError("Provide a rollout name and explicit selected endpoint IDs")
    ids = sorted(set(ids))
    with store.lock, store.meta() as db:
        if getattr(db, "dialect", "sqlite") == "sqlite":
            db.execute("BEGIN IMMEDIATE")
        bindings, targets = rollout_preview(store, ids, db)
        identifier = str(uuid.uuid4())
        plan_digest = digest({"id": identifier, "server_ids": ids, "bindings": bindings})
        plan = {"id": identifier, "name": name.strip(), "status": "draft", "server_ids": ids, "bindings": bindings, "plan_digest": plan_digest, "preview": {"targets": targets}, "requires_double_confirmation": True, "confirmation_count": 0, "confirmation_nonce": secrets.token_urlsafe(24), "confirmation_phrase": "ENFORCE " + plan_digest[:12], "created_at": stamp(), "created_by": actor, "expires_at": stamp(now() + timedelta(minutes=10)), "results": {}}
        from . import approvals
        approvals.request(store, db, plan, actor, principal, endpoint_ids=ids, scope_kind="managed_rollout")
        if plan["approval"]["mode"] == "single_admin":
            if any(target["blockers"] for target in targets):raise ValueError("Every target needs its ready protected baseline before publishing enforcement")
            decision = approvals.decide(store, db, plan, actor, principal)
            plan.update(status="queued", requires_double_confirmation=False, confirmation_count=1, confirmation_nonce="", confirmed_at=stamp(), expires_at="9999-12-31T23:59:59Z")
            for server_id, target in bindings.items():
                db.execute("UPDATE managed_approvals SET active=0 WHERE server_id=? AND active=1", (server_id,))
                normalized={"authorized":True,"approval_id":identifier,"approved_digest":target["digest"],"approved_version":target["version"],"protection_digest":target["protection_digest"],"binding_digest":target["binding_digest"],"digest":target["binding_digest"],"approved_ips":target["ips"],"target_digest":target["target_digest"],"intent":target["intent"],"confirmation_count":1,"expires_at":plan["expires_at"],"approval_proof":decision}
                db.execute("INSERT INTO managed_approvals(id,server_id,version,digest,protection_digest,approval_id,expires_at,active,data) VALUES(?,?,?,?,?,?,?,?,?)", (identifier+":"+server_id,server_id,target["version"],target["digest"],target["protection_digest"],identifier,plan["expires_at"],1,json.dumps(normalized)))
            from .policy_deployments import create as create_deployment
            plan["deployment"] = create_deployment(store, db, [{"server_id": server_id, "version": target["version"], "digest": target["digest"]} for server_id, target in bindings.items()], actor, plan["name"], origin="managed_rollout")
        _review_size(plan, MAX_ROLLOUT_BYTES)
        store._put(db, "managed_rollouts", plan)
        store.audit("managed_rollout.drafted", actor, {"approval_id": identifier, "bindings": bindings}, db)
        return plan


def rollouts(store, identifier=None):
    with store.read_meta() as db:
        rows = [store._get(db, "managed_rollouts", identifier)] if identifier else store._all(db, "managed_rollouts")
        if identifier and not rows[0]:
            raise KeyError(identifier)
        result = []
        for row in rows:
            public = dict(row)
            if row.get("kind") != "host_default_deny" and public["status"] in ("draft", "awaiting_second_confirmation", "queued"):
                if parse_time(public["expires_at"]) <= now():
                    public["status"] = "expired"
                else:
                    current, _ = rollout_preview(store, row["server_ids"], db)
                    if current != row["bindings"]:
                        public["status"] = "invalidated"
                        public["error"] = "Desired policy, protected baseline or exact target IPs changed"
            outcomes = db.execute("SELECT data FROM managed_outcomes WHERE approval_id=? ORDER BY created_at DESC", (row["id"],)).fetchall()
            result_by_host = {}
            for outcome in outcomes:
                value = json.loads(outcome[0])
                if value.get("history_only"):continue
                if value["server_id"] not in result_by_host:
                    result_by_host[value["server_id"]] = value
            public["results"] = result_by_host
            result.append(public)
        return result[0] if identifier else sorted(result, key=lambda row: row["created_at"], reverse=True)[:100]


def confirm(store, identifier, value, actor, *, principal=None):
    problem = None
    with store.lock, store.meta() as db:
        plan = store._get(db, "managed_rollouts", identifier)
        if not plan:
            raise KeyError(identifier)
        if plan.get("kind") == "host_default_deny":raise ValueError("Use the dedicated whole-server deny confirmation and manual downtime acknowledgement")
        bindings, targets = rollout_preview(store, plan["server_ids"], db)
        if plan["status"] not in ("draft", "awaiting_second_confirmation"):
            problem = "This managed rollout no longer awaits confirmation"
        elif parse_time(plan["expires_at"]) <= now() or bindings != plan["bindings"]:
            plan["status"] = "expired" if parse_time(plan["expires_at"]) <= now() else "invalidated"
            plan["confirmation_nonce"] = ""
            problem = "Desired bundle or protected baseline changed; create a fresh rollout preview"
            store._put(db, "managed_rollouts", plan)
        elif any(target["blockers"] for target in targets):
            problem = "Every target must have complete protected management configuration and an enforced desired bundle"
        elif not isinstance(value.get("confirmation_nonce"), str) or not secrets.compare_digest(value["confirmation_nonce"], plan["confirmation_nonce"]):
            problem = "Confirmation nonce is no longer current"
        elif plan["confirmation_count"] == 1 and value.get("challenge") != plan["confirmation_phrase"]:
            problem = "Typed enforcement phrase does not match this exact rollout"
        else:
            from . import approvals
            approvals.confirm(store, db, plan, actor, principal, final=plan["confirmation_count"] == 1, pilot_nonce=value.get("pilot_confirmation_nonce"))
            plan["confirmation_count"] += 1
            plan["confirmation_nonce"] = secrets.token_urlsafe(24)
            plan["status"] = "awaiting_second_confirmation"
            if plan["confirmation_count"] == 2:
                plan.update({"status": "queued", "confirmation_nonce": "", "confirmed_at": stamp(), "expires_at": stamp(now() + timedelta(hours=24))})
            # Maker/checker evidence grows after drafting. Validate the whole
            # record before any normalized approval is inserted or persisted.
            _review_size(plan, MAX_ROLLOUT_BYTES)
            if plan["confirmation_count"] == 2:
                for server_id, binding in bindings.items():
                    db.execute("UPDATE managed_approvals SET active=0 WHERE server_id=? AND active=1", (server_id,))
                    approval = {"authorized": True, "approval_id": identifier, "approved_digest": binding["digest"], "approved_version": binding["version"], "protection_digest": binding["protection_digest"], "binding_digest": binding["binding_digest"], "digest": binding["binding_digest"], "approved_ips": binding["ips"], "target_digest": binding["target_digest"], "intent": binding["intent"], "confirmation_count": 2, "expires_at": plan["expires_at"], "approval_proof": approvals.proof(plan)}
                    db.execute("INSERT INTO managed_approvals(id,server_id,version,digest,protection_digest,approval_id,expires_at,active,data) VALUES(?,?,?,?,?,?,?,?,?)", (identifier + ":" + server_id, server_id, binding["version"], binding["digest"], binding["protection_digest"], identifier, plan["expires_at"], 1, json.dumps(approval)))
                from .policy_deployments import create as create_deployment
                plan["deployment"] = create_deployment(store, db, [{"server_id": server_id, "version": binding["version"], "digest": binding["digest"]} for server_id, binding in bindings.items()], actor, plan.get("name", "Managed policy rollout"), origin="managed_rollout")
            store._put(db, "managed_rollouts", plan)
            store.audit("managed_rollout.confirmed", actor, {"approval_id": identifier, "step": plan["confirmation_count"], "bindings": bindings}, db)
    if problem:
        raise WorkflowConflict(problem, plan)
    return plan


def cancel(store, identifier, actor):
    with store.lock, store.meta() as db:
        plan = store._get(db, "managed_rollouts", identifier)
        if not plan:
            raise KeyError(identifier)
        if plan["status"] in ("draft", "awaiting_second_confirmation", "queued"):
            plan.update({"status": "cancelled", "confirmation_nonce": "", "cancelled_at": stamp()})
            db.execute("UPDATE managed_approvals SET active=0 WHERE approval_id=?", (identifier,))
            store._put(db, "managed_rollouts", plan)
            store.audit("managed_rollout.cancelled", actor, {"approval_id": identifier}, db)
        return plan
