"""Compact inventory projections; stored canonical snapshots remain unchanged."""
import json
import uuid


def rows(db, sql, parameters=(), *, batch_size=8):
    if getattr(db,"dialect","sqlite")=="postgresql":
        from .postgres import postgres_sql
        with db.connection.cursor(name="prthak_view_"+uuid.uuid4().hex) as cursor:
            cursor.itersize=batch_size
            cursor.execute(postgres_sql(sql),parameters)
            for row in cursor: yield row
    else:
        yield from db.execute(sql,parameters)


MAINTENANCE_FIELDS = ("id", "operation", "target_operation", "status", "checked_at", "error", "baseline_digest")
MAINTENANCE_FACTS = ("can_apply", "blockers", "firewalld_active", "ufw_active", "version", "backend")


def maintenance_summary(receipt):
    """Bounded public outcome; exact assessed rules use the paged maintenance API."""
    result = {key: receipt[key] for key in MAINTENANCE_FIELDS if key in receipt}
    facts = receipt.get("assessment")
    if isinstance(facts, dict):
        result["assessment"] = {key: facts[key] for key in MAINTENANCE_FACTS if key in facts}
        # SQLite JSON extraction represents booleans as 0/1.
        for key in ("can_apply", "firewalld_active", "ufw_active"):
            if result["assessment"].get(key) in (0, 1):
                result["assessment"][key] = bool(result["assessment"][key])
    return result


def server_rows(db):
    """Project large/private evidence in SQL before decoding a fleet list."""
    fields = ("status", "digest", "collected_at", "last_attempt_at", "error")
    removed = ("firewall_snapshot", "firewall_activation", "discovery_changes", "firewall_change_results", "_compiled", "_metadata_overrides", "risky_ports", "_risk_matches", "_source_bank_job", "_firewall_activation_job")
    if getattr(db, "dialect", "sqlite") == "postgresql":
        base = "document - ARRAY["+",".join("'"+key+"'" for key in removed)+"]::text[]"
        pairs = ",".join("'%s',document->'firewall_snapshot'->'%s'" % (key,key) for key in fields)
        expression = "CASE WHEN jsonb_typeof(document->'firewall_snapshot')='object' THEN jsonb_set("+base+",'{firewall_snapshot}',jsonb_build_object("+pairs+",'rule_count',jsonb_array_length(COALESCE(document->'firewall_snapshot'->'rules','[]'::jsonb)),'summary_only',true)) ELSE "+base+" END"
        pairs = ",".join("'%s',document->'firewall_activation'->'%s'" % (key,key) for key in MAINTENANCE_FIELDS)
        facts = ",".join("'%s',document->'firewall_activation'->'assessment'->'%s'" % (key,key) for key in MAINTENANCE_FACTS)
        expression = "CASE WHEN jsonb_typeof(document->'firewall_activation')='object' THEN jsonb_set(("+expression+"),'{firewall_activation}',jsonb_build_object("+pairs+",'assessment',jsonb_build_object("+facts+"))) ELSE ("+expression+") END"
        # OFFSET0 parses each large canonical TEXT snapshot once per host.
        sql = "SELECT ("+expression+")::text FROM servers CROSS JOIN LATERAL (SELECT data::jsonb AS document OFFSET 0) projected"
    else:
        base = "json_remove(data,"+",".join("'$."+key+"'" for key in removed)+")"
        pairs = ",".join("'%s',json_extract(data,'$.firewall_snapshot.%s')" % (key,key) for key in fields)
        expression = "CASE WHEN json_type(data,'$.firewall_snapshot')='object' THEN json_set("+base+",'$.firewall_snapshot',json_object("+pairs+",'rule_count',COALESCE(json_array_length(data,'$.firewall_snapshot.rules'),0),'summary_only',json('true'))) ELSE "+base+" END"
        pairs = ",".join("'%s',json_extract(data,'$.firewall_activation.%s')" % (key,key) for key in MAINTENANCE_FIELDS)
        # json_extract preserves native JSON types for arrays and booleans.
        facts = ",".join("'%s',json_extract(data,'$.firewall_activation.assessment.%s')" % (key,key) for key in MAINTENANCE_FACTS)
        expression = "CASE WHEN json_type(data,'$.firewall_activation')='object' THEN json_set(("+expression+"),'$.firewall_activation',json_object("+pairs+",'assessment',json_object("+facts+"))) ELSE ("+expression+") END"
        sql = "SELECT "+expression+" FROM servers"
    for row in rows(db,sql):
        yield json.loads(row[0])


def canonical_servers(db, selected=None):
    # Stream rows, rather than _all()/fetchall() of every full snapshot.
    if selected is not None and not selected: return
    ids=tuple(sorted(selected)) if selected is not None else ()
    sql="SELECT data FROM servers"+(" WHERE id IN ("+",".join("?" for _ in ids)+")" if selected is not None else "")
    for row in rows(db,sql,ids): yield json.loads(row[0])


def endpoint_labels(db):
    """Read only current agent-reported identities for traffic export labels."""
    if getattr(db, "dialect", "sqlite") == "postgresql":
        fields = "data::jsonb->>'hostname',(data::jsonb->'ips')::text"
    else:
        fields = "json_extract(data,'$.hostname'),json_extract(data,'$.ips')"
    return {
        identifier: (hostname or identifier, "; ".join(json.loads(ips) or []) if ips else "")
        for identifier, hostname, ips in rows(db, "SELECT id," + fields + " FROM servers", batch_size=128)
    }
