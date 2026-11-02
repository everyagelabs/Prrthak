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


def server_rows(db):
    """Project large evidence in SQL before decoding a fleet list in Python."""
    fields = ("status", "digest", "collected_at", "last_attempt_at", "error")
    if getattr(db, "dialect", "sqlite") == "postgresql":
        pairs = ",".join("'%s',document->'firewall_snapshot'->'%s'" % (key,key) for key in fields)
        base="document - ARRAY['firewall_snapshot','discovery_changes','firewall_change_results','_compiled','_metadata_overrides','risky_ports','_risk_matches','_source_bank_job']::text[]"
        expression = "CASE WHEN document->'firewall_snapshot' IS NOT NULL THEN jsonb_set("+base+",'{firewall_snapshot}',jsonb_build_object("+pairs+",'rule_count',jsonb_array_length(COALESCE(document->'firewall_snapshot'->'rules','[]'::jsonb)),'summary_only',true)) ELSE "+base+" END"
        # OFFSET0 is a projection barrier: parse a large stored TEXT snapshot
        # into jsonb once per host, not once for every summary field.
        sql = "SELECT ("+expression+")::text FROM servers CROSS JOIN LATERAL (SELECT data::jsonb AS document OFFSET 0) projected"
    else:
        base = "json_remove(data,'$.firewall_snapshot','$.discovery_changes','$.firewall_change_results','$._compiled','$._metadata_overrides','$.risky_ports','$._risk_matches','$._source_bank_job')"
        pairs = ",".join("'%s',json_extract(data,'$.firewall_snapshot.%s')" % (key,key) for key in fields)
        expression = "CASE WHEN json_type(data,'$.firewall_snapshot')='object' THEN json_set("+base+",'$.firewall_snapshot',json_object("+pairs+",'rule_count',COALESCE(json_array_length(data,'$.firewall_snapshot.rules'),0),'summary_only',json('true'))) ELSE "+base+" END"
        sql = "SELECT "+expression+" FROM servers"
    for row in rows(db,sql):
        yield json.loads(row[0])


def canonical_servers(db, selected=None):
    # Stream rows, rather than _all()/fetchall() of every full snapshot.
    if selected is not None and not selected: return
    ids=tuple(sorted(selected)) if selected is not None else ()
    sql="SELECT data FROM servers"+(" WHERE id IN ("+",".join("?" for _ in ids)+")" if selected is not None else "")
    for row in rows(db,sql,ids): yield json.loads(row[0])
