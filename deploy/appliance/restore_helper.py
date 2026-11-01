"""Fixed owned-cluster recovery database operations; bounded private stdin only."""
import hashlib
import json
from pathlib import Path
import re
import sys
import uuid

import psycopg
from psycopg import sql


def names(identifier):
    if not isinstance(identifier,str) or not re.fullmatch('[0-9a-f]{32}',identifier):raise ValueError('Invalid recovery identity')
    return {kind:'prthak_restore_'+identifier+'_'+kind for kind in ('metadata','traffic')}


def digest(value):return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()


def main():
    raw=sys.stdin.buffer.read(65537)
    if len(raw)>65536:raise ValueError()
    request=json.loads(raw);binding=request['binding'];targets=names(binding['restore_id'])
    if set(request)-{'action','binding','allow_empty_recovery'} or request['action'] not in ('inspect','create','verify'):raise ValueError()
    if set(binding)!={'restore_id','deployment_id','archive_sha256','target_epoch','fence_digest','source_databases'} or str(uuid.UUID(binding['deployment_id']))!=binding['deployment_id']:raise ValueError()
    if not isinstance(binding['target_epoch'],int) or isinstance(binding['target_epoch'],bool) or binding['target_epoch']<2 or any(not re.fullmatch('[0-9a-f]{64}',binding[key]) for key in ('archive_sha256','fence_digest')):raise ValueError()
    if set(binding['source_databases'])!={'metadata','traffic'} or any(not re.fullmatch('[a-z][a-z0-9_]{0,62}',value) or value in targets.values() for value in binding['source_databases'].values()):raise ValueError()
    private=json.loads(Path('/config/roles.json').read_text());database=private['database'];options={'host':'127.0.0.1','sslmode':'verify-full','sslrootcert':'/config/ca.pem','connect_timeout':5,'autocommit':True,'options':'-c statement_timeout=20000 -c lock_timeout=3000 -c synchronous_commit=remote_apply'}
    connect=lambda name,user='prthak_admin',password=None:psycopg.connect(dbname=name,user=user,password=private['secrets']['admin'] if password is None else password,**options)
    # Independently inspect BOTH old namespaces; the controller's boolean flag
    # alone is not a database writer fence.
    fences={}
    for kind,source in binding['source_databases'].items():
        with connect(source) as db:
            row=db.execute("SELECT data FROM runtime_deployment WHERE id='active'").fetchone()
            value=json.loads(row[0]) if row else {}
            if value.get('state')!='FENCED_RECOVERY' or value.get('namespace')!=kind or value.get('deployment_id')!=binding['deployment_id'] or value.get('recovery_id')!=binding['restore_id'] or value.get('recovery_fence_digest')!=binding['fence_digest'] or not isinstance(value.get('epoch'),int) or binding['target_epoch']<=value['epoch']:raise ValueError('Both original database writers must be fenced for this exact higher recovery epoch')
            fences[kind]=True
    fingerprint=digest(binding);provenance='Prthak reviewed recovery '+fingerprint
    with connect('postgres') as admin:
        primary=not admin.execute('SELECT pg_is_in_recovery()').fetchone()[0]
        for kind in ('metadata','traffic'):
            row=admin.execute('SELECT rolsuper,rolcreatedb,rolcreaterole,rolreplication,rolbypassrls,rolcanlogin,EXISTS(SELECT 1 FROM pg_auth_members WHERE member=pg_roles.oid) FROM pg_roles WHERE rolname=%s',(database[kind+'_user'],)).fetchone()
            if row is None or any(row[:5]) or row[5] is not True or row[6]:raise ValueError('Recovery imports require restricted login owners without elevated role membership')
        if request['action']=='create' and not primary:return {'phase':'not_primary','not_primary':True,'mutated':False,'binding_digest':fingerprint}
        if request['action']=='create':admin.execute('SELECT pg_advisory_lock(hashtext(%s))',('prthak-recovery-'+binding['deployment_id'],))
        existing={};created=False
        for kind,name in targets.items():
            row=admin.execute('SELECT pg_get_userbyid(datdba),shobj_description(oid,\'pg_database\') FROM pg_database WHERE datname=%s',(name,)).fetchone()
            if row and row[0]!=database[kind+'_user']:raise ValueError('A foreign recovery database exists')
            if row and row[1]!=provenance:
                if not (request['action']=='create' and request.get('allow_empty_recovery') is True):raise ValueError('A database without this exact recovery provenance exists')
                with connect(name) as candidate:
                    if candidate.execute("SELECT EXISTS(SELECT 1 FROM pg_tables WHERE schemaname NOT IN ('pg_catalog','information_schema')) OR EXISTS(SELECT 1 FROM pg_namespace WHERE nspname NOT IN ('pg_catalog','information_schema','public','pg_toast') AND nspname NOT LIKE 'pg_temp_%' AND nspname NOT LIKE 'pg_toast_temp_%') OR EXISTS(SELECT 1 FROM pg_extension WHERE extname<>'plpgsql')").fetchone()[0]:raise ValueError('An interrupted candidate is not empty')
            if request['action']=='create':
                if not row:
                    admin.execute(sql.SQL('CREATE DATABASE {} OWNER {} TEMPLATE template0').format(sql.Identifier(name),sql.Identifier(database[kind+'_user'])));created=True
                admin.execute(sql.SQL('COMMENT ON DATABASE {} IS {}').format(sql.Identifier(name),sql.Literal(provenance)))
            existing[kind]=bool(row)
        if request['action']=='inspect':
            if any(existing.values()):raise ValueError('Recovery targets must initially be absent')
            return {'phase':'inspected','targets_absent':True,'source_fenced':True,'owners_verified':True,'binding_digest':fingerprint,'database_names':targets}
    if request['action']=='create':
        for kind,name in targets.items():
            with connect(name,database[kind+'_user'],private['secrets'][kind]) as db:
                if db.execute("SELECT EXISTS(SELECT 1 FROM pg_tables WHERE schemaname NOT IN ('pg_catalog','information_schema'))").fetchone()[0]:raise ValueError('Candidate is no longer empty; do not repeat a CREATE phase after import')
        return {'phase':'created','created':True,'mutated':created,'empty':True,'owners_verified':True,'not_primary':False,'binding_digest':fingerprint,'database_names':targets}
    markers={};catalog=[]
    for kind,name in targets.items():
        with connect(name,database[kind+'_user'],private['secrets'][kind]) as db:
            if db.execute('SELECT current_user').fetchone()[0]!=database[kind+'_user']:raise ValueError()
            rows=db.execute("SELECT tablename,tableowner FROM pg_tables WHERE schemaname='public' ORDER BY tablename").fetchall()
            if not rows or any(owner!=database[kind+'_user'] for table,owner in rows):raise ValueError('Candidate schema owners differ from the reviewed application role')
            row=db.execute("SELECT data FROM runtime_deployment WHERE id='active'").fetchone();marker=json.loads(row[0]) if row else {}
            if marker.get('deployment_id')!=binding['deployment_id'] or marker.get('epoch')!=binding['target_epoch'] or marker.get('namespace')!=kind or marker.get('import_id')!=binding['restore_id'] or marker.get('state') not in ('VERIFIED','READY'):raise ValueError('Candidate namespace identity/epoch has not been verified')
            markers[kind]={key:marker[key] for key in ('deployment_id','epoch','namespace','state')};catalog.append({'kind':kind,'tables':[table for table,owner in rows]})
    return {'phase':'verified','verified':True,'marker_verified':True,'new_connections':True,'namespace_markers':markers,'catalog_digest':digest(catalog),'binding_digest':fingerprint,'database_names':targets}


if __name__=='__main__':
    try:result=main()
    except Exception as error:
        print(json.dumps({'phase':'error','code':getattr(error,'sqlstate',None) or type(error).__name__,'error':'Fixed recovery database operation failed; originals were preserved'}));raise SystemExit(1)
    print(json.dumps(result,separators=(',',':')))
