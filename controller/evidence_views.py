"""Bounded public evidence reads; canonical authority matrices are not paged."""
from contextlib import contextmanager
import csv
import io
import json
import re
import tempfile
import threading

from .inventory_views import rows

MAX_EXPORT_BYTES=64*1024*1024
EXPORT_SLOTS=threading.BoundedSemaphore(2)
FIELDS=('session_id','server_id','hostname','source_ip','source_cidr','port','protocol','service','process','count','verdicts','first_seen','last_seen','eligible_for_auto','excluded_reason')

class ExportBusy(RuntimeError):
    pass


def server_filter(session,identifier):
    if identifier is not None and (not isinstance(identifier,str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,100}',identifier) or identifier not in session['server_ids']):
        raise ValueError('server_id must identify a member of this learning session')
    return identifier


def clause(session_id,server_id=None):
    return ('session_id=?'+(' AND server_id=?' if server_id is not None else ''),(session_id,server_id) if server_id is not None else (session_id,))


def evidence_rows(db,session_id,server_id=None,limit=None,offset=0):
    where,args=clause(session_id,server_id)
    sql='SELECT data FROM learning_evidence WHERE '+where+' ORDER BY server_id,id'
    if limit is not None:sql+=' LIMIT ? OFFSET ?';args+= (limit,offset)
    for row in rows(db,sql,args):yield json.loads(row[0])


def _json(value,default):
    return json.loads(value) if isinstance(value,str) else default if value is None else value


def server_view(db,identifier,ssh=True):
    paths=('hostname','ips','protection.ssh_ports','protection.controller_url','protection.controller_addresses','learning_coverage','collector_state')
    postgres=getattr(db,'dialect','sqlite')=='postgresql'
    expressions=["data::jsonb "+('#>>' if index in (0,3,6) else '#>')+" '{"+path.replace('.',',')+"}'" if postgres else "json_extract(data,'$."+path+"')" for index,path in enumerate(paths)]
    row=db.execute('SELECT '+','.join(expressions)+' FROM servers WHERE id=?',(identifier,)).fetchone()
    if not row:return {'id':identifier,'hostname':identifier,'listeners':[],'protection':{}}
    value={path:_json(row[index],None) if index in (1,2,4,5) else row[index] for index,path in enumerate(paths)}
    result={'id':identifier,'hostname':value['hostname'] or identifier,'ips':value['ips'] or [],'learning_coverage':value['learning_coverage'],'collector_state':value['collector_state'] or 'unknown','protection':{'ssh_ports':value['protection.ssh_ports'] or [],'controller_url':value['protection.controller_url'] or '', 'controller_addresses':value['protection.controller_addresses'] or []},'listeners':[]}
    if ssh:
        if postgres:
            sql="SELECT DISTINCT item->>'port' FROM servers CROSS JOIN LATERAL jsonb_array_elements(COALESCE(data::jsonb->'listeners','[]'::jsonb)) item WHERE id=? AND (lower(COALESCE(item->>'service',''))='ssh' OR position('sshd' in lower(COALESCE(item->>'service','')||' '||COALESCE(item->>'process','')||' '||COALESCE(item->>'systemd_unit','')))>0)"
        else:
            sql="SELECT DISTINCT json_extract(item.value,'$.port') FROM servers,json_each(data,'$.listeners') item WHERE servers.id=? AND (lower(COALESCE(json_extract(item.value,'$.service'),''))='ssh' OR instr(lower(COALESCE(json_extract(item.value,'$.service'),'')||' '||COALESCE(json_extract(item.value,'$.process'),'')||' '||COALESCE(json_extract(item.value,'$.systemd_unit'),'')),'sshd')>0)"
        result['listeners']=[{'port':int(item[0]),'service':'ssh'} for item in db.execute(sql,(identifier,)) if item[0] is not None]
    return result


def policy_summaries(db,session_id):
    fields=('id','name','server_id','hostname','status','error')
    if getattr(db,'dialect','sqlite')=='postgresql':
        expressions=["data::jsonb->>'"+field+"'" for field in fields]
    else:expressions=["json_extract(data,'$."+field+"')" for field in fields]
    total=db.execute('SELECT COUNT(*) FROM learning_allow_policies WHERE session_id=?',(session_id,)).fetchone()[0]
    result=[]
    for row in db.execute('SELECT '+','.join(expressions)+' FROM learning_allow_policies WHERE session_id=? ORDER BY id LIMIT 100',(session_id,)):
        item={field:row[index] for index,field in enumerate(fields)};item['error']=(item['error'] or '')[:512];item['summary_only']=True;result.append(item)
    return result,int(total)


def pending_summary(plan):
    # This list is a navigation hint, never an authorization or review matrix.
    result={field:plan.get(field) for field in ('id','session_id','kind','status','created_at','expires_at','digest')}
    result['summary_only']=True
    return result


def pending_summaries(db,session_id,limit=100):
    from .store import stamp
    fields=('id','session_id','kind','status','created_at','expires_at','digest')
    def expression(field):
        return "data::jsonb->>'"+field+"'" if getattr(db,'dialect','sqlite')=='postgresql' else "json_extract(data,'$."+field+"')"
    where=expression('session_id')+'=? AND '+expression('status')+" IN ('reviewed','awaiting_second_confirmation') AND "+expression('expires_at')+'>?'
    args=(session_id,stamp())
    total=int(db.execute('SELECT COUNT(*) FROM learning_policy_previews WHERE '+where,args).fetchone()[0])
    result=[]
    for row in db.execute('SELECT '+','.join(expression(field) for field in fields)+' FROM learning_policy_previews WHERE '+where+' ORDER BY id LIMIT ?',args+(limit,)):
        result.append(pending_summary({field:row[index] for index,field in enumerate(fields)}))
    return result,total


def csv_values(row):
    values=[]
    for field in FIELDS:
        value=';'.join(row[field]) if field=='verdicts' else row.get(field,'')
        if isinstance(value,str) and value.lstrip(' \t\r\n').startswith(('=','+','-','@')):value="'"+value
        values.append(value)
    return values


@contextmanager
def csv_spool(store,session_id,server_id=None,*,max_bytes=None):
    from .learning_policies import _row_public
    max_bytes=MAX_EXPORT_BYTES if max_bytes is None else max_bytes
    if not 3<=max_bytes<=MAX_EXPORT_BYTES:raise ValueError('Invalid complete CSV size bound')
    if not EXPORT_SLOTS.acquire(blocking=False):raise ExportBusy('CSV export capacity is busy; retry shortly')
    try:
        # Anonymous/unlinked on POSIX: closing or a killed worker removes it.
        with tempfile.TemporaryFile(mode='w+b',dir=store.path if getattr(store,'path',None) else None) as output:
            size=0
            def write(values):
                nonlocal size
                line=io.StringIO(newline='');csv.writer(line).writerow(values);raw=line.getvalue().encode('utf-8')
                if size+len(raw)>max_bytes:raise ValueError(f'Complete CSV exceeds the {max_bytes} byte limit; export a smaller session or add a session-member server_id filter')
                output.write(raw);size+=len(raw)
            output.write(b'\xef\xbb\xbf');size=3
            if size>max_bytes:raise ValueError('Complete CSV exceeds its size bound')
            write(FIELDS)
            with store.read_meta() as db:
                if getattr(db,'dialect','sqlite')=='sqlite':db.execute('BEGIN')
                from .session_views import header
                session=header(db,session_id)
                server_filter(session,server_id)
                current_id,current_server=None,None
                for row in evidence_rows(db,session_id,server_id):
                    if row['server_id']!=current_id:current_id=row['server_id'];current_server=server_view(db,current_id)
                    write(csv_values(_row_public(row,current_server)))
            output.flush();output.seek(0)
            yield output,size
    finally:EXPORT_SLOTS.release()
