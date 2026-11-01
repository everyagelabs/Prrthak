"""Explicit, scoped and acknowledged whole-host inbound enforcement.

Desired policy may keep compiling, but only an exact dedicated acknowledgement
can publish a whole-host fallback. Selection never enrolls future group members.
"""
from __future__ import annotations

import copy
from datetime import timedelta
import json
import re
import secrets
import uuid

from . import approvals
from .firewall import WorkflowConflict
from .review_limits import MAX_REVIEW_BYTES, encoded_size
from .store import digest, now, parse_time, stamp

CAPABILITY = 'host_default_deny_v1'
PROFILE = 'host-inbound-control-v1'
STATE = 'host_default_deny_state'
KIND = 'host_default_deny'
FOREVER = '9999-12-31T23:59:59Z'


def guarded(server):
    state = server.get(STATE) or {}
    return bool(state.get('enabled') or state.get('removal_pending') or server.get('_host_default_deny_active') or server.get('_compiled', {}).get('host_default_deny'))


def payload(server, ordinary):
    state = server.get(STATE) or {}
    if state.get('removal_pending') and isinstance(state.get('removal_payload'), dict):
        return copy.deepcopy(state['removal_payload'])
    if state.get('enabled'):
        return {**ordinary, 'mode': 'enforce', 'host_default_deny': True}
    return ordinary


def _normal(bundle):
    services = copy.deepcopy(bundle.get('services', []))
    return {'mode': 'enforce' if any(row.get('mode', bundle.get('mode')) == 'enforce' for row in services) else 'monitor', 'services': services}


def _selection(store, db, value):
    from .inventory_views import server_rows
    ids, groups = value.get('server_ids', []), value.get('group_ids', [])
    if any(not isinstance(items, list) or len(items) > 20000 or any(not isinstance(item, str) or not re.fullmatch(r'[A-Za-z0-9_.:-]{1,128}', item) for item in items) for items in (ids, groups)):
        raise ValueError('Select bounded explicit servers or saved server groups')
    if not ids and not groups:raise ValueError('Select at least one server or server group')
    selected, snapshots = set(ids), []
    if groups:
        servers, locations = list(server_rows(db)), store._all(db, 'locations')
        for identifier in sorted(set(groups)):
            group = store._get(db, 'groups', identifier)
            if not group:raise ValueError('A selected group no longer exists')
            members = sorted(store._group_members(group, servers, locations))
            snapshots.append({'group': group, 'server_ids': members})
            selected.update(members)
    if not selected or len(selected) > 20000:raise ValueError('The selection must resolve to 1..20000 existing servers')
    return sorted(selected), snapshots


def _target(store, db, server, action, overlays=None):
    from .managed import baseline, binding_digest
    state, protected = server.get(STATE) or {}, server.get('protection') or {}
    configuration = server.get('configuration_state') or {}
    current = baseline(server)
    blockers = []
    for field, label in (('last_seen','authenticated heartbeat'),('protection_reported_at','received protection snapshot')):
        try:fresh=now()-timedelta(seconds=180)<=parse_time(server.get(field,''))<=now()+timedelta(seconds=60)
        except (ValueError,TypeError):fresh=False
        if not fresh:blockers.append('A fresh '+label+' within 180 seconds is required')
    if CAPABILITY not in server.get('capabilities', []) or 'signed_assignments_v1' not in server.get('capabilities', []):blockers.append('Upgrade to an agent supporting signed host_default_deny_v1')
    if not protected.get('ready'):blockers.append('A ready protected SSH/controller baseline is required')
    if not server.get('ips'):blockers.append('Agent-reported endpoint IPs are required')
    if not re.fullmatch(r'[a-f0-9]{64}', configuration.get('digest', '')):blockers.append('A fresh authenticated endpoint configuration receipt is required')
    if action == 'enable':
        if configuration.get('allow_host_default_deny') is not True:blockers.append('Enable the local whole-host deny opt-in with a signed endpoint configuration kit')
        if protected.get('host_default_deny_control_profile') != PROFILE or not re.fullmatch(r'[a-f0-9]{64}', protected.get('host_default_deny_context_digest', '')):blockers.append('A fresh whole-host inbound network-context descriptor is required')
        if protected.get('host_default_deny_ready') is not True:blockers.extend(protected.get('host_default_deny_blockers') or ['The agent has not reported whole-host deny readiness'])
        overlays=overlays or {}
        if server['id'] in overlays.get('automatic',set()):blockers.append('Stop automatic learning before enabling whole-host deny')
        if server['id'] in overlays.get('policies',set()):blockers.append('Remove learning-owned access grants before enabling whole-host deny')
        if server['id'] in overlays.get('hosts',set()):blockers.append('Wait for the authenticated removal receipt of all learning-owned access grants')
        candidate = {**_normal(server.get('_compiled') or {}), 'mode':'enforce', 'host_default_deny':True}
    else:
        if not guarded(server):blockers.append('This server has no desired, active or pending whole-host deny to remove')
        version = server.get('last_good_version') or server.get('_last_managed_applied_version') or 0
        historical = db.execute('SELECT data FROM bundle_history WHERE server_id=? AND version=?', (server['id'],version)).fetchone() if version else None
        if server.get('_host_default_deny_active') and not historical:blockers.append('The last authenticated applied bundle is missing; controlled recovery is required')
        candidate = _normal(json.loads(historical[0])) if historical else {'mode':'monitor','services':[]}
    desired_digest = digest(candidate)
    maximum = db.execute('SELECT MAX(version) FROM bundle_history WHERE server_id=?', (server['id'],)).fetchone()[0] or 0
    floor = server.get('_recovery_version_floor') or 0
    version = current['version'] if desired_digest == current['digest'] and maximum <= current['version'] and floor < current['version'] else max(current['version'],maximum,floor)+1
    desired = {**current,'version':version,'digest':desired_digest,'binding_digest':binding_digest(server['id'],version,desired_digest,current['protection_digest'])}
    binding = {'revision':state.get('revision',0),'current':current,'desired':desired,'candidate':candidate,'configuration_digest':configuration.get('digest','')}
    view = {'server_id':server['id'],'hostname':server['hostname'],'revision':state.get('revision',0),'base_version':current['version'],
            **{key:desired[key] for key in ('version','digest','ips')},'services':[row for row in candidate['services'] if row.get('mode',candidate['mode'])=='enforce'],
            'protection':protected,'configuration_digest':configuration.get('digest',''),'blockers':blockers}
    return binding, view


def _snapshot(store, db, value):
    from .managed import _rollout_server
    ids, groups = _selection(store,db,value)
    bindings, targets, blockers = {}, [], []
    overlays={}
    if value['action']=='enable':
        from .approval_views import _expression
        automatic=set()
        for row in db.execute('SELECT '+_expression(db,('server_ids',))+" FROM sessions WHERE "+_expression(db,('status',))+"='active' AND "+_expression(db,('policy_action',))+"='auto_allow' AND "+_expression(db,('expires_at',))+'>?',(stamp(),)):
            automatic.update(json.loads(row[0]))
        removed="(data::jsonb->>'removed')::boolean" if getattr(db,'dialect','sqlite')=='postgresql' else "json_extract(data,'$.removed')"
        policies={row[0] for row in db.execute("SELECT DISTINCT server_id FROM learning_allow_policies WHERE COALESCE("+removed+",false)=false AND COALESCE("+_expression(db,('status',))+",'')<>'removed'")}
        def count(path):
            if getattr(db,'dialect','sqlite')=='postgresql':return "jsonb_array_length(COALESCE(data::jsonb#>'{"+path+"}','[]'::jsonb))"
            return "COALESCE(json_array_length(json_extract(data,'$."+path+"')),0)"
        hosts={row[0] for row in db.execute('SELECT id FROM learning_allow_hosts WHERE '+count('services')+'+'+count('applied_services')+'>0')}
        overlays={'automatic':automatic,'policies':policies,'hosts':hosts}
    remaining = MAX_REVIEW_BYTES
    for identifier in ids:
        server = _rollout_server(db, identifier)
        binding, view = _target(store,db,server,value['action'],overlays)
        remaining -= encoded_size(binding,remaining)+encoded_size(view,remaining)
        bindings[identifier]=binding;targets.append(view)
        blockers.extend(identifier+': '+reason for reason in view['blockers'])
    return {'server_ids':ids,'groups':groups,'bindings':bindings},targets,blockers


def _public(plan):
    return {key:copy.deepcopy(plan[key]) for key in ('id','revision','digest','plan_digest','confirmation_nonce','action','server_ids','group_ids','preview','can_apply','blockers','status','created_at','expires_at','approval') if key in plan}


def preview(store, value, actor, principal):
    if not isinstance(value,dict) or set(value)-{'action','server_ids','group_ids'} or value.get('action') not in ('enable','disable'):raise ValueError('Choose enable or disable with an explicit server/group selection')
    with store.lock,store.meta() as db:
        if getattr(db,'dialect','sqlite')=='sqlite':db.execute('BEGIN IMMEDIATE')
        approvals.identity(store,db,actor,principal)
        snapshot,targets,blockers=_snapshot(store,db,value)
        identifier=str(uuid.uuid4())
        selection={'action':value['action'],'server_ids':sorted(set(value.get('server_ids',[]))),'group_ids':sorted(set(value.get('group_ids',[])))}
        immutable={'id':identifier,'action':value['action'],'selection':selection,'snapshot':snapshot}
        plan={**immutable,'kind':KIND,'name':'Whole-server inbound default deny: '+value['action'],'revision':1,'server_ids':snapshot['server_ids'],
              'group_ids':selection['group_ids'],'digest':digest(immutable),'plan_digest':digest(immutable),'status':'draft','confirmation_count':0,
              'confirmation_nonce':secrets.token_urlsafe(32),'preview':{'targets':targets},'can_apply':not blockers,'blockers':blockers,
              'created_at':stamp(),'created_by':actor,'expires_at':stamp(now()+timedelta(minutes=10))}
        approvals.request(store,db,plan,actor,principal,endpoint_ids=plan['server_ids'],scope_kind=KIND)
        plan['approval']['scope']['action']=value['action']
        encoded_size(plan)
        store._put(db,'managed_rollouts',plan)
        store.audit('host_default_deny.previewed',actor,{'rollout_id':identifier,'action':value['action'],'digest':plan['digest'],'server_ids':plan['server_ids']},db)
        return _public(plan)


def get(store, identifier):
    with store.read_meta() as db:
        plan=store._get(db,'managed_rollouts',identifier)
        if not plan or plan.get('kind')!=KIND:raise KeyError(identifier)
        return _public(plan)


def confirm(store, identifier, value, actor, principal):
    expected={'digest','expected_revision','confirmation_nonce','acknowledge_downtime'}
    if not isinstance(value,dict) or set(value)!=expected or value.get('acknowledge_downtime') is not True or type(value.get('expected_revision')) is not int:
        raise ValueError('Manually acknowledge downtime for this exact push with its digest, revision and current nonce')
    with store.lock,store.meta() as db:
        if getattr(db,'dialect','sqlite')=='sqlite':db.execute('BEGIN IMMEDIATE')
        approvals.identity(store,db,actor,principal)
        plan=store._get(db,'managed_rollouts',identifier)
        if not plan or plan.get('kind')!=KIND:raise KeyError(identifier)
        request_digest=digest(value)
        if plan.get('status')=='queued' and plan.get('confirmed_request_digest')==request_digest and plan.get('created_by')==actor:return {**_public(plan),'duplicate':True}
        if plan.get('status')!='draft' or value['expected_revision']!=plan['revision'] or value['digest']!=plan['digest'] or not isinstance(value['confirmation_nonce'],str) or not secrets.compare_digest(value['confirmation_nonce'],plan['confirmation_nonce']) or parse_time(plan['expires_at'])<=now():
            raise WorkflowConflict('The downtime review changed, expired or is no longer current; create a fresh preview',_public(plan))
        try:snapshot,targets,blockers=_snapshot(store,db,plan['selection'])
        except (ValueError,KeyError):raise WorkflowConflict('The selected scope changed; create a fresh downtime review',_public(plan)) from None
        if snapshot!=plan['snapshot']:raise WorkflowConflict('Selected membership, desired policy, protection, endpoint configuration or state revision changed; review again',_public(plan))
        if blockers:raise ValueError(blockers[0])
        decision=approvals.decide(store,db,plan,actor,principal)
        for server_id,binding in snapshot['bindings'].items():
            server=store._get(db,'servers',server_id)
            prior=server.get(STATE) or {}
            state={'enabled':plan['action']=='enable','revision':binding['revision']+1,'rollout_id':identifier,'removal_pending':plan['action']=='disable',
                   'authorized_digest':binding['desired']['digest'],'authorized_protection_digest':binding['desired']['protection_digest'],
                   'authorized_configuration_digest':binding['configuration_digest'],'updated_at':stamp(),'updated_by':actor}
            if prior.get('last_outcome'):state['last_outcome']=prior['last_outcome']
            if plan['action']=='disable':state['removal_payload']=binding['candidate']
            server[STATE]=state;store._put(db,'servers',server)
        if plan['action']=='enable':
            selected=set(plan['server_ids'])
            for imported in store._all(db,'firewall_changes'):
                if imported.get('status') in ('draft','awaiting_second_confirmation','queued') and selected.intersection(imported.get('operations_by_server',{})):
                    imported.update(status='invalidated',confirmation_nonce='',invalidation_reason='Whole-server inbound deny requires dedicated acknowledged policy pushes')
                    store._put(db,'firewall_changes',imported)
                    store.audit('firewall_change.invalidated',actor,{'change_id':imported['id'],'host_default_deny_rollout_id':identifier},db)
        store.compile_all(db)
        for server_id,binding in snapshot['bindings'].items():
            from .managed import baseline
            server=store._get(db,'servers',server_id)
            if baseline(server)!=binding['desired']:raise WorkflowConflict('The compiled candidate no longer matches the exact reviewed bundle',{})
            current=binding['desired'];state=server[STATE]
            normalized={'authorized':True,'approval_id':identifier,'approved_digest':current['digest'],'approved_version':current['version'],
                'protection_digest':current['protection_digest'],'binding_digest':current['binding_digest'],'digest':current['binding_digest'],
                'approved_ips':current['ips'],'target_digest':current['target_digest'],'intent':'enforce_host_default_deny' if state['enabled'] else 'remove_host_default_deny',
                'confirmation_count':1,'expires_at':FOREVER,'approval_proof':decision,'host_default_deny_ack':True,
                'host_default_deny_revision':state['revision'],'host_default_deny_configuration_digest':binding['configuration_digest']}
            db.execute('UPDATE managed_approvals SET active=0 WHERE server_id=? AND active=1',(server_id,))
            db.execute('INSERT INTO managed_approvals(id,server_id,version,digest,protection_digest,approval_id,expires_at,active,data) VALUES(?,?,?,?,?,?,?,?,?)',
                (identifier+':'+server_id,server_id,current['version'],current['digest'],current['protection_digest'],identifier,FOREVER,1,json.dumps(normalized)))
        plan.update(status='queued',revision=plan['revision']+1,confirmation_count=1,confirmation_nonce='',confirmed_at=stamp(),confirmed_request_digest=request_digest,expires_at=FOREVER)
        store._put(db,'managed_rollouts',plan)
        store.audit('host_default_deny.pushed',actor,{'rollout_id':identifier,'action':plan['action'],'digest':plan['digest'],'acknowledge_downtime':True,'server_ids':plan['server_ids']},db)
        return _public(plan)


def valid_authority(store,db,server,approval):
    state=server.get(STATE) or {}
    proof=approval.get('approval_proof') or {}
    return (approval.get('host_default_deny_ack') is True and proof.get('scope',{}).get('kind')==KIND
        and proof.get('scope',{}).get('action')==('enable' if state.get('enabled') else 'disable')
        and approval.get('intent')==('enforce_host_default_deny' if state.get('enabled') else 'remove_host_default_deny')
        and CAPABILITY in server.get('capabilities',[]) and approval.get('host_default_deny_revision')==state.get('revision')
        and approval.get('approval_id')==state.get('rollout_id')
        and approval.get('host_default_deny_configuration_digest')==(server.get('configuration_state') or {}).get('digest')
        and (not state.get('enabled') or (server.get('configuration_state') or {}).get('allow_host_default_deny') is True))


def outcome(store,db,server,result,approval):
    if not approval or not approval.get('host_default_deny_ack'):return
    state=server.get(STATE) or {}
    current=state.get('rollout_id')==approval.get('approval_id')
    status=result['status']
    if status in ('enforced','rolled_back','error'):
        state['last_outcome']={key:result.get(key,'') for key in ('status','version','updated_at','error','rollback_reason','last_good_version','last_good_digest')}
        state['last_outcome']['rollout_id']=approval['approval_id']
        state['last_outcome'].update(last_good_version=server.get('last_good_version',0),last_good_digest=server.get('last_good_digest',''))
    if status=='enforced':
        row=db.execute('SELECT data FROM bundle_history WHERE server_id=? AND version=?',(server['id'],result['version'])).fetchone()
        applied=json.loads(row[0]);server['_host_default_deny_active']=applied.get('host_default_deny') is True
        # Removing the global fallback deliberately retains protected control
        # accepts, even when the application policy is an empty monitor bundle.
        server['_managed_rules_active']=result.get('managed_rules_present',True)
        if current:
            state['last_error']='';state['review_required']=False
            if not server['_host_default_deny_active'] and state.get('removal_pending'):
                state['removal_pending']=False;state.pop('removal_payload',None);server['_host_default_deny_recompile']=True
                server['_host_default_deny_owned_cleanup_required']=bool(server['_managed_rules_active'] and applied['mode']!='enforce')
    elif status=='rolled_back':
        row=db.execute('SELECT data FROM bundle_history WHERE server_id=? AND version=?',(server['id'],result['last_good_version'])).fetchone()
        server['_host_default_deny_active']=bool(row and json.loads(row[0]).get('host_default_deny'))
    if current and status in ('rolled_back','error'):
        state['review_required']=True;state['last_error']=result.get('error') or result.get('rollback_reason') or 'The acknowledged push failed; review and acknowledge a new push'
        db.execute('UPDATE managed_approvals SET active=0 WHERE approval_id=? AND server_id=?',(approval['approval_id'],server['id']))
    server[STATE]=state


def listing(store, value=None):
    """Paged scalar SQL projection: never decode fleet policy/source matrices."""
    from .approval_views import _expression
    from .managed import authorization
    value=value or {}
    if not isinstance(value,dict) or set(value)-{'limit','offset','server_ids','server_id','search'}:raise ValueError('Unsupported whole-server status filter')
    limit,offset=value.get('limit',50),value.get('offset',0)
    if type(limit) is not int or not 1<=limit<=500 or type(offset) is not int or offset<0:raise ValueError('Use a bounded status page')
    if 'server_id' in value and (not isinstance(value['server_id'],str) or not value['server_id'] or 'server_ids' in value):raise ValueError('Use one exact status server selection')
    filtered='server_ids' in value or 'server_id' in value
    ids=value.get('server_ids', [value['server_id']] if 'server_id' in value else [])
    if not isinstance(ids,list) or len(ids)>20000 or any(not isinstance(item,str) or len(item)>128 for item in ids):raise ValueError('Invalid status server selection')
    search=value.get('search','')
    if not isinstance(search,str) or len(search)>200:raise ValueError('Status search must be bounded text')
    fields={
        'id':('id',),'hostname':('hostname',),'ips':('ips',),'capabilities':('capabilities',),
        'active':('_host_default_deny_active',),'managed_active':('_managed_rules_active',),'applied_version':('applied_version',),
        'version':('_compiled','version'),'digest':('_compiled','digest'),'mode':('_compiled','mode'),
        'enabled':(STATE,'enabled'),'revision':(STATE,'revision'),'rollout_id':(STATE,'rollout_id'),'removal_pending':(STATE,'removal_pending'),
        'last_error':(STATE,'last_error'),'held':(STATE,'review_required'),
        'configuration_digest':('configuration_state','digest'),'local_optin':('configuration_state','allow_host_default_deny'),
        'protection_digest':('protection','digest'),'protection_ready':('protection','ready'),'ssh_ports':('protection','ssh_ports'),
        'protection_blockers':('protection','blockers'),'last_good_version':('last_good_version',),
        'outcome_status':(STATE,'last_outcome','status'),'outcome_rollout':(STATE,'last_outcome','rollout_id'),
        'outcome_version':(STATE,'last_outcome','version'),'outcome_at':(STATE,'last_outcome','updated_at'),
        'outcome_error':(STATE,'last_outcome','error'),'outcome_rollback':(STATE,'last_outcome','rollback_reason'),
        'outcome_good_version':(STATE,'last_outcome','last_good_version'),'outcome_good_digest':(STATE,'last_outcome','last_good_digest')}
    with store.read_meta() as db:
        where,args=[],[]
        if filtered and not ids:where.append('1=0')
        elif ids:
            where.append('id IN (SELECT '+('jsonb_array_elements_text(?::jsonb)' if getattr(db,'dialect','sqlite')=='postgresql' else 'value FROM json_each(?)')+')')
            args.append(json.dumps(sorted(set(ids))))
        if search:
            where.append('(LOWER('+_expression(db,('hostname',))+') LIKE ? ESCAPE \'!\' OR LOWER(id) LIKE ? ESCAPE \'!\')')
            needle='%'+search.casefold().replace('!','!!').replace('%','!%').replace('_','!_')+'%';args.extend((needle,needle))
        clause=' WHERE '+' AND '.join(where) if where else ''
        total=db.execute('SELECT COUNT(*) FROM servers'+clause,args).fetchone()[0]
        if getattr(db,'dialect','sqlite')=='postgresql':
            count="(SELECT COUNT(*) FROM jsonb_array_elements(COALESCE(servers.data::jsonb#>'{_compiled,services}','[]'::jsonb)) element WHERE element->>'mode'='enforce')"
        else:count="(SELECT COUNT(*) FROM json_each(json_extract(servers.data,'$._compiled.services')) WHERE json_extract(value,'$.mode')='enforce')"
        sql='SELECT '+','.join(_expression(db,path) for path in fields.values())+','+count+' FROM servers'+clause+' ORDER BY LOWER('+_expression(db,('hostname',))+'),id LIMIT ? OFFSET ?'
        items=[]
        for row in db.execute(sql,[*args,limit,offset]).fetchall():
            values={}
            for index,(key,path) in enumerate(fields.items()):
                raw=row[index]
                if isinstance(raw,str) and key not in ('id','hostname','digest','mode','rollout_id','last_error','configuration_digest','protection_digest','outcome_status','outcome_rollout','outcome_at','outcome_error','outcome_rollback','outcome_good_digest'):
                    try:raw=json.loads(raw)
                    except (ValueError,TypeError):pass
                values[key]=raw
            state={'enabled':bool(values['enabled']),'removal_pending':bool(values['removal_pending']),'revision':values['revision'] or 0,'rollout_id':values['rollout_id']}
            projected={'id':values['id'],'hostname':values['hostname'],'ips':values['ips'] or [],'capabilities':values['capabilities'] or [],STATE:state,
                '_host_default_deny_active':bool(values['active']),'_managed_rules_active':bool(values['managed_active']),
                '_compiled':{'mode':values['mode'],'version':values['version'] or 0,'digest':values['digest'] or '',**({'host_default_deny':True} if state['enabled'] else {})},
                'protection':{'digest':values['protection_digest'],'ready':bool(values['protection_ready'])},
                'configuration_state':{'digest':values['configuration_digest'],'allow_host_default_deny':bool(values['local_optin'])}}
            active=guarded(projected)
            allowed=authorization(store,db,projected)['authorized'] if active else False
            current_outcome=values['outcome_rollout']==state['rollout_id'] and bool(state['rollout_id'])
            if current_outcome and values['outcome_status'] in ('rolled_back','error'):status=values['outcome_status']
            elif allowed:status='removal_pending' if state['removal_pending'] else 'enforced' if values['active'] and values['applied_version']==values['version'] else 'pending'
            elif active:status='review_required'
            else:status='disabled' if values['outcome_status']=='enforced' and state['revision'] and not values['active'] else 'not_enabled'
            last_outcome={'status':values['outcome_status'],'rollout_id':values['outcome_rollout'],'version':values['outcome_version'],
                'updated_at':values['outcome_at'],'error':values['outcome_error'] or '','rollback_reason':values['outcome_rollback'] or '',
                'last_good_version':values['outcome_good_version'] or 0,'last_good_digest':values['outcome_good_digest'] or '',
                'is_current':current_outcome} if values['outcome_status'] else None
            blockers=list(values['protection_blockers'] or [])
            if values['last_error']:blockers.append(values['last_error'])
            items.append({'server_id':values['id'],'hostname':values['hostname'],'desired_enabled':state['enabled'],'active':bool(values['active']),
                'removal_pending':state['removal_pending'],'revision':state['revision'],'rollout_id':state['rollout_id'],'status':status,
                'desired_version':values['version'] or 0,'applied_version':values['applied_version'] or 0,'allowed_service_count':int(row[-1]),
                'protected_ssh_ports':values['ssh_ports'] or [],'capable':CAPABILITY in projected['capabilities'],'local_optin':bool(values['local_optin']),'blockers':blockers,
                'last_outcome':last_outcome,'last_good_version':values['last_good_version'] or 0,
                'active_verified':bool(values['active']) and values['outcome_status']=='enforced'})
    return {'items':items,'total':total,'limit':limit,'offset':offset,'has_more':offset+limit<total}
