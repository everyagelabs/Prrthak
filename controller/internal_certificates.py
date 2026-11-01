"""Internal appliance identity lifecycle, separate from endpoint/web issuers.

Only same-CA, same-key leaf renewal is automatic. A CA-holding member cannot be
securely revoked by a CRL alone; suspension blocks sync/renewal and an explicit
offline fencing/trust/credential recovery gate protects decommissioning.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
from pathlib import Path
import re
import secrets
import socket
import ssl
import struct
import sys
from datetime import timedelta

from .store import now,stamp,digest,parse_time

RENEW_BEFORE=timedelta(days=30)
DENIED_STATES={'suspended','revoked','decommissioning','decommissioned'}


def assert_member_active(member):
    if not member or member.get('state') in DENIED_STATES:
        raise PermissionError('This appliance member is suspended; synchronization and certificate renewal are denied')


def certificate_info(pem):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes,serialization
    value=x509.load_pem_x509_certificate(pem.encode())
    return {'fingerprint':value.fingerprint(hashes.SHA256()).hex(),'serial':str(value.serial_number),'not_before':value.not_valid_before_utc.isoformat(),'not_after':value.not_valid_after_utc.isoformat(),'public_key_digest':hashlib.sha256(value.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()}


def renewal_due(pem,at=None):
    from cryptography import x509
    return x509.load_pem_x509_certificate(pem.encode()).not_valid_after_utc<=(at or now())+RENEW_BEFORE


def validate_candidate(payload):
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.x509.oid import ExtendedKeyUsageOID
    expected={'ca','certificate','previous_certificate','node_id','node_ip'}
    if not isinstance(payload,dict) or set(payload)!=expected or any(not isinstance(payload[key],str) for key in expected):raise ValueError('Exact public internal certificate validation fields are required')
    if any('PRIVATE KEY' in payload[key] for key in ('ca','certificate','previous_certificate')):raise ValueError('Private keys are not accepted by public certificate validation')
    ca=x509.load_pem_x509_certificate(payload['ca'].encode());leaf=x509.load_pem_x509_certificate(payload['certificate'].encode());previous=x509.load_pem_x509_certificate(payload['previous_certificate'].encode())
    if not ca.extensions.get_extension_for_class(x509.BasicConstraints).value.ca or leaf.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:raise ValueError('A dedicated issuing CA and non-CA node leaf are required')
    leaf.verify_directly_issued_by(ca)
    if leaf.not_valid_before_utc>now()+timedelta(minutes=2) or leaf.not_valid_after_utc<=now()+timedelta(days=1) or leaf.not_valid_after_utc>now()+timedelta(days=100) or leaf.not_valid_after_utc>ca.not_valid_after_utc:raise ValueError('Renewed internal identity must be currently valid within its issuer lifetime')
    form=lambda cert:cert.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)
    if form(leaf)!=form(previous):raise ValueError('Automatic renewal cannot replace the registered node key')
    sans=leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    ips={str(value) for value in sans.get_values_for_type(x509.IPAddress)};dns=set(sans.get_values_for_type(x509.DNSName))
    if ips!={str(ipaddress.ip_address(payload['node_ip'])),'127.0.0.1'} or dns!={payload['node_id'],'localhost','router'}:raise ValueError('Internal leaf identity must be restricted to this exact node and local appliance aliases')
    usages=set(leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value)
    if usages!={ExtendedKeyUsageOID.SERVER_AUTH,ExtendedKeyUsageOID.CLIENT_AUTH}:raise ValueError('Both internal TLS client and server authentication are required')
    info=certificate_info(payload['certificate']);info.update(previous_valid=previous.not_valid_before_utc<=now()<previous.not_valid_after_utc,previous_not_after=previous.not_valid_after_utc.isoformat())
    return info


def _member_binding(config,member):
    return digest({'revision':config['revision'],'deployment_id':config['deployment_id'],'member':{key:member.get(key) for key in ('id','ip','site','role','state','transport_public_key','certificate_revision')},'voters':config.get('voters',[])})


def suspension(api,node_id,actor,*,expected_binding=None,plan_id=None):
    """Deny future delivery, without pretending copied credentials are revoked."""
    with api.app.store.lock,api.app.store.meta() as db:
        config=api._config(db);member=next((item for item in config.get('members',[]) if item['id']==node_id),None)
        if not member:raise KeyError(node_id)
        if plan_id and member.get('suspension_plan_id')==plan_id:return member['suspension_receipt']
        if expected_binding and expected_binding!=_member_binding(config,member):
            from .firewall import WorkflowConflict
            raise WorkflowConflict('Controller membership changed after suspension review',{})
        receipt={'node_id':node_id,'state':'suspended','sync_blocked':True,'renewal_blocked':True,'runtime_credentials_revoked':False,'requires_offline_recovery':True}
        member.update(state='suspended',suspended_at=stamp(),suspended_by=actor,suspension_plan_id=plan_id,suspension_receipt=receipt);config['revision']+=1
        api.app.store._put(db,'maintenance_settings',config)
        api.app.store.audit('appliance.member_suspended',actor,{'node_id':node_id,'runtime_credentials_revoked':False,'requires_offline_recovery':True},db)
    return receipt


def suspension_preview(api,body,actor):
    from .platform import _private_json
    api.manager._production()
    if not isinstance(body,dict) or set(body)-{'node_id','expected_revision'}:raise ValueError('Choose one registered controller for suspension review')
    config=api._config();member=next((item for item in config.get('members',[]) if item['id']==body.get('node_id')),None)
    if not member:raise KeyError(body.get('node_id'))
    if body.get('expected_revision',config['revision'])!=config['revision']:raise ValueError('Reload current controller membership before review')
    blockers=[]
    if member.get('state') in DENIED_STATES:blockers.append('This member is already suspended or requires offline recovery')
    if sum(item.get('state') not in DENIED_STATES for item in config['members'])<=1:blockers.append('Do not suspend the last active control identity; use a reviewed offline recovery plan')
    plan={'id':secrets.token_hex(16),'node_id':member['id'],'binding':_member_binding(config,member),'requested_by':actor,'expires_at':stamp(now()+timedelta(minutes=10)),'confirmation_nonce':secrets.token_urlsafe(24),'confirmation_phrase':'SUSPEND CONTROLLER '+member['id'],'can_apply':not blockers,'blockers':blockers,'summary':{'node':{key:member.get(key) for key in ('id','site','ip','role','state')},'runtime_credentials_revoked':False,'voter_removed':False,'warning':'Suspension denies future sync/renewal and removes web routing. A former controller retains CA/database secrets; secure decommission requires fenced offline recovery.'}}
    plan['digest']=digest(plan);_private_json(api.manager.root/'internal-node-plans'/(plan['id']+'.json'),plan)
    return plan


def suspension_apply(api,body,actor):
    from .platform import _private_json,_read_json
    from .firewall import WorkflowConflict
    api.manager._production()
    if not isinstance(body,dict) or not re.fullmatch('[0-9a-f]{32}',body.get('preview_id','')):raise ValueError('Review this exact controller suspension first')
    path=api.manager.root/'internal-node-plans'/(body['preview_id']+'.json');plan=_read_json(path)
    if not plan or any(body.get(key)!=plan[key] for key in ('digest','confirmation_nonce','confirmation_phrase')):raise WorkflowConflict('Confirm the exact reviewed controller suspension',{})
    if plan.get('result'):return plan['result']
    if not plan['can_apply'] or parse_time(plan['expires_at'])<=now():raise WorkflowConflict('Suspension review is blocked or expired',{})
    result=suspension(api,plan['node_id'],actor,expected_binding=plan['binding'],plan_id=plan['id'])
    plan['result']=result;_private_json(path,plan);return result


def status(api):
    from .platform import _read_json
    config=api._config();nodes=[];issuer=None;issuer_error=None;issuance_allowed=None
    try:
        pointer=_read_json(api.manager.root/'appliance-material.json')
        if pointer:
            material=json.loads(api.manager.vault.get(pointer['material_ref']))
            marker=_read_json(api.manager.root/'appliance-authority.json')
            expected={'ca_sha256':hashlib.sha256(material['ca'].encode()).hexdigest(),'sync_sha256':hashlib.sha256(material.get('sync_key','').encode()).hexdigest()}
            if material.get('pki_purpose')!='internal-database-v1' or marker and marker!=expected:raise ValueError('Protected authority mismatch')
            issuer=certificate_info(material['ca'])
            remaining=(parse_time(issuer['not_after'])-now()).total_seconds();issuance_allowed=remaining>120*86400
            issuer.update(days_remaining=int(remaining//86400),automatic_leaf_issuance_allowed=issuance_allowed,requires_offline_recovery=not issuance_allowed)
            if not issuance_allowed:issuer_error='Internal issuer needs reviewed offline recovery before new leaf issuance'
        elif (api.manager.root/'appliance-material.json').exists() or (api.manager.root/'appliance-authority.json').exists() or any(member.get('node_certificate') for member in config.get('members',[])) or getattr(api.app.store,'ha',False) or api.manager.active_profile() or any((api.manager.root/'policy-signing').glob('*.seed')):
            raise ValueError('Protected authority is missing')
        else:
            with api.app.store.read_meta() as db:
                if db.execute("SELECT 1 FROM maintenance_settings WHERE id LIKE 'internal-cert-%' LIMIT 1").fetchone():raise ValueError('Issued internal authority history requires matching recovery')
    except (ValueError,KeyError,TypeError,OSError):
        issuance_allowed=False;issuer_error='Protected internal authority requires reviewed recovery'
    for member in config.get('members',[]):
        info=member.get('internal_certificate')
        if not info and member.get('node_certificate'):
            try:info=certificate_info(member['node_certificate'])
            except (ValueError,TypeError):info=None
        remaining=(parse_time(info['not_after'])-now()).total_seconds() if info else None
        nodes.append({'id':member['id'],'site':member.get('site'),'ip':member.get('ip'),'role':member.get('role'),'state':member.get('state'),'certificate':info,'days_remaining':int(remaining//86400) if remaining is not None else None,'renewal_due':remaining is not None and remaining<=RENEW_BEFORE.total_seconds(),'renewal_allowed':member.get('state') not in DENIED_STATES and issuance_allowed is not False,'applied':member.get('internal_tls_receipt'),'decommission_gate':decommission_gate(api,member['id'])})
    local=api._local();runtime=None
    try:runtime=api.client.status().get('internal_tls')
    except Exception:pass
    operation=local.get('internal_tls_operation')
    return {'revision':config['revision'],'renew_before_days':30,'leaf_lifetime_days':90,'automatic_scope':'same_ca_same_registered_key','issuer':issuer,'nodes':nodes,'local_runtime':runtime,'local_operation':{key:operation.get(key) for key in ('id','target','phase','attempt','error','retry_after')} if operation else None,'error':issuer_error or local.get('internal_tls_error'),'secure_revocation_requires_offline_recovery':True,'cross_ca_live_rotation_supported':False}


def decommission_gate(api,node_id):
    member=next((item for item in api._config().get('members',[]) if item['id']==node_id),None)
    if not member:raise KeyError(node_id)
    return {'node_id':node_id,'can_decommission':False,'can_suspend':member.get('state') not in DENIED_STATES,'requires_offline_recovery':True,'blockers':['Fence the retired controller and every old writable database process','A former controller retains internal CA and database secrets; CRL-only revocation cannot remove that authority','Rotate the internal CA, synchronization secret and every database-role credential through the reviewed offline recovery workflow','Rebuild the fixed three-voter topology and verify all new identities before removing the old member']}


def _record_receipt(api,fingerprint,verified):
    identifier=api._identity()['id']
    with api.app.store.lock,api.app.store.meta() as db:
        config=api._config(db);member=next((item for item in config.get('members',[]) if item['id']==identifier),None)
        if member:
            old=member.get('internal_tls_receipt',{})
            if old.get('fingerprint')==fingerprint and old.get('runtime_verified')==bool(verified):return
            member['internal_tls_receipt']={'fingerprint':fingerprint,'runtime_verified':bool(verified),'status':'verified' if verified else 'staged','updated_at':stamp()}
            api.app.store._put(db,'maintenance_settings',config)


def reconcile(api,desired):
    """One bounded per-node same-CA renewal pass through durable manager jobs."""
    from .platform import _private_json
    local=api._local();state=api.client.status();installed=state.get('internal_tls',{});target=certificate_info(desired['pki']['certificate'])['fingerprint']
    if not installed.get('fingerprint') and not state.get('cluster',{}).get('configured'):return False  # initial install
    if installed.get('fingerprint')==target and not installed.get('drift') and installed.get('phase') in (None,'committed'):
        if installed.get('phase')=='committed':_record_receipt(api,target,installed.get('runtime_verified',False))
        changed=local.pop('internal_tls_operation',None) or local.get('internal_tls_error');local.pop('internal_tls_error',None)
        if changed:_private_json(api.manager.root/'appliance-local.json',local)
        return False
    if 'internal_tls_v1' not in state.get('capabilities',[]):
        local['internal_tls_error']='Upgrade the fixed appliance manager before internal identity renewal';_private_json(api.manager.root/'appliance-local.json',local);return True
    operation=local.get('internal_tls_operation')
    if operation and installed.get('fingerprint')==operation['target'] and not installed.get('drift') and installed.get('phase')=='committed':operation=None;local.pop('internal_tls_operation',None)
    if operation and operation.get('certificate_pem'):
        from .store import parse_time
        if parse_time(certificate_info(operation['certificate_pem'])['not_after'])<=now():operation=None
    if not operation:
        operation={'id':secrets.token_hex(16),'target':target,'certificate_pem':desired['pki']['certificate'],'generation':desired['generation'],'phase':'prepare','attempt':0,'expected_fingerprint':installed['fingerprint']};local['internal_tls_operation']=operation
    target=operation['target']
    if operation.get('retry_after',0)>now().timestamp():return True
    _private_json(api.manager.root/'appliance-local.json',local)
    request_id=digest({'operation':operation['id'],'phase':operation['phase'],'attempt':operation['attempt']})[:32]
    try:job=api.client.job(request_id)
    except KeyError:
        request={'action':'internal-tls','request_id':request_id,'operation_id':operation['id'],'phase':operation['phase'],'expected_revision':state['revision'],'expected_fingerprint':operation['expected_fingerprint'],'certificate_pem':operation['certificate_pem'],'generation':operation['generation']}
        job=api.client.submit(request)
    if job.get('status') in ('queued','running'):return True
    if job.get('status') not in ('completed','applied'):
        observed=api.client.status().get('internal_tls',{}).get('phase')
        if observed in ('rolled_back','aborted'):
            operation.update(id=secrets.token_hex(16),phase='prepare',attempt=0,expected_fingerprint=api.client.status()['internal_tls']['fingerprint'])
        elif observed=='rollback_failed':operation.update(phase='abort',attempt=0)
        elif observed=='rollforward_pending':operation.update(phase='activate',attempt=0)
        else:operation['attempt']+=1
        operation.update(retry_after=now().timestamp()+60,error=job.get('error','Internal identity operation needs recovery'))
        _private_json(api.manager.root/'appliance-local.json',local);return True
    result=job.get('result',{});phase=operation['phase']
    if phase=='abort' and result.get('phase') in ('rolled_back','aborted'):
        operation.update(id=secrets.token_hex(16),phase='prepare',attempt=0,retry_after=now().timestamp()+60)
        _private_json(api.manager.root/'appliance-local.json',local);return True
    expected={'prepare':'prepared','activate':'activated','verify':'verified','commit':'committed'}
    if result.get('phase')!=expected.get(phase) or result.get('fingerprint')!=target or not result.get(expected.get(phase,'')):
        operation.update(attempt=operation['attempt']+1,retry_after=now().timestamp()+60,error='Exact internal certificate phase was not acknowledged')
    elif phase=='commit':
        _record_receipt(api,target,result.get('runtime_verified',False))
        local.pop('internal_tls_operation',None);local.pop('internal_tls_error',None)
    else:operation.update(phase={'prepare':'activate','activate':'verify','verify':'commit'}[phase],attempt=0,retry_after=0)
    _private_json(api.manager.root/'appliance-local.json',local);return True


def probe(payload,directory='/run/prthak-tls'):
    root=Path(directory);ports=payload.get('ports');name=payload.get('hostname');fingerprint=payload.get('fingerprint')
    if not isinstance(ports,list) or not ports or any(port not in (2379,2380,5432,8008) for port in ports) or not isinstance(name,str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,100}',name) or not re.fullmatch('[0-9a-f]{64}',fingerprint or ''):raise ValueError('Fixed internal TLS probe required')
    context=ssl.create_default_context(cafile=str(root/'ca.pem'));context.load_cert_chain(root/'node.pem',root/'node-key.pem')
    verified=[]
    for port in ports:
        with socket.create_connection(('127.0.0.1',port),timeout=5) as connection:
            if port==5432:
                connection.sendall(struct.pack('!II',8,80877103))
                if connection.recv(1)!=b'S':raise ValueError('PostgreSQL refused required TLS')
            with context.wrap_socket(connection,server_hostname=name) as tls:
                if hashlib.sha256(tls.getpeercert(binary_form=True)).hexdigest()!=fingerprint:raise ValueError('Runtime certificate fingerprint differs on internal port '+str(port))
                if port!=5432:
                    path='/health' if port in (2379,8008) else '/version'
                    tls.sendall(('GET '+path+' HTTP/1.1\r\nHost: '+name+'\r\nConnection: close\r\n\r\n').encode())
                    response=tls.recv(65536)
                    if not response.startswith(b'HTTP/1.') or not any(b' '+str(value).encode()+b' ' in response.split(b'\r\n',1)[0] for value in ((200,404) if port==2380 else (200,))):raise ValueError('Authenticated internal service did not respond')
                verified.append(port)
    return {'verified':True,'ports':verified,'fingerprint':fingerprint}


if __name__=='__main__':
    try:
        raw=sys.stdin.buffer.read(524289)
        if len(raw)>524288:raise ValueError('Bounded certificate payload required')
        payload=json.loads(raw)
        result=validate_candidate(payload) if sys.argv[1:]==['--validate'] else probe(payload) if sys.argv[1:]==['--probe'] else (_ for _ in ()).throw(ValueError('Fixed validation/probe mode required'))
        print(json.dumps(result))
    except Exception as error:
        print(json.dumps({'error':'Internal TLS validation failed','code':type(error).__name__}));raise SystemExit(1)
