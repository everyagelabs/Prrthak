#!/usr/bin/env python3
"""Public real-Store Python -> Go typed capture/proof interoperability vectors.

No agent or firewall is started. Current Entra principals are isolated database
fixtures, not a Microsoft login. CA/signing private material lives only in the
disposable fixture directory and is never exported. Historical omitted-field
rows are explicitly modelled; new scopes use the real reviewed APIs.
"""
from __future__ import annotations

import argparse
import copy
from datetime import timedelta
import hashlib
import json
from pathlib import Path
import sys
import uuid

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))

from controller import hit_monitoring as hm, learning, learning_policies as lp, traffic_capture
from controller.policy_signing import PolicySigner
from controller.store import now, stamp
from controller.tests.test_approvals import IndependentApprovalTests
from controller.tests.fixtures.generate_host_default_deny import endpoint_public_identity


def event(kind, source, identity, point):
    backend, unit, verdict = traffic_capture.TYPED[kind]
    return dict(event_id=hashlib.sha256(identity.encode()).hexdigest(), source_ip=source,
                port=443, protocol='tcp', verdict=verdict, count=1, first_seen=point,
                last_seen=point, capture_kind=kind, capture_backend=backend,
                count_unit=unit, address_family='ipv6' if ':' in source else 'ipv4')


def scoped_events(events, domain, scope_id):
    result = copy.deepcopy(events)
    for item in result:
        item['event_id'] = hashlib.sha256((domain+'\0'+scope_id+'\0'+item['event_id']).encode()).hexdigest()
    return result


def generate_case(name, kinds, *, legacy=False):
    fixture = IndependentApprovalTests()
    try:
        fixture.setUp()
        store = fixture.store
        root = store.path
        ips = ['10.70.0.1', '2001:db8:10::1']
        body = {'hostname':'target', 'ips':ips, 'listeners':[
            {'port':443, 'protocol':'tcp', 'address':'::', 'service':'HTTPS', 'process':'nginx'}],
            'firewalld_state':'running', 'discovery_performed':True, 'discovered_at':stamp(),
            'capabilities':['signed_assignments_v1','learning_discovery_v1','learning_auto_allow_v1',
                            'port_hit_monitor_v1','traffic_capture_v1']}
        store.report('target', body)
        if legacy:
            # Explicit stored pre-feature history, never a downgrade through a
            # current API. No access authority or proof is created/relabelled.
            session={'id':str(uuid.uuid4()),'server_ids':['target'],'selection_mode':'manual',
                     'policy_action':'observe','ports':[{'port':443,'protocol':'tcp'}],
                     'starts_at':stamp(),'expires_at':stamp(now()+timedelta(hours=1)),'status':'active'}
            monitor={'id':str(uuid.uuid4()),'name':'Historical journal-only monitor','ports':session['ports'],
                     'retention_hours':1,'enabled':True,'revision':1,'target_count':1,
                     'created_at':stamp(),'started_at':stamp(),'updated_at':stamp()}
            with store.meta() as db:
                store._put(db,'sessions',session)
                store._put(db,'hit_monitors',monitor)
                target={'server_id':'target','hostname':'target','service_snapshot':{},'service_basis':'historical_fixture'}
                db.execute('INSERT INTO hit_monitor_targets(id,monitor_id,server_id,enabled,data) VALUES(?,?,?,1,?)',
                           (monitor['id']+':target',monitor['id'],'target',json.dumps(target)))
        else:
            session = learning.create_session(store, {'server_ids':['target'], 'selection_mode':'discovered',
                'port_filter':[{'port':443,'protocol':'tcp'}], 'policy_action':'auto_allow',
                'auto_allow_confirmed':True, 'observation_kinds':kinds}, fixture.maker['actor'], principal=fixture.maker)
            store.report('target', {**body, 'discovered_at':stamp(), 'learning_discovery_session_ids':[session['id']]})
            review = hm.preview(store, {'name':'Typed IPv6 interoperability', 'selection':{'server_ids':['target']},
                'ports':[{'port':443,'protocol':'tcp'}], 'retention_hours':1, 'observation_kinds':kinds}, fixture.maker['actor'])
            monitor = hm.apply(store, {'preview_id':review['id'], **{field:review[field] for field in
                ('digest','confirmation_nonce','confirmation_phrase')}}, fixture.maker['actor'])
        point = stamp()
        events = [event(kind,source,name+'-'+kind+'-'+source,point)
                  for kind in kinds for source in ('2001:db8:20::44','10.50.0.8')]
        learning_events = scoped_events(events, 'prthak-learning-capture-v1', session['id'])
        monitor_events = scoped_events(events, 'prthak-hit-capture-v1', monitor['id'])
        if legacy:
            learning_events = [{key:value for key,value in item.items() if key not in
                                (*traffic_capture.FIELDS,'event_id')} for item in learning_events]
            for item in learning_events:item['count']=7
            monitor_events = [{key:value for key,value in item.items() if key not in traffic_capture.FIELDS}
                              for item in monitor_events]
            for item in monitor_events:item['verdict']='observed'
        first = store.enqueue_flows('target', {'batch_id':name+'-learning', 'session_id':session['id'], 'events':learning_events})
        retry = store.enqueue_flows('target', {'batch_id':name+'-learning-retry', 'session_id':session['id'], 'events':learning_events})
        assignment = store.assignment('target')[0]
        lease = assignment['hit_monitors'][0]
        batch = {'batch_id':name+'-monitor', 'monitor_id':monitor['id'],
                 'lease_starts_at':lease['starts_at'], 'lease_expires_at':lease['expires_at'], 'events':monitor_events}
        monitor_first = hm.enqueue(store,'target',batch)
        monitor_retry = hm.enqueue(store,'target',{**batch,'batch_id':name+'-monitor-retry'})
        store.process_flows()
        assignment = store.assignment('target')[0]
        if not legacy and (not assignment['learning_allow']['authorized'] or retry.get('duplicate_events') != len(events)):
            raise AssertionError('The real typed-ingest/current Admin authority path did not complete')
        if monitor_retry['accepted'] != 0:
            raise AssertionError('Cross-batch monitor replay counted the same observation again')
        at = int((now()+timedelta(seconds=1)).timestamp())
        signer = PolicySigner(root/'ephemeral-capture-signing-seed', '00000000-0000-4000-8000-000000000009', create=True)
        trust = signer.public_trust()
        certificate, ca = endpoint_public_identity(root)
        protection = store.get('servers','target')['protection']
        return {'name':name, 'legacy':legacy, 'at':at, 'trust':trust,
                'policy':signer.sign(assignment,at=at), 'endpoint_ips':ips, 'protection':protection,
                'certificate_pem':certificate, 'endpoint_ca_pem':ca,
                'native_events':events, 'learning_events':learning_events, 'monitor_events':monitor_events,
                'flow_rows':store.flows(), 'monitor_rows':hm.hits(store,monitor['id'])['items'],
                'recommendations':lp.recommendations(store,session['id'])['rows'],
                'receipts':{'learning':first,'learning_retry':retry,'monitor':monitor_first,'monitor_retry':monitor_retry},
                'coverage':traffic_capture.coverage({'capture_backends':[
                    {'backend':'conntrack','status':'active','ipv4':True,'ipv6':True,'lost_events':None},
                    {'backend':'nflog','status':'unsupported','ipv4':False,'ipv6':False,'lost_events':None,'error':'fixture: no native packet capture executed'}],
                    'capture_gaps':['Fixture verifies wire/identity/count semantics; native capture was not executed.']})}
    finally:
        fixture.doCleanups()


def generate():
    return {'schema_version':1, 'provenance':{'generator':str(Path(__file__).relative_to(ROOT)),
        'pipeline':['Current Entra fixture principal','learning.create_session','Store.report fresh discovery',
                    'hit_monitoring.preview/apply','Store.enqueue_flows','hit_monitoring.enqueue',
                    'Store.process_flows','Store.assignment','PolicySigner.sign'],
        'private_material_exported':False, 'native_firewall_or_live_Entra':False,
        'historical_case':'Explicit pre-feature rows with omitted observation_kinds, observation only'},
        'cases':[generate_case('both',list(traffic_capture.KINDS)),
                 generate_case('accepted-only',['accepted_connection']),
                 generate_case('denied-only',['denied_packet']),
                 generate_case('legacy',list(traffic_capture.KINDS),legacy=True)]}


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,default=Path(__file__).with_name('traffic-capture-v1.json'))
    output=parser.parse_args().output
    document=generate()
    encoded=json.dumps(document,ensure_ascii=False,indent=2)+'\n'
    if 'PRIVATE KEY' in encoded:raise AssertionError('Private material must never enter a public vector')
    output.write_text(encoded,encoding='utf-8')
    print('Wrote public capture interop vectors:',output)
