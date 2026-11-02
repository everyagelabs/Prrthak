"""Whole-host mode is exact, acknowledged, scoped and fail-closed."""
import copy
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
import json
import threading
import unittest
from unittest.mock import patch

from controller import host_default_deny as deny, managed, managed_views
from controller.firewall import WorkflowConflict
from controller.store import Store, digest, now, stamp
from controller.tests import test_approvals as fixture


class HostDefaultDenyTests(unittest.TestCase):
    person=fixture.IndependentApprovalTests.person

    def setUp(self):
        fixture.IndependentApprovalTests.setUp(self)
        with self.store.meta() as db:
            server=self.store._get(db,'servers','target')
            protected={key:server['protection'][key] for key in ('management_sources','ssh_ports','controller_url','management_probe_url','zone')}
            protected.update(host_default_deny_context_digest='c'*64,host_default_deny_control_profile=deny.PROFILE)
            server['protection']=managed.protection({**protected,'digest':digest(protected),'ready':True,'blockers':[],'host_default_deny_ready':True,'host_default_deny_blockers':[]})
            server['protection_digest']=server['protection']['digest']
            server['configuration_state']={'digest':'d'*64,'allow_host_default_deny':True}
            server['capabilities'].append(deny.CAPABILITY)
            self.store._put(db,'servers',server)
        self.policy=self.store.all('policies')[0]
        self.policy=self.store.save_policy(self.policy,self.maker['actor'],self.policy['id'],principal=self.maker)

    def preview(self,action='enable',**scope):
        return deny.preview(self.store,{'action':action,**(scope or {'server_ids':['target']})},self.maker['actor'],self.maker)

    @staticmethod
    def confirmation(plan,**changes):
        return {'digest':plan['digest'],'expected_revision':plan['revision'],'confirmation_nonce':plan['confirmation_nonce'],'acknowledge_downtime':True,**changes}

    def push(self,action='enable'):
        plan=self.preview(action)
        self.assertTrue(plan['can_apply'],plan['blockers'])
        return deny.confirm(self.store,plan['id'],self.confirmation(plan),self.maker['actor'],self.maker)

    def receipt(self,status='enforced',last=None):
        policy=self.store.assignment('target')[0];approval=policy['enforcement']
        result={'status':status,'version':policy['version'],'digest':policy['digest'],'approval_id':approval['approval_id'],
            'last_good_version':last['version'] if last else 0,'last_good_digest':last['digest'] if last else '', 'updated_at':stamp()}
        if status=='rolled_back':result['rollback_reason']='forced health failure'
        server=self.store.get('servers','target')
        return self.store.report('target',{'hostname':'target','ips':server['ips'],'listeners':[], 'capabilities':server['capabilities'],
            'managed_enforcement':result,'applied_version':policy['version'],'apply_status':'synced'})

    def test_preview_is_read_only_and_ack_is_literal_unchecked_until_each_push(self):
        before=self.store.assignment('target')[0]
        plan=self.preview()
        self.assertEqual(self.store.assignment('target')[0],before)
        self.assertEqual(plan['preview']['targets'][0]['base_version'],before['version'])
        self.assertGreater(plan['preview']['targets'][0]['version'],before['version'])
        self.assertEqual(plan['preview']['targets'][0]['protection']['ssh_ports'],[2022])
        for ack in (False,'true',1,None):
            with self.subTest(ack=ack),self.assertRaises(ValueError):deny.confirm(self.store,plan['id'],self.confirmation(plan,acknowledge_downtime=ack),self.maker['actor'],self.maker)
        missing=self.confirmation(plan);missing.pop('acknowledge_downtime')
        with self.assertRaises(ValueError):deny.confirm(self.store,plan['id'],missing,self.maker['actor'],self.maker)
        self.assertNotIn('host_default_deny',self.store.assignment('target')[0])
        deny.confirm(self.store,plan['id'],self.confirmation(plan),self.maker['actor'],self.maker)
        next_plan=self.preview()
        self.assertNotEqual(plan['confirmation_nonce'],next_plan['confirmation_nonce'])
        with self.assertRaises(ValueError):deny.confirm(self.store,next_plan['id'],self.confirmation(next_plan,acknowledge_downtime=False),self.maker['actor'],self.maker)

    def test_push_signed_flag_authority_health_and_history_are_exact(self):
        plan=self.push();assigned=self.store.assignment('target')[0];authority=assigned['enforcement']
        self.assertTrue(assigned['host_default_deny']);self.assertTrue(authority['authorized']);self.assertTrue(authority['host_default_deny_ack'])
        self.assertEqual(authority['intent'],'enforce_host_default_deny');self.assertEqual(authority['approval_proof']['scope']['kind'],deny.KIND)
        self.assertEqual(authority['host_default_deny_configuration_digest'],'d'*64)
        self.assertEqual(assigned['digest'],digest({key:assigned[key] for key in ('mode','services','host_default_deny')}))
        witness=self.store.verify_managed_enforcement('target',{'approval_id':authority['approval_id'],'version':assigned['version'],'digest':assigned['digest'],'protection_digest':authority['protection_digest'],'binding_digest':authority['binding_digest']})
        self.assertTrue(witness['host_default_deny_ack'])
        self.assertTrue(self.store.policy_history('target',assigned['version'])['host_default_deny'])
        self.assertEqual(managed_views.rollout(self.store,plan['id'])['action'],'enable')
        with self.assertRaises(ValueError):self.store.confirm_managed_rollout(plan['id'],{'confirmation_nonce':'forged'},self.maker['actor'],principal=self.maker)

    def test_generic_policy_and_rollout_never_manufacture_whole_host_ack(self):
        self.store.save_policy({**self.policy,'host_default_deny':True},self.maker['actor'],self.policy['id'],principal=self.maker)
        self.assertNotIn('host_default_deny',self.store.assignment('target')[0])
        self.push()
        with self.assertRaises(ValueError):self.store.create_managed_rollout({'name':'Bypass','server_ids':['target']},self.maker['actor'],principal=self.maker)
        self.store.save_policy({**self.policy,'services':[{'port':8443,'sources':['10.60.0.0/24']}]},self.maker['actor'],self.policy['id'],principal=self.maker)
        changed=self.store.assignment('target')[0]
        self.assertTrue(changed['host_default_deny']);self.assertFalse(changed['enforcement']['authorized'])
        self.assertEqual(deny.listing(self.store)['items'][0]['status'],'review_required')
        self.push();self.assertTrue(self.store.assignment('target')[0]['enforcement']['authorized'])

    def test_membership_is_frozen_and_future_members_never_inherit_the_mode(self):
        self.store.update_server('target',{'tags':{'application':'billing'}},self.maker['actor'])
        group=self.store.save_group({'name':'Billing','type':'dynamic','selector':{'application':'billing'}},self.maker['actor'])
        plan=self.preview(group_ids=[group['id']])
        self.store.update_server('target',{'tags':{'application':'other'}},self.maker['actor'])
        with self.assertRaises(WorkflowConflict):deny.confirm(self.store,plan['id'],self.confirmation(plan),self.maker['actor'],self.maker)
        self.store.update_server('target',{'tags':{'application':'billing'}},self.maker['actor'])
        plan=self.preview(group_ids=[group['id']]);deny.confirm(self.store,plan['id'],self.confirmation(plan),self.maker['actor'],self.maker)
        self.store.report('future',{'hostname':'future','ips':['10.70.0.2'],'listeners':[]})
        self.store.update_server('future',{'tags':{'application':'billing'}},self.maker['actor'])
        self.assertNotIn('host_default_deny',self.store.assignment('future')[0])
        self.assertTrue(self.store.assignment('target')[0]['host_default_deny'])

    def test_stale_context_configuration_ips_and_revision_need_new_review(self):
        for key,value in (('configuration_state',{'digest':'e'*64,'allow_host_default_deny':True}),('ips',['10.70.0.99'])):
            plan=self.preview()
            with self.store.meta() as db:
                server=self.store._get(db,'servers','target');original=copy.deepcopy(server[key]);server[key]=value;self.store._put(db,'servers',server)
            with self.assertRaises(WorkflowConflict):deny.confirm(self.store,plan['id'],self.confirmation(plan),self.maker['actor'],self.maker)
            with self.store.meta() as db:
                server=self.store._get(db,'servers','target');server[key]=original;self.store._put(db,'servers',server)
        plan=self.preview()
        with self.assertRaises(WorkflowConflict):deny.confirm(self.store,plan['id'],self.confirmation(plan,expected_revision=0),self.maker['actor'],self.maker)
        with patch('controller.host_default_deny.now',return_value=now()+timedelta(minutes=11)),self.assertRaises(WorkflowConflict):deny.confirm(self.store,plan['id'],self.confirmation(plan),self.maker['actor'],self.maker)

    def test_disable_is_remove_only_then_resumes_normal_desired_flow_after_receipt(self):
        self.push();self.receipt()
        old=self.store.assignment('target')[0]
        self.store.save_policy({**self.policy,'services':[{'port':8443,'sources':['10.60.0.0/24']}]},self.maker['actor'],self.policy['id'],principal=self.maker)
        self.assertFalse(self.store.assignment('target')[0]['enforcement']['authorized'])
        self.push('disable');removing=self.store.assignment('target')[0]
        self.assertNotIn('host_default_deny',removing);self.assertEqual(removing['services'],old['services'])
        self.assertEqual(removing['enforcement']['intent'],'remove_host_default_deny');self.assertTrue(removing['enforcement']['authorized'])
        with self.assertRaises(ValueError):self.store.create_managed_rollout({'name':'No bypass removal','server_ids':['target']},self.maker['actor'],principal=self.maker)
        self.receipt();normal=self.store.assignment('target')[0]
        self.assertNotIn('host_default_deny',normal);self.assertEqual(normal['services'][0]['sources'],['10.60.0.0/24'])
        self.assertTrue(normal['enforcement']['authorized']);self.assertFalse(self.store.get('servers','target').get('_host_default_deny_active'))

    def test_empty_allowlist_enable_and_disable_does_not_use_generic_cleanup(self):
        self.store.delete_policy(self.policy['id'],self.maker['actor'])
        self.push();self.assertEqual(self.store.assignment('target')[0]['services'],[]);self.receipt()
        self.push('disable');candidate=self.store.assignment('target')[0]
        self.assertEqual(candidate['mode'],'monitor');self.assertTrue(candidate['enforcement']['authorized'])
        self.assertEqual(candidate['enforcement']['intent'],'remove_host_default_deny')
        self.receipt();self.assertFalse(self.store.assignment('target')[0]['enforcement']['authorized'])
        self.assertEqual(deny.listing(self.store)['items'][0]['status'],'disabled')

    def test_rollback_revokes_retry_until_another_manual_ack(self):
        previous=self.store.assignment('target')[0]
        self.push();self.receipt('rolled_back',previous)
        self.assertFalse(self.store.assignment('target')[0]['enforcement']['authorized'])
        self.assertFalse(self.store.get('servers','target').get('_host_default_deny_active'))
        self.push();self.assertTrue(self.store.assignment('target')[0]['enforcement']['authorized'])

    def test_capability_local_optin_and_context_readiness_are_required(self):
        for field,value in (('capabilities',['signed_assignments_v1']),('configuration_state',{'digest':'d'*64,'allow_host_default_deny':False})):
            with self.store.meta() as db:
                server=self.store._get(db,'servers','target');original=server[field];server[field]=value;self.store._put(db,'servers',server)
            plan=self.preview();self.assertFalse(plan['can_apply'])
            with self.assertRaises(ValueError):deny.confirm(self.store,plan['id'],self.confirmation(plan),self.maker['actor'],self.maker)
            with self.store.meta() as db:
                server=self.store._get(db,'servers','target');server[field]=original;self.store._put(db,'servers',server)

    def test_fresh_heartbeat_cannot_reuse_an_old_protection_context(self):
        with self.store.meta() as db:
            server=self.store._get(db,'servers','target');server['protection_reported_at']=stamp(now()-timedelta(seconds=181));self.store._put(db,'servers',server)
        server=self.store.get('servers','target')
        self.store.report('target',{'hostname':'target','ips':server['ips'],'listeners':[],'capabilities':server['capabilities']})
        plan=self.preview();self.assertFalse(plan['can_apply'])
        self.assertTrue(any('protection snapshot' in reason for reason in plan['blockers']))

    def test_current_actor_role_and_provider_authority_are_rechecked(self):
        plan=self.preview()
        with self.assertRaises(PermissionError):deny.confirm(self.store,plan['id'],self.confirmation(plan),self.checker['actor'],self.checker)
        readonly=self.person('66666666-6666-6666-6666-666666666666','read_only')
        with self.assertRaises(PermissionError):deny.preview(self.store,{'action':'enable','server_ids':['target']},readonly['actor'],readonly)
        self.push()
        with self.store.meta() as db:
            user=self.store._get(db,'auth_users',self.maker['user']['id']);self.store._put(db,'auth_users',{**user,'enabled':False})
        self.assertFalse(self.store.assignment('target')[0]['enforcement']['authorized'])
        with self.store.meta() as db:
            self.store._put(db,'auth_users',user)
            self.store._put(db,'maintenance_settings',{'id':'controller_provider_authority','fingerprint':self.config.fingerprint,'epoch':'e'*64})
        self.assertFalse(self.store.assignment('target')[0]['enforcement']['authorized'])

    def test_disable_remains_available_if_local_optin_was_switched_off(self):
        self.push();self.receipt()
        with self.store.meta() as db:
            server=self.store._get(db,'servers','target');server['configuration_state']={'digest':'e'*64,'allow_host_default_deny':False};self.store._put(db,'servers',server)
        self.push('disable')
        authority=self.store.assignment('target')[0]['enforcement']
        self.assertTrue(authority['authorized']);self.assertEqual(authority['intent'],'remove_host_default_deny')
        self.assertEqual(authority['host_default_deny_configuration_digest'],'e'*64)

    def test_imported_and_automatic_learning_mutations_are_held(self):
        from controller import firewall
        plan=firewall.create_change(self.store,{'name':'Old imported','server_ids':['target'],'rule_key':firewall.fingerprints('runtime','public','port','8080/tcp')[1],'operation':'remove','scopes':['runtime']},self.maker['actor'],principal=self.maker)
        plan=firewall.confirm_change(self.store,plan['id'],{'confirmation_nonce':plan['confirmation_nonce']},self.maker['actor'],principal=self.maker)
        firewall.confirm_change(self.store,plan['id'],{'confirmation_nonce':plan['confirmation_nonce'],'challenge':plan['confirmation_phrase']},self.maker['actor'],principal=self.maker)
        self.push()
        self.assertEqual(self.store.assignment('target')[0]['firewall_changes'],[])
        self.assertEqual(self.store.get('firewall_changes',plan['id'])['status'],'invalidated')
        with self.store.meta() as db:
            server=self.store._get(db,'servers','target');server['capabilities']+=['learning_discovery_v1','learning_auto_allow_v1','traffic_capture_v1'];self.store._put(db,'servers',server)
        with self.assertRaises(ValueError):self.store.create_session({'server_ids':['target'],'selection_mode':'discovered','policy_action':'auto_allow','auto_allow_confirmed':True},self.maker['actor'],principal=self.maker)
        observe=self.store.create_session({'server_ids':['target'],'ports':[{'port':443,'protocol':'tcp'}]},self.maker['actor'],principal=self.maker)
        self.assertEqual(observe['policy_action'],'observe')

    def test_monitor_rules_never_appear_as_approved_inbound_grants(self):
        self.store.save_policy({'name':'Monitor9000','selector':{},'mode':'monitor','services':[{'port':9000,'sources':['0.0.0.0/0']}]},self.maker['actor'],principal=self.maker)
        plan=self.preview()
        self.assertNotIn(9000,[row['port'] for row in plan['preview']['targets'][0]['services']])
        self.assertIn(8443,[row['port'] for row in plan['preview']['targets'][0]['services']])

    def test_fresh_health_receipt_carries_ack_and_rechecks_configuration(self):
        from controller.management_health import ManagementHealth
        self.push();assigned=self.store.assignment('target')[0];authority=assigned['enforcement']
        request={'nonce':'n'*32,'ssh_ports':[2022],'version':assigned['version'],'digest':assigned['digest'],**{key:authority[key] for key in ('approval_id','protection_digest','binding_digest')}}
        health=ManagementHealth('10.90.0.5',['10.70.0.0/24'])
        with patch.object(health,'_ssh',return_value={}):result=health.check(self.store,'target',request)
        self.assertTrue(result['host_default_deny_ack']);self.assertEqual(result['host_default_deny_configuration_digest'],'d'*64)
        def changed(*args):
            with self.store.meta() as db:
                server=self.store._get(db,'servers','target');server['configuration_state']['digest']='e'*64;self.store._put(db,'servers',server)
            return {}
        with patch.object(health,'_ssh',side_effect=changed),self.assertRaises(PermissionError):health.check(self.store,'target',request)

    def test_explicit_empty_filter_is_zero_and_status_never_decodes_snapshots(self):
        marker='PRIVATE_DEEP_SNAPSHOT_'*100000
        with self.store.meta() as db:
            server=self.store._get(db,'servers','target');server['firewall_snapshot']={'payload':marker};self.store._put(db,'servers',server)
        original=self.store._get
        def no_server(db,table,identifier):
            if table=='servers':raise AssertionError('Status decoded full server snapshot')
            return original(db,table,identifier)
        with patch.object(self.store,'_get',side_effect=no_server),patch.object(self.store,'_all',side_effect=AssertionError('Status loaded a full catalogue')):
            self.assertEqual(deny.listing(self.store,{'server_ids':[]})['total'],0)
            page=deny.listing(self.store,{'server_ids':['target'],'limit':1})
            self.assertEqual(page['total'],1);self.assertNotIn('PRIVATE_DEEP_SNAPSHOT',json.dumps(page))
        with self.assertRaises(ValueError):deny.listing(self.store,{'server_ids':None})

    def test_two_independent_writers_cannot_confirm_different_stale_reviews(self):
        first,second=self.preview(),self.preview()
        stores=[Store(self.store.path),Store(self.store.path)]
        for store in stores:store.approval_auth_fingerprint=self.config.fingerprint;store.approval_tenant_id=self.config.tenant_id
        barrier=threading.Barrier(2)
        def perform(pair):
            store,plan=pair;barrier.wait()
            try:deny.confirm(store,plan['id'],self.confirmation(plan),self.maker['actor'],self.maker);return 'committed'
            except WorkflowConflict:return 'conflict'
        with ThreadPoolExecutor(max_workers=2) as workers:outcomes=list(workers.map(perform,zip(stores,(first,second))))
        self.assertCountEqual(outcomes,['committed','conflict'])
        self.assertEqual(self.store.get('servers','target')[deny.STATE]['revision'],1)

    def test_paired_native_context_preserves_legacy_protection_hash(self):
        old={key:self.store.get('servers','target')['protection'][key] for key in ('management_sources','ssh_ports','controller_url','management_probe_url','zone')}
        legacy={**old,'digest':digest(old),'ready':True,'blockers':[]}
        self.assertEqual(managed.protection(legacy)['digest'],digest(old))
        metadata=managed.protection({**legacy,'host_default_deny_ready':False,'host_default_deny_blockers':['disabled']})
        self.assertEqual(metadata['digest'],digest(old));self.assertTrue(metadata['ready'])
        with self.assertRaises(ValueError):managed.protection({**legacy,'host_default_deny_context_digest':'a'*64})
