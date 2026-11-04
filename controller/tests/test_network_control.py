import copy
from datetime import timedelta
import os
from pathlib import Path
import unittest
from unittest.mock import patch

from controller import network_control as control
from controller.firewall import WorkflowConflict
from controller.store import digest, now, stamp
from controller.tests import test_approvals as fixture
from controller.tests import private_pg


class NetworkControlTests(unittest.TestCase):
    person = fixture.IndependentApprovalTests.person

    def setUp(self):
        fixture.IndependentApprovalTests.setUp(self)
        with self.store.meta() as db:
            control.initialize(db)
            server = self.store._get(db, 'servers', 'target')
            server['capabilities'] += [value[0] for value in control.KINDS.values()]
            server['configuration_state'] = {'digest': 'd'*64, 'enforce': True, 'allow_firewall_changes': True, 'allow_host_default_deny': True}
            self.store._put(db, 'servers', server)

    def assignment(self):
        with self.store.read_meta() as db:
            return control.assignment(self.store, db, self.store._get(db, 'servers', 'target'))

    def body(self, kind='egress', **extra):
        return {'kind': kind, 'server_ids': ['target'], **({'operation': 'apply', 'default_deny': False, 'services': [{'port': 443, 'protocol': 'tcp', 'destinations': ['10.20.0.0/16']}]} if kind=='egress' else {'operation': 'enable', 'ttl_seconds': 900}), **extra}

    def assess(self, kind='egress'):
        plan = control.assess(self.store, {'kind': kind, 'server_ids': ['target']}, self.maker['actor'], self.maker)
        self.assertEqual(plan['status'], 'queued')
        descriptor = self.assignment()[control.KINDS[kind][2]]
        self.receipt(kind, descriptor=descriptor, status='assessed')
        return plan

    def receipt(self, kind='egress', *, descriptor=None, status='enforced', feature_changes=None, **changes):
        descriptor = descriptor or self.assignment()[control.KINDS[kind][2]]
        with self.store.meta() as db:
            server = self.store._get(db, 'servers', 'target')
            empty = {'supported': True, 'ready': True, 'status': 'unknown', 'id': '', 'plan_digest': '', 'generation': 0, 'expires_at': None, 'error': ''}
            metadata = {'schema_version': 1, 'checked_at': now().isoformat().replace('+00:00','Z'), 'protection_digest': server['protection']['digest'], 'context_digest': 'c'*64,
                        'configuration_digest': server['configuration_state']['digest'], 'protected_egress': [{'destination': '10.0.0.1/32', 'port': 8787, 'protocol': 'tcp', 'kind': 'controller'}],
                        'egress': copy.deepcopy((server.get('network_control') or {}).get('egress') or empty), 'quarantine': copy.deepcopy((server.get('network_control') or {}).get('quarantine') or empty), 'blockers': []}
            metadata[kind] = {**empty, 'id': descriptor['id'], 'plan_digest': descriptor['plan_digest'], 'generation': descriptor['generation'], 'status': status, 'expires_at': descriptor.get('expires_at')}
            metadata[kind].update(feature_changes or {})
            metadata.update(changes)
            control.report(self.store, db, server, metadata); self.store._put(db, 'servers', server)
        return metadata

    def preview(self, body=None):
        return control.preview(self.store, body or self.body(), self.maker['actor'], self.maker)

    @staticmethod
    def confirmation(plan, **extra):
        return {'digest': plan['digest'], 'confirmation_nonce': plan['confirmation_nonce'], 'confirmation_phrase': plan['confirmation_phrase'], 'acknowledge_downtime': True, **extra}

    def apply(self, body=None):
        plan = self.preview(body)
        self.assertTrue(plan['can_apply'], plan['blockers'])
        return control.confirm(self.store, plan['id'], self.confirmation(plan), self.maker['actor'], self.maker)

    def test_disabled_default_and_signed_read_only_assessment_do_not_enable_policy(self):
        self.assertEqual(self.assignment(), {})
        plan = control.assess(self.store, {'kind': 'egress', 'server_ids': ['target']}, self.maker['actor'], self.maker)
        descriptor = self.assignment()['egress_bundle']
        self.assertEqual(descriptor['operation'], 'assess'); self.assertFalse(descriptor['downtime_ack'])
        self.assertFalse(descriptor['default_deny']); self.assertEqual(descriptor['services'], [])
        self.assertEqual(descriptor['approval_proof']['scope']['kind'], 'egress_policy')
        self.assertEqual(plan['server_ids'], ['target'])

    def test_recent_native_assessment_local_opt_ins_and_context_are_required(self):
        self.assertFalse(self.preview()['can_apply'])
        self.assess(); self.assertTrue(self.preview()['can_apply'])
        for field, value in (('configuration_state', {'digest': 'd'*64}), ('capabilities', ['signed_assignments_v1'])):
            with self.store.meta() as db:
                server=self.store._get(db,'servers','target'); previous=copy.deepcopy(server[field]);server[field]=value;self.store._put(db,'servers',server)
            self.assertFalse(self.preview()['can_apply'])
            with self.store.meta() as db: server[field]=previous;self.store._put(db,'servers',server)
        with patch.object(control,'now',return_value=now()+timedelta(minutes=4)):
            self.assertFalse(self.preview()['can_apply'])

    def test_egress_review_exact_digest_same_admin_acknowledgement_and_generation(self):
        self.assess(); before=self.assignment()['egress_bundle']; plan=self.preview()
        self.assertEqual(self.assignment()['egress_bundle'],before)
        for ack in (False, 'true', 1, None):
            with self.subTest(ack=ack),self.assertRaises(ValueError):
                control.confirm(self.store,plan['id'],self.confirmation(plan,acknowledge_downtime=ack),self.maker['actor'],self.maker)
        with self.assertRaises(WorkflowConflict): control.confirm(self.store,plan['id'],self.confirmation(plan),self.checker['actor'],self.checker)
        with self.assertRaises(WorkflowConflict): control.confirm(self.store,plan['id'],self.confirmation(plan,confirmation_phrase='yes'),self.maker['actor'],self.maker)
        control.confirm(self.store,plan['id'],self.confirmation(plan),self.maker['actor'],self.maker)
        descriptor=self.assignment()['egress_bundle']
        self.assertEqual(descriptor['generation'],before['generation']+1);self.assertTrue(descriptor['downtime_ack'])
        self.assertEqual(descriptor['plan_digest'],digest({key:value for key,value in descriptor.items() if key not in ('plan_digest','approval_proof')}))
        self.assertEqual(descriptor['approval_proof']['plan_id'],descriptor['id']);self.assertEqual(descriptor['approval_proof']['plan_digest'],descriptor['plan_digest'])
        self.assertTrue(control.confirm(self.store,plan['id'],self.confirmation(plan),self.maker['actor'],self.maker)['duplicate'])

    def test_context_configuration_ips_and_generation_changes_invalidate_review(self):
        self.assess()
        for field,value in (('ips',['10.70.0.99']),('configuration_state',{'digest':'e'*64,'enforce':True,'allow_firewall_changes':True,'allow_host_default_deny':True})):
            plan=self.preview()
            with self.store.meta() as db:server=self.store._get(db,'servers','target');old=copy.deepcopy(server[field]);server[field]=value;self.store._put(db,'servers',server)
            with self.assertRaises(WorkflowConflict):control.confirm(self.store,plan['id'],self.confirmation(plan),self.maker['actor'],self.maker)
            with self.store.meta() as db:server[field]=old;self.store._put(db,'servers',server)
        plan=self.preview();self.assess()
        with self.assertRaises(WorkflowConflict):control.confirm(self.store,plan['id'],self.confirmation(plan),self.maker['actor'],self.maker)

    def test_group_membership_is_frozen_and_future_members_never_receive_control(self):
        self.assess();self.store.update_server('target',{'tags':{'application':'billing'}},self.maker['actor'])
        group=self.store.save_group({'name':'Billing','type':'dynamic','selector':{'application':'billing'}},self.maker['actor'])
        body={**self.body(),'server_ids':[],'group_ids':[group['id']]};plan=self.preview(body)
        self.store.report('future',{'hostname':'future','ips':['10.70.0.2'],'listeners':[]})
        self.store.update_server('future',{'tags':{'application':'billing'}},self.maker['actor'])
        with self.assertRaises(WorkflowConflict):control.confirm(self.store,plan['id'],self.confirmation(plan),self.maker['actor'],self.maker)
        with self.store.read_meta() as db:self.assertEqual(control.assignment(self.store,db,self.store._get(db,'servers','future')), {})

    def test_quarantine_ttl_is_explicit_bounded_and_never_claimed_as_applied_intent(self):
        self.assess('quarantine');plan=self.apply(self.body('quarantine',ttl_seconds=60))
        descriptor=self.assignment()['quarantine'];self.assertEqual(descriptor['operation'],'enable')
        self.assertEqual(parse_delta(descriptor['expires_at'],descriptor['issued_at']),60)
        self.assertEqual(control.get(self.store,plan['id'])['status'],'queued')
        with patch.object(control,'now',return_value=now()+timedelta(seconds=61)):
            self.assertNotIn('quarantine',self.assignment())
        self.receipt('quarantine',status='quarantined')
        self.assertEqual(control.get(self.store,plan['id'])['preview']['targets'][0]['last_report']['status'],'quarantined')
        for ttl in (True,0,59,3601,'900'):
            with self.subTest(ttl=ttl),self.assertRaises(ValueError):self.preview(self.body('quarantine',ttl_seconds=ttl))

    def test_revoked_admin_or_expired_authority_is_not_delivered_or_witnessed(self):
        self.assess();self.apply();descriptor=self.assignment()['egress_bundle']
        body={key:descriptor[key] for key in ('id','plan_digest','generation','protection_digest','context_digest')}|{'kind':'egress','nonce':'fresh-nonce-1234567890','ssh_ports':[2022]}
        self.assertEqual(control.witness(self.store,'target',body)['ssh_ports'],[2022])
        with self.store.meta() as db:user=self.store._get(db,'auth_users',self.maker['user']['id']);user['enabled']=False;self.store._put(db,'auth_users',user)
        self.assertNotIn('egress_bundle',self.assignment())
        with self.assertRaises(PermissionError):control.witness(self.store,'target',body)

    def test_witness_rejects_changed_identity_digest_and_opt_out(self):
        self.assess();self.apply();descriptor=self.assignment()['egress_bundle']
        body={key:descriptor[key] for key in ('id','plan_digest','generation','protection_digest','context_digest')}|{'kind':'egress','nonce':'fresh-nonce-1234567890','ssh_ports':[2022]}
        for change in ({'generation':True},{'context_digest':'f'*64},{'id':'foreign'}):
            with self.assertRaises((ValueError,PermissionError)):control.witness(self.store,'target',{**body,**change})
        with self.store.meta() as db:server=self.store._get(db,'servers','target');server['configuration_state']['enforce']=False;self.store._put(db,'servers',server)
        with self.assertRaises(PermissionError):control.witness(self.store,'target',body)

    def test_canonical_destinations_and_duplicates_are_os_neutral_and_empty_means_selected_port_deny(self):
        result=control._services([{'port':443,'protocol':'tcp','destinations':['10.2.3.4/16','10.2.0.0/16']},{'port':443,'protocol':'tcp','destinations':['2001:db8::1/128']},{'port':22,'protocol':'tcp','destinations':[]}])
        self.assertEqual(result,[{'port':22,'protocol':'tcp','destinations':[]},{'port':443,'protocol':'tcp','destinations':['10.2.0.0/16','2001:db8::1/128']}])
        for value in ('::ffff:192.0.2.3/128','fe80::1%eth0/128','not-a-network'):
            with self.assertRaises(ValueError):control._services([{'port':443,'protocol':'tcp','destinations':[value]}])

    def test_normalized_outbound_budgets_match_native_while_duplicates_do_not_block(self):
        duplicate={'port':443,'protocol':'tcp','destinations':['192.0.2.1/32']*70}
        self.assertEqual(control._services([duplicate,duplicate]),[{'port':443,'protocol':'tcp','destinations':['192.0.2.1/32']}])
        destinations=['192.0.2.'+str(index)+'/32' for index in range(1,66)]
        matrices=([
            {'port':index+1,'protocol':'tcp','destinations':[]} for index in range(65)],
            [{'port':443,'protocol':'tcp','destinations':destinations}],
            [{'port':443,'protocol':'tcp','destinations':destinations[:64]}, {'port':444,'protocol':'tcp','destinations':destinations[:64]}, {'port':445,'protocol':'tcp','destinations':destinations[:1]}])
        for rows in matrices:
            with self.assertRaisesRegex(ValueError,'native outbound apply budget'):control._services(rows)

    def test_native_other_feature_ready_and_fractional_same_second_assessment_are_valid(self):
        self.assess();descriptor=self.assignment()['egress_bundle']
        other=copy.deepcopy(self.store.get('servers','target')['network_control']['quarantine']);other['status']='ready'
        self.receipt(checked_at=descriptor['issued_at'].replace('Z','.999999Z'),quarantine=other)
        self.assertTrue(self.preview()['can_apply'])
        self.assertEqual(control.public_summary(self.store.get('servers','target'))['quarantine']['status'],'ready')

    def test_unsupported_assessment_reports_are_retained_without_fake_readiness(self):
        self.assess();metadata=self.receipt(status='blocked',context_digest='',blockers=['Native context unsupported'])
        self.assertFalse(self.preview()['can_apply']);self.assertEqual(self.store.get('servers','target')['network_control']['context_digest'],'')
        for change in ({'schema_version':True},{'protected_egress':[{'destination':'127.0.0.1','port':True,'protocol':'tcp','kind':'controller'}]},{'blockers':['x'*501]}):
            with self.store.meta() as db,self.assertRaises(ValueError):control.report(self.store,db,self.store._get(db,'servers','target'),{**metadata,**change})

    def test_remove_disable_are_separate_signed_operations_and_normal_policy_is_unchanged(self):
        self.assess();self.apply();self.receipt();self.apply(self.body(operation='remove',services=[]))
        self.assertEqual(self.assignment()['egress_bundle']['operation'],'remove')
        self.assertNotIn('quarantine',self.assignment())
        self.assertEqual(self.store.all('policies')[0]['services'][0]['port'],8443)

    def test_recovery_preserves_floors_and_ttl_without_replaying_or_removing_native_control(self):
        self.assess();self.apply();egress=self.assignment()['egress_bundle'];self.receipt()
        self.assess('quarantine');plan=self.apply(self.body('quarantine'));quarantine=self.assignment()['quarantine'];self.receipt('quarantine',status='quarantined')
        with self.store.meta() as db:
            result=control.invalidate_after_recovery(self.store,db)
            state=self.store._get(db,'network_control_assignments','target')
        self.assertEqual(result['held_descriptors'],2);self.assertEqual(self.assignment(),{})
        self.assertEqual(state['egress']['generation_floor'],egress['generation'])
        self.assertEqual(state['quarantine']['held_descriptor']['expires_at'],quarantine['expires_at'])
        self.assertEqual(self.store.get('servers','target')['network_control']['quarantine']['status'],'quarantined')
        self.assertEqual(control.get(self.store,plan['id'])['status'],'requires_fresh_review')
        self.assess();self.assertGreater(self.assignment()['egress_bundle']['generation'],egress['generation'])

    def test_recovery_helper_accepts_static_store_context_used_by_recovery_overlay(self):
        self.assess();self.apply();floor=self.assignment()['egress_bundle']['generation']
        with self.store.meta() as db:
            self.assertEqual(control.invalidate_after_recovery(None,db)['held_descriptors'],1)
            state=self.store._get(db,'network_control_assignments','target')
        self.assertEqual(state['egress']['generation_floor'],floor);self.assertEqual(self.assignment(),{})

    def test_public_summary_is_small_cadence_aware_and_never_invents_expiry_receipt(self):
        self.assess('quarantine');self.apply(self.body('quarantine'));self.receipt('quarantine',status='quarantined')
        server=self.store.get('servers','target');summary=control.public_summary(server)
        self.assertFalse(summary['stale']);self.assertEqual(summary['quarantine']['status'],'quarantined')
        self.assertNotIn('protected_egress',str(summary));self.assertNotIn('context_digest',str(summary))
        with patch.object(control,'now',return_value=now()+timedelta(seconds=901)):
            summary=control.public_summary(server);self.assertEqual(summary['quarantine']['status'],'expiry_unconfirmed');self.assertTrue(summary['quarantine']['expiry_unconfirmed']);self.assertTrue(summary['stale'])
        server['control_interval_seconds']=600
        with patch.object(control,'now',return_value=now()+timedelta(seconds=500)):
            self.assertFalse(control.public_summary(server)['stale'])

    def test_failed_readback_cannot_refresh_old_active_enforcement_as_verified(self):
        self.assess();self.apply();self.receipt(status='enforced')
        server=self.store.get('servers','target');metadata=server['network_control']
        metadata['checked_at']=now().isoformat().replace('+00:00','Z');metadata['egress']['ready']=False
        metadata['blockers']=['Fresh kernel read-back failed']
        summary=control.public_summary(server)
        self.assertTrue(summary['egress']['active']);self.assertTrue(summary['egress']['stale']);self.assertTrue(summary['egress']['unverified']);self.assertFalse(summary['egress']['verified'])
        metadata['blockers']=[]
        self.assertFalse(control.public_summary(server)['stale']);self.assertTrue(control.public_summary(server)['egress']['stale'])
        self.receipt(status='unverified',feature_changes={'ready':False,'error':'Current read-back is unavailable'})
        self.assertEqual(self.store.get('servers','target')['network_control']['egress']['status'],'unverified')

    def test_matching_error_receipts_raise_alert_recovery_resolves_and_quarantine_is_visible(self):
        self.assess();self.apply();self.receipt(status='rolled_back')
        alert=self.store.get('alerts','network-control:egress:target');self.assertEqual((alert['kind'],alert['severity'],alert['status']),('egress_control_error','critical','open'))
        self.receipt(status='enforced');self.assertEqual(self.store.get('alerts',alert['id'])['status'],'resolved')
        self.assess('quarantine');self.apply(self.body('quarantine'));self.receipt('quarantine',status='quarantined')
        self.assertEqual(self.store.get('alerts','quarantine-active:target')['kind'],'server_quarantined')
        self.receipt('quarantine',status='expired')
        self.assertEqual(self.store.get('alerts','quarantine-active:target')['status'],'resolved')

    def test_quarantine_receipt_cannot_extend_or_omit_the_frozen_lease(self):
        self.assess('quarantine');self.apply(self.body('quarantine'));descriptor=self.assignment()['quarantine']
        metadata=self.receipt('quarantine',status='quarantined')
        for expires in (None,stamp(now()+timedelta(hours=2))):
            changed=copy.deepcopy(metadata);changed['quarantine']['expires_at']=expires
            with self.store.meta() as db,self.assertRaises(ValueError):
                control.report(self.store,db,self.store._get(db,'servers','target'),changed)
        self.assertEqual(self.store.get('servers','target')['network_control']['quarantine']['expires_at'],descriptor['expires_at'])

    def test_failed_replacement_retains_separate_old_active_quarantine_and_original_expiry(self):
        self.assess('quarantine');self.apply(self.body('quarantine'));old=self.assignment()['quarantine'];self.receipt('quarantine',status='quarantined')
        self.apply(self.body('quarantine'));current=self.assignment()['quarantine'];metadata=self.receipt('quarantine',status='rolled_back',feature_changes={'active':True,'active_id':old['id'],'active_plan_digest':old['plan_digest'],'active_generation':old['generation'],'active_expires_at':old['expires_at']})
        summary=control.public_summary(self.store.get('servers','target'))['quarantine']
        self.assertTrue(summary['active']);self.assertEqual(summary['last_operation_status'],'rolled_back');self.assertEqual(summary['expires_at'],old['expires_at'])
        self.assertEqual(control.get(self.store,self.store.all('network_control_assignments')[0]['quarantine']['parent_id'])['preview']['targets'][0]['last_report']['id'],current['id'])
        with patch.object(control,'now',return_value=now()+timedelta(hours=1)):
            self.assertTrue(control.public_summary(self.store.get('servers','target'))['quarantine']['expiry_unconfirmed'])
        for change in ({'active':'true'},{'active_generation':True},{'active_expires_at':None}):
            invalid=copy.deepcopy(metadata);invalid['quarantine'].update(change)
            with self.store.meta() as db,self.assertRaises(ValueError):control.report(self.store,db,self.store._get(db,'servers','target'),invalid)

    def test_delayed_older_snapshot_is_ignored_and_equal_time_divergence_is_rejected(self):
        self.assess();self.apply();first=self.receipt(status='rolled_back');latest=self.receipt(status='enforced')
        with self.store.meta() as db:
            server=self.store._get(db,'servers','target');self.assertEqual(control.report(self.store,db,server,first),latest)
            self.assertEqual(server['network_control'],latest)
            self.assertEqual(control.report(self.store,db,server,copy.deepcopy(latest)),latest)
        divergent=copy.deepcopy(latest);divergent['egress']['status']='rolled_back'
        with self.store.meta() as db,self.assertRaises(ValueError):control.report(self.store,db,self.store._get(db,'servers','target'),divergent)
        self.assertEqual(self.store.get('alerts','network-control:egress:target')['status'],'resolved')

    def test_read_only_shared_token_unknown_fields_and_page_bounds_are_rejected(self):
        readonly=self.person('66666666-6666-6666-6666-666666666666','read_only')
        for principal in (readonly,{**self.maker,'auth_type':'token'}):
            with self.assertRaises(PermissionError):control.assess(self.store,{'kind':'egress','server_ids':['target']},principal['actor'],principal)
        for body in ({**self.body(),'command':'shell'},self.body(kind=[]),self.body(default_deny='true')):
            with self.assertRaises(ValueError):self.preview(body)
        for kwargs in ({'limit':True},{'limit':101},{'offset':-1}):
            with self.assertRaises(ValueError):control.listing(self.store,**kwargs)


def parse_delta(later,earlier):
    from controller.store import parse_time
    return int((parse_time(later)-parse_time(earlier)).total_seconds())


@unittest.skipUnless(os.environ.get('PRTHAK_PLATFORM_PG_ACCEPTANCE')=='1','Owner opt-in for private PostgreSQL network-control fixture')
class PostgreSQLNetworkControlTests(NetworkControlTests):
    @classmethod
    def setUpClass(cls):
        import psycopg
        from psycopg import sql
        from psycopg.conninfo import make_conninfo
        cls.driver,cls.sql,cls.parameters=psycopg,sql,private_pg.parameters()
        cls.names=private_pg.names('network_control');cls.created=[]
        cls.addClassCleanup(cls.cleanup_databases)
        with psycopg.connect(**cls.parameters,dbname='postgres',autocommit=True) as db:
            cls.verify_cluster(db)
            for name in cls.names.values():
                if db.execute('SELECT 1 FROM pg_database WHERE datname=%s',(name,)).fetchone():raise RuntimeError('Refusing to adopt an existing fixture database')
                db.execute(sql.SQL('CREATE DATABASE {}').format(sql.Identifier(name)));cls.created.append(name)
        cls.dsns={key:make_conninfo(**cls.parameters,dbname=name) for key,name in cls.names.items()}

    @classmethod
    def verify_cluster(cls,db):
        user,directory=db.execute("SELECT current_user,current_setting('data_directory')").fetchone()
        if user!='prthak_test' or Path(directory).resolve()!=private_pg.data_directory():raise RuntimeError('Only the project-owned private PostgreSQL test cluster is allowed')

    @classmethod
    def cleanup_databases(cls):
        with cls.driver.connect(**cls.parameters,dbname='postgres',autocommit=True) as db:
            cls.verify_cluster(db)
            for name in cls.created:db.execute(cls.sql.SQL('DROP DATABASE {} WITH (FORCE)').format(cls.sql.Identifier(name)))

    def make_store(self):
        from controller.postgres import PostgresStore
        for dsn in self.dsns.values():
            with self.driver.connect(dsn,autocommit=True) as db:
                self.verify_cluster(db);db.execute('DROP SCHEMA public CASCADE');db.execute('CREATE SCHEMA public')
        return PostgresStore(self.dsns['metadata'],self.dsns['traffic'])

    def setUp(self):
        with patch.object(fixture,'Store',side_effect=lambda _:self.make_store()):super().setUp()
