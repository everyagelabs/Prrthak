"""Current contributing authority and exact current-Admin cleanup, no OS writes."""
from datetime import timedelta
import hashlib
import json
import os
from pathlib import Path
import secrets
import tempfile
import unittest
from unittest.mock import patch

from controller import learning_targets
from controller.auth import EntraAuth, EntraConfig, SESSION_COOKIE
from controller.store import Store, digest, now, stamp
from controller.tests import private_pg


class AdmissionChecks:
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.store = self.make_store()
        self.config = EntraConfig('11111111-1111-1111-1111-111111111111', '22222222-2222-2222-2222-222222222222', 'https://localhost/api/v1/auth/callback', 'private-fixture-secret')
        self.auth = EntraAuth(self.store, self.config, provider=object())
        self.store.approval_tenant_id = self.config.tenant_id
        self.store.approval_auth_fingerprint = self.config.fingerprint
        self.cookies = {}
        self.maker = self.person('33333333-3333-3333-3333-333333333333')
        self.other = self.person('44444444-4444-4444-4444-444444444444')
        baseline = {'management_sources':['192.0.2.0/24'], 'ssh_ports':[2022], 'controller_url':'https://localhost', 'management_probe_url':'https://localhost/api/v1/agent/enforcement/check', 'zone':'public'}
        self.heartbeat = {'hostname':'target', 'ips':['192.0.2.10'], 'listeners':[], 'firewalld_state':'running', 'capabilities':['signed_assignments_v1','policy_verification_v1'], 'protection':{**baseline,'digest':digest(baseline),'ready':True,'blockers':[]}}
        self.store.report('target', self.heartbeat)

    def make_store(self):
        return Store(self.temp.name)

    def person(self, object_id, role='admin'):
        identifier = self.config.tenant_id + ':' + object_id
        raw = secrets.token_urlsafe(32)
        with self.store.meta() as db:
            self.store._put(db,'auth_users',{'id':identifier,'tenant_id':self.config.tenant_id,'object_id':object_id,'role':role,'enabled':True})
            self.store._put(db,'auth_sessions',{'id':hashlib.sha256(raw.encode()).hexdigest(),'user_id':identifier,'expires_at':stamp(now()+timedelta(hours=1)),'config':self.config.fingerprint})
        self.cookies[identifier] = SESSION_COOKIE + '=' + raw
        principal = self.auth.authenticate({'Cookie':self.cookies[identifier]})
        self.assertIsNotNone(principal)
        return principal

    def policy(self, principal, port=8443, **extra):
        return self.store.save_policy({'name':'Port '+str(port),'mode':'enforce','selector':{},'services':[{'port':port,'sources':['198.51.100.0/24']}],**extra},principal['actor'],principal=principal)

    def change_user(self, principal, **changes):
        with self.store.meta() as db:
            user = self.store._get(db,'auth_users',principal['user']['id'])
            self.store._put(db,'auth_users',{**user,**changes})

    def merged(self):
        self.policy(self.maker)
        self.policy(self.other,9443)
        assigned = self.store.assignment('target')[0]
        self.assertTrue(assigned['enforcement']['authorized'])
        chosen = assigned['enforcement']['approval_proof']['requester']['user_id']
        omitted = next(principal for principal in (self.maker,self.other) if principal['user']['id'] != chosen)
        return assigned, omitted

    def test_any_contributor_revocation_blocks_new_admission_and_retires_merged_approval(self):
        assigned, omitted = self.merged()
        self.change_user(omitted,enabled=False)
        after = self.store.assignment('target')[0]
        self.assertFalse(after['enforcement']['authorized'])
        self.assertNotIn('policy_verification',after)
        self.assertGreater(after['assignment_generation'],assigned['assignment_generation'])
        with self.store.read_meta() as db:
            active = db.execute('SELECT active FROM managed_approvals WHERE server_id=? AND approval_id=?',('target',assigned['enforcement']['approval_id'])).fetchone()[0]
        self.assertEqual(active,0)
        # Existing installed rules are not removed by this control-plane check.
        self.assertEqual(after['services'],assigned['services'])

    def test_downgraded_contributor_also_blocks_management_health_before_a_poll(self):
        assigned, omitted = self.merged()
        self.change_user(omitted,role='read_only')
        check = {key:assigned['enforcement'][source] for key,source in [('approval_id','approval_id'),('version','approved_version'),('digest','approved_digest'),('protection_digest','protection_digest'),('binding_digest','binding_digest')]}
        with self.assertRaises(PermissionError): self.store.verify_managed_enforcement('target',check)
        with self.store.read_meta() as db:
            self.assertEqual(db.execute('SELECT active FROM managed_approvals WHERE server_id=? AND approval_id=?',('target',assigned['enforcement']['approval_id'])).fetchone()[0],0)

    def test_poll_projects_only_current_contributor_proofs_not_policy_source_matrices(self):
        self.merged()
        with self.store.meta() as db:
            policy = self.store._get(db,'policies',self.store._all(db,'policies')[0]['id'])
            self.store._put(db,'policies',{**policy,'unused_large_metadata':'NEVER_DECODE_POLICY_MATRIX'*10000})
        original = json.loads
        def bounded(value,*args,**kwargs):
            if isinstance(value,str): self.assertNotIn('NEVER_DECODE_POLICY_MATRIX',value)
            return original(value,*args,**kwargs)
        with patch('controller.managed.json.loads',side_effect=bounded):
            self.assertTrue(self.store.assignment('target')[0]['enforcement']['authorized'])

    def test_symbolic_intent_mutation_cannot_reuse_an_old_authorization_scalar(self):
        assigned,_ = self.merged()
        with self.store.meta() as db:
            policy = self.store._all(db,'policies')[0]
            # A missing cache entry must fail closed, not compare None==None.
            approval = json.loads(db.execute('SELECT data FROM managed_approvals WHERE server_id=? AND approval_id=?',('target',assigned['enforcement']['approval_id'])).fetchone()[0])
            db.execute('DELETE FROM policy_intent_headers WHERE id=?',(policy['id'],))
            from controller.managed import direct_authorities_valid
            self.assertFalse(direct_authorities_valid(self.store,db,self.store._get(db,'servers','target'),approval))
            policy['services'][0]['sources'] = ['203.0.113.0/24']
            self.store._put(db,'policies',policy)
        self.assertFalse(self.store.assignment('target')[0]['enforcement']['authorized'])

    def test_policy_header_backfill_preserves_exact_canonical_policy_byte_limit(self):
        from controller import policy_views
        policy = self.policy(self.maker)
        with self.store.meta() as db:
            original = db.execute('SELECT data FROM policies WHERE id=?',(policy['id'],)).fetchone()[0]
            db.execute('DELETE FROM policy_intent_headers')
            with patch.object(policy_views,'MAX_DETAIL_BYTES',len(original.encode())):
                from controller.managed import backfill
                backfill(self.store,db)
            self.assertEqual(db.execute('SELECT data FROM policies WHERE id=?',(policy['id'],)).fetchone()[0],original)
            self.assertEqual(self.store._get(db,'policy_intent_headers',policy['id'])['digest'],policy['direct_authorization']['scope']['intent_digest'])
        self.assertTrue(self.store.assignment('target')[0]['enforcement']['authorized'])

    def test_author_logout_does_not_revoke_saved_future_group_or_source_intent(self):
        self.policy(self.maker,selector={'application':'billing'},services=[{'port':8443,'sources':[],'source_selector':{'application':'client'}}])
        with self.store.meta() as db: db.execute('DELETE FROM auth_sessions WHERE id=?',(self.maker['_session_id'],))
        self.store.report('future',{**self.heartbeat,'hostname':'future','ips':['192.0.2.11']})
        self.store.update_server('future',{'tags':{'application':'billing'}},self.other['actor'])
        before = self.store.assignment('future')[0]
        self.assertTrue(before['enforcement']['authorized'])
        self.store.report('source',{'hostname':'source','ips':['203.0.113.10'],'listeners':[]})
        self.store.update_server('source',{'tags':{'application':'client'}},self.other['actor'])
        after = self.store.assignment('future')[0]
        self.assertTrue(after['enforcement']['authorized'])
        self.assertGreater(after['version'],before['version'])
        self.assertEqual(after['services'][0]['sources'],['203.0.113.10/32'])

    def test_current_admin_delete_authorizes_cleanup_after_original_author_disabled(self):
        policy = self.policy(self.maker)
        with self.store.meta() as db:
            server = self.store._get(db,'servers','target'); server['_managed_rules_active'] = True
            self.store._put(db,'servers',server)
        self.change_user(self.maker,enabled=False)
        removed = self.store.delete_policy(policy['id'],self.other['actor'],expected_revision=policy['revision'],principal=self.other)
        after = self.store.assignment('target')[0]
        self.assertTrue(removed['deleted']); self.assertEqual(removed['deployment']['target_count'],1)
        self.assertTrue(after['enforcement']['authorized'])
        self.assertEqual(after['enforcement']['intent'],'remove_managed_rules')
        self.assertEqual(after['enforcement']['approval_proof']['scope']['kind'],'managed_rollout')
        self.assertEqual(after['enforcement']['approval_proof']['requester']['user_id'],self.other['user']['id'])
        first = after['enforcement']['approval_id']
        self.store.report('target',self.heartbeat)
        self.assertEqual(self.store.assignment('target')[0]['enforcement']['approval_id'],first)

    def test_deleted_policy_cannot_mint_cleanup_under_a_stale_admin_principal(self):
        policy = self.policy(self.maker)
        self.change_user(self.other,role='read_only')
        with self.assertRaises(PermissionError):
            self.store.delete_policy(policy['id'],self.other['actor'],principal=self.other)
        self.assertEqual(self.store.get('policies',policy['id'])['revision'],policy['revision'])

    def test_delete_never_bypasses_whole_host_deny_acknowledgement(self):
        policy = self.policy(self.maker)
        with self.store.meta() as db:
            server = self.store._get(db,'servers','target')
            server.update(_managed_rules_active=True,host_default_deny_state={'enabled':True,'revision':1})
            self.store._put(db,'servers',server)
        self.store.delete_policy(policy['id'],self.other['actor'],principal=self.other)
        after = self.store.assignment('target')[0]
        self.assertTrue(after['host_default_deny'])
        self.assertFalse(after['enforcement']['authorized'])

    def session(self, identifier, *, ids=None, status='active', start=-60, expiry=3600, stopped=None, **extra):
        at = self.at
        value = {'id':identifier,'server_ids':ids or ['target'],'status':status,'starts_at':stamp(at+timedelta(seconds=start)),'expires_at':stamp(at+timedelta(seconds=expiry)),'ports':[{'port':443,'protocol':'tcp'}],'selection_mode':'manual','policy_action':'observe',**extra}
        if stopped is not None:value['stopped_at'] = stamp(at+timedelta(seconds=stopped))
        with self.store.meta() as db:self.store._put(db,'sessions',value)
        return value

    def test_endpoint_poll_and_report_do_not_decode_retained_unrelated_or_expired_history(self):
        self.at = now().replace(microsecond=0)
        for index in range(30):
            self.session('history-'+str(index),ids=['unrelated-'+str(i) for i in range(100)],status='expired',expiry=-3600,large_history='NEVER_DECODE_SESSION_HISTORY'*1000)
        self.session('active-own')
        self.session('active-other',ids=['other'])
        self.session('recent-stop',status='stopped',stopped=-299)
        self.session('old-own',status='stopped',stopped=-301)
        original_all, original_load = self.store._all, json.loads
        def no_history(db,table):
            self.assertNotEqual(table,'sessions')
            return original_all(db,table)
        def bounded(value,*args,**kwargs):
            if isinstance(value,str):self.assertNotIn('NEVER_DECODE_SESSION_HISTORY',value)
            return original_load(value,*args,**kwargs)
        with patch.object(self.store,'_all',side_effect=no_history),patch('controller.learning_targets.json.loads',side_effect=bounded),patch('controller.store.now',return_value=self.at):
            assigned = self.store.assignment('target')[0]
            self.store.report('target',self.heartbeat)
        self.assertEqual([row['id'] for row in assigned['learning_sessions']],['active-own'])
        self.assertEqual([row['id'] for row in assigned['learning_tombstones']],['recent-stop'])
        self.assertEqual(len(self.store.all('sessions')),34)

    def test_index_preserves_future_start_expiry_and_exact_five_minute_stop_edges(self):
        self.at = now().replace(microsecond=0)
        self.session('future',start=10,expiry=20)
        for seconds,live,dead in [(0,[],[]),(10,['future'],[]),(20,[],['future']),(320,[],['future']),(321,[],[])]:
            with self.subTest(seconds=seconds),patch('controller.store.now',return_value=self.at+timedelta(seconds=seconds)):
                assigned = self.store.assignment('target')[0]
                self.assertEqual([row['id'] for row in assigned['learning_sessions']],live)
                self.assertEqual([row['id'] for row in assigned['learning_tombstones']],dead)

    def test_index_backfills_old_inline_rows_and_recovery_rebuild_cannot_revive_stopped_scope(self):
        self.at = now().replace(microsecond=0)
        old = self.session('old-inline')
        with self.store.meta() as db:
            db.execute('DELETE FROM learning_session_targets')
            db.execute('DELETE FROM maintenance_settings WHERE id=?',(learning_targets.MARKER,))
            learning_targets.initialize(self.store,db)
            self.assertEqual([row['id'] for row in learning_targets.for_endpoint(db,'target',at=self.at)],['old-inline'])
            # Restore safety overlay updates canonical rows before rebuilding.
            db.execute('UPDATE sessions SET data=? WHERE id=?',(json.dumps({**old,'status':'stopped','stopped_at':stamp(self.at-timedelta(minutes=6))}),old['id']))
            learning_targets.rebuild(self.store,db)
            self.assertEqual(learning_targets.for_endpoint(db,'target',at=self.at,recent=True),[])
            self.assertEqual(db.execute('SELECT status FROM learning_session_targets WHERE session_id=?',(old['id'],)).fetchone()[0],'stopped')

    def test_fractional_lease_expiry_is_not_truncated_by_the_endpoint_index(self):
        self.at = now().replace(microsecond=0)
        session = self.session('fractional-expiry',expiry=1)
        session['expires_at'] = (self.at+timedelta(microseconds=900000)).isoformat().replace('+00:00','Z')
        with self.store.meta() as db:
            self.store._put(db,'sessions',session)
            self.assertEqual([scope['id'] for scope in learning_targets.for_endpoint(db,'target',at=self.at+timedelta(microseconds=500000))],['fractional-expiry'])
            self.assertEqual(learning_targets.for_endpoint(db,'target',at=self.at+timedelta(microseconds=900000)),[])

    def test_discovery_metadata_update_does_not_rewrite_the_membership_index(self):
        self.at = now().replace(microsecond=0)
        old = self.session('stable-index')
        with self.store.meta() as db:
            with patch.object(learning_targets,'hashlib') as hashing:
                self.store._put(db,'sessions',{**old,'discovery_results':{'target':{'status':'ready'}}})
                hashing.sha256.assert_not_called()


class SQLiteLivePolicyAuthorities(AdmissionChecks,unittest.TestCase):
    pass


PG_NAMES = private_pg.names('live_authority')


@unittest.skipUnless(os.environ.get('PRTHAK_PLATFORM_PG_ACCEPTANCE')=='1','Private PostgreSQL fixture owner opt-in required')
class PostgreSQLLivePolicyAuthorities(AdmissionChecks,unittest.TestCase):
    @classmethod
    def verify(cls,db,expected):
        user,directory,database = db.execute("SELECT current_user,current_setting('data_directory'),current_database()").fetchone()
        if user!='prthak_test' or Path(directory).resolve()!=private_pg.data_directory() or database!=expected:
            raise RuntimeError('Only the prepared private PostgreSQL fixture is allowed')

    @classmethod
    def setUpClass(cls):
        import psycopg
        from psycopg import sql
        from psycopg.conninfo import make_conninfo
        cls.driver,cls.sql,cls.parameters = psycopg,sql,private_pg.parameters()
        with psycopg.connect(**cls.parameters,dbname='postgres',autocommit=True) as db:
            cls.verify(db,'postgres')
            for name in PG_NAMES.values():
                if db.execute('SELECT 1 FROM pg_database WHERE datname=%s',(name,)).fetchone():raise RuntimeError('Refusing existing fixture database')
                db.execute(sql.SQL('CREATE DATABASE {}').format(sql.Identifier(name)))
        cls.dsns = {key:make_conninfo(**cls.parameters,dbname=name) for key,name in PG_NAMES.items()}

    @classmethod
    def tearDownClass(cls):
        with cls.driver.connect(**cls.parameters,dbname='postgres',autocommit=True) as db:
            cls.verify(db,'postgres')
            for name in PG_NAMES.values():db.execute(cls.sql.SQL('DROP DATABASE {} WITH (FORCE)').format(cls.sql.Identifier(name)))

    def make_store(self):
        for namespace,dsn in self.dsns.items():
            with self.driver.connect(dsn,autocommit=True) as db:
                self.verify(db,PG_NAMES[namespace])
                tables = [row[0] for row in db.execute("SELECT tablename FROM pg_tables WHERE schemaname='public'")]
                if tables:db.execute(self.sql.SQL('TRUNCATE {}').format(self.sql.SQL(',').join(map(self.sql.Identifier,tables))))
        from controller.postgres import PostgresStore
        return PostgresStore(self.dsns['metadata'],self.dsns['traffic'])


class LivePolicyAuthorityHTTPS(unittest.TestCase):
    def setUp(self):
        from controller.tests.test_policy_delivery_regressions import PolicyDeliveryHTTPSRegressions
        self.fixture = PolicyDeliveryHTTPSRegressions('test_actual_policy_edit_invalidates_both_worker_etags_and_returns_exact_sources')
        self.addCleanup(self.fixture.doCleanups); self.fixture.setUp()
        self.store = self.fixture.store
        self.config = EntraConfig('11111111-1111-1111-1111-111111111111','22222222-2222-2222-2222-222222222222','https://localhost:'+str(self.fixture.ports[0])+'/api/v1/auth/callback','private-http-fixture')
        self.auth = EntraAuth(self.store,self.config,provider=object()); self.cookies = {}
        for app in self.fixture.apps:
            app.auth = EntraAuth(app.store,self.config,provider=object())
            app.store.approval_tenant_id = self.config.tenant_id
            app.store.approval_auth_fingerprint = self.config.fingerprint
        self.maker = AdmissionChecks.person(self,'33333333-3333-3333-3333-333333333333')
        self.other = AdmissionChecks.person(self,'44444444-4444-4444-4444-444444444444')
        baseline = {'management_sources':['192.0.2.0/24'],'ssh_ports':[2022],'controller_url':'https://localhost','management_probe_url':'https://localhost/api/v1/agent/enforcement/check','zone':'public'}
        self.store.report('target',{'hostname':'target','ips':['192.0.2.10'],'listeners':[],'capabilities':['signed_assignments_v1'],'protection':{**baseline,'digest':digest(baseline),'ready':True,'blockers':[]}})

    def request(self,method,path,principal=None,body=None,csrf=True):
        connection = self.fixture.connection()
        headers = {'Content-Type':'application/json'}
        if principal:
            headers['Cookie'] = self.cookies[principal['user']['id']]
            if csrf:headers['X-CSRF-Token'] = principal['csrf_token']
        connection.request(method,'/api/v1/'+path,body=json.dumps(body) if body is not None else None,headers=headers)
        reply = connection.getresponse(); raw = reply.read()
        return reply.status,json.loads(raw) if raw else None

    def test_real_https_delete_checks_csrf_and_returns_actor_bound_cleanup_deployment(self):
        code,policy = self.request('POST','policies',self.maker,{'name':'HTTP opening','mode':'enforce','selector':{},'services':[{'port':8443,'sources':['198.51.100.0/24']}]})
        self.assertEqual(code,201,policy)
        with self.store.meta() as db:
            server = self.store._get(db,'servers','target');server['_managed_rules_active'] = True;self.store._put(db,'servers',server)
            user = self.store._get(db,'auth_users',self.maker['user']['id']);self.store._put(db,'auth_users',{**user,'enabled':False})
        path = 'policies/'+policy['id']
        self.assertEqual(self.request('DELETE',path,self.other,{'expected_revision':policy['revision']},csrf=False)[0],403)
        code,result = self.request('DELETE',path,self.other,{'expected_revision':policy['revision']})
        self.assertEqual(code,200,result);self.assertTrue(result['deleted']);self.assertEqual(result['deployment']['target_count'],1)
        assigned = self.store.assignment('target')[0]
        self.assertTrue(assigned['enforcement']['authorized'])
        self.assertEqual(assigned['enforcement']['approval_proof']['requester']['user_id'],self.other['user']['id'])

    def test_real_mtls_policy_and_management_check_reject_revoked_contributor(self):
        for principal,port in ((self.maker,8443),(self.other,9443)):
            self.assertEqual(self.request('POST','policies',principal,{'name':'HTTP '+str(port),'mode':'enforce','selector':{},'services':[{'port':port,'sources':['198.51.100.0/24']}]})[0],201)
        before = self.store.assignment('target')[0]
        chosen = before['enforcement']['approval_proof']['requester']['user_id']
        omitted = next(p for p in (self.maker,self.other) if p['user']['id']!=chosen)
        AdmissionChecks.change_user(self,omitted,enabled=False)
        approval = before['enforcement']
        check = {key:approval[source] for key,source in [('approval_id','approval_id'),('version','approved_version'),('digest','approved_digest'),('protection_digest','protection_digest'),('binding_digest','binding_digest')]}
        code,_ = self.request('POST','agent/enforcement/check',body={**check,'nonce':'authority-health-nonce-123','ssh_ports':[2022]})
        self.assertEqual(code,403)
        code,value = self.request('GET','agent/policy')
        self.assertEqual(code,200);self.assertFalse(value['enforcement']['authorized'])
