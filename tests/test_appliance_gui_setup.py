"""No-env bootstrap and fixed GUI configuration; no host/Docker mutations."""
import copy
import importlib.util
import json
from pathlib import Path
import sqlite3
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).parent))
import test_appliance_installer as baseline

n=baseline.appliance
spec=importlib.util.spec_from_file_location('gui_setup_entrypoint',Path(__file__).resolve().parents[1]/'deploy/appliance/controller_entrypoint.py')
entrypoint=importlib.util.module_from_spec(spec);spec.loader.exec_module(entrypoint)


class GUISetupManagerTests(unittest.TestCase):
    def setUp(self):
        baseline.ApplianceManagerTests.setUpClass();self.fixture=baseline.ApplianceManagerTests();self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.manager,self.root,self.shared=self.fixture.manager,self.fixture.root,self.fixture.shared
        self.initial={'node_id':self.fixture.local['node_id'],'node_ip':self.fixture.local['node_ip'],
            'site':self.fixture.local['site'],'controller_origin':self.fixture.local['controller_origin'],
            'environment':{'PRTHAK_APPLIANCE':'1','PRTHAK_APPLIANCE_NODE_ID':self.fixture.local['node_id']}}
        n.atomic(self.root/'config/controller/settings.json',self.initial,owner=10001)
        self.manager.render()
        self.initial_installed=copy.deepcopy(self.manager.installed)
        self.initial=n.load(self.root/'config/controller/settings.json')
        n.atomic(self.root/'config/controller/initial-admin-token','PRIVATE-BOOTSTRAP-TOKEN',owner=10001)
        self.manager.engine.validate_initial_environment=entrypoint.validate_initial_environment
        self.manager._controller_configuration_material=lambda:{'chain':'PUBLIC TEST CHAIN','name':'localhost','fingerprint':'a'*64}
        self.manager._controller_configuration_probe_budget=0
        self.probes=[]
        def probe(record,previous=False):
            self.probes.append(previous)
            expected=record['previous_settings'] if previous else record['desired_settings']
            self.assertEqual(n.load(self.root/'config/controller/settings.json'),expected)
            if self.shared.get('candidate_failure') and not previous:raise n.Blocked('injected candidate readiness failure')
        self.manager._controller_configuration_probe=probe
        self.manager._web_probe=lambda *arguments,**kwargs:None
        self.auth={'SEG_ENTRA_TENANT_ID':'11111111-1111-4111-8111-111111111111',
            'SEG_ENTRA_CLIENT_ID':'22222222-2222-4222-8222-222222222222',
            'SEG_ENTRA_REDIRECT_URI':'https://controller.example/api/v1/auth/callback',
            'SEG_BOOTSTRAP_SUPER_ADMIN_OID':'33333333-3333-4333-8333-333333333333'}

    def request(self,environment,secret='',identifier='1'*32,verified=False):
        state=self.manager.controller_configuration_status()
        body={'action':'controller-config','request_id':identifier,'operation_id':identifier,
              'expected_revision':state['expected_revision'],'expected_config_digest':state['digest'],'environment':environment}
        if secret:body['client_secret']=secret
        if verified:body.update(candidate_login_verified=True,candidate_binding_digest=n.controller_configuration_binding(body))
        return body

    def test_runtime_review_is_durable_secret_free_and_same_operation_idempotent(self):
        body=self.request({'SEG_HTTP_WORKERS':'2','SEG_HTTP_THREADS':'32','SEG_DB_POOL_META_MAX':'8','SEG_DB_POOL_TRAFFIC_MAX':'2'})
        self.manager.submit(body);self.assertTrue(self.manager.work_once());job=self.manager.job(body['request_id'])
        self.assertEqual(job['status'],'completed');self.assertTrue(job['result']['applied']);self.assertEqual(job['result']['revision'],1)
        self.assertEqual(n.load(self.root/'config/controller/settings.json')['environment']['SEG_DB_POOL_META_MAX'],'8')
        before=copy.deepcopy(self.shared['calls'])
        self.assertTrue(self.manager.controller_configuration(body)['applied']);self.assertEqual(before,self.shared['calls'])
        self.assertEqual((self.root/'config/controller/initial-admin-token').read_text(),'PRIVATE-BOOTSTRAP-TOKEN')
        self.assertEqual(n.load(self.root/'config/installed.json'),self.initial_installed)
        self.assertNotIn('PRIVATE-BOOTSTRAP-TOKEN',json.dumps(job))

    def test_candidate_binding_matches_controller_for_empty_and_present_secret(self):
        from controller.gui_setup import binding
        for secret in ('','private-test-candidate-secret'):
            body=self.request({key:'' for key in (*n.AUTH_PUBLIC,*n.RUNTIME_PUBLIC)},secret)
            self.assertEqual(n.controller_configuration_binding(body),binding(body))

    def test_reviewed_runtime_persists_exact_host_ssh_probe_scope(self):
        from controller.management_health import PROBE_SOURCE, PROBE_TARGETS
        values = {PROBE_SOURCE: '10.90.0.5', PROBE_TARGETS: '10.40.0.0/24'}
        body = self.request(values)
        result = self.manager.controller_configuration(body)
        self.assertTrue(result['applied'])
        environment = self.manager.controller_configuration_status()['environment']
        self.assertEqual({key: environment[key] for key in values}, values)

    def test_initial_provider_requires_exact_candidate_proof_before_any_write(self):
        secret='private-test-candidate-secret'
        body=self.request({**self.auth,'SEG_HTTP_WORKERS':'2'},secret)
        before=(self.root/'config/controller/settings.json').read_bytes()
        for extra in ({},{'candidate_login_verified':True,'candidate_binding_digest':'0'*64}):
            with self.assertRaises(n.Blocked):self.manager.controller_configuration({**body,**extra})
            self.assertEqual((self.root/'config/controller/settings.json').read_bytes(),before)
            self.assertFalse((self.root/'config/controller/entra-client-secret').exists())
        good=self.request({**self.auth,'SEG_HTTP_WORKERS':'2'},secret,verified=True)
        result=self.manager.controller_configuration(good)
        self.assertTrue(result['applied'])
        saved=n.load(self.root/'config/controller/settings.json')['environment']
        self.assertNotIn('SEG_ENTRA_CLIENT_SECRET',saved)
        self.assertEqual(saved['SEG_ENTRA_CLIENT_SECRET_FILE'],'/run/prthak-bootstrap/entra-client-secret')
        self.assertEqual((self.root/'config/controller/entra-client-secret').read_text().strip(),secret)
        self.assertEqual((self.root/'config/controller/entra-client-secret').stat().st_mode&0o777,0o600)
        self.assertNotIn(secret,json.dumps(result));self.assertNotIn(secret,json.dumps(self.manager.status()))
        self.assertNotIn(secret,json.dumps(self.shared['calls']))
        self.assertTrue((self.root/'config/controller/initial-admin-token').is_file())

    def test_configured_provider_secret_and_bootstrap_are_preserved_for_runtime_only(self):
        secret='private-preserved-provider-secret'
        self.manager.controller_configuration(self.request(self.auth,secret,verified=True))
        before=(self.root/'config/controller/entra-client-secret').read_bytes()
        self.manager.controller_configuration(self.request({**self.auth,'SEG_HTTP_WORKERS':'3'},identifier='2'*32))
        self.assertEqual((self.root/'config/controller/entra-client-secret').read_bytes(),before)
        self.assertEqual(n.load(self.root/'config/controller/settings.json')['environment']['SEG_BOOTSTRAP_SUPER_ADMIN_OID'],self.auth['SEG_BOOTSTRAP_SUPER_ADMIN_OID'])
        for environment,new_secret in (({**self.auth,'SEG_ENTRA_TENANT_ID':'44444444-4444-4444-8444-444444444444'},''),(self.auth,'different-private-secret'),({},'')):
            with self.assertRaises(n.Blocked):self.manager.controller_configuration(self.request(environment,new_secret,identifier='3'*32,verified=True))
        self.assertEqual((self.root/'config/controller/entra-client-secret').read_bytes(),before)

    def test_invalid_schema_counts_stale_revision_digest_and_secret_sources_fail_closed(self):
        for environment in ({'SEG_HTTP_WORKERS':'17'},{'SEG_DB_POOL_META_MAX':'0'},{'SEG_EXEC_COMMAND':'id'},{'SEG_ENTRA_CLIENT_SECRET':'not-a-public-value'}):
            with self.assertRaises((n.Blocked,ValueError)):self.manager.controller_configuration(self.request(environment))
        for changes in ({'expected_revision':True},{'expected_revision':8},{'expected_config_digest':'0'*64},{'bind_address':'0.0.0.0'}):
            with self.assertRaises(n.Blocked):self.manager.controller_configuration({**self.request({'SEG_HTTP_WORKERS':'2'}),**changes})
        self.assertEqual(n.load(self.root/'config/controller/settings.json'),self.initial)

    def test_candidate_failure_verifiably_rolls_back_and_cannot_silently_retry(self):
        self.shared['candidate_failure']=True
        body=self.request(self.auth,'private-failed-candidate-secret',verified=True)
        result=self.manager.controller_configuration(body)
        self.assertTrue(result['rolled_back']);self.assertFalse(result['applied']);self.assertEqual(result['revision'],0)
        self.assertEqual(n.load(self.root/'config/controller/settings.json'),self.initial)
        self.assertFalse((self.root/'config/controller/entra-client-secret').exists())
        self.shared['candidate_failure']=False;calls=len(self.shared['calls'])
        self.assertTrue(self.manager.controller_configuration(body)['rolled_back'])
        self.assertEqual(len(self.shared['calls']),calls)
        self.assertTrue(self.manager.controller_configuration_status()['bootstrap_available'])

    def test_process_interruption_recovers_exact_old_settings_on_new_manager(self):
        body=self.request(self.auth,'private-interrupted-candidate-secret',verified=True)
        original=self.manager.engine.compose
        def interrupted(arguments,**options):raise KeyboardInterrupt()
        self.manager.engine.compose=interrupted
        with self.assertRaises(KeyboardInterrupt):self.manager.controller_configuration(body)
        self.assertEqual(n.load(self.root/'manager/controller-config.json')['phase'],'applying')
        self.manager.engine.compose=original
        with patch.object(n.Manager,'_wait_controller_configuration',lambda manager,record,previous=False:None):
            recovered=n.Manager(self.root,self.fixture.parent/'pointer',self.fixture.factory,self.fixture.parent)
        self.assertEqual(n.load(self.root/'config/controller/settings.json'),self.initial)
        self.assertFalse((self.root/'config/controller/entra-client-secret').exists())
        self.assertEqual(recovered.state()['revision'],0)
        self.assertEqual(n.load(self.root/'manager/controller-config.json')['phase'],'rolled_back')

    def test_reviewed_active_secret_rotation_and_explicit_rollback_restore_exact_provider(self):
        self.manager.controller_configuration(self.request(self.auth,'private-original-secret',verified=True))
        previous=n.load(self.root/'config/controller/settings.json')
        body=self.request({**self.auth,'SEG_BOOTSTRAP_SUPER_ADMIN_OID':''},'private-rotated-secret',identifier='4'*32)
        body.update(provider_change=True,provider_epoch='e'*32,binding_salt='b'*64,candidate_login_verified=True)
        body['candidate_binding_digest']=n.controller_configuration_binding(body)
        self.assertTrue(self.manager.controller_configuration(body)['applied'])
        self.assertEqual((self.root/'config/controller/entra-client-secret').read_text().strip(),'private-rotated-secret')
        self.assertEqual(n.load(self.root/'config/controller/settings.json')['environment']['PRTHAK_PROVIDER_EPOCH'],'e'*32)
        result=self.manager.controller_configuration({'action':'controller-config','operation_id':'4'*32,'expected_revision':0,'expected_config_digest':'0'*64,'environment':{},'rollback_operation':True})
        self.assertTrue(result['rolled_back'])
        self.assertEqual((self.root/'config/controller/entra-client-secret').read_text().strip(),'private-original-secret')
        self.assertEqual(n.load(self.root/'config/controller/settings.json'),previous)

    def test_rollback_fence_rejects_a_late_queued_apply_that_never_started(self):
        body=self.request({'SEG_HTTP_WORKERS':'2'},identifier='5'*32)
        self.assertTrue(self.manager.controller_configuration({'action':'controller-config','operation_id':'5'*32,'expected_revision':0,'expected_config_digest':'0'*64,'environment':{},'rollback_operation':True})['rolled_back'])
        with self.assertRaises(n.Blocked):self.manager.controller_configuration(body)
        self.assertEqual(n.load(self.root/'config/controller/settings.json'),self.initial)

    def test_native_channel_alias_ack_cannot_be_forged_with_a_string(self):
        with self.assertRaises(n.Blocked):self.manager.controller_configuration({**self.request({'SEG_HTTP_WORKERS':'2'}),'acknowledge_agent_aliases':'true'})

    def test_old_operation_cannot_replace_a_newer_committed_runtime_generation(self):
        old=self.request({'SEG_HTTP_WORKERS':'2'})
        self.manager.controller_configuration(old)
        self.manager.controller_configuration(self.request({'SEG_HTTP_WORKERS':'3'},identifier='2'*32))
        before=(self.root/'config/controller/settings.json').read_bytes()
        with self.assertRaises(n.Blocked):self.manager.controller_configuration(old)
        with self.assertRaises(n.Blocked):self.manager.controller_configuration({**old,'environment':{'SEG_HTTP_WORKERS':'4'}})
        self.assertEqual((self.root/'config/controller/settings.json').read_bytes(),before)
        self.assertEqual(self.manager.state()['revision'],2)

    def test_unverified_rollback_remains_fenced_against_unrelated_manager_actions(self):
        calls=[]
        def failed_after_preflight(record,previous=False):
            calls.append(previous)
            if len(calls)>1:raise n.Blocked('injected readiness outage')
        self.manager._controller_configuration_probe=failed_after_preflight
        with self.assertRaises(n.Blocked):self.manager.controller_configuration(self.request({'SEG_HTTP_WORKERS':'2'}))
        self.assertEqual(n.load(self.root/'manager/controller-config.json')['phase'],'rollback_failed')
        before=len(self.shared['calls'])
        job=self.manager.submit({'action':'restart','service':'controller','request_id':'a'*32})
        self.assertTrue(self.manager.work_once());self.assertEqual(self.manager.job(job['id'])['status'],'blocked')
        self.assertEqual(len(self.shared['calls']),before)

    def test_bootstrap_origin_drains_then_checks_real_inventory_and_preserves_fixed_addresses(self):
        database=self.root/'controller/inventory.sqlite3';database.parent.mkdir(exist_ok=True)
        with sqlite3.connect(database) as db:db.execute('CREATE TABLE servers(id TEXT PRIMARY KEY,data TEXT NOT NULL)')
        value=self.fixture.partial();value['controller_origin']='https://controller.example:8787';value['local_node']['site']='New site'
        result=self.manager.configure({'expected_revision':0,'configuration':value})
        self.assertTrue(result['origin_verified']);self.assertEqual(self.manager.installed['controller_origin'],value['controller_origin'])
        self.assertEqual(n.load(self.root/'config/controller/settings.json')['site'],'New site')
        self.assertEqual(self.manager.installed['node_ip'],self.fixture.local['node_ip']);self.assertEqual(self.manager.installed['bind_ip'],self.fixture.local['bind_ip'])
        self.assertEqual(self.shared['calls'][0],['stop','--timeout','30','controller'])
        self.assertEqual(n.load(self.root/'manager/origin-bootstrap.json')['phase'],'applied')

    def test_bootstrap_origin_enrollment_race_after_preflight_is_detected_after_drain(self):
        database=self.root/'controller/inventory.sqlite3';database.parent.mkdir(exist_ok=True)
        with sqlite3.connect(database) as db:db.execute('CREATE TABLE servers(id TEXT PRIMARY KEY,data TEXT NOT NULL)')
        original=self.manager.engine.compose
        def raced(arguments,**options):
            if arguments[0]=='stop':
                with sqlite3.connect(database) as db:db.execute("INSERT INTO servers VALUES('new-enrollment','{}')")
            return original(arguments,**options)
        self.manager.engine.compose=raced
        value=self.fixture.partial();value['controller_origin']='https://controller.example:8787'
        with self.assertRaises(n.Blocked):self.manager.configure({'expected_revision':0,'configuration':value})
        self.assertEqual(self.manager.installed,self.initial_installed)
        self.assertEqual(n.load(self.root/'config/controller/settings.json'),self.initial)
        self.assertEqual(n.load(self.root/'manager/origin-bootstrap.json')['phase'],'rolled_back')
        with sqlite3.connect(database) as db:self.assertEqual(db.execute('SELECT COUNT(*) FROM servers').fetchone()[0],1)

    def test_origin_unreadable_inventory_or_existing_provider_is_not_an_empty_database(self):
        value=self.fixture.partial();value['controller_origin']='https://controller.example:8787'
        with self.assertRaises(n.Blocked):self.manager.configure({'expected_revision':0,'configuration':value})
        database=self.root/'controller/inventory.sqlite3';database.parent.mkdir(exist_ok=True);database.write_text('not-a-database')
        with self.assertRaises(n.Blocked):self.manager.configure({'expected_revision':0,'configuration':value})
        n.atomic(self.root/'config/controller/settings.json',{**self.initial,'environment':self.auth})
        with self.assertRaises(n.Blocked):self.manager.configure({'expected_revision':0,'configuration':value})
        self.assertEqual(self.shared['calls'],[])


class GUIInstallerDefaultsTests(unittest.TestCase):
    def setUp(self):
        baseline.ApplianceManagerTests.setUpClass();self.fixture=baseline.ApplianceManagerTests();self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        self.parent,self.root=self.fixture.parent,self.fixture.root
        original=n.safe_path
        self.paths=patch.object(n,'safe_path',side_effect=lambda value:original(value,self.parent));self.paths.start();self.addCleanup(self.paths.stop)

    def test_explicit_gui_mode_ignores_env_and_detects_only_unicast_management_address(self):
        fresh=self.parent/'fresh';args=SimpleNamespace(gui_setup=True,env_file=None,data_root=str(fresh))
        class Route:
            def __enter__(self):return self
            def __exit__(self,*arguments):pass
            def connect(self,target):pass
            def getsockname(self):return '10.241.2.11',12345
        with patch.object(n,'read_env',side_effect=AssertionError('GUI bootstrap read an .env')),patch.object(n.socket,'socket',return_value=Route()):
            values,settings,root=n.installer_configuration(args,self.parent/'pointer')
        self.assertEqual(values,{});self.assertEqual(settings['node_ip'],'10.241.2.11');self.assertEqual(settings['bind_ip'],'10.241.2.11')
        self.assertEqual(settings['controller_origin'],'https://10.241.2.11:8787')
        for address in ('127.0.0.1','0.0.0.0','169.254.1.1','224.0.0.1'):
            with patch.object(n.socket,'socket',return_value=Route()):
                with patch.object(Route,'getsockname',return_value=(address,12345)),self.assertRaises(n.Blocked):n.settings({})

    def test_gui_rerun_preserves_committed_root_identity_port_and_configuration(self):
        pointer=self.parent/'pointer';pointer.write_text(str(self.root))
        installed={**self.fixture.local,'controller_port':9443,'site':'Custom preserved site'};n.atomic(self.root/'config/installed.json',installed)
        args=SimpleNamespace(gui_setup=True,env_file=None,data_root=None)
        with patch.object(n.socket,'socket',side_effect=AssertionError('Reinstall re-detected identity')):
            values,current,root=n.installer_configuration(args,pointer)
        self.assertEqual(current,installed);self.assertEqual(root,self.root);self.assertEqual(values,{})
        args.env_file=str(self.parent/'missing.env')
        with self.assertRaises(n.Blocked):n.installer_configuration(args,pointer)
        args.gui_setup=False
        with self.assertRaises(OSError):n.installer_configuration(args,pointer)

    def test_entrypoint_never_loads_raw_secrets_or_arbitrary_environment(self):
        self.assertEqual(entrypoint.controller_environment({'environment':{'PRTHAK_APPLIANCE':'1','SEG_HTTP_WORKERS':'2'}}),{'PRTHAK_APPLIANCE':'1','SEG_HTTP_WORKERS':'2'})
        for environment in ({'SEG_ENTRA_CLIENT_SECRET':'raw-secret'},{'LD_PRELOAD':'/untrusted'},{'SEG_ENTRA_CLIENT_SECRET_FILE':'/arbitrary/path'}):
            with self.assertRaises(ValueError):entrypoint.controller_environment({'environment':environment})


if __name__=='__main__':unittest.main()
