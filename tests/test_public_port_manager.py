"""Reviewed public publication, transaction/readback/replay failure boundaries."""
import copy
import subprocess
import time
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).parent))
import test_appliance_installer as baseline
n=baseline.appliance


class PublicPortManagerTests(unittest.TestCase):
    def setUp(self):
        baseline.ApplianceManagerTests.setUpClass();self.fixture=baseline.ApplianceManagerTests();self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        self.manager=self.fixture.manager;self.root=self.fixture.root;self.shared=self.fixture.shared;self.shared['states'].update(controller='running',router='running')
        self.free=[];self.manager.engine.assert_public_port_free=lambda address,port:self.free.append((address,port));self.probes=[]
        self.manager._web_probe=lambda chain,name,port,fingerprint:self.probes.append(port)
        self.body={'operation_id':'1'*32,'expected_revision':0,'old_port':8787,'new_port':9443,'expected_fingerprint':'a'*64,'server_name':'localhost','controller_origin':self.fixture.local['controller_origin'],'origin_mode':'preserve'}
    def phase(self,name,**fields):return self.manager.public_port({**self.body,'phase':name,**fields})
    def test_phased_exact_public_mapping_only_tls_proven_then_committed_and_replayed(self):
        before=n.load(self.root/'runtime/compose.json');result=self.phase('prepare');self.assertTrue(result['prepared']);self.assertEqual(before,n.load(self.root/'runtime/compose.json'))
        self.phase('activate');current=n.load(self.root/'runtime/compose.json');expected=copy.deepcopy(before);expected['services']['router']['ports'][0]=self.fixture.local['bind_ip']+':9443:8787';self.assertEqual(current,expected)
        self.assertEqual(self.manager.status()['public_port'],8787);self.assertEqual(self.manager.status()['public_listener']['candidate_port'],9443)
        with self.assertRaises(n.Blocked):self.phase('commit')
        self.assertTrue(self.phase('verify')['tls_verified']);self.assertTrue(self.phase('commit')['committed'])
        self.assertEqual(self.manager.status()['public_port'],9443);self.assertEqual(self.manager.installed['controller_origin'],self.body['controller_origin']);self.assertEqual(self.manager.state()['revision'],1)
        self.assertEqual((self.root/'config/gui-overrides.env').read_text(),'CONTROLLER_PORT=9443\n')
        self.assertTrue(self.phase('commit')['committed']);self.assertEqual(self.manager.state()['revision'],1)
        self.assertTrue(all('controller' not in call and 'database' not in call and 'etcd' not in call for call in self.shared['calls']))
        self.assertEqual(self.probes,[8787,9443,9443,9443])
    def test_bad_ports_origin_revision_arbitrary_fields_or_occupied_bind_rejected(self):
        for fields in ({'new_port':0},{'new_port':True},{'new_port':65536},{'new_port':8786},{'new_port':8788},{'new_port':8789},{'new_port':8796},{'new_port':8797},{'new_port':5433},{'new_port':22},{'expected_revision':1},{'origin_mode':'direct'},{'controller_origin':'https://other.example'},{'command':'id'}):
            with self.subTest(fields=fields),self.assertRaises(n.Blocked):self.phase('prepare',**fields)
        self.manager.engine.assert_public_port_free=lambda *args:(_ for _ in ()).throw(n.Blocked('occupied'))
        with self.assertRaises(n.Blocked):self.phase('prepare')
        self.assertFalse((self.root/'manager/public-port.json').exists())
    def test_443_publication_does_not_lower_app_or_internal_port_privileges(self):
        self.body['new_port']=443;self.phase('prepare');self.phase('activate');self.phase('verify');self.phase('commit')
        compose=n.load(self.root/'runtime/compose.json');self.assertTrue(compose['services']['router']['ports'][0].endswith(':443:8787'));self.assertEqual(compose['services']['controller']['user'],'10001:10001');self.assertEqual(compose['services']['router']['user'],'10003:10003');self.assertEqual(compose['services']['controller']['ports'],[self.fixture.local['bind_ip']+':8786:8787',self.fixture.local['bind_ip']+':8796:8788',self.fixture.local['bind_ip']+':8797:8789'])
    def test_custom_agent_channels_survive_commit_cancel_and_rollback_exactly(self):
        settings={'environment':{'SEG_CONTROL_PORT':'10444','SEG_DISCOVERY_PORT':'10445'}}
        n.atomic(self.root/'config/controller/settings.json',settings);self.manager.render();settings=n.load(self.root/'config/controller/settings.json')
        before=n.load(self.root/'runtime/compose.json');unchanged=before['services']['router']['ports'][1:]
        self.assertEqual(unchanged,[self.fixture.local['bind_ip']+':10444:8788',self.fixture.local['bind_ip']+':10445:8789',self.fixture.local['bind_ip']+':5433:5433'])
        self.phase('prepare');self.phase('activate');self.phase('verify');self.phase('commit')
        committed=n.load(self.root/'runtime/compose.json');self.assertEqual(committed['services']['router']['ports'][1:],unchanged)
        self.assertEqual(n.load(self.root/'config/controller/settings.json'),{**settings,'public_port':9443})
        self.body.update(operation_id='2'*32,expected_revision=1,old_port=9443,new_port=11443)
        self.assertTrue(self.phase('abort')['verified']);self.assertEqual(n.load(self.root/'runtime/compose.json'),committed)
        self.body['operation_id']='3'*32;self.phase('prepare');self.phase('activate');self.phase('verify');self.phase('abort')
        self.assertEqual(n.load(self.root/'runtime/compose.json'),committed);self.assertEqual(self.manager.installed['controller_port'],9443)
    def test_extra_missing_or_changed_agent_publication_blocks_prepare_and_unseen_cancel(self):
        original=n.load(self.root/'runtime/compose.json')
        changes=[original['services']['router']['ports']+['0.0.0.0:12000:8788'],original['services']['router']['ports'][:1]+original['services']['router']['ports'][2:]]
        changed=copy.deepcopy(original['services']['router']['ports']);changed[1]=self.fixture.local['bind_ip']+':12000:8788';changes.append(changed)
        for ports in changes:
            compose=copy.deepcopy(original);compose['services']['router']['ports']=ports;n.atomic(self.root/'runtime/compose.json',compose)
            with self.subTest(ports=ports):
                with self.assertRaisesRegex(n.Blocked,'ambiguous or unmanaged'):self.phase('prepare')
                with self.assertRaisesRegex(n.Blocked,'exact old owned publication'):self.phase('abort')
                self.assertEqual(n.load(self.root/'runtime/compose.json'),compose)
        self.assertFalse((self.root/'manager/public-port.json').exists())
    def test_terminal_readback_refuses_agent_mapping_changes_without_overwriting(self):
        self.phase('prepare');self.phase('activate');self.phase('verify');self.phase('commit')
        compose=n.load(self.root/'runtime/compose.json');compose['services']['router']['ports'][2]=self.fixture.local['bind_ip']+':12000:8789';n.atomic(self.root/'runtime/compose.json',compose)
        with self.assertRaisesRegex(n.Blocked,'unchanged agent channels'):self.phase('commit')
        self.assertEqual(n.load(self.root/'runtime/compose.json'),compose)
    def test_cancelled_readback_refuses_later_agent_mapping_changes(self):
        self.phase('abort');compose=n.load(self.root/'runtime/compose.json');compose['services']['router']['ports'][1]=self.fixture.local['bind_ip']+':12000:8788';n.atomic(self.root/'runtime/compose.json',compose)
        with self.assertRaisesRegex(n.Blocked,'unchanged agent channels'):self.phase('abort')
        self.assertEqual(n.load(self.root/'runtime/compose.json'),compose)
    def test_failed_candidate_automatically_restores_old_mapping_and_latches_review(self):
        previous=n.load(self.root/'runtime/compose.json');self.phase('prepare');self.phase('activate')
        def probe(*args):
            if args[2]==9443:raise n.Blocked('candidateTLSfailure')
        self.manager._web_probe=probe
        with patch.object(n.time,'sleep'),self.assertRaises(n.Blocked):self.phase('verify')
        self.assertEqual(n.load(self.root/'runtime/compose.json'),previous);self.assertEqual(self.manager.installed['controller_port'],8787);self.assertEqual(n.load(self.root/'manager/public-port.json')['phase'],'aborted')
        with self.assertRaises(n.Blocked):self.phase('activate')
        self.assertTrue(self.phase('abort')['verified'])
    def test_manager_restart_recovers_interrupted_mapping_and_deadline_aborts(self):
        self.phase('prepare');self.phase('activate');self.manager.recover_public_port()
        self.assertTrue(self.phase('abort')['rolled_back']);self.assertEqual(self.manager.status()['public_port'],8787)
        self.body['operation_id']='2'*32;self.phase('prepare');record=n.load(self.root/'manager/public-port.json');record['deadline']=0;n.atomic(self.root/'manager/public-port.json',record);self.manager.recover_public_port(expired_only=True)
        self.assertEqual(n.load(self.root/'manager/public-port.json')['phase'],'aborted')
    def test_pending_transition_blocks_other_mutations_and_unmanaged_edits_are_not_overwritten(self):
        self.phase('prepare')
        with self.assertRaises(n.Blocked):self.manager.operate('restart','router')
        with self.assertRaises(n.Blocked):self.phase('activate',new_port=9888)
        original=n.load(self.root/'runtime/compose.json');foreign=copy.deepcopy(original);foreign['services']['router']['labels']['foreign']='changed';n.atomic(self.root/'runtime/compose.json',foreign)
        with self.assertRaises(n.Blocked):self.phase('activate')
        with self.assertRaises(n.Blocked):self.phase('abort')
        self.assertEqual(n.load(self.root/'runtime/compose.json'),foreign)
    def test_old_generation_cannot_abort_new_committed_mapping(self):
        self.phase('prepare');self.phase('activate');self.phase('verify');self.phase('commit');old=dict(self.body)
        self.body.update(operation_id='2'*32,expected_revision=1,old_port=9443,new_port=10443);self.phase('prepare');self.phase('activate');self.phase('verify');self.phase('commit')
        with self.assertRaises(n.Blocked):self.manager.public_port({**old,'phase':'abort'})
        self.assertEqual(self.manager.installed['controller_port'],10443)
    def test_partial_commit_recovery_restores_old_protected_files_and_revision(self):
        self.phase('prepare');self.phase('activate');self.phase('verify');record=n.load(self.root/'manager/public-port.json');record['phase']='committing';n.atomic(self.root/'manager/public-port.json',record)
        self.manager.installed=record['candidate_installed'];n.atomic(self.root/'config/installed.json',self.manager.installed);n.atomic(self.root/'manager/state.json',{'revision':1,'last_public_port_operation':self.body['operation_id']})
        self.manager.recover_public_port();self.assertEqual(self.manager.status()['public_port'],8787);self.assertEqual(self.manager.state()['revision'],0);self.assertTrue(self.phase('abort')['verified'])
    def test_docker_nat_publication_without_listener_is_detected(self):
        engine=n.Engine(self.root,'private')
        engine.run=lambda args,**kwargs:'a'*64 if args[0]=='ps' else '{"8787/tcp":[{"HostIp":"0.0.0.0","HostPort":"9443"}]}'
        with self.assertRaisesRegex(n.Blocked,'published'):engine.assert_public_port_free('127.0.0.1',9443)
    def test_secret_files_and_unrelated_settings_export_are_preserved(self):
        settings={'environment':{'SEG_ENTRA_CLIENT_SECRET_FILE':'/run/prthak-bootstrap/entra-client-secret','SEG_HTTP_THREADS':'32'},'node_id':'unchanged'}
        n.atomic(self.root/'config/controller/settings.json',settings);n.atomic(self.root/'config/controller/entra-client-secret','private-fixture-secret')
        n.atomic(self.root/'config/gui-overrides.env','SEG_HTTP_THREADS=32\nCONTROLLER_PORT=8787\n')
        self.phase('prepare');self.phase('activate');self.phase('verify');self.phase('commit')
        self.assertEqual(n.load(self.root/'config/controller/settings.json'),{**settings,'public_port':9443})
        self.assertEqual((self.root/'config/controller/entra-client-secret').read_text(),'private-fixture-secret')
        self.assertEqual((self.root/'config/gui-overrides.env').read_text(),'SEG_HTTP_THREADS=32\nCONTROLLER_PORT=9443\n')
    def test_timeout_fences_compose_child_group_before_compensation(self):
        sentinel=self.fixture.parent/'must-not-be-written';script=self.fixture.parent/'slow-fixed-command.py'
        script.write_text('import subprocess,sys,time\nsubprocess.Popen([sys.executable,"-c","import pathlib,sys,time;time.sleep(.7);pathlib.Path(sys.argv[1]).write_text(\'late\')",sys.argv[1]])\ntime.sleep(5)\n')
        engine=n.Engine(self.root,'private',docker=(sys.executable,str(script)))
        with self.assertRaises(n.Blocked):engine.run([str(sentinel)],timeout=.1)
        time.sleep(.9);self.assertFalse(sentinel.exists())
    def test_unknown_prepare_cancellation_freshly_proves_old_and_blocks_late_prepare(self):
        before=n.load(self.root/'runtime/compose.json');state=self.manager.state();result=self.phase('abort')
        self.assertTrue(result['rolled_back']);self.assertTrue(result['verified']);self.assertEqual(self.probes,[8787]);self.assertFalse((self.root/'manager/public-port.json').exists())
        self.assertEqual(self.manager.state(),state);self.assertEqual(n.load(self.root/'runtime/compose.json'),before);self.assertEqual(self.shared['calls'],[])
        with self.assertRaises(n.Blocked):self.phase('prepare')
        with self.assertRaises(n.Blocked):self.phase('activate')
        with self.assertRaises(n.Blocked):self.phase('abort',new_port=9888)
        self.assertTrue(self.phase('abort')['verified'])
    def test_unknown_cancel_preserves_previous_committed_journal_and_current_mapping(self):
        self.phase('prepare');self.phase('activate');self.phase('verify');self.phase('commit')
        journal=(self.root/'manager/public-port.json').read_bytes();mapping=n.load(self.root/'runtime/compose.json');state=self.manager.state()
        self.body.update(operation_id='2'*32,expected_revision=1,old_port=9443,new_port=10443)
        self.assertTrue(self.phase('abort')['verified']);self.assertEqual((self.root/'manager/public-port.json').read_bytes(),journal);self.assertEqual(self.manager.state(),state);self.assertEqual(n.load(self.root/'runtime/compose.json'),mapping);self.assertEqual(self.manager.installed['controller_port'],9443)
        with self.assertRaises(n.Blocked):self.phase('prepare')
    def test_cancellation_bound_fails_closed_without_eviction_or_late_authority(self):
        directory=self.root/'manager/public-port-cancelled';directory.mkdir()
        for index in range(1024):n.atomic(directory/format(index,'032x'),{'retained':True})
        with self.assertRaisesRegex(n.Blocked,'bound is full'):self.phase('abort')
        self.assertEqual(len(list(directory.iterdir())),1024);self.assertFalse((directory/self.body['operation_id']).exists())
    def test_unseen_cancel_refuses_changed_owned_mapping_and_preserves_it(self):
        compose=n.load(self.root/'runtime/compose.json');compose['services']['router']['ports'][0]=self.fixture.local['bind_ip']+':9443:8787';n.atomic(self.root/'runtime/compose.json',compose)
        with self.assertRaisesRegex(n.Blocked,'exact old owned publication'):self.phase('abort')
        self.assertEqual(n.load(self.root/'runtime/compose.json'),compose);self.assertFalse((self.root/'manager/public-port-cancelled'/self.body['operation_id']).exists())


if __name__=='__main__':unittest.main()
