"""Fixed recovery control tests; no real database or Docker services are used."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).parent))
import test_appliance_installer as baseline
n=baseline.appliance


class RestoreDatabaseManagerTests(unittest.TestCase):
    def setUp(self):
        baseline.ApplianceManagerTests.setUpClass();self.fixture=baseline.ApplianceManagerTests();self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        self.manager=self.fixture.manager;self.root=self.fixture.root;self.shared=self.fixture.shared
        manifest=self.fixture.full();manifest['local_node']['role']='database_voter';manifest['voters'][0]={'id':self.fixture.local['node_id'],'site':'Noida','ip':self.fixture.local['node_ip']}
        self.manager.configure({'expected_revision':0,'configuration':manifest});self.shared['states'].update(database='running',etcd='running')
        self.calls=[]
        def helper(request):
            self.calls.append(request);binding=request['binding'];fingerprint=n.digest(binding);targets={kind:'prthak_restore_'+binding['restore_id']+'_'+kind for kind in ('metadata','traffic')};common={'database_names':targets,'binding_digest':fingerprint}
            if self.shared.get('helper_fail'):raise n.Blocked('injected fixed helper failure')
            if request['action']=='inspect':return {**common,'targets_absent':True,'source_fenced':True,'owners_verified':True}
            if request['action']=='create':
                if self.shared.get('not_primary'):return {'not_primary':True,'mutated':False}
                return {**common,'created':True,'empty':True,'owners_verified':True,'not_primary':False}
            return {**common,'phase':'verified','verified':True,'marker_verified':True,'new_connections':True,'namespace_markers':{kind:{'deployment_id':binding['deployment_id'],'epoch':binding['target_epoch'],'namespace':kind,'state':'VERIFIED'} for kind in ('metadata','traffic')}}
        self.manager.engine.restore_database_helper=helper
        self.request={'restore_id':'a'*32,'expected_revision':1,'deployment_id':manifest['deployment_id'],'archive_sha256':'b'*64,'target_epoch':2,'fence_digest':'c'*64,'all_writers_fenced':True}
    def phase(self,name,**extra):return self.manager.restore_databases({**self.request,'phase':name,**extra})
    def test_exact_derived_empty_targets_phase_order_owner_and_profile_ack_gates(self):
        with self.assertRaises(n.Blocked):self.phase('create')
        prepared=self.phase('prepare');self.assertTrue(prepared['prepared']);self.assertTrue(prepared['hba_reloaded'])
        self.assertEqual(prepared['database_names']['metadata'],'prthak_restore_'+'a'*32+'_metadata')
        self.assertEqual(self.manager.manifest()['database']['metadata_name'],'prthak_metadata')
        self.phase('create');self.phase('verify')
        with self.assertRaises(n.Blocked):self.phase('finalize')
        result=self.phase('finalize',all_profile_acks=True);self.assertTrue(result['finalized']);self.assertTrue(result['original_databases_preserved'])
        self.assertEqual(self.manager.manifest()['database']['metadata_name'],prepared['database_names']['metadata'])
        self.assertEqual(self.manager.state()['restore_epoch'],2)
        configuration=n.load(self.root/'config/database/patroni.json')
        self.assertTrue(any('prthak_metadata ' in rule for rule in configuration['postgresql']['pg_hba']))
        self.assertTrue(any(prepared['database_names']['metadata'] in rule for rule in configuration['postgresql']['pg_hba']))
        count=len(self.calls);self.phase('finalize',all_profile_acks=True);self.assertEqual(len(self.calls),count)
    def test_untrusted_paths_names_sql_unfenced_and_rebound_requests_block(self):
        for fields in ({'all_writers_fenced':False},{'target_epoch':True},{'sql':'DROP DATABASE postgres'},{'path':'/etc/shadow'},{'metadata_name':'postgres'}):
            with self.subTest(fields=fields),self.assertRaises(n.Blocked):self.phase('prepare',**fields)
        self.phase('prepare')
        for fields in ({'archive_sha256':'d'*64},{'target_epoch':3},{'restore_id':'e'*32}):
            with self.subTest(fields=fields),self.assertRaises(n.Blocked):self.phase('create',**fields)
        self.assertFalse(any(call['action']=='create' for call in self.calls))
    def test_nonprimary_retry_and_create_reply_retry_never_repeat_sql_after_import(self):
        self.phase('prepare');self.shared['not_primary']=True;self.assertTrue(self.phase('create')['not_primary'])
        self.shared['not_primary']=False;self.phase('create');count=len(self.calls)
        self.phase('create');self.assertEqual(len(self.calls),count)
        self.phase('verify');self.phase('create');self.assertEqual(len(self.calls),count+1)
    def test_interrupted_prepare_resumes_and_blocks_other_mutations_without_overwrite(self):
        original=self.manager.manifest();self.phase('prepare')
        self.shared['helper_fail']=True
        with self.assertRaises(n.Blocked):self.phase('create')
        self.assertEqual(self.manager.manifest(),original)
        with self.assertRaises(n.Blocked):self.manager.operate('stop','all')
        with self.assertRaises(n.Blocked):self.manager.storage_review({'data_root':str(self.fixture.parent/'new')})
        self.shared['helper_fail']=False;self.phase('create');self.assertEqual(n.load(self.root/'manager/restore-databases.json')['phase'],'created')
        self.assertTrue(self.calls[-1]['allow_empty_recovery'])


if __name__=='__main__':unittest.main()
