"""Real EntraConfig validation and private importer; no Microsoft requests."""
import importlib.util
import json
import os
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).parent))
import test_appliance_installer as baseline
n=baseline.appliance
spec=importlib.util.spec_from_file_location('auth_entrypoint',Path(__file__).resolve().parents[1]/'deploy/appliance/controller_entrypoint.py');entrypoint=importlib.util.module_from_spec(spec);spec.loader.exec_module(entrypoint)


class InitialApplianceAuthTests(unittest.TestCase):
    def setUp(self):
        baseline.ApplianceManagerTests.setUpClass();self.fixture=baseline.ApplianceManagerTests();self.fixture.setUp();self.addCleanup(self.fixture.doCleanups);self.root=self.fixture.root
        self.values={'SEG_ENTRA_TENANT_ID':'11111111-1111-4111-8111-111111111111','SEG_ENTRA_CLIENT_ID':'22222222-2222-4222-8222-222222222222','SEG_ENTRA_REDIRECT_URI':'https://controller.example/api/v1/auth/callback','SEG_BOOTSTRAP_SUPER_ADMIN_OID':'33333333-3333-4333-8333-333333333333','SEG_ENTRA_CLIENT_SECRET':'private-test-client-secret','SEG_HTTP_WORKERS':'2','SEG_HTTP_THREADS':'32'}
        class Engine:
            def validate_initial_environment(self,payload):return entrypoint.validate_initial_environment(payload)
        self.engine=Engine()
    def test_real_config_validated_secret_is_file_only_and_runtime_auto_unset(self):
        public=n.stage_initial_environment(self.engine,self.root,self.values)
        path=self.root/'config/controller/entra-client-secret';self.assertEqual(path.read_text().strip(),self.values['SEG_ENTRA_CLIENT_SECRET']);self.assertEqual(path.stat().st_mode&0o777,0o600)
        self.assertEqual(public['SEG_ENTRA_CLIENT_SECRET_FILE'],'/run/prthak-bootstrap/entra-client-secret');self.assertNotIn('SEG_ENTRA_CLIENT_SECRET',public);self.assertNotIn(self.values['SEG_ENTRA_CLIENT_SECRET'],json.dumps(public))
        self.assertEqual(entrypoint.validate_initial_environment({})['environment'],{})
    def test_partial_bad_guid_http_callback_or_counts_rejected_before_secret_file(self):
        for fields in ({'SEG_ENTRA_CLIENT_ID':'bad'},{'SEG_ENTRA_REDIRECT_URI':'http://controller.example/api/v1/auth/callback'},{'SEG_HTTP_WORKERS':'17'},{'SEG_HTTP_THREADS':'1'},{'SEG_ENTRA_CLIENT_SECRET':''}):
            with self.subTest(fields=fields),self.assertRaises(ValueError):n.stage_initial_environment(self.engine,self.root,{**self.values,**fields})
        self.assertFalse((self.root/'config/controller/entra-client-secret').exists())
    def test_owned_private_file_import_and_public_symlink_or_dual_source_refused(self):
        source=self.fixture.parent/'entra-source';source.write_text('file-only-private-test-secret\n');source.chmod(0o600);values={**self.values,'SEG_ENTRA_CLIENT_SECRET':'','SEG_ENTRA_CLIENT_SECRET_FILE':str(source)}
        public=n.stage_initial_environment(self.engine,self.root,values);self.assertNotIn(str(source),json.dumps(public))
        source.chmod(0o644)
        with self.assertRaises(n.Blocked):n.initial_environment(values)
        source.chmod(0o600);link=self.fixture.parent/'link';link.symlink_to(source)
        with self.assertRaises(n.Blocked):n.initial_environment({**values,'SEG_ENTRA_CLIENT_SECRET_FILE':str(link)})
        with self.assertRaises(n.Blocked):n.initial_environment({**values,'SEG_ENTRA_CLIENT_SECRET':'another'})
        fifo=self.fixture.parent/'not-a-secret-file';os.mkfifo(fifo,0o600)
        with self.assertRaises(n.Blocked):n.initial_environment({**values,'SEG_ENTRA_CLIENT_SECRET_FILE':str(fifo)})
    def test_reinstall_preserves_private_config_and_refuses_unreviewed_rotation(self):
        public=n.stage_initial_environment(self.engine,self.root,self.values);existing={'environment':public};path=self.root/'config/controller/entra-client-secret';before=path.read_bytes()
        self.assertEqual(n.stage_initial_environment(self.engine,self.root,{},existing),public)
        self.assertEqual(n.stage_initial_environment(self.engine,self.root,self.values,existing),public)
        for fields in ({'SEG_ENTRA_CLIENT_SECRET':'different-private-secret'},{'SEG_HTTP_WORKERS':'3'},{'SEG_ENTRA_CLIENT_ID':'44444444-4444-4444-8444-444444444444'}):
            with self.subTest(fields=fields),self.assertRaises(n.Blocked):n.stage_initial_environment(self.engine,self.root,fields,existing)
        self.assertEqual(path.read_bytes(),before)
    def test_env_allowlist_recognizes_only_the_fixed_initial_keys(self):
        source=self.fixture.parent/'private.env';source.write_text('\n'.join(key+'='+value for key,value in self.values.items()));source.chmod(0o600)
        self.assertEqual(n.read_env(source),self.values)
        with source.open('a') as output:output.write('\nSEG_EXEC_COMMAND=id\n')
        with self.assertRaises(n.Blocked):n.read_env(source)
    def test_failed_first_install_resumes_only_exact_private_owned_identity(self):
        root=self.fixture.parent/'fresh';local=n.settings({'NODE_ID':'fresh','NODE_IP':'127.0.0.1','SUPER_ADMIN_TOKEN':'private-test-token-'*3,'CLUSTER_PASSWORD':'private-test-cluster-'*3})
        first=n.installation_identity(root,local);n.atomic(root/'runtime/build-state.json',{'stage':'validation_failed'})
        second=n.installation_identity(root,local);self.assertEqual(first['appliance_id'],second['appliance_id'])
        contents=(root/'config/install-pending.json').read_text();self.assertNotIn(local['super_admin_token'],contents);self.assertNotIn(local['cluster_password'],contents)
        with self.assertRaises(n.Blocked):n.installation_identity(root,{**local,'node_id':'foreign'})
        foreign=self.fixture.parent/'foreign';foreign.mkdir();(foreign/'must-retain').write_text('unmanaged')
        with self.assertRaises(n.Blocked):n.installation_identity(foreign,local)
        self.assertEqual((foreign/'must-retain').read_text(),'unmanaged')


if __name__=='__main__':unittest.main()
