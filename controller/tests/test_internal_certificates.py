import copy
from datetime import timedelta
import json
import subprocess
import sys
import unittest
from unittest.mock import patch

from controller import cluster_bootstrap as bootstrap
from controller import internal_certificates as lifecycle
from controller.store import now
from controller.tests.test_cluster_bootstrap import BootstrapFixture


class InternalCertificateAuthorityTests(BootstrapFixture,unittest.TestCase):
    def test_renews_before_expiry_once_with_same_key_and_immutable_history(self):
        first=bootstrap.manifest(self.api);before=self.api._config()['revision'];at=now()
        with patch('controller.internal_certificates.now',return_value=at+timedelta(days=59)),patch('controller.cluster_bootstrap.now',return_value=at+timedelta(days=59)):
            self.assertEqual(bootstrap.manifest(self.api)['pki']['certificate'],first['pki']['certificate'])
        self.assertEqual(self.api._config()['revision'],before)
        with patch('controller.internal_certificates.now',return_value=at+timedelta(days=61)),patch('controller.cluster_bootstrap.now',return_value=at+timedelta(days=61)):
            renewed=bootstrap.manifest(self.api);again=bootstrap.manifest(self.api)
        self.assertNotEqual(first['pki']['certificate'],renewed['pki']['certificate'])
        self.assertEqual(again['pki']['certificate'],renewed['pki']['certificate'])
        self.assertEqual(renewed['generation'],before+1)
        self.assertEqual(lifecycle.certificate_info(first['pki']['certificate'])['public_key_digest'],lifecycle.certificate_info(renewed['pki']['certificate'])['public_key_digest'])
        for certificate in (first['pki']['certificate'],renewed['pki']['certificate']):
            fingerprint=lifecycle.certificate_info(certificate)['fingerprint']
            self.assertIsNotNone(self.api.app.store.get('maintenance_settings','internal-cert-'+fingerprint))
    def test_exact_node_identity_and_both_tls_usages_validated(self):
        desired=bootstrap.manifest(self.api);certificate=desired['pki']['certificate'];identity=desired['local_node']
        request={'ca':desired['pki']['ca'],'certificate':certificate,'previous_certificate':certificate,'node_id':identity['id'],'node_ip':identity['ip']}
        self.assertEqual(lifecycle.validate_candidate(request)['fingerprint'],lifecycle.certificate_info(certificate)['fingerprint'])
        for key,value in (('node_ip','10.99.0.9'),('node_id','other-node'),('ca',self.api.app.signer.ca.read_text())):
            with self.subTest(key=key),self.assertRaises(ValueError):
                lifecycle.validate_candidate({**request,key:value})
    def test_suspension_blocks_password_resume_sync_and_renewal_without_fake_revocation(self):
        response,key,body=self.enroll();member_id=body['node_id']
        before=copy.deepcopy(self.api._config()['voters'])
        result=lifecycle.suspension(self.api,member_id,'super_admin')
        self.assertFalse(result['runtime_credentials_revoked']);self.assertTrue(result['requires_offline_recovery'])
        self.assertEqual(self.api._config()['voters'],before)
        with self.assertRaises(PermissionError):bootstrap.enroll(self.api,body,'192.0.2.9')
        with self.assertRaises(PermissionError):bootstrap.enroll(self.api,{'action':'node-sync','node_id':member_id,'site':body['site'],'node_ip':body['node_ip'],'sync_secret':response['sync_secret']},'192.0.2.9')
        member=next(item for item in self.api._config()['members'] if item['id']==member_id)
        with self.assertRaises(PermissionError):bootstrap._cached_certificate(self.api,bootstrap._material(self.api),member,key.public_key(),self.api._config()['controller_origin'])
        self.assertFalse(lifecycle.decommission_gate(self.api,member_id)['can_decommission'])
    def test_near_expiry_issuer_blocks_new_leaves_instead_of_silent_trust_replacement(self):
        bootstrap.manifest(self.api)
        original=now()
        with patch('controller.cluster_bootstrap.now',return_value=original+timedelta(days=3550)),patch('controller.internal_certificates.now',return_value=original+timedelta(days=3550)):
            with self.assertRaisesRegex(ValueError,'offline rotation'):bootstrap.manifest(self.api)
            current=lifecycle.status(self.api);self.assertFalse(current['issuer']['automatic_leaf_issuance_allowed']);self.assertTrue(current['issuer']['requires_offline_recovery']);self.assertFalse(current['nodes'][0]['renewal_allowed'])
    def test_pending_delivery_keeps_stable_operation_across_lost_or_queued_receipts(self):
        desired=bootstrap.manifest(self.api);target=lifecycle.certificate_info(desired['pki']['certificate'])['fingerprint']
        class Client:
            def __init__(self):self.requests=[];self.jobs={}
            def status(self):return {'revision':1,'cluster':{'configured':True},'capabilities':['internal_tls_v1'],'internal_tls':{'fingerprint':'a'*64}}
            def job(self,identifier):
                if identifier not in self.jobs:raise KeyError(identifier)
                return self.jobs[identifier]
            def submit(self,request):
                self.requests.append(request);self.jobs[request['request_id']]={'id':request['request_id'],'status':'queued'};return self.jobs[request['request_id']]
        self.api.client=Client()
        self.assertTrue(lifecycle.reconcile(self.api,desired));first=self.api._local()['internal_tls_operation']['id']
        self.assertTrue(lifecycle.reconcile(self.api,desired));self.assertEqual(first,self.api._local()['internal_tls_operation']['id'])
        self.assertEqual(len(self.api.client.requests),1)
        self.assertNotIn('private_key',json.dumps(self.api.client.requests))
        request=self.api.client.requests[0];self.api.client.jobs[request['request_id']]={'status':'completed','result':{'phase':'prepared','fingerprint':target,'prepared':True}}
        lifecycle.reconcile(self.api,desired);self.assertEqual(self.api._local()['internal_tls_operation']['phase'],'activate')
    def test_suspension_requires_fresh_exact_typed_review_and_replays_once(self):
        from controller.firewall import WorkflowConflict
        self.enroll();before=self.api._config()['revision']
        plan=lifecycle.suspension_preview(self.api,{'node_id':'node-2','expected_revision':before},'maker')
        body={'preview_id':plan['id'],**{key:plan[key] for key in ('digest','confirmation_nonce','confirmation_phrase')}}
        with self.assertRaises(WorkflowConflict):lifecycle.suspension_apply(self.api,{**body,'confirmation_phrase':'SUSPEND'},'checker')
        self.assertEqual(self.api._config()['revision'],before)
        result=lifecycle.suspension_apply(self.api,body,'checker');self.assertEqual(lifecycle.suspension_apply(self.api,body,'checker'),result)
        self.assertEqual(self.api._config()['revision'],before+1)
        manifest=bootstrap.manifest(self.api)
        self.assertNotIn('node-2',[member['id'] for member in manifest['controller_members']])
        self.assertIn('node-2',[member['id'] for member in manifest['voters']])
        summary=lifecycle.status(self.api);member=next(item for item in summary['nodes'] if item['id']=='node-2')
        self.assertFalse(member['renewal_allowed']);self.assertFalse(summary['cross_ca_live_rotation_supported']);self.assertNotIn('PRIVATE KEY',json.dumps(summary))
    def test_stale_review_and_last_identity_block_suspension(self):
        from controller.firewall import WorkflowConflict
        plan=lifecycle.suspension_preview(self.api,{'node_id':'node-1'},'maker');self.assertFalse(plan['can_apply'])
        self.enroll();plan=lifecycle.suspension_preview(self.api,{'node_id':'node-2'},'maker')
        body={'preview_id':plan['id'],**{key:plan[key] for key in ('digest','confirmation_nonce','confirmation_phrase')}}
        self.enroll(identifier='node-3',site='site-3',address='10.70.0.3')
        with self.assertRaises(WorkflowConflict):lifecycle.suspension_apply(self.api,body,'checker')
    def test_partial_commit_resumes_and_committed_fingerprint_publishes_receipt(self):
        from controller.platform import _private_json
        desired=bootstrap.manifest(self.api);target=lifecycle.certificate_info(desired['pki']['certificate'])['fingerprint']
        local=self.api._local();local['internal_tls_operation']={'id':'a'*32,'target':target,'certificate_pem':desired['pki']['certificate'],'generation':desired['generation'],'phase':'commit','attempt':0,'expected_fingerprint':'b'*64};_private_json(self.api.manager.root/'appliance-local.json',local)
        class Client:
            def __init__(self):self.phase='verified';self.requests=[]
            def status(self):return {'revision':0,'cluster':{'configured':True},'capabilities':['internal_tls_v1'],'internal_tls':{'fingerprint':target,'phase':self.phase,'runtime_verified':True}}
            def job(self,identifier):raise KeyError(identifier)
            def submit(self,request):self.requests.append(request);return {'status':'queued'}
        self.api.client=Client()
        self.assertTrue(lifecycle.reconcile(self.api,desired));self.assertEqual(self.api.client.requests[0]['phase'],'commit')
        self.api.client.phase='committed';self.assertFalse(lifecycle.reconcile(self.api,desired))
        receipt=self.api._config()['members'][0]['internal_tls_receipt'];self.assertEqual(receipt['fingerprint'],target);self.assertTrue(receipt['runtime_verified'])
        self.assertNotIn('internal_tls_operation',self.api._local())
    def test_old_manager_blocks_delivery_instead_of_silent_generic_trust_update(self):
        desired=bootstrap.manifest(self.api)
        self.api.client.status=lambda:{'revision':1,'cluster':{'configured':True}}
        self.assertTrue(lifecycle.reconcile(self.api,desired))
        self.assertIn('Upgrade',self.api._local()['internal_tls_error'])
    def _parallel_identity_reads(self):
        code='''
import hashlib,json,sys
from pathlib import Path
from types import SimpleNamespace
from controller.cluster_bootstrap import _material,_keys,_public_key
from controller.platform import Vault,_read_json
root=Path(sys.argv[1]);api=SimpleNamespace(manager=SimpleNamespace(root=root,vault=Vault(root/'vault')),app=SimpleNamespace(signer=SimpleNamespace(ca=Path(sys.argv[2]))),_local=lambda:_read_json(root/'appliance-local.json',{}),_config=lambda:{'bootstrap_seed_id':'node-1'},_identity=lambda:{'id':'node-1'})
value=_material(api)
print(json.dumps({'ca':hashlib.sha256(value['ca'].encode()).hexdigest(),'sync':hashlib.sha256(value['sync_key'].encode()).hexdigest(),'key':hashlib.sha256(_public_key(_keys(api)).encode()).hexdigest()}))
'''
        processes=[subprocess.Popen([sys.executable,'-c',code,str(self.api.manager.root),str(self.pki/'ca.pem')],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True) for _ in range(4)]
        try:
            values=[]
            for process in processes:
                output,error=process.communicate(timeout=15);self.assertEqual(process.returncode,0,error);values.append(json.loads(output))
            self.assertEqual(len({tuple(sorted(value.items())) for value in values}),1)
            return values[0]
        finally:
            for process in processes:
                if process.poll() is None:process.kill();process.wait()
    def test_first_material_and_node_key_are_single_identity_across_processes(self):
        (self.api.manager.root/'appliance-material.json').unlink(missing_ok=True);(self.api.manager.root/'appliance-node-key.json').unlink(missing_ok=True)
        values=self._parallel_identity_reads()
        import hashlib
        self.assertEqual(hashlib.sha256(bootstrap._material(self.api)['ca'].encode()).hexdigest(),values['ca'])
        self.assertEqual(hashlib.sha256(bootstrap._public_key(bootstrap._keys(self.api)).encode()).hexdigest(),values['key'])
    def test_legacy_sync_seed_creation_is_single_value_across_processes(self):
        material=bootstrap._material(self.api);material.pop('sync_key');bootstrap._save_material(self.api,material)
        values=self._parallel_identity_reads()
        import hashlib
        self.assertEqual(hashlib.sha256(bootstrap._material(self.api)['sync_key'].encode()).hexdigest(),values['sync'])
    def test_missing_material_after_authority_or_signing_evidence_never_regenerates(self):
        material=bootstrap._material(self.api);path=self.api.manager.root/'appliance-material.json';marker=self.api.manager.root/'appliance-authority.json';before=marker.read_bytes()
        path.unlink()
        with self.assertRaisesRegex(ValueError,'matching PKI/vault recovery'):bootstrap._material(self.api)
        self.assertFalse(path.exists());self.assertEqual(marker.read_bytes(),before)
        marker.unlink();seed=self.api.manager.root/'policy-signing'/'retained.seed';seed.parent.mkdir();seed.write_bytes(b'private-test-seed')
        with self.assertRaisesRegex(ValueError,'never a new CA'):bootstrap._material(self.api)
        self.assertFalse(path.exists())
    def test_missing_material_on_active_or_previously_issued_deployment_requires_recovery(self):
        path=self.api.manager.root/'appliance-material.json'
        with patch.object(self.api.manager,'active_profile',return_value={'deployment_id':'protected-existing'}):
            with self.assertRaisesRegex(ValueError,'Protected internal authority'):bootstrap._material(self.api)
        self.assertFalse(path.exists())
        bootstrap.manifest(self.api);path.unlink();(self.api.manager.root/'appliance-authority.json').unlink()
        with self.assertRaisesRegex(ValueError,'Protected internal authority'):bootstrap._material(self.api)
        self.assertFalse(path.exists())
        # Immutable issued history remains evidence even if an old configuration
        # snapshot lacks its current member cache and private cache files.
        with self.api.app.store.meta() as db:
            config=self.api._config(db)
            for member in config['members']:
                for key in ('node_certificate','certificate_binding','internal_certificate'):member.pop(key,None)
            self.api.app.store._put(db,'maintenance_settings',config)
        import shutil
        shutil.rmtree(self.api.manager.root/'node-certificates')
        with self.assertRaisesRegex(ValueError,'Protected internal authority'):bootstrap._material(self.api)
        self.assertFalse(path.exists())
        self.assertIn('reviewed recovery',lifecycle.status(self.api)['error'])
    def test_missing_registered_node_key_never_generates_replacement_identity(self):
        bootstrap.manifest(self.api);path=self.api.manager.root/'appliance-node-key.json';path.unlink()
        with self.assertRaisesRegex(ValueError,'restore its matching private key'):bootstrap._keys(self.api)
        self.assertFalse(path.exists())
        path.write_text('{}')
        with self.assertRaisesRegex(ValueError,'pointer is invalid'):bootstrap._keys(self.api)
        self.assertEqual(path.read_text(),'{}')


if __name__=='__main__':unittest.main()
