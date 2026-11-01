"""Fixed same-CA node lifecycle tests; no host services or sockets are used."""
from datetime import datetime,timedelta,timezone
import importlib.util
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).parent))
import test_appliance_installer as base_tests
appliance=base_tests.appliance
from controller import internal_certificates as lifecycle


class InternalTLSManagerTests(unittest.TestCase):
    def setUp(self):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes,serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID,ExtendedKeyUsageOID
        base_tests.ApplianceManagerTests.setUpClass();self.fixture=base_tests.ApplianceManagerTests();self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        self.manager=self.fixture.manager;self.root=self.fixture.root;self.shared=self.fixture.shared
        self.x509=x509;self.hashes=hashes;self.serialization=serialization;self.key=ec.generate_private_key(ec.SECP256R1());self.now=datetime.now(timezone.utc)
        issuer_key=ec.generate_private_key(ec.SECP256R1());issuer=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'Private lifecycle test CA')])
        ca=x509.CertificateBuilder().subject_name(issuer).issuer_name(issuer).public_key(issuer_key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(self.now-timedelta(days=1)).not_valid_after(self.now+timedelta(days=3650)).add_extension(x509.BasicConstraints(ca=True,path_length=None),True).sign(issuer_key,hashes.SHA256())
        def leaf(expiry):
            certificate=x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,self.fixture.local['node_id'])])).issuer_name(issuer).public_key(self.key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(self.now-timedelta(days=30)).not_valid_after(expiry).add_extension(x509.BasicConstraints(ca=False,path_length=None),True).add_extension(x509.SubjectAlternativeName([x509.DNSName(self.fixture.local['node_id']),x509.DNSName('localhost'),x509.DNSName('router'),x509.IPAddress(__import__('ipaddress').ip_address(self.fixture.local['node_ip'])),x509.IPAddress(__import__('ipaddress').ip_address('127.0.0.1'))]),False).add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH,ExtendedKeyUsageOID.SERVER_AUTH]),False).sign(issuer_key,hashes.SHA256())
            return certificate.public_bytes(serialization.Encoding.PEM).decode()
        self.leaf=leaf;self.old=leaf(self.now+timedelta(days=5));self.new=leaf(self.now+timedelta(days=90))
        manifest=self.fixture.full();manifest['local_node']['role']='database_voter';manifest['voters'][0]={'id':self.fixture.local['node_id'],'site':'Noida','ip':self.fixture.local['node_ip']};manifest['pki']={'ca':ca.public_bytes(serialization.Encoding.PEM).decode(),'certificate':self.old,'private_key':self.key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()).decode()}
        self.manager.configure({'expected_revision':0,'configuration':manifest})
        self.shared['states'].update(database='running',etcd='running')
        self.manager.engine.internal_tls_validate=lifecycle.validate_candidate
        self.probes=[]
        def probe(service,ports,directory,hostname,fingerprint):
            self.probes.append((service,list(ports),hostname,fingerprint))
            if self.shared.get('fail_new') and fingerprint==self.manager._leaf_fingerprint(self.new):raise appliance.Blocked('injected candidate read-back failure')
            if self.shared.get('fail_all'):raise appliance.Blocked('injected all read-back failure')
            return {'verified':True,'ports':ports,'fingerprint':fingerprint}
        self.manager.engine.internal_tls_probe=probe
        self.request={'operation_id':'1'*32,'phase':'prepare','expected_revision':1,'expected_fingerprint':self.manager._leaf_fingerprint(self.old),'certificate_pem':self.new,'generation':2}
    def phase(self,value,**extra):return self.manager.internal_tls({**self.request,'phase':value,**extra})
    def test_prepare_is_read_only_and_commit_requires_fresh_every_service_fingerprint(self):
        self.assertTrue(self.phase('prepare')['prepared'])
        self.assertEqual((self.root/'config/database/node.pem').read_text(),self.old)
        with self.assertRaises(appliance.Blocked):self.phase('commit')
        self.phase('activate');self.assertEqual((self.root/'config/database/node.pem').read_text(),self.new)
        self.assertTrue(self.manager.status()['internal_tls']['drift'])
        verified=self.phase('verify');self.assertEqual(sorted(verified['ports']),[2379,2380,5432,8008])
        self.assertTrue(verified['runtime_verified']);self.phase('commit')
        self.assertEqual(self.manager.manifest()['pki']['certificate'],self.new);self.assertFalse(self.manager.status()['internal_tls']['drift'])
        revision=self.manager.state()['revision'];self.phase('commit');self.assertEqual(self.manager.state()['revision'],revision)
        self.assertTrue(any(call[:3]==['kill','--signal','SIGHUP'] for call in self.shared['calls']))
        self.assertFalse(any(call[0]=='restart' or 'reload' in call and 'firewalld' in call for call in self.shared['calls']))
    def test_bad_candidate_wrong_identity_and_ordinary_ca_replacement_fail_before_writes(self):
        with self.assertRaises(ValueError):self.phase('prepare',certificate_pem=self.fixture.pki['certificate'])
        self.assertEqual((self.root/'config/database/node.pem').read_text(),self.old)
        changed=self.manager.manifest();changed['generation']=2;changed['pki']['ca']=self.fixture.pki['ca']
        with self.assertRaisesRegex(appliance.Blocked,'offline recovery'):self.manager.configure({'expected_revision':1,'configuration':changed})
    def test_failed_candidate_proof_automatically_restores_previous_valid_identity(self):
        self.phase('prepare');self.phase('activate');self.shared['fail_new']=True
        with patch.object(appliance.time,'sleep'):
            with self.assertRaisesRegex(appliance.Blocked,'previous valid'):self.phase('verify')
        self.assertEqual((self.root/'config/database/node.pem').read_text(),self.old)
        self.assertEqual(appliance.load(self.root/'manager/internal-tls.json')['phase'],'rolled_back')
        self.assertEqual(self.manager.manifest()['pki']['certificate'],self.old)
    def test_expired_previous_identity_is_never_reintroduced_after_failure(self):
        expired=self.leaf(self.now-timedelta(days=1));manifest=self.manager.manifest();manifest['pki']['certificate']=expired
        appliance.atomic(self.root/'config/manifest.json',manifest);self.manager._internal_files(expired)
        self.request['expected_fingerprint']=self.manager._leaf_fingerprint(expired)
        self.phase('prepare');self.phase('activate');self.shared['fail_new']=True
        with patch.object(appliance.time,'sleep'):
            with self.assertRaisesRegex(appliance.Blocked,'retained'):self.phase('verify')
        self.assertEqual((self.root/'config/database/node.pem').read_text(),self.new)
        self.assertEqual(appliance.load(self.root/'manager/internal-tls.json')['phase'],'rollforward_pending')
        self.assertTrue(self.phase('abort')['requires_rollforward'])
        self.shared['fail_new']=False;self.phase('activate');self.phase('verify');self.phase('commit')
        self.assertEqual(self.manager.manifest()['pki']['certificate'],self.new)
    def test_pending_transaction_fences_other_changes_and_stopped_services_are_not_started(self):
        self.phase('prepare')
        with self.assertRaisesRegex(appliance.Blocked,'staged internal'):self.manager.operate('start','database')
        with self.assertRaises(appliance.Blocked):self.manager.storage_review({'data_root':str(self.fixture.parent/'next')})
        self.shared['states'].update(database='exited',etcd='exited',router='exited')
        self.phase('activate');verified=self.phase('verify');self.assertFalse(verified['runtime_verified'])
        self.phase('commit');self.assertEqual(self.shared['states']['database'],'exited')
    def test_same_key_candidate_and_operation_are_pinned_against_replay(self):
        self.phase('prepare')
        with self.assertRaises(appliance.Blocked):self.phase('activate',generation=3)
        with self.assertRaises(appliance.Blocked):self.phase('prepare',operation_id='2'*32)
        self.assertEqual(self.phase('abort')['phase'],'aborted')
        with self.assertRaises(appliance.Blocked):self.phase('activate')


if __name__=='__main__':unittest.main()
