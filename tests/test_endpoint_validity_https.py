"""Leaf lifetime is enforced again on an already established mTLS connection."""
from datetime import timedelta
import http.client
import json
from pathlib import Path
import ssl
import tempfile
import time
import unittest
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

from controller.app import App
from controller import endpoint_certificates as lifecycle
from controller.pki import Signer, init_ca
from controller.store import Store, now
from test_integration import running


class EndpointLeafValidityHTTPS(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='prthak-leaf-validity-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.store = Store(self.root/'state')
        self.pki = init_ca(self.root)
        self.signer = Signer(self.pki/'ca.pem', self.pki/'ca-key.pem')
        self.identity = 'validity-https'
        self.store.report(self.identity, {'hostname': self.identity, 'ips':['10.40.0.1'], 'listeners':[]})

    def connection(self, short=False):
        key = ec.generate_private_key(ec.SECP256R1())
        ca = x509.load_pem_x509_certificate(self.signer.ca.read_bytes())
        ca_key = serialization.load_pem_private_key(self.signer.ca_key.read_bytes(), None)
        at = now()
        self.leaf = x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,self.identity)])).issuer_name(ca.subject).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(at-timedelta(seconds=10)).not_valid_after(at+timedelta(seconds=4) if short else at+timedelta(days=1)).add_extension(x509.BasicConstraints(ca=False,path_length=None),True).add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),False).sign(ca_key,hashes.SHA256())
        cert_path, key_path = self.root/'client.pem', self.root/'client-key.pem'
        cert_path.write_bytes(self.leaf.public_bytes(serialization.Encoding.PEM)); cert_path.chmod(0o600)
        key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()));key_path.chmod(0o600)
        with self.store.meta() as db:
            server=self.store._get(db,'servers',self.identity)
            lifecycle.record_issued(self.store,db,server,cert_path.read_text());self.store._put(db,'servers',server)
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(self.pki/'controller.pem',self.pki/'controller-key.pem')
        tls.load_verify_locations(self.pki/'ca.pem');tls.verify_mode=ssl.CERT_OPTIONAL
        manager=running(App(self.store,signer=self.signer),tls)
        port=manager.__enter__();self.addCleanup(manager.__exit__,None,None,None)
        client=ssl.create_default_context(cafile=str(self.pki/'ca.pem'));client.load_cert_chain(cert_path,key_path)
        connection=http.client.HTTPSConnection('localhost',port,context=client,timeout=10)
        self.addCleanup(connection.close)
        return connection

    def post_report(self, connection):
        connection.request('POST','/api/v1/agent/report',json.dumps({'hostname':self.identity,'ips':['10.40.0.1'],'listeners':[]}),{'Content-Type':'application/json'})
        response=connection.getresponse();body=response.read()
        return response.status,body

    def test_certificate_expiry_rejects_same_authenticated_socket(self):
        connection=self.connection(short=True)
        self.assertEqual(self.post_report(connection)[0],200)
        authenticated_socket=connection.sock
        self.assertIsNotNone(authenticated_socket)
        time.sleep(max(0,(self.leaf.not_valid_after_utc-now()).total_seconds())+.1)
        self.assertIs(connection.sock,authenticated_socket)
        status,body=self.post_report(connection)
        self.assertEqual(status,403,body)
        self.assertIn(b'expired or not yet valid',body)

    def test_not_before_is_rechecked_on_same_authenticated_socket(self):
        connection=self.connection()
        self.assertEqual(self.post_report(connection)[0],200)
        authenticated_socket=connection.sock
        with patch('controller.endpoint_certificates.now',return_value=self.leaf.not_valid_before_utc-timedelta(seconds=1)):
            self.assertIs(connection.sock,authenticated_socket)
            status,body=self.post_report(connection)
        self.assertEqual(status,403,body)
