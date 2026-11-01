"""Real private HTTPS/mTLS; logging only, no endpoint firewall commands."""
import copy
import hashlib
import http.client
import json
from pathlib import Path
import ssl
import tempfile
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from controller.app import App
from controller.pki import Signer, init_ca
from controller.store import Store, stamp, now
from test_integration import running


class HitMonitorHTTPS(unittest.TestCase):
    def test_actual_mtls_lease_ingestion_and_readonly_views(self):
        with tempfile.TemporaryDirectory(prefix='prthak-hits-https-') as directory:
            root = Path(directory); store = Store(root/'state'); pki = init_ca(root)
            signer = Signer(pki/'ca.pem', pki/'ca-key.pem')
            tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            tls.load_cert_chain(pki/'controller.pem', pki/'controller-key.pem')
            tls.load_verify_locations(pki/'ca.pem'); tls.verify_mode = ssl.CERT_OPTIONAL
            browser = ssl.create_default_context(cafile=str(pki/'ca.pem'))
            app = App(store, signer=signer, tokens={'admin': 'private-admin', 'read_only': 'private-reader'})
            app.start_jobs = lambda: None
            with running(app, tls) as port:
                def request(method, path, body=None, token=None, context=browser):
                    connection = http.client.HTTPSConnection('localhost', port, context=context, timeout=10)
                    headers = {'Content-Type': 'application/json'}
                    if token: headers['Authorization'] = 'Bearer ' + token
                    try:
                        connection.request(method, '/api/v1/' + path, json.dumps(body) if body is not None else None, headers)
                        response = connection.getresponse(); raw = response.read()
                        return response.status, raw if 'csv' in response.getheader('Content-Type','') else json.loads(raw)
                    finally: connection.close()
                key = ec.generate_private_key(ec.SECP256R1())
                csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'hit-https')])).sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode()
                token = store.create_token('private HTTPS monitor fixture', 'test')['token']
                code, enrolled = request('POST', 'agent/enroll', {'hostname': 'hit-https', 'token': token, 'csr': csr})
                self.assertEqual(code, 201, enrolled)
                cert = root/'endpoint.pem'; private = root/'endpoint-key.pem'
                cert.write_text(enrolled['certificate']); cert.chmod(0o600)
                private.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())); private.chmod(0o600)
                endpoint = ssl.create_default_context(cafile=str(pki/'ca.pem')); endpoint.load_cert_chain(cert, private)
                code, _ = request('POST', 'agent/report', {'hostname': 'hit-https', 'ips': ['192.0.2.9'], 'listeners': [{'port': 22, 'protocol': 'tcp', 'service': 'SSH'}], 'firewalld_state': 'running', 'agent_version': '0.7.0', 'capabilities': ['signed_assignments_v1','port_hit_monitor_v1']}, context=endpoint)
                self.assertEqual(code, 200)
                body = {'name': 'SSH observations only', 'selection': {'server_ids': [enrolled['server_id']]}, 'ports': [{'port': 22, 'protocol': 'tcp'}], 'retention_hours': 1}
                self.assertEqual(request('POST','hit-monitors/preview',body,token='private-reader')[0],403)
                code, plan = request('POST','hit-monitors/preview',body,token='private-admin'); self.assertEqual(code,201,plan)
                confirmation = {'preview_id':plan['id'], **{field:plan[field] for field in ('digest','confirmation_nonce','confirmation_phrase')}}
                code, monitor = request('POST','hit-monitors/apply',confirmation,token='private-admin'); self.assertEqual(code,200,monitor)
                code, policy = request('GET','agent/policy',context=endpoint); self.assertEqual(code,200,policy)
                lease = policy['hit_monitors'][0]; self.assertIn('signature',policy)
                point = stamp(now())
                body = {'batch_id':'https-one','monitor_id':monitor['id'],'lease_starts_at':lease['starts_at'],'lease_expires_at':lease['expires_at'],'events':[{'event_id':hashlib.sha256(b'private-kernel-cursor').hexdigest(),'source_ip':'2001:db8::9','port':22,'protocol':'tcp','verdict':'observed','count':1,'first_seen':point,'last_seen':point}]}
                self.assertEqual(request('POST','agent/hits',body)[0],403)
                code,result=request('POST','agent/hits',body,context=endpoint); self.assertEqual(code,202,result)
                store.process_flows()
                code,result=request('GET',f'hit-monitors/{monitor["id"]}/hits',token='private-reader')
                self.assertEqual(code,200,result); self.assertEqual(result['items'][0]['source_ip'],'2001:db8::9')
                code,data=request('GET',f'hit-monitors/{monitor["id"]}/export.csv',token='private-reader')
                self.assertEqual(code,200); self.assertIn(b'2001:db8::9',data)
                code,plan=request('POST',f'hit-monitors/{monitor["id"]}/stop-preview',{'expected_revision':1},token='private-admin'); self.assertEqual(code,201,plan)
                confirmation={'preview_id':plan['id'],**{field:plan[field] for field in ('digest','confirmation_nonce','confirmation_phrase')}}
                self.assertEqual(request('POST','hit-monitors/apply',confirmation,token='private-admin')[0],200)
                self.assertEqual(request('GET','agent/policy',context=endpoint)[1]['hit_monitors'],[])
                with store.read_meta() as db:
                    self.assertEqual(db.execute('SELECT COUNT(*) FROM learning_allow_policies').fetchone()[0],0)
