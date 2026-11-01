"""Real Gunicorn/TLS sockets prove path isolation and endpoint certificate use."""
from datetime import timedelta
import http.client
import json
import os
from pathlib import Path
import secrets
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import unittest

ROOT=Path(__file__).resolve().parents[1]


class SeparatedListenerHTTPS(unittest.TestCase):
    def test_real_three_listener_enrollment_policy_and_discovery(self):
        try:
            import gunicorn
            from cryptography import x509
            from cryptography.hazmat.primitives import hashes,serialization
            from cryptography.hazmat.primitives.asymmetric import ec
            from cryptography.x509.oid import NameOID
        except ImportError:self.skipTest('Production transport dependencies required')
        from controller.pki import init_ca
        from controller.store import Store
        with tempfile.TemporaryDirectory(prefix='prthak-channels-') as directory:
            root=Path(directory);pki=init_ca(root);state=root/'state'
            token=Store(state).create_token('channel fixture','test')['token']
            sockets=[]
            try:
                for _ in range(3):
                    listener=socket.socket();listener.bind(('127.0.0.1',0));sockets.append(listener)
                management,control,discovery=[s.getsockname()[1] for s in sockets]
            finally:
                for listener in sockets:listener.close()
            environment={k:v for k,v in os.environ.items() if not k.startswith(('SEG_','PRTHAK_'))}
            secret=secrets.token_urlsafe(40)
            environment.update(SEG_SUPER_ADMIN_TOKEN=secret,PRTHAK_SUPERVISED_CHILD='1',
                               PRTHAK_CONTROLLER_ORIGIN=f'https://localhost:{management}')
            args=[sys.executable,'-m','controller','--listen',f'127.0.0.1:{management}',
                  '--control-listen',f'127.0.0.1:{control}','--discovery-listen',f'127.0.0.1:{discovery}',
                  '--data-dir',str(state),'--cert',str(pki/'controller.pem'),'--key',str(pki/'controller-key.pem'),
                  '--ca',str(pki/'ca.pem'),'--ca-key',str(pki/'ca-key.pem'),'--http-threads','4']
            context=ssl.create_default_context(cafile=str(pki/'ca.pem'))
            def request(port,method,path,body=None,authenticated=False,tls=context,extra=None):
                connection=http.client.HTTPSConnection('localhost',port,context=tls,timeout=5)
                headers={'Content-Type':'application/json',**(extra or {})}
                if authenticated:headers['Authorization']='Bearer '+secret
                try:
                    connection.request(method,path,json.dumps(body).encode() if body is not None else None,headers)
                    response=connection.getresponse();raw=response.read()
                    return response.status,json.loads(raw) if raw else {}
                finally:connection.close()
            with (root/'server.log').open('w+') as log:
                process=subprocess.Popen(args,cwd=ROOT,env=environment,stdout=log,stderr=log)
                try:
                    deadline=time.monotonic()+15
                    while True:
                        try:
                            if request(management,'GET','/healthz')[0]==200:break
                        except (OSError,http.client.HTTPException):pass
                        if time.monotonic()>deadline:
                            log.seek(0);self.fail('TLS fixture did not start: '+log.read()[-4000:])
                        time.sleep(.05)
                    for port in (control,discovery):
                        self.assertEqual(request(port,'GET','/api/v1/auth/config',authenticated=True)[0],404)
                        self.assertEqual(request(port,'GET','/servers',authenticated=True)[0],404)
                    status,config=request(management,'GET','/api/v1/auth/config')
                    self.assertEqual(status,200)
                    self.assertEqual(config['agent_channels']['control_url'],f'https://localhost:{control}')
                    self.assertEqual(request(management,'GET','/api/v1/agent/policy',extra={'X-Prthak-Channel':'control','Host':f'localhost:{control}'})[0],404)
                    self.assertEqual(request(control,'GET','/api/v1/agent/policy')[0],403)
                    key=ec.generate_private_key(ec.SECP256R1())
                    csr=x509.CertificateSigningRequestBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'channel-agent')])).sign(key,hashes.SHA256())
                    enrollment={'token':token,'hostname':'channel-agent','csr':csr.public_bytes(serialization.Encoding.PEM).decode()}
                    self.assertEqual(request(control,'POST','/api/v1/agent/enroll',enrollment)[0],404)
                    code,enrolled=request(discovery,'POST','/api/v1/agent/enroll',enrollment)
                    self.assertEqual(code,201,enrolled)
                    cert=root/'endpoint.pem';private=root/'endpoint-key.pem'
                    cert.write_text(enrolled['certificate']);cert.chmod(0o600)
                    private.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()));private.chmod(0o600)
                    endpoint=ssl.create_default_context(cafile=str(pki/'ca.pem'));endpoint.load_cert_chain(cert,private)
                    self.assertEqual(request(control,'GET','/api/v1/agent/policy',tls=endpoint)[0],200)
                    self.assertEqual(request(discovery,'GET','/api/v1/agent/policy',tls=endpoint)[0],404)
                    report={'hostname':'channel-agent','ips':['192.0.2.41'],'listeners':[],'firewalld_state':'running'}
                    self.assertEqual(request(control,'POST','/api/v1/agent/report',report,tls=endpoint)[0],404)
                    self.assertEqual(request(discovery,'POST','/api/v1/agent/report',report,tls=endpoint)[0],200)
                finally:
                    process.terminate()
                    try:process.wait(timeout=10)
                    except subprocess.TimeoutExpired:process.kill();process.wait(timeout=5)
