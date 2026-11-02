"""Actual private IPv6 TLS sockets, enrollment and listener-role isolation."""
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
import threading
import time
import unittest

from controller.listener_address import split_listener, format_listener


class ListenerAddressTests(unittest.TestCase):
    def test_native_addresses_are_normalized_without_double_brackets(self):
        for text, expected in [('127.0.0.1:8787',('127.0.0.1',8787)),('[::1]:8787',('::1',8787)),('::1:8787',('::1',8787)),('[2001:DB8::1]:443',('2001:db8::1',443)),('localhost:8787',('localhost',8787))]:
            self.assertEqual(split_listener(text),expected)
        self.assertEqual(format_listener('[::1]',8787),'[::1]:8787')
        from controller.application_port import _listen
        self.assertEqual(_listen('::1:8787'),('[::1]',8787))

    def test_malformed_ambiguous_or_scoped_listeners_are_refused(self):
        for text in ('[127.0.0.1]:8787','[::1:8787','[::1]]:8787','[fe80::1%eth0]:8787','[::ffff:127.0.0.1]:8787','localhost:0','localhost:65536','localhost:１２','localhost/path:8787','localhost :8787'):
            with self.subTest(value=text),self.assertRaises(ValueError):split_listener(text)


class IPv6TransportTests(unittest.TestCase):
    def setUp(self):
        try:
            probe=socket.socket(socket.AF_INET6);probe.bind(('::1',0));probe.close()
        except OSError:self.skipTest('IPv6 loopback is unavailable on this validation host')

    def test_stdlib_listener_accepts_bracketed_ipv6_without_changing_ipv4_default(self):
        from controller.app import App,Server
        from controller.store import Store
        with tempfile.TemporaryDirectory(prefix='prthak-ipv6-http-') as directory:
            app=App(Store(directory),demo=True)
            server=Server(('[::1]',0),app);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
            try:
                self.assertEqual(server.address_family,socket.AF_INET6)
                connection=http.client.HTTPConnection('::1',server.server_address[1],timeout=5)
                try:connection.request('GET','/healthz');response=connection.getresponse();self.assertEqual(response.status,200);response.read()
                finally:connection.close()
            finally:server.shutdown();server.server_close();thread.join(timeout=5)

    def test_production_ipv6_mtls_enrollment_and_three_port_isolation(self):
        from controller.pki import init_ca
        from controller.store import Store
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes,serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID
        with tempfile.TemporaryDirectory(prefix='prthak-ipv6-tls-') as directory:
            root=Path(directory);pki=init_ca(root/'pki');state=root/'state';token=Store(state).create_token('IPv6 test','test')['token']
            held=[]
            try:
                for _ in range(3):
                    probe=socket.socket(socket.AF_INET6);probe.bind(('::1',0));held.append(probe)
                management,control,discovery=[probe.getsockname()[1] for probe in held]
            finally:
                for probe in held:probe.close()
            environment={k:v for k,v in os.environ.items() if not k.startswith(('SEG_','PRTHAK_'))}
            secret=secrets.token_urlsafe(40)
            environment.update(SEG_SUPER_ADMIN_TOKEN=secret,PRTHAK_SUPERVISED_CHILD='1',PRTHAK_CONTROLLER_ORIGIN=f'https://[::1]:{management}')
            arguments=[sys.executable,'-m','controller','--listen',f'[::1]:{management}','--control-listen',f'[::1]:{control}','--discovery-listen',f'[::1]:{discovery}','--data-dir',str(state),'--cert',str(pki/'controller.pem'),'--key',str(pki/'controller-key.pem'),'--ca',str(pki/'ca.pem'),'--ca-key',str(pki/'ca-key.pem'),'--http-threads','4']
            context=ssl.create_default_context(cafile=str(pki/'ca.pem'))
            def request(port,method,path,body=None,tls=context,headers=None):
                client=http.client.HTTPSConnection('::1',port,context=tls,timeout=5)
                try:
                    client.request(method,path,None if body is None else json.dumps(body),{'Content-Type':'application/json',**(headers or {})})
                    response=client.getresponse();raw=response.read();return response.status,json.loads(raw) if raw else {}
                finally:client.close()
            with (root/'controller.log').open('w+') as log:
                process=subprocess.Popen(arguments,cwd=Path(__file__).resolve().parents[1],env=environment,stdout=log,stderr=log)
                try:
                    deadline=time.monotonic()+20
                    while True:
                        try:
                            if request(management,'GET','/healthz')[0]==200:break
                        except (OSError,http.client.HTTPException):pass
                        if process.poll() is not None or time.monotonic()>deadline:
                            log.seek(0);self.fail('Private IPv6 controller failed to start: '+log.read()[-1800:])
                        time.sleep(.05)
                    status,config=request(management,'GET','/api/v1/auth/config');self.assertEqual(status,200)
                    self.assertEqual(config['agent_channels']['control_url'],f'https://[::1]:{control}')
                    self.assertEqual(request(control,'GET','/api/v1/auth/config',headers={'Authorization':'Bearer '+secret})[0],404)
                    self.assertEqual(request(management,'GET','/api/v1/agent/policy',headers={'X-Prthak-Channel':'control','Host':f'[::1]:{control}'})[0],404)
                    self.assertEqual(request(control,'GET','/api/v1/agent/policy')[0],403)
                    key=ec.generate_private_key(ec.SECP256R1())
                    csr=x509.CertificateSigningRequestBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'ipv6-agent')])).sign(key,hashes.SHA256())
                    code,enrolled=request(discovery,'POST','/api/v1/agent/enroll',{'token':token,'hostname':'ipv6-agent','csr':csr.public_bytes(serialization.Encoding.PEM).decode()});self.assertEqual(code,201,enrolled)
                    certificate=root/'agent.crt';private=root/'agent.key';certificate.write_text(enrolled['certificate']);private.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()));private.chmod(0o600)
                    endpoint=ssl.create_default_context(cafile=str(pki/'ca.pem'));endpoint.load_cert_chain(certificate,private)
                    self.assertEqual(request(control,'GET','/api/v1/agent/policy',tls=endpoint)[0],200)
                    self.assertEqual(request(discovery,'GET','/api/v1/agent/policy',tls=endpoint)[0],404)
                    self.assertEqual(request(discovery,'POST','/api/v1/agent/report',{'hostname':'ipv6-agent','ips':['2001:db8::41'],'listeners':[],'firewalld_state':'running'},tls=endpoint)[0],200)
                finally:
                    process.terminate()
                    try:process.wait(timeout=10)
                    except subprocess.TimeoutExpired:process.kill();process.wait(timeout=5)
