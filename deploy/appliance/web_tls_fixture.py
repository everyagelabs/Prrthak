"""TEST ONLY: real TLS sockets + actual HAProxy with the fixed manager action.

The Engine transport controls only one in-container HAProxy process instead of
Docker Compose. No host sockets, mounts, ports or firewall privileges are used.
"""
from datetime import datetime,timedelta,timezone
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import signal
import ssl
import subprocess
import sys
import threading
import time
import uuid

from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID,ExtendedKeyUsageOID

sys.path.insert(0,'/opt/prthak');import node_manager as n


def material(label,name):
    now=datetime.now(timezone.utc);issuer_key=ec.generate_private_key(ec.SECP256R1());issuer=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,label)])
    ca=x509.CertificateBuilder().subject_name(issuer).issuer_name(issuer).public_key(issuer_key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=1)).not_valid_after(now+timedelta(days=1)).add_extension(x509.BasicConstraints(ca=True,path_length=None),True).add_extension(x509.KeyUsage(False,False,False,False,False,True,True,False,False),True).add_extension(x509.SubjectKeyIdentifier.from_public_key(issuer_key.public_key()),False).sign(issuer_key,hashes.SHA256())
    key=ec.generate_private_key(ec.SECP256R1());leaf=x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,name)])).issuer_name(issuer).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=1)).not_valid_after(now+timedelta(days=1)).add_extension(x509.BasicConstraints(ca=False,path_length=None),True).add_extension(x509.KeyUsage(True,False,False,False,False,False,False,False,False),True).add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),False).add_extension(x509.SubjectAlternativeName([x509.DNSName(name),x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]),False).add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()),False).sign(issuer_key,hashes.SHA256())
    return {'leaf':leaf.public_bytes(serialization.Encoding.PEM).decode(),'ca':ca.public_bytes(serialization.Encoding.PEM).decode(),'key':key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()).decode(),'name':name,'fingerprint':leaf.fingerprint(hashes.SHA256()).hex()}


def main():
    root=Path('/var/lib/prthak');old=material('Old endpoint issuer','old.prthak.test');new=material('Corporate web issuer','corp.prthak.test');bad=material('Candidate issuer','candidate.prthak.test')
    settings={'appliance_id':uuid.uuid4().hex,'node_id':'private-tls','site':'private','node_ip':'127.0.0.1','bind_ip':'127.0.0.1','controller_port':8787,'controller_backend_port':8786,'database_router_port':5433,'controller_origin':'https://127.0.0.1:8787'}
    n.atomic(root/'config/installed.json',settings);n.atomic(root/'config/controller/pki/ca.pem',old['ca'])
    desired={'schema_version':1,'deployment_id':str(uuid.uuid4()),'generation':1,'cluster_name':'private','controller_origin':settings['controller_origin'],'controller_tls_server_name':old['name'],'controller_ca':old['ca'],'local_node':{'id':settings['node_id'],'site':'private','ip':'127.0.0.1','role':'management'},'voters':[],'controller_members':[]}
    n.atomic(root/'config/desired.json',desired)
    active={'context':None,'ready':True};process={'router':None,'fail_after_start':False}
    class Backend(ThreadingHTTPServer):
        def get_request(self):
            connection,address=super().get_request()
            return active['context'].wrap_socket(connection,server_side=True),address
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*args):pass
        def do_GET(self):
            data=b'{"status":"ok"}';self.send_response(200 if active['ready'] else 503);self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
    def activate(value):
        n.atomic(root/'backend.pem',value['leaf']+value['ca']);n.atomic(root/'backend-key.pem',value['key'])
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(root/'backend.pem',root/'backend-key.pem');active['context']=context
    def stop():
        if process['router'] and process['router'].poll() is None:
            os.killpg(process['router'].pid,signal.SIGTERM);process['router'].wait(timeout=5)
    class Engine:
        def __init__(self,*args):pass
        def states(self):return {'router':'running'} if process['router'] and process['router'].poll() is None else {}
        def compose(self,arguments,timeout=180):
            assert 'database' not in arguments and 'etcd' not in arguments and 'controller' not in arguments
            path=root/'config/router/haproxy.cfg'
            n.atomic(path,path.read_text().replace('controller:8787','127.0.0.1:8786'),owner=10003)
            if arguments[0] in ('exec','run'):
                result=subprocess.run(['haproxy','-c','-f',str(path)],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
                if result.returncode:raise RuntimeError(result.stderr.decode())
            else:
                stop();process['router']=subprocess.Popen(['haproxy','-W','-db','-f',str(path)],start_new_session=True,stdout=open('/tmp/private-router.log','ab'),stderr=subprocess.STDOUT)
                if process['fail_after_start']:active['ready']=False
            return ''
    # Only this fixture maps the production /config path to its private directory.
    Path('/config').symlink_to(root/'config/router')
    manager=n.Manager(root,engine_factory=Engine);manager.render();activate(old)
    backend=Backend(('127.0.0.1',8786),Handler);threading.Thread(target=backend.serve_forever,daemon=True).start()
    try:
        manager.engine.compose(['up','-d','router']);time.sleep(1)
        activate(new)
        result=manager.web_tls({'certificate_chain':new['leaf']+new['ca'],'server_name':new['name'],'expected_revision':0})
        assert result['phase']=='web_tls_verified' and result['router_ready'] and result['fingerprint_sha256']==new['fingerprint']
        assert manager.web_tls({'certificate_chain':new['leaf']+new['ca'],'server_name':new['name'],'expected_revision':0})['already_applied']
        print('actual web-tls action: strict backend + real HAProxy corporate chain/name/ready/fingerprint and idempotent retry: PASS',flush=True)
        previous=(root/'config/router/haproxy.cfg').read_bytes();activate(bad);process['fail_after_start']=True
        try:manager.web_tls({'certificate_chain':bad['leaf']+bad['ca'],'server_name':bad['name'],'expected_revision':1})
        except n.Blocked:pass
        else:raise AssertionError('Routed readiness failure was falsely accepted')
        assert (root/'config/router/haproxy.cfg').read_bytes()==previous
        process['fail_after_start']=False;active['ready']=True;activate(old)
        # Old CA-issued bootstrap leaf only is valid using its retained issuer.
        restored=manager.web_tls({'certificate_chain':old['leaf'],'server_name':old['name'],'expected_revision':1})
        assert restored['router_ready'] and restored['fingerprint_sha256']==old['fingerprint']
        print('actual web-tls failure restores prior router files; old CA-issued leaf restore verifies retained issuer: PASS',flush=True)
    except Exception:
        print(Path('/tmp/private-router.log').read_text()[-3000:],flush=True)
        print('private transaction phase: '+str(n.load(root/'manager/web-tls-transaction.json',{}).get('phase')),flush=True)
        raise
    finally:stop();backend.shutdown();backend.server_close()


if __name__=='__main__':main()
