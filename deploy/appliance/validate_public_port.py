#!/usr/bin/env python3
"""Actual Compose publication proof on task-owned loopback ports/named volumes.

Only the fixture filesystem chown calls are adapted for a nonroot test host.
The real manager journal, Docker Compose recreation and strict routed TLS/ready
fingerprint checks execute. The backend is a TLS readiness fixture, not a full
controller authentication/cluster test. No host directory/socket mounts exist.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import uuid
from unittest.mock import patch


GENERATOR=r'''
from pathlib import Path
from datetime import datetime,timedelta,timezone
import json,os
from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID,ExtendedKeyUsageOID
root=Path('/fixture');at=datetime.now(timezone.utc);key=ec.generate_private_key(ec.SECP256R1());subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'Private port fixture CA')])
ca=x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(at-timedelta(minutes=1)).not_valid_after(at+timedelta(days=1)).add_extension(x509.BasicConstraints(ca=True,path_length=None),True).sign(key,hashes.SHA256())
leafkey=ec.generate_private_key(ec.SECP256R1());leaf=x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'localhost')])).issuer_name(subject).public_key(leafkey.public_key()).serial_number(x509.random_serial_number()).not_valid_before(at-timedelta(minutes=1)).not_valid_after(at+timedelta(days=1)).add_extension(x509.BasicConstraints(ca=False,path_length=None),True).add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost')]),False).add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),False).sign(key,hashes.SHA256())
directory=root/'backend';directory.mkdir(mode=0o700);os.chown(directory,10001,10001)
for name,value in [('chain.pem',leaf.public_bytes(serialization.Encoding.PEM)+ca.public_bytes(serialization.Encoding.PEM)),('key.pem',leafkey.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))]:
 path=directory/name;path.write_bytes(value);path.chmod(0o600);os.chown(path,10001,10001)
print(json.dumps({'ca':ca.public_bytes(serialization.Encoding.PEM).decode(),'fingerprint':leaf.fingerprint(hashes.SHA256()).hex()}))
'''
BACKEND=r'''
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import ssl
class H(BaseHTTPRequestHandler):
 def log_message(self,*args):pass
 def do_GET(self):
  data=b'{"status":"ready"}';self.send_response(200);self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
server=ThreadingHTTPServer(('0.0.0.0',8787),H);context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain('/tls/chain.pem','/tls/key.pem');server.socket=context.wrap_socket(server.socket,server_side=True);server.serve_forever()
'''
WRITER=r'''
import json,os,sys
from pathlib import Path
root=Path('/fixture/router');root.mkdir(exist_ok=True,mode=0o700);os.chown(root,10003,10003)
for name,value in json.load(sys.stdin).items():
 assert name in ('haproxy.cfg','controller-ca.pem');path=root/name;path.write_text(value);path.chmod(0o600);os.chown(path,10003,10003)
'''


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--context',required=True);parser.add_argument('--image',default='prthak-appliance-controller-test');args=parser.parse_args()
    source=Path(__file__).with_name('node_manager.py');spec=importlib.util.spec_from_file_location('fixed_port_manager',source);n=importlib.util.module_from_spec(spec);spec.loader.exec_module(n)
    prefix='prthak-port-smoke-'+uuid.uuid4().hex[:10];volume=prefix+'-state'
    def docker(values,input=None):
        result=subprocess.run(['docker','--context',args.context,*values],input=input,text=True,capture_output=True,timeout=120)
        if result.returncode:raise RuntimeError('Private fixed Compose fixture failed: '+result.stderr[-1500:])
        return result.stdout
    sockets=[]
    try:
        for _ in range(4):
            probe=socket.socket();probe.bind(('127.0.0.1',0));sockets.append(probe)
        old,new,bad,db=[probe.getsockname()[1] for probe in sockets]
    finally:
        for probe in sockets:probe.close()
    docker(['volume','create',volume]);manager=None;project=None
    try:
        public=json.loads(docker(['run','--rm','--network','none','--user','0','--cap-drop','ALL','--cap-add','CHOWN','--cap-add','DAC_OVERRIDE','--security-opt','no-new-privileges:true','--mount','type=volume,source='+volume+',target=/fixture','--entrypoint','python3','-i',args.image,'-'],GENERATOR))
        assert 'PRIVATE KEY' not in json.dumps(public)
        with tempfile.TemporaryDirectory(prefix='prthak-public-port-') as temporary,patch.object(n.os,'chown'),patch.object(n.os,'fchown'):
            root=Path(temporary).resolve()/'owned';local={'appliance_id':uuid.uuid4().hex,'node_id':prefix,'site':'private','node_ip':'127.0.0.1','bind_ip':'127.0.0.1','controller_port':old,'controller_backend_port':8786,'database_router_port':db,'controller_origin':'https://localhost:'+str(old)}
            n.atomic(root/'config/installed.json',local);n.atomic(root/'config/controller/pki/ca.pem',public['ca']);n.atomic(root/'config/desired.json',{'controller_origin':local['controller_origin'],'controller_tls_server_name':'localhost','controller_members':[]})
            class Engine(n.Engine):
                def __init__(self,root,project):super().__init__(root,project,docker=('docker','--context',args.context))
            manager=n.Manager(root,engine_factory=Engine,allowed_parent=Path(temporary).resolve());project=manager.project;manager.render()
            docker(['run','--rm','--network','none','--user','0','--cap-drop','ALL','--cap-add','CHOWN','--cap-add','DAC_OVERRIDE','--security-opt','no-new-privileges:true','--mount','type=volume,source='+volume+',target=/fixture','--entrypoint','python3','-i',args.image,'-c',WRITER],json.dumps({name:(root/'config/router'/name).read_text() for name in ('haproxy.cfg','controller-ca.pem')}))
            compose=n.load(root/'runtime/compose.json');compose['services']={key:value for key,value in compose['services'].items() if key in ('controller','router')}
            compose['volumes']={'private':{'external':True,'name':volume}}
            compose['services']['controller'].update(image=args.image,entrypoint=['python3','-c',BACKEND],volumes=[{'type':'volume','source':'private','target':'/tls','read_only':True,'volume':{'subpath':'backend'}}],ports=[])
            compose['services']['router']['volumes']=[{'type':'volume','source':'private','target':'/config','read_only':True,'volume':{'subpath':'router'}}]
            n.atomic(root/'runtime/compose.json',compose);manager.engine.compose(['up','-d','controller','router'])
            request={'operation_id':uuid.uuid4().hex,'expected_revision':0,'old_port':old,'new_port':new,'expected_fingerprint':public['fingerprint'],'server_name':'localhost','controller_origin':local['controller_origin'],'origin_mode':'preserve'}
            def phase(name):
                receipt=manager.submit({'action':'public-port','request_id':uuid.uuid4().hex,**request,'phase':name});manager.work_once();job=manager.job(receipt['id'])
                assert job['status']=='completed',job;return job['result']
            phase('prepare');phase('activate');assert phase('verify')['tls_verified'];assert phase('commit')['committed'];assert phase('commit')['applied_port']==new
            assert manager.installed['controller_port']==new and manager.installed['controller_origin']==local['controller_origin']
            # Occupancy is proved against actual Docker publication even when
            # the source host's userland-forwarding listener is absent.
            try:manager.engine.assert_public_port_free('127.0.0.1',new)
            except n.Blocked:pass
            else:raise AssertionError('Actual published port was not detected')
            print('actual Compose router-only publication→strict TLS/name/fingerprint/ready→commit/retry, occupied Docker bind detection: PASS',flush=True)
            request.update(operation_id=uuid.uuid4().hex,expected_revision=1,old_port=new,new_port=bad)
            phase('prepare');phase('activate')
            original_probe=manager._web_probe
            def fail_candidate(chain,name,port,fingerprint):
                if port==bad:raise n.Blocked('Injected candidate verification failure')
                return original_probe(chain,name,port,fingerprint)
            manager._web_probe=fail_candidate
            receipt=manager.submit({'action':'public-port','request_id':uuid.uuid4().hex,**request,'phase':'verify'});manager.work_once();job=manager.job(receipt['id'])
            assert job['status']=='blocked' and n.load(root/'manager/public-port.json')['phase']=='aborted',job
            manager._web_probe=original_probe;original_probe(public['ca'],'localhost',new,public['fingerprint'])
            assert manager.installed['controller_port']==new
            print('actual failed candidate Compose publication automatically restored/proved previous mapping; protected origin/container ports unchanged: PASS',flush=True)
            request.update(operation_id=uuid.uuid4().hex)
            phase('prepare');phase('activate')
            manager=n.Manager(root,engine_factory=Engine,allowed_parent=Path(temporary).resolve());manager.recover_public_port()
            assert phase('abort')['rolled_back'];assert manager.installed['controller_port']==new
            print('actual interrupted activated publication on manager restart restores/proves committed mapping; stale approval stays aborted: PASS',flush=True)
            manager.engine.compose(['down','--remove-orphans'])
            manager=None
    finally:
        if manager:
            try:manager.engine.compose(['down','--remove-orphans'])
            except Exception:pass
        if project:
            identifiers=docker(['ps','-aq','--filter','label=com.docker.compose.project='+project]).split()
            if identifiers:docker(['rm','-f','-v',*identifiers])
            networks=docker(['network','ls','--filter','label=com.docker.compose.project='+project,'--format','{{.ID}}']).split()
            if networks:docker(['network','rm',*networks])
        docker(['volume','rm',volume])


if __name__=='__main__':main()
