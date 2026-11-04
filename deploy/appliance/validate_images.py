#!/usr/bin/env python3
"""Bounded disposable image smoke. No host ports, binds, device or privilege grants.

Requires the two public appliance test images to be built. All TLS/private state
is generated inside a named Docker volume and deleted at the end.
"""
import argparse
import json
import subprocess
import time
import uuid


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--context',required=True)
    parser.add_argument('--controller-image',default='prthak-appliance-controller-test')
    parser.add_argument('--router-image',default='haproxy:3.2-alpine3.24@sha256:5893840576071e6217cd52ebdcc14f454c6f7a631056fa6f4e0f40d3cac4215b')
    parser.add_argument('--database-image',default='prthak-appliance-database-test')
    parser.add_argument('--corporate-web',action='store_true')
    args=parser.parse_args();prefix='prthak-appliance-smoke-'+uuid.uuid4().hex[:10]
    volume=prefix+'-state';network=prefix+'-network';backend=prefix+'-controller';router=prefix+'-router'
    def run(values,input=None,check=True):
        result=subprocess.run(['docker','--context',args.context,*values],input=input,text=True,capture_output=True,timeout=120)
        if check and result.returncode:raise RuntimeError('Fixed smoke operation failed: '+str(values[:3])+'\n'+result.stderr[-2000:]+result.stdout[-2000:])
        return result.stdout if check else result.stdout+result.stderr
    try:
        run(['volume','create',volume]);run(['network','create','--internal',network])
        fixture=r'''
from pathlib import Path
import sys,secrets,uuid,ipaddress
sys.path.insert(0,'/opt/prthak')
import node_manager as n
from controller_entrypoint import initialize
root=Path('/var/lib/prthak')
settings={'appliance_id':uuid.uuid4().hex,'node_id':'private-smoke','site':'private','node_ip':'127.0.0.1','bind_ip':'127.0.0.1','controller_port':8787,'controller_backend_port':8786,'database_router_port':5433,'controller_origin':'https://127.0.0.1:8787','existing_node_ip':''}
n.atomic(root/'config/installed.json',settings)
n.private_dir(root/'config/controller',10001)
n.atomic(root/'config/controller/settings.json',{**settings,'environment':{}},owner=10001)
n.atomic(root/'config/controller/initial-admin-token',secrets.token_urlsafe(48),owner=10001)
initialize(root/'config/controller')
if sys.argv[1]=='corporate':
 from datetime import datetime,timedelta,timezone
 from cryptography import x509
 from cryptography.hazmat.primitives import hashes,serialization
 from cryptography.hazmat.primitives.asymmetric import ec
 from cryptography.x509.oid import NameOID,ExtendedKeyUsageOID
 now=datetime.now(timezone.utc);key=ec.generate_private_key(ec.SECP256R1());ca_name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'Disposable corporate web CA')])
 ca=x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=1)).not_valid_after(now+timedelta(days=1)).add_extension(x509.BasicConstraints(ca=True,path_length=None),True).add_extension(x509.KeyUsage(digital_signature=False,content_commitment=False,key_encipherment=False,data_encipherment=False,key_agreement=False,key_cert_sign=True,crl_sign=True,encipher_only=None,decipher_only=None),True).add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()),False).add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()),False).sign(key,hashes.SHA256())
 leaf_key=ec.generate_private_key(ec.SECP256R1());leaf=x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'corp.prthak.test')])).issuer_name(ca_name).public_key(leaf_key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=1)).not_valid_after(now+timedelta(days=1)).add_extension(x509.BasicConstraints(ca=False,path_length=None),True).add_extension(x509.SubjectAlternativeName([x509.DNSName('corp.prthak.test'),x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]),False).add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),False).add_extension(x509.KeyUsage(digital_signature=True,content_commitment=False,key_encipherment=False,data_encipherment=False,key_agreement=False,key_cert_sign=False,crl_sign=False,encipher_only=None,decipher_only=None),True).add_extension(x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()),False).add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()),False).sign(key,hashes.SHA256())
 public_ca=ca.public_bytes(serialization.Encoding.PEM).decode();public_leaf=leaf.public_bytes(serialization.Encoding.PEM).decode()
 n.atomic(root/'config/controller/pki/controller.pem',public_leaf+public_ca,owner=10001)
 n.atomic(root/'config/controller/pki/controller-key.pem',leaf_key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()),owner=10001)
 n.atomic(root/'config/controller/pki/web-ca.pem',public_ca,owner=10001)
 desired={'schema_version':1,'deployment_id':str(uuid.uuid4()),'generation':1,'cluster_name':'private-corporate-web','controller_origin':settings['controller_origin'],'controller_tls_server_name':'corp.prthak.test','controller_ca':(root/'config/controller/pki/ca.pem').read_text()+public_leaf+public_ca,'local_node':{'id':settings['node_id'],'site':settings['site'],'ip':settings['node_ip'],'role':'management'},'controller_members':[{'id':settings['node_id'],'site':settings['site'],'ip':settings['node_ip']}],'voters':[]}
 n.atomic(root/'config/desired.json',n.validate_manifest(desired,settings))
class E:
 def __init__(self,*args):pass
 def states(self):return {}
n.Manager(root,engine_factory=E).render()
print('private TLS/configuration generated')
'''
        print(run(['run','--rm','--network','none','--user','0','--entrypoint','python3','-i','--mount','type=volume,source='+volume+',target=/var/lib/prthak',args.controller_image,'-','corporate' if args.corporate_web else 'bootstrap'],fixture).strip())
        compose=run(['run','--rm','--network','none','--user','0','--entrypoint','python3','--mount','type=volume,source='+volume+',target=/fixture,readonly',args.controller_image,'-c',"print(open('/fixture/runtime/compose.json').read())"])
        # Parse schema via stdin only. No service is started from these host paths.
        run(['compose','--project-name',prefix,'-f','-','config','--quiet'],compose)
        print('actual Docker Compose schema: PASS')
        print(run(['run','--rm','--network','none','--entrypoint','/opt/patroni/bin/python',args.database_image,'-c',"import os,subprocess,patroni,psycopg,importlib.metadata; assert os.getuid()==999; print('nonroot database image:',subprocess.check_output(['postgres','--version'],text=True).strip(),'Patroni',importlib.metadata.version('patroni'),'psycopg',psycopg.__version__)"]).strip())
        run(['run','-d','--name',backend,'--network',network,'--network-alias','controller','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges:true','--user','10001:10001','--tmpfs','/tmp:rw,noexec,nosuid,size=128m','--tmpfs','/data:uid=10001,gid=10001,mode=700','--mount','type=volume,source='+volume+',target=/run/prthak-bootstrap,volume-subpath=config/controller,readonly',args.controller_image])
        run(['run','-d','--name',router,'--network',network,'--network-alias','router','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges:true','--user','10003:10003','--tmpfs','/tmp:rw,noexec,nosuid,size=16m','--mount','type=volume,source='+volume+',target=/config,volume-subpath=config/router,readonly',args.router_image,'haproxy','-W','-db','-f','/config/haproxy.cfg'])
        probe=r'''
import json,socket,ssl,time
context=ssl.create_default_context(cafile='/run/prthak-bootstrap/pki/ca.pem')
with context.wrap_socket(socket.create_connection(('ROUTER',8787),timeout=3),server_hostname='127.0.0.1') as connection:
 connection.sendall(b'GET /readyz HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n')
 response=b''
 while True:
  part=connection.recv(65536)
  if not part:break
  response+=part
 assert response.startswith(b'HTTP/1.1 200') or response.startswith(b'HTTP/1.0 200'),response[:200]
print('strict verified HTTPS through real HAProxy and nonroot controller: PASS')
'''.replace('ROUTER',router)
        # Outlast HAProxy's initial optimistic state and default fall threshold.
        time.sleep(8)
        if args.corporate_web:
            probe=probe.replace("pki/ca.pem","pki/web-ca.pem").replace("server_hostname='127.0.0.1'","server_hostname='corp.prthak.test'")
        direct=probe.replace("('"+router+"',8787)","('127.0.0.1',8787)")
        print(run(['exec',backend,'python3','-c',direct]).strip().replace('through real HAProxy','direct to'))
        for attempt in range(10):
            try:
                print(run(['exec',backend,'python3','-c',probe]).strip());break
            except RuntimeError:
                if attempt==9:
                    print(run(['logs',router],check=False)[-3000:]);print(run(['logs',backend],check=False)[-3000:]);raise
                time.sleep(1)
        if args.corporate_web:
            print('corporate web CA distinct from endpoint issuer, complete chain and explicit DNS identity: PASS',flush=True)
            mutate=r'''
from pathlib import Path
import sys
sys.path.insert(0,'/opt/prthak');import node_manager as n
from cryptography import x509
from cryptography.hazmat.primitives import serialization
root=Path('/fixture');path=root/'config/router/haproxy.cfg';config=path.read_text()
if sys.argv[1]=='wrong-name':n.atomic(path,config.replace('verifyhost corp.prthak.test','verifyhost wrong.prthak.test'),owner=10003)
else:
 n.atomic(path,config.replace('verifyhost wrong.prthak.test','verifyhost corp.prthak.test'),owner=10003)
 leaf=x509.load_pem_x509_certificate((root/'config/controller/pki/controller.pem').read_bytes()).public_bytes(serialization.Encoding.PEM).decode()
 n.atomic(root/'config/router/controller-ca.pem',(root/'config/controller/pki/ca.pem').read_text()+leaf,owner=10003)
'''
            for mode in ('wrong-name','leaf-only'):
                run(['run','--rm','--network','none','--user','0','--entrypoint','python3','-i','--mount','type=volume,source='+volume+',target=/fixture',args.controller_image,'-',mode],mutate)
                run(['restart',router]);time.sleep(8)
                rejected=False
                try:run(['exec',backend,'python3','-c',probe])
                except RuntimeError:rejected=True
                if mode=='wrong-name':
                    if not rejected:raise AssertionError('HAProxy accepted the wrong configured certificate hostname')
                    print('HAProxy rejects wrong DNS identity despite trusted corporate CA: PASS',flush=True)
                else:print('HAProxy corporate leaf-only trust: '+('REJECTED; complete public issuer/root chain is required' if rejected else 'ACCEPTED as an explicit leaf trust pin'),flush=True)
    finally:
        for name in (router,backend):run(['rm','-f','-v',name],check=False)
        run(['network','rm',network],check=False);run(['volume','rm',volume],check=False)


if __name__=='__main__':main()
