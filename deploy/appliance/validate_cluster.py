#!/usr/bin/env python3
"""Private TLS/quorum/replication wiring smoke; NOT native watchdog validation.

Only generated test Patroni configs set watchdog.mode=off. The installer renderer
and manager guard remain required. No host ports, binds or device grants.
"""
import argparse
import json
import secrets
import subprocess
import time
import uuid


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--context',required=True)
    parser.add_argument('--controller-image',default='prthak-appliance-controller-test');parser.add_argument('--database-image',default='prthak-appliance-database-test')
    parser.add_argument('--etcd-image',default='prthak-appliance-etcd-test');mode=parser.add_mutually_exclusive_group();mode.add_argument('--rotation',action='store_true');mode.add_argument('--coordinator',action='store_true');mode.add_argument('--internal-tls',action='store_true');mode.add_argument('--restore',action='store_true');args=parser.parse_args()
    prefix='prthak-quorum-smoke-'+uuid.uuid4().hex[:10];volume=prefix+'-state';network=prefix+'-network'
    subnet='10.249.'+str(secrets.randbelow(200)+20);ips=[subnet+'.'+str(index+11) for index in range(3)]
    dcs=[prefix+'-etcd-'+str(index) for index in range(3)];databases=[prefix+'-db-'+str(index) for index in range(3)]
    def run(values,input=None,check=True):
        result=subprocess.run(['docker','--context',args.context,*values],input=input,text=True,capture_output=True,timeout=120)
        if check and result.returncode:raise RuntimeError('Fixed cluster smoke operation failed: '+str(values[:3])+'\n'+result.stderr[-2000:]+result.stdout[-2000:])
        return result.stdout if check else result.stdout+result.stderr
    fixture=r'''
from pathlib import Path
import ipaddress,json,secrets,sys,uuid
from datetime import datetime,timedelta,timezone
sys.path.insert(0,'/opt/prthak')
import node_manager as n
from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID,ExtendedKeyUsageOID
ips=json.loads(sys.argv[1]);root=Path('/var/lib/prthak');now=datetime.now(timezone.utc)
key=ec.generate_private_key(ec.SECP256R1());name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'Private disposable cluster CA')])
ca=x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(days=1)).not_valid_after(now+timedelta(days=3650)).add_extension(x509.BasicConstraints(ca=True,path_length=None),True).add_extension(x509.KeyUsage(digital_signature=False,content_commitment=False,key_encipherment=False,data_encipherment=False,key_agreement=False,key_cert_sign=True,crl_sign=True,encipher_only=None,decipher_only=None),True).add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()),False).add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()),False).sign(key,hashes.SHA256())
n.atomic(root/'fixture-authority/ca-key.pem',key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()).decode())
voters=[{'id':'private-node-'+str(i),'site':'site-'+str(i),'ip':address,'tls_server_name':'private-node-'+str(i)} for i,address in enumerate(ips)]
passwords={kind:secrets.token_urlsafe(36) for kind in ('admin','replication','metadata','traffic','rotation_test')};deployment=str(uuid.uuid4())
class E:
 def __init__(self,*args):pass
 def states(self):return {}
for i,node in enumerate(voters):
 data=root/str(i);local={'appliance_id':uuid.uuid4().hex,'node_id':node['id'],'site':node['site'],'node_ip':node['ip'],'bind_ip':node['ip'],'controller_port':8787,'controller_backend_port':8786,'database_router_port':5433,'controller_origin':'https://'+node['ip']+':8787','existing_node_ip':''}
 leafkey=ec.generate_private_key(ec.SECP256R1());leaf=x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,node['id'])])).issuer_name(name).public_key(leafkey.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(days=1)).not_valid_after(now+timedelta(days=2)).add_extension(x509.BasicConstraints(ca=False,path_length=None),True).add_extension(x509.SubjectAlternativeName([x509.DNSName(node['id']),x509.DNSName('localhost'),x509.IPAddress(ipaddress.ip_address(node['ip'])),x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]),False).add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH,ExtendedKeyUsageOID.SERVER_AUTH]),False).add_extension(x509.KeyUsage(digital_signature=True,content_commitment=False,key_encipherment=False,data_encipherment=False,key_agreement=False,key_cert_sign=False,crl_sign=False,encipher_only=None,decipher_only=None),True).add_extension(x509.SubjectKeyIdentifier.from_public_key(leafkey.public_key()),False).add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()),False).sign(key,hashes.SHA256())
 pki={'ca':ca.public_bytes(serialization.Encoding.PEM).decode(),'certificate':leaf.public_bytes(serialization.Encoding.PEM).decode(),'private_key':leafkey.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()).decode()}
 manifest=n.validate_manifest({'schema_version':1,'deployment_id':deployment,'generation':1,'cluster_name':'private-disposable-cluster','controller_origin':local['controller_origin'],'controller_ca':pki['ca'],'controller_tls_server_name':node['id'],'local_node':{**node,'role':'database_voter'},'voters':voters,'controller_members':voters,'pki':pki,'secrets':passwords,'watchdog':{'required':True,'approved':False}},local)
 n.atomic(data/'config/installed.json',local);n.atomic(data/'config/manifest.json',manifest)
 n.atomic(data/'manager/network-sources.json',[str(ipaddress.ip_network(ips[0]+'/24',strict=False))])
 n.Manager(data,engine_factory=E).render()
 path=data/'config/database/patroni.json';configuration=n.load(path)
 assert configuration['watchdog']['mode']=='required'
 n.atomic(data/'config/database/production-patroni.json',configuration,owner=999)
 configuration['watchdog']['mode']='off'
 configuration['log']={'level':'DEBUG'}
 n.atomic(path,configuration,owner=999)
print('Private 3-node fixture generated; ONLY fixture watchdog is OFF')
'''
    probe=r'''
import json,ssl,http.client,sys
context=ssl.create_default_context(cafile='/config/ca.pem');context.load_cert_chain('/config/node.pem','/config/node-key.pem')
results=[]
for address in json.loads(sys.argv[1]):
 item={'ip':address}
 for port,path,kind in [(2379,'/health','etcd'),(8008,'/','patroni')]:
  try:
   connection=http.client.HTTPSConnection(address,port,timeout=2,context=context);connection.request('GET',path);reply=connection.getresponse();item[kind]=json.loads(reply.read());item[kind+'_status']=reply.status;connection.close()
  except Exception:item[kind]={'state':'unavailable'}
 results.append(item)
print(json.dumps(results))
'''
    try:
        # Validate the explicitly built candidate, never silently pull an older
        # upstream etcd image in place of its reviewed dependency-patched build.
        run(['image','inspect',args.etcd_image]);run(['network','create','--internal','--subnet',subnet+'.0/24',network]);run(['volume','create',volume])
        print(run(['run','--rm','--network','none','--user','0','--entrypoint','python3','-i','--mount','type=volume,source='+volume+',target=/var/lib/prthak',args.controller_image,'-',json.dumps(ips)],fixture).strip(),flush=True)
        for index,name in enumerate(dcs):
            run(['run','-d','--name',name,'--network',network,'--ip',ips[index],'--read-only','--cap-drop','ALL','--security-opt','no-new-privileges:true','--user','10002:10002','--tmpfs','/tmp:rw,noexec,nosuid,size=16m','--mount','type=volume,source='+volume+',target=/config,volume-subpath='+str(index)+'/config/etcd,readonly','--mount','type=volume,source='+volume+',target=/etcd-data,volume-subpath='+str(index)+'/etcd',args.etcd_image,'/usr/local/bin/etcd','--config-file=/config/etcd.json'])
        for index,name in enumerate(databases):
            run(['run','-d','--name',name,'--network','container:'+dcs[index],'--read-only','--cap-drop','ALL','--security-opt','no-new-privileges:true','--user','999:999','--tmpfs','/tmp:rw,noexec,nosuid,size=128m','--mount','type=volume,source='+volume+',target=/config,volume-subpath='+str(index)+'/config/database,readonly','--mount','type=volume,source='+volume+',target=/var/lib/postgresql/data,volume-subpath='+str(index)+'/database',args.database_image])
        observations=[]
        deadline=time.monotonic()+180
        for attempt in range(90):
            observations=json.loads(run(['exec',databases[0],'/opt/patroni/bin/python','-c',probe,json.dumps(ips)]))
            primaries=[i for i in observations if i.get('patroni',{}).get('state')=='running' and i['patroni'].get('role') in ('primary','master')]
            replicas=[i for i in observations if i.get('patroni',{}).get('state')=='running' and i['patroni'].get('role')=='replica']
            if len(primaries)==1 and len(replicas)==2 and all(i.get('etcd',{}).get('health') in (True,'true') for i in observations):break
            if time.monotonic()>deadline:raise RuntimeError('Bounded cluster readiness deadline expired')
            time.sleep(2)
        else:raise RuntimeError('Three authenticated etcd voters + one PG primary and two replicas did not become ready: '+json.dumps(observations))
        print('actual mTLS etcd quorum + PostgreSQL16/Patroni primary and two replicas: PASS',flush=True)
        writer=ips.index(primaries[0]['ip'])
        sql=r'''
import json,sys,time,psycopg
private=json.load(open('/config/roles.json'));password=private['secrets']['metadata']
def connect(address):return psycopg.connect(host=address,dbname=private['database']['metadata_name'],user=private['database']['metadata_user'],password=password,sslmode='verify-full',sslrootcert='/config/ca.pem',connect_timeout=3,options='-c statement_timeout=10000',autocommit=True)
with connect(sys.argv[1]) as db:
 db.execute('CREATE TABLE prthak_private_smoke (id integer PRIMARY KEY, value text)');db.execute("INSERT INTO prthak_private_smoke VALUES(1,'verified-synchronous-write')")
for address in json.loads(sys.argv[2]):
 for attempt in range(20):
  try:
   with connect(address) as db:row=db.execute('SELECT value FROM prthak_private_smoke WHERE id=1').fetchone();readonly=db.execute('SELECT pg_is_in_recovery()').fetchone()[0]
   if row and row[0]=='verified-synchronous-write':break
  except psycopg.Error:pass
  time.sleep(.2)
 else:raise AssertionError('replicated write missing')
 if address!=sys.argv[1]:assert readonly
print('verify-full SCRAM application role write + replica read-only and replicated row: PASS')
'''
        print(run(['exec',databases[writer],'/opt/patroni/bin/python','-c',sql,ips[writer],json.dumps(ips)]).strip(),flush=True)
        if args.restore:
            for database in databases:run(['exec','-d',database,'/opt/patroni/bin/python','/opt/prthak/helper_rpc_fixture.py'])
            print(run(['run','--rm','--network',network,'--user','0','--cap-drop','ALL','--cap-add','CHOWN','--cap-add','DAC_OVERRIDE','--cap-add','FOWNER','--security-opt','no-new-privileges:true','--entrypoint','python3','--mount','type=volume,source='+volume+',target=/var/lib/prthak',args.controller_image,'/opt/prthak/restore_fixture.py',json.dumps(ips),str(writer)]).strip(),flush=True)
        if args.internal_tls:
            for database in databases:run(['exec','-d',database,'/opt/patroni/bin/python','/opt/prthak/helper_rpc_fixture.py'])
            for index in range(3):
                print(run(['run','--rm','--network','container:'+dcs[index],'--user','0','--cap-drop','ALL','--cap-add','CHOWN','--cap-add','DAC_OVERRIDE','--security-opt','no-new-privileges:true','--entrypoint','python3','--mount','type=volume,source='+volume+',target=/var/lib/prthak',args.controller_image,'/opt/prthak/internal_tls_fixture.py',str(index)]).strip(),flush=True)
            observations=json.loads(run(['exec',databases[0],'/opt/patroni/bin/python','-c',probe,json.dumps(ips)]))
            assert len([i for i in observations if i.get('patroni',{}).get('role') in ('primary','master') and i['patroni'].get('state')=='running'])==1,observations
            assert all(i.get('etcd',{}).get('health') in (True,'true') for i in observations),observations
            print('all3 voters remain TLS-healthy, one primary and two replicas after leaf renewal: PASS',flush=True)
        if args.coordinator:
            # Metadata is the actual replicated PostgreSQL database, not a
            # SQLite Store with a simulated HA flag. Remove only our test table.
            drop="import json,psycopg;p=json.load(open('/config/roles.json'));c=psycopg.connect(host='127.0.0.1',dbname=p['database']['metadata_name'],user=p['database']['metadata_user'],password=p['secrets']['metadata'],sslmode='verify-full',sslrootcert='/config/ca.pem',autocommit=True);c.execute('DROP TABLE prthak_private_smoke')"
            run(['exec',databases[writer],'/opt/patroni/bin/python','-c',drop])
            for database in databases:run(['exec','-d',database,'/opt/patroni/bin/python','/opt/prthak/helper_rpc_fixture.py'])
            print(run(['run','--rm','--network',network,'--user','0','--cap-drop','ALL','--cap-add','CHOWN','--cap-add','DAC_OVERRIDE','--security-opt','no-new-privileges:true','--entrypoint','python3','--mount','type=volume,source='+volume+',target=/var/lib/prthak',args.controller_image,'/opt/prthak/coordinator_fixture.py',json.dumps(ips)]).strip(),flush=True)
        if args.rotation:
            adapter=r'''
import json,subprocess,sys
from pathlib import Path
sys.path.insert(0,'/opt/prthak');import node_manager as n
index,phase=sys.argv[1:3];root=Path('/var/lib/prthak')/index
class E:
 def __init__(self,*args):pass
 def states(self):return {'database':'running','etcd':'running'}
 def database_helper(self,payload):
  result=subprocess.run([sys.executable,'/opt/prthak/rotation_helper.py'],input=json.dumps(payload).encode(),capture_output=True,timeout=30)
  if result.returncode:raise n.Blocked('private fixed helper failed: '+str(json.loads(result.stdout).get('code','unknown')))
  return json.loads(result.stdout)
manager=n.Manager(root,engine_factory=E)
body={'rotation_id':'a'*32,'phase':phase,'expected_revision':0}
if phase=='prepare':body['password']=json.loads(Path('/config/roles.json').read_text())['secrets']['rotation_test']
if phase=='finalize':body['all_voters_verified']=True
result=manager.rotate_replication(body)
expected={'prepare':'prepared','change-role':'role_changed','reload':'reloaded','verify':'verified','finalize':'finalized'}[phase]
assert result['phase']==expected,result
print(json.dumps(result))
'''
            def phase(index,name):
                return run(['run','--rm','--network','container:'+dcs[index],'--user','0','--cap-drop','ALL','--cap-add','CHOWN','--cap-add','DAC_OVERRIDE','--security-opt','no-new-privileges:true','--entrypoint','python3','-i','--mount','type=volume,source='+volume+',target=/var/lib/prthak','--mount','type=volume,source='+volume+',target=/config,volume-subpath='+str(index)+'/config/database,readonly',args.controller_image,'-',str(index),name],adapter)
            for index in range(3):phase(index,'prepare')
            phase(writer,'change-role')
            for index in range(3):phase(index,'reload')
            # Let Patroni apply the new local authentication configuration.
            time.sleep(7)
            for index in range(3):phase(index,'verify')
            for index in range(3):phase(index,'finalize')
            for index in range(3):phase(index,'finalize')
            print('real local adapter prepare→primary SCRAM change→mTLS reload→NEW replication auth on all 3→finalize/retry: PASS',flush=True)
        print('Native watchdog reset, real host/site-loss fencing and promotion under partition: NOT VALIDATED',flush=True)
    except Exception:
        for name in [*databases,*dcs]:
            logs=run(['logs','--tail','30',name],check=False)
            print(name+'\n'+logs[-4000:],flush=True)
        raise
    finally:
        for name in [*databases,*dcs]:run(['rm','-f','-v',name],check=False)
        run(['network','rm',network],check=False);run(['volume','rm',volume],check=False)


if __name__=='__main__':main()
