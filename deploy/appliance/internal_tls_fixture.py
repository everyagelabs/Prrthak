"""TEST ONLY: real three-node internal leaf rollover with a fixed reload bridge.

Runs in the selected node's private network namespace, with only a disposable
named volume. Database/etcd/Patroni and all TLS probes are real; the Docker
compose signal transport is replaced by the test-only mTLS fixed helper.
"""
from datetime import datetime,timedelta,timezone
import http.client
import ipaddress
import json
from pathlib import Path
import secrets
import ssl
import sys
import time

sys.path[:0]=['/opt/prthak','/app']
import node_manager as n
from controller import internal_certificates as lifecycle
from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.x509.oid import ExtendedKeyUsageOID,NameOID


def main():
    index=sys.argv[1];root=Path('/var/lib/prthak')/index;original=n.load(root/'config/manifest.json')
    ca=x509.load_pem_x509_certificate(original['pki']['ca'].encode())
    ca_key=serialization.load_pem_private_key(Path('/var/lib/prthak/fixture-authority/ca-key.pem').read_bytes(),None)
    leafkey=serialization.load_pem_private_key(original['pki']['private_key'].encode(),None)
    at=datetime.now(timezone.utc);node=original['local_node']
    candidate=x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,node['id'])])).issuer_name(ca.subject).public_key(leafkey.public_key()).serial_number(x509.random_serial_number()).not_valid_before(at-timedelta(minutes=1)).not_valid_after(at+timedelta(days=90)).add_extension(x509.BasicConstraints(ca=False,path_length=None),True).add_extension(x509.SubjectAlternativeName([x509.DNSName(node['id']),x509.DNSName('localhost'),x509.DNSName('router'),x509.IPAddress(ipaddress.ip_address(node['ip'])),x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]),False).add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH,ExtendedKeyUsageOID.SERVER_AUTH]),False).sign(ca_key,hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode()
    fingerprint=lifecycle.certificate_info(candidate)['fingerprint'];previous=lifecycle.certificate_info(original['pki']['certificate'])['fingerprint']

    class Engine:
        def __init__(self,*args):self.fail_new=False;self.reloads=0
        def states(self):return {'database':'running','etcd':'running'}
        def internal_tls_validate(self,payload):return lifecycle.validate_candidate(payload)
        def compose(self,arguments,**kwargs):
            if arguments[:3]==['kill','--signal','SIGHUP']:
                context=ssl.create_default_context(cadata=original['pki']['ca']);context.load_cert_chain(root/'config/database/node.pem',root/'config/database/node-key.pem')
                peer=http.client.HTTPSConnection(node['ip'],9009,context=context,timeout=10)
                peer.request('POST','/fixed-internal-reload',body='{}',headers={'Content-Type':'application/json'})
                response=peer.getresponse();result=json.loads(response.read());peer.close()
                if response.status!=200 or result!={'reloaded':True}:raise n.Blocked('Fixed private reload bridge failed')
                self.reloads+=1
            elif arguments[:3]!=['exec','-T','database']:raise n.Blocked('Unexpected operation in internal identity fixture')
            return ''
        def internal_tls_probe(self,service,ports,directory,hostname,expected):
            try:result=lifecycle.probe({'ports':ports,'hostname':hostname,'fingerprint':expected},directory)
            except Exception as error:
                print('private probe diagnostics: '+service+' '+type(error).__name__+' '+str(error),flush=True);raise
            if self.fail_new and expected==fingerprint:raise n.Blocked('Injected post-readback verification failure')
            return result

    manager=n.Manager(root,engine_factory=Engine)
    def request(identifier,phase):
        return {'operation_id':identifier,'phase':phase,'expected_revision':manager.state()['revision'],'expected_fingerprint':previous,'generation':original['generation']+1,'certificate_pem':candidate}
    # Exercise durable accepted jobs rather than bypassing the actual worker.
    def phase(identifier,name):
        body={'action':'internal-tls','request_id':secrets.token_hex(16),**request(identifier,name)}
        receipt=manager.submit(body);manager.work_once();result=manager.job(receipt['id'])
        return result
    identifier=secrets.token_hex(16)
    assert phase(identifier,'prepare')['result']['prepared']
    assert n.load(root/'config/manifest.json')['pki']['certificate']==original['pki']['certificate']
    assert phase(identifier,'activate')['result']['activated']
    manager.engine.fail_new=True
    result=phase(identifier,'verify')
    assert result['status']=='blocked' and n.load(root/'manager/internal-tls.json')['phase']=='rolled_back',result
    assert manager.engine.internal_tls_probe('database',[5432,8008],root/'manager/internal-tls-staging'/identifier,node['id'],previous)['verified']
    assert manager.engine.internal_tls_probe('etcd',[2379,2380],root/'manager/internal-tls-staging'/identifier,node['id'],previous)['verified']
    manager.engine.fail_new=False
    identifier=secrets.token_hex(16)
    for name,flag in [('prepare','prepared'),('activate','activated'),('verify','verified'),('commit','committed')]:
        result=phase(identifier,name);assert result['status']=='completed' and result['result'][flag],result
    assert result['result']['runtime_verified']
    assert n.load(root/'config/manifest.json')['pki']['certificate']==candidate
    assert phase(identifier,'commit')['result']['committed']
    assert manager.status()['internal_tls']['fingerprint']==fingerprint
    assert manager.status()['internal_tls']['runtime_verified']
    print('node '+index+': actual etcd2379/2380 + PostgreSQL5432 + Patroni8008 new-TLS fingerprint, failed-renewal rollback, durable commit/retry: PASS')


if __name__=='__main__':main()
