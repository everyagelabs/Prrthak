#!/usr/bin/env python3
"""Bounded local-only Gunicorn/TLS DAST; synthetic Entra and disposable SQLite.

No remote target option exists. It starts its own private loopback server and
never opens more than two simultaneous connections. No real tenant is contacted.
"""
from datetime import timedelta
import argparse
import hashlib
import http.client
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import time
from urllib.parse import parse_qs, urlencode, urlsplit

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))


def serve_fixture(directory,port):
    from cryptography.hazmat.primitives import serialization
    from controller.app import App
    from controller.auth import EntraAuth,EntraConfig
    from controller.pki import Signer
    from controller.production_http import serve
    from controller.store import Store
    from controller.tests.test_auth import LocalMicrosoft,TENANT,CLIENT,SUPER
    class FileCodes(LocalMicrosoft):
        def _json(self,url,data=None,maximum=1024*1024):
            if url.endswith('/token'):
                code=parse_qs(data.decode())['code'][0]
                if not code.isalnum():raise ValueError('Invalid fixture code')
                path=directory/'codes'/(code+'.json')
                self.codes[code]=json.loads(path.read_text());path.unlink()
            return super()._json(url,data,maximum)
    settings=json.loads((directory/'fixture.json').read_text())
    config=EntraConfig(TENANT,CLIENT,f'https://localhost:{port}/api/v1/auth/callback','local-only-fixture-secret',SUPER)
    provider=FileCodes(config,serialization.load_pem_private_key((directory/'oidc-key.pem').read_bytes(),None))
    store=Store(directory/'state')
    original_token=store.create_token
    def token_with_fixture_delay(name,*args,**kwargs):
        if name=='Fixture consumed-body long response':time.sleep(32)
        return original_token(name,*args,**kwargs)
    store.create_token=token_with_fixture_delay
    app=App(store,signer=Signer(directory/'pki/ca.pem',directory/'pki/ca-key.pem'),auth=EntraAuth(store,config,provider),tokens={'super_admin':settings['legacy_super']})
    app.start_jobs=lambda:None
    store.approval_production=True
    serve(app,'127.0.0.1',port,certificate=directory/'pki/controller.pem',private_key=directory/'pki/controller-key.pem',ca=directory/'pki/ca.pem',workers=1,threads=4)


class Audit:
    def __init__(self,directory,port):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa,ec
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.x509.oid import NameOID
        from controller.auth import EntraAuth,EntraConfig
        from controller import endpoint_certificates
        from controller.pki import Signer,init_ca
        from controller.store import Store
        from controller.tests.test_auth import LocalMicrosoft,TENANT,CLIENT,SUPER,ADMIN,READ
        self.directory,self.port=directory,port
        self.origin=f'https://localhost:{port}'
        self.records=[];self.headers={};self.started=time.monotonic()
        self.store=Store(directory/'state');self.pki=init_ca(directory)
        (directory/'codes').mkdir(mode=0o700)
        self.key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        key_path=directory/'oidc-key.pem';key_path.write_bytes(self.key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()));key_path.chmod(0o600)
        self.config=EntraConfig(TENANT,CLIENT,self.origin+'/api/v1/auth/callback','local-only-fixture-secret',SUPER)
        self.provider=LocalMicrosoft(self.config,self.key);self.auth=EntraAuth(self.store,self.config,self.provider)
        self.users={'super_admin':SUPER,'admin':ADMIN,'read_only':READ}
        with self.store.meta() as db:
            for role,oid in self.users.items():self.store._put(db,'auth_users',self.auth._user({'object_id':oid,'role':role,'display_name':'Synthetic '+role}))
        self.legacy=secrets.token_urlsafe(48)
        config=directory/'fixture.json';config.write_text(json.dumps({'legacy_super':self.legacy}));config.chmod(0o600)
        self.tls=ssl.create_default_context(cafile=str(self.pki/'ca.pem'))
        for identifier in ('endpoint-a','endpoint-b'):
            self.store.report(identifier,{'hostname':identifier,'ips':['10.40.0.1' if identifier=='endpoint-a' else '10.40.0.2'],'listeners':[]})
        agent_key=ec.generate_private_key(ec.SECP256R1())
        csr=x509.CertificateSigningRequestBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'endpoint-a')])).sign(agent_key,hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode()
        leaf,_=Signer(self.pki/'ca.pem',self.pki/'ca-key.pem')('endpoint-a',csr)
        cert_path,key_path=directory/'agent.pem',directory/'agent-key.pem'
        cert_path.write_text(leaf);cert_path.chmod(0o600)
        key_path.write_bytes(agent_key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()));key_path.chmod(0o600)
        with self.store.meta() as db:
            server=self.store._get(db,'servers','endpoint-a');endpoint_certificates.record_issued(self.store,db,server,leaf);self.store._put(db,'servers',server)
        self.agent_tls=ssl.create_default_context(cafile=str(self.pki/'ca.pem'));self.agent_tls.load_cert_chain(cert_path,key_path)
        # Provision synthetic sessions with actual RSA/OIDC verification. Human
        # route requests below use real Secure cookies and current DB roles.
        for role,oid in self.users.items():
            start=self.auth.begin_login({})
            result=self.auth.callback(self.provider.issue(start['location'],oid,roles=['super_admin'],groups=['admin']),{'Cookie':start['cookies'][0].split(';',1)[0]})
            cookie=next(item.split(';',1)[0] for item in result['cookies'] if item.startswith('__Host-prthak-session='))
            self.headers[role]={'Cookie':cookie,'X-CSRF-Token':result['principal']['csrf_token'],'Origin':self.origin}

    def record(self,name,passed,**details):
        value={'name':name,'passed':bool(passed),**details};self.records.append(value)
        print(json.dumps(value,sort_keys=True),flush=True)

    def http(self,method,path,body=None,role=None,headers=None,tls=None,timeout=10):
        connection=http.client.HTTPSConnection('localhost',self.port,context=tls or self.tls,timeout=timeout)
        outgoing=dict(self.headers.get(role,{}) if role else {});outgoing.update(headers or {})
        raw=json.dumps(body).encode() if body is not None else None
        if raw is not None:outgoing['Content-Type']='application/json'
        try:
            connection.request(method,path,raw,outgoing);response=connection.getresponse()
            return response.status,response.read(),dict(response.getheaders())
        finally:connection.close()

    def matrix(self):
        routes=[('overview','GET','/api/v1/overview',None,'all'),('users','GET','/api/v1/access/users',None,'super'),('backups','GET','/api/v1/platform/backups',None,'super'),('notifications','GET','/api/v1/platform/notifications',None,'super'),('recovery','GET','/api/v1/platform/recovery',None,'super'),('metadata-profiles','GET','/api/v1/metadata/imports/profiles',None,'write'),('enroll-token','POST','/api/v1/enrollment-tokens',{'name':'Private DAST only'},'write'),('new-user','POST','/api/v1/access/users',{},'super'),('polling-change','POST','/api/v1/platform/agent-settings',{},'super'),('service-apply','POST','/api/v1/platform/appliance/services/apply',{},'super'),('certificate-apply','POST','/api/v1/platform/certificates/apply',{},'super'),('database-recovery-confirm','POST','/api/v1/platform/recovery/confirm',{},'super'),('managed-rollout','POST','/api/v1/policy-rollouts',{},'write'),('imported-rule-change','POST','/api/v1/firewall/changes',{},'write'),('learning-create','POST','/api/v1/learning',{},'write')]
        for role in (None,'read_only','admin','super_admin'):
            for name,method,path,body,scope in routes:
                status,raw,_=self.http(method,path,body,role)
                allowed=role is not None and (scope=='all' or scope=='write' and role in ('admin','super_admin') or scope=='super' and role=='super_admin')
                expected=(401,) if role is None else (403,) if not allowed else (200,201) if method=='GET' or name=='enroll-token' else (400,404,409,503)
                self.record('matrix:'+str(role)+':'+name,status in expected,status=status,expected=list(expected),method=method,path=path)
        # Concrete authority check: only Super can create even a Read Only user.
        user={'object_id':'77777777-7777-7777-7777-777777777777','role':'read_only'}
        for role in ('read_only','admin','super_admin'):
            status,_,_=self.http('POST','/api/v1/access/users',user,role)
            self.record('concrete-user-create:'+role,status==(201 if role=='super_admin' else 403),status=status)
        status,body,_=self.http('POST','/api/v1/platform/backups',{},'super_admin')
        self.record('super-private-backup-create',status==201,status=status)
        if status==201:
            identifier=json.loads(body)['id']
            for role in (None,'read_only','admin','super_admin'):
                code,archive,_=self.http('GET',f'/api/v1/platform/backups/{identifier}/download',role=role)
                expected=401 if role is None else 200 if role=='super_admin' else 403
                self.record('backup-download:'+str(role),code==expected and (code!=200 or archive[:2]==b'PK'),status=code)

    def identity_and_csrf(self):
        spoof={'X-Agent-ID':'endpoint-b','X-Forwarded-Client-Cert':'CN=endpoint-b','X-SSL-Client-S-DN':'CN=endpoint-b','X-Forwarded-User':'super_admin','X-Forwarded-Proto':'https','X-Forwarded-For':'10.40.0.2'}
        for name,headers in (('forwarded-human',spoof),('legacy-super',{'Authorization':'Bearer '+self.legacy}),('legacy-super-forwarded',{**spoof,'Authorization':'Bearer '+self.legacy})):
            code,_,_=self.http('GET','/api/v1/access/users',headers=headers)
            self.record(name+'-cannot-authenticate-entra',code==401,status=code)
        code,_,_=self.http('GET','/api/v1/agent/policy',headers=spoof)
        self.record('forwarded-agent-without-mtls',code==403,status=code)
        code,_,_=self.http('POST','/api/v1/agent/report',{'hostname':'owns-a-only','ips':['10.40.0.1'],'listeners':[]},headers=spoof,tls=self.agent_tls)
        b=self.store.get('servers','endpoint-b');a=self.store.get('servers','endpoint-a')
        self.record('forwarded-agent-cannot-change-another-endpoint',code==200 and b['hostname']=='endpoint-b' and a['hostname']=='owns-a-only',status=code)
        cookie=self.headers['admin']['Cookie']
        for name,headers in (('missing-csrf',{'Cookie':cookie,'Origin':self.origin}),('wrong-csrf',{'Cookie':cookie,'X-CSRF-Token':'wrong','Origin':self.origin}),('foreign-origin',{**self.headers['admin'],'Origin':'https://attacker.invalid'}),('foreign-origin-spoofed-host',{**self.headers['admin'],'Origin':'https://attacker.invalid','Host':'attacker.invalid'})):
            code,_,_=self.http('POST','/api/v1/enrollment-tokens',{'name':'Must not issue'},headers=headers)
            self.record('csrf:'+name,code==403,status=code)
        code,_,headers=self.http('GET','/api/v1/overview',role='read_only',headers={'Origin':'https://attacker.invalid'})
        self.record('cross-origin-read-has-no-cors-grant',code==200 and 'Access-Control-Allow-Origin' not in headers,status=code)
        for name,path,role in (('static-parent','/../controller/auth.py',None),('static-percent-parent','/%2e%2e/controller/auth.py',None),('static-nested-parent','/assets/%2e%2e/%2e%2e/controller/auth.py',None),('static-absolute','/%2fetc%2fpasswd',None),('backup-percent-traversal','/api/v1/platform/backups/%2e%2e%2f%2e%2e%2fetc%2fpasswd/download','super_admin')):
            code,body,_=self.http('GET',path,role=role)
            self.record('traversal:'+name,code in (400,404) and b'root:' not in body and b'class EntraAuth' not in body,status=code)

    def jwt_callbacks(self):
        import jwt
        from cryptography.hazmat.primitives.asymmetric import rsa
        from controller.auth import _b64
        from controller.tests.test_auth import SUPER
        cases=[('valid',{}),('wrong-audience',{'aud':'attacker-client'}),('wrong-issuer',{'iss':'https://attacker.invalid'}),('expired',{'iat':int(time.time())-7200,'exp':int(time.time())-3600}),('future-nbf',{'nbf':int(time.time())+3600}),('wrong-nonce',{'nonce':'not-the-browser-nonce'}),('none-algorithm',{}),('wrong-signature',{})]
        replay=None
        for name,changes in cases:
            start=self.auth.begin_login({});params=parse_qs(urlsplit(start['location']).query)
            issued=int(time.time());claims={'iss':self.config.issuer,'aud':self.config.client_id,'sub':'synthetic-super','tid':self.config.tenant_id,'oid':SUPER,'nonce':params['nonce'][0],'iat':issued,'nbf':issued,'exp':issued+3600,**changes}
            key=rsa.generate_private_key(public_exponent=65537,key_size=2048) if name=='wrong-signature' else self.key
            token=jwt.encode(claims,None if name=='none-algorithm' else key,algorithm='none' if name=='none-algorithm' else 'RS256',headers={'kid':'fixture-key'})
            code=secrets.token_hex(24);path=self.directory/'codes'/(code+'.json');path.write_text(json.dumps({'token':token,'challenge':params['code_challenge'][0]}));path.chmod(0o600)
            query=urlencode({'state':params['state'][0],'code':code});headers={'Cookie':start['cookies'][0].split(';',1)[0]}
            status,_,out=self.http('GET','/api/v1/auth/callback?'+query,headers=headers)
            self.record('oidc:'+name,status==(303 if name=='valid' else 403) and (name=='valid' or '__Host-prthak-session=' not in out.get('Set-Cookie','')),status=status)
            if name=='valid':replay=(query,headers)
        status,_,_=self.http('GET','/api/v1/auth/callback?'+replay[0],headers=replay[1])
        self.record('oidc:state-replay',status==403,status=status)
        status,_,_=self.http('GET','/api/v1/auth/login')
        self.record('oidc:actual-login-start',status==302,status=status)

    def raw(self,payload,timeout=6):
        with socket.create_connection(('127.0.0.1',self.port),timeout=timeout) as raw:
            with self.tls.wrap_socket(raw,server_hostname='localhost') as connection:
                connection.sendall(payload);connection.settimeout(timeout)
                try:return connection.recv(8192)
                except (ConnectionResetError,ssl.SSLError):return b''

    def framing(self):
        common=f'Host: localhost:{self.port}\r\nConnection: close\r\n'.encode()
        cases=[('duplicate-length',b'POST /api/v1/agent/enroll HTTP/1.1\r\n'+common+b'Content-Length: 2\r\nContent-Length: 4\r\nContent-Type: application/json\r\n\r\n{}'),('transfer-and-length',b'POST /api/v1/agent/enroll HTTP/1.1\r\n'+common+b'Content-Length: 2\r\nTransfer-Encoding: chunked\r\nContent-Type: application/json\r\n\r\n0\r\n\r\n'),('chunked-only',b'POST /api/v1/agent/enroll HTTP/1.1\r\n'+common+b'Transfer-Encoding: chunked\r\nContent-Type: application/json\r\n\r\n2\r\n{}\r\n0\r\n\r\n'),('oversize-unread',b'POST /api/v1/agent/enroll HTTP/1.1\r\n'+common+b'Content-Length: 2097153\r\nContent-Type: application/json\r\n\r\n'),('certificate-oversize-unread',b'POST /api/v1/platform/certificates/preview HTTP/1.1\r\n'+common+('Cookie: '+self.headers['super_admin']['Cookie']+'\r\nX-CSRF-Token: '+self.headers['super_admin']['X-CSRF-Token']+'\r\nOrigin: '+self.origin+'\r\n').encode()+b'Content-Length: 4194305\r\nContent-Type: application/json\r\n\r\n'),('oversized-header',b'GET /healthz HTTP/1.1\r\n'+common+b'X-Too-Large: '+b'a'*9000+b'\r\n\r\n'),('header-fold',b'GET /healthz HTTP/1.1\r\n'+common+b'X-A: one\r\n folded\r\n\r\n')]
        for name,payload in cases:
            at=time.monotonic();raw=self.raw(payload)
            status=int(raw.split(b' ',2)[1]) if raw.startswith(b'HTTP/') else None
            self.record('framing:'+name,status in (400,413,431) and time.monotonic()-at<5,status=status,seconds=round(time.monotonic()-at,3))

    def slow_deadlines(self,methods=('GET',),names=None):
        # One malicious connection at a time; the separate probe is the second
        # slot. Production deadlines are not shortened in this fixture.
        for name,tls,prefix,expected in (
            ('partial-tls',False,b'\x16\x03\x01',20),
            ('partial-header',True,b'GET /healthz HTTP/1.1\r\nHost: localhost',20),
            ('partial-post-body',True,('POST /api/v1/enrollment-tokens HTTP/1.1\r\nHost: localhost:'+str(self.port)+'\r\nCookie: '+self.headers['admin']['Cookie']+'\r\nX-CSRF-Token: '+self.headers['admin']['X-CSRF-Token']+'\r\nOrigin: '+self.origin+'\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{').encode(),30)):
            if names is not None and name not in names:continue
            raw=socket.create_connection(('127.0.0.1',self.port),timeout=5)
            connection=self.tls.wrap_socket(raw,server_hostname='localhost') if tls else raw
            try:
                at=time.monotonic();connection.sendall(prefix)
                time.sleep(1)
                code,_,_=self.http('GET','/healthz');self.record('healthy-during:'+name,code==200,status=code)
                connection.settimeout(expected+8)
                try:result=connection.recv(8192)
                except (ConnectionResetError,ssl.SSLError):result=b''
                closed=not result
                status=int(result.split(b' ',2)[1]) if result.startswith(b'HTTP/') else None
                if result:
                    connection.settimeout(1)
                    try:
                        while len(result)<8192:
                            remaining=connection.recv(8192-len(result))
                            if not remaining:closed=True;break
                            result+=remaining
                    except (ConnectionResetError,ssl.SSLError):closed=True
                    except TimeoutError:pass
                elapsed=time.monotonic()-at
                self.record('deadline:'+name,elapsed<=expected+5 and closed and (not result or name=='partial-tls' or status is not None and 400<=status<600),seconds=round(elapsed,3),received_bytes=len(result),response_status=status,peer_closed=closed)
            finally:connection.close()
        for method in methods:self.unread_body_deadline(method)

    def unread_body_deadline(self,method='GET'):
        connection=self.tls.wrap_socket(socket.create_connection(('127.0.0.1',self.port),timeout=5),server_hostname='localhost')
        try:
            at=time.monotonic();connection.sendall(f'{method} /healthz HTTP/1.1\r\nHost: localhost:{self.port}\r\nContent-Length: 64\r\n\r\n'.encode())
            connection.settimeout(5)
            first=http.client.HTTPResponse(connection,method=method);first.begin();initial_status=first.status;first.read()
            closed=False;sent=0;outcome='inconclusive';closure_seconds=None
            for _ in range(6):
                time.sleep(6)
                try:connection.sendall(b'x');sent+=1
                except (BrokenPipeError,ConnectionResetError,ssl.SSLError):closed=True;closure_seconds=time.monotonic()-at;break
                connection.settimeout(.05)
                try:
                    if not connection.recv(1):closed=True;closure_seconds=time.monotonic()-at;break
                except (ConnectionResetError,ssl.SSLError):closed=True;closure_seconds=time.monotonic()-at;break
                except TimeoutError:pass
                finally:connection.settimeout(5)
            if not closed:
                try:
                    # Separate TLS records: sending a pipelined request in the
                    # same record as the last body bytes can leave it buffered
                    # in Gunicorn's parser while its poller waits for new data.
                    connection.sendall(b'x'*(64-sent));time.sleep(.15)
                    connection.sendall(f'GET /healthz HTTP/1.1\r\nHost: localhost:{self.port}\r\nConnection: close\r\n\r\n'.encode())
                    second=http.client.HTTPResponse(connection);second.begin();survived=second.status==200;second.read()
                    outcome='survived_absolute_body_deadline' if survived else 'unexpected_response'
                except TimeoutError:survived=False;outcome='inconclusive_read_timeout'
                except (OSError,ssl.SSLError,http.client.HTTPException):survived=False;outcome='closed_after_trickle'
            else:survived=False;outcome='closed_during_trickle'
            self.record('deadline:'+method.lower()+'-unread-body',closed and closure_seconds<=35,seconds=round(time.monotonic()-at,3),initial_response_status=initial_status,second_response_after_30s=survived,closed_during_trickle=closed,closure_seconds=round(closure_seconds,3) if closure_seconds else None,outcome=outcome)
        finally:connection.close()

    def consumed_body_long_response(self):
        at=time.monotonic()
        code,_,_=self.http('POST','/api/v1/enrollment-tokens',{'name':'Fixture consumed-body long response'},'admin',timeout=40)
        elapsed=time.monotonic()-at
        self.record('deadline:fully-consumed-post-long-response',code==201 and 31<=elapsed<=39,status=code,seconds=round(elapsed,3))

    def revocation(self):
        oid=self.users['admin'];identifier=self.config.tenant_id+':'+oid
        code,_,_=self.http('PATCH','/api/v1/access/users/'+identifier,{'enabled':False},'super_admin')
        status,_,_=self.http('GET','/api/v1/overview',role='admin')
        self.record('live-role-disable-revokes-cookie',code==200 and status==401,disable_status=code,reused_cookie_status=status)


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--fixture',type=Path);parser.add_argument('--port',type=int);parser.add_argument('--skip-slow',action='store_true');parser.add_argument('--get-body-only',action='store_true');parser.add_argument('--post-body-only',action='store_true');parser.add_argument('--all-body-methods',action='store_true');args=parser.parse_args()
    if args.fixture:
        serve_fixture(args.fixture,args.port);return
    output=ROOT/'.local/security-audit';output.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='prthak-api-dast-') as private:
        directory=Path(private)
        with socket.socket() as selected:selected.bind(('127.0.0.1',0));port=selected.getsockname()[1]
        audit=Audit(directory,port)
        source_files=['controller/app.py','controller/auth.py','controller/production_http.py','controller/gunicorn_worker.py','controller/endpoint_certificates.py','scripts/security-api-dast.py']
        source={name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in source_files}
        env={key:value for key,value in os.environ.items() if not key.startswith(('SEG_','PRTHAK_')) and key!='CONTROLLER_ORIGIN'}
        with (output/'controller-dast-server.log').open('wb') as log:
            process=subprocess.Popen([sys.executable,__file__,'--fixture',str(directory),'--port',str(port)],cwd=ROOT,env=env,stdout=log,stderr=log,start_new_session=True)
            try:
                deadline=time.monotonic()+15
                while True:
                    try:
                        if audit.http('GET','/healthz')[0]==200:break
                    except OSError:pass
                    if process.poll() is not None or time.monotonic()>deadline:raise RuntimeError('Private Gunicorn fixture did not start; see private server log')
                    time.sleep(.1)
                audit.matrix();audit.identity_and_csrf();audit.jwt_callbacks();audit.framing()
                if args.post_body_only:audit.slow_deadlines(methods=(),names={'partial-post-body'})
                elif args.all_body_methods:
                    audit.slow_deadlines(('GET','HEAD','OPTIONS','TRACE'))
                    audit.consumed_body_long_response()
                elif args.get_body_only:audit.unread_body_deadline('GET')
                elif not args.skip_slow:audit.slow_deadlines();audit.consumed_body_long_response()
                audit.revocation()
            finally:
                if process.poll() is None:
                    os.killpg(process.pid,signal.SIGTERM)
                    try:process.wait(timeout=10)
                    except subprocess.TimeoutExpired:os.killpg(process.pid,signal.SIGKILL);process.wait(timeout=5)
                from importlib.metadata import version
                report={'transport':'real Gunicorn BoundedThreadWorker/TLS, one worker and four threads','gunicorn_version':version('gunicorn'),'python_version':sys.version.split()[0],'storage':'isolated temporary SQLite','identity':'synthetic Entra records and locally signed RSA tokens; no tenant traffic','source_sha256':source,'slow_deadlines_tested':not args.skip_slow,'maximum_simultaneous_connections':2,'seconds':round(time.monotonic()-audit.started,3),'checks':audit.records,'failed':sum(not row['passed'] for row in audit.records)}
                (output/'controller-dast-results.json').write_text(json.dumps(report,indent=2)+'\n')
        print(json.dumps({'checks':len(audit.records),'failed':report['failed'],'seconds':report['seconds']}),flush=True)
        raise SystemExit(1 if report['failed'] else 0)


if __name__=='__main__':main()
