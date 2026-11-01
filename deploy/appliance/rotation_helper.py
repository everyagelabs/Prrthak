"""Fixed in-container replication-role operations; private input is stdin only."""
import base64
import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import sys

import psycopg
from psycopg import pq
from psycopg import sql


def verifier(password):
    salt=os.urandom(16);salted=hashlib.pbkdf2_hmac('sha256',password.encode(),salt,4096)
    stored=hashlib.sha256(hmac.new(salted,b'Client Key',hashlib.sha256).digest()).digest();server=hmac.new(salted,b'Server Key',hashlib.sha256).digest()
    encoded=lambda value:base64.b64encode(value).decode()
    return 'SCRAM-SHA-256$4096:'+encoded(salt)+'$'+encoded(stored)+':'+encoded(server)


def matches(password,stored):
    try:
        scheme,parameters,keys=stored.split('$');iterations,salt=parameters.split(':');stored_key,server_key=keys.split(':')
        if scheme!='SCRAM-SHA-256' or not 4096<=int(iterations)<=1000000:return False
        salted=hashlib.pbkdf2_hmac('sha256',password.encode(),base64.b64decode(salt),int(iterations))
        computed=hashlib.sha256(hmac.new(salted,b'Client Key',hashlib.sha256).digest()).digest()
        return hmac.compare_digest(computed,base64.b64decode(stored_key))
    except (ValueError,TypeError,AttributeError):return False


def main():
    payload=sys.stdin.buffer.read(4097)
    if len(payload)>4096:raise ValueError()
    request=json.loads(payload);password=request.get('password')
    if set(request)-{'action','password','primary_ip'} or not isinstance(password,str) or not 32<=len(password)<=128 or any(ord(value)<32 or ord(value)>126 for value in password):raise ValueError()
    private=json.loads(Path('/config/roles.json').read_text())
    options={'sslmode':'verify-full','sslrootcert':'/config/ca.pem','connect_timeout':5,'autocommit':True,'options':'-c statement_timeout=10000 -c lock_timeout=3000'}
    if request['action']=='change-role':
        with psycopg.connect(host='127.0.0.1',dbname='postgres',user='prthak_admin',password=private['secrets']['admin'],**options) as db:
            if db.execute('SELECT pg_is_in_recovery()').fetchone()[0]:return {'status':'not_primary','not_primary':True,'mutated':False}
            old=db.execute("SELECT rolpassword FROM pg_authid WHERE rolname='prthak_replication'").fetchone()
            if old is None:raise ValueError()
            changed=not matches(password,old[0])
            # Reconfirm the exact verifier through a synchronous catalog write
            # even after an earlier client timeout: a local match alone cannot
            # prove that the role change reached the synchronous replica.
            db.execute(sql.SQL('ALTER ROLE prthak_replication PASSWORD {}').format(sql.Literal(verifier(password) if changed else old[0])))
            return {'status':'role_changed','not_primary':False,'mutated':True,'credential_changed':changed,'synchronous_commit_confirmed':True}
    if request['action']=='probe':
        address=str(ipaddress.IPv4Address(request['primary_ip']))
        configuration=json.loads(Path('/config/patroni.json').read_text())
        if address not in {value.rsplit(':',1)[0] for value in configuration['etcd3']['hosts']}:raise ValueError()
        options.pop('options')
        if address==configuration['postgresql']['connect_address'].rsplit(':',1)[0]:
            # Keep TLS verification bound to the approved IP SAN, while a
            # local-primary probe stays inside this PG network namespace and
            # avoids Docker hairpin NAT changing its HBA source identity.
            options['hostaddr']='127.0.0.1'
        with psycopg.connect(host=address,dbname='replication',user='prthak_replication',password=password,replication='true',**options) as db:
            # Replication protocol accepts simple-query messages only. The
            # regular cursor can select extended-query protocol on some driver
            # versions, so issue this exact fixed command through libpq.
            result=db.pgconn.exec_(b'IDENTIFY_SYSTEM')
            if result.status!=pq.ExecStatus.TUPLES_OK or result.ntuples!=1:raise ValueError('replication identity response unavailable')
            system=result.get_value(0,0).decode()
        options.pop('hostaddr',None)
        with psycopg.connect(host='127.0.0.1',dbname='postgres',user='prthak_admin',password=private['secrets']['admin'],**options) as db:
            expected=str(db.execute('SELECT system_identifier FROM pg_control_system()').fetchone()[0])
        if system!=expected:raise ValueError()
        return {'status':'verified','verified':True,'new_connection':True,'system_identifier':system}
    raise ValueError()


if __name__=='__main__':
    try:result=main()
    except Exception as error:
        code=getattr(error,'sqlstate',None) or type(error).__name__
        print(json.dumps({'status':'error','code':code,'error':'Fixed replication operation failed; no private input was exposed'}));raise SystemExit(1)
    print(json.dumps(result,separators=(',',':')))
