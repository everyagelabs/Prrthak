"""Fixed initial role creation; never accepts SQL or credentials in arguments."""
import json
import base64
import hashlib
import hmac
import os
from pathlib import Path
import psycopg
from psycopg import sql

private = json.loads(Path('/config/roles.json').read_text())
def scram(password):
    salt=os.urandom(16);salted=hashlib.pbkdf2_hmac('sha256',password.encode(),salt,4096)
    stored=hashlib.sha256(hmac.new(salted,b'Client Key',hashlib.sha256).digest()).digest()
    server=hmac.new(salted,b'Server Key',hashlib.sha256).digest()
    encode=lambda value:base64.b64encode(value).decode()
    return 'SCRAM-SHA-256$4096:'+encode(salt)+'$'+encode(stored)+':'+encode(server)
with psycopg.connect(host='127.0.0.1', dbname='postgres', user='prthak_admin',
        password=private['secrets']['admin'], sslmode='verify-full',
        sslrootcert='/config/ca.pem', autocommit=True, connect_timeout=5) as db:
    # No application data exists during Patroni's initial bootstrap. Do not wait
    # for not-yet-cloned replicas while creating their initial cluster roles.
    db.execute("SET synchronous_commit=local")
    db.execute("SET statement_timeout='30s'")
    for kind in ('metadata', 'traffic'):
        role, name = private['database'][kind + '_user'], private['database'][kind + '_name']
        if not db.execute('SELECT 1 FROM pg_roles WHERE rolname=%s', (role,)).fetchone():
            db.execute(sql.SQL('CREATE ROLE {} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION PASSWORD {}').format(sql.Identifier(role), sql.Literal(scram(private['secrets'][kind]))))
        if not db.execute('SELECT 1 FROM pg_database WHERE datname=%s', (name,)).fetchone():
            db.execute(sql.SQL('CREATE DATABASE {} OWNER {} TEMPLATE template0').format(sql.Identifier(name), sql.Identifier(role)))
        db.execute(sql.SQL('REVOKE ALL ON DATABASE {} FROM PUBLIC').format(sql.Identifier(name)))
