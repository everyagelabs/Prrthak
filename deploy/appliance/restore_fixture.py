"""TEST ONLY real PostgreSQL16 custom-dump recovery through fixed host actions.

The private fixed mTLS bridge replaces Docker exec/signals only. This is host
staging/restore proof, not the all-controller RuntimeSupervisor protocol test.
"""
import hashlib
import http.client
import json
import os
from pathlib import Path
import secrets
import ssl
import subprocess
import sys
import tempfile
import time

sys.path[:0]=['/opt/prthak','/app']
import node_manager as n
import psycopg


def main():
    addresses=json.loads(sys.argv[1]);writer=int(sys.argv[2]);base=Path('/var/lib/prthak');manifests=[n.load(base/str(i)/'config/manifest.json') for i in range(3)]
    deployment=manifests[0]['deployment_id'];identifier=secrets.token_hex(16);fence=secrets.token_hex(32)
    def connect(index,kind,target=False):
        manifest=manifests[index];name='prthak_restore_'+identifier+'_'+kind if target else manifest['database'][kind+'_name']
        return psycopg.connect(host=addresses[index],dbname=name,user=manifest['database'][kind+'_user'],password=manifest['secrets'][kind],sslmode='verify-full',sslrootcert=str(base/str(index)/'config/database/ca.pem'),connect_timeout=5,options='-c statement_timeout=20000',autocommit=True)
    for kind in ('metadata','traffic'):
        with connect(writer,kind) as db:
            db.execute('CREATE TABLE runtime_deployment(id text PRIMARY KEY,data text NOT NULL)')
            db.execute('INSERT INTO runtime_deployment VALUES(%s,%s)',('active',json.dumps({'namespace':kind,'deployment_id':deployment,'epoch':1,'state':'READY','import_id':'initial-private-fixture','source_fingerprint':'private-fixture'})))
            db.execute('CREATE TABLE prthak_restore_fixture(id integer PRIMARY KEY,value text NOT NULL)')
            db.execute('INSERT INTO prthak_restore_fixture VALUES(1,%s)',('original-'+kind,))
    with tempfile.TemporaryDirectory(prefix='private-recovery-') as temporary:
        paths={kind:Path(temporary)/(kind+'.dump') for kind in ('metadata','traffic')}
        def program(kind,restore=False):
            manifest=manifests[writer];env={key:os.environ[key] for key in ('PATH','LANG','LC_ALL') if key in os.environ}
            env.update(PGHOST=addresses[writer],PGPORT='5432',PGUSER=manifest['database'][kind+'_user'],PGPASSWORD=manifest['secrets'][kind],PGDATABASE='prthak_restore_'+identifier+'_'+kind if restore else manifest['database'][kind+'_name'],PGSSLMODE='verify-full',PGSSLROOTCERT=str(base/str(writer)/'config/database/ca.pem'))
            arguments=['pg_restore','--no-owner','--no-privileges','--single-transaction','--exit-on-error','--dbname='+env['PGDATABASE'],str(paths[kind])] if restore else ['pg_dump','--format=custom','--no-owner','--no-privileges','--file='+str(paths[kind])]
            result=subprocess.run(arguments,env=env,capture_output=True,timeout=60)
            if result.returncode:raise AssertionError('Bounded private pg_dump/pg_restore failed: '+result.stderr.decode()[-1000:])
        for kind in paths:program(kind)
        archive=hashlib.sha256(b''.join(paths[kind].read_bytes() for kind in ('metadata','traffic'))).hexdigest()
        for kind in paths:
            with connect(writer,kind) as db:
                marker=json.loads(db.execute("SELECT data FROM runtime_deployment WHERE id='active'").fetchone()[0]);marker.update(state='FENCED_RECOVERY',recovery_id=identifier,recovery_fence_digest=fence)
                db.execute("UPDATE runtime_deployment SET data=%s WHERE id='active'",(json.dumps(marker),))
        for i in range(3):
            for kind in paths:
                for attempt in range(20):
                    with connect(i,kind) as db:marker=json.loads(db.execute("SELECT data FROM runtime_deployment WHERE id='active'").fetchone()[0])
                    if marker.get('state')=='FENCED_RECOVERY':break
                    time.sleep(.25)
                else:raise AssertionError('Physical replica did not replay source fence')
        class Engine:
            def __init__(self,root,*args):self.root=Path(root);self.index=int(self.root.name)
            def states(self):return {'database':'running','etcd':'running'}
            def rpc(self,path,payload):
                context=ssl.create_default_context(cafile=str(self.root/'config/database/ca.pem'));context.load_cert_chain(self.root/'config/database/node.pem',self.root/'config/database/node-key.pem')
                peer=http.client.HTTPSConnection(addresses[self.index],9009,context=context,timeout=60);peer.request('POST',path,json.dumps(payload),{'Content-Type':'application/json'})
                response=peer.getresponse();result=json.loads(response.read());peer.close()
                if response.status!=200:raise n.Blocked('Fixed private recovery helper failed: '+result.get('code','unknown'))
                return result
            def restore_database_helper(self,payload):return self.rpc('/fixed-restore-helper',payload)
            def compose(self,arguments,**kwargs):
                if arguments[:3]==['kill','--signal','SIGHUP']:assert self.rpc('/fixed-internal-reload',{})['reloaded']
                elif arguments[:3]!=['exec','-T','database']:raise n.Blocked('Unexpected private fixture command')
                return ''
        class FixtureManager(n.Manager):
            def render(self):
                super().render();path=self.root/'config/database/patroni.json';config=n.load(path)
                assert config['watchdog']['mode']=='required'
                config['watchdog']['mode']='off';n.atomic(path,config,owner=999)
        managers=[FixtureManager(base/str(i),engine_factory=Engine) for i in range(3)]
        common={'action':'restore-databases','restore_id':identifier,'deployment_id':deployment,'archive_sha256':archive,'fence_digest':fence,'target_epoch':2,'all_writers_fenced':True}
        def phase(index,name,**extra):
            manager=managers[index]
            for attempt in range(10):
                request={**common,**extra,'request_id':secrets.token_hex(16),'expected_revision':manager.state()['revision'],'phase':name}
                receipt=manager.submit(request);manager.work_once();job=manager.job(receipt['id'])
                if job['status']=='completed':return job['result']
                time.sleep(1)
            raise AssertionError('Fixed private manager phase did not complete: '+str(job))
        for i in range(3):assert phase(i,'prepare')['prepared']
        replica=(writer+1)%3;assert phase(replica,'create')['not_primary']
        assert phase(writer,'create')['empty']
        for kind in paths:
            program(kind,restore=True)
            with connect(writer,kind,True) as db:
                assert db.execute('SHOW is_superuser').fetchone()[0]=='off'
                assert db.execute('SELECT value FROM prthak_restore_fixture WHERE id=1').fetchone()[0]=='original-'+kind
                marker={'namespace':kind,'deployment_id':deployment,'epoch':2,'state':'VERIFIED','import_id':identifier,'source_fingerprint':'private-post-restore-proof'}
                db.execute("UPDATE runtime_deployment SET data=%s WHERE id='active'",(json.dumps(marker),))
        for i in range(3):assert phase(i,'verify')['new_connections']
        for i in range(3):assert phase(i,'finalize',all_profile_acks=True)['original_databases_preserved']
        for i in range(3):
            assert phase(i,'finalize',all_profile_acks=True)['finalized']
            for kind in paths:
                with connect(i,kind) as db:
                    assert db.execute('SELECT value FROM prthak_restore_fixture WHERE id=1').fetchone()[0]=='original-'+kind
                    assert json.loads(db.execute("SELECT data FROM runtime_deployment WHERE id='active'").fetchone()[0])['state']=='FENCED_RECOVERY'
                with connect(i,kind,True) as db:assert db.execute('SELECT value FROM prthak_restore_fixture WHERE id=1').fetchone()[0]=='original-'+kind
        print('actual3 voters: fenced BOTH source namespaces, derived EMPTY restricted-owner candidates, nonprimary refusal, pg_dump→non-superuser pg_restore→new epoch/readback, finalized/retried with originals+oldHBA preserved: PASS')
        print('This validates host recovery staging only; all-controller supervisor fencing/profile ACKs and native watchdog/site-loss remain separate acceptance gates')


if __name__=='__main__':main()
