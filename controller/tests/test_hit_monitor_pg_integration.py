"""Opt-in actual PG; UUID-owned databases only, never shared literal fixtures."""
from datetime import timedelta
import hashlib
import json
import os
from pathlib import Path
import unittest
import uuid
from unittest.mock import patch

from controller import hit_monitoring as hm
from controller.store import now, stamp


@unittest.skipUnless(os.environ.get('PRTHAK_HIT_MONITOR_PG_ACCEPTANCE') == '1', 'Actual private PostgreSQL opt-in required')
class HitMonitorPostgres(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import psycopg
        from psycopg import sql
        from psycopg.conninfo import make_conninfo
        from controller.postgres import PostgresStore
        cls.psycopg, cls.sql = psycopg, sql
        cls.admin_dsn = os.environ.get('PRTHAK_PG_TEST_ADMIN_DSN') or make_conninfo(host=str(Path.cwd()/'.local/pilot-0.7/pg-socket'), port=55434, user='prthak_test', dbname='postgres')
        suffix = uuid.uuid4().hex[:12]
        cls.names = ['prthak_test_hits_' + suffix + '_' + namespace for namespace in ('metadata','traffic')]
        cls.created = []
        try:
            with psycopg.connect(cls.admin_dsn, autocommit=True) as connection:
                for name in cls.names:
                    connection.execute(sql.SQL('CREATE DATABASE {}').format(sql.Identifier(name))); cls.created.append(name)
            cls.store = PostgresStore(*(make_conninfo(cls.admin_dsn, dbname=name) for name in cls.names))
        except BaseException:
            cls.tearDownClass(); raise

    @classmethod
    def tearDownClass(cls):
        with cls.psycopg.connect(cls.admin_dsn, autocommit=True) as connection:
            for name in cls.created:
                if not name.startswith('prthak_test_hits_'): raise AssertionError('Unowned test database')
                connection.execute(cls.sql.SQL('DROP DATABASE {} WITH (FORCE)').format(cls.sql.Identifier(name)))

    def make(self, identifier):
        self.store.report(identifier, {'hostname': identifier, 'ips': ['192.0.2.9'], 'listeners': [{'port':443,'protocol':'tcp','service':'HTTPS'}], 'capabilities':['signed_assignments_v1',hm.CAPABILITY], 'agent_version':'0.7.0','firewalld_state':'running'})
        plan = hm.preview(self.store, {'name':'Actual PG logs', 'selection':{'server_ids':[identifier]}, 'ports':[{'port':443,'protocol':'tcp'}], 'retention_hours':1}, 'fixture')
        monitor = hm.apply(self.store, {'preview_id':plan['id'],**{key:plan[key] for key in ('digest','confirmation_nonce','confirmation_phrase')}}, 'fixture')
        with self.store.read_meta() as db:
            lease = hm.assignments(self.store, db, self.store._get(db,'servers',identifier))[0]
        return monitor, lease

    def test_actual_schema_assignment_and_namespace_readiness(self):
        monitor, lease = self.make('pg-hit-schema')
        self.assertTrue(all(self.store.readiness().values()))
        self.assertEqual(lease['server_id'], 'pg-hit-schema')
        self.assertEqual(hm.target_page(self.store,monitor['id'])['total'],1)
        with self.store.read_meta() as db:
            self.assertIsNotNone(db.execute("SELECT indexname FROM pg_indexes WHERE indexname='hit_reviews_expiry'").fetchone())

    def test_actual_ipv6_queue_dedup_csv_and_retention_accounting(self):
        monitor, lease = self.make('pg-hit-data')
        point=stamp(now())
        body={'batch_id':'pg-log','monitor_id':monitor['id'],'lease_starts_at':lease['starts_at'],'lease_expires_at':lease['expires_at'],'events':[{'event_id':hashlib.sha256(b'pg-cursor').hexdigest(),'source_ip':'2001:db8::44','port':443,'protocol':'tcp','count':1,'verdict':'observed','first_seen':point,'last_seen':point}]}
        self.assertEqual(hm.enqueue(self.store,'pg-hit-data',body)['accepted'],1)
        self.assertTrue(hm.enqueue(self.store,'pg-hit-data',body)['duplicate'])
        hm.process(self.store)
        self.assertEqual(hm.hits(self.store,monitor['id'])['items'][0]['source_ip'],'2001:db8::44')
        with hm.csv_spool(self.store,monitor['id']) as (source,size):self.assertIn(b'2001:db8::44',source.read())
        with patch.object(hm,'now',return_value=now()+timedelta(hours=2)):hm.prune(self.store)
        self.assertEqual(hm.listing(self.store)['storage_budget']['event_count'],0)

    def test_actual_stop_receipt_and_no_implicit_access_policy(self):
        monitor, lease = self.make('pg-hit-stop')
        plan=hm.stop_preview(self.store,monitor['id'],{'expected_revision':1},'fixture')
        hm.apply(self.store,{'preview_id':plan['id'],**{key:plan[key] for key in ('digest','confirmation_nonce','confirmation_phrase')}},'fixture')
        with self.store.meta() as db:
            server=self.store._get(db,'servers','pg-hit-stop')
            self.assertTrue(hm.retirement_blockers(self.store,db,server))
            hm.report_status(self.store,db,server,{'hit_monitoring':[{'id':monitor['id'],'status':'off','checked_at':stamp(now())}]})
            self.assertEqual(hm.retirement_blockers(self.store,db,server),[])
            self.assertEqual(db.execute('SELECT COUNT(*) FROM learning_allow_policies').fetchone()[0],0)
        self.assertEqual(hm.target_page(self.store,monitor['id'])['items'][0]['last_outcome']['status'],'off')

    def test_two_stores_serialize_first_sparse_quota_admission(self):
        from concurrent.futures import ThreadPoolExecutor
        import threading
        from controller.postgres import PostgresStore
        from psycopg.conninfo import make_conninfo
        other = PostgresStore(*(make_conninfo(self.admin_dsn, dbname=name) for name in self.names))
        fixtures = []
        for identifier in ('pg-first-one', 'pg-first-two'):
            monitor, lease = self.make(identifier)
            point = stamp(now())
            fixtures.append((identifier, {'batch_id':identifier, 'monitor_id':monitor['id'], 'lease_starts_at':lease['starts_at'], 'lease_expires_at':lease['expires_at'], 'events':[{'event_id':hashlib.sha256(identifier.encode()).hexdigest(),'source_ip':'192.0.2.70','port':443,'protocol':'tcp','verdict':'observed','count':1,'first_seen':point,'last_seen':point}]}))
        with self.store.traffic() as db:
            db.execute('DELETE FROM hit_events'); db.execute('DELETE FROM hit_batches'); db.execute('DELETE FROM hit_limits')
        gate = threading.Barrier(2)
        def upload(item):
            store, fixture = item
            gate.wait(timeout=5)
            try: hm.enqueue(store, fixture[0], fixture[1]); return 'accepted'
            except RuntimeError: return 'full'
        with patch.object(hm, 'MAX_STORED_EVENTS', 1), ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(upload, [(self.store, fixtures[0]), (other, fixtures[1])]))
        self.assertCountEqual(outcomes, ['accepted', 'full'])
        with self.store.read_traffic() as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM hit_events').fetchone()[0], 1)
            self.assertEqual(hm._usage(db)['events'], 1)

    def test_actual_sql_projects_large_group_history_before_decode(self):
        monitor, lease = self.make('pg-summary-history')
        groups = ['unrequested-group-' + str(index) + '-' + 'x' * 80 for index in range(10000)]
        with self.store.meta() as db:
            canonical = self.store._get(db, 'hit_monitors', monitor['id'])
            canonical['selection_summary']['group_ids'] = groups
            self.store._put(db, 'hit_monitors', canonical)
        original = json.loads
        def bounded_load(value, *args, **kwargs):
            if isinstance(value, str) and 'unrequested-group-' in value:
                raise AssertionError('Historical membership reached Python JSON decoding')
            return original(value, *args, **kwargs)
        with patch.object(hm.json, 'loads', side_effect=bounded_load):
            page = hm.listing(self.store, limit=100)
            selected = next(item for item in page['items'] if item['id'] == monitor['id'])
            self.assertNotIn('group_ids', selected['selection_summary'])
            self.assertNotIn('group_ids', hm.hits(self.store, monitor['id'])['monitor']['selection_summary'])
            with self.store.read_meta() as db:
                assigned = hm.assignments(self.store, db, self.store._get(db, 'servers', 'pg-summary-history'))
                self.assertEqual(assigned[0]['ports'], monitor['ports'])
        self.assertEqual(self.store.get('hit_monitors', monitor['id'])['selection_summary']['group_ids'], groups)
        self.assertEqual(hm.target_page(self.store, monitor['id'])['total'], 1)
