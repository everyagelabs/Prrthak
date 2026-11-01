"""Current receipt state never regresses to delayed historical authority."""
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
import importlib.util
import json
import os
import threading
import unittest
from unittest.mock import patch

from controller import host_default_deny as deny, managed, server_management
from controller.firewall import WorkflowConflict
from controller.store import digest, now, stamp
from controller.tests import test_host_default_deny as fixture


class ManagedReceiptOrderingTests(unittest.TestCase):
    def make_case(self):
        case=fixture.HostDefaultDenyTests();case.setUp();return case

    def setUp(self):
        self.case=self.make_case();self.addCleanup(self.case.doCleanups)
        self.store=self.case.store
        self.time=now()-timedelta(seconds=40)

    def assignment(self):return self.store.assignment('target')[0]

    def frame(self,policy,status='enforced',second=0,last=None,rules=True):
        return {'status':status,'version':policy['version'],'digest':policy['digest'],'approval_id':policy['enforcement']['approval_id'],
            'last_good_version':last['version'] if last else policy['version'] if status=='enforced' else 0,
            'last_good_digest':last['digest'] if last else policy['digest'] if status=='enforced' else '',
            'updated_at':stamp(self.time+timedelta(seconds=second)),'managed_rules_present':rules,
            'host_default_deny_active':bool((last if status=='rolled_back' and last else policy).get('host_default_deny')),
            **({'rollback_reason':'verified forced rollback'} if status=='rolled_back' else {})}

    def send(self,frame):
        server=self.store.get('servers','target')
        applied=frame['last_good_version'] if frame['status']=='rolled_back' else frame['version']
        self.store.report('target',{'hostname':'target','ips':server['ips'],'listeners':[],'capabilities':server['capabilities'],
            'managed_enforcement':frame,'applied_version':applied,'apply_status':'rolled_back' if frame['status']=='rolled_back' else 'synced'})

    def test_late_enable_after_disable_is_history_only_and_deduplicated(self):
        self.case.push();enabled=self.assignment();self.send(self.frame(enabled,second=1))
        self.case.push('disable');disabled=self.assignment();self.send(self.frame(disabled,second=2))
        before=self.store.get('servers','target')
        late=self.frame(enabled,second=20);self.send(late);self.send(late)
        current=self.store.get('servers','target')
        for key in ('_host_default_deny_active','last_good_version','last_good_digest','managed_enforcement','applied_version','apply_status'):
            self.assertEqual(current.get(key),before.get(key),key)
        self.assertFalse(current['_host_default_deny_active'])
        self.assertEqual(current[deny.STATE]['last_outcome'],before[deny.STATE]['last_outcome'])
        with self.store.read_meta() as db:
            rows=[json.loads(row[0]) for row in db.execute('SELECT data FROM managed_outcomes WHERE server_id=?',('target',))]
        self.assertEqual(sum(row.get('history_only',False) for row in rows),1)

    def test_late_disable_after_newer_enable_cannot_clear_active_or_lastgood(self):
        self.case.push();first=self.assignment();self.send(self.frame(first,second=1))
        self.case.push('disable');disabled=self.assignment();self.send(self.frame(disabled,second=2))
        self.case.push();newer=self.assignment();self.send(self.frame(newer,second=3))
        self.send(self.frame(disabled,second=20))
        current=self.store.get('servers','target')
        self.assertTrue(current['_host_default_deny_active']);self.assertEqual(current['last_good_version'],newer['version'])
        self.assertEqual(current['managed_enforcement']['approval_id'],newer['enforcement']['approval_id'])

    def test_same_version_current_authority_wins_even_when_its_clock_is_older(self):
        self.case.push();first=self.assignment();self.send(self.frame(first,second=10))
        self.case.push();current=self.assignment();self.assertEqual(current['version'],first['version'])
        self.send(self.frame(current,second=5));self.send(self.frame(first,second=20))
        actual=self.store.get('servers','target')
        self.assertEqual(actual['managed_enforcement']['approval_id'],current['enforcement']['approval_id'])
        self.assertEqual(actual['_managed_receipt_cursor']['approval_id'],current['enforcement']['approval_id'])

    def test_same_authority_timestamp_and_phase_order_preserve_current_status(self):
        self.case.push();current=self.assignment();self.send(self.frame(current,second=10))
        self.send(self.frame(current,'staging',second=5))
        self.assertEqual(self.store.get('servers','target')['managed_enforcement']['status'],'enforced')
        self.send(self.frame(current,'staging',second=15))
        self.send(self.frame(current,second=12))
        self.assertEqual(self.store.get('servers','target')['managed_enforcement']['status'],'staging')
        self.send(self.frame(current,second=16));self.send(self.frame(current,'staging',second=16))
        self.assertEqual(self.store.get('servers','target')['managed_enforcement']['status'],'enforced')

    def test_newer_attempt_rollback_can_restore_older_lastgood_without_rearming_retry(self):
        self.case.push();first=self.assignment();self.send(self.frame(first,second=1))
        self.store.save_policy({**self.case.policy,'services':[{'port':8443,'sources':['10.61.0.0/24']}]},self.case.maker['actor'],self.case.policy['id'],principal=self.case.maker)
        self.case.push();attempt=self.assignment();self.assertGreater(attempt['version'],first['version'])
        self.send(self.frame(attempt,'rolled_back',second=2,last=first))
        self.send(self.frame(first,second=20));self.send(self.frame(attempt,second=21))
        current=self.store.get('servers','target')
        self.assertEqual(current['last_good_version'],first['version']);self.assertTrue(current['_host_default_deny_active'])
        self.assertEqual(current['managed_enforcement']['status'],'rolled_back');self.assertEqual(current['_managed_receipt_cursor']['version'],attempt['version'])
        self.assertFalse(self.assignment()['enforcement']['authorized'])
        self.case.push();renewed=self.assignment();self.send(self.frame(renewed,second=22))
        self.assertEqual(self.store.get('servers','target')['last_good_version'],renewed['version'])

    def test_empty_application_removal_retains_controls_until_explicit_cleanup_then_retirement(self):
        self.store.delete_policy(self.case.policy['id'],self.case.maker['actor'])
        self.case.push();enabled=self.assignment();self.send(self.frame(enabled,second=1))
        self.case.push('disable');removed=self.assignment();self.send(self.frame(removed,second=2,rules=True))
        current=self.store.get('servers','target')
        self.assertFalse(current['_host_default_deny_active']);self.assertTrue(current['_managed_rules_active'])
        self.assertTrue(current['_host_default_deny_owned_cleanup_required']);self.assertFalse(self.assignment()['enforcement']['authorized'])
        self.assertFalse(server_management.delete_preview(self.store,'target',self.case.maker['actor'])['can_delete'])
        self.store.create_managed_rollout({'name':'Explicit ordinary cleanup','server_ids':['target']},self.case.maker['actor'],principal=self.case.maker)
        cleanup=self.assignment();self.assertEqual(cleanup['enforcement']['intent'],'remove_managed_rules')
        self.send(self.frame(cleanup,second=3,rules=False))
        self.assertFalse(self.store.get('servers','target')['_managed_rules_active'])
        self.send(self.frame(removed,second=19,rules=True))
        self.assertFalse(self.store.get('servers','target')['_managed_rules_active'])
        self.send(self.frame(enabled,second=20))
        self.assertTrue(server_management.delete_preview(self.store,'target',self.case.maker['actor'])['can_delete'])

    def test_verified_cancel_before_first_apply_does_not_invent_owned_rules(self):
        self.store.delete_policy(self.case.policy['id'],self.case.maker['actor'])
        self.case.push();self.case.push('disable');removed=self.assignment()
        self.send(self.frame(removed,second=2,rules=False))
        current=self.store.get('servers','target')
        self.assertFalse(current['_managed_rules_active']);self.assertFalse(current['_host_default_deny_active'])
        self.assertFalse(current.get('_host_default_deny_owned_cleanup_required'))


@unittest.skipUnless(os.environ.get('PRTHAK_PLATFORM_PG_ACCEPTANCE')=='1' and importlib.util.find_spec('psycopg'), 'Enable private PostgreSQL platform acceptance fixtures')
class HostDefaultDenyPostgresTests(ManagedReceiptOrderingTests):
    def make_case(self):
        import psycopg
        from psycopg import sql
        from psycopg.conninfo import make_conninfo
        from controller.postgres import PostgresStore
        from controller.tests import private_pg
        from controller.tests import test_approvals as approval_fixture
        parameters,expected=private_pg.configuration()
        admin=make_conninfo(**parameters,dbname='postgres')
        names=private_pg.names('hostdeny')
        owned=[]
        def cleanup():
            with psycopg.connect(admin,autocommit=True) as connection:
                for name in owned:connection.execute(sql.SQL('DROP DATABASE {} WITH (FORCE)').format(sql.Identifier(name)))
        self.addCleanup(cleanup)
        with psycopg.connect(admin,autocommit=True) as connection:
            identity,directory=connection.execute("SELECT current_user,current_setting('data_directory')").fetchone()
            if identity!='prthak_test' or private_pg.ROOT.joinpath(directory).resolve()!=expected:raise RuntimeError('Wrong private PostgreSQL fixture')
            for name in names.values():
                if connection.execute('SELECT 1 FROM pg_database WHERE datname=%s',(name,)).fetchone():raise RuntimeError('Never adopt an existing database')
                connection.execute(sql.SQL('CREATE DATABASE {}').format(sql.Identifier(name)));owned.append(name)
        self.pg_metadata=make_conninfo(**parameters,dbname=names['metadata']);self.pg_traffic=make_conninfo(**parameters,dbname=names['traffic'])
        pg=PostgresStore(self.pg_metadata,self.pg_traffic)
        self.addCleanup(pg.close_worker_pool)
        with patch.object(approval_fixture,'Store',return_value=pg):
            case=fixture.HostDefaultDenyTests();case.setUp()
        return case

    def test_postgresql_scalar_projection_empty_scope_and_source_canary(self):
        self.case.test_explicit_empty_filter_is_zero_and_status_never_decodes_snapshots()
        self.case.push();page=deny.listing(self.store,{'server_ids':['target'],'limit':1})
        self.assertEqual(page['items'][0]['status'],'pending')
        self.assertEqual(page['items'][0]['server_id'],'target')

    def test_postgresql_concurrent_reviews_are_serialized(self):
        from controller.postgres import PostgresStore
        first,second=self.case.preview(),self.case.preview()
        stores=[PostgresStore(self.pg_metadata,self.pg_traffic,initialize=False) for _ in range(2)]
        for store in stores:
            store.approval_auth_fingerprint=self.case.config.fingerprint;store.approval_tenant_id=self.case.config.tenant_id
            self.addCleanup(store.close_worker_pool)
        barrier=threading.Barrier(2)
        def push(pair):
            store,plan=pair;barrier.wait()
            try:deny.confirm(store,plan['id'],self.case.confirmation(plan),self.case.maker['actor'],self.case.maker);return 'committed'
            except WorkflowConflict:return 'conflict'
        with ThreadPoolExecutor(max_workers=2) as workers:results=list(workers.map(push,zip(stores,(first,second))))
        self.assertCountEqual(results,['committed','conflict'])
        self.assertEqual(self.store.get('servers','target')[deny.STATE]['revision'],1)
