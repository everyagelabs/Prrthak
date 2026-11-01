import tempfile
import unittest
import sqlite3
from controller import recovery
from controller.store import Store,digest,stamp


class RecoveryAuthorityTests(unittest.TestCase):
    def test_current_provider_survives_but_pilot_and_pending_kits_cannot_rearm(self):
        with tempfile.TemporaryDirectory() as directory:
            store=Store(directory)
            with store.meta() as db:
                authority={'id':'controller_provider_authority','fingerprint':'current','epoch':'current-epoch'}
                store._put(db,'maintenance_settings',authority)
                store._put(db,'maintenance_settings',{'id':'approval_settings','revision':9,'mode':'single_admin_pilot','server_ids':['x'],'expires_at':'2099-01-01T00:00:00Z','membership_digest':digest({}),'provider_authority':{'fingerprint':'current','epoch':'current-epoch'}})
                store._put(db,'endpoint_configuration_reviews',{'id':'review-current','status':'approved'})
                store._put(db,'maintenance_settings',{'id':'platform_join:used','consumed':True,'sealed_response':{'fixture':'immutable'}})
                safety=recovery._safety(db)
                store._put(db,'maintenance_settings',{'id':'controller_provider_authority','fingerprint':'old','epoch':'old-epoch'})
                store._put(db,'maintenance_settings',{'id':'approval_settings','revision':1,'mode':'single_admin_pilot','server_ids':['old']})
                store._put(db,'maintenance_settings',{'id':'platform_join:old-unused','consumed':False})
                recovery._overlay_safety(db,safety,'test-recovery')
                self.assertEqual(store._get(db,'maintenance_settings',authority['id']),authority)
                pilot=store._get(db,'maintenance_settings','approval_settings')
                self.assertEqual((pilot['revision'],pilot['mode'],pilot['server_ids']),(10,'two_person',[]))
                self.assertEqual(store._get(db,'endpoint_configuration_reviews','review-current')['status'],'revoked')
                self.assertIsNone(store._get(db,'maintenance_settings','platform_join:old-unused'))
                self.assertEqual(store._get(db,'maintenance_settings','platform_join:used')['sealed_response'],{'fixture':'immutable'})

    def test_recovery_refuses_an_inflight_provider_transition(self):
        with tempfile.TemporaryDirectory() as directory:
            store=Store(directory)
            with store.meta() as db:
                store._put(db,'maintenance_settings',{'id':'controller_provider_transition','phase':'apply'})
                with self.assertRaises(recovery.RecoveryError):recovery._exclude_port_transition(store,db)

    def test_fresh_sqlite_recovery_check_excludes_a_second_writer(self):
        with tempfile.TemporaryDirectory() as directory:
            store=Store(directory);peer=Store(directory)
            with store.meta() as db:
                self.assertFalse(db.in_transaction)
                recovery._exclude_port_transition(store,db)
                self.assertTrue(db.in_transaction)
                with peer.meta() as other:
                    other.execute('PRAGMA busy_timeout=1')
                    with self.assertRaisesRegex(sqlite3.OperationalError,'locked'):
                        peer._put(other,'maintenance_settings',{'id':'controller_provider_transition','phase':'apply'})
