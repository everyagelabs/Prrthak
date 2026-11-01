import copy
import unittest
from unittest.mock import patch

from controller import approvals, learning_policies as policies, review_limits
from controller.tests import test_approvals as approval_fixture
from controller.tests import test_learning_policies as policy_fixture


class LearningReviewLimitsTests(unittest.TestCase):
    def fixture(self, case_type=policy_fixture.LearningPolicyTests):
        case = case_type()
        case.setUp()
        self.addCleanup(case.doCleanups)
        return case

    @staticmethod
    def counts(store):
        with store.read_meta() as db:
            return tuple(db.execute('SELECT COUNT(*) FROM ' + table).fetchone()[0]
                         for table in ('learning_policy_previews', 'learning_allow_policies', 'audit'))

    def test_recommendation_stops_before_next_target_and_persists_no_partial_review(self):
        case = self.fixture()
        session = case.session(auto=False)
        case.batch(session, [('10.20.0.1', 80, 1)])
        evidence = policies.recommendations(case.store, session['id'])['rows']
        before, visited = self.counts(case.store), []
        original = policies._capacity_error
        def checked(server, services):
            visited.append(server['id'])
            return original(server, services)
        with patch.object(review_limits, 'MAX_REVIEW_BYTES', 64), patch.object(policies, '_capacity_error', side_effect=checked):
            with self.assertRaisesRegex(ValueError, '8 MiB'):
                policies.preview(case.store, session['id'], {'name': 'Bounded review', 'row_ids': [row['id'] for row in evidence], 'server_ids': ['a', 'b'], 'expected_evidence_revision': case.store.get('sessions', session['id'])['evidence_revision']}, 'admin')
        self.assertEqual(visited, ['a'])
        self.assertEqual(self.counts(case.store), before)

    def test_group_scope_uses_exact_location_and_omits_unrelated_firewall_matrices(self):
        case = self.fixture()
        location = case.store.save_location({'name': 'Noida 81', 'type': 'datacenter', 'location': 'Noida, India'}, 'admin')
        case.store.update_server('a', {'location_id': location['id']}, 'admin')
        group = case.store.save_group({'name': 'Noida servers', 'type': 'dynamic', 'selector': {'location_id': location['id']}}, 'admin')
        session = case.session(auto=False)
        case.batch(session, [('10.20.0.1', 80, 1)])
        rows = policies.recommendations(case.store, session['id'])['rows']
        original = case.store._all
        def no_global_servers(db, table):
            if table == 'servers':
                raise AssertionError('A review must not decode every canonical firewall snapshot')
            return original(db, table)
        with patch.object(case.store, '_all', side_effect=no_global_servers):
            plan = policies.preview(case.store, session['id'], {'name': 'Exact Noida scope', 'row_ids': [row['id'] for row in rows], 'group_ids': [group['id']], 'expected_evidence_revision': case.store.get('sessions', session['id'])['evidence_revision']}, 'admin')
        self.assertEqual(plan['target_server_ids'], ['a'])
        self.assertEqual(plan['services'], [{'port': 80, 'protocol': 'tcp', 'sources': ['10.20.0.1/32']}])
        self.assertEqual(plan['target_fingerprints']['a'], policies._target_fingerprint(case.store.get('servers', 'a')))

    def test_all_learning_preview_writes_have_exact_storage_byte_guard(self):
        case = self.fixture()
        before = self.counts(case.store)
        with patch.object(review_limits, 'MAX_REVIEW_BYTES', 32):
            with case.store.meta() as db, self.assertRaisesRegex(ValueError, '8 MiB'):
                case.store._put(db, 'learning_policy_previews', {'id': 'oversized', 'name': '漢' * 20})
        self.assertEqual(self.counts(case.store), before)

    def test_initial_review_rejects_large_enclosing_session_without_authority_or_audit(self):
        case = self.fixture(approval_fixture.IndependentApprovalTests)
        session = case.learned_session(auto=True)
        case.discover_and_hit(session)
        with case.store.meta() as db:
            stored = case.store._get(db, 'sessions', session['id'])
            stored['isolated_test_padding'] = 'x' * 200000
            case.store._put(db, 'sessions', stored)
        before, counts = copy.deepcopy(case.store.get('sessions', session['id'])), self.counts(case.store)
        with patch.object(review_limits, 'MAX_REVIEW_BYTES', 100000):
            with self.assertRaisesRegex(ValueError, '8 MiB'):
                approvals.learning_preview(case.store, session['id'], {}, case.maker['actor'], case.maker)
        self.assertEqual(case.store.get('sessions', session['id']), before)
        self.assertEqual(self.counts(case.store), counts)

