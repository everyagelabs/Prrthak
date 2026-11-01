import copy
import socket
import threading
import unittest
from unittest.mock import patch

from controller import application_port as port
from controller.platform import _private_json, _read_json
from controller.platform_runtime import _argument
from controller.store import digest
from controller.tests import test_recovery as fixture


def free_port():
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        return listener.getsockname()[1]


class Process:
    def __init__(self, failed=False):
        self.failed = failed

    def poll(self):
        return 1 if self.failed else None


class Supervisor:
    def __init__(self, test, fail=False):
        self.test, self.manager = test, test.manager
        self.arguments = ['--listen', '127.0.0.1:' + str(test.old)]
        self.child, self.current_profile = Process(), None
        self.stopping, self.fail = threading.Event(), fail
        self.starts, self.stops = [], 0
        self.probe = lambda arguments, profile: True
        self._certificate_matches = lambda arguments, hostname, fingerprint: True

    def stop(self, child):
        self.stops += 1
        return True

    def start_child(self, profile=None, arguments=None, *, application_port_override=None):
        actual = port.launch_arguments(self.manager, self.arguments if arguments is None else arguments, application_port_override)
        value = int(_argument(actual, '--listen').rsplit(':', 1)[1])
        self.starts.append(value)
        self.last_launch_arguments = actual
        self.child = Process(self.fail and value == self.test.new)
        self.manager.app.application_listen = _argument(actual, '--listen')
        return actual


class FixedPublisher:
    def __init__(self, old, failure=False, lost_commit=False):
        self.port, self.old, self.failure, self.lost_commit = old, old, failure, lost_commit
        self.phase, self.operation, self.jobs, self.requests = None, None, {}, []

    def status(self):
        return {'capabilities': ['public_port_v1'], 'revision': 8 if self.phase == 'committed' else 7, 'appliance_id': 'private-fixed-publisher', 'public_port': self.port, 'bind_address': '127.0.0.1', 'public_listener': {'operation_id': self.operation, 'phase': self.phase, 'container_port': 8787, 'backend_port': 8786}}

    def job(self, identifier):
        if identifier not in self.jobs:
            raise KeyError(identifier)
        return self.jobs[identifier]

    def submit(self, body):
        self.requests.append(copy.deepcopy(body))
        self.operation = body['operation_id']
        phase = body['phase']
        bound = {'kind': 'prthak-public-port-v1', 'operation_id': self.operation, 'appliance_id': 'private-fixed-publisher', 'base_revision': 7, 'old_port': body['old_port'], 'new_port': body['new_port'], 'bind_address': '127.0.0.1', 'expected_fingerprint': body['expected_fingerprint'], 'server_name': body['server_name'], 'controller_origin': body['controller_origin'], 'origin_mode': 'preserve'}
        result = {'binding_digest': digest(bound)}
        if phase == 'verify' and self.failure:
            value = {'status': 'error', 'result': {}}
        else:
            self.phase = {'prepare': 'prepared', 'activate': 'activated', 'verify': 'verified', 'commit': 'committed', 'abort': 'aborted'}[phase]
            result['phase'] = self.phase
            result[{'prepare': 'prepared', 'activate': 'activated', 'verify': 'verified', 'commit': 'committed', 'abort': 'rolled_back'}[phase]] = True
            if phase == 'verify':
                result.update(tls_verified=True, readiness_verified=True, observed_port=body['new_port'])
            if phase in ('commit', 'abort'):
                self.port = body['new_port'] if phase == 'commit' else self.old
                result.update(verified=True, applied_port=self.port)
            value = {'status': 'completed', 'result': result}
        self.jobs[body['request_id']] = value
        if phase == 'commit' and self.lost_commit:
            self.lost_commit = False
            raise OSError('lost commit response fixture')
        return value


class ApplicationPortTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixture.SQLiteRecoveryTests.setUpClass.__func__(cls)

    def setUp(self):
        fixture.SQLiteRecoveryTests.setUp(self)
        self.old, self.new = free_port(), free_port()
        self.manager.local_controller_id('node-a', explicit=True)
        self.manager.app.application_listen = '127.0.0.1:' + str(self.old)
        port.record_context(self.manager, ['--listen', self.manager.app.application_listen])

    person = fixture.SQLiteRecoveryTests.person

    def review(self):
        return port.preview(self.manager, {'expected_revision': port.status(self.manager)['revision'], 'port': self.new}, 'named-super-admin')

    def submit(self, plan):
        return port.apply(self.manager, {key: plan[key] for key in ('preview_id', 'digest', 'expected_revision', 'confirmation_nonce', 'confirmation_phrase')} | {'acknowledge_dependencies': True}, 'named-super-admin')

    def test_exact_review_dependencies_and_stale_state(self):
        plan = self.review()
        body = {key: plan[key] for key in ('preview_id', 'digest', 'expected_revision', 'confirmation_nonce', 'confirmation_phrase')}
        with self.assertRaises(ValueError):
            port.apply(self.manager, body, 'named-super-admin')
        with self.assertRaises(ValueError):
            port.apply(self.manager, {**body, 'acknowledge_dependencies': True, 'confirmation_phrase': 'not exact'}, 'named-super-admin')
        self.assertFalse(list((self.manager.root / 'jobs').glob('*.json')))
        self.assertIn('SSO', ' '.join(plan['dependencies']))

    def test_collision_before_review_and_after_queue_never_stops_original(self):
        with socket.socket() as occupied:
            occupied.bind(('127.0.0.1', self.new))
            plan = self.review()
            self.assertFalse(plan['can_apply'])
        plan = self.review()
        job = self.submit(plan)
        with socket.socket() as occupied:
            occupied.bind(('127.0.0.1', self.new))
            supervisor = Supervisor(self)
            port.execute(supervisor, self.manager.claim_runtime_job())
        self.assertEqual(supervisor.stops, 0)
        self.assertEqual(self.manager.job(job['id'])['status'], 'blocked')
        self.assertIsNone(port._state(self.manager)['pending'])

    def test_success_survives_original_cli_and_explicit_tls_arguments(self):
        job = self.submit(self.review())
        supervisor = Supervisor(self)
        port.execute(supervisor, self.manager.claim_runtime_job())
        self.assertEqual(self.manager.job(job['id'])['status'], 'applied')
        self.assertEqual(port.status(self.manager)['applied_port'], self.new)
        args = port.launch_arguments(self.manager, ['--listen', '127.0.0.1:' + str(self.old), '--cert', '/private/current.pem'])
        self.assertEqual(_argument(args, '--listen'), '127.0.0.1:' + str(self.new))
        self.assertEqual(_argument(args, '--cert'), '/private/current.pem')
        with self.assertRaises(port.PortError):
            port.launch_arguments(self.manager, ['--listen', '0.0.0.0:' + str(self.old)])

    def test_failed_candidate_rolls_back_and_clears_pending_authority(self):
        job = self.submit(self.review())
        supervisor = Supervisor(self, fail=True)
        port.execute(supervisor, self.manager.claim_runtime_job())
        self.assertEqual(supervisor.starts, [self.new, self.old])
        self.assertEqual(self.manager.job(job['id'])['status'], 'rolled_back')
        self.assertIsNone(port._state(self.manager)['pending'])
        with self.store.read_meta() as db:
            self.assertFalse(port.in_progress(self.store, db))

    def test_committed_reservation_recovers_worker_crash_without_early_publication(self):
        plan = self.review()
        original = port._private_json

        def crash(path, value):
            if path == self.manager.root / port.STATE:
                raise SystemExit('isolated API-worker crash')
            return original(path, value)

        with patch('controller.application_port._private_json', crash):
            with self.assertRaises(SystemExit):
                self.submit(plan)
        self.assertIsNone(self.manager.claim_runtime_job())
        port.recover_incomplete(self.manager)
        actual = self.manager.claim_runtime_job()
        self.assertEqual(actual['operation'], 'application-port')
        port.execute(Supervisor(self), actual)
        self.assertEqual(self.manager.job(actual['id'])['status'], 'applied')
        self.assertEqual(self.submit(plan)['id'], actual['id'])

    def test_demo_reviews_but_cannot_apply(self):
        port.record_context(self.manager, ['--demo', '--listen', '127.0.0.1:' + str(self.old)])
        self.manager.app.demo = True
        plan = self.review()
        self.assertFalse(plan['can_apply'])
        with self.assertRaises(PermissionError):
            self.submit(plan)

    def native(self, failure=False, lost_commit=False):
        with patch.dict('os.environ', {'PRTHAK_APPLIANCE': '1'}):
            port.record_context(self.manager, ['--listen', '0.0.0.0:8787'])
        self.manager.application_port_client = FixedPublisher(self.old, failure, lost_commit)
        with self.store.meta() as db:
            self.store._put(db, 'maintenance_settings', {'id': 'appliance_cluster', 'controller_origin': 'https://localhost:' + str(self.old), 'members': [{'id': 'node-a'}]})
        self.new = 443

    def test_public443_uses_fixed_publisher_without_restarting_internal_listener(self):
        self.native(lost_commit=True)
        job = self.submit(self.review())
        supervisor = Supervisor(self)
        port.execute(supervisor, self.manager.claim_runtime_job())
        self.assertEqual(self.manager.job(job['id'])['status'], 'applied')
        self.assertEqual(supervisor.stops, 0)
        self.assertEqual(supervisor.starts, [])
        self.assertEqual(port.status(self.manager)['applied_port'], 443)
        self.assertEqual(port.advertised_origin(self.manager, '10.0.0.5'), 'https://10.0.0.5:443')
        self.assertEqual({request['expected_revision'] for request in self.manager.application_port_client.requests}, {7})

    def test_public_failure_compensates_and_no_pending_marker_survives(self):
        self.native(failure=True)
        job = self.submit(self.review())
        port.execute(Supervisor(self), self.manager.claim_runtime_job())
        self.assertEqual(self.manager.job(job['id'])['status'], 'rolled_back')
        self.assertEqual(self.manager.application_port_client.port, self.old)
        self.assertEqual(self.manager.job(job['id'])['result']['applied_port'], self.old)
        self.assertIsNone(port._state(self.manager)['pending'])

    def test_public_status_outage_after_activation_never_restarts_internal_child(self):
        self.native()
        job = self.submit(self.review())
        supervisor = Supervisor(self)
        actual = self.manager.claim_runtime_job()
        path = self.manager.root / 'application-port-journals' / (job['id'] + '.json')
        _private_json(path, {'phase': 'public_transition', 'requested_phase': 'verify'})
        with patch.object(self.manager.application_port_client, 'status', side_effect=OSError('temporary manager outage')):
            port.execute(supervisor, actual)
        self.assertEqual(self.manager.job(job['id'])['status'], 'queued')
        self.assertEqual(supervisor.stops, 0)
        self.assertEqual(supervisor.starts, [])
        self.assertIsNotNone(port._state(self.manager)['pending'])
        port.execute(supervisor, self.manager.claim_runtime_job())
        self.assertEqual(self.manager.job(job['id'])['status'], 'applied')

    def test_public_preflight_revision_change_blocks_without_unknown_abort(self):
        self.native()
        job = self.submit(self.review())
        supervisor = Supervisor(self)
        native = self.manager.application_port_client
        original = native.status
        with patch.object(native, 'status', side_effect=lambda: {**original(), 'revision': 9}):
            port.execute(supervisor, self.manager.claim_runtime_job())
        self.assertEqual(self.manager.job(job['id'])['status'], 'blocked')
        self.assertEqual(native.requests, [])
        self.assertEqual(supervisor.stops, 0)
        self.assertIsNone(port._state(self.manager)['pending'])

    def test_historical_staged_appliance_configuration_does_not_block_port_review(self):
        job = self.manager._queue('appliance', {}, 'named-super-admin')
        self.manager.runtime_job_update(job['id'], 'staged', {'phase': 'waiting_for_voters'})
        self.assertTrue(self.review()['can_apply'])

    def test_public_transient_abort_failure_retries_same_binding_with_new_request_id(self):
        self.native(failure=True)
        job = self.submit(self.review())
        supervisor = Supervisor(self)
        client = self.manager.application_port_client
        original = client.submit
        failed = []

        def transient(body):
            if body['phase'] == 'abort' and not failed:
                failed.append(body['request_id'])
                client.jobs[body['request_id']] = {'status': 'error', 'result': {}}
                return client.jobs[body['request_id']]
            return original(body)

        with patch.object(client, 'submit', side_effect=transient):
            port.execute(supervisor, self.manager.claim_runtime_job())
            self.assertEqual(self.manager.job(job['id'])['status'], 'queued')
            path = self.manager.root / 'application-port-journals' / (job['id'] + '.json')
            journal = _read_json(path)
            journal.pop('retry_after')
            _private_json(path, journal)
            port.execute(supervisor, self.manager.claim_runtime_job())
        self.assertEqual(self.manager.job(job['id'])['status'], 'rolled_back')
        self.assertNotEqual(client.requests[-1]['request_id'], failed[0])
        self.assertEqual(client.requests[-1]['operation_id'], self.manager._job(job['id'])['private']['plan']['id'])
        self.assertEqual(supervisor.stops, 0)

    def test_committed_host_with_lost_terminal_receipt_never_aborts_and_reads_back_new_id(self):
        self.native()
        job = self.submit(self.review())
        actual = self.manager.claim_runtime_job()
        plan = actual['private']['plan']
        client = self.manager.application_port_client
        client.phase, client.operation, client.port = 'committed', plan['id'], self.new
        identifier = digest({'application_port_job': job['id'], 'phase': 'commit'})[:32]
        client.jobs[identifier] = {'status': 'error', 'result': {}}
        path = self.manager.root / 'application-port-journals' / (job['id'] + '.json')
        # Also covers COMMIT completing just after an uncertain transition
        # entered compensation. Observed commitment must win over old intent.
        _private_json(path, {'phase': 'rolling_back', 'requested_phase': 'commit'})
        supervisor = Supervisor(self)
        port.execute(supervisor, actual)
        self.assertEqual(self.manager.job(job['id'])['status'], 'queued')
        self.assertEqual(client.requests, [])
        journal = _read_json(path)
        self.assertEqual(journal['phase'], 'public_committed_receipt_pending')
        journal.pop('retry_after')
        _private_json(path, journal)
        port.execute(supervisor, self.manager.claim_runtime_job())
        self.assertEqual(self.manager.job(job['id'])['status'], 'applied')
        self.assertEqual([value['phase'] for value in client.requests], ['commit'])
        self.assertNotEqual(client.requests[0]['request_id'], identifier)
        self.assertEqual(supervisor.stops, 0)
        self.assertEqual(supervisor.starts, [])

    def test_initial_prepare_rpc_never_accepted_cancels_without_internal_restart(self):
        self.native()

        class UnseenPreparation(FixedPublisher):
            def submit(self, body):
                self.requests.append(copy.deepcopy(body))
                if body['phase'] == 'prepare':
                    raise OSError('RPC failed before the fixed manager accepted it')
                if body['phase'] != 'abort':
                    raise AssertionError('An unaccepted preparation cannot activate')
                # The fixed adapter records a side cancellation tombstone after
                # fresh old TLS/readiness proof. Its main journal, publication
                # and revision remain unchanged; delayed prepare is refused.
                receipt = FixedPublisher.submit(FixedPublisher(self.old), body)
                self.jobs[body['request_id']] = receipt
                self.cancelled_operation = body['operation_id']
                return receipt

        client = UnseenPreparation(self.old)
        self.manager.application_port_client = client
        job = self.submit(self.review())
        supervisor = Supervisor(self)
        port.execute(supervisor, self.manager.claim_runtime_job())
        result = self.manager.job(job['id'])
        self.assertEqual(result['status'], 'rolled_back')
        self.assertEqual(result['result']['applied_port'], self.old)
        self.assertEqual([request['phase'] for request in client.requests], ['prepare', 'abort'])
        self.assertEqual(client.cancelled_operation, self.manager._job(job['id'])['private']['plan']['id'])
        self.assertEqual(client.port, self.old)
        self.assertIsNone(client.phase)
        self.assertIsNone(port._state(self.manager)['pending'])
        self.assertEqual(supervisor.stops, 0)
        self.assertEqual(supervisor.starts, [])


if __name__ == '__main__':
    unittest.main()
