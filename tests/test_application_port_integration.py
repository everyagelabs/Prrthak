"""Actual owned CLI listener handover; no main preview/system service changes."""
import http.client
import json
import os
from pathlib import Path
import secrets
import socket
import ssl
import subprocess
import sys
import time
import unittest

from controller.platform import _read_json
import test_certificates_integration as fixture

ROOT = Path(__file__).resolve().parents[1]


def free_port():
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        return listener.getsockname()[1]


class ApplicationPortCLIIntegration(unittest.TestCase):
    stop = fixture.CertificateCLIIntegrationTests.stop
    wait = fixture.CertificateCLIIntegrationTests.wait

    def setUp(self):
        fixture.CertificateCLIIntegrationTests.setUp(self)
        self.launch_port, self.scheme = self.port, 'https'
        self.read_token = secrets.token_urlsafe(40)

    def request(self, method, path, value=None, token=None):
        headers = {'Authorization': 'Bearer ' + (token or self.token)}
        payload = json.dumps(value) if value is not None else None
        if value is not None:
            headers['Content-Type'] = 'application/json'
        connection = http.client.HTTPSConnection('localhost', self.port, context=self.context, timeout=3) if self.scheme == 'https' else http.client.HTTPConnection('127.0.0.1', self.port, timeout=3)
        try:
            connection.request(method, path, payload, headers)
            response = connection.getresponse()
            return response.status, json.loads(response.read())
        finally:
            connection.close()

    def start(self, demo=False, fail_port=None):
        self.scheme = 'http' if demo else 'https'
        environment = {key: value for key, value in os.environ.items() if not key.startswith(('SEG_', 'PRTHAK_')) and key != 'CONTROLLER_ORIGIN'}
        environment.update(SEG_SUPER_ADMIN_TOKEN=self.token, SEG_READ_ONLY_TOKEN=self.read_token, CONTROLLER_ORIGIN=self.scheme + '://localhost:' + str(self.launch_port), PYTHONPYCACHEPREFIX=str(self.root.resolve() / 'pycache'))
        arguments = ['--listen', '127.0.0.1:' + str(self.launch_port), '--data-dir', str(self.data), '--controller-id', 'port-cli-fixture']
        if demo:
            arguments += ['--demo']
        else:
            arguments += ['--cert', str(self.pki / 'controller.pem'), '--key', str(self.pki / 'controller-key.pem'), '--ca', str(self.pki / 'ca.pem'), '--ca-key', str(self.pki / 'ca-key.pem')]
        command = [sys.executable, '-m', 'controller']
        if fail_port:
            # Only the parent fixture stops a genuine candidate process. The
            # candidate and restored children both execute the normal CLI.
            wrapper = ('from controller.platform_runtime import RuntimeSupervisor,stop_process_group\n'
                       'original=RuntimeSupervisor.start_child\n'
                       'def start(self,profile=None,arguments=None,**options):\n'
                       '    result=original(self,profile,arguments,**options)\n'
                       '    if options.get("application_port_override")=='+str(fail_port)+':\n'
                       '        stop_process_group(self.child)\n        self.child=None\n'
                       '    return result\n'
                       'RuntimeSupervisor.start_child=start\nfrom controller.__main__ import main\nmain()\n')
            command = [sys.executable, '-c', wrapper]
        self.log = (self.root / 'controller.log').open('ab')
        self.child = subprocess.Popen(command + arguments, cwd=ROOT, env=environment, stdout=self.log, stderr=self.log, start_new_session=True)
        self.wait('/readyz', lambda value: value.get('status') == 'ready')

    def review(self, target):
        code, status = self.request('GET', '/api/v1/platform/application-port')
        self.assertEqual(code, 200, status)
        code, plan = self.request('POST', '/api/v1/platform/application-port/preview', {'expected_revision': status['revision'], 'port': target})
        self.assertEqual(code, 200, plan)
        return plan

    def apply(self, plan):
        body = {key: plan[key] for key in ('preview_id', 'digest', 'expected_revision', 'confirmation_nonce', 'confirmation_phrase')}
        try:
            code, result = self.request('POST', '/api/v1/platform/application-port/apply', {**body, 'acknowledge_dependencies': True})
            self.assertEqual(code, 202, result)
            return result['id']
        except (OSError, http.client.HTTPException):
            # An accepted handover may close the old connection before its
            # response arrives. Read the exact owned pending file, not a guess.
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                state = _read_json(self.data / 'platform/application-port.json', {})
                if state.get('last_job_id'):
                    return state['last_job_id']
                time.sleep(.05)
            raise

    def terminal(self, identifier, seconds=30):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            value = self.manager.job(identifier)
            if value['status'] in ('applied', 'rolled_back', 'blocked', 'failed'):
                return value
            time.sleep(.1)
        self.fail('Owned port handover did not finish: ' + repr(self.manager.job(identifier)) + (self.root / 'controller.log').read_text()[-2500:])

    def test_real_https_change_restarts_on_saved_port_with_original_cli_argument(self):
        self.start()
        original_parent = self.child.pid
        code, readonly = self.request('GET', '/api/v1/platform/application-port', token=self.read_token)
        self.assertEqual(code, 200, readonly)
        code, _ = self.request('POST', '/api/v1/platform/application-port/preview', {'expected_revision': 0, 'port': free_port()}, token=self.read_token)
        self.assertEqual(code, 403)
        target = free_port()
        plan = self.review(target)
        self.assertTrue(plan['can_apply'], plan)
        identifier = self.apply(plan)
        result = self.terminal(identifier)
        self.assertEqual(result['status'], 'applied', result)
        self.assertTrue(result['result']['verified'])
        self.port = target
        self.wait('/readyz', lambda value: value.get('status') == 'ready')
        self.assertEqual(self.child.pid, original_parent)
        code, current = self.request('GET', '/api/v1/platform/application-port')
        self.assertEqual(code, 200, current)
        self.assertEqual(current['applied_port'], target)
        self.assertEqual(current['bind_address'], '127.0.0.1')
        self.stop()
        self.start()  # Still --listen ORIGINAL; private GUI overlay must win.
        self.assertEqual(self.request('GET', '/api/v1/platform/application-port')[1]['applied_port'], target)

    def test_real_bind_collision_is_rejected_before_old_listener_stops(self):
        self.start()
        with socket.socket() as occupied:
            occupied.bind(('127.0.0.1', 0))
            target = occupied.getsockname()[1]
            plan = self.review(target)
            self.assertFalse(plan['can_apply'])
        self.assertEqual(self.request('GET', '/readyz')[0], 200)
        self.assertFalse(list((self.data / 'platform/jobs').glob('*.json')))

    def test_real_candidate_exit_restores_original_https_and_requires_fresh_review(self):
        target = free_port()
        self.start(fail_port=target)
        plan = self.review(target)
        identifier = self.apply(plan)
        result = self.terminal(identifier)
        self.assertEqual(result['status'], 'rolled_back', result)
        self.assertEqual(result['result']['applied_port'], self.launch_port)
        self.assertTrue(result['result']['verified'])
        self.wait('/readyz', lambda value: value.get('status') == 'ready')
        state = self.request('GET', '/api/v1/platform/application-port')[1]
        self.assertEqual(state['applied_port'], self.launch_port)
        self.assertEqual(state['desired_port'], self.launch_port)

    def test_real_demo_http_reviews_but_refuses_listener_mutation(self):
        self.start(demo=True)
        plan = self.review(free_port())
        self.assertFalse(plan['can_apply'])
        body = {key: plan[key] for key in ('preview_id', 'digest', 'expected_revision', 'confirmation_nonce', 'confirmation_phrase')}
        code, _ = self.request('POST', '/api/v1/platform/application-port/apply', {**body, 'acknowledge_dependencies': True})
        self.assertEqual(code, 403)
        self.assertEqual(self.request('GET', '/readyz')[0], 200)


if __name__ == '__main__':
    unittest.main()
