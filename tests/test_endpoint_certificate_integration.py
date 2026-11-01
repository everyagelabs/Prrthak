"""Real CLI/Gunicorn + native-Go renewal, revocation and fresh-key recovery."""
from contextlib import contextmanager
import json
import http.client
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
import unittest

from cryptography import x509
from controller.pki import init_ca
from test_integration import request

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(os.environ.get('SEG_AGENT_BINARY'), 'Set SEG_AGENT_BINARY to the current native agent')
class EndpointCertificateNativeIntegration(unittest.TestCase):
    separate_issuing_ca = False

    def test_real_gunicorn_identity_renews_is_revoked_and_recovers_with_fresh_key(self):
        with tempfile.TemporaryDirectory(prefix='prthak-certificate-native-') as directory:
            root = Path(directory)
            pki = init_ca(root / 'tls')
            web_pki = init_ca(root / 'web-tls') if self.separate_issuing_ca else pki
            with socket.socket() as selected:
                selected.bind(('127.0.0.1', 0))
                port = selected.getsockname()[1]
            token = secrets.token_urlsafe(48)
            env = {key: value for key, value in os.environ.items() if not key.startswith(('SEG_', 'PRTHAK_')) and key != 'CONTROLLER_ORIGIN'}
            env['SEG_SUPER_ADMIN_TOKEN'] = token
            # Run the child CLI directly so the fixture-only issuer survives
            # Gunicorn's fork; production supervisor behavior has separate tests.
            env['PRTHAK_SUPERVISED_CHILD'] = '1'
            env['CONTROLLER_ORIGIN'] = 'https://localhost:' + str(port)
            # Fixture-only short initial leaf exercises renewal now, without
            # changing machine clocks or shortening production certificates.
            injection = '''from datetime import datetime,timedelta,timezone
from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from controller import pki
original=pki.Signer.__call__
def issue(self,identity,csr):
    certificate,ca=original(self,identity,csr)
    if not getattr(self,'fixture_initial',False):
        self.fixture_initial=True
        leaf=x509.load_pem_x509_certificate(certificate.encode())
        key=serialization.load_pem_private_key(self.ca_key.read_bytes(),None)
        builder=x509.CertificateBuilder().subject_name(leaf.subject).issuer_name(leaf.issuer).public_key(leaf.public_key()).serial_number(leaf.serial_number).not_valid_before(leaf.not_valid_before_utc).not_valid_after(datetime.now(timezone.utc)+timedelta(days=20))
        for extension in leaf.extensions:builder=builder.add_extension(extension.value,extension.critical)
        certificate=builder.sign(key,hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode()
    return certificate,ca
pki.Signer.__call__=issue
from controller.__main__ import main
main()
'''
            log = (root / 'controller.log').open('wb')
            process = subprocess.Popen([sys.executable, '-c', injection, '--listen', '127.0.0.1:' + str(port), '--data-dir', str(root / 'controller'), '--cert', str(web_pki / 'controller.pem'), '--key', str(web_pki / 'controller-key.pem'), '--ca', str(pki / 'ca.pem'), '--ca-key', str(pki / 'ca-key.pem')], cwd=ROOT, env=env, stdout=log, stderr=log, start_new_session=True)
            try:
                context = ssl.create_default_context(cafile=str(web_pki / 'ca.pem'))
                headers = {'Authorization': 'Bearer ' + token}
                deadline = time.monotonic() + 15
                while True:
                    try:
                        status, _, _ = request(port, 'GET', '/readyz', context=context)
                        if status == 200:
                            break
                    except OSError:
                        pass
                    if time.monotonic() > deadline or process.poll() is not None:
                        self.fail((root / 'controller.log').read_text())
                    time.sleep(.1)
                def api(method, path, body=None):
                    status, result, _ = request(port, method, '/api/v1/' + path, body, headers, context)
                    self.assertIn(status, (200, 201), result)
                    return result
                enrollment = api('POST', 'enrollment-tokens', {'name': 'native-certificate-test'})
                token_path = root / 'enrollment-token'
                token_path.write_text(enrollment['token'])
                token_path.chmod(0o600)
                state = root / 'endpoint'
                config = root / 'agent.json'
                config.write_text(json.dumps({'controller_url': 'https://localhost:' + str(port), 'ca_cert': str(web_pki / 'ca.pem'), 'endpoint_ca_cert': str(pki / 'ca.pem') if self.separate_issuing_ca else '', 'state_dir': str(state), 'enrollment_token_file': str(token_path), 'interval_seconds': 60, 'request_timeout_seconds': 5}))
                binary = str(Path(os.environ['SEG_AGENT_BINARY']).resolve())
                def agent(*arguments):
                    return subprocess.run([binary, '--config', str(config), *arguments], cwd=ROOT, capture_output=True, text=True, timeout=30)
                initial = agent('--once')
                self.assertEqual(initial.returncode, 0, initial.stderr)
                self.assertTrue((state / 'agent.crt.previous').is_file(), initial.stderr + '\n' + (root / 'controller.log').read_text())
                current = x509.load_pem_x509_certificate((state / 'agent.crt').read_bytes())
                previous = x509.load_pem_x509_certificate((state / 'agent.crt.previous').read_bytes())
                self.assertGreater((current.not_valid_after_utc - previous.not_valid_after_utc).days, 60)
                identity = api('GET', 'servers')['items'][0]['id']
                self.assertTrue((state / 'policy-signing-trust.json').is_file())
                endpoint_tls = ssl.create_default_context(cafile=str(web_pki / 'ca.pem'))
                endpoint_tls.load_cert_chain(state / 'agent.crt', state / 'agent.key')
                persistent = http.client.HTTPSConnection('localhost', port, context=endpoint_tls, timeout=5)
                persistent.request('GET', '/api/v1/agent/policy')
                first = persistent.getresponse()
                self.assertEqual(first.status, 200)
                first.read()
                review = api('POST', 'platform/endpoint-certificates/revoke-preview', {'server_id': identity})
                api('POST', 'platform/endpoint-certificates/revoke-apply', {'preview_id': review['id'], **{key: review[key] for key in ('digest', 'confirmation_nonce', 'confirmation_phrase')}})
                persistent.request('GET', '/api/v1/agent/policy')
                revoked = persistent.getresponse()
                self.assertEqual(revoked.status, 403, 'Revocation must also stop a previously established TLS connection')
                revoked.read()
                persistent.close()
                denied = agent('--once')
                self.assertNotEqual(denied.returncode, 0)
                old_key = (state / 'agent.key').read_bytes()
                recovery = api('POST', 'platform/endpoint-certificates/recovery-token', {'server_id': identity})
                recovery_path = root / 'recovery-token'
                recovery_path.write_text(recovery['token'])
                recovery_path.chmod(0o600)
                recovered = agent('--recover-certificate', str(recovery_path))
                self.assertEqual(recovered.returncode, 0, recovered.stderr)
                self.assertNotEqual(old_key, (state / 'agent.key').read_bytes())
                resumed = agent('--once')
                self.assertEqual(resumed.returncode, 0, resumed.stderr)
                self.assertEqual(api('GET', 'servers')['items'][0]['id'], identity)
                records = api('GET', 'platform/endpoint-certificates')['items']
                self.assertEqual(sum(row['status'] == 'active' for row in records), 1)
                self.assertEqual(sum(row['status'] == 'revoked' for row in records), 2)
                previous_key = (state / 'agent.key').read_bytes()
                second = api('POST', 'platform/endpoint-certificates/recovery-token', {'server_id': identity})
                recovery_path.write_text(second['token'])
                again = agent('--recover-certificate', str(recovery_path))
                self.assertEqual(again.returncode, 0, again.stderr)
                self.assertNotEqual(previous_key, (state / 'agent.key').read_bytes(), 'Every completed recovery must use another fresh key')
                self.assertEqual(agent('--once').returncode, 0)
            finally:
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGTERM)
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        os.killpg(process.pid, signal.SIGKILL)
                        process.wait(timeout=5)
                log.close()


class EndpointCertificateSeparateCAIntegration(EndpointCertificateNativeIntegration):
    """Corporate HTTPS trust and the endpoint issuing CA remain independent."""
    separate_issuing_ca = True
