"""Exercise the signed router entrypoint with the legacy Compose command."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ENTRYPOINT = Path(__file__).resolve().parents[1] / 'deploy/appliance/router-entrypoint.sh'
COMPOSE_COMMAND = ['haproxy', '-W', '-db', '-f', '/config/haproxy.cfg']
LEGACY_CONFIG = (
    'backend management\n'
    '    server local controller:8787 check check-ssl verify required ca-file /config/controller-ca.pem\n'
    '    server remote remote.example:8787 check\n'
    'backend control\n'
    '    server local controller:8788 check check-ssl\n'
    'backend discovery\n'
    '    server local controller:8789 check check-ssl\n'
)


class OfflineRouterStartTests(unittest.TestCase):
    def run_entrypoint(self, command, ready_after):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / 'haproxy.cfg'
            config.write_text(LEGACY_CONFIG)
            scripts = {
                'getent': '[ "$1" = hosts ] && [ "$2" = controller ] || exit 2\nprintf "dns\\n" >> "$ROUTER_TEST_LOG"\n[ "$(wc -l < "$ROUTER_TEST_LOG")" -ge "$ROUTER_TEST_READY" ]',
                'timeout': '[ "$1" = 2 ] || exit 2\nshift\nexec "$@"',
                'sleep': '[ "$1" = 1 ]',
                # Redirect the container paths into the fixture, running the real rewrite and mktemp.
                'awk': '[ "$#" = 2 ] && [ "$2" = /config/haproxy.cfg ] || exit 2\n'
                       'exec /usr/bin/awk "$1" "$ROUTER_TEST_CONFIG"',
                'mktemp': '[ "$#" = 1 ] && [ "$1" = /tmp/prthak-haproxy.XXXXXX ] || exit 2\n'
                          'exec /usr/bin/mktemp "$ROUTER_TEST_DIR/prthak-haproxy.XXXXXX"',
                'docker-entrypoint.sh': 'printf "started %s\\n" "$*" >> "$ROUTER_TEST_LOG"',
            }
            for name, body in scripts.items():
                script = root / name
                script.write_text('#!/bin/sh\n' + body + '\n')
                script.chmod(0o755)
            log = root / 'calls'
            log.touch()
            result = subprocess.run(['/bin/sh', str(ENTRYPOINT), *command], capture_output=True, text=True, check=False,
                                    env={**os.environ, 'PATH': f'{root}:/usr/bin:/bin', 'ROUTER_TEST_LOG': str(log),
                                         'ROUTER_TEST_DIR': str(root), 'ROUTER_TEST_CONFIG': str(config),
                                         'ROUTER_TEST_READY': str(ready_after)})
            rewritten = next(root.glob('prthak-haproxy.*'), None)
            self.assertEqual(config.read_text(), LEGACY_CONFIG)
            return result, log.read_text().splitlines(), rewritten, rewritten.read_text() if rewritten else None

    def test_legacy_start_waits_for_the_controller_hostname(self):
        result, calls, config_path, config = self.run_entrypoint(COMPOSE_COMMAND, 3)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIsNotNone(config_path)
        self.assertEqual(calls, ['dns'] * 3 + ['started ' + ' '.join([*COMPOSE_COMMAND[:-1], str(config_path)])])
        expected = LEGACY_CONFIG
        for port in (8787, 8788, 8789):
            expected = expected.replace(f'controller:{port}', f'controller:{10000 + port} send-proxy-v2 port {port}')
        self.assertEqual(config, expected)

    def test_timeout_stops_before_starting_haproxy(self):
        result, calls, config_path, _ = self.run_entrypoint(COMPOSE_COMMAND, 100)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(calls, ['dns'] * 20)
        self.assertIn('Docker DNS', result.stderr)
        self.assertIsNone(config_path)

    def test_config_check_is_passed_through(self):
        command = ['haproxy', '-c', '-f', '/config/haproxy.cfg']
        result, calls, config_path, _ = self.run_entrypoint(command, 100)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(calls, ['started ' + ' '.join(command)])
        self.assertIsNone(config_path)
