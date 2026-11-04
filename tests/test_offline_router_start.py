"""Exercise the signed router entrypoint with the legacy Compose command."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ENTRYPOINT = Path(__file__).resolve().parents[1] / 'deploy/appliance/router-entrypoint.sh'
COMPOSE_COMMAND = ['haproxy', '-W', '-db', '-f', '/config/haproxy.cfg']


class OfflineRouterStartTests(unittest.TestCase):
    def run_entrypoint(self, command, ready_after):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            scripts = {
                'getent': '[ "$1" = hosts ] && [ "$2" = controller ] || exit 2\nprintf "dns\\n" >> "$ROUTER_TEST_LOG"\n[ "$(wc -l < "$ROUTER_TEST_LOG")" -ge "$ROUTER_TEST_READY" ]',
                'timeout': '[ "$1" = 2 ] || exit 2\nshift\nexec "$@"',
                'sleep': '[ "$1" = 1 ]',
                'docker-entrypoint.sh': 'printf "started %s\\n" "$*" >> "$ROUTER_TEST_LOG"',
            }
            for name, body in scripts.items():
                script = root / name
                script.write_text('#!/bin/sh\n' + body + '\n')
                script.chmod(0o755)
            log = root / 'calls'
            result = subprocess.run(['/bin/sh', str(ENTRYPOINT), *command], capture_output=True, text=True, check=False,
                                    env={**os.environ, 'PATH': f'{root}:/usr/bin:/bin', 'ROUTER_TEST_LOG': str(log),
                                         'ROUTER_TEST_READY': str(ready_after)})
            return result, log.read_text().splitlines()

    def test_legacy_start_waits_for_the_controller_hostname(self):
        result, calls = self.run_entrypoint(COMPOSE_COMMAND, 3)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(calls, ['dns'] * 3 + ['started ' + ' '.join(COMPOSE_COMMAND)])

    def test_timeout_stops_before_starting_haproxy(self):
        result, calls = self.run_entrypoint(COMPOSE_COMMAND, 100)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(calls, ['dns'] * 20)
        self.assertIn('Docker DNS', result.stderr)

    def test_config_check_is_passed_through(self):
        command = ['haproxy', '-c', '-f', '/config/haproxy.cfg']
        result, calls = self.run_entrypoint(command, 100)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(calls, ['started ' + ' '.join(command)])
