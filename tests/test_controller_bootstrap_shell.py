"""Fail-closed shell dispatch; no package manager or host service is executed."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'scripts/install-controller.sh'


class ControllerBootstrapDispatchTests(unittest.TestCase):
    def test_production_entrypoint_ignores_hostile_path_before_dispatch(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            marker = root / 'executed'
            for name in ('dirname', 'sh', 'cat'):
                executable = root / name
                executable.write_text('#!/bin/sh\n: > "' + str(marker) + '"\nexit 77\n')
                executable.chmod(0o755)
            result = subprocess.run(['/bin/sh', str(SCRIPT), '--help'],
                                    env={**os.environ, 'PATH': str(root)},
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('configuration in the GUI', result.stdout)
            self.assertFalse(marker.exists())

    def run_script(self, *arguments, python=None):
        environment = {**os.environ}
        if python is not None:
            environment['PRTHAK_INSTALL_PYTHON'] = str(python)
        return subprocess.run(['/bin/sh', str(SCRIPT), *arguments], env=environment,
                              capture_output=True, text=True, timeout=10)

    def test_help_is_available_before_python_linux_or_root_and_cannot_execute_an_override(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            interpreter = root / 'untrusted-python'
            marker = root / 'executed'
            interpreter.write_text('#!/bin/sh\n: > "' + str(marker) + '"\n')
            interpreter.chmod(0o755)
            result = self.run_script('--help', python=interpreter)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('sudo ./scripts/install-controller.sh', result.stdout)
            self.assertIn('configuration in the GUI', result.stdout)
            self.assertFalse(marker.exists())

    def test_bad_arguments_and_missing_values_stop_before_any_interpreter(self):
        for arguments in [('--unknown',), ('--data-root',), ('--env-file',),
                          ('--env-file', '--no-start'), ('--gui-setup', '--env-file', '/not-used'),
                          ('--gui-setup', '--gui-setup'), ('--data-root', '/first', '--data-root', '/second')]:
            with self.subTest(arguments=arguments):
                result = self.run_script(*arguments, python='/not-a-real-interpreter')
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn('Installing', result.stdout)
                self.assertNotIn('interpreter is required', result.stderr)

    def test_unknown_private_argument_is_never_echoed(self):
        sentinel = 'PRIVATE-ARGUMENT-SENTINEL'
        result = self.run_script(sentinel)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn(sentinel, result.stdout + result.stderr)

    def test_prepared_validation_and_staging_do_not_bootstrap_a_missing_interpreter(self):
        for arguments in [('--validate-only',), ('--no-start',), ('--env-file', '/not-used')]:
            with self.subTest(arguments=arguments):
                result = self.run_script(*arguments, python='/not-a-real-interpreter')
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn('Installing', result.stdout)
                # A root process on another OS may stop at its platform gate.
                self.assertTrue('prepared-host operation' in result.stderr or
                                'requires Linux' in result.stderr, result.stderr)

    def test_relative_custom_python_is_rejected_in_prepared_mode(self):
        result = self.run_script('--validate-only', python='user-python')
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue('absolute protected interpreter' in result.stderr or
                        'requires Linux' in result.stderr, result.stderr)


if __name__ == '__main__':
    unittest.main()
