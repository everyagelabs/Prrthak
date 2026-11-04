"""Independent recovery modes cannot be combined with normal agent operation."""
import os
from pathlib import Path
import subprocess
import unittest


@unittest.skipUnless(os.environ.get('SEG_AGENT_BINARY'),'Native helper required')
class NetworkRecoveryCommandIsolation(unittest.TestCase):
    def test_recovery_modes_reject_mixed_flags_before_any_native_command(self):
        binary=Path(os.environ['SEG_AGENT_BINARY']).resolve(strict=True)
        nonce='a'*32
        cases=[
            ['--network-control-nonce',nonce],
            ['--restore-quarantine','/private/tmp/test-only-unused','--version'],
            ['--restore-quarantine','/private/tmp/test-only-unused','--once'],
            ['--restore-quarantine','/private/tmp/test-only-unused','--network-control-nonce',nonce],
            ['--rollback-network-control','/private/tmp/test-only-unused','--network-control-nonce',nonce,'--simulate'],
            ['--expire-quarantine','/private/tmp/test-only-unused','--network-control-nonce',nonce,'--check-config'],
            ['--expire-quarantine','/private/tmp/test-only-unused','--rollback-network-control','/private/tmp/other-unused','--network-control-nonce',nonce],
            ['--rollback-network-control','/private/tmp/test-only-unused'],
            ['--restore-quarantine','/private/tmp/test-only-unused','unexpected-positional-value'],
        ]
        for arguments in cases:
            with self.subTest(arguments=arguments):
                result=subprocess.run([str(binary),*arguments],capture_output=True,text=True,timeout=5)
                self.assertNotEqual(result.returncode,0)
                self.assertIn('independent network rollback/expiry/boot recovery',result.stderr)
