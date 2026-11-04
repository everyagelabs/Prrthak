"""Installer acceptance checks using a staging filesystem and fake endpoint binary.

No test writes to real /etc, controls systemd, contacts a controller, or touches a firewall.
The Go suite separately exercises real configuration/credential validation and first sync.
"""
import json
from datetime import datetime, timezone
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import shlex
import sys

PROJECT = Path(__file__).resolve().parents[1]
INSTALLER = PROJECT / 'scripts' / 'install-agent.sh'


class AgentInstallerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.root = self.base / 'target-root'
        self.calls = self.base / 'agent-calls.log'
        self.systemctl_calls = self.base / 'systemctl-calls.log'
        self.binary = self.base / 'fake-agent'
        self.binary.write_text('''#!/bin/sh
set -eu
printf '%s\\n' "$*" >> "$PSEGRA_AGENT_CALLS"
case "$*" in
  *--check-release*) ;;
  *--check-config*)
    if [ "${PSEGRA_REJECT_CONFIG:-0}" = 1 ]; then echo 'Reviewed config failed preflight' >&2; exit 1; fi
    printf '%s\\n' 'Prṛthak (पृथक्) configuration validated'
    ;;
  *--status*) printf '%s\\n' 'Prṛthak (पृथक्) ready: auto-created-server registered and reported to the dashboard' ;;
  *--check-upgrade*)
    if [ -n "${PSEGRA_PENDING_AFTER_STOP:-}" ] && [ -f "$PSEGRA_PENDING_AFTER_STOP" ]; then echo 'nonterminal enforcement journal' >&2; exit 1; fi
    ;;
  *) exit 1 ;;
esac
''')
        self.binary.chmod(0o755)
        fakebin = self.base / 'fake-bin'
        fakebin.mkdir()
        systemctl = fakebin / 'systemctl'
        systemctl.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$PSEGRA_SYSTEMCTL_CALLS"\nexit 99\n')
        systemctl.chmod(0o755)
        self.config = self.base / 'reviewed.json'
        self.settings = json.loads((PROJECT / 'agent' / 'config.example.json').read_text())
        self.config.write_text(json.dumps(self.settings))
        self.ca = self.base / 'bootstrap-ca.pem'
        self.ca.write_text('public-ca-fixture')
        self.token = self.base / 'bootstrap-token'
        self.token.write_text('installer-private-token-that-must-not-be-an-argument')
        self.token.chmod(0o600)
        self.env = {**os.environ, 'PSEGRA_AGENT_CALLS': str(self.calls),
                    'PSEGRA_SYSTEMCTL_CALLS': str(self.systemctl_calls),
                    'PATH': str(fakebin) + os.pathsep + os.environ.get('PATH', '')}
        self.env.pop('SEG_ENROLLMENT_TOKEN', None)
        self.env.pop('SEG_ENROLLMENT_TOKEN_FILE', None)

    def run_install(self, *options, env=None, token=True):
        arguments = ['sh', str(INSTALLER), '--root', str(self.root), '--no-start',
                     '--ca-file', str(self.ca)]
        if token:
            arguments.extend(['--token-file', str(self.token)])
        arguments.extend(options)
        arguments.extend([str(self.binary), str(self.config)])
        return subprocess.run(arguments, capture_output=True, text=True,
                              env={**self.env, **(env or {})}, timeout=15)

    def test_staging_installs_enabled_unit_without_touching_live_systemd(self):
        result = self.run_install()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('enrolls and appears in the dashboard automatically', result.stdout)
        self.assertFalse(self.systemctl_calls.exists())
        self.assertTrue((self.root / 'usr/local/bin/seg-agent').is_file())
        self.assertEqual(json.loads((self.root / 'etc/seg-agent/config.json').read_text()), self.settings)
        enabled = self.root / 'etc/systemd/system/multi-user.target.wants/seg-agent.service'
        self.assertTrue(enabled.is_symlink())
        self.assertEqual(os.readlink(enabled), '../seg-agent.service')
        self.assertEqual((self.root / 'etc/seg-agent/enrollment-token').stat().st_mode & 0o777, 0o600)
        self.assertEqual((self.root / 'etc/seg-agent/config.json').stat().st_mode & 0o777, 0o600)
        self.assertEqual((self.root / 'etc/seg-agent/bootstrap.env').stat().st_mode & 0o777, 0o600)
        calls = self.calls.read_text().splitlines()
        self.assertEqual(len(calls), 2)
        self.assertIn('--check-config --install-check', calls[0])
        self.assertIn('--config ' + str(self.root.resolve() / 'etc/seg-agent/config.json'), calls[1])
        self.assertNotIn(self.token.read_text(), self.calls.read_text() + result.stdout + result.stderr)

    def test_resource_limits_require_live_native_systemd_before_any_staging_mutation(self):
        for options in (('--resource-limits',), ('--resource-limits', '--require-state-volume')):
            result = self.run_install(*options)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('require a live install', result.stderr)
            self.assertFalse(self.root.exists())
            self.assertFalse(self.calls.exists())
            self.assertFalse(self.systemctl_calls.exists())

    def test_existing_different_config_aborts_before_install_or_start(self):
        active = self.root / 'etc/seg-agent/config.json'
        active.parent.mkdir(parents=True)
        active.write_text('{"reviewed":"previous"}')
        result = self.run_install()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('--replace-config', result.stderr)
        self.assertEqual(active.read_text(), '{"reviewed":"previous"}')
        self.assertFalse(self.calls.exists())
        self.assertFalse((self.root / 'usr/local/bin/seg-agent').exists())
        self.assertFalse(self.systemctl_calls.exists())

    def test_transaction_armed_during_stop_refuses_every_copy_and_restarts_previous_service(self):
        # A private copy redirects every install destination into this fixture.
        # Fake uname/id/systemctl exercise the live branch without controlling
        # any real service or writing outside the test directory.
        active = self.root / 'etc/seg-agent/config.json'
        active.parent.mkdir(parents=True)
        active.write_text(self.config.read_text())
        previous = self.root / 'usr/local/bin/seg-agent'
        previous.parent.mkdir(parents=True)
        previous.write_bytes(b'previous-agent-must-survive')
        private = self.base / 'private-live-installer.sh'
        value = INSTALLER.read_text()
        destinations = {'ETC_DIR=$ROOT/etc/seg-agent': active.parent, 'STATE_DIR=$ROOT/var/lib/seg-agent': self.root/'var/lib/seg-agent', 'BIN_DIR=$ROOT/usr/local/bin': previous.parent, 'UNIT_DIR=$ROOT/etc/systemd/system': self.root/'etc/systemd/system'}
        for line, path in destinations.items():
            value = value.replace(line, line.split('=',1)[0]+'='+shlex.quote(str(path)))
        value = value.replace('PROJECT_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)', 'PROJECT_ROOT='+shlex.quote(str(PROJECT)))
        private.write_text(value)
        fakebin = self.base/'fake-bin'
        manifest=self.base/'mock-runtime-integrity.json';manifest.write_text('{}')
        trust=self.base/'mock-public-trust.json';trust.write_text('{}')
        value=value.replace('RUNTIME_MANIFEST=$PROJECT_ROOT/runtime-integrity.json','RUNTIME_MANIFEST='+shlex.quote(str(manifest)))
        value=value.replace('RELEASE_TRUST=$PROJECT_ROOT/deploy/release-public-trust.json','RELEASE_TRUST='+shlex.quote(str(trust)))
        private.write_text(value)
        flock=fakebin/'flock';flock.write_text('#!/bin/sh\n[ -e /dev/fd/9 ] || exit 1\nexit 0\n');flock.chmod(0o755)
        for name, output in (('uname','Linux'),('id','0'),('stat','0')):
            path=fakebin/name
            path.write_text('#!/bin/sh\nprintf "%s\\n" '+shlex.quote(output)+'\n')
            path.chmod(0o755)
        marker=self.base/'pending-after-stop'
        systemctl=fakebin/'systemctl'
        systemctl.write_text('''#!/bin/sh
printf '%s\\n' "$*" >> "$PSEGRA_SYSTEMCTL_CALLS"
case "$1" in
is-active) exit 0 ;;
stop) touch "$PSEGRA_PENDING_AFTER_STOP"; exit 0 ;;
start) exit 0 ;;
*) exit 99 ;;
esac
''')
        result=subprocess.run(['sh',str(private),'--ca-file',str(self.ca),'--token-file',str(self.token),str(self.binary),str(self.config)],capture_output=True,text=True,env={**self.env,'PSEGRA_PENDING_AFTER_STOP':str(marker)},timeout=15)
        self.assertNotEqual(result.returncode,0)
        self.assertIn('Nothing was replaced',result.stderr)
        self.assertEqual(previous.read_bytes(),b'previous-agent-must-survive')
        self.assertEqual(active.read_text(),self.config.read_text())
        calls=self.systemctl_calls.read_text()
        self.assertIn('stop seg-agent.service',calls)
        self.assertIn('start seg-agent.service',calls)
        self.assertNotIn('daemon-reload',calls)

    def test_native_installer_refuses_nonregular_or_unowned_lease_before_open(self):
        # Redirect the native-shaped branch completely; a FIFO must fail
        # before opening it can block the installer, and no service is called.
        value=INSTALLER.read_text()
        state=self.root/'var/lib/seg-agent';lease=state/'configuration-transitions'/'lock'
        destinations={'ETC_DIR=$ROOT/etc/seg-agent':self.root/'etc/seg-agent','STATE_DIR=$ROOT/var/lib/seg-agent':state,'BIN_DIR=$ROOT/usr/local/bin':self.root/'usr/local/bin','UNIT_DIR=$ROOT/etc/systemd/system':self.root/'etc/systemd/system'}
        for line,path in destinations.items():value=value.replace(line,line.split('=',1)[0]+'='+shlex.quote(str(path)))
        value=value.replace('PROJECT_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)','PROJECT_ROOT='+shlex.quote(str(PROJECT)))
        manifest=self.base/'runtime.json';manifest.write_text('{}');trust=self.base/'trust.json';trust.write_text('{}')
        value=value.replace('RUNTIME_MANIFEST=$PROJECT_ROOT/runtime-integrity.json','RUNTIME_MANIFEST='+shlex.quote(str(manifest))).replace('RELEASE_TRUST=$PROJECT_ROOT/deploy/release-public-trust.json','RELEASE_TRUST='+shlex.quote(str(trust)))
        private=self.base/'lease-refusal-installer.sh';private.write_text(value)
        fakebin=self.base/'fake-bin'
        for name,output in [('uname','Linux'),('id','0'),('stat','0')]:
            path=fakebin/name;path.write_text('#!/bin/sh\nprintf "%s\\n" '+shlex.quote(output)+'\n');path.chmod(0o755)
        flock=fakebin/'flock';flock.write_text('#!/bin/sh\nexit 0\n');flock.chmod(0o755)
        lease.parent.mkdir(parents=True)
        for kind in ['fifo','symlink','unowned']:
            with self.subTest(kind=kind):
                if lease.exists() or lease.is_symlink():lease.unlink()
                if kind=='fifo':os.mkfifo(lease)
                elif kind=='symlink':lease.symlink_to(self.base/'absent-target')
                else:
                    lease.write_text('')
                    (fakebin/'stat').write_text('#!/bin/sh\nprintf "501\\n"\n')
                result=subprocess.run(['sh',str(private),str(self.binary),str(self.config)],capture_output=True,text=True,env=self.env,timeout=2)
                self.assertNotEqual(result.returncode,0)
                self.assertRegex(result.stderr,'regular file|symlink|owned by root')
                self.assertFalse(self.systemctl_calls.exists())
                self.assertFalse((self.root/'usr/local/bin/seg-agent').exists())

    def test_native_installer_keeps_real_generation_lease_through_copies_and_service_start(self):
        # Only the branch selection is native-shaped. Every filesystem target
        # is redirected and systemctl is a recorder; fcntl supplies real locks.
        value=INSTALLER.read_text()
        destinations={'ETC_DIR=$ROOT/etc/seg-agent':self.root/'etc/seg-agent','STATE_DIR=$ROOT/var/lib/seg-agent':self.root/'var/lib/seg-agent','BIN_DIR=$ROOT/usr/local/bin':self.root/'usr/local/bin','UNIT_DIR=$ROOT/etc/systemd/system':self.root/'etc/systemd/system'}
        for line,path in destinations.items():value=value.replace(line,line.split('=',1)[0]+'='+shlex.quote(str(path)))
        value=value.replace('$ROOT/usr/','$PSEGRA_FIXTURE_ROOT/usr/')
        value=value.replace('PROJECT_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)','PROJECT_ROOT='+shlex.quote(str(PROJECT)))
        manifest=self.base/'mock-runtime-integrity.json';manifest.write_text('{}')
        trust=self.base/'mock-public-trust.json';trust.write_text('{}')
        value=value.replace('RUNTIME_MANIFEST=$PROJECT_ROOT/runtime-integrity.json','RUNTIME_MANIFEST='+shlex.quote(str(manifest))).replace('RELEASE_TRUST=$PROJECT_ROOT/deploy/release-public-trust.json','RELEASE_TRUST='+shlex.quote(str(trust)))
        private=self.base/'private-lease-installer.sh';private.write_text(value)
        fakebin=self.base/'fake-bin'
        for name,output in [('uname','Linux'),('id','0'),('stat','0')]:
            path=fakebin/name;path.write_text('#!/bin/sh\nprintf "%s\\n" '+shlex.quote(output)+'\n');path.chmod(0o755)
        flock=fakebin/'flock';flock.write_text('#!'+sys.executable+'\nimport fcntl,sys\nfcntl.flock(int(sys.argv[-1]),fcntl.LOCK_EX|fcntl.LOCK_NB)\n');flock.chmod(0o755)
        probe='''import fcntl,os,sys
def verify_lease():
    path=os.environ['PSEGRA_EXPECTED_LEASE']
    assert os.fstat(9).st_ino==os.stat(path).st_ino
    file=open(path,'a')
    try:
        fcntl.flock(file.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
    except BlockingIOError:
        return
    raise RuntimeError('generation lease released before installation completed')
'''
        self.binary.write_text('#!'+sys.executable+'\n'+probe+'''
args=sys.argv[1:]
if '--check-release' not in args:
    verify_lease()
with open(os.environ['PSEGRA_AGENT_CALLS'],'a') as out:out.write(' '.join(args)+'\\n')
if '--status' in args:print('dashboard ready')
''');self.binary.chmod(0o755)
        systemctl=fakebin/'systemctl';systemctl.write_text('#!'+sys.executable+'\n'+probe+'''
with open(os.environ['PSEGRA_SYSTEMCTL_CALLS'],'a') as out:out.write(' '.join(sys.argv[1:])+'\\n')
if sys.argv[1]=='is-active':sys.exit(1)
verify_lease()
''');systemctl.chmod(0o755)
        lease=self.root/'var/lib/seg-agent/configuration-transitions/lock'
        result=subprocess.run(['sh',str(private),'--ca-file',str(self.ca),'--token-file',str(self.token),str(self.binary),str(self.config)],capture_output=True,text=True,env={**self.env,'PSEGRA_FIXTURE_ROOT':str(self.root),'PSEGRA_EXPECTED_LEASE':str(lease)},timeout=15)
        self.assertEqual(result.returncode,0,result.stderr)
        calls=self.calls.read_text();self.assertIn('--installation-lease-fd 9',calls);self.assertIn('--status',calls)
        self.assertIn('start seg-agent.service',self.systemctl_calls.read_text())
        self.assertEqual((self.root/'etc/seg-agent/config.json').read_text(),self.config.read_text())
        # Once the parent shell exits, its lease is released.
        import fcntl
        with lease.open('a') as file:fcntl.flock(file.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)

    def test_explicit_replacement_preserves_previous_reviewed_config(self):
        active = self.root / 'etc/seg-agent/config.json'
        active.parent.mkdir(parents=True)
        active.write_text('{"reviewed":"previous"}')
        result = self.run_install('--replace-config')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((active.parent / 'config.json.previous').read_text(), '{"reviewed":"previous"}')
        self.assertEqual(json.loads(active.read_text()), self.settings)

    def test_failed_credential_preflight_makes_no_installation_changes(self):
        result = self.run_install(env={'PSEGRA_REJECT_CONFIG': '1'})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('failed preflight', result.stderr)
        self.assertFalse((self.root / 'etc/seg-agent/config.json').exists())
        self.assertFalse((self.root / 'usr/local/bin/seg-agent').exists())
        self.assertFalse(self.systemctl_calls.exists())

    def test_environment_token_is_persisted_private_without_entering_argv(self):
        secret = 'explicit-env-secret-never-on-command-line'
        result = self.run_install(token=False, env={'SEG_ENROLLMENT_TOKEN': secret})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.root / 'etc/seg-agent/enrollment-token').read_text(), secret)
        self.assertNotIn(secret, self.calls.read_text() + result.stdout + result.stderr)
        self.assertEqual((self.root / 'etc/seg-agent/enrollment-token').stat().st_mode & 0o777, 0o600)

    def test_staging_root_cannot_start_live_service(self):
        result = subprocess.run(['sh', str(INSTALLER), '--root', str(self.root),
                                 str(self.binary), str(self.config)], capture_output=True,
                                text=True, env=self.env, timeout=15)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('requires --no-start', result.stderr)
        self.assertFalse(self.systemctl_calls.exists())

    @unittest.skipUnless(os.environ.get('SEG_AGENT_BINARY'), 'Set SEG_AGENT_BINARY for real Go installer preflight')
    def test_real_agent_validates_and_stages_the_bootstrap_bundle(self):
        ca_key = self.base / 'test-ca.key'
        real_ca = self.base / 'test-ca.crt'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt',
                        'ec_paramgen_curve:P-256', '-nodes', '-keyout', str(ca_key),
                        '-out', str(real_ca), '-days', '1', '-subj', '/CN=Prṛthak (पृथक्) installer acceptance'],
                       capture_output=True, check=True, timeout=15)
        result = subprocess.run(['sh', str(INSTALLER), '--root', str(self.root), '--no-start',
                                 '--ca-file', str(real_ca), '--token-file', str(self.token),
                                 os.environ['SEG_AGENT_BINARY'], str(self.config)],
                                capture_output=True, text=True, env=self.env, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('private enrollment credential ready', result.stdout)
        self.assertFalse(self.systemctl_calls.exists())
        self.assertTrue((self.root / 'etc/systemd/system/multi-user.target.wants/seg-agent.service').is_symlink())

    @unittest.skipUnless(os.environ.get('SEG_AGENT_BINARY'), 'Set SEG_AGENT_BINARY for real Go readiness checks')
    def test_real_status_rejects_old_controller_and_previous_restart(self):
        state = self.base / 'readiness-state'
        state.mkdir()
        settings = dict(self.settings, state_dir=str(state), controller_url='https://new-controller.example:8787')
        self.config.write_text(json.dumps(settings))
        generation_file = state / 'readiness-generation.json'
        generation_file.write_text(json.dumps({'generation': 'new-process'}))
        ready = {'status': 'ready', 'server_id': 'node-unique', 'hostname': 'endpoint-test',
                 'controller_url': 'https://old-controller.example:8787',
                 'updated_at': datetime.now(timezone.utc).isoformat(), 'generation': 'new-process'}
        status_file = state / 'status.json'
        def query():
            status_file.write_text(json.dumps(ready))
            return subprocess.run([os.environ['SEG_AGENT_BINARY'], '--config', str(self.config), '--status'],
                                  capture_output=True, text=True, timeout=10)
        result = query()
        self.assertEqual(result.returncode, 2)
        self.assertIn('different controller', result.stdout)
        ready['controller_url'] = settings['controller_url']
        ready['generation'] = 'old-process'
        result = query()
        self.assertEqual(result.returncode, 2)
        self.assertIn('earlier service instance', result.stdout)
        ready['generation'] = 'new-process'
        self.assertEqual(query().returncode, 0)
        prepared = subprocess.run([os.environ['SEG_AGENT_BINARY'], '--config', str(self.config), '--prepare-start'],
                                  capture_output=True, text=True, timeout=10)
        self.assertEqual(prepared.returncode, 0, prepared.stderr)
        self.assertFalse(status_file.exists())
        self.assertNotEqual(json.loads(generation_file.read_text())['generation'], 'new-process')
        # Even an old daemon writing after restart preparation cannot satisfy readiness.
        result = query()
        self.assertEqual(result.returncode, 2)
        self.assertIn('earlier service instance', result.stdout)

    def test_symlink_at_effective_config_is_rejected(self):
        active = self.root / 'etc/seg-agent/config.json'
        active.parent.mkdir(parents=True)
        active.symlink_to(self.config)
        result = self.run_install('--replace-config')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('symlink', result.stderr)
        self.assertFalse(self.calls.exists())


if __name__ == '__main__':
    unittest.main()
