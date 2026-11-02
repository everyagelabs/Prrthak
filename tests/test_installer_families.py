"""OS-entrypoint acceptance with disposable roots; no host package/service changes."""
import json
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
import unittest

PROJECT = Path(__file__).resolve().parents[1]


class AgentFamilyInstallerTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='prthak-family-install-')
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.bundle = self.base / 'verified bundle'
        self.target = self.base / 'target root'
        self.fakebin = self.base / 'fake-bin'
        self.calls = self.base / 'agent-calls'
        self.commands = self.base / 'command-calls'
        for path in [self.bundle/'scripts', self.bundle/'agent', self.bundle/'deploy/systemd', self.target/'etc', self.target/'usr/bin', self.fakebin]:
            path.mkdir(parents=True, exist_ok=True)
        for name in ['install-agent.sh', 'install-agent-linux.sh', 'install-agent-rhel.sh', 'install-agent-ubuntu.sh']:
            shutil.copy2(PROJECT/'scripts'/name, self.bundle/'scripts'/name)
        shutil.copy2(PROJECT/'agent/README.md', self.bundle/'agent/README.md')
        shutil.copy2(PROJECT/'deploy/systemd/seg-agent.service', self.bundle/'deploy/systemd/seg-agent.service')
        self.config = self.base/'reviewed configuration.json'
        self.config.write_text((PROJECT/'agent/config.example.json').read_text())
        self.ca = self.base/'controller ca.pem'
        self.ca.write_text('public fixture CA')
        self.token = self.base/'private token'
        self.token.write_text('private-family-enrollment-token-never-an-argument')
        self.token.chmod(0o600)
        self.env = dict(os.environ, PATH=str(self.fakebin)+os.pathsep+os.environ.get('PATH',''),
                        PRTHAK_FAMILY_AGENT_CALLS=str(self.calls), PRTHAK_FAMILY_COMMAND_CALLS=str(self.commands),
                        PRTHAK_FAMILY_ARCH='x86_64')
        self.env.pop('SEG_ENROLLMENT_TOKEN', None)
        self.env.pop('SEG_ENROLLMENT_TOKEN_FILE', None)
        self.write_executable(self.fakebin/'uname', '#!/bin/sh\ncase "$1" in -s) echo Linux;; -m) echo "$PRTHAK_FAMILY_ARCH";; *) exit 99;; esac\n')
        for name in ['systemctl','journalctl','systemd-run','ss','firewall-cmd','flock']:
            # These are inspected as target files, never executed by staging.
            self.write_executable(self.target/'usr/bin'/name, '#!/bin/sh\nprintf "%s\\n" "'+name+' $*" >> "$PRTHAK_FAMILY_COMMAND_CALLS"\nexit 99\n')
        self.release('rhel','8.10')

    def write_executable(self, path, value):
        path.parent.mkdir(parents=True,exist_ok=True)
        path.write_text(value)
        path.chmod(0o755)

    def release(self, distro, version):
        (self.target/'etc/os-release').write_text('ID="'+distro+'"\nVERSION_ID="'+version+'"\n')

    def binary(self, relative='seg-agent', marker='bundled'):
        path=self.bundle/relative
        self.write_executable(path, '''#!/bin/sh
set -eu
printf '%s\\n' "MARKER='''+marker+''' $*" >> "$PRTHAK_FAMILY_AGENT_CALLS"
case "$*" in
 *--check-config*)
  if [ "${PRTHAK_FAMILY_REJECT_CONFIG:-0}" = 1 ]; then echo 'Credential preflight refused' >&2; exit 1; fi ;;
 *) exit 99 ;;
esac
''')
        return path

    def run_entrypoint(self, family, *options, config=True, env=None):
        argv=['sh',str(self.bundle/'scripts'/('install-agent-'+family+'.sh')), '--root',str(self.target), *options]
        if config: argv.append(str(self.config))
        return subprocess.run(argv, env={**self.env, **(env or {})}, capture_output=True, text=True, timeout=15)

    def test_rhel8_and9_stage_shared_installer_with_private_credentials(self):
        self.binary()
        for version in ['8.10','9.6']:
            with self.subTest(version=version):
                self.release('rhel',version)
                result=self.run_entrypoint('rhel','--no-start','--ca-file',str(self.ca),'--token-file',str(self.token))
                self.assertEqual(result.returncode,0,result.stderr)
                self.assertIn('Platform preflight passed: rhel '+version+', amd64',result.stdout)
                self.assertFalse(self.commands.exists())
                self.assertEqual((self.target/'etc/seg-agent/enrollment-token').stat().st_mode&0o777,0o600)
                self.assertEqual(json.loads((self.target/'etc/seg-agent/config.json').read_text()),json.loads(self.config.read_text()))
                self.assertTrue((self.target/'etc/systemd/system/multi-user.target.wants/seg-agent.service').is_symlink())
                self.assertNotIn(self.token.read_text(),self.calls.read_text()+result.stdout+result.stderr)

    def test_ubuntu_arm64_bundle_preflight_retains_ufw_and_never_runs_target_commands(self):
        self.release('ubuntu','26.04');self.binary()
        self.write_executable(self.target/'usr/bin/ufw','#!/bin/sh\nexit 99\n')
        result=self.run_entrypoint('ubuntu','--no-start','--token-file',str(self.token),env={'PRTHAK_FAMILY_ARCH':'aarch64'})
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('ubuntu 26.04, arm64',result.stdout)
        self.assertIn('UFW is installed',result.stdout)
        self.assertFalse(self.commands.exists())

    def test_source_tree_automatically_selects_matching_architecture_binary(self):
        for native,arch in [('x86_64','amd64'),('aarch64','arm64')]:
            self.binary('agent/bin/seg-agent-linux-'+arch,marker=arch)
            result=self.run_entrypoint('rhel','--no-start','--token-file',str(self.token),env={'PRTHAK_FAMILY_ARCH':native})
            self.assertEqual(result.returncode,0,result.stderr)
            calls=self.calls.read_text(); self.assertIn('MARKER='+arch,calls)
            self.calls.unlink()

    def test_check_only_makes_no_installation_or_credential_calls(self):
        self.binary()
        result=self.run_entrypoint('rhel','--check-only',config=False)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('Platform check only',result.stdout)
        self.assertFalse(self.calls.exists());self.assertFalse(self.commands.exists())
        self.assertFalse((self.target/'etc/seg-agent').exists())

    def test_missing_dependency_prints_family_package_guidance_before_any_install(self):
        self.binary();(self.target/'usr/bin/firewall-cmd').unlink()
        for family,distro,version,package in [('rhel','rhel','9.6','iproute,'),('ubuntu','ubuntu','26.04','iproute2,')]:
            self.release(distro,version)
            result=self.run_entrypoint(family,'--no-start','--token-file',str(self.token))
            self.assertNotEqual(result.returncode,0)
            self.assertIn('Missing target commands: firewall-cmd',result.stderr)
            self.assertIn(package,result.stderr)
            self.assertIn('post-install scripts may start firewalld',result.stderr)
            self.assertFalse(self.calls.exists());self.assertFalse(self.commands.exists())
            self.assertFalse((self.target/'etc/seg-agent').exists())

    def test_wrong_family_unsupported_release_and_architecture_fail_before_mutation(self):
        self.binary()
        for family,distro,version in [('rhel','ubuntu','26.04'),('ubuntu','ubuntu','24.04'),('rhel','rhel','10.0'),('ubuntu','debian','13')]:
            self.release(distro,version)
            result=self.run_entrypoint(family,'--no-start')
            self.assertNotEqual(result.returncode,0)
            self.assertIn('unsupported',result.stderr)
        self.release('rhel','8.10')
        result=self.run_entrypoint('rhel','--no-start',env={'PRTHAK_FAMILY_ARCH':'riscv64'})
        self.assertNotEqual(result.returncode,0);self.assertIn('amd64 and arm64',result.stderr)
        self.assertFalse(self.calls.exists());self.assertFalse((self.target/'etc/seg-agent').exists())

    def test_os_release_is_parsed_as_data_and_duplicate_keys_are_rejected(self):
        self.binary();marker=self.base/'os-release-was-executed'
        for value in ['ID="$(touch '+str(marker)+')"\nVERSION_ID="8.10"\n',
                      'ID="rhel"\nVERSION_ID="8.$(touch '+str(marker)+')"\n',
                      'ID="rhel"\nID="ubuntu"\nVERSION_ID="8.10"\n']:
            (self.target/'etc/os-release').write_text(value)
            result=self.run_entrypoint('rhel','--no-start')
            self.assertNotEqual(result.returncode,0)
            self.assertFalse(marker.exists());self.assertFalse(self.calls.exists())

    def test_staging_without_no_start_or_root_slash_cannot_control_live_services(self):
        self.binary()
        result=self.run_entrypoint('rhel','--token-file',str(self.token))
        self.assertNotEqual(result.returncode,0);self.assertIn('requires --no-start',result.stderr)
        result=self.run_entrypoint('rhel','--root','/','--no-start')
        self.assertNotEqual(result.returncode,0);self.assertIn('Use no --root',result.stderr)
        self.assertFalse(self.calls.exists());self.assertFalse(self.commands.exists())

    def test_failed_common_credential_preflight_preserves_existing_config_and_binary(self):
        self.binary()
        active=self.target/'etc/seg-agent/config.json';active.parent.mkdir(parents=True)
        active.write_text(self.config.read_text())
        previous=self.target/'usr/local/bin/seg-agent';previous.parent.mkdir(parents=True)
        previous.write_bytes(b'previous reviewed binary')
        result=self.run_entrypoint('rhel','--no-start','--token-file',str(self.token),env={'PRTHAK_FAMILY_REJECT_CONFIG':'1'})
        self.assertNotEqual(result.returncode,0);self.assertIn('Credential preflight refused',result.stderr)
        self.assertEqual(previous.read_bytes(),b'previous reviewed binary')
        self.assertEqual(active.read_text(),self.config.read_text());self.assertFalse(self.commands.exists())

    def test_explicit_config_replacement_and_wait_option_delegate_without_secret_arguments(self):
        self.binary()
        active=self.target/'etc/seg-agent/config.json';active.parent.mkdir(parents=True)
        active.write_text('{"previous":true}')
        result=self.run_entrypoint('rhel','--no-start','--replace-config','--wait-seconds','0','--token-file',str(self.token))
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual((active.parent/'config.json.previous').read_text(),'{"previous":true}')
        self.assertNotIn(self.token.read_text(),self.calls.read_text()+result.stdout+result.stderr)

    def test_setup_file_cannot_mix_manual_inputs_or_environment_token(self):
        self.binary()
        setup=self.base/'setup.json';setup.write_text('{}');setup.chmod(0o600)
        for options,environment in [(['--ca-file',str(self.ca)],{}),
                                     (['--token-file',str(self.token)],{}),
                                     (['--check-only'],{}),
                                     ([],{'SEG_ENROLLMENT_TOKEN':'private-env-token'})]:
            result=self.run_entrypoint('rhel','--setup-file',str(setup),'--no-start',*options,config=False,env=environment)
            self.assertNotEqual(result.returncode,0)
            self.assertIn('cannot be combined',result.stderr)
            self.assertNotIn('private-env-token',result.stdout+result.stderr)
            self.assertFalse(self.calls.exists());self.assertFalse(self.commands.exists())

    def test_configuration_transition_refuses_staging_or_bootstrap_inputs_before_any_execution(self):
        self.binary()
        kit=self.base/'private-configuration.json';kit.write_text('{}');kit.chmod(0o600)
        for options in [[],['--no-start'],['--setup-file',str(kit)],['--replace-config'],['--token-file',str(self.token)]]:
            with self.subTest(options=options):
                result=self.run_entrypoint('rhel','--configuration-file',str(kit),*options,config=False)
                self.assertNotEqual(result.returncode,0)
                self.assertIn('one live independently approved kit',result.stderr)
                self.assertFalse(self.calls.exists());self.assertFalse(self.commands.exists())

    def real_setup(self, *, separate_issuer=False, expired=False, expected_hostname=None):
        public=self.base/'setup-web-ca.pem'
        subprocess.run(['openssl','req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256',
                        '-nodes','-keyout',str(self.base/'setup-web-ca.key'),'-out',str(public),
                        '-days','1','-subj','/CN=Prthak private setup fixture'],check=True,capture_output=True,timeout=15)
        settings=json.loads(self.config.read_text());settings['interval_seconds']=30
        endpoint=''
        if separate_issuer:
            endpoint=public.read_text()
            settings['endpoint_ca_cert']='/etc/seg-agent/endpoint-ca.crt'
        instant=datetime.now(timezone.utc)
        setup=self.base/'private-setup.json'
        value={'schema_version':1,'issued_at':(instant-timedelta(minutes=10) if expired else instant).isoformat(),
               'expires_at':(instant-timedelta(seconds=1) if expired else instant+timedelta(minutes=10)).isoformat(),
               'expected_hostname':socket.gethostname() if expected_hostname is None else expected_hostname,
               'config':settings,'controller_ca_pem':public.read_text(),'endpoint_ca_pem':endpoint,
               'enrollment_token':'n'*43}
        setup.write_text(json.dumps(value));setup.chmod(0o600)
        return setup.resolve(),value

    @unittest.skipUnless(os.environ.get('SEG_AGENT_BINARY'), 'Set SEG_AGENT_BINARY for real GUI setup-file preparation')
    def test_gui_setup_file_stages_without_manual_config_ca_or_token_and_cleans_private_temp(self):
        shutil.copy2(os.environ['SEG_AGENT_BINARY'],self.bundle/'seg-agent')
        setup,value=self.real_setup()
        temporary=self.base/'setup-work';temporary.mkdir(mode=0o700)
        result=self.run_entrypoint('rhel','--setup-file',str(setup),'--no-start',config=False,env={'TMPDIR':str(temporary)})
        self.assertEqual(result.returncode,0,result.stderr)
        active=json.loads((self.target/'etc/seg-agent/config.json').read_text())
        self.assertEqual(active['controller_url'],value['config']['controller_url']);self.assertEqual(active['interval_seconds'],30)
        self.assertEqual((self.target/'etc/seg-agent/enrollment-token').read_text(),value['enrollment_token'])
        self.assertEqual((self.target/'etc/seg-agent/controller-ca.crt').read_text(),value['controller_ca_pem'])
        self.assertEqual((self.target/'etc/seg-agent/enrollment-token').stat().st_mode&0o777,0o600)
        self.assertNotIn(value['enrollment_token'],result.stdout+result.stderr)
        self.assertEqual(list(temporary.iterdir()),[]);self.assertFalse(self.commands.exists())

    @unittest.skipUnless(os.environ.get('SEG_AGENT_BINARY'), 'Set SEG_AGENT_BINARY for real separate-issuer setup preparation')
    def test_gui_setup_installs_separate_endpoint_ca_before_final_preflight(self):
        shutil.copy2(os.environ['SEG_AGENT_BINARY'],self.bundle/'seg-agent')
        self.release('ubuntu','26.04')
        setup,value=self.real_setup(separate_issuer=True)
        result=self.run_entrypoint('ubuntu','--setup-file',str(setup),'--no-start',config=False)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual((self.target/'etc/seg-agent/endpoint-ca.crt').read_text(),value['endpoint_ca_pem'])
        self.assertEqual((self.target/'etc/seg-agent/endpoint-ca.crt').stat().st_mode&0o777,0o644)
        self.assertFalse(self.commands.exists())

    @unittest.skipUnless(os.environ.get('SEG_AGENT_BINARY'), 'Set SEG_AGENT_BINARY for setup helper CLI isolation')
    def test_setup_helper_rejects_other_modes_and_positional_arguments_before_reading_files(self):
        binary = os.environ['SEG_AGENT_BINARY']
        for arguments in [
            ['--prepare-setup', '/missing-setup-file'],
            ['--setup-output', '/missing-output-directory'],
            ['--prepare-setup', '/missing-setup-file', '--setup-output', '/missing-output-directory', '--once'],
            ['--prepare-setup', '/missing-setup-file', '--setup-output', '/missing-output-directory', '--check-config'],
            ['--prepare-setup', '/missing-setup-file', '--setup-output', '/missing-output-directory', 'unreviewed-positional-input'],
        ]:
            with self.subTest(arguments=arguments):
                result = subprocess.run([binary, *arguments], capture_output=True, text=True, timeout=15)
                self.assertNotEqual(result.returncode, 0)
                self.assertTrue('required together' in result.stderr or 'another operating mode' in result.stderr, result.stderr)
                self.assertNotIn('cannot open', result.stderr)
                self.assertNotIn('Private endpoint setup prepared', result.stdout)

    @unittest.skipUnless(os.environ.get('SEG_AGENT_BINARY'), 'Set SEG_AGENT_BINARY for real invalid setup-file guard')
    def test_expired_or_wrong_recipient_gui_setup_stops_before_install_and_cleans_temp(self):
        shutil.copy2(os.environ['SEG_AGENT_BINARY'],self.bundle/'seg-agent')
        temporary=self.base/'setup-work';temporary.mkdir(mode=0o700)
        for options in [{'expired':True},{'expected_hostname':'definitely-another-endpoint'}]:
            setup,value=self.real_setup(**options)
            result=self.run_entrypoint('rhel','--setup-file',str(setup),'--no-start',config=False,env={'TMPDIR':str(temporary)})
            self.assertNotEqual(result.returncode,0)
            self.assertFalse((self.target/'etc/seg-agent/config.json').exists());self.assertFalse(self.commands.exists())
            self.assertNotIn(value['enrollment_token'],result.stdout+result.stderr)
            self.assertEqual(list(temporary.iterdir()),[])

    @unittest.skipUnless(os.environ.get('SEG_AGENT_BINARY'), 'Set SEG_AGENT_BINARY for real compatible-host Go staging preflight')
    def test_real_agent_credential_preflight_through_both_family_entrypoints(self):
        shutil.copy2(os.environ['SEG_AGENT_BINARY'],self.bundle/'seg-agent')
        real_ca=self.base/'actual public CA.pem'
        subprocess.run(['openssl','req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256',
                        '-nodes','-keyout',str(self.base/'fixture-ca.key'),'-out',str(real_ca),
                        '-days','1','-subj','/CN=Prthak family installer staging'],check=True,capture_output=True,timeout=15)
        for family,distro,version in [('rhel','rhel','9.6'),('ubuntu','ubuntu','26.04')]:
            with self.subTest(family=family):
                self.release(distro,version)
                result=self.run_entrypoint(family,'--no-start','--ca-file',str(real_ca),'--token-file',str(self.token))
                self.assertEqual(result.returncode,0,result.stderr)
                self.assertIn('HTTPS CA and private one-time enrollment token ready',result.stdout)
                self.assertIn('staged and enabled for the target boot',result.stdout)
                self.assertFalse(self.commands.exists())


class AgentFamilyPackageTests(unittest.TestCase):
    def test_isolated_packages_include_both_family_entrypoints_and_guide(self):
        with tempfile.TemporaryDirectory(prefix='prthak-private-package-') as temp:
            target=Path(temp)
            inputs=['scripts/package-agent.py','agent/internal/agent/types.go','agent/config.example.json','agent/README.md',
                    'docs/managed-enforcement.md','docs/whole-server-default-deny.md','docs/traffic-capture.md','docs/fleet-enrollment.md','docs/linux-validation.md','docs/scale-validation.md','docs/ipset-enforcement.md',
                    'docs/policy-signing.md','docs/linux-agent-installation.md','docs/pilot-gui-installation.md','docs/authentication.md','deploy/systemd/seg-agent.service',
                    'scripts/install-agent.sh','scripts/install-agent-linux.sh','scripts/install-agent-rhel.sh','scripts/install-agent-ubuntu.sh',
                    'scripts/prepare-managed-ipsets.py','scripts/verify-release.py']
            for name in inputs:
                path=target/name;path.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(PROJECT/name,path)
            for arch in ['amd64','arm64']:
                path=target/'agent/bin'/('seg-agent-linux-'+arch);path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(b'fixture binary '+arch.encode())
            env=dict(os.environ);env.pop('PRTHAK_RELEASE_SIGNING_KEY_FILE',None)
            result=subprocess.run([sys.executable,str(target/'scripts/package-agent.py')],cwd=target,env=env,capture_output=True,text=True,timeout=15)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertIn('Unsigned lab packages only',result.stdout)
            archives=list((target/'dist').glob('*.tar.gz'));self.assertEqual(len(archives),2)
            for archive in archives:
                with tarfile.open(archive) as bundle:
                    names={'/'.join(Path(item.name).parts[1:]) for item in bundle.getmembers()}
                    self.assertEqual(len(names),22)
                    self.assertIn('docs/authentication.md',names)
                    for name in ['scripts/install-agent-linux.sh','scripts/install-agent-rhel.sh','scripts/install-agent-ubuntu.sh','docs/linux-agent-installation.md','docs/whole-server-default-deny.md','docs/traffic-capture.md','docs/fleet-enrollment.md']:
                        self.assertIn(name,names)
                        item=next(item for item in bundle.getmembers() if item.name.endswith('/'+name))
                        self.assertEqual(bundle.extractfile(item).read(),(PROJECT/name).read_bytes())
                    install=next(item for item in bundle.getmembers() if item.name.endswith('/INSTALL.txt'))
                    guidance=bundle.extractfile(install).read().decode()
                    self.assertIn('install-agent-rhel.sh',guidance);self.assertIn('install-agent-ubuntu.sh',guidance)
                    self.assertNotIn('enrollment-token-value',guidance)
