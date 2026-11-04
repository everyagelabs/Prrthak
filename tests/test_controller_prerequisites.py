"""Controller bootstrap fixtures; no package, Docker or systemd command executes."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
PUBLIC_KEY = b'-----BEGIN PGP PUBLIC KEY BLOCK-----\nPUBLIC FIXTURE\n-----END PGP PUBLIC KEY BLOCK-----\n'
SPEC = importlib.util.spec_from_file_location('controller_prerequisites', ROOT/'deploy/appliance/install_prerequisites.py')
bootstrap = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bootstrap)


class FakeHost:
    def __init__(self, root):
        self.root = root
        self.calls = []
        self.state = 'active'
        self.rootless = False
        self.conflict = ''
        self.failure = ''
        self.rpm_inventory = 'rpm\nbash\npodman-helper\n'
        self.rpm_stderr = b''
        self.compose_version = '2.39.0'
        self.gpg_output = None
        self.configuration_status = 'validated'

    def executable(self, relative):
        path = self.root/relative.lstrip('/')
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('#!/bin/sh\nexit 99\n')
        path.chmod(0o755)

    def __call__(self, arguments, timeout=30):
        self.calls.append((list(arguments), timeout))
        name = Path(arguments[0]).name
        output, code = '', 0
        if name == self.failure:
            return subprocess.CompletedProcess(arguments, 37, b'', b'private fixture error')
        if name in ('dnf', 'env') and 'install' in arguments:
            packages = arguments[arguments.index('install')+1:]
            if 'docker-ce' in packages:
                self.executable('/usr/bin/docker')
            if 'docker-compose-plugin' in packages:
                self.executable('/usr/libexec/docker/cli-plugins/docker-compose')
            if 'curl' in packages:
                self.executable('/usr/bin/curl')
            if 'gnupg2' in packages or 'gnupg' in packages:
                self.executable('/usr/bin/gpg')
            if 'shadow-utils' in packages or 'passwd' in packages:
                for value in ('useradd', 'groupadd', 'nologin'):
                    self.executable('/usr/bin/'+value)
        elif name == 'rpm' and '-qa' in arguments:
            return subprocess.CompletedProcess(arguments, 0, (self.rpm_inventory + self.conflict).encode(),
                                               self.rpm_stderr)
        elif name == 'rpm' and '-q' in arguments:
            packages = arguments[arguments.index('--qf')+2:]
            missing = [package for package in packages if package != self.conflict]
            output = '\n'.join(self.conflict if package == self.conflict else f'package {package} is not installed'
                               for package in packages)
            code = len(missing)
        elif name == 'dpkg-query':
            output = self.conflict+' ii ' if self.conflict else ''
        elif name == 'curl':
            Path(arguments[arguments.index('--output')+1]).write_bytes(PUBLIC_KEY)
        elif name == 'gpg':
            output = self.gpg_output or 'pub:-:4096:1:fixture::::::\nfpr:::::::::'+bootstrap.RHEL_FINGERPRINT+':\n'
        elif name == 'systemctl':
            if arguments[1] == 'is-active':
                output, code = self.state, 0 if self.state == 'active' else 3
            elif arguments[1] in ('enable', 'start'):
                self.state = 'active'
        elif name == 'docker':
            if 'compose' in arguments:
                output = self.compose_version
            elif 'info' in arguments:
                output = json.dumps({'OSType':'linux', 'SecurityOptions':['name=rootless'] if self.rootless else ['name=seccomp']})
        elif '-I' in arguments:
            output = json.dumps({'status':self.configuration_status})
        return subprocess.CompletedProcess(arguments, code, output.encode(), b'')


class ControllerPrerequisiteTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='prthak-controller-bootstrap-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.uid = os.geteuid()
        for directory in ('etc', 'usr/bin', 'usr/libexec/docker/cli-plugins', 'run', 'proc/1',
                          'etc/pki/rpm-gpg', 'etc/pki/tls/certs', 'etc/yum.repos.d',
                          'etc/apt/keyrings', 'etc/apt/sources.list.d', 'etc/ssl/certs'):
            (self.root/directory).mkdir(parents=True, exist_ok=True)
        (self.root/'etc/os-release').write_text('ID=rhel\nVERSION_ID="9.4"\n')
        (self.root/'proc/1/comm').write_text('systemd\n')
        (self.root/'etc/pki/tls/certs/ca-bundle.crt').write_text('public fixture')
        (self.root/'etc/ssl/certs/ca-certificates.crt').write_text('public fixture')
        self.host = FakeHost(self.root)
        for name in ('dnf', 'rpm', 'apt-get', 'env', 'dpkg-query', 'curl', 'gpg', 'tar', 'systemctl', 'useradd', 'groupadd', 'nologin'):
            self.host.executable('/usr/bin/'+name)
        self.installer = bootstrap.Installer(self.root, self.host, expected_uid=self.uid)
        self.platform = patch.object(bootstrap.platform, 'system', return_value='Linux')
        self.machine = patch.object(bootstrap.platform, 'machine', return_value='x86_64')
        self.user = patch.object(bootstrap.os, 'geteuid', return_value=0)
        for context in (self.platform, self.machine, self.user):
            context.start(); self.addCleanup(context.stop)
        self.environment = patch.dict(os.environ, {'DOCKER_HOST':'', 'DOCKER_CONTEXT':''})
        self.environment.start(); self.addCleanup(self.environment.stop)

    def healthy(self):
        self.host.executable('/usr/bin/docker')
        self.host.executable('/usr/libexec/docker/cli-plugins/docker-compose')

    def names(self):
        return [Path(arguments[0]).name for arguments, _ in self.host.calls]

    def test_fresh_rhel_adds_authenticated_owned_repo_and_reads_back_runtime(self):
        self.host.compose_version = 'v5.7.0'
        self.installer.prepare()
        repo = (self.root/'etc/yum.repos.d/prthak-docker-ce.repo').read_text()
        self.assertIn('gpgcheck=1', repo)
        self.assertNotIn('gpgcheck=0', repo)
        self.assertEqual((self.root/'etc/pki/rpm-gpg/PRTHAK-DOCKER.asc').read_bytes(), PUBLIC_KEY)
        installs = [args for args, _ in self.host.calls if Path(args[0]).name == 'dnf']
        self.assertTrue(any('docker-ce' in arguments for arguments in installs))
        self.assertFalse(any('remove' in args or '--allowerasing' in args for args in installs))
        self.assertIn('info', self.host.calls[-1][0])

    def test_fresh_ubuntu_uses_signed_by_scope_and_never_upgrades_or_removes(self):
        (self.root/'etc/os-release').write_text('ID=ubuntu\nVERSION_ID="26.04"\nVERSION_CODENAME=resolute\n')
        self.installer.prepare()
        repo = (self.root/'etc/apt/sources.list.d/prthak-docker.sources').read_text()
        self.assertIn('Signed-By: /etc/apt/keyrings/prthak-docker.asc', repo)
        installs = [args for args, _ in self.host.calls if 'install' in args]
        self.assertTrue(installs)
        self.assertTrue(all('--no-upgrade' in args and '--no-remove' in args for args in installs))
        self.assertNotIn('firewalld', str(self.host.calls))

    def test_healthy_existing_runtime_has_no_package_repo_or_service_mutation(self):
        self.healthy()
        self.installer.prepare(); self.host.calls.clear(); self.installer.prepare()
        self.assertNotIn('dnf', self.names()); self.assertNotIn('apt-get', self.names())
        self.assertNotIn('curl', self.names())
        self.assertFalse(any('enable' in args or 'start' in args for args, _ in self.host.calls))
        self.assertFalse((self.root/'etc/yum.repos.d/prthak-docker-ce.repo').exists())
        self.assertTrue(all('--config' in args and '--host' in args for args, _ in self.host.calls if Path(args[0]).name == 'docker'))

    def test_existing_missing_compose_only_installs_plugin_using_existing_repos(self):
        self.host.executable('/usr/bin/docker')
        self.installer.prepare()
        packages = [args[args.index('install')+1:] for args, _ in self.host.calls if 'install' in args]
        self.assertEqual(packages, [['docker-compose-plugin']])
        self.assertNotIn('curl', self.names())

    def test_existing_stopped_docker_starts_without_changing_enablement(self):
        self.healthy(); self.host.state = 'inactive'
        self.installer.prepare()
        starts = [args for args, _ in self.host.calls if Path(args[0]).name == 'systemctl' and args[1] in ('start', 'enable')]
        self.assertEqual([args[1:] for args in starts], [['start', 'docker.service']])

    def test_unknown_or_injected_os_refuses_before_any_command(self):
        for content in ('ID=rhel\nVERSION_ID=8.10\n', 'ID=ubuntu\nVERSION_ID=24.04\n',
                        'ID="$(touch /tmp/never-execute)"\nVERSION_ID=9\n', 'ID=rhel\nID=rhel\nVERSION_ID=9\n'):
            with self.subTest(content=content):
                (self.root/'etc/os-release').write_text(content)
                with self.assertRaises(bootstrap.Blocked): self.installer.prepare()
                self.assertEqual(self.host.calls, [])

    def test_non_systemd_and_unsupported_cpu_refuse_before_any_command(self):
        (self.root/'proc/1/comm').write_text('init\n')
        with self.assertRaises(bootstrap.Blocked): self.installer.prepare()
        (self.root/'proc/1/comm').write_text('systemd\n')
        with patch.object(bootstrap.platform, 'machine', return_value='s390x'), self.assertRaises(bootstrap.Blocked):
            self.installer.prepare()
        self.assertEqual(self.host.calls, [])

    def test_remote_or_custom_docker_environment_refuses_before_any_command(self):
        for values in ({'DOCKER_HOST':'tcp://192.0.2.1:2375'}, {'DOCKER_CONTEXT':'other'}):
            with self.subTest(values=values), patch.dict(os.environ, values), self.assertRaises(bootstrap.Blocked):
                self.installer.prepare()
            self.assertEqual(self.host.calls, [])

    def test_rootless_or_unknown_daemon_is_not_reported_ready(self):
        self.healthy(); self.host.rootless = True
        with self.assertRaisesRegex(bootstrap.Blocked, 'rootful'): self.installer.prepare()
        self.assertNotIn('dnf', self.names())

    def test_container_conflict_is_preserved_and_blocks_packages(self):
        self.host.conflict = 'podman'
        with self.assertRaisesRegex(bootstrap.Blocked, 'conflicts'): self.installer.prepare()
        self.assertNotIn('dnf', self.names()); self.assertNotIn('curl', self.names())

    def test_package_database_query_error_blocks_before_dependency_mutations(self):
        for family, manager in (('rhel','rpm'),('ubuntu','dpkg-query')):
            with self.subTest(family=family):
                if family == 'ubuntu':
                    (self.root/'etc/os-release').write_text('ID=ubuntu\nVERSION_ID="26.04"\nVERSION_CODENAME=resolute\n')
                self.host.failure=manager;self.host.calls.clear()
                with self.assertRaisesRegex(bootstrap.Blocked, 'package state'):self.installer.prepare()
                self.assertNotIn('dnf',self.names());self.assertNotIn('env',self.names());self.assertNotIn('curl',self.names())

    def test_untrustworthy_rpm_inventory_blocks_even_on_zero_exit(self):
        for inventory, stderr in (('', b''), ('rpm\nbash\n', b'package database error')):
            with self.subTest(inventory=inventory, stderr=stderr):
                self.host.rpm_inventory, self.host.rpm_stderr = inventory, stderr
                self.host.calls.clear()
                with self.assertRaisesRegex(bootstrap.Blocked, 'package state'):
                    self.installer.prepare()
                self.assertNotIn('dnf', self.names())
                self.assertNotIn('curl', self.names())

    def test_unsupported_compose_plugin_is_preserved(self):
        self.healthy()
        self.host.compose_version = '1.29.2'
        with self.assertRaisesRegex(bootstrap.Blocked, 'unsupported plugin was preserved'):
            self.installer.prepare()
        self.assertNotIn('dnf', self.names())

    def test_foreign_repository_or_key_symlink_is_preserved(self):
        repo = self.root/'etc/yum.repos.d/prthak-docker-ce.repo'; repo.write_text('foreign\n')
        with self.assertRaises(bootstrap.Blocked): self.installer.prepare()
        self.assertEqual(repo.read_text(), 'foreign\n'); self.assertNotIn('curl', self.names())
        repo.unlink(); target = self.root/'etc/pki/rpm-gpg/PRTHAK-DOCKER.asc'; target.symlink_to(repo)
        self.host.calls.clear()
        with self.assertRaises(bootstrap.Blocked): self.installer.prepare()
        self.assertTrue(target.is_symlink()); self.assertNotIn('curl', self.names())

    def test_foreign_repository_blocks_even_missing_base_or_account_packages(self):
        for value in ('curl','gpg','useradd'):(self.root/'usr/bin'/value).unlink()
        repo=self.root/'etc/yum.repos.d/prthak-docker-ce.repo';repo.write_text('foreign\n')
        with self.assertRaises(bootstrap.Blocked):self.installer.prepare()
        self.assertEqual(self.host.calls,[])

    def test_foreign_key_is_compared_before_any_package_action(self):
        (self.root/'etc/pki/rpm-gpg/PRTHAK-DOCKER.asc').write_bytes(b'foreign public bytes')
        (self.root/'usr/bin/useradd').unlink()
        with self.assertRaises(bootstrap.Blocked):self.installer.prepare()
        self.assertNotIn('dnf',self.names());self.assertNotIn('env',self.names())

    def test_oversized_owned_repository_is_rejected_before_reading_or_packages(self):
        path=self.root/'etc/yum.repos.d/prthak-docker-ce.repo';path.write_bytes(b'x'*262145)
        with self.assertRaisesRegex(bootstrap.Blocked,'bounded'):self.installer.prepare()
        self.assertEqual(self.host.calls,[])

    def test_writable_compose_plugin_is_never_executed(self):
        self.healthy(); (self.root/'usr/libexec/docker/cli-plugins/docker-compose').chmod(0o777)
        with self.assertRaises(bootstrap.Blocked): self.installer.prepare()
        self.assertNotIn('docker', self.names()); self.assertNotIn('dnf', self.names())

    def test_dangling_tool_symlink_is_preserved_and_never_treated_as_missing(self):
        docker = self.root/'usr/bin/docker'
        docker.symlink_to(self.root/'missing-docker')
        with self.assertRaisesRegex(bootstrap.Blocked, 'symlink'):
            self.installer.prepare()
        self.assertTrue(docker.is_symlink())
        self.assertEqual(self.host.calls, [])

    def test_pinned_key_bundled_with_another_key_is_not_imported(self):
        self.host.gpg_output = ('pub:-:4096:1:fixture::::::\nfpr:::::::::'+bootstrap.RHEL_FINGERPRINT+':\n'
                                'pub:-:4096:1:other::::::\nfpr:::::::::'+'B'*40+':\n')
        with self.assertRaisesRegex(bootstrap.Blocked, 'fingerprint'): self.installer.prepare()
        self.assertFalse(any('--import' in args for args, _ in self.host.calls))
        self.assertNotIn('dnf', self.names())

    def test_existing_main_apt_docker_repository_is_preserved(self):
        (self.root/'etc/os-release').write_text('ID=ubuntu\nVERSION_ID="26.04"\nVERSION_CODENAME=resolute\n')
        source=self.root/'etc/apt/sources.list';source.write_text('deb https://download.docker.com/linux/ubuntu resolute stable\n')
        with self.assertRaisesRegex(bootstrap.Blocked, 'existing Docker repository'): self.installer.prepare()
        self.assertEqual(source.read_text(), 'deb https://download.docker.com/linux/ubuntu resolute stable\n')
        self.assertFalse((self.root/'etc/apt/sources.list.d/prthak-docker.sources').exists())

    def test_package_failure_never_starts_docker_or_claims_readiness(self):
        self.host.failure = 'dnf'
        with self.assertRaises(bootstrap.Blocked): self.installer.prepare()
        self.assertNotIn('systemctl', self.names()); self.assertNotIn('docker', self.names())

    def test_missing_account_tools_are_prepared_and_verified(self):
        self.healthy(); (self.root/'usr/bin/useradd').unlink()
        self.installer.prepare()
        packages = [args[args.index('install')+1:] for args, _ in self.host.calls if 'install' in args]
        self.assertEqual(packages, [['shadow-utils']])

    def test_manager_configuration_preflight_is_read_only_and_fails_closed(self):
        self.installer.configuration_preflight(self.root,['--gui-setup','--data-root','/var/lib/test'])
        arguments=self.host.calls[-1][0]
        self.assertEqual(arguments[1],'-I');self.assertEqual(arguments[-1],'--validate-only')
        self.assertNotIn('dnf',self.names())
        self.host.configuration_status='unknown'
        with self.assertRaisesRegex(bootstrap.Blocked,'preflight'):self.installer.configuration_preflight(self.root,['--gui-setup'])

    def test_root_docker_home_rejects_unsafe_config_and_plugin_overrides(self):
        home=self.root/'root';home.mkdir();docker=home/'.docker';docker.mkdir()
        config=docker/'config.json';config.write_text('{"auths":{}}')
        self.installer.docker_home_safe(home)
        config.write_text('{"cliPluginsExtraDirs":["/untrusted"]}')
        with self.assertRaisesRegex(bootstrap.Blocked,'plugin overrides'):self.installer.docker_home_safe(home)
        config.write_text('{"auths":{}}');plugins=docker/'cli-plugins';plugins.mkdir();(plugins/'docker-compose').write_text('not executable')
        with self.assertRaisesRegex(bootstrap.Blocked,'system Docker plugins'):self.installer.docker_home_safe(home)
        (plugins/'docker-compose').unlink();config.chmod(0o666)
        with self.assertRaises(bootstrap.Blocked):self.installer.docker_home_safe(home)
        self.assertEqual(self.host.calls,[])


class ControllerArgumentTests(unittest.TestCase):
    def test_default_is_gui_but_legacy_and_read_only_paths_skip_preparation(self):
        self.assertEqual(bootstrap.manager_arguments([]), (['--gui-setup'], True))
        for arguments in (['--help'], ['--validate-only'], ['--no-start'], ['--env-file','/private/initial.env']):
            result, automatic = bootstrap.manager_arguments(arguments)
            self.assertFalse(automatic)
            self.assertTrue(all(value in result for value in arguments))
        for arguments in (['--shell'], ['--data-root'], ['--gui-setup','--env-file','/a'], ['--no-start','--no-start']):
            with self.subTest(arguments=arguments), self.assertRaises(bootstrap.Blocked): bootstrap.manager_arguments(arguments)

    def test_read_only_main_delegates_without_dependency_actions(self):
        for arguments in ('--help', '--validate-only', '--no-start'):
            with self.subTest(arguments=arguments), patch.object(bootstrap, 'delegate') as delegate, patch.object(bootstrap.Installer, 'prepare') as prepare:
                self.assertEqual(bootstrap.main(['--release-root',str(ROOT),'--',arguments]), 0)
                prepare.assert_not_called(); self.assertIn(arguments, delegate.call_args.args[1])

    def test_delegate_isolated_python_clears_python_and_docker_injection(self):
        execute = Mock()
        with patch.object(bootstrap.platform, 'system', return_value='Darwin'), patch.dict(os.environ, {'PYTHONPATH':'/untrusted', 'DOCKER_CONFIG':'/untrusted', 'LD_PRELOAD':'/untrusted'}):
            bootstrap.delegate(ROOT, ['--gui-setup','--validate-only'], execute=execute)
        command, arguments, environment = execute.call_args.args
        self.assertEqual(arguments[1], '-I')
        self.assertNotIn('PYTHONPATH', environment); self.assertNotIn('DOCKER_CONFIG', environment); self.assertNotIn('LD_PRELOAD', environment)
        self.assertEqual(environment['PATH'], bootstrap.PATH)

    def test_timeout_kills_owned_command_process_group(self):
        process = Mock(pid=12345, returncode=-9)
        process.wait.side_effect = [subprocess.TimeoutExpired('fixture', 1), 0]
        with patch.object(bootstrap.subprocess, 'Popen', return_value=process), patch.object(bootstrap.os, 'killpg') as kill, self.assertRaises(bootstrap.Blocked):
            bootstrap.Runner()(['/never-execute'], timeout=1)
        kill.assert_called_once_with(12345, bootstrap.signal.SIGKILL)


if __name__ == '__main__': unittest.main()
