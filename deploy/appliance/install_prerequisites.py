#!/usr/bin/env python3
"""Fixed controller dependency preparation, followed by GUI-only setup.

Only the reviewed local root installer calls this program. Tests inject a private
filesystem root and command runner through Python, never a CLI/environment hook.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import platform
import pwd
import re
import signal
import stat
import subprocess
import sys
import tempfile

PATH = '/usr/sbin:/usr/bin:/sbin:/bin'
SOCKET = 'unix:///var/run/docker.sock'
RHEL_KEY = 'https://download.docker.com/linux/rhel/gpg'
UBUNTU_KEY = 'https://download.docker.com/linux/ubuntu/gpg'
RHEL_FINGERPRINT = '060A61C51B558A7F742B77AAC52FEB6B621E9F35'
PLUGIN_DIRS = ('/usr/local/lib/docker/cli-plugins', '/usr/local/libexec/docker/cli-plugins',
               '/usr/lib/docker/cli-plugins', '/usr/libexec/docker/cli-plugins')
CONFLICTS = {
    'rhel': ('podman', 'podman-docker', 'runc', 'containerd', 'docker', 'docker-client',
             'docker-common', 'docker-engine', 'docker-latest', 'docker-latest-logrotate'),
    'ubuntu': ('podman', 'podman-docker', 'runc', 'containerd', 'docker.io', 'docker-compose',
               'docker-compose-v2', 'docker-buildx', 'docker-doc'),
}


class Blocked(ValueError):
    pass


def environment():
    return {'PATH': PATH, 'LANG': 'C', 'LC_ALL': 'C', 'HOME': pwd.getpwuid(os.geteuid()).pw_dir}


def manager_arguments(arguments):
    values = list(arguments)
    seen = set()
    index = 0
    while index < len(values):
        name = values[index]
        if name in seen:
            raise Blocked('Duplicate installer option')
        seen.add(name)
        if name in ('--help', '-h', '--gui-setup', '--validate-only', '--no-start'):
            index += 1
        elif name in ('--env-file', '--data-root'):
            if index + 1 >= len(values) or not values[index + 1] or values[index + 1].startswith('-'):
                raise Blocked('Installer option requires a value')
            index += 2
        else:
            raise Blocked('Unsupported installer option')
    if '--gui-setup' in seen and '--env-file' in seen:
        raise Blocked('Choose GUI setup or an explicit environment file, not both')
    if '--env-file' not in seen and '--gui-setup' not in seen:
        values.append('--gui-setup')
    automatic = not seen.intersection(('--env-file', '--validate-only', '--no-start', '--help', '-h'))
    return values, automatic


class Runner:
    def __call__(self, arguments, timeout=30):
        with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
            try:
                process = subprocess.Popen(arguments, stdin=subprocess.DEVNULL, stdout=output,
                                           stderr=errors, env=environment(), cwd='/', start_new_session=True)
                try:
                    process.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.wait()
                    raise Blocked('Dependency command timed out; no controller was started') from None
            except OSError:
                raise Blocked('A required dependency operation could not start; no controller was started') from None
            output.seek(0); errors.seek(0)
            stdout, stderr = output.read(4 * 1024 * 1024 + 1), errors.read(4 * 1024 * 1024 + 1)
            if len(stdout) > 4 * 1024 * 1024 or len(stderr) > 4 * 1024 * 1024:
                raise Blocked('Dependency command output exceeded its limit')
            return subprocess.CompletedProcess(arguments, process.returncode, stdout, stderr)


class Installer:
    def __init__(self, root=Path('/'), runner=None, expected_uid=0):
        self.root = Path(root)
        self.runner = runner or Runner()
        self.expected_uid = expected_uid
        self.family = ''
        self.arch = ''
        self.work = self.path('/run/prthak-installation')
        self.cli_config = self.work / 'docker-cli'
        self.key_cache = {}

    def path(self, value):
        return self.root / value.lstrip('/')

    def protected(self, path, allow_missing=False, resolve=False, directory=False):
        path = Path(path)
        if resolve:
            path = path.resolve(strict=True)
        try:
            relative = path.relative_to(self.root)
        except ValueError:
            raise Blocked('A dependency path escapes the protected filesystem') from None
        current = self.root
        for component in (None, *relative.parts):
            if component is not None:
                current = current / component
            try:
                info = current.lstat()
            except FileNotFoundError:
                if allow_missing:
                    return path
                raise Blocked('A required protected dependency path is missing') from None
            if stat.S_ISLNK(info.st_mode) or info.st_uid != self.expected_uid or info.st_mode & 0o022:
                raise Blocked('Dependency paths must be protected and root-owned; symlinks are refused')
            if current != path and not stat.S_ISDIR(info.st_mode):
                raise Blocked('A dependency ancestor is not a directory')
        if directory and not stat.S_ISDIR(info.st_mode):
            raise Blocked('A protected dependency directory is required')
        return path

    def tool(self, name, optional=False):
        for prefix in ('/usr/bin/', '/usr/sbin/', '/bin/', '/sbin/'):
            candidate = self.path(prefix + name)
            if candidate.exists() or candidate.is_symlink():
                try:
                    self.protected(candidate, resolve=True)
                except (OSError, RuntimeError):
                    raise Blocked('A dependency tool symlink cannot be resolved safely') from None
                if candidate.is_file() and os.access(candidate, os.X_OK):
                    return str(candidate)
                raise Blocked('A fixed dependency tool is not executable')
        if optional:
            return None
        raise Blocked('A required OS tool is missing: ' + name)

    def call(self, arguments, timeout=30, required=True):
        result = self.runner(list(arguments), timeout=timeout)
        if required and result.returncode:
            raise Blocked('Dependency operation failed; preserve the error state and rerun after review')
        return result.stdout.decode('utf-8', 'replace').strip(), result.returncode

    def mkdir(self, path, mode=0o700):
        self.protected(path, allow_missing=True)
        path.mkdir(parents=True, mode=mode, exist_ok=True)
        self.protected(path, directory=True)
        if path.stat().st_mode & 0o077:
            raise Blocked('Installer private state has unsafe permissions')

    def validate_host(self):
        if platform.system() != 'Linux' or os.geteuid() != 0:
            raise Blocked('Automatic dependency installation requires Linux and sudo/root')
        for name in ('DOCKER_HOST', 'DOCKER_CONTEXT'):
            value = os.environ.get(name, '')
            if value and not (name == 'DOCKER_HOST' and value == SOCKET):
                raise Blocked('Remove remote/custom Docker environment settings before using the local installer')
        release = self.path('/etc/os-release')
        self.protected(release, resolve=True)
        if release.stat().st_size > 16384:
            raise Blocked('OS identification is too large')
        fields = {}
        for line in release.read_text().splitlines():
            match = re.fullmatch(r'(ID|VERSION_ID|VERSION_CODENAME)=(?:"([^"\n]*)"|\x27([^\x27\n]*)\x27|([^\s\n]+))', line)
            if not match:
                continue
            key, double, single, plain = match.groups()
            if key in fields:
                raise Blocked('OS identification contains duplicate fields')
            fields[key] = next(value for value in (double, single, plain) if value is not None)
        family, version = fields.get('ID'), fields.get('VERSION_ID', '')
        if family == 'rhel' and re.fullmatch(r'9(?:\.[0-9]+)*', version):
            self.family = 'rhel'
        elif family == 'ubuntu' and version == '26.04' and fields.get('VERSION_CODENAME') == 'resolute':
            self.family = 'ubuntu'
        else:
            raise Blocked('Automatic controller preparation supports RHEL 9 and Ubuntu 26.04 only')
        architecture = platform.machine()
        if architecture in ('x86_64', 'amd64'):
            self.arch = 'amd64'
        elif architecture in ('aarch64', 'arm64'):
            self.arch = 'arm64'
        else:
            raise Blocked('Controller preparation supports only AMD64 and ARM64')
        if self.path('/proc/1/comm').read_text().strip() != 'systemd':
            raise Blocked('A genuine systemd host is required')

    def package(self, packages):
        if not packages:
            return
        if self.family == 'rhel':
            arguments = [self.tool('dnf'), '-y', '--setopt=install_weak_deps=False', 'install', *packages]
        else:
            arguments = [self.tool('env'), 'DEBIAN_FRONTEND=noninteractive', 'APT_LISTCHANGES_FRONTEND=none',
                         self.tool('apt-get'), '-y', '--no-install-recommends', '--no-upgrade', '--no-remove', 'install', *packages]
        self.call(arguments, timeout=900)

    def conflicts(self):
        if self.family == 'rhel':
            # Named queries count absent packages as errors, even on a clean host.
            # Inventory installed names instead; any inventory failure must block.
            output, code = self.call([self.tool('rpm'), '-qa', '--qf', '%{NAME}\n'], required=False)
            found = set(output.splitlines()).intersection(CONFLICTS['rhel'])
        else:
            output, code = self.call([self.tool('dpkg-query'), '-W', '-f=${binary:Package} ${db:Status-Abbrev}\n',
                                   *CONFLICTS['ubuntu']], required=False)
            found = {line.split()[0].split(':')[0] for line in output.splitlines()
                     if len(line.split()) >= 2 and line.split()[1].startswith('ii')}
            found.intersection_update(CONFLICTS['ubuntu'])
        allowed_codes = (0,) if self.family == 'rhel' else (0, 1)
        if code not in allowed_codes:
            raise Blocked('The existing package state could not be inspected; no package installation was attempted')
        if found:
            raise Blocked('An existing container stack conflicts with automatic Docker preparation; no packages were removed')

    def bounded_file(self, path, limit):
        self.protected(path)
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != self.expected_uid or info.st_mode & 0o022 or info.st_size > limit:
                raise Blocked('An existing installer input is not a protected bounded regular file')
            raw = stream.read(limit + 1)
            if len(raw) > limit:
                raise Blocked('An installer input grew beyond its limit')
            return raw

    def atomic_owned(self, destination, data, mode=0o644):
        self.protected(destination, allow_missing=True)
        if destination.exists():
            if self.bounded_file(destination, 262144) != data:
                raise Blocked('An existing repository/key file is not owned by this installer; it was preserved')
            return
        self.protected(destination.parent, directory=True)
        descriptor, temporary = tempfile.mkstemp(prefix='.prthak-', dir=destination.parent)
        try:
            with os.fdopen(descriptor, 'wb') as stream:
                os.fchmod(stream.fileno(), mode)
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            # Hard-link publication refuses a concurrently-created destination.
            try:
                os.link(temporary, destination)
            except FileExistsError:
                raise Blocked('The repository target changed during preparation; existing bytes were preserved') from None
            directory = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            os.unlink(temporary)

    def downloaded_key(self, url):
        if url in self.key_cache:
            return self.key_cache[url]
        with tempfile.TemporaryDirectory(prefix='key-', dir=self.work) as directory:
            home = Path(directory)
            target = home / 'docker.asc'
            self.call([self.tool('curl'), '--fail', '--silent', '--show-error', '--location', '--proto', '=https',
                       '--proto-redir', '=https', '--tlsv1.2', '--max-time', '120', '--max-filesize', '262144',
                       '--output', str(target), url], timeout=150)
            if target.is_symlink() or not target.is_file() or not 1 <= target.stat().st_size <= 262144:
                raise Blocked('The public repository key could not be downloaded safely')
            raw = self.bounded_file(target, 262144)
            if not raw.startswith(b'-----BEGIN PGP PUBLIC KEY BLOCK-----') or b'PRIVATE KEY BLOCK' in raw:
                raise Blocked('The vendor download is not an armored public repository key')
            self.key_cache[url] = raw
            return raw

    def key_bytes(self, url):
        raw = self.downloaded_key(url)
        with tempfile.TemporaryDirectory(prefix='inspect-', dir=self.work) as directory:
            home = Path(directory)
            target = home / 'docker.asc'
            target.write_bytes(raw)
            output, _ = self.call([self.tool('gpg'), '--no-options', '--batch', '--no-autostart', '--homedir', str(home),
                                   '--with-colons', '--show-keys', '--fingerprint', str(target)])
            records = [line.split(':') for line in output.splitlines()]
            if not any(row[0] == 'pub' for row in records) or any(row[0] in ('sec', 'ssb') for row in records):
                raise Blocked('Only a public vendor repository key is accepted')
            primary = []
            awaiting_primary = False
            for row in records:
                if row[0] == 'pub':
                    awaiting_primary = True
                elif row[0] == 'fpr' and awaiting_primary:
                    if len(row) <= 9 or not re.fullmatch('[A-F0-9]{40,64}', row[9]):
                        raise Blocked('The vendor public key has an invalid fingerprint')
                    primary.append(row[9]); awaiting_primary = False
            # Do not accept a valid pinned key bundled with an additional key:
            # rpm --import would otherwise trust both of them.
            if awaiting_primary or len(primary) != 1 or self.family == 'rhel' and primary[0] != RHEL_FINGERPRINT:
                raise Blocked('The vendor repository public-key fingerprint did not verify')
            return raw

    def repository_specification(self):
        if self.family == 'rhel':
            key = self.path('/etc/pki/rpm-gpg/PRTHAK-DOCKER.asc')
            repository = self.path('/etc/yum.repos.d/prthak-docker-ce.repo')
            content = ('[prthak-docker-ce-stable]\nname=Docker CE Stable for Prthak\n'
                       'baseurl=https://download.docker.com/linux/rhel/$releasever/$basearch/stable\n'
                       'enabled=1\ngpgcheck=1\ngpgkey=file:///etc/pki/rpm-gpg/PRTHAK-DOCKER.asc\n').encode()
            # Do not add an overlapping provider beside an existing Docker repo.
            patterns = (self.path('/etc/yum.repos.d'), '*.repo')
            url = RHEL_KEY
        else:
            key = self.path('/etc/apt/keyrings/prthak-docker.asc')
            repository = self.path('/etc/apt/sources.list.d/prthak-docker.sources')
            content = ('Types: deb\nURIs: https://download.docker.com/linux/ubuntu\nSuites: resolute\n'
                       'Components: stable\nArchitectures: '+self.arch+'\nSigned-By: /etc/apt/keyrings/prthak-docker.asc\n').encode()
            patterns = (self.path('/etc/apt/sources.list.d'), '*')
            url = UBUNTU_KEY
        return key, repository, content, patterns, url

    def preflight_repository(self, allow_existing_provider=False):
        key, repository, content, patterns, url = self.repository_specification()
        for parent in (key.parent, repository.parent):
            self.protected(parent, allow_missing=True)
            if parent.exists() and not parent.is_dir():
                raise Blocked('A repository parent is not a protected directory')
        self.protected(key, allow_missing=True)
        self.protected(repository, allow_missing=True)
        if repository.exists() and self.bounded_file(repository, 262144) != content:
            raise Blocked('The installer repository file has foreign contents; it was preserved')
        existing_sources = list(patterns[0].glob(patterns[1]))
        if self.family == 'ubuntu' and self.path('/etc/apt/sources.list').exists():
            existing_sources.append(self.path('/etc/apt/sources.list'))
        for file in existing_sources:
            if file == repository:
                continue
            if b'download.docker.com' in self.bounded_file(file, 1024 * 1024) and not allow_existing_provider:
                raise Blocked('An existing Docker repository was preserved; prepare the runtime through that approved repository')
        if key.exists():
            # Comparing existing bytes to the authenticated official download
            # occurs before installing any missing tool. If curl is absent, an
            # existing unproven key is preserved for explicit review instead.
            current = self.bounded_file(key, 262144)
            if self.tool('curl', optional=True) is None or current != self.downloaded_key(url):
                raise Blocked('An existing repository key is not proven to be the owned vendor key; it was preserved')

    def repository(self):
        self.preflight_repository()
        key, repository, content, patterns, url = self.repository_specification()
        self.protected(key.parent, directory=True)
        self.protected(repository.parent, directory=True)
        raw = self.key_bytes(url)
        self.atomic_owned(key, raw)
        self.atomic_owned(repository, content)
        if self.family == 'rhel':
            self.call([self.tool('rpm'), '--import', str(key)])
        else:
            self.call([self.tool('apt-get'), 'update'], timeout=900)

    def docker_arguments(self, *arguments):
        return [self.tool('docker'), '--config', str(self.cli_config), '--host', SOCKET, *arguments]

    def plugins_safe(self):
        found = False
        for directory in PLUGIN_DIRS:
            path = self.path(directory)
            if path.exists() or path.is_symlink():
                self.protected(path, directory=True)
                candidate = path / 'docker-compose'
                if candidate.exists() or candidate.is_symlink():
                    self.protected(candidate, resolve=True)
                    if not candidate.is_file() or not os.access(candidate, os.X_OK):
                        raise Blocked('The system Compose plugin is not a protected executable')
                    found = True
        return found

    def compose_ready(self):
        if not self.plugins_safe():
            return False
        output, code = self.call(self.docker_arguments('compose', 'version', '--short'), required=False)
        if code or not re.fullmatch(r'v?2\.[0-9]+(?:\.[0-9]+)?(?:[-+][A-Za-z0-9._-]+)?', output):
            raise Blocked('A protected Compose v2 plugin is required; an existing unsupported plugin was preserved')
        return True

    def prepare(self):
        self.validate_host()
        self.mkdir(self.work)
        self.mkdir(self.cli_config)
        config = self.cli_config / 'config.json'
        self.atomic_owned(config, b'{"auths":{}}\n', mode=0o600)
        docker_present = self.tool('docker', optional=True) is not None
        compose_present = self.compose_ready() if docker_present else False
        account_tools = ('useradd', 'groupadd', 'nologin')
        accounts_missing = any(self.tool(tool, optional=True) is None for tool in account_tools)
        if not docker_present or not compose_present or accounts_missing:
            self.preflight_repository(allow_existing_provider=docker_present)
            self.conflicts()
        if accounts_missing:
            self.package(['shadow-utils' if self.family == 'rhel' else 'passwd'])
            if any(self.tool(tool, optional=True) is None for tool in account_tools):
                raise Blocked('The required dedicated-account tools were not installed')
        if docker_present:
            if not compose_present:
                self.package(['docker-compose-plugin'])
        else:
            basic = [('curl', 'curl'), ('tar', 'tar'), ('gpg', 'gnupg2' if self.family == 'rhel' else 'gnupg')]
            missing = [package for tool, package in basic if self.tool(tool, optional=True) is None]
            # CA trust is an OS package and is needed before authenticated curl.
            if not self.path('/etc/ssl/certs/ca-certificates.crt' if self.family == 'ubuntu' else '/etc/pki/tls/certs/ca-bundle.crt').is_file():
                missing.append('ca-certificates')
            if self.family == 'ubuntu':
                self.call([self.tool('apt-get'), 'update'], timeout=900)
                keyrings = self.path('/etc/apt/keyrings')
                self.protected(keyrings, allow_missing=True)
                keyrings.mkdir(mode=0o755, exist_ok=True)
            self.package(missing)
            self.repository()
            self.package(['docker-ce', 'docker-ce-cli', 'containerd.io', 'docker-buildx-plugin', 'docker-compose-plugin'])
        if not self.compose_ready():
            raise Blocked('Dependency installation did not supply Compose v2')
        systemctl = self.tool('systemctl')
        state, _ = self.call([systemctl, 'is-active', 'docker.service'], required=False)
        if state == 'active':
            pass
        elif state in ('inactive', 'failed'):
            arguments = [systemctl, 'start', 'docker.service'] if docker_present else [systemctl, 'enable', '--now', 'docker.service']
            self.call(arguments, timeout=180)
        else:
            raise Blocked('Docker service state is unknown; no service was started')
        state, _ = self.call([systemctl, 'is-active', 'docker.service'], required=False)
        if state != 'active':
            raise Blocked('Docker did not become active')
        output, _ = self.call(self.docker_arguments('info', '--format', '{{json .}}'))
        try:
            info = json.loads(output)
            if info.get('OSType') != 'linux' or not isinstance(info.get('SecurityOptions'), list):
                raise ValueError()
            if any('rootless' in str(value).lower() for value in info['SecurityOptions']):
                raise ValueError()
        except (ValueError, TypeError, AttributeError):
            raise Blocked('A local rootful Linux Docker daemon is required') from None

    def configuration_preflight(self, release, arguments):
        output, _ = self.call([sys.executable, '-I', str(release/'deploy/appliance/node_manager.py'),
                               'install', '--release-root', str(release), *arguments, '--validate-only'])
        try:
            if json.loads(output).get('status') != 'validated':
                raise ValueError()
        except (ValueError, AttributeError, TypeError):
            raise Blocked('Controller configuration preflight did not validate; no dependencies were changed') from None

    def docker_home_safe(self, home):
        home = Path(home)
        self.protected(home, directory=True)
        configuration = home/'.docker'
        self.protected(configuration, allow_missing=True)
        if not configuration.exists():
            return
        self.protected(configuration, directory=True)
        settings = configuration/'config.json'
        if settings.exists() or settings.is_symlink():
            try:
                values = json.loads(self.bounded_file(settings, 1024 * 1024))
                if not isinstance(values, dict) or values.get('cliPluginsExtraDirs'):
                    raise ValueError()
            except (ValueError, UnicodeError, TypeError):
                raise Blocked('Root Docker CLI configuration has unsupported plugin overrides') from None
        plugins = configuration/'cli-plugins'
        self.protected(plugins, allow_missing=True)
        if plugins.exists():
            self.protected(plugins, directory=True)
            for name in ('docker-compose', 'docker-buildx'):
                candidate = plugins/name
                if candidate.exists() or candidate.is_symlink():
                    raise Blocked('Privileged controller setup requires system Docker plugins; root-home overrides were preserved')


def delegate(release_root, arguments, execute=None):
    manager = release_root / 'deploy/appliance/node_manager.py'
    if os.geteuid() == 0 and platform.system() == 'Linux':
        protector = Installer()
        protector.protected(release_root, directory=True)
        protector.protected(manager)
        protector.protected(Path(sys.executable).resolve(), resolve=True)
        protector.docker_home_safe(Path(pwd.getpwuid(0).pw_dir))
    (execute or os.execve)(sys.executable, [sys.executable, '-I', str(manager), 'install', '--release-root', str(release_root), *arguments], environment())


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--release-root', type=Path, required=True)
    parser.add_argument('manager_args', nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    original = args.manager_args[1:] if args.manager_args[:1] == ['--'] else args.manager_args
    try:
        arguments, automatic = manager_arguments(original)
        release = args.release_root.absolute()
        if automatic:
            protector = Installer()
            protector.protected(release, directory=True)
            protector.protected(release / 'deploy/appliance/install_prerequisites.py')
            protector.protected(release / 'deploy/appliance/node_manager.py')
            protector.protected(Path(sys.executable).resolve(), resolve=True)
            if sys.version_info < (3, 9):
                raise Blocked('Python 3.9 or newer is required')
            protector.validate_host()
            protector.docker_home_safe(Path(pwd.getpwuid(0).pw_dir))
            protector.configuration_preflight(release, arguments)
            protector.prepare()
        delegate(release, arguments)
    except (Blocked, OSError, UnicodeError):
        print('Controller prerequisites blocked: '+str(sys.exc_info()[1]), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

