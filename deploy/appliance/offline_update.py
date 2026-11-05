"""Fixed local transaction for a signed standalone offline appliance update."""
from __future__ import annotations

import copy
from datetime import datetime, timezone
import hashlib
import hmac
import http.client
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import secrets
import shutil
import socket
import stat
import subprocess
import tarfile
import time

MAX_ARCHIVE = 2 * 1024**3 - 1
MAX_EXTRACTED = 4 * 1024**3
MAX_FILES = 4096
VERSION = r'[0-9]{1,6}\.[0-9]{1,6}\.[0-9]{1,6}'
RELEASE = re.compile(rf'prthak-controller-({VERSION})-offline-rhel(9|10)-x86_64\.tar\.gz\Z')
IMAGE = re.compile(r'sha256:[0-9a-f]{64}\Z')
SYSTEMCTL = '/usr/bin/systemctl'
MANAGER_UNIT = 'prthak-appliance-manager.service'
UPDATE_UNIT = 'prthak-appliance-update.service'
HOST_CODE = Path('/opt/prthak-appliance')
UNITS = Path('/etc/systemd/system')
ACTIONS = ('controller-update-review', 'controller-update-apply')
SERVICES = ('controller', 'router')
TERMINAL = ('committed', 'rolled_back', 'blocked')
REVIEW_SECONDS = 1800

# Run inside the current immutable controller image with no network or mounts.
# The uploaded signature never chooses its own trust key or executable.
VERIFY_SIGNATURE = """
import base64, hashlib, json, pathlib, sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
envelope = json.load(sys.stdin)
trust = json.loads(pathlib.Path('/opt/prthak-integrity/public-trust.json').read_text())
key = base64.b64decode(trust['keys'][envelope['key_id']], validate=True)
if envelope['algorithm'] != 'Ed25519' or hashlib.sha256(key).hexdigest()[:32] != envelope['key_id']:
    raise SystemExit(1)
payload = base64.b64decode(envelope['payload'], validate=True)
Ed25519PublicKey.from_public_bytes(key).verify(base64.b64decode(envelope['signature'], validate=True), payload)
document = json.loads(payload)
if document['domain'] != 'prthak-package-manifest-v1':
    raise SystemExit(1)
print(json.dumps(document['manifest']))
"""


def host_rhel_major():
    fields = {}
    try:
        raw = Path('/etc/os-release').read_text()
    except OSError:
        return None
    if len(raw) > 16384:
        return None
    for line in raw.splitlines():
        match = re.fullmatch(r'(ID|VERSION_ID)=(?:"([^"\n]*)"|\x27([^\x27\n]*)\x27|([^\s\n]+))', line)
        if not match:
            continue
        key, *values = match.groups()
        if key in fields:
            return None
        fields[key] = next(value for value in values if value is not None)
    version = fields.get('VERSION_ID', '')
    if fields.get('ID') != 'rhel' or not re.fullmatch(r'(?:9|10)(?:\.[0-9]+)*', version):
        return None
    return version.split('.')[0]


def supported(manager):
    try:
        return (
            platform.system() == 'Linux' and platform.machine() == 'x86_64'
            and host_rhel_major() in ('9', '10')
            and not manager.manifest() and not manager.desired()
            and IMAGE.fullmatch(manager.installed.get('images', {}).get('controller', '')) is not None
            and (UNITS / UPDATE_UNIT).is_file()
        )
    except (OSError, ValueError, AttributeError):
        return False


def directory(root):
    return root / 'manager/controller-update'


def active(root, host):
    record = host.load(directory(root) / 'active.json', {})
    return record if record and record.get('phase') not in TERMINAL else None


def _fixed_run(arguments):
    return subprocess.run(
        [SYSTEMCTL, *arguments], cwd='/', check=True, timeout=180,
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C', 'LC_ALL': 'C'},
    )


def _image_python(engine, image, arguments, *, inputs=None):
    command = [
        'run', '--pull=never', '--rm', '--network', 'none', '--read-only',
        '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true',
        '--user', '10001:10001', '--entrypoint', 'python3',
    ]
    if inputs is not None:
        command += ['-i']
    return engine.run([*command, image, *arguments], timeout=120, private_input=inputs)


def _signature(manager, filename, size, envelope, host):
    if not isinstance(envelope, dict):
        raise host.Blocked('Upload the detached JSON signature for this release')
    encoded = json.dumps(envelope, separators=(',', ':')).encode()
    if len(encoded) > 16384:
        raise host.Blocked('Detached signature exceeds its size limit')
    try:
        raw = _image_python(manager.engine, manager.installed['images']['controller'],
                            ['-c', VERIFY_SIGNATURE], inputs=encoded)
        data = json.loads(raw)
        if (data.get('filename') != filename or type(data.get('bytes')) is not int
                or data['bytes'] != size or not re.fullmatch(r'[0-9a-f]{64}', data.get('sha256', ''))):
            raise ValueError()
        return data['sha256']
    except (host.Blocked, ValueError, TypeError, AttributeError):
        raise host.Blocked('The detached signature did not verify against the installed release trust') from None


def _copy_upload(root, upload_id, size, expected, output, host):
    # Controller-writable directories cannot redirect the root reader through a
    # symlink. Hash the copied bytes, even if the upload changes during reading.
    if shutil.disk_usage(output.parent).free < 2 * size:
        raise host.Blocked('The appliance data root has insufficient space to stage this release')
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    fd = os.open(root, flags)
    try:
        for part in ('controller', 'platform', 'controller-updates'):
            next_fd = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        source_fd = os.open(upload_id + '.tar.gz',
                            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        with os.fdopen(source_fd, 'rb') as source:
            info = os.fstat(source.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != host.CONTROLLER_UID
                    or info.st_nlink != 1 or info.st_size != size or info.st_mode & 0o077):
                raise host.Blocked('Upload is unavailable or is not a private complete archive')
            digest = hashlib.sha256()
            with output.open('xb') as target:
                remaining = size
                while remaining:
                    data = source.read(min(remaining, 1024**2))
                    if not data:
                        raise host.Blocked('The uploaded archive changed during verification')
                    target.write(data)
                    digest.update(data)
                    remaining -= len(data)
                if source.read(1) or not hmac.compare_digest(digest.hexdigest(), expected):
                    raise host.Blocked('The uploaded archive does not match its signed digest')
                target.flush()
                os.fsync(target.fileno())
    finally:
        os.close(fd)


def _extract(archive, staging, stem, host, *, rhel_major="9"):
    total, seen = 0, set()
    try:
        with tarfile.open(archive, 'r|gz') as source:
            for entry in source:
                path = PurePosixPath(entry.name)
                component = r'[A-Za-z0-9_.+~:-]{1,180}' if path.parts[1:3] == ('offline', 'rpms') else r'[A-Za-z0-9_.-]{1,180}'
                if (not entry.isfile() or entry.issparse() or path.is_absolute() or len(path.parts) < 2
                        or path.parts[0] != stem or '..' in path.parts
                        or any(not re.fullmatch(component, part) for part in path.parts)
                        or path in seen or entry.mode & 0o7022 or not 0 <= entry.size <= MAX_ARCHIVE):
                    raise host.Blocked('Signed archive has an unsupported file path or type')
                seen.add(path)
                total += entry.size
                if len(seen) > MAX_FILES or total > MAX_EXTRACTED or shutil.disk_usage(staging).free < entry.size:
                    raise host.Blocked('Signed archive exceeds the extraction or disk limits')
                target = staging.joinpath(*path.parts)
                target.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
                with target.open('xb') as destination, source.extractfile(entry) as stream:
                    shutil.copyfileobj(stream, destination, 1024**2)
                    os.fchmod(destination.fileno(), 0o600 if entry.mode & 0o077 == 0 else 0o644)
                    destination.flush()
                    os.fsync(destination.fileno())
    except (tarfile.TarError, EOFError, OSError):
        raise host.Blocked('Signed archive is damaged or could not be staged') from None
    release = staging / stem
    version = stem.removeprefix('prthak-controller-')
    required_agents = [f'prthak-agent-{version}-linux-{architecture}.tar.gz{extension}'
                       for architecture in ('amd64', 'arm64') for extension in ('', '.signature.json')]
    if (not (release / 'OFFLINE-CONTROLLER').is_file()
            or not (release / 'offline/rpms/repodata/repomd.xml').is_file()
            or not any((release / 'offline/rpms').glob('*.rpm'))
            or not (release / 'offline/keys').is_dir()
            or not all((release / 'agent-releases' / name).is_file() for name in required_agents)
            or not all((release / 'deploy/appliance' / name).is_file()
                       for name in ('node_manager.py', 'offline_update.py'))):
        raise host.Blocked('Use a complete signed offline update release with GUI update support')
    target_path = release / 'offline/target.json'
    if target_path.exists():
        try:
            if target_path.stat().st_size > 1024:
                raise ValueError()
            target = json.loads(target_path.read_text())
        except (ValueError, UnicodeError, OSError):
            raise host.Blocked('The offline dependency target is invalid') from None
        if target != {'id': 'rhel', 'version_id': rhel_major, 'architecture': 'x86_64'}:
            raise host.Blocked('The offline dependency target differs from this RHEL major version')
    elif rhel_major != '9':
        raise host.Blocked('RHEL 10 updates require an explicit matching offline dependency target')
    return release


def _idle(manager, host):
    if not supported(manager):
        raise host.Blocked('Offline GUI updates require a standalone RHEL 9/10 x86_64 appliance')
    manager._assert_controller_configuration_idle()
    manager._assert_public_port_idle()
    manager._assert_restoration_idle()
    manager._assert_internal_idle()
    if manager.state().get('configuration_pending') or manager.engine.foreign_bindings(manager.root):
        raise host.Blocked('Resolve pending configuration or foreign data mounts before updating')
    rotation = host.load(manager.root / 'manager/rotation.json')
    if rotation and rotation.get('phase') not in ('finalized', 'aborted'):
        raise host.Blocked('Resolve the active rotation before updating')
    states = manager.engine.states()
    if {name for name, state in states.items() if state == 'running'} != set(SERVICES):
        raise host.Blocked('Start the healthy standalone controller and router before updating')
    info = json.loads(manager.engine.run(['info', '--format', '{{json .}}']))
    security = info.get('SecurityOptions')
    if (info.get('OSType') != 'linux' or not isinstance(security, list)
            or any('rootless' in str(option).lower() for option in security)):
        raise host.Blocked('A local rootful Linux Docker daemon is required')
    compose = manager.engine.run(['compose', 'version', '--short']).strip()
    if not re.fullmatch(r'v?(?:2|5)\.[0-9]+(?:\.[0-9]+)?(?:[-+][A-Za-z0-9._-]+)?', compose):
        raise host.Blocked('Compose v2 or v5 is required')


def _version(engine, image):
    return _image_python(engine, image, ['-c', 'from controller import __version__;print(__version__)']).strip()


def _verify_candidate(manager, release, version, host):
    images = host.offline_appliance_images(manager.engine, release / 'offline')
    candidate = images['controller']
    # Check both root executables against the verified image runtime manifest.
    for filename, flag in (('node_manager.py', '--check-host'), ('offline_update.py', '--check-host-update')):
        manager.engine.run([
            'run', '--pull=never', '--rm', '-i', '--network', 'none', '--read-only', '--user', '0',
            '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true', '--tmpfs', '/prthak-host:mode=0755',
            '--entrypoint', 'sh', candidate, '-ec',
            'umask 022; cat > "$2"; exec python3 /opt/prthak-integrity/launch.py "$1" "$2"',
            'verify-host', flag, '/prthak-host/' + filename,
        ], timeout=120, private_input=(release / 'deploy/appliance' / filename).read_bytes())
    _image_python(manager.engine, candidate, ['/opt/prthak/controller_entrypoint.py', '--validate-initial-env'], inputs=b'{}\n')
    installed = _version(manager.engine, manager.installed['images']['controller'])
    if not re.fullmatch(VERSION, installed) or _version(manager.engine, candidate) != version:
        raise host.Blocked('The signed archive and installed controller versions could not be verified')
    if tuple(map(int, version.split('.'))) <= tuple(map(int, installed.split('.'))):
        raise host.Blocked('Choose a controller release newer than the installed version')
    return images, installed


def review(manager, body, host):
    if set(body) != {'action', 'request_id', 'upload_id', 'name', 'size', 'signature'}:
        raise host.Blocked('Provide the exact offline upload and detached signature')
    filename, size, upload_id = body['name'], body['size'], body['upload_id']
    match = RELEASE.fullmatch(filename) if isinstance(filename, str) else None
    if (not match or type(size) is not int or not 0 < size <= MAX_ARCHIVE
            or not isinstance(upload_id, str) or not host.JOB.fullmatch(upload_id)):
        raise host.Blocked('Choose a supported offline RHEL 9/10 x86_64 controller archive')
    _idle(manager, host)
    if match[2] != host_rhel_major():
        raise host.Blocked('Choose the update archive for this controller’s RHEL major version')
    base = directory(manager.root)
    host.private_dir(base)
    # Keep at most one pending review. Active transaction state is separate.
    for item in base.glob('review-*'):
        if item.is_dir() and not item.is_symlink():
            shutil.rmtree(item)
    expected = _signature(manager, filename, size, body['signature'], host)
    identifier = secrets.token_hex(16)
    staging = base / ('review-' + identifier)
    host.private_dir(staging)
    archive = staging / 'upload.tar.gz'
    version = match[1]
    try:
        _copy_upload(manager.root, upload_id, size, expected, archive, host)
        release = _extract(archive, staging, 'prthak-controller-' + version, host, rhel_major=match[2])
        archive.unlink()
        # Loading signed images is additive. No installed Compose image changes here.
        images, installed = _verify_candidate(manager, release, version, host)
        record = {
            'review_id': identifier, 'version': version, 'current_version': installed,
            'sha256': expected, 'images': images, 'base': host.digest(manager.installed),
            'revision': manager.state()['revision'], 'expires_at': time.time() + REVIEW_SECONDS,
            'confirmation_nonce': secrets.token_urlsafe(24),
        }
        host.atomic(staging / 'review.json', record)
    except Exception:
        shutil.rmtree(staging)
        raise
    return {**{key: record[key] for key in ('review_id', 'version', 'current_version', 'sha256', 'confirmation_nonce')},
            'expires_at': datetime.fromtimestamp(record['expires_at'], timezone.utc).isoformat(),
            'phase': 'reviewed', 'host_rpms': 'validated_only'}


def queue(manager, body, host):
    identifier, nonce = body.get('review_id'), body.get('confirmation_nonce')
    if (set(body) != {'action', 'request_id', 'review_id', 'confirmation_nonce'}
            or not isinstance(identifier, str) or not host.JOB.fullmatch(identifier)
            or not isinstance(nonce, str)):
        raise host.Blocked('Confirm the exact offline update review')
    _idle(manager, host)
    base = directory(manager.root)
    staged = base / ('review-' + identifier)
    record = host.load(staged / 'review.json')
    if (not record or record['expires_at'] <= time.time() or record['base'] != host.digest(manager.installed)
            or record['revision'] != manager.state()['revision']
            or not hmac.compare_digest(nonce, record['confirmation_nonce'])):
        raise host.Blocked('The offline update review expired or the appliance changed')
    active_file = base / 'active.json'
    if active(manager.root, host):
        raise host.Blocked('An offline update is already in progress')
    transaction = {**record, 'phase': 'queued', 'job_id': body['request_id']}
    host.atomic(active_file, transaction)
    try:
        _fixed_run(['start', '--no-block', UPDATE_UNIT])
    except (OSError, subprocess.SubprocessError):
        transaction['phase'] = 'blocked'
        host.atomic(active_file, transaction)
        raise host.Blocked('The installed offline update service could not be started') from None


def _system_snapshot(manager, backup, host):
    host.private_dir(backup)
    files = {
        'node_manager.py': HOST_CODE / 'node_manager.py',
        'offline_update.py': HOST_CODE / 'offline_update.py',
        'manager.service': UNITS / MANAGER_UNIT,
        'installed.json': manager.root / 'config/installed.json',
        'compose.json': manager.root / 'runtime/compose.json',
    }
    for name, path in files.items():
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or info.st_size > 4 * 1024**2:
            raise host.Blocked('Existing host runtime files are not protected')
        host.atomic(backup / name, path.read_bytes())
    return files


def _stop_services(manager, host):
    manager.engine.compose(['stop', '--timeout', '60', *SERVICES], timeout=150)
    if any(state == 'running' for state in manager.engine.states().values()):
        raise host.Blocked('Controller services could not be stopped and fenced')


def _durable_move(source, target):
    os.replace(source, target)
    for parent in {source.parent, target.parent}:
        fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def _copy_data(manager, backup, host):
    original = manager.root / 'controller'
    proof = manager._tree(original)
    if shutil.disk_usage(original.parent).free < sum(info[0] for info in proof.values()):
        raise host.Blocked('Insufficient free space for a recoverable controller data copy')
    snapshot = backup / 'controller'
    _durable_move(original, snapshot)
    shutil.copytree(snapshot, original, copy_function=shutil.copy2)
    for path in [original, *original.rglob('*')]:
        info = (snapshot / path.relative_to(original)).stat()
        os.chown(path, info.st_uid, info.st_gid)
        fd = os.open(path, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    if manager._tree(original) != proof:
        raise host.Blocked('Stopped controller data copy could not be verified')


def _compose(backup, images, root, host):
    compose = host.load(backup / 'compose.json')
    if set(compose.get('services', {})) != set(host.SERVICES):
        raise host.Blocked('Installed Compose services differ from the supported appliance layout')
    for name, image in images.items():
        compose['services'][name].update(image=image, pull_policy='never')
    volumes = compose['services']['controller']['volumes']
    for mount, directory_name in (('/run/prthak-agent-releases', 'agent-releases'),
                                  ('/run/prthak-controller-update', 'controller-update-fence')):
        if not any(value.get('target') == mount for value in volumes):
            volumes.append({'type': 'bind', 'source': str(root / 'runtime' / directory_name), 'target': mount,
                            'read_only': True, 'bind': {'create_host_path': False, 'selinux': 'z'}})
    return compose


def _fenced(compose, *, loopback=True):
    result = copy.deepcopy(compose)
    for name in SERVICES:
        service = result['services'][name]
        if loopback:
            service['ports'] = ['127.0.0.1:' + ':'.join(port.split(':')[-2:]) for port in service['ports']]
        service['restart'] = 'no'
    return result


def _restart(manager):
    manager.engine.compose(['up', '-d', '--no-deps', '--force-recreate', *SERVICES], timeout=180)


def _wait_health(manager, material, host, *, fenced=False):
    deadline = time.monotonic() + 100
    while True:
        try:
            for key in ('controller_backend_port', 'controller_port'):
                manager._web_probe(material['chain'], material['name'], manager.installed[key], material['fingerprint'])
                if fenced:
                    manager._web_probe(material['chain'], material['name'], manager.installed[key], material['fingerprint'],
                                       path='/api/v1/auth/config', expected=503)
            if all(manager.engine.states().get(name) == 'running' for name in SERVICES):
                return
        except (OSError, ValueError, http.client.HTTPException, host.Blocked):
            pass
        if time.monotonic() >= deadline:
            raise host.Blocked('Controller and router HTTPS readiness could not be verified')
        time.sleep(1)


def _terminal(root, record, phase, host, error=''):
    record['phase'] = phase
    record['error'] = error
    host.atomic(directory(root) / 'active.json', record)
    _receipt(root, record, host)
    _release_fence(root, record, host)


def _receipt(root, record, host):
    phase, error = record['phase'], record.get('error', '')
    job_path = root / 'manager/jobs' / record['job_id']
    job = host.load(job_path, {'id': record['job_id']})
    result = {'phase': phase, 'verified': phase == 'committed', 'rolled_back': phase == 'rolled_back',
              'version': record['version']}
    if phase != 'committed' and 'failure_stage' in record:
        result['failure_stage'] = record['failure_stage']
    if phase == 'rollback_failed' and 'recovery_stage' in record:
        result['recovery_stage'] = record['recovery_stage']
    job.update(status='completed' if phase == 'committed' else 'error', phase=phase, result=result, updated_at=time.time())
    if error:
        job['error'] = error
    host.atomic(job_path, job)


def _install_fence(root, record, host):
    fence = root / 'runtime/controller-update-fence'
    fence.mkdir(mode=0o755, exist_ok=True)
    host.protected_release_directory(fence)
    host.atomic(fence / 'pending', record['job_id'], 0o644)
    descriptor = os.open(fence, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        # The root systemd worker uses UMask=0077. The controller runs as 10001.
        os.fchmod(descriptor, 0o755)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def repair_fence(root, record, host):
    """Make the exact active fence visible after an older worker creates it mode 0700."""
    if record.get('phase') not in ('applying', 'publishing', 'verified', 'rollback_failed'):
        return
    root = host.safe_path(str(root))
    journal = directory(root) / 'active.json'
    fence = root / 'runtime/controller-update-fence'
    for path in (journal.parent.parent, journal.parent, fence.parent, fence):
        host.protected_release_directory(path)
    info = journal.lstat()
    job = record.get('job_id', '')
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077 or info.st_nlink != 1
            or not isinstance(job, str) or not host.JOB.fullmatch(job) or host.load(journal) != record):
        raise host.Blocked('The active offline update journal is unsafe')
    descriptor = os.open(fence, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        marker = os.open('pending', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=descriptor)
        with os.fdopen(marker, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or info.st_nlink != 1
                    or info.st_size != 32 or stream.read(33) != job.encode('ascii')):
                raise host.Blocked('The offline update writer fence does not match the active journal')
            if stat.S_IMODE(info.st_mode) != 0o644:
                os.fchmod(stream.fileno(), 0o644)
                os.fsync(stream.fileno())
        if stat.S_IMODE(os.fstat(descriptor).st_mode) != 0o755:
            os.fchmod(descriptor, 0o755)
            os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _release_fence(root, record, host):
    marker = root / 'runtime/controller-update-fence/pending'
    if not marker.exists():
        return
    host.protected_release_directory(marker.parent)
    info = marker.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or info.st_size != 32:
        raise host.Blocked('The offline update writer fence is unsafe')
    if marker.read_text() != record['job_id']:
        raise host.Blocked('An unrelated offline update writer fence is active')
    marker.unlink()
    fd = os.open(marker.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _start_manager(record, host):
    host.atomic('/run/prthak-appliance/controller-update-start.json', {'job_id': record['job_id']})
    _fixed_run(['start', MANAGER_UNIT])


def _wait_manager(manager, host):
    deadline = time.monotonic() + 30
    token = (manager.root / 'config/manager-token').read_text().strip()
    if not re.fullmatch(r'[A-Za-z0-9_-]{32,256}', token):
        raise host.Blocked('The private manager health credential is invalid')
    while time.monotonic() < deadline:
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(3)
                connection.connect('/run/prthak-appliance/manager.sock')
                if host.peer_uid(connection) != 0:
                    raise host.Blocked('The manager health socket peer is not root')
                connection.sendall(('GET /v1/status HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer ' + token
                                    + '\r\nConnection: close\r\n\r\n').encode())
                response = http.client.HTTPResponse(connection)
                response.begin()
                result = json.loads(response.read(65537))
                if (response.status == 200 and result.get('appliance_id') == manager.installed['appliance_id']
                        and 'offline_update_v1' in result.get('capabilities', [])):
                    return
        except (OSError, ValueError, http.client.HTTPException, AttributeError):
            pass
        time.sleep(1)
    raise host.Blocked('The signed host manager did not confirm readiness')


def _rollback(manager, record, backup, host):
    # Repeating compensation after a process/host crash is safe because each
    # directory rename is atomic and the original is moved back only once.
    record['recovery_stage'] = 'restore_files'
    _fixed_run(['stop', MANAGER_UNIT])
    lease = host.acquire_lease()
    try:
        if record['phase'] in ('applying', 'publishing', 'verified', 'rollback_failed'):
            _stop_services(manager, host)
            for name, destination, mode in (
                ('node_manager.py', HOST_CODE / 'node_manager.py', 0o755),
                ('offline_update.py', HOST_CODE / 'offline_update.py', 0o755),
                ('manager.service', UNITS / MANAGER_UNIT, 0o644),
                ('installed.json', manager.root / 'config/installed.json', 0o600),
                ('compose.json', manager.root / 'runtime/compose.json', 0o600),
            ):
                host.atomic(destination, (backup / name).read_bytes(), mode)
            controller = manager.root / 'controller'
            if (backup / 'controller').exists():
                if controller.exists():
                    _durable_move(controller, backup / 'failed-controller')
                _durable_move(backup / 'controller', controller)
            agents = manager.root / 'runtime/agent-releases'
            if (backup / 'agent-releases').exists():
                if agents.exists():
                    _durable_move(agents, backup / 'failed-agent-releases')
                _durable_move(backup / 'agent-releases', agents)
            elif (backup / 'agents-absent').exists() and agents.exists():
                _durable_move(agents, backup / 'failed-agent-releases')
            manager.installed = host.load(manager.root / 'config/installed.json')
        record['recovery_stage'] = 'start_previous'
        _fixed_run(['daemon-reload'])
        _restart(manager)
    finally:
        os.close(lease)
    _start_manager(record, host)
    record['recovery_stage'] = 'verify_previous'
    _wait_manager(manager, host)
    _wait_health(manager, manager._controller_configuration_material(), host)
    _terminal(manager.root, record, 'rolled_back', host, 'The update failed and the previous appliance was restored')


def run(root, host):
    """Run in the separately supervised root unit. Resume by rolling back."""
    root = host.safe_path(str(root))
    record = host.load(directory(root) / 'active.json', {})
    if not record:
        return
    if record.get('phase') in TERMINAL:
        _receipt(root, record, host)
        _release_fence(root, record, host)
        return
    manager = host.Manager(root, recover=False)
    base = directory(root)
    staged = base / ('review-' + record['review_id'])
    release = staged / ('prthak-controller-' + record['version'])
    backup = base / ('backup-' + record['review_id'])
    journal = base / 'active.json'
    stage = 'preflight'
    try:
        if record['phase'] == 'verified':
            stage = 'final_verification'
            _publish_verified(manager, record, backup, staged, host)
            return
        if record['phase'] != 'queued':
            record.setdefault('failure_stage', 'interrupted')
            _rollback(manager, record, backup, host)
            return
        _idle(manager, host)
        if (record['expires_at'] <= time.time() or record['base'] != host.digest(manager.installed)
                or record['revision'] != manager.state()['revision']):
            raise host.Blocked('The installed appliance changed after update review')
        stage = 'previous_health'
        _wait_health(manager, manager._controller_configuration_material(), host)
        stage = 'backup_runtime'
        _system_snapshot(manager, backup, host)
        record['phase'] = 'stopping'
        host.atomic(journal, record)
        stage = 'stop_previous'
        _fixed_run(['stop', MANAGER_UNIT])
        lease = host.acquire_lease()
        try:
            _stop_services(manager, host)
            record['phase'] = 'applying'
            host.atomic(journal, record)
            stage = 'copy_data'
            _copy_data(manager, backup, host)
            stage = 'stage_candidate'
            agents = root / 'runtime/agent-releases'
            if agents.exists():
                _durable_move(agents, backup / 'agent-releases')
            else:
                host.atomic(backup / 'agents-absent', '')
            host.stage_agent_releases(release, root)
            _install_fence(root, record, host)
            for name in ('node_manager.py', 'offline_update.py'):
                host.atomic(HOST_CODE / name, (release / 'deploy/appliance' / name).read_bytes(), 0o755)
            host.write_manager_unit(manager.engine, record['images']['controller'])
            candidate = {**manager.installed, 'images': record['images']}
            host.atomic(root / 'config/installed.json', candidate)
            compose = _compose(backup, record['images'], root, host)
            host.atomic(root / 'runtime/compose.json', _fenced(compose))
            _fixed_run(['daemon-reload'])
            stage = 'start_candidate'
            _restart(manager)
        finally:
            os.close(lease)
        stage = 'candidate_manager'
        _start_manager(record, host)
        manager.installed = {**candidate, 'bind_ip': '127.0.0.1'}
        material = manager._controller_configuration_material()
        _wait_manager(manager, host)
        stage = 'candidate_health'
        _wait_health(manager, material, host, fenced=True)
        stage = 'publish_listener'
        record['phase'] = 'publishing'
        host.atomic(journal, record)
        host.atomic(root / 'runtime/compose.json', _fenced(compose, loopback=False))
        manager.installed = candidate
        _restart(manager)
        stage = 'public_health'
        _wait_health(manager, material, host, fenced=True)
        record['phase'] = 'verified'
        host.atomic(journal, record)
        stage = 'final_verification'
        _publish_verified(manager, record, backup, staged, host)
    except Exception:
        if record['phase'] in TERMINAL:
            raise  # The systemd retry reconciles a terminal journal and writer fence.
        # Publish only fixed stage codes. Exception messages can include private
        # filesystem paths or command data and are not update diagnostics.
        record.setdefault('failure_stage', stage)
        if record['phase'] == 'queued':
            _terminal(root, record, 'blocked', host, 'The reviewed offline update could not be safely started')
        else:
            try:
                _rollback(manager, record, backup, host)
            except Exception:
                if record['phase'] in TERMINAL:
                    raise
                record['phase'] = 'rollback_failed'
                record['error'] = 'Automatic recovery could not be verified; the protected backup was retained'
                host.atomic(journal, record)
                _receipt(root, record, host)
                raise


def _publish_verified(manager, record, backup, staged, host):
    """Only a durably verified release can acquire automatic restart at boot."""
    root = manager.root
    compose = _compose(backup, record['images'], root, host)
    host.atomic(root / 'runtime/compose.json', compose)
    _start_manager(record, host)
    _wait_manager(manager, host)
    _restart(manager)
    _wait_health(manager, manager._controller_configuration_material(), host, fenced=True)
    _terminal(root, record, 'committed', host)
    shutil.rmtree(staged, ignore_errors=True)
    host.atomic(backup / 'committed.json', {'review_id': record['review_id']})
    for previous in directory(root).glob('backup-*'):
        if previous != backup and (previous / 'committed.json').is_file():
            shutil.rmtree(previous, ignore_errors=True)
