#!/usr/bin/env python3
"""Build a public, allowlisted controller installer archive; never copy runtime state."""
from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import tarfile
import tempfile

PROJECT = Path(__file__).resolve().parents[1]
MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_PAYLOAD_BYTES = 64 * 1024 * 1024
FIXED_FILES = (
    'controller/requirements.txt',
    'dashboard/index.html',
    'deploy/Dockerfile.controller',
    'deploy/verify_runtime_entrypoint.py',
    'deploy/appliance/Dockerfile.controller',
    'deploy/appliance/Dockerfile.database',
    'deploy/appliance/node_manager.py',
    'deploy/appliance/controller_entrypoint.py',
    'deploy/appliance/bootstrap_roles.py',
    'deploy/appliance/rotation_helper.py',
    'deploy/appliance/restore_helper.py',
    'deploy/cluster/node_helper.py',
    'deploy/release-public-trust.json',
    'scripts/install-controller.sh',
    'scripts/verify-release.py',
    '.env.example',
    'docs/controller-installation.md',
    'docs/controller-vm-requirements.md',
    'agent/README.md',
)
ASSET_SUFFIXES = frozenset(('.svg', '.png', '.jpg', '.jpeg', '.webp', '.gif', '.ico', '.woff', '.woff2', '.ttf', '.otf'))
EXECUTABLES = frozenset(('scripts/install-controller.sh', 'scripts/verify-release.py', 'deploy/appliance/node_manager.py'))


class PackageError(ValueError):
    pass


def _regular_bytes(root: Path, name: str) -> bytes:
    """Walk inside an opened root; no selected path component may be a symlink."""
    relative = PurePosixPath(name)
    if relative.is_absolute() or any(part in ('', '.', '..') for part in relative.parts):
        raise PackageError('Unsafe package source path')
    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in relative.parts[:-1]:
            following = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = following
        descriptor = os.open(relative.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        with os.fdopen(descriptor, 'rb') as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > MAX_FILE_BYTES:
                raise PackageError('Selected source must be a single regular bounded file: ' + name)
            data = handle.read(MAX_FILE_BYTES + 1)
            if len(data) > MAX_FILE_BYTES:
                raise PackageError('Selected source grew beyond the byte limit: ' + name)
            return data
    finally:
        os.close(directory)


def selected_paths(root: Path) -> list[str]:
    names = set(FIXED_FILES)
    if (root / 'deploy/runtime-integrity.json').exists():
        names.add('deploy/runtime-integrity.json')
    for directory, suffixes in [('controller', {'.py'}), ('dashboard', {'.js', '.css', '.html'})]:
        source = root / directory
        if source.is_symlink() or not source.is_dir():
            raise PackageError('Expected a real source directory: ' + directory)
        for path in source.iterdir():
            is_test = (path.name.startswith('test_') or path.name.endswith('_test.py') or
                       '.test.' in path.name or path.name in ('tests.py', 'conftest.py'))
            if path.suffix in suffixes and not is_test:
                names.add(path.relative_to(root).as_posix())
    for required in ('controller/__init__.py', 'controller/__main__.py', 'controller/app.py', 'dashboard/app.js', 'dashboard/styles.css'):
        if required not in names:
            raise PackageError('Required runtime source is missing: ' + required)
    documentation = root / 'docs'
    if documentation.is_symlink() or not documentation.is_dir():
        raise PackageError('Expected a real public documentation directory')
    for path in documentation.iterdir():
        if path.suffix == '.md':
            names.add(path.relative_to(root).as_posix())
    guides = documentation / 'guide'
    if guides.is_symlink():
        raise PackageError('Illustrated guide directory must not be a symlink')
    for path in guides.glob('prthak-pilot-*'):
        if re.fullmatch(r'prthak-pilot-[0-9]+\.[0-9]+\.[0-9]+\.(pdf|html)', path.name):
            names.add(path.relative_to(root).as_posix())
    assets = root / 'dashboard/assets'
    if assets.is_symlink() or not assets.is_dir():
        raise PackageError('Expected a real dashboard assets directory')
    for directory, subdirectories, files in os.walk(assets, followlinks=False):
        for value in subdirectories:
            if (Path(directory) / value).is_symlink():
                raise PackageError('Dashboard asset directories must not be symlinks')
        for value in files:
            path = Path(directory) / value
            if value == 'README.md':
                if path.is_symlink() or not path.is_file():
                    raise PackageError('Dashboard asset documentation must not be a symlink')
                continue
            if path.suffix.lower() not in ASSET_SUFFIXES:
                raise PackageError('Unexpected nonpublic dashboard asset: ' + path.relative_to(root).as_posix())
            names.add(path.relative_to(root).as_posix())
    return sorted(names)


def _validate_public_templates(payload: dict[str, bytes]) -> None:
    seen = set()
    for line in payload['.env.example'].decode('utf-8').splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        if not re.fullmatch(r'[A-Z][A-Z0-9_]*=.*', line):
            raise PackageError('The .env.example template contains an unexpected statement')
        key, value = line.split('=', 1)
        if key in seen:
            raise PackageError('The .env.example template contains a duplicate field: ' + key)
        seen.add(key)
        if any(word in key for word in ('PASSWORD', 'TOKEN', 'SECRET', 'PRIVATE_KEY')) and value.strip() not in ('', '""', "''"):
            raise PackageError('A secret field in .env.example must be blank: ' + key)
    try:
        trust = json.loads(payload['deploy/release-public-trust.json'])
        if set(trust) - {'deployment_id', 'keys'} or not isinstance(trust['keys'], dict) or not 1 <= len(trust['keys']) <= 16:
            raise ValueError()
        for key_id, encoded in trust['keys'].items():
            public = base64.b64decode(encoded, validate=True)
            if len(public) != 32 or hashlib.sha256(public).hexdigest()[:32] != key_id:
                raise ValueError()
    except (ValueError, KeyError, TypeError):
        raise PackageError('Release trust input must contain only valid public Ed25519 trust') from None


def snapshot(root: Path) -> tuple[str, dict[str, bytes]]:
    names = selected_paths(root)
    payload = {}
    total = 0
    for name in names:
        data = _regular_bytes(root, name)
        total += len(data)
        if total > MAX_PAYLOAD_BYTES:
            raise PackageError('Selected public release source exceeds the package byte budget')
        payload[name] = data
    version = re.search(rb'^__version__\s*=\s*"([0-9]+\.[0-9]+\.[0-9]+)"\s*$', payload['controller/__init__.py'], re.MULTILINE)
    if not version:
        raise PackageError('Controller version must be a literal semantic version')
    _validate_public_templates(payload)
    return version.group(1).decode('ascii'), payload


def _manifest(version: str, payload: dict[str, bytes]) -> dict:
    return {'product': 'Prṛthak controller', 'version': version, 'source_only': True,
            'files': {name: {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
                      for name, data in sorted(payload.items())}}


def build(source_root: Path, output_dir: Path, *, dry_run: bool = False, overwrite: bool = False) -> dict:
    source_root = source_root.resolve(strict=True)
    version, payload = snapshot(source_root)
    stem = 'prthak-controller-' + version
    filename = stem + '.tar.gz'
    manifest = _manifest(version, payload)
    if dry_run:
        return {'dry_run': True, 'archive': filename, 'public_source_files': len(payload), 'manifest': manifest}
    output_dir = output_dir.resolve()
    output_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = output_dir.stat()
    if info.st_uid != os.geteuid() or info.st_mode & 0o022:
        raise PackageError('Use a private owned output directory, without group/other write access')
    archive = output_dir / filename
    destinations = [archive, output_dir / (filename + '.sha256'), output_dir / (filename + '.manifest.json'),
                    output_dir / (filename + '.signature.json'), output_dir / (filename + '.public-trust.json')]
    for path in destinations:
        if path.is_symlink() or (path.exists() and not path.is_file()):
            raise PackageError('Output destinations must be regular files, never symlinks')
        if path.exists() and not overwrite:
            raise PackageError('Release output already exists; use --overwrite only for a reviewed unpublished rebuild')
    install = f'''Prṛthak · पृथक् — controller {version} source installation bundle

Verify this exact archive's Ed25519 signature before extraction, using an
independently approved public pin and approved copy of verify-release.py.
The adjacent public-trust file alone does not establish trust. A local project
signing authority is not an organization-approved release authority.

Read docs/controller-installation.md and docs/controller-vm-requirements.md.
Git is optional for obtaining source and is not a controller runtime dependency.
The host needs genuine Linux systemd, protected root-owned Python3.9+, local
Docker Engine and Composev2. After verified extraction, run once:

  sudo ./scripts/install-controller.sh --gui-setup

Open the printed HTTPS /settings URL. The private initial credential FILE path
is printed separately; obtain it through your approved secure channel. Complete
site/TLS, initial Entra candidate sign-in and runtime configuration in the GUI.
No manual .env editing is required. Read docs/pilot-gui-installation.md.
Advanced --env-file installation remains supported for existing deployments.

The installer builds images and fetches base images/OS/Python packages, etcd and
HAProxy. Approved registry/package access is required; this is not an offline
image bundle. Native/DC/DR and target hardware validation remain separate.
No keys, real environment file, database, test fixture or agent binary is included.
'''.encode('utf-8')
    archive_payload = dict(payload, **{'INSTALL.txt': install, 'MANIFEST.json': (json.dumps(manifest, sort_keys=True, indent=2, ensure_ascii=False) + '\n').encode('utf-8')})
    with tempfile.TemporaryDirectory(prefix='.prthak-controller-build-', dir=output_dir) as temporary:
        stage = Path(temporary)
        candidate = stage / filename
        with candidate.open('xb') as raw, gzip.GzipFile(filename='', mode='wb', fileobj=raw, mtime=0) as compressed:
            with tarfile.open(mode='w|', fileobj=compressed, format=tarfile.PAX_FORMAT) as bundle:
                for name, data in sorted(archive_payload.items()):
                    entry = tarfile.TarInfo(stem + '/' + name)
                    entry.size, entry.mtime, entry.uid, entry.gid = len(data), 0, 0, 0
                    entry.uname = entry.gname = 'root'
                    entry.mode = 0o755 if name in EXECUTABLES else 0o644
                    bundle.addfile(entry, io.BytesIO(data))
        # A source freeze is required; refuse a mixed build after concurrent edits.
        final_version, final_payload = snapshot(source_root)
        if final_version != version or final_payload != payload:
            raise PackageError('Release source changed while packaging; freeze it and build again')
        digest = hashlib.sha256(candidate.read_bytes()).hexdigest()
        (stage / (filename + '.sha256')).write_text(digest + '  ' + filename + '\n')
        (stage / (filename + '.manifest.json')).write_text(json.dumps(manifest, sort_keys=True, indent=2, ensure_ascii=False) + '\n')
        signing_key = os.environ.get('PRTHAK_RELEASE_SIGNING_KEY_FILE')
        if signing_key:
            subprocess.run([sys.executable, str(PROJECT / 'scripts/sign-release.py'), '--key-file', signing_key, str(candidate)], check=True)
        for path in stage.iterdir():
            path.chmod(0o644)
            os.replace(path, output_dir / path.name)
        if not signing_key:
            # A reviewed unsigned rebuild must not retain stale detached authority.
            for suffix in ('.signature.json', '.public-trust.json'):
                (output_dir / (filename + suffix)).unlink(missing_ok=True)
    return {'dry_run': False, 'archive': str(archive), 'sha256': digest, 'bytes': archive.stat().st_size,
            'public_source_files': len(payload), 'archive_files': len(archive_payload), 'signed': bool(signing_key)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', type=Path, default=PROJECT)
    parser.add_argument('--output-dir', type=Path, default=PROJECT / 'dist')
    parser.add_argument('--dry-run', action='store_true', help='validate and list public inputs without creating files or signing')
    parser.add_argument('--overwrite', action='store_true', help='replace a reviewed unpublished package and its sidecars')
    args = parser.parse_args()
    try:
        result = build(args.source_root, args.output_dir, dry_run=args.dry_run, overwrite=args.overwrite)
    except (PackageError, OSError, UnicodeError, subprocess.SubprocessError) as error:
        print('Controller package blocked: ' + str(error), file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
