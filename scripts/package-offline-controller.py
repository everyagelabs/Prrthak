#!/usr/bin/env python3
"""Combine the reviewed controller archive and local dependency payload."""

import argparse
import importlib.util
import io
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tarfile
import tempfile


PROJECT = Path(__file__).resolve().parents[1]
REQUIRED = {'keys/docker.asc', 'rpms/repodata/repomd.xml', 'images.json', 'images.tar.gz'}
GUI_ONLY = 'OFFLINE-UPDATE-ONLY'
RPM = re.compile(r'rpms/[A-Za-z0-9._+~:-]+\.rpm')
REPODATA = re.compile(r'rpms/repodata/[A-Za-z0-9._-]+')
INSTALL = """Prthak offline controller for RHEL 9 x86_64

Verify the detached release signature with an independently trusted public pin
before extraction. See docs/offline-controller-installation.md for instructions.

On the controller VM, run the installer from the verified release directory.

  sudo ./scripts/install-controller.sh

The installer detects the offline payload and uses the bundled RPMs and images.
Open the printed HTTPS setup URL to finish configuration.

Created by Pratik Srivastava
""".encode('utf-8')
UPDATE = """Prthak offline GUI controller update for RHEL 9 x86_64

Sign in as a Super Admin and open Platform settings > Updates. Upload this
archive and its matching detached signature, review the result and confirm the
restart. The installed appliance verifies the signature against its release
trust. Host packages are preserved. The included signed RPM repository is for
compatibility with older update validators. Use a full installation archive
when setting up a new controller.

Created by Pratik Srivastava
""".encode('utf-8')


def payload_files(root):
    files = {}
    for directory, children, names in os.walk(root, followlinks=False):
        directory = Path(directory)
        if any((directory/name).is_symlink() for name in children):
            raise ValueError('Offline payload directories must not be symlinks')
        for name in names:
            path = directory/name
            relative = path.relative_to(root).as_posix()
            if (path.is_symlink() or not path.is_file() or not path.stat().st_size
                    or not (relative in REQUIRED or RPM.fullmatch(relative) or REPODATA.fullmatch(relative))):
                raise ValueError('Unexpected offline payload file: ' + relative)
            files[relative] = path
    if REQUIRED - files.keys() or not any(RPM.fullmatch(name) for name in files):
        raise ValueError('The offline image or RPM payload is incomplete')
    return files


def verified_agents(directory, version):
    spec = importlib.util.spec_from_file_location('prthak_controller_packager', PROJECT/'scripts/package-controller.py')
    packager = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(packager)
    return packager.verified_agent_assets(directory, version, (PROJECT/'deploy/release-public-trust.json').read_bytes())


def pack(controller, payload, output, key, agent_dist=PROJECT/'dist', *, gui_update_only=False):
    match = re.fullmatch(r'(prthak-controller-([0-9]+\.[0-9]+\.[0-9]+))\.tar\.gz', controller.name)
    if not match or controller.is_symlink() or not controller.is_file():
        raise ValueError('Supply a reviewed controller installation archive')
    stem = match[1]
    files = payload_files(payload)
    packages = [name for name in files if RPM.fullmatch(name)]
    if gui_update_only:
        if len(packages) != 1 or not packages[0].startswith('rpms/docker-compose-plugin-'):
            raise ValueError('A GUI-only update needs the verified Docker Compose compatibility repository')
    elif not any(name.startswith('rpms/docker-ce-') and not name.startswith(('rpms/docker-ce-cli-', 'rpms/docker-ce-rootless-')) for name in packages):
        raise ValueError('A full installation needs the Docker Engine dependency repository')
    filename = stem + '-offline-rhel9-x86_64.tar.gz'
    output.mkdir(mode=0o700, parents=True, exist_ok=True)
    names = (filename, filename + '.signature.json', filename + '.public-trust.json')
    if any(os.path.lexists(output/name) for name in names):
        raise ValueError('Offline release output already exists')
    with tempfile.TemporaryDirectory(prefix='.offline-controller-', dir=output) as temporary:
        stage = Path(temporary)
        agents = verified_agents(agent_dist, match[2])
        candidate = stage/filename
        with tarfile.open(controller, 'r:gz') as base, tarfile.open(candidate, 'x:gz', compresslevel=1) as bundle:
            marker_data = b'Prthak controller offline release for RHEL 9 x86_64\n'
            marker = tarfile.TarInfo(stem + '/OFFLINE-CONTROLLER')
            marker.mode, marker.size = 0o644, len(marker_data)
            marker.uname = marker.gname = 'root'
            bundle.addfile(marker, io.BytesIO(marker_data))
            if gui_update_only:
                marker = tarfile.TarInfo(stem + '/' + GUI_ONLY)
                marker_data = b'Upload this archive and its signature through the installed Prthak GUI.\n'
                marker.mode, marker.size = 0o644, len(marker_data)
                marker.uname = marker.gname = 'root'
                bundle.addfile(marker, io.BytesIO(marker_data))
            seen = set()
            embedded = set()
            for member in base:
                parts = PurePosixPath(member.name).parts
                if (not member.isfile() or len(parts) < 2 or parts[0] != stem or '..' in parts
                        or parts[1] in ('offline', 'OFFLINE-CONTROLLER', GUI_ONLY) or member.name in seen or member.mode & 0o022):
                    raise ValueError('Unsafe entry in the controller archive')
                seen.add(member.name)
                if member.name == stem + '/INSTALL.txt':
                    instructions = UPDATE if gui_update_only else INSTALL
                    member.size = len(instructions)
                    bundle.addfile(member, io.BytesIO(instructions))
                elif parts[1] == 'agent-releases':
                    data = agents.get(parts[-1]) if len(parts) == 3 else None
                    with base.extractfile(member) as source:
                        if data is None or member.size != len(data) or source.read() != data:
                            raise ValueError('Embedded agent artifact does not match the signed release: ' + member.name)
                    bundle.addfile(member, io.BytesIO(data))
                    embedded.add(parts[-1])
                else:
                    with base.extractfile(member) as source:
                        bundle.addfile(member, source)
            if embedded and embedded != agents.keys():
                raise ValueError('The controller archive contains an incomplete set of signed agent artifacts')
            if not embedded:
                for name, data in sorted(agents.items()):
                    member = tarfile.TarInfo(stem + '/agent-releases/' + name)
                    member.mode, member.size = 0o644, len(data)
                    member.uname = member.gname = 'root'
                    bundle.addfile(member, io.BytesIO(data))
            for name, path in sorted(files.items()):
                member = tarfile.TarInfo(stem + '/offline/' + name)
                member.mode = 0o600 if name == 'images.json' else 0o644
                member.size = path.stat().st_size
                member.uname = member.gname = 'root'
                with path.open('rb') as source:
                    bundle.addfile(member, source)
        if candidate.stat().st_size >= 2 * 1024**3:
            raise ValueError('Offline archive exceeds the GitHub release asset limit')
        subprocess.run([sys.executable, str(PROJECT/'scripts/sign-release.py'), '--key-file', key,
                        str(candidate)], check=True)
        subprocess.run([sys.executable, str(PROJECT/'scripts/verify-release.py'), '--public-trust-file',
                        str(PROJECT/'deploy/release-public-trust.json'), '--signature',
                        str(candidate) + '.signature.json', str(candidate)], check=True)
        for name in names:
            os.link(stage/name, output/name)
    return output/filename


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--controller-archive', type=Path, required=True)
    parser.add_argument('--payload', type=Path, required=True, help='staged offline/ payload directory')
    parser.add_argument('--agent-dist', type=Path, default=PROJECT/'dist',
                        help='directory containing both signed Linux agent archives and detached signatures')
    parser.add_argument('--output-dir', type=Path, required=True)
    parser.add_argument('--gui-update-only', action='store_true',
                        help='build a GUI upload that preserves installed host packages')
    args = parser.parse_args()
    key = os.environ.get('PRTHAK_RELEASE_SIGNING_KEY_FILE')
    if not key:
        parser.error('PRTHAK_RELEASE_SIGNING_KEY_FILE is required')
    try:
        print(pack(args.controller_archive, args.payload.resolve(strict=True), args.output_dir, key, args.agent_dist,
                   gui_update_only=args.gui_update_only))
    except (ValueError, OSError, tarfile.TarError, subprocess.SubprocessError) as error:
        parser.exit(1, 'Offline controller packaging blocked: ' + str(error) + '\n')


if __name__ == '__main__':
    main()
