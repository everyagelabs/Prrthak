#!/usr/bin/env python3
"""Combine the reviewed controller archive and local dependency payload."""

import argparse
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tarfile
import tempfile


PROJECT = Path(__file__).resolve().parents[1]
REQUIRED = {'keys/docker.asc', 'rpms/repodata/repomd.xml', 'images.json', 'images.tar.gz'}
RPM = re.compile(r'rpms/[A-Za-z0-9._+~:-]+\.rpm')
REPODATA = re.compile(r'rpms/repodata/[A-Za-z0-9._-]+')


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


def pack(controller, payload, output, key):
    match = re.fullmatch(r'(prthak-controller-[0-9]+\.[0-9]+\.[0-9]+)\.tar\.gz', controller.name)
    if not match or controller.is_symlink() or not controller.is_file():
        raise ValueError('Supply a reviewed controller installation archive')
    stem = match[1]
    files = payload_files(payload)
    filename = stem + '-offline-rhel9-x86_64.tar.gz'
    output.mkdir(mode=0o700, parents=True, exist_ok=True)
    names = (filename, filename + '.signature.json', filename + '.public-trust.json')
    if any(os.path.lexists(output/name) for name in names):
        raise ValueError('Offline release output already exists')
    with tempfile.TemporaryDirectory(prefix='.offline-controller-', dir=output) as temporary:
        stage = Path(temporary)
        candidate = stage/filename
        with tarfile.open(controller, 'r:gz') as base, tarfile.open(candidate, 'x:gz', compresslevel=1) as bundle:
            seen = set()
            for member in base:
                parts = PurePosixPath(member.name).parts
                if (not member.isfile() or len(parts) < 2 or parts[0] != stem or '..' in parts
                        or parts[1] == 'offline' or member.name in seen or member.mode & 0o022):
                    raise ValueError('Unsafe entry in the controller archive')
                seen.add(member.name)
                with base.extractfile(member) as source:
                    bundle.addfile(member, source)
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
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args()
    key = os.environ.get('PRTHAK_RELEASE_SIGNING_KEY_FILE')
    if not key:
        parser.error('PRTHAK_RELEASE_SIGNING_KEY_FILE is required')
    try:
        print(pack(args.controller_archive, args.payload.resolve(strict=True), args.output_dir, key))
    except (ValueError, OSError, tarfile.TarError, subprocess.SubprocessError) as error:
        parser.exit(1, 'Offline controller packaging blocked: ' + str(error) + '\n')


if __name__ == '__main__':
    main()
