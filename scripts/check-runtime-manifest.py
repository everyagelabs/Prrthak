#!/usr/bin/env python3
"""Check committed signed runtime bytes without private keys or image builds."""
import argparse
import base64
import importlib.util
import json
import re
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'scripts'))
from controller.runtime_integrity import IntegrityError, verify


def check(root, manifest=None, trust=None):
    root = Path(root).resolve(strict=True)
    manifest = Path(manifest) if manifest else root / 'deploy/runtime-integrity.json'
    trust = Path(trust) if trust else root / 'deploy/release-public-trust.json'
    result = verify(root, manifest, trust, protected_directories=False)
    spec = importlib.util.spec_from_file_location('prthak_runtime_manifest_builder', ROOT / 'scripts/sign-runtime.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    expected = module.controller_manifest(root)
    version = re.search(r'^__version__\s*=\s*"([0-9]+\.[0-9]+\.[0-9]+)"\s*$', (root / 'controller/__init__.py').read_text(), re.MULTILINE)
    if not version:
        raise IntegrityError('Source controller version must be a literal semantic version')
    expected['version'] = version.group(1)
    signed = json.loads(base64.b64decode(json.loads(manifest.read_bytes())['payload']))['manifest']
    if signed != expected:
        raise IntegrityError('Signed runtime version, bootstrap, manager or file inventory differs from source; regenerate the reviewed manifest')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', type=Path, default=ROOT)
    parser.add_argument('--manifest', type=Path)
    parser.add_argument('--public-trust-file', type=Path)
    args = parser.parse_args()
    try:
        result = check(args.source_root, args.manifest, args.public_trust_file)
    except (IntegrityError, OSError, ValueError) as error:
        parser.exit(1, 'Runtime manifest check failed: ' + str(error) + '\n')
    print('Signed runtime matches source: version ' + result['version'] + ', ' + str(result['files']) + ' public files')


if __name__ == '__main__':
    main()
