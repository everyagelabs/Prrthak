#!/usr/bin/env python3
"""Sign public runtime bytes; the private release key never enters an image."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from controller import __version__
from controller.policy_signing import PolicySigner
from release_safety import outside_source_key


def file_record(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError("Sign only regular public runtime files")
    raw = path.read_bytes()
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def controller_manifest(root=ROOT):
    paths = list((root / "controller").glob("*.py"))
    paths.extend(p for p in (root / "dashboard").rglob("*") if p.is_file() and 'tests' not in p.relative_to(root / 'dashboard').parts and p.suffix in (".js", ".html", ".css", ".svg", ".png", ".woff2"))
    paths.append(root / 'deploy/cluster/node_helper.py')
    return {"kind": "prthak-controller-runtime-v1", "version": __version__,
            "files": {p.relative_to(root).as_posix(): file_record(p) for p in sorted(paths)},
            "bootstrap_files":{'/opt/prthak-integrity/runtime_verify.py':file_record(root/'controller/runtime_integrity.py'),
                               '/opt/prthak-integrity/launch.py':file_record(root/'deploy/verify_runtime_entrypoint.py'),
                               '/opt/prthak/controller_entrypoint.py':file_record(root/'deploy/appliance/controller_entrypoint.py')},
            "host_files":{'/opt/prthak-appliance/node_manager.py':file_record(root/'deploy/appliance/node_manager.py')}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--key-file', required=True)
    parser.add_argument('--agent-binary')
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    signer = PolicySigner(outside_source_key(args.key_file), '00000000-0000-0000-0000-000000000000', create=False)
    if args.agent_binary:
        manifest = {"kind": "prthak-agent-runtime-v1", "version": __version__, "files": {
            "/usr/local/bin/seg-agent": file_record(Path(args.agent_binary)),
            "/etc/systemd/system/seg-agent.service": file_record(ROOT / 'deploy/systemd/seg-agent.service')}}
    else:
        manifest = controller_manifest()
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(signer.sign_package(manifest), sort_keys=True, indent=2) + '\n')
    print('Signed runtime integrity manifest: ' + output.name + ' (' + signer.key_id + ')')


if __name__ == '__main__':
    main()
