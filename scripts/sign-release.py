#!/usr/bin/env python3
"""Sign release archives with an independently provisioned Ed25519 seed."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from controller.policy_signing import PolicySigner
from release_safety import outside_source_key
from release_provenance import provenance

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--key-file", required=True)
parser.add_argument("--create-key", action="store_true", help="create a new private seed only if absent; distribute its public trust independently")
parser.add_argument("archives", nargs="+")
args = parser.parse_args()
if args.create_key and not Path(args.key_file).exists():
    candidate=outside_source_key(args.key_file,must_exist=False)
    PolicySigner(candidate,"00000000-0000-0000-0000-000000000000",create=True)
signer = PolicySigner(outside_source_key(args.key_file), "00000000-0000-0000-0000-000000000000", create=False)
for value in args.archives:
    archive = Path(value)
    if archive.is_symlink() or not archive.is_file():
        raise SystemExit("Sign only a regular release archive")
    digest = hashlib.sha256()
    with archive.open("rb") as handle:
        while block := handle.read(1024 * 1024):
            digest.update(block)
    manifest = {"filename": archive.name, "bytes": archive.stat().st_size, "sha256": digest.hexdigest(),"provenance":provenance()}
    archive.with_name(archive.name + ".signature.json").write_text(json.dumps(signer.sign_package(manifest), sort_keys=True, indent=2) + "\n")
    archive.with_name(archive.name + ".public-trust.json").write_text(json.dumps(signer.public_trust(), sort_keys=True, indent=2) + "\n")
    print("Signed " + archive.name + " with public key " + signer.key_id)
