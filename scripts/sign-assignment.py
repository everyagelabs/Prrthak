#!/usr/bin/env python3
"""Run on an isolated signing workstation after reviewing the exact assignment."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from controller.policy_signing import PolicySigner

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--key-file", required=True)
parser.add_argument("--deployment-id", required=True)
parser.add_argument("--output-directory", required=True)
parser.add_argument("--confirm", required=True, help="exact phrase: SIGN REVIEWED ASSIGNMENT")
parser.add_argument("assignment", help="reviewed unsigned JSON assignment exported by the operator")
args = parser.parse_args()
if args.confirm != "SIGN REVIEWED ASSIGNMENT":
    raise SystemExit("Review the complete target, sources, authorities and expiry before signing")
policy = json.loads(Path(args.assignment).read_text())
signer = PolicySigner(args.key_file, args.deployment_id)
value = signer.sign(policy)
directory = Path(args.output_directory)
directory.mkdir(parents=True, exist_ok=True, mode=0o700)
path = directory / (hashlib.sha256(policy["server_id"].encode()).hexdigest() + ".json")
descriptor, temporary = tempfile.mkstemp(prefix=path.name+".", dir=directory)
try:
    with os.fdopen(descriptor, "w") as handle:
        json.dump(value, handle, sort_keys=True, indent=2)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)
    descriptor = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
finally:
    if os.path.exists(temporary):
        os.unlink(temporary)
print("Signed exact assignment for " + policy["server_id"] + "; transfer the protected artifact through your approved process")
