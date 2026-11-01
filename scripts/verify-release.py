#!/usr/bin/env python3
"""Verify before extracting; use independently obtained public trust, not a key
downloaded alongside an untrusted archive as the authority for that archive."""
import argparse
import base64
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--public-trust-file", required=True)
parser.add_argument("--signature", required=True)
parser.add_argument("archive")
args = parser.parse_args()
try:
    trust_path = Path(args.public_trust_file)
    if trust_path.is_symlink() or trust_path.stat().st_mode & 0o022 or trust_path.stat().st_size > 16384:
        raise ValueError()
    trust = json.loads(trust_path.read_text())
    signature_path = Path(args.signature)
    if signature_path.stat().st_size > 16384:
        raise ValueError()
    signature = json.loads(signature_path.read_text())
    if signature["algorithm"] != "Ed25519":
        raise ValueError()
    public = base64.b64decode(trust["keys"][signature["key_id"]], validate=True)
    if len(public) != 32 or hashlib.sha256(public).hexdigest()[:32] != signature["key_id"]:
        raise ValueError()
    raw = base64.b64decode(signature["payload"], validate=True)
    Ed25519PublicKey.from_public_bytes(public).verify(base64.b64decode(signature["signature"], validate=True), raw)
    document = json.loads(raw)
    if document["domain"] != "prthak-package-manifest-v1":
        raise ValueError()
    manifest = document["manifest"]
    archive = Path(args.archive)
    if archive.is_symlink() or not archive.is_file() or manifest["filename"] != archive.name or manifest["bytes"] != archive.stat().st_size:
        raise ValueError()
    digest = hashlib.sha256()
    with archive.open("rb") as handle:
        while block := handle.read(1024 * 1024):
            digest.update(block)
    if digest.hexdigest() != manifest["sha256"]:
        raise ValueError()
except Exception:
    raise SystemExit("Release signature or exact archive digest did not verify; do not extract or install") from None
print("Verified trusted Ed25519 signature and exact archive bytes: " + archive.name)
