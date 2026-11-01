"""Independent Ed25519 assignment/package signatures and public trust manifests.

The key is separate from HTTPS and endpoint PKI. HA operators provision the same
private seed on controllers, or import signatures from an isolated signer. A
new public key is never silently accepted because an HTTPS certificate changed.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import re
from pathlib import Path
import stat
import time
import uuid

DOMAIN = "prthak-policy-assignment-v1"
PACKAGE_DOMAIN = "prthak-package-manifest-v1"
# A signed response includes both the original assignment and base64 envelope.
# Three MiB here keeps their combined serialization below the agent's8MiB cap.
MAX_PAYLOAD = 3 * 1024 * 1024


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()


def _encode(value):
    return base64.b64encode(value).decode()


def _decode(value):
    if not isinstance(value, str) or len(value) > MAX_PAYLOAD * 2:
        raise ValueError("Invalid signed material")
    try:
        return base64.b64decode(value, validate=True)
    except Exception:
        raise ValueError("Invalid signed material") from None


def key_id(public):
    return hashlib.sha256(public).hexdigest()[:32]


class PolicySigner:
    def __init__(self, path, deployment_id, *, create=False):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization
        self.path = Path(path)
        self.deployment_id = str(uuid.UUID(deployment_id))
        if create and not self.path.exists():
            self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            key = Ed25519PrivateKey.generate()
            seed = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
            with os.fdopen(fd, "wb") as handle:
                handle.write(seed)
                handle.flush()
                os.fsync(handle.fileno())
        info = self.path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
            raise ValueError("Assignment signing seed must be a private regular mode0600 file")
        seed = self.path.read_bytes()
        if len(seed) != 32:
            raise ValueError("An Ed25519 signing seed must contain exactly32 bytes")
        self.key = Ed25519PrivateKey.from_private_bytes(seed)
        self.public = self.key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.key_id = key_id(self.public)

    def public_trust(self):
        return {"deployment_id": self.deployment_id, "keys": {self.key_id: _encode(self.public)}}

    def sign(self, policy, at=None):
        current = int(time.time() if at is None else at)
        # Stable five-minute buckets keep conditional polling cheap. The ETag
        # must include the returned signature so a connected agent refreshes it.
        issued = current // 300 * 300
        value = copy.deepcopy(policy)
        value.pop("signature", None)
        document = {"domain": DOMAIN, "deployment_id": self.deployment_id, "issued_at": issued,
                    "expires_at": issued + 1800, "policy": value}
        raw = _json(document)
        if len(raw) > MAX_PAYLOAD:
            raise ValueError("Assignment exceeds signed payload limit")
        value["signature"] = {"algorithm": "Ed25519", "key_id": self.key_id,
                              "payload": _encode(raw), "signature": _encode(self.key.sign(raw))}
        return value

    def sign_package(self, manifest):
        raw = _json({"domain": PACKAGE_DOMAIN, "manifest": manifest})
        return {"algorithm": "Ed25519", "key_id": self.key_id, "payload": _encode(raw), "signature": _encode(self.key.sign(raw))}


class OfflinePolicySigner:
    """Serve exact independently produced signatures with no controller seed.

    A signing workstation deposits one artifact per hashed endpoint identity.
    Any changed authority/source/timing requires a new artifact; there is no
    online-key fallback. Endpoint trust remains separately pinned.
    """
    def __init__(self, directory, trust_file):
        self.directory = Path(directory)
        self.trust_file = Path(trust_file)
        info = self.directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o022:
            raise ValueError("Offline signature directory must be protected against external writes")
        info = self.trust_file.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o022 or info.st_size > 16384:
            raise ValueError("Offline signing trust must be a protected public manifest")
        self.trust = json.loads(self.trust_file.read_text())
        if not isinstance(self.trust, dict) or set(self.trust) != {"deployment_id", "keys"} or not isinstance(self.trust["keys"], dict) or not 1 <= len(self.trust["keys"]) <= 8:
            raise ValueError("Offline trust must contain only a deployment ID and bounded public signing keys")
        for identifier, value in self.trust["keys"].items():
            public = _decode(value)
            if len(public) != 32 or key_id(public) != identifier:
                raise ValueError("Offline trust contains an invalid public signing key")
        self.deployment_id = str(uuid.UUID(self.trust["deployment_id"]))

    def public_trust(self):
        return copy.deepcopy(self.trust)

    def sign(self, policy, at=None):
        identifier = policy.get("server_id")
        if not isinstance(identifier, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", identifier):
            raise ValueError("A valid endpoint identity is required for offline signing")
        path = self.directory / (hashlib.sha256(identifier.encode()).hexdigest() + ".json")
        try:
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_size > 8 * 1024 * 1024:
                raise ValueError()
            artifact = json.loads(path.read_text())
            signed = verify(artifact, self.trust, at=at)
            expected = copy.deepcopy(policy)
            expected.pop("signature", None)
            if _json(signed) != _json(expected):
                raise ValueError()
        except Exception:
            raise ValueError("The exact independent signed assignment is missing, changed or expired; obtain a new offline approval") from None
        return artifact


def verify(value, trust, at=None):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    signature = value.get("signature") if isinstance(value, dict) else None
    if not isinstance(signature, dict) or signature.get("algorithm") != "Ed25519":
        raise ValueError("A trusted Ed25519 assignment signature is required")
    try:
        public = _decode(trust["keys"][signature["key_id"]])
        if len(public) != 32 or key_id(public) != signature["key_id"]:
            raise ValueError()
        raw = _decode(signature["payload"])
        if len(raw) > MAX_PAYLOAD:
            raise ValueError()
        Ed25519PublicKey.from_public_bytes(public).verify(_decode(signature["signature"]), raw)
        document = json.loads(raw)
        current = int(time.time() if at is None else at)
        issued, expires = document["issued_at"], document["expires_at"]
        if type(issued) is not int or type(expires) is not int or issued > current + 60 or not issued < expires <= issued + 1800 or current >= expires:
            raise ValueError()
        expected = copy.deepcopy(value)
        expected.pop("signature", None)
        if document["domain"] != DOMAIN or document["deployment_id"] != trust["deployment_id"] or document["policy"] != expected:
            raise ValueError()
    except Exception:
        raise ValueError("Assignment signature, pinned deployment, content or validity did not verify") from None
    return document["policy"]
