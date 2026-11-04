"""Bounded downloads of agent packages staged in the protected release mount."""
import base64
from contextlib import ExitStack, contextmanager
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import __version__
from .runtime_integrity import DOMAIN


RELEASE_DIR = Path("/run/prthak-agent-releases")
PUBLIC_TRUST = Path("/opt/prthak-integrity/public-trust.json")
ARCHITECTURES = ("amd64", "arm64")
VERSIONS = tuple(dict.fromkeys((__version__, "0.18.5", "0.18.4", "0.18.3", "0.18.2", "0.18.1", "0.18.0")))
ARCHIVE_LIMIT = 16 * 1024 * 1024
METADATA_LIMIT = 16 * 1024


@contextmanager
def _protected_file(path, maximum):
    for parent in path.parents:
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError("Agent release directories must be root-owned and protected")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as source:
        info = os.fstat(source.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022
                or info.st_nlink != 1 or not 0 < info.st_size <= maximum):
            raise ValueError("Agent release must be a bounded protected regular file")
        yield source, info.st_size


def _metadata(path):
    with _protected_file(path, METADATA_LIMIT) as (source, size):
        raw = source.read(size + 1)
    if len(raw) != size:
        raise ValueError("Agent release metadata changed during read")
    return raw


def _manifest(signature, trust, filename, size):
    envelope = json.loads(signature)
    keys = json.loads(trust)["keys"]
    key_id = envelope["key_id"]
    if envelope["algorithm"] != "Ed25519" or not 1 <= len(keys) <= 16:
        raise ValueError("Unsupported agent release signature")
    public = base64.b64decode(keys[key_id], validate=True)
    if len(public) != 32 or hashlib.sha256(public).hexdigest()[:32] != key_id:
        raise ValueError("Agent release signing key does not match its trust pin")
    payload = base64.b64decode(envelope["payload"], validate=True)
    Ed25519PublicKey.from_public_bytes(public).verify(base64.b64decode(envelope["signature"], validate=True), payload)
    document = json.loads(payload)
    manifest = document["manifest"]
    if (document["domain"] != DOMAIN or manifest["filename"] != filename or type(manifest["bytes"]) is not int
            or manifest["bytes"] != size or not re.fullmatch(r"[a-f0-9]{64}", manifest["sha256"])):
        raise ValueError("Agent release signature does not describe this archive")
    return manifest["sha256"]


@contextmanager
def _release(architecture, version):
    filename = f"prthak-agent-{version}-linux-{architecture}.tar.gz"
    with _protected_file(RELEASE_DIR / filename, ARCHIVE_LIMIT) as (source, size):
        signature = _metadata(RELEASE_DIR / (filename + ".signature.json"))
        digest = _manifest(signature, _metadata(PUBLIC_TRUST), filename, size)
        yield filename, size, source, signature, digest


_INVALID = (OSError, ValueError, TypeError, KeyError, InvalidSignature)


def _verify_archive(release):
    _, size, source, _, expected = release
    checksum = hashlib.sha256()
    remaining = size
    while remaining and (chunk := source.read(min(65536, remaining))):
        checksum.update(chunk)
        remaining -= len(chunk)
    if remaining or source.read(1) or checksum.hexdigest() != expected:
        raise ValueError("Agent archive digest changed")
    source.seek(0)


def available_versions(*, verify=False, version=None):
    result = []
    for candidate in VERSIONS:
        if version is not None and version != candidate:
            continue
        architectures = {}
        for architecture in ARCHITECTURES:
            try:
                with _release(architecture, candidate) as release:
                    if verify:
                        _verify_archive(release)
                    architectures[architecture] = {"bytes": release[1], "sha256": release[4]}
            except _INVALID:
                continue
        if architectures:
            result.append({"version": candidate, "architectures": architectures})
    return result


def _asset(release, asset):
    filename, size, source, signature, _ = release
    if asset == "signature":
        return filename + ".signature.json", len(signature), io.BytesIO(signature)
    return filename, size, source


@contextmanager
def _select_release(architecture):
    with ExitStack() as stack:
        for version in VERSIONS:
            try:
                release = stack.enter_context(_release(architecture, version))
            except _INVALID:
                continue
            yield version, release
            return
    raise FileNotFoundError("Signed agent package is unavailable")


def available():
    result = {}
    for architecture in ARCHITECTURES:
        try:
            with _select_release(architecture) as (version, _):
                result[architecture] = version
        except FileNotFoundError:
            continue
    return result


@contextmanager
def open_download(architecture, asset):
    """Keep the authenticated file open across verification and streaming."""
    if architecture not in ARCHITECTURES or asset not in ("archive", "signature"):
        raise FileNotFoundError("Signed agent package is unavailable")
    with _select_release(architecture) as (_, release):
        try:
            _verify_archive(release)
        except _INVALID:
            raise FileNotFoundError("Signed agent package is unavailable") from None
        yield _asset(release, asset)


@contextmanager
def open_exact_download(architecture, version, asset, expected):
    """Verify the exact reviewed artifact and never substitute a fallback."""
    if architecture not in ARCHITECTURES or version not in VERSIONS or asset not in ("archive", "signature"):
        raise FileNotFoundError("Signed agent package is unavailable")
    with ExitStack() as stack:
        try:
            release = stack.enter_context(_release(architecture, version))
            if release[1] != expected["bytes"] or release[4] != expected["sha256"]:
                raise ValueError("Signed agent package does not match the reviewed assignment")
            _verify_archive(release)
        except _INVALID:
            raise FileNotFoundError("Signed agent package is unavailable") from None
        yield _asset(release, asset)
