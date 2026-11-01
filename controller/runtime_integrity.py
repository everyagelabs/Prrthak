"""Verify signed immutable application bytes before an installed runtime starts.

This protects release integrity, not confidentiality or a compromised root host.
GUI settings, PKI, inventory and other mutable state are intentionally excluded.
"""
import base64
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat

DOMAIN = "prthak-package-manifest-v1"
KIND = "prthak-controller-runtime-v1"


class IntegrityError(RuntimeError):
    pass


def _read(path, maximum, owner):
    path = Path(path)
    for parent in (path.parent, *path.parent.parents):
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != owner or info.st_mode & 0o022:
            raise IntegrityError("Runtime integrity requires protected owned directories")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != owner or info.st_mode & 0o022 or info.st_size > maximum:
            raise IntegrityError("Runtime integrity requires protected regular release files")
        value = source.read(maximum + 1)
        if len(value) > maximum:
            raise IntegrityError("Runtime integrity file exceeds its byte limit")
        return value


def verify(root, manifest_path, trust_path, *, owner=0, protected_directories=True, component=None, host_manager=None):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    def read(path, maximum):
        if protected_directories:
            return _read(path, maximum, owner)
        # Isolated test fixtures still reject symlinks and writable files.
        info = Path(path).lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o022:
            raise IntegrityError("Invalid release file")
        value = Path(path).read_bytes()
        if len(value) > maximum:
            raise IntegrityError("Oversized release file")
        return value
    try:
        signed = json.loads(read(manifest_path, 512 * 1024))
        trust = json.loads(read(trust_path, 16384))
        if signed["algorithm"] != "Ed25519" or not 1 <= len(trust["keys"]) <= 16:
            raise ValueError()
        public = base64.b64decode(trust["keys"][signed["key_id"]], validate=True)
        if len(public) != 32 or hashlib.sha256(public).hexdigest()[:32] != signed["key_id"]:
            raise ValueError()
        payload = base64.b64decode(signed["payload"], validate=True)
        Ed25519PublicKey.from_public_bytes(public).verify(base64.b64decode(signed["signature"], validate=True), payload)
        document = json.loads(payload)
        manifest = document["manifest"]
        if document["domain"] != DOMAIN or manifest["kind"] != KIND or not isinstance(manifest["version"], str):
            raise ValueError()
        files = manifest["files"]
        if not isinstance(files, dict) or not 5 <= len(files) <= 1000:
            raise ValueError()
        root = Path(root)
        for name, expected in files.items():
            path = PurePosixPath(name)
            if path.is_absolute() or path.as_posix() != name or ".." in path.parts or "\\" in name or path.parts[0] not in ("controller", "dashboard", "deploy"):
                raise ValueError()
            value = read(root.joinpath(*path.parts), 8 * 1024 * 1024)
            if expected != {"bytes": len(value), "sha256": hashlib.sha256(value).hexdigest()}:
                raise IntegrityError("Application release bytes changed: " + name)
        actual = {p.relative_to(root).as_posix() for p in (root / "controller").glob("*.py")}
        actual.update(p.relative_to(root).as_posix() for p in (root / "dashboard").rglob("*") if p.is_file() and p.suffix in (".js", ".html", ".css", ".svg", ".png", ".woff2"))
        if actual - set(files):
            raise IntegrityError("An unlisted application runtime file is present")
        if component:
            bootstrap=manifest.get('bootstrap_files',{})
            required=['/opt/prthak-integrity/runtime_verify.py','/opt/prthak-integrity/launch.py']
            if component=='appliance':required.append('/opt/prthak/controller_entrypoint.py')
            for name in required:
                raw=read(name,1024*1024)
                if bootstrap.get(name)!={'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}:
                    raise IntegrityError('Signed runtime bootstrap bytes changed')
        if host_manager is not None:
            raw=read(host_manager,1024*1024)
            if manifest.get('host_files',{}).get('/opt/prthak-appliance/node_manager.py')!={'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}:
                raise IntegrityError('Signed host-manager bytes changed')
        return {"verified": True, "version": manifest["version"], "files": len(files), "key_id": signed["key_id"]}
    except IntegrityError:
        raise
    except Exception:
        raise IntegrityError("Signed application runtime integrity did not verify; startup refused") from None


def verify_installed():
    if os.environ.get("PRTHAK_REQUIRE_INTEGRITY") != "1":
        return None
    return verify("/app", "/opt/prthak-integrity/runtime-integrity.json", "/opt/prthak-integrity/public-trust.json",component="appliance" if os.environ.get("PRTHAK_APPLIANCE")=="1" else "base")
