"""Bounded browser staging for an independently verified host update."""
from __future__ import annotations

import base64
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import fcntl
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import stat

from .appliance import ManagerUnavailable, NodeClient
from .firewall import WorkflowConflict
from .platform import _private_json, _read_json
from .store import now, parse_time, stamp

CAPABILITY = "offline_update_v1"
CHUNK_BYTES = 4 * 1024 * 1024
MAX_BYTES = 2 * 1024 * 1024 * 1024 - 1
SIGNATURE_BYTES = 16 * 1024
SPACE_RESERVE = 128 * 1024 * 1024
CONFIRMATION = "INSTALL CONTROLLER UPDATE"
ID = re.compile(r"[0-9a-f]{32}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
FILENAME = re.compile(r"prthak-controller-([0-9]{1,6}\.[0-9]{1,6}\.[0-9]{1,6})-offline-rhel9-x86_64\.tar\.gz\Z")
PENDING = frozenset(("queued", "running"))


def read_chunk(headers, stream):
    """Read only the declared byte count. The transport still enforces its deadline."""
    lengths = headers.get_all("Content-Length", [])
    if (len(lengths) != 1 or not re.fullmatch(r"[0-9]{1,8}", lengths[0])
            or headers.get("Transfer-Encoding") or headers.get("Content-Encoding")):
        raise ValueError("A bounded unencoded update chunk with Content-Length is required")
    size = int(lengths[0])
    if not 1 <= size <= CHUNK_BYTES or headers.get("Content-Type") != "application/octet-stream":
        raise ValueError("Use a binary update chunk no larger than 4 MiB")
    chunk = stream.read(size)
    if len(chunk) != size:
        raise ValueError("The update chunk was cut short; retry it at the same offset")
    return chunk


def _release(value):
    if set(value) != {"name", "size", "signature"}:
        raise ValueError("Select an offline controller archive and its detached release signature")
    name, size, signature = value["name"], value["size"], value["signature"]
    match = FILENAME.fullmatch(name) if isinstance(name, str) else None
    if not match or type(size) is not int or not 1 <= size <= MAX_BYTES:
        raise ValueError("Select a signed RHEL 9 x86_64 offline controller archive within the upload limit")
    try:
        if (not isinstance(signature, dict) or set(signature) != {"algorithm", "key_id", "payload", "signature"}
                or len(json.dumps(signature).encode()) > SIGNATURE_BYTES or signature["algorithm"] != "Ed25519"
                or not ID.fullmatch(signature["key_id"])
                or len(base64.b64decode(signature["signature"], validate=True)) != 64):
            raise ValueError()
        document = json.loads(base64.b64decode(signature["payload"], validate=True))
        manifest = document["manifest"]
        if (document["domain"] != "prthak-package-manifest-v1" or manifest["filename"] != name
                or type(manifest["bytes"]) is not int or manifest["bytes"] != size
                or not SHA256.fullmatch(manifest["sha256"])):
            raise ValueError()
    except (AttributeError, KeyError, TypeError, ValueError):
        raise ValueError("The detached signature must describe the selected archive and its exact size") from None
    return {"name": name, "size": size, "version": match[1], "sha256": manifest["sha256"], "signature": signature}


def _protected(descriptor, kind):
    info = os.fstat(descriptor)
    if not kind(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ValueError("Controller update staging has unsafe ownership or permissions")
    if stat.S_ISREG(info.st_mode) and info.st_nlink != 1:
        raise ValueError("Controller update files must have one link")
    return info


class OfflineUpdates:
    def __init__(self, manager, principal, client=None):
        if principal.get("role") != "super_admin" or principal.get("auth_type") != "session":
            raise PermissionError("Sign in as a Super Admin to manage controller updates")
        self.manager, self.principal = manager, principal
        self.actor = principal["actor"]
        self.client = client if client is not None else NodeClient()

    @property
    def directory(self):
        return self.manager.root / "controller-updates"

    @property
    def record_path(self):
        return self.directory / "active.json"

    def _available(self):
        if not self.manager or self.manager.app.demo or os.environ.get("PRTHAK_APPLIANCE") != "1":
            return "Controller updates require the installed appliance"
        if self.manager.app.store.ha:
            return "Controller updates currently require a standalone appliance"
        try:
            state = self.client.status()
        except (KeyError, ManagerUnavailable):
            return "The local appliance manager is unavailable"
        if CAPABILITY not in (state.get("capabilities") or ()):
            return "Install an updater-enabled standalone RHEL 9 x86_64 appliance release first"
        return ""

    def _require_available(self):
        blocker = self._available()
        if blocker:
            raise WorkflowConflict(blocker, {})

    def _authorize(self):
        with self.manager.app.store.read_meta() as db:
            self.manager.app.auth._require_super(self.principal, db)

    def _audit(self, action, record):
        self.manager.app.store.audit("controller_update." + action, self.actor, {
            "upload_id": record["id"], "archive": record["name"], "sha256": record["sha256"],
        })

    @contextmanager
    def _locked(self):
        directory = self.directory
        directory.mkdir(mode=0o700, exist_ok=True)
        descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            _protected(descriptor, stat.S_ISDIR)
            lock = os.open(".lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=descriptor)
            try:
                _protected(lock, stat.S_ISREG)
                fcntl.flock(lock, fcntl.LOCK_EX)
                yield
            finally:
                os.close(lock)
        finally:
            os.close(descriptor)

    def _archive(self, identifier):
        if not isinstance(identifier, str) or not ID.fullmatch(identifier):
            raise KeyError("Unknown controller update")
        return self.directory / (identifier + ".tar.gz")

    def _record(self, identifier):
        self._archive(identifier)
        value = _read_json(self.record_path)
        if not value or value["id"] != identifier:
            raise KeyError("Unknown controller update")
        if value["actor"] != self.actor:
            raise PermissionError("Only the Super Admin who staged this update can change it")
        return value

    @contextmanager
    def _file(self, record, flags=os.O_RDONLY):
        path = self._archive(record["id"])
        fd = os.open(path, flags | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
        try:
            info = _protected(fd, stat.S_ISREG)
            if info.st_size > record["size"]:
                raise ValueError("The update archive is larger than its declared size")
            yield fd, info.st_size
        finally:
            os.close(fd)

    def _job(self, identifier):
        try:
            value = self.client.job(identifier)
            return value if isinstance(value, dict) else None
        except (KeyError, ManagerUnavailable):
            return None

    @staticmethod
    def _review_result(record, job):
        result = job.get("result", {})
        try:
            review_id, nonce = result.get("review_id"), result.get("confirmation_nonce")
            deadline = result["expires_at"]
            expiry = datetime.fromtimestamp(deadline, timezone.utc) if type(deadline) in (float, int) else parse_time(deadline)
            valid = (isinstance(review_id, str) and ID.fullmatch(review_id)
                     and isinstance(nonce, str) and 20 <= len(nonce) <= 128
                     and result.get("version") == record["version"] and result.get("sha256") == record["sha256"]
                     and expiry > now())
        except (AttributeError, KeyError, OSError, OverflowError, TypeError, ValueError):
            valid = False
        return {**result, "expires_at": stamp(expiry)} if valid else None

    @staticmethod
    def _public_review(review):
        fields = ("version", "current_version", "sha256", "expires_at", "host_rpms")
        return {key: review[key] for key in fields if key in review}

    def _public(self, record):
        fields = ("id", "name", "size", "version", "created_at", "expires_at")
        public = {key: record[key] for key in fields}
        public.update(status=record["status"], offset=record["size"], can_cancel=False, can_retry=False)
        if "review" in record:
            public["review"] = record["review"]
        owned = self.actor == record["actor"]
        if record["status"] == "uploading":
            with self._file(record) as (_, size):
                public["offset"] = size
            public["can_cancel"] = owned or parse_time(record["expires_at"]) <= now()
            return public
        job = self._job(record["job_id"])
        if job is None:
            public["can_retry"] = owned
            if owned and record["status"] == "applying":
                public["confirmation_phrase"] = CONFIRMATION
            return public
        if job.get("status") in PENDING:
            return public
        result = job.get("result") or {}
        if record["status"] == "reviewing" and job.get("status") == "completed":
            review = self._review_result(record, job)
            if review:
                public.update(status="ready", can_cancel=owned, review=self._public_review(review))
                if owned:
                    public["confirmation_phrase"] = CONFIRMATION
                return public
            public["error"] = "The verified host review expired or no longer matches this upload"
        if record["status"] == "applying":
            if (job.get("status") == "completed" and result.get("phase") == "committed"
                    and result.get("verified") is True and result.get("rolled_back") is False):
                public.update(status="applied", can_cancel=True, result={"verified": True, "rolled_back": False, "phase": "committed"})
                return public
            if result.get("phase") == "rolled_back" and result.get("rolled_back") is True:
                public.update(status="rolled_back", can_cancel=True, result={"verified": False, "rolled_back": True, "phase": "rolled_back"})
                return public
        public.update(status="failed", can_cancel=True, error=public.get("error") or job.get("error") or "The host update did not return a verified outcome")
        return public

    def status(self):
        blocker = self._available()
        update = None
        if self.manager and self.record_path.exists():
            with self._locked():
                if record := _read_json(self.record_path):
                    update = self._public(record)
        return {"available": not blocker, "blockers": [blocker] if blocker else [], "update": update,
                "max_bytes": MAX_BYTES, "chunk_bytes": CHUNK_BYTES}

    def _remove(self, record):
        self.record_path.unlink()
        self._archive(record["id"]).unlink(missing_ok=True)

    def _prune_upload_files(self):
        # With no active record, no controller can submit one of these files to
        # the host. Remove archives left by a process crash around record writes.
        for path in self.directory.glob("*.tar.gz"):
            if ID.fullmatch(path.name.removesuffix(".tar.gz")):
                path.unlink(missing_ok=True)

    def start(self, value):
        self._require_available()
        release = _release(value)
        with self._locked():
            self._authorize()
            previous = _read_json(self.record_path)
            if previous:
                public = self._public(previous)
                if (public["status"] == "uploading" and previous["actor"] == self.actor
                        and parse_time(previous["expires_at"]) > now()
                        and all(previous[key] == val for key, val in release.items())):
                    return public
                expired_upload = public["status"] == "uploading" and parse_time(previous["expires_at"]) <= now()
                if not expired_upload and public["status"] not in ("applied", "rolled_back", "failed"):
                    raise WorkflowConflict("Finish or cancel the current controller update before starting another", {})
                self._remove(previous)
            self._prune_upload_files()
            if shutil.disk_usage(self.directory).free < release["size"] + SPACE_RESERVE:
                raise WorkflowConflict("Free disk space is too low for the controller archive upload", {})
            record = {**release, "id": secrets.token_hex(16), "actor": self.actor, "status": "uploading",
                      "created_at": stamp(), "expires_at": stamp(now() + timedelta(hours=4))}
            with self._file(record, os.O_WRONLY | os.O_CREAT | os.O_EXCL):
                pass
            try:
                _private_json(self.record_path, record)
            except Exception:
                self._archive(record["id"]).unlink(missing_ok=True)
                raise
            self._audit("upload_started", record)
            return self._public(record)

    def chunk(self, identifier, offset, content):
        if type(offset) is not int or not 0 <= offset < MAX_BYTES or not 1 <= len(content) <= CHUNK_BYTES:
            raise ValueError("Invalid update chunk size or offset")
        with self._locked():
            self._authorize()
            record = self._record(identifier)
            if record["status"] != "uploading" or parse_time(record["expires_at"]) <= now():
                raise WorkflowConflict("This controller update no longer accepts upload chunks", {})
            with self._file(record, os.O_RDWR) as (fd, received):
                if offset < received and offset + len(content) <= received and os.pread(fd, len(content), offset) == content:
                    return self._public(record)
                if offset != received or offset + len(content) > record["size"]:
                    raise WorkflowConflict("Update chunk offset does not match the staged archive", {"offset": received})
                if shutil.disk_usage(self.directory).free < len(content) + SPACE_RESERVE:
                    raise WorkflowConflict("Free disk space is too low to continue the controller upload", {})
                try:
                    view = memoryview(content)
                    cursor = offset
                    while view:
                        written = os.pwrite(fd, view, cursor)
                        if written <= 0:
                            raise OSError("The archive write did not complete")
                        cursor += written
                        view = view[written:]
                    os.fsync(fd)
                except OSError:
                    os.ftruncate(fd, received)
                    raise RuntimeError("Could not store this update chunk; retry at the same offset") from None
            return self._public(record)

    def review(self, identifier, value):
        self._require_available()
        if value:
            raise ValueError("The update review uses the staged release signature")
        with self._locked():
            self._authorize()
            record = self._record(identifier)
            if record["status"] == "uploading":
                with self._file(record) as (_, size):
                    if size != record["size"] or parse_time(record["expires_at"]) <= now():
                        raise WorkflowConflict("Upload the entire archive before requesting review", {})
                record.update(status="reviewing", job_id=secrets.token_hex(16))
                self._audit("review_requested", record)
                _private_json(self.record_path, record)
            if record["status"] != "reviewing":
                raise WorkflowConflict("This update has already been submitted for installation", {})
            self.client.submit({"action": "controller-update-review", "request_id": record["job_id"],
                                "upload_id": record["id"], **{key: record[key] for key in ("name", "size", "signature")}})
            return self._public(record)

    def apply(self, identifier, value):
        self._require_available()
        if value != {"confirmation": CONFIRMATION}:
            raise ValueError("Enter the exact confirmation to install the reviewed update")
        with self._locked():
            self._authorize()
            record = self._record(identifier)
            if record["status"] == "reviewing":
                job = self._job(record["job_id"])
                review = self._review_result(record, job) if job and job.get("status") == "completed" else None
                if not review:
                    raise WorkflowConflict("A current verified host update review is required", {})
                record.update(status="applying", job_id=secrets.token_hex(16),
                              review_id=review["review_id"], confirmation_nonce=review["confirmation_nonce"],
                              review=self._public_review(review))
                self._audit("apply_confirmed", record)
                _private_json(self.record_path, record)
            if record["status"] != "applying":
                raise WorkflowConflict("A current verified host update review is required", {})
            # The completed host review owns an independent, verified copy.
            # Keep the browser spool out of the stopped controller data backup.
            self._archive(identifier).unlink(missing_ok=True)
            self.client.submit({"action": "controller-update-apply", "request_id": record["job_id"],
                                "review_id": record["review_id"], "confirmation_nonce": record["confirmation_nonce"]})
            return self._public(record)

    def cancel(self, identifier):
        if not self.manager:
            raise KeyError("Unknown controller update")
        with self._locked():
            self._authorize()
            record = _read_json(self.record_path)
            if not record or record["id"] != identifier:
                raise KeyError("Unknown controller update")
            if not self._public(record)["can_cancel"]:
                raise WorkflowConflict("An active host update cannot be cancelled", {})
            self._audit("cancelled", record)
            self._remove(record)
        return {"cancelled": True}
