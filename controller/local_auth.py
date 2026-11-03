"""Local accounts, one-time bootstrap and version-bound password sessions.

Password work happens outside metadata transactions. Every completed login or
password operation rechecks its immutable credential version while holding the
database write fence, so a concurrent reset/disable cannot issue stale access.
"""
from __future__ import annotations

import base64
from datetime import timedelta
import hashlib
import hmac
import re
import secrets
import threading
import uuid

from .auth import (AuthConflict, AuthDenied, AuthUnavailable, ROLES, SESSION_COOKIE, SESSION_SECONDS,
                   _b64, _cookie, _email, _origin, _set_cookie, _sha, _text)
from .store import now, parse_time, stamp


REALM_ID = "local_auth_realm"
MAX_ATTEMPTS = 5
ATTEMPT_SECONDS = 15 * 60
CHANGE_SESSION_SECONDS = 10 * 60
PASSWORD_MIN = 12
PASSWORD_MAX = 256
USERNAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.@-]{0,63}")
SCRYPT_ALGORITHM = "scrypt-n16384-r8-p5-v1"
_KDF_SLOTS = threading.BoundedSemaphore(4)
LOGIN_ERROR = "Invalid username or password, or sign-in is temporarily unavailable"


def initialize(db):
    db.execute("CREATE TABLE IF NOT EXISTS auth_local_attempts (id TEXT PRIMARY KEY, data TEXT NOT NULL)")
    from .approval_views import _expression
    db.execute("CREATE INDEX IF NOT EXISTS local_attempt_expiry ON auth_local_attempts ((" + _expression(db, ("expires_at",)) + "))")
    db.execute("CREATE INDEX IF NOT EXISTS auth_session_user ON auth_sessions ((" + _expression(db, ("user_id",)) + "))")
    db.execute("CREATE INDEX IF NOT EXISTS auth_session_expiry ON auth_sessions ((" + _expression(db, ("expires_at",)) + "))")


def write_fence(db):
    """Match shared PostgreSQL's transaction fence on SQLite writers too."""
    if getattr(db, "dialect", "sqlite") == "sqlite" and not db.in_transaction:
        db.execute("BEGIN IMMEDIATE")


def public_user(value):
    result = {key: value.get(key) for key in (
        "id", "tenant_id", "object_id", "display_name", "email", "role", "enabled",
        "created_at", "updated_at", "last_login_at")}
    result["provider"] = value.get("provider", "entra")
    if result["provider"] == "local":
        result.update(username=value["username"], password_change_required=bool(value.get("password_change_required")),
                      protected_account=value.get("protected_account") is True)
    elif result["provider"] == "saml":
        result["subject"] = value.get("subject", "")
    return result


def username(value):
    if not isinstance(value, str) or not USERNAME.fullmatch(value):
        raise ValueError("Username must contain 1 to 64 ASCII letters, digits, dots, underscores, @ or hyphens and start with a letter or digit")
    return value.casefold()


def _password(value, *, new=False):
    if not isinstance(value, str) or not 1 <= len(value) <= PASSWORD_MAX:
        raise ValueError("Password must contain 12 to 256 characters without control characters")
    try:
        size = len(value.encode("utf-8"))
    except UnicodeError:
        raise ValueError("Password must contain valid Unicode characters") from None
    if (size > 1024 or any(ord(char) < 32 or ord(char) == 127 for char in value)):
        raise ValueError("Password must contain 12 to 256 characters without control characters")
    if new and len(value) < PASSWORD_MIN:
        raise ValueError("Password must contain 12 to 256 characters without control characters")
    return value


def _derive_password(value, salt):
    if not _KDF_SLOTS.acquire(blocking=False):
        raise AuthUnavailable("Password sign-in capacity is busy; try again shortly")
    try:
        return hashlib.scrypt(value.encode("utf-8"), salt=salt, n=16384, r=8, p=5, maxmem=64 * 1024 * 1024, dklen=32)
    except (ValueError, OSError):
        raise AuthUnavailable("Password hashing is unavailable on this controller") from None
    finally:
        _KDF_SLOTS.release()


def hash_password(value):
    salt = secrets.token_bytes(16)
    result = _derive_password(value, salt)
    return {"algorithm": SCRYPT_ALGORITHM, "salt": _b64(salt), "digest": _b64(result)}


def verify_password(value, encoded):
    # The database cannot select arbitrary scrypt resource parameters.
    if not isinstance(encoded, dict) or set(encoded) != {"algorithm", "salt", "digest"} or encoded.get("algorithm") != SCRYPT_ALGORITHM:
        return False
    try:
        if (not isinstance(encoded["salt"], str) or not isinstance(encoded["digest"], str)
                or not re.fullmatch(r"[A-Za-z0-9_-]{22}", encoded["salt"])
                or not re.fullmatch(r"[A-Za-z0-9_-]{43}", encoded["digest"])):
            return False
        salt = base64.urlsafe_b64decode(encoded["salt"] + "=" * (-len(encoded["salt"]) % 4))
        expected = base64.urlsafe_b64decode(encoded["digest"] + "=" * (-len(encoded["digest"]) % 4))
        if len(salt) != 16 or len(expected) != 32 or _b64(salt) != encoded["salt"] or _b64(expected) != encoded["digest"]:
            return False
        actual = _derive_password(value, salt)
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError, UnicodeError):
        return False


def local_fingerprint(store, db):
    value = store._get(db, "maintenance_settings", REALM_ID)
    if not value or value.get("bootstrap_done") is not True:
        raise AuthDenied("Local account authority is unavailable")
    try:
        realm = str(uuid.UUID(value["realm_id"]))
    except (KeyError, ValueError, TypeError, AttributeError):
        raise AuthDenied("Local account authority is unavailable") from None
    expected = _sha("prthak-local-password-v1\n" + realm)
    if value.get("realm_id") != realm or value.get("fingerprint") != expected:
        raise AuthDenied("Local account authority is unavailable")
    return realm, expected


def revoke_sessions(store, db, identifier):
    from .approval_views import _expression
    where = _expression(db, ("user_id",)) + "=?"
    count = db.execute("SELECT COUNT(*) FROM auth_sessions WHERE " + where, (identifier,)).fetchone()[0]
    db.execute("DELETE FROM auth_sessions WHERE " + where, (identifier,))
    return int(count)


def clear_attempts(store, db, canonical):
    key = _sha("prthak-local-login-rate-v1\n" + canonical)
    db.execute("DELETE FROM auth_local_attempts WHERE id=?", (key,))


class LocalAuth:
    def __init__(self, store, *, origin=None, bootstrap=True):
        self.store = store
        self.origin = self._origin(origin) if origin else None
        # Unknown accounts perform the same bounded password work.
        self._dummy = hash_password(secrets.token_urlsafe(32))
        with store.read_meta() as db:
            existing = store._get(db, "maintenance_settings", REALM_ID)
        initial_hash = hash_password("admin") if not existing and bootstrap else None
        with store.lock, store.meta() as db:
            initialize(db)
            write_fence(db)
            value = store._get(db, "maintenance_settings", REALM_ID)
            if value is None:
                realm = str(uuid.uuid4())
                # Any retained account, including a disabled account, means an
                # existing deployment. A new default credential is never added.
                empty = db.execute("SELECT 1 FROM auth_users LIMIT 1").fetchone() is None
                value = {"id": REALM_ID, "realm_id": realm,
                         "fingerprint": _sha("prthak-local-password-v1\n" + realm),
                         "bootstrap_done": True, "seeded": bool(empty and bootstrap), "created_at": stamp()}
                if empty and bootstrap:
                    user = self._new_user({"username": "admin", "role": "super_admin", "display_name": "Initial Super Admin"},
                                          realm, initial_hash)
                    value["bootstrap_user_id"] = user["id"]
                    user["protected_account"] = True
                    store._put(db, "auth_users", user)
                    store.audit("access.local.bootstrapped", "system:local-bootstrap",
                                {"user_id": user["id"], "after": public_user(user), "password_change_required": True}, db)
                store._put(db, "maintenance_settings", value)
            self.realm_id, self.fingerprint = local_fingerprint(store, db)
            # The original 0.15 bootstrap stored the durable seeded decision but
            # not its account ID. Its deterministic identity permits an in-place
            # backfill without creating credentials or matching a display name.
            protected_id = self.protected_identifier(db)
            if protected_id:
                if value.get("bootstrap_user_id") is None:
                    value["bootstrap_user_id"] = protected_id
                    store._put(db, "maintenance_settings", value)
                user = store._get(db, "auth_users", protected_id)
                if user and user.get("provider") == "local" and user.get("protected_account") is not True:
                    user["protected_account"] = True
                    store._put(db, "auth_users", user)

    def protected_identifier(self, db):
        """Return only the original seeded account's immutable local identity."""
        value = self.store._get(db, "maintenance_settings", REALM_ID)
        if not value or (value.get("seeded") is not True and "bootstrap_user_id" not in value):
            return None
        realm, _ = local_fingerprint(self.store, db)
        expected = realm + ":" + str(uuid.uuid5(uuid.UUID(realm), "admin"))
        if value.get("bootstrap_user_id", expected) != expected:
            raise AuthDenied("The built-in administrator identity is unavailable")
        return expected

    @staticmethod
    def _origin(value):
        from urllib.parse import urlsplit
        parsed = urlsplit(value)
        if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
                or parsed.path not in ("", "/") or parsed.query or parsed.fragment or "\\" in value
                or any(char.isspace() for char in value)):
            raise ValueError("Local account origin must be an HTTPS origin")
        return _origin(value)

    def check_origin(self, headers, *, origin=None):
        supplied = headers.get("Origin")
        if supplied is None:
            return
        try:
            expected = origin or self.origin or self._origin("https://" + headers.get("Host", ""))
        except ValueError:
            raise AuthDenied("Cross-origin sign-in or session mutation rejected") from None
        if supplied != expected:
            raise AuthDenied("Cross-origin sign-in or session mutation rejected")

    @staticmethod
    def _new_user(value, realm, encoded):
        canonical = username(value.get("username"))
        role = value.get("role")
        enabled = value.get("enabled", True)
        if role not in ROLES or not isinstance(enabled, bool):
            raise ValueError("Choose a valid role and enabled true or false")
        person = str(uuid.uuid5(uuid.UUID(realm), canonical))
        return {"id": realm + ":" + person, "tenant_id": realm, "object_id": person,
                "provider": "local", "username": canonical,
                "role": role, "enabled": enabled,
                "display_name": _text(value.get("display_name", ""), "Display name", 200),
                "email": _email(value.get("email", "")),
                "password_hash": encoded, "credential_version": secrets.token_hex(16),
                "password_change_required": True, "created_at": stamp(), "updated_at": stamp(), "last_login_at": None}

    def prepare_user(self, value):
        if not isinstance(value, dict) or set(value) - {"provider", "username", "password", "confirm_password", "display_name", "email", "role", "enabled"}:
            raise ValueError("Provide local username, temporary password, role and optional profile fields")
        secret = _password(value.get("password"), new=True)
        if "confirm_password" in value and value["confirm_password"] != secret:
            raise ValueError("Password confirmation does not match")
        # Validate cheap inputs before the expensive, transaction-free hash.
        self._new_user(value, self.realm_id, None)
        return self._new_user(value, self.realm_id, hash_password(secret))

    def _reserve_attempt(self, canonical):
        key = _sha("prthak-local-login-rate-v1\n" + canonical)
        reservation = secrets.token_hex(16)
        with self.store.lock, self.store.meta() as db:
            write_fence(db)
            at = now()
            value = self.store._get(db, "auth_local_attempts", key)
            if value and parse_time(value["expires_at"]) > at and value.get("attempts", 0) >= MAX_ATTEMPTS:
                raise AuthDenied(LOGIN_ERROR)
            if not value or parse_time(value["expires_at"]) <= at:
                # Limit cardinality, including invented usernames. No account
                # names or passwords are stored in the attempt ledger.
                from .approval_views import _expression
                db.execute("DELETE FROM auth_local_attempts WHERE " + _expression(db, ("expires_at",)) + "<=?", (stamp(at),))
                if db.execute("SELECT COUNT(*) FROM auth_local_attempts").fetchone()[0] >= 4096:
                    raise AuthDenied(LOGIN_ERROR)
                value = {"id": key, "attempts": 0, "expires_at": stamp(at + timedelta(seconds=ATTEMPT_SECONDS))}
            value.update(attempts=value.get("attempts", 0) + 1, reservation=reservation)
            self.store._put(db, "auth_local_attempts", value)
        return key, reservation

    def _success_attempt(self, db, attempt):
        key, reservation = attempt
        value = self.store._get(db, "auth_local_attempts", key)
        if value:
            if value.get("reservation") == reservation:
                db.execute("DELETE FROM auth_local_attempts WHERE id=?", (key,))
            else:
                # Do not clear failures reserved by concurrent requests.
                value["attempts"] = max(0, value.get("attempts", 0) - 1)
                self.store._put(db, "auth_local_attempts", value)

    def _issue(self, db, user):
        from .approval_views import _expression
        db.execute("DELETE FROM auth_sessions WHERE " + _expression(db, ("expires_at",)) + "<=?", (stamp(),))
        raw = secrets.token_urlsafe(32)
        seconds = CHANGE_SESSION_SECONDS if user.get("password_change_required") else SESSION_SECONDS
        session = {"id": _sha(raw), "provider": "local", "user_id": user["id"],
                   "created_at": stamp(), "expires_at": stamp(now() + timedelta(seconds=seconds)),
                   "config": self.fingerprint, "credential_version": user["credential_version"],
                   "password_change_required": bool(user.get("password_change_required"))}
        self.store._put(db, "auth_sessions", session)
        principal = self._principal(user, session, raw)
        return {"cookies": [_set_cookie(SESSION_COOKIE, raw, seconds)], "principal": principal}

    @staticmethod
    def _principal(user, session, raw):
        return {"role": user["role"], "actor": "local:" + user["id"], "auth_type": "session", "auth_provider": "local",
                "user": public_user(user), "password_change_required": bool(user.get("password_change_required") or session.get("password_change_required")),
                "csrf_token": _b64(hmac.new(raw.encode(), b"prthak-csrf-v1", hashlib.sha256).digest()), "_session_id": session["id"]}

    def login(self, value, headers):
        self.check_origin(headers)
        if not isinstance(value, dict) or set(value) != {"username", "password"}:
            raise AuthDenied(LOGIN_ERROR)
        try:
            canonical = username(value.get("username"))
            secret = _password(value.get("password"))
        except (ValueError, UnicodeError):
            raise AuthDenied(LOGIN_ERROR) from None
        attempt = self._reserve_attempt(canonical)
        identifier = self.realm_id + ":" + str(uuid.uuid5(uuid.UUID(self.realm_id), canonical))
        with self.store.read_meta() as db:
            snapshot = self.store._get(db, "auth_users", identifier)
        encoded = snapshot.get("password_hash") if snapshot and snapshot.get("provider") == "local" else self._dummy
        valid = verify_password(secret, encoded)
        result = None
        with self.store.lock, self.store.meta() as db:
            write_fence(db)
            realm, fingerprint = local_fingerprint(self.store, db)
            current = self.store._get(db, "auth_users", identifier)
            if (valid and snapshot and current and current.get("provider") == "local"
                    and current.get("enabled") is True and current.get("role") in ROLES
                    and current.get("username") == canonical and current.get("tenant_id") == realm
                    and fingerprint == self.fingerprint and current.get("password_hash") == snapshot.get("password_hash")
                    and current.get("credential_version") == snapshot.get("credential_version")):
                current["last_login_at"] = stamp()
                self.store._put(db, "auth_users", current)
                self._success_attempt(db, attempt)
                result = self._issue(db, current)
                self.store.audit("auth.local.login.succeeded", "local:" + identifier,
                                 {"user_id": identifier, "role": current["role"], "password_change_required": current["password_change_required"]}, db)
            else:
                self.store.audit("auth.local.login.denied", "local:sign-in", {"reason": "Credentials unavailable or invalid"}, db)
        if result is None:
            raise AuthDenied(LOGIN_ERROR)
        return result

    def authenticate(self, headers):
        raw = _cookie(headers, SESSION_COOKIE)
        if not raw:
            return None
        with self.store.read_meta() as db:
            session = self.store._get(db, "auth_sessions", _sha(raw))
            if not session or session.get("provider") != "local":
                return None
            realm, fingerprint = local_fingerprint(self.store, db)
            if (session.get("config") != fingerprint or parse_time(session["expires_at"]) <= now()):
                return None
            user = self.store._get(db, "auth_users", session.get("user_id", ""))
            if (not user or user.get("provider") != "local" or user.get("tenant_id") != realm
                    or user.get("enabled") is not True or user.get("role") not in ROLES
                    or user.get("credential_version") != session.get("credential_version")):
                return None
            expected = realm + ":" + str(uuid.uuid5(uuid.UUID(realm), username(user.get("username"))))
            if user.get("id") != expected:
                return None
            return self._principal(user, session, raw)

    def require_csrf(self, headers, principal, *, origin=None):
        supplied = headers.get("X-CSRF-Token", "")
        if (not isinstance(supplied, str) or not supplied or not principal.get("csrf_token")
                or not hmac.compare_digest(supplied, principal["csrf_token"])):
            raise AuthDenied("A valid session CSRF token is required")
        self.check_origin(headers, origin=origin)

    def change_password(self, value, principal, headers):
        from .authentication import validate_current_principal
        self.require_csrf(headers, principal)
        if not isinstance(value, dict) or set(value) - {"current_password", "new_password", "confirm_password"}:
            raise ValueError("Provide the current password, a new password and its confirmation")
        old, new = _password(value.get("current_password")), _password(value.get("new_password"), new=True)
        if old == new:
            raise ValueError("Choose a different password")
        if "confirm_password" in value and value["confirm_password"] != new:
            raise ValueError("Password confirmation does not match")
        with self.store.read_meta() as db:
            snapshot = validate_current_principal(self.store, db, principal, allow_password_change=True)
        if snapshot.get("provider") != "local":
            raise AuthDenied("Directory passwords are managed by the identity provider")
        attempt = self._reserve_attempt(snapshot["username"])
        valid = verify_password(old, snapshot.get("password_hash"))
        if not valid:
            with self.store.lock, self.store.meta() as db:
                self.store.audit("access.local.password_change.denied", principal["actor"], {"user_id": snapshot["id"]}, db)
            raise AuthDenied("Current password did not match")
        encoded = hash_password(new)
        with self.store.lock, self.store.meta() as db:
            write_fence(db)
            current = validate_current_principal(self.store, db, principal, allow_password_change=True)
            if current.get("credential_version") != snapshot.get("credential_version") or current.get("password_hash") != snapshot.get("password_hash"):
                raise AuthDenied("The account changed; sign in again before changing its password")
            current.update(password_hash=encoded, credential_version=secrets.token_hex(16), password_change_required=False, updated_at=stamp())
            revoked = revoke_sessions(self.store, db, current["id"])
            self.store._put(db, "auth_users", current)
            self._success_attempt(db, attempt)
            result = self._issue(db, current)
            self.store.audit("access.local.password_changed", principal["actor"],
                             {"user_id": current["id"], "revoked_sessions": revoked, "password_change_required": False}, db)
            return result
