"""Single-tenant Microsoft Entra sign-in and application-owned user authority.

Entra authenticates an immutable tenant/object identity. Only an existing,
enabled application user grants access; directory groups, email and app-role
claims never create users or grant Prṛthak privileges.
"""
from __future__ import annotations

import base64
import copy
from dataclasses import dataclass, field
from datetime import timedelta
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import re
import secrets
import stat
import threading
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener
import uuid

from .store import now, parse_time, stamp


ROLES = ("read_only", "admin", "super_admin")
SESSION_SECONDS = 8 * 3600
STATE_SECONDS = 10 * 60
SESSION_COOKIE = "__Host-prthak-session"
STATE_COOKIE = "__Host-prthak-oidc"
MICROSOFT_HOST = "https://login.microsoftonline.com"
TOKEN_PATTERN = re.compile(r"[A-Za-z0-9_-]{43,128}")


class AuthUnavailable(RuntimeError):
    """Public-safe sign-in dependency/configuration error."""


class AuthDenied(PermissionError):
    """Invalid sign-in or unauthorized application identity."""


class AuthConflict(ValueError):
    """A user-management operation conflicts with existing authority."""


def initialize(db):
    for table in ("auth_users", "auth_sessions", "auth_states"):
        db.execute(f"CREATE TABLE IF NOT EXISTS {table} (id TEXT PRIMARY KEY, data TEXT NOT NULL)")


def _guid(value, label):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", value):
        raise ValueError(f"{label} must be a UUID")
    return str(uuid.UUID(value))


def _sha(value):
    return hashlib.sha256(value.encode()).hexdigest()


def _b64(value):
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def _origin(value):
    parsed = urlsplit(value)
    hostname = parsed.hostname
    if not hostname:
        raise ValueError("A valid HTTPS application origin is required")
    try:
        port = parsed.port
    except ValueError:
        raise ValueError("A valid HTTPS application port is required") from None
    host = "[" + hostname.lower() + "]" if ":" in hostname else hostname.lower()
    return f"{parsed.scheme.lower()}://{host}" + (f":{port}" if port and port != 443 else "")


@dataclass(frozen=True)
class EntraConfig:
    tenant_id: str = ""
    client_id: str = ""
    redirect_uri: str = ""
    client_secret: str = field(default="", repr=False)
    bootstrap_oid: str = ""

    def __post_init__(self):
        present = (self.tenant_id, self.client_id, self.redirect_uri, self.client_secret)
        if not any(present):
            if self.bootstrap_oid:
                raise ValueError("Configure Entra tenant, client, redirect URI and client secret before bootstrap")
            return
        if not all(present):
            raise ValueError("Entra requires tenant ID, client ID, HTTPS redirect URI and client secret")
        object.__setattr__(self, "tenant_id", _guid(self.tenant_id, "Entra tenant ID"))
        object.__setattr__(self, "client_id", _guid(self.client_id, "Entra client ID"))
        if not isinstance(self.client_secret, str) or len(self.client_secret) > 16384 or not self.client_secret.strip():
            raise ValueError("Invalid Entra client secret configuration")
        parsed = urlsplit(self.redirect_uri)
        if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
                or parsed.query or parsed.fragment or parsed.path != "/api/v1/auth/callback"
                or any(char.isspace() for char in self.redirect_uri) or "\\" in self.redirect_uri):
            raise ValueError("Entra redirect URI must be https://<application-host>/api/v1/auth/callback")
        _origin(self.redirect_uri)
        if self.bootstrap_oid:
            object.__setattr__(self, "bootstrap_oid", _guid(self.bootstrap_oid, "Bootstrap Super Admin object ID"))

    @property
    def enabled(self):
        return bool(self.tenant_id)

    @property
    def issuer(self):
        return f"{MICROSOFT_HOST}/{self.tenant_id}/v2.0"

    @property
    def origin(self):
        return _origin(self.redirect_uri)

    @property
    def fingerprint(self):
        return _sha("\n".join((self.tenant_id, self.client_id, self.redirect_uri)))

    @classmethod
    def from_env(cls, environ=None):
        env = os.environ if environ is None else environ
        secret = env.get("SEG_ENTRA_CLIENT_SECRET", "")
        secret_file = env.get("SEG_ENTRA_CLIENT_SECRET_FILE", "")
        if secret and secret_file:
            raise ValueError("Configure Entra client secret by file or environment, not both")
        if secret_file:
            try:
                path = Path(secret_file)
                info = path.stat()
                if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_size > 16384:
                    raise ValueError("Entra client secret file must be a private regular file (mode 0600 or stricter)")
                secret = path.read_text().strip()
            except (OSError, UnicodeError):
                raise ValueError("Entra client secret file could not be read") from None
        return cls(env.get("SEG_ENTRA_TENANT_ID", ""), env.get("SEG_ENTRA_CLIENT_ID", ""),
                   env.get("SEG_ENTRA_REDIRECT_URI", ""), secret,
                   env.get("SEG_BOOTSTRAP_SUPER_ADMIN_OID", ""))


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class MicrosoftProvider:
    """Bounded HTTPS OIDC transport with fixed tenant/host and verified JWTs."""

    def __init__(self, config):
        self.config = config
        try:
            import jwt
            from jwt.algorithms import RSAAlgorithm  # noqa: F401
            version=re.fullmatch(r"(\d+)\.(\d+)\.(\d+)",str(getattr(jwt,"__version__","")))
            if not version or int(version[1])!=2 or int(version[2])<10:
                raise ImportError()
            if "RS256" not in jwt.algorithms.get_default_algorithms():
                raise ImportError()
        except ImportError:
            raise AuthUnavailable("Entra sign-in requires PyJWT >=2.10,<3 with cryptography; install controller/requirements.txt") from None
        self.jwt = jwt
        self._opener = build_opener(_NoRedirect())
        self._lock = threading.RLock()
        self._metadata = None
        self._keys = None
        self._keys_at = 0.0
        self._metadata_at = 0.0
        self._unknown_refresh_at = 0.0

    def _json(self, url, data=None, maximum=1024 * 1024):
        # All callers select one of the explicitly checked Microsoft URLs.
        request = Request(url, data=data, headers={"Accept": "application/json", **(
            {"Content-Type": "application/x-www-form-urlencoded"} if data is not None else {})})
        try:
            with self._opener.open(request, timeout=8) as response:
                if response.status != 200:
                    raise AuthUnavailable("Microsoft Entra sign-in is unavailable; start sign-in again")
                content = response.read(maximum + 1)
                if len(content) > maximum:
                    raise AuthUnavailable("Microsoft Entra returned an oversized response")
                result = json.loads(content)
                if not isinstance(result, dict):
                    raise ValueError()
                return result
        except HTTPError as error:
            # Never return error_description, token response bodies or codes.
            if data is not None and error.code in (400, 401, 403):
                raise AuthDenied("Microsoft Entra did not accept this sign-in; start sign-in again") from None
            raise AuthUnavailable("Microsoft Entra sign-in is unavailable; start sign-in again") from None
        except (URLError, OSError, ValueError, UnicodeError):
            raise AuthUnavailable("Microsoft Entra sign-in is unavailable; start sign-in again") from None

    def metadata(self):
        with self._lock:
            if self._metadata is not None and time.monotonic() - self._metadata_at < 3600:
                return self._metadata
            base = f"{MICROSOFT_HOST}/{self.config.tenant_id}"
            result = self._json(base + "/v2.0/.well-known/openid-configuration")
            expected = {"issuer": self.config.issuer, "authorization_endpoint": base + "/oauth2/v2.0/authorize",
                        "token_endpoint": base + "/oauth2/v2.0/token"}
            if any(result.get(key) != value for key, value in expected.items()):
                raise AuthUnavailable("Microsoft Entra discovery did not match the configured tenant")
            allowed_keys = (base + "/discovery/v2.0/keys", MICROSOFT_HOST + "/common/discovery/v2.0/keys")
            if result.get("jwks_uri") not in allowed_keys:
                raise AuthUnavailable("Microsoft Entra signing-key location was not approved")
            self._metadata, self._metadata_at = result, time.monotonic()
            return result

    def authorization_url(self, state, nonce, challenge):
        return self.metadata()["authorization_endpoint"] + "?" + urlencode({
            "client_id": self.config.client_id, "response_type": "code", "response_mode": "query",
            "redirect_uri": self.config.redirect_uri, "scope": "openid profile email",
            "state": state, "nonce": nonce, "code_challenge": challenge, "code_challenge_method": "S256"})

    def exchange(self, code, verifier):
        body = urlencode({"client_id": self.config.client_id, "client_secret": self.config.client_secret,
                          "grant_type": "authorization_code", "code": code, "code_verifier": verifier,
                          "redirect_uri": self.config.redirect_uri, "scope": "openid profile email"}).encode()
        result = self._json(self.metadata()["token_endpoint"], body, maximum=128 * 1024)
        token = result.get("id_token")
        if not isinstance(token, str) or len(token) > 32768:
            raise AuthDenied("Microsoft Entra did not return a valid ID token")
        return token

    def _load_keys(self, force=False):
        with self._lock:
            if not force and self._keys is not None and time.monotonic() - self._keys_at < 3600:
                return self._keys
            result = self._json(self.metadata()["jwks_uri"])
            keys = result.get("keys")
            if not isinstance(keys, list) or not 1 <= len(keys) <= 100:
                raise AuthUnavailable("Microsoft Entra signing keys are unavailable")
            self._keys, self._keys_at = keys, time.monotonic()
            return keys

    def verify(self, token):
        try:
            header = self.jwt.get_unverified_header(token)
            kid = header.get("kid")
            if (header.get("alg") != "RS256" or not isinstance(kid, str) or not kid
                    or len(kid) > 200 or header.get("crit") or header.get("jku") or header.get("x5u")):
                raise AuthDenied("Invalid Microsoft Entra ID token")
            keys = self._load_keys()
            matching = [key for key in keys if isinstance(key, dict) and key.get("kid") == kid]
            if not matching:
                with self._lock:
                    if time.monotonic() - self._unknown_refresh_at >= 30:
                        self._unknown_refresh_at = time.monotonic()
                        keys = self._load_keys(force=True)
                matching = [key for key in keys if isinstance(key, dict) and key.get("kid") == kid]
            if len(matching) != 1:
                raise AuthDenied("Invalid Microsoft Entra signing key")
            key = matching[0]
            if key.get("kty") != "RSA" or key.get("use", "sig") != "sig" or key.get("alg", "RS256") != "RS256":
                raise AuthDenied("Invalid Microsoft Entra signing key")
            public_key = self.jwt.PyJWK.from_dict(key, algorithm="RS256").key
            claims = self.jwt.decode(token, public_key, algorithms=["RS256"], issuer=self.config.issuer,
                audience=self.config.client_id, leeway=30,
                options={"require": ["exp", "iat", "iss", "aud", "sub", "nonce", "tid", "oid"],
                         "verify_signature": True, "strict_aud": True})
            # PyJWT intentionally accepts some numeric strings and booleans.
            # OIDC NumericDate claims must actually be finite JSON numbers.
            for field_name in ("exp", "iat", "nbf"):
                if field_name in claims:
                    value = claims[field_name]
                    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
                        raise AuthDenied("Invalid Microsoft Entra token timestamp")
            if claims["exp"] <= claims["iat"]:
                raise AuthDenied("Invalid Microsoft Entra token lifetime")
            return claims
        except AuthDenied:
            raise
        except (self.jwt.PyJWTError, ValueError, TypeError, KeyError, OverflowError):
            raise AuthDenied("Invalid or expired Microsoft Entra ID token") from None


def _cookie(headers, name):
    value = headers.get("Cookie", "")
    if not isinstance(value, str) or len(value) > 16384:
        return None
    values = [part.strip().split("=", 1)[1] for part in value.split(";")
              if part.strip().split("=", 1)[0] == name and "=" in part]
    if len(values) != 1 or not TOKEN_PATTERN.fullmatch(values[0]):
        return None
    return values[0]


def _set_cookie(name, value="", seconds=0):
    return f"{name}={value}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={seconds}"


def _public_user(value):
    return {key: value.get(key) for key in ("id", "tenant_id", "object_id", "display_name", "email", "role", "enabled",
                                          "created_at", "updated_at", "last_login_at")}


class EntraAuth:
    def __init__(self, store, config=None, provider=None, *, purpose="login"):
        self.store = store
        self.config = config if config is not None else EntraConfig.from_env()
        self.provider = provider if provider is not None else (MicrosoftProvider(self.config) if self.config.enabled else None)
        self.purpose = purpose

    @property
    def enabled(self):
        return self.config.enabled

    def status(self):
        return {"mode": "entra" if self.enabled else "tokens", "configured": self.enabled,
                "login_url": "/api/v1/auth/login" if self.enabled else None,
                "tenant_id": self.config.tenant_id or None, "client_id": self.config.client_id or None,
                "redirect_uri": self.config.redirect_uri or None,
                "roles": list(ROLES), "session_seconds": SESSION_SECONDS}

    def _configured(self):
        if not self.enabled or self.provider is None:
            raise AuthUnavailable("Configure Microsoft Entra ID before directory sign-in or user provisioning")

    def _prune(self, db):
        current = now()
        for table in ("auth_states", "auth_sessions"):
            for value in self.store._all(db, table):
                if parse_time(value["expires_at"]) <= current:
                    db.execute(f"DELETE FROM {table} WHERE id=?", (value["id"],))

    def begin_login(self, headers):
        self._configured()
        if self.purpose == "login":
            with self.store.read_meta() as db:
                from .provider_lifecycle import assert_auth_current
                assert_auth_current(self, db)
            if headers.get("Host") and _origin("https://" + headers["Host"]) != self.config.origin:
                # Start on the reviewed canonical origin so its host-only
                # browser binding can return to the configured callback.
                return {"location": self.config.origin + "/api/v1/auth/login", "cookies": []}
        state, nonce, verifier, binding = [secrets.token_urlsafe(32) for _ in range(4)]
        # Validate discovery before persisting a state/cookie that cannot be used.
        location = self.provider.authorization_url(state, nonce, _b64(hashlib.sha256(verifier.encode()).digest()))
        with self.store.lock, self.store.meta() as db:
            self._prune(db)
            if len(self.store._all(db, "auth_states")) >= 4096:
                raise AuthUnavailable("Too many pending sign-ins; try again later")
            self.store._put(db, "auth_states", {"id": _sha(state), "nonce_hash": _sha(nonce), "verifier": verifier,
                "binding_hash": _sha(binding), "config": self.config.fingerprint, "purpose": self.purpose, "created_at": stamp(),
                "expires_at": stamp(now() + timedelta(seconds=STATE_SECONDS)), "consumed": False})
        return {"location": location, "cookies": [_set_cookie(STATE_COOKIE, binding, STATE_SECONDS)]}

    def _consume_state(self, query, headers):
        # parse_qs returns lists; reject duplicate protocol parameters explicitly.
        if not isinstance(query, dict):
            raise AuthDenied("Invalid sign-in callback")
        for key in ("state", "code", "error"):
            if key in query and (not isinstance(query[key], list) or len(query[key]) != 1 or not isinstance(query[key][0], str)):
                raise AuthDenied("Invalid sign-in callback")
        state = (query.get("state") or [None])[0]
        binding = _cookie(headers, STATE_COOKIE)
        if not isinstance(state, str) or not TOKEN_PATTERN.fullmatch(state) or not binding:
            raise AuthDenied("Sign-in state or browser binding is missing; start sign-in again")
        with self.store.lock, self.store.meta() as db:
            value = self.store._get(db, "auth_states", _sha(state))
            if (not value or value.get("consumed") or parse_time(value["expires_at"]) <= now()
                    or value.get("purpose", "login") != self.purpose
                    or value.get("config") != self.config.fingerprint
                    or not hmac.compare_digest(value["binding_hash"], _sha(binding))):
                raise AuthDenied("Sign-in is expired, already used or belongs to another browser; start again")
            result = copy.deepcopy(value)
            value.update({"consumed": True, "consumed_at": stamp()})
            value.pop("verifier", None)
            self.store._put(db, "auth_states", value)
            return result

    def verify_callback_identity(self, query, headers):
        """Verify one bound OIDC response without provisioning users or sessions."""
        self._configured()
        state = self._consume_state(query, headers)
        if query.get("error"):
            raise AuthDenied("Microsoft Entra sign-in was cancelled or denied")
        code = (query.get("code") or [None])[0]
        if not isinstance(code, str) or not code or len(code) > 16384:
            raise AuthDenied("Microsoft Entra authorization code is missing")
        claims = self.provider.verify(self.provider.exchange(code, state["verifier"]))
        if not isinstance(claims, dict):
            raise AuthDenied("Invalid Microsoft Entra identity")
        try:
            tenant = _guid(claims.get("tid"), "Token tenant ID")
            object_id = _guid(claims.get("oid"), "Token object ID")
        except ValueError:
            raise AuthDenied("Invalid Microsoft Entra identity") from None
        nonce = claims.get("nonce")
        if (tenant != self.config.tenant_id or not isinstance(nonce, str)
                or not hmac.compare_digest(_sha(nonce), state["nonce_hash"])):
            raise AuthDenied("Microsoft Entra tenant or sign-in nonce did not match")
        identifier = tenant + ":" + object_id
        return claims, identifier

    def callback(self, query, headers):
        claims, identifier = self.verify_callback_identity(query, headers)
        object_id = claims["oid"].lower()
        raw_session = secrets.token_urlsafe(32)
        with self.store.lock, self.store.meta() as db:
            from .provider_lifecycle import assert_auth_current
            assert_auth_current(self, db)
            self._prune(db)
            user = self.store._get(db, "auth_users", identifier)
            if (user is None and object_id == self.config.bootstrap_oid
                    and not any(value.get("provider", "entra") == "entra" for value in self.store._all(db, "auth_users"))):
                user = self._user({"object_id": object_id, "role": "super_admin"})
                user["display_name"] = _claim_text(claims.get("name"), 200) or "Initial Super Admin"
                user["email"] = _claim_email(claims)
                self.store._put(db, "auth_users", user)
                self.store.audit("access.user.bootstrapped", "entra:" + identifier,
                                 {"user_id": identifier, "after": _public_user(user)}, db)
            if user is None or not user.get("enabled") or user.get("role") not in ROLES:
                self.store.audit("auth.login.denied", "entra:" + identifier,
                                 {"reason": "Application access is not provisioned or is disabled"}, db)
                # Commit the audit while rejecting sign-in outside the transaction.
                user = None
            else:
                if not user.get("display_name"):
                    user["display_name"] = _claim_text(claims.get("name"), 200)
                if not user.get("email"):
                    user["email"] = _claim_email(claims)
                user["last_login_at"] = stamp()
                self.store._put(db, "auth_users", user)
                self.store._put(db, "auth_sessions", {"id": _sha(raw_session), "user_id": identifier,
                    "created_at": stamp(), "expires_at": stamp(now() + timedelta(seconds=SESSION_SECONDS)),
                    "config": self.config.fingerprint})
                self.store.audit("auth.login.succeeded", "entra:" + identifier,
                                 {"user_id": identifier, "role": user["role"], "display_name": user["display_name"]}, db)
        if user is None:
            raise AuthDenied("Your Microsoft identity has no enabled Prṛthak account; contact a Super Admin")
        principal = self.authenticate({"Cookie": SESSION_COOKIE + "=" + raw_session})
        return {"location": "/overview", "cookies": [_set_cookie(STATE_COOKIE),
                _set_cookie(SESSION_COOKIE, raw_session, SESSION_SECONDS)], "principal": principal}

    def authenticate(self, headers):
        if not self.enabled:
            return None
        raw = _cookie(headers, SESSION_COOKIE)
        if raw is None:
            return None
        with self.store.read_meta() as db:
            from .provider_lifecycle import assert_auth_current
            assert_auth_current(self, db)
            session = self.store._get(db, "auth_sessions", _sha(raw))
            if (session is None or parse_time(session["expires_at"]) <= now()
                    or session.get("config") != self.config.fingerprint):
                return None
            user = self.store._get(db, "auth_users", session["user_id"])
            if (user is None or not user.get("enabled") or user.get("role") not in ROLES
                    or user.get("tenant_id") != self.config.tenant_id):
                return None
        csrf = _b64(hmac.new(raw.encode(), b"prthak-csrf-v1", hashlib.sha256).digest())
        return {"role": user["role"], "actor": "entra:" + user["id"], "auth_type": "session",
                "user": _public_user(user), "csrf_token": csrf, "_session_id": session["id"]}

    def require_csrf(self, headers, principal):
        if principal is None or principal.get("auth_type") != "session":
            return
        supplied = headers.get("X-CSRF-Token", "")
        expected = principal.get("csrf_token", "")
        if not isinstance(supplied, str) or not supplied or not hmac.compare_digest(supplied, expected):
            raise AuthDenied("A valid session CSRF token is required")
        origin = headers.get("Origin")
        if origin and origin != self.config.origin:
            raise AuthDenied("Cross-origin session mutation rejected")

    def logout(self, headers):
        principal = self.authenticate(headers)
        if principal:
            self.require_csrf(headers, principal)
            with self.store.lock, self.store.meta() as db:
                db.execute("DELETE FROM auth_sessions WHERE id=?", (principal["_session_id"],))
                self.store.audit("auth.logout", principal["actor"], {"user_id": principal["user"]["id"]}, db)
        return {"cookies": [_set_cookie(SESSION_COOKIE), _set_cookie(STATE_COOKIE)]}

    def _require_super(self, principal, db):
        from .provider_lifecycle import assert_auth_current
        assert_auth_current(self, db)
        if not isinstance(principal, dict) or principal.get("role") != "super_admin":
            raise AuthDenied("Super Admin role required to manage users")
        if principal.get("auth_type") == "session":
            identifier = (principal.get("user") or {}).get("id")
            user = self.store._get(db, "auth_users", identifier or "")
            session = self.store._get(db, "auth_sessions", principal.get("_session_id", ""))
            if (not user or not user.get("enabled") or user.get("role") != "super_admin" or not session
                    or user.get("tenant_id") != self.config.tenant_id or session.get("config") != self.config.fingerprint
                    or session.get("user_id") != identifier or parse_time(session["expires_at"]) <= now()):
                raise AuthDenied("Your Super Admin session is no longer authorized")

    def list_users(self, principal):
        with self.store.read_meta() as db:
            self._require_super(principal, db)
            users = self.store._all(db, "auth_users")
            return {"items": sorted((_public_user(user) for user in users),
                                    key=lambda user: (user.get("display_name") or user.get("email") or user["object_id"]).casefold())}

    def _user(self, value):
        self._configured()
        if not isinstance(value, dict) or set(value) - {"object_id", "display_name", "email", "role", "enabled"}:
            raise ValueError("Provide object_id, role and optional display_name/email/enabled")
        object_id = _guid(value.get("object_id"), "Entra user object ID")
        if value.get("role") not in ROLES:
            raise ValueError("Role must be read_only, admin or super_admin")
        enabled = value.get("enabled", True)
        if not isinstance(enabled, bool):
            raise ValueError("enabled must be true or false")
        return {"id": self.config.tenant_id + ":" + object_id, "tenant_id": self.config.tenant_id,
                "object_id": object_id, "role": value["role"], "enabled": enabled,
                "display_name": _text(value.get("display_name", ""), "Display name", 200),
                "email": _email(value.get("email", "")), "created_at": stamp(), "updated_at": stamp(),
                "last_login_at": None}

    def create_user(self, value, principal):
        with self.store.lock, self.store.meta() as db:
            self._require_super(principal, db)
            user = self._user(value)
            if self.store._get(db, "auth_users", user["id"]) is not None:
                raise AuthConflict("This Entra user already has a Prṛthak access record")
            self.store._put(db, "auth_users", user)
            self.store.audit("access.user.created", principal["actor"], {"user_id": user["id"], "before": None,
                             "after": _public_user(user)}, db)
            return _public_user(user)

    def update_user(self, identifier, value, principal):
        if not isinstance(value, dict) or not value or set(value) - {"role", "enabled", "display_name", "email"}:
            raise ValueError("Only role, enabled, display_name and email can be changed")
        with self.store.lock, self.store.meta() as db:
            self._require_super(principal, db)
            user = self.store._get(db, "auth_users", identifier)
            if user is None:
                raise KeyError(identifier)
            if user.get("tenant_id") != self.config.tenant_id:
                raise AuthDenied("This user does not belong to the configured Entra tenant")
            before = _public_user(user)
            edited = self._user({**{key: user[key] for key in ("object_id", "role", "enabled", "display_name", "email")}, **value})
            if identifier == (principal.get("user") or {}).get("id") and (
                    edited["role"] != user["role"] or edited["enabled"] != user["enabled"]):
                raise AuthConflict("A Super Admin cannot change their own role or disable their own account")
            if user["enabled"] and user["role"] == "super_admin" and (
                    not edited["enabled"] or edited["role"] != "super_admin"):
                remaining = [other for other in self.store._all(db, "auth_users")
                             if other["id"] != identifier and other.get("enabled") and other.get("role") == "super_admin"
                             and other.get("tenant_id") == self.config.tenant_id]
                if not remaining:
                    raise AuthConflict("Keep at least one enabled Super Admin")
            user.update({key: edited[key] for key in ("role", "enabled", "display_name", "email")})
            user["updated_at"] = stamp()
            self.store._put(db, "auth_users", user)
            authority_changed = user["role"] != before["role"] or user["enabled"] != before["enabled"]
            revoked = self._revoke(db, identifier) if authority_changed else 0
            self.store.audit("access.user.updated", principal["actor"], {"user_id": identifier, "before": before,
                             "after": _public_user(user), "revoked_sessions": revoked}, db)
            return {**_public_user(user), "revoked_sessions": revoked}

    def _revoke(self, db, identifier):
        sessions = [session for session in self.store._all(db, "auth_sessions") if session["user_id"] == identifier]
        for session in sessions:
            db.execute("DELETE FROM auth_sessions WHERE id=?", (session["id"],))
        return len(sessions)

    def revoke_sessions(self, identifier, principal):
        with self.store.lock, self.store.meta() as db:
            self._require_super(principal, db)
            user = self.store._get(db, "auth_users", identifier)
            if user is None:
                raise KeyError(identifier)
            if user.get("tenant_id") != self.config.tenant_id:
                raise AuthDenied("This user does not belong to the configured Entra tenant")
            revoked = self._revoke(db, identifier)
            self.store.audit("access.user.sessions_revoked", principal["actor"],
                             {"user_id": identifier, "revoked_sessions": revoked}, db)
            return {"user_id": identifier, "revoked_sessions": revoked}


def _text(value, label, maximum):
    if not isinstance(value, str) or len(value) > maximum or any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError(f"{label} must be text of at most {maximum} characters without control characters")
    return value.strip()


def _email(value):
    result = _text(value, "Email", 254)
    if result and not re.fullmatch(r"[^\s@]+@[^\s@]+", result):
        raise ValueError("Email must be a valid address or blank; authentication uses the Entra object ID")
    return result.casefold()


def _claim_text(value, maximum):
    try:
        return _text(value, "Directory display metadata", maximum)
    except ValueError:
        return ""


def _claim_email(claims):
    try:
        return _email(claims.get("email") or claims.get("preferred_username") or "")
    except ValueError:
        return ""
