"""SP-initiated SAML 2.0 sign-in with application-owned user roles.

The SAML toolkit validates XML schema, signatures and protocol semantics. The
application additionally requires exact endpoint bindings and short bounded
assertions; a valid IdP assertion never provisions or promotes an app user.
Only uploaded metadata supplies trust. This module never fetches IdP URLs.
"""
from __future__ import annotations

import base64
import copy
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import re
import secrets
from urllib.parse import urlsplit
import uuid

from .auth import (AuthDenied, AuthUnavailable, ROLES, SESSION_COOKIE,
                   SESSION_SECONDS, STATE_SECONDS, TOKEN_PATTERN, _b64,
                   _cookie, _email, _origin, _set_cookie, _sha, _text)
from .store import digest, now, parse_time, stamp

STATE_COOKIE = "__Host-prthak-saml"
CONFIG_ID = "saml_configuration"
MAX_METADATA_BYTES = 512 * 1024
MAX_RESPONSE_BYTES = 1024 * 1024
# Entra's normal SAML assertions can last about an hour. The one-use browser
# request is still only ten minutes; this cap also bounds the replay cache.
MAX_ASSERTION_SECONDS = 2 * 3600
NS = {"md": "urn:oasis:names:tc:SAML:2.0:metadata",
      "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
      "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
      "ds": "http://www.w3.org/2000/09/xmldsig#"}


def _runtime():
    """Keep local/OIDC access usable when optional SAML is unconfigured."""
    try:
        from importlib.metadata import version
        from onelogin.saml2.auth import OneLogin_Saml2_Auth
        from onelogin.saml2.idp_metadata_parser import OneLogin_Saml2_IdPMetadataParser
        from onelogin.saml2.response import OneLogin_Saml2_Response
        from onelogin.saml2.settings import OneLogin_Saml2_Settings
        from onelogin.saml2.xml_utils import OneLogin_Saml2_XML
        import xmlsec
        for name, floor in (("python3-saml", (1, 16, 0)), ("xmlsec", (1, 3, 18)), ("lxml", (6, 1, 3))):
            found = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)", version(name))
            if not found or tuple(map(int, found.groups())) < floor:
                raise ImportError()
        # Loading xmlsec here also fails closed on incompatible libxml builds.
        if not xmlsec.__version__:
            raise ImportError()
        return OneLogin_Saml2_Auth, OneLogin_Saml2_IdPMetadataParser, OneLogin_Saml2_Response, OneLogin_Saml2_Settings, OneLogin_Saml2_XML
    except Exception:
        raise AuthUnavailable("SAML sign-in requires the current controller SAML/XML dependencies; install controller/requirements.txt") from None


def _https_url(value, label, *, origin=False):
    if not isinstance(value, str) or not value or len(value) > 2048 or any(c.isspace() for c in value) or "\\" in value:
        raise ValueError(f"{label} must be an HTTPS URL")
    try:
        parsed = urlsplit(value)
        parsed.port
        if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
                or parsed.fragment or (origin and (parsed.path not in ("", "/") or parsed.query))):
            raise ValueError()
        return _origin(value) if origin else value
    except ValueError:
        raise ValueError(f"{label} must be an HTTPS {'origin' if origin else 'URL'} without credentials or fragments") from None


def _entity(value, label):
    if (not isinstance(value, str) or not 1 <= len(value) <= 2048 or not urlsplit(value).scheme
            or any(ord(c) <= 32 or ord(c) == 127 for c in value) or "\\" in value):
        raise ValueError(f"{label} must be a nonempty URI of at most 2048 characters")
    return value


def _xml(value, maximum):
    if not isinstance(value, (str, bytes)):
        raise ValueError("SAML XML must be text")
    encoded = value.encode("utf-8") if isinstance(value, str) else value
    if not encoded or len(encoded) > maximum:
        raise ValueError("SAML XML is empty or exceeds the allowed size")
    # Reject declarations even before the toolkit's entity/DTD-disabled parser.
    if re.search(br"<!\s*(?:DOCTYPE|ENTITY)\b", encoded, re.I):
        raise ValueError("SAML XML must not contain DTD or entity declarations")
    return _runtime()[4].to_etree(encoded)


@dataclass(frozen=True)
class SAMLConfig:
    enabled: bool = False
    sp_entity_id: str = ""
    origin: str = ""
    idp_metadata_xml: str = field(default="", repr=False)
    display_name: str = "SAML single sign-on"
    idp_entity_id: str = field(default="", init=False)
    sso_url: str = field(default="", init=False)
    signing_certificates: tuple = field(default=(), init=False, repr=False)
    certificate_validity: tuple = field(default=(), init=False, repr=False)

    def __post_init__(self):
        if not isinstance(self.enabled, bool):
            raise ValueError("SAML enabled must be true or false")
        object.__setattr__(self, "display_name", _text(self.display_name, "SAML display name", 100) or "SAML single sign-on")
        if not self.enabled:
            # Disabled providers retain editable values but perform no XML work.
            for value in (self.sp_entity_id, self.origin, self.idp_metadata_xml):
                if not isinstance(value, str):
                    raise ValueError("SAML configuration fields must be text")
            if len(self.idp_metadata_xml.encode()) > MAX_METADATA_BYTES:
                raise ValueError("IdP metadata exceeds 512 KiB")
            return
        object.__setattr__(self, "origin", _https_url(self.origin, "SAML application origin", origin=True))
        _entity(self.sp_entity_id, "SP entity ID")
        try:
            tree = _xml(self.idp_metadata_xml, MAX_METADATA_BYTES)
            entities = tree.xpath("self::md:EntityDescriptor | .//md:EntityDescriptor", namespaces=NS)
            if len(entities) != 1:
                raise ValueError("Upload metadata containing exactly one IdP EntityDescriptor")
            descriptors = entities[0].xpath("./md:IDPSSODescriptor", namespaces=NS)
            if len(descriptors) != 1:
                raise ValueError("Upload metadata containing exactly one IdP SSO descriptor")
            if descriptors[0].get("WantAuthnRequestsSigned", "false").lower() in ("true", "1"):
                raise ValueError("This IdP requires signed AuthnRequests; the current SP uses unsigned requests")
            parsed = _runtime()[1].parse(self.idp_metadata_xml)
            data = parsed.get("idp", {})
            entity = _entity(data.get("entityId"), "IdP entity ID")
            endpoint = _https_url(data.get("singleSignOnService", {}).get("url"), "IdP HTTP-Redirect SSO endpoint")
            # The metadata parser can fall back to encryption-only material.
            # Select trust only from actual signing/use-unspecified descriptors.
            certificates = descriptors[0].xpath("./md:KeyDescriptor[not(@use) or @use='signing']/ds:KeyInfo/ds:X509Data/ds:X509Certificate", namespaces=NS)
            if not 1 <= len(certificates) <= 8:
                raise ValueError("IdP metadata must contain one to eight signing certificates")
            trusted, validity = [], []
            from cryptography import x509
            from cryptography.hazmat.primitives.asymmetric import rsa
            for node in certificates:
                raw = base64.b64decode("".join((node.text or "").split()), validate=True)
                if len(raw) > 16384:
                    raise ValueError("IdP signing certificate is too large")
                cert = x509.load_der_x509_certificate(raw)
                key = cert.public_key()
                if not isinstance(key, rsa.RSAPublicKey) or key.key_size < 2048:
                    raise ValueError("IdP signing certificates require RSA keys of at least 2048 bits")
                encoded = base64.b64encode(raw).decode()
                trusted.append(encoded)
                validity.append((encoded, cert.not_valid_before_utc, cert.not_valid_after_utc))
            object.__setattr__(self, "idp_entity_id", entity)
            object.__setattr__(self, "sso_url", endpoint)
            object.__setattr__(self, "signing_certificates", tuple(sorted(set(trusted))))
            object.__setattr__(self, "certificate_validity", tuple(validity))
            # Validate the complete SP/IdP settings without contacting the IdP.
            _runtime()[3](self.settings())
        except AuthUnavailable:
            raise
        except ValueError:
            raise
        except Exception:
            raise ValueError("IdP metadata could not be validated; upload a valid SAML IdP metadata file") from None

    @classmethod
    def from_value(cls, value):
        if value is None:
            return cls()
        if not isinstance(value, dict):
            raise ValueError("SAML configuration must be an object")
        allowed = {"enabled", "sp_entity_id", "origin", "idp_metadata_xml", "display_name"}
        bookkeeping = {"id", "revision", "updated_at", "updated_by", "created_at"}
        if set(value) - allowed - bookkeeping:
            raise ValueError("Unknown SAML configuration fields")
        return cls(**{key: item for key, item in value.items() if key in allowed})

    @property
    def acs_url(self):
        return self.origin + "/api/v1/auth/saml/callback" if self.origin else ""

    @property
    def realm_id(self):
        return str(uuid.uuid5(uuid.NAMESPACE_URL, "prthak-saml-realm-v1\n" + self.idp_entity_id + "\n" + self.sp_entity_id))

    @property
    def fingerprint(self):
        return digest({"provider": "saml", "enabled": self.enabled, "sp_entity_id": self.sp_entity_id,
                       "origin": self.origin, "idp_entity_id": self.idp_entity_id,
                       "sso_url": self.sso_url, "signing_certificates": self.signing_certificates})

    def settings(self):
        # Metadata may advertise the next rollover certificate before activation.
        # Keep its pin in the stable configuration fingerprint, while admitting
        # signatures only from certificates valid at the moment of validation.
        active = sorted({cert for cert, starts, ends in self.certificate_validity if starts <= now() < ends})
        if not active:
            raise ValueError("IdP metadata has no currently valid signing certificate")
        return {"strict": True, "debug": False,
                "sp": {"entityId": self.sp_entity_id,
                       "assertionConsumerService": {"url": self.acs_url, "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"},
                       "NameIDFormat": "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"},
                "idp": {"entityId": self.idp_entity_id,
                        "singleSignOnService": {"url": self.sso_url, "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"},
                        "x509certMulti": {"signing": active}},
                "security": {"authnRequestsSigned": False, "wantMessagesSigned": True,
                             "wantAssertionsSigned": True, "wantNameId": True, "wantAttributeStatement": False,
                             "rejectUnsolicitedResponsesWithInResponseTo": True, "rejectDeprecatedAlgorithm": True,
                             "requestedAuthnContext": False, "allowSingleLabelDomains": True,
                             "signatureAlgorithm": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
                             "digestAlgorithm": "http://www.w3.org/2001/04/xmlenc#sha256"}}


def config_from_store(store, db=None):
    if db is None:
        with store.read_meta() as connection:
            return config_from_store(store, connection)
    value = store._get(db, "maintenance_settings", CONFIG_ID)
    return SAMLConfig.from_value(value.get("config", value) if value else None)


def authority_fingerprint(config, row):
    """Bind an explicit settings save to a fresh, shared provider epoch.

    Historical/imported fixtures may have only semantic settings. An epoch,
    once present, is never ignored or silently downgraded on corrupt headers.
    """
    if not row or "epoch" not in row:
        return config.fingerprint
    epoch = row.get("epoch")
    if (not isinstance(epoch, str) or not re.fullmatch(r"[a-f0-9]{64}", epoch)
            or row.get("configuration_fingerprint") != config.fingerprint):
        raise AuthDenied("SAML configuration authority is invalid")
    expected = digest({"configuration_fingerprint": config.fingerprint, "epoch": epoch})
    if row.get("fingerprint") != expected:
        raise AuthDenied("SAML configuration authority is invalid")
    return expected


def public_user(value):
    fields = ("id", "tenant_id", "object_id", "provider", "subject", "display_name", "email", "role", "enabled", "created_at", "updated_at", "last_login_at")
    return {key: value.get(key) for key in fields}


def _state_cookie(value="", seconds=0):
    # The cross-site IdP POST needs this one-time binding. The eventual session
    # remains SameSite=Lax; a pre-existing app session is never an ACS input.
    return f"{STATE_COOKIE}={value}; Path=/; Secure; HttpOnly; SameSite=None; Max-Age={seconds}"


class SAMLAuth:
    def __init__(self, store, config=None):
        self.store = store
        self.config = config if config is not None else config_from_store(store)
        with store.read_meta() as db:
            row = store._get(db, "maintenance_settings", CONFIG_ID)
            self._persisted = row is not None
            # A disabled instance also represents a quarantined/malformed IdP
            # configuration. It must be safe to construct while local users
            # repair the record; it can never authenticate a SAML session.
            self.fingerprint = authority_fingerprint(self.config, row) if self.enabled else self.config.fingerprint

    @property
    def enabled(self):
        return self.config.enabled

    def _configured(self):
        if not self.enabled:
            raise AuthUnavailable("SAML single sign-on is not configured")

    def status(self):
        return {"provider": "saml", "configured": self.enabled, "enabled": self.enabled,
                "display_name": self.config.display_name, "login_url": "/api/v1/auth/saml/login" if self.enabled else None,
                "sp_entity_id": self.config.sp_entity_id or None, "idp_entity_id": self.config.idp_entity_id or None,
                "acs_url": self.config.acs_url or None, "metadata_url": self.config.origin + "/api/v1/auth/saml/metadata" if self.enabled else None,
                "signature_requirement": "response_and_assertion", "roles": list(ROLES)}

    def _assert_current(self, db):
        value = self.store._get(db, "maintenance_settings", CONFIG_ID)
        if value is None and not self._persisted:
            return
        try:
            current = SAMLConfig.from_value(value.get("config", value) if value else None)
        except (ValueError, AuthUnavailable):
            raise AuthDenied("SAML configuration is unavailable; contact a Super Admin") from None
        if not current.enabled or not hmac.compare_digest(authority_fingerprint(current, value), self.fingerprint):
            raise AuthDenied("SAML configuration changed; start sign-in again")

    def _request(self, headers, post=None):
        if headers.get("Host") and _origin("https://" + headers["Host"]) != self.config.origin:
            raise AuthDenied("Use the configured HTTPS application origin for SAML sign-in")
        parsed = urlsplit(self.config.origin)
        return {"https": "on", "http_host": parsed.netloc,
                "script_name": "/api/v1/auth/saml/callback", "get_data": {}, "post_data": post or {}}

    def _prune(self, db):
        values = self.store._all(db, "auth_states")
        for value in values:
            if parse_time(value["expires_at"]) <= now():
                db.execute("DELETE FROM auth_states WHERE id=?", (value["id"],))
        return sum(parse_time(value["expires_at"]) > now() for value in values)

    def begin_login(self, headers):
        self._configured()
        if headers.get("Host") and _origin("https://" + headers["Host"]) != self.config.origin:
            return {"location": self.config.origin + "/api/v1/auth/saml/login", "cookies": []}
        relay, binding = (secrets.token_urlsafe(32) for _ in range(2))
        toolkit = _runtime()[0](self._request(headers), self.config.settings())
        location = toolkit.login(return_to=relay)
        with self.store.lock, self.store.meta() as db:
            self._assert_current(db)
            if self._prune(db) >= 4096:
                raise AuthUnavailable("Too many pending sign-ins; try again later")
            self.store._put(db, "auth_states", {"id": "saml-request:" + _sha(relay), "purpose": "saml_login",
                            "request_id": toolkit.get_last_request_id(), "binding_hash": _sha(binding),
                            "config": self.fingerprint, "created_at": stamp(), "consumed": False,
                            "expires_at": stamp(now() + timedelta(seconds=STATE_SECONDS))})
        return {"location": location, "cookies": [_state_cookie(binding, STATE_SECONDS)]}

    def user(self, value):
        self._configured()
        if not isinstance(value, dict) or set(value) - {"provider", "subject", "display_name", "email", "role", "enabled"}:
            raise ValueError("Provide SAML subject, role and optional display_name/email/enabled")
        subject = value.get("subject")
        if not isinstance(subject, str) or not 1 <= len(subject) <= 512 or subject != subject.strip() or any(ord(c) < 32 or ord(c) == 127 for c in subject):
            raise ValueError("SAML subject must exactly match the persistent NameID (1–512 characters)")
        if value.get("role") not in ROLES or not isinstance(value.get("enabled", True), bool):
            raise ValueError("Choose a supported role and boolean enabled state")
        person = str(uuid.uuid5(uuid.UUID(self.config.realm_id), subject))
        return {"id": self.config.realm_id + ":" + person, "tenant_id": self.config.realm_id,
                "object_id": person, "provider": "saml", "subject": subject, "role": value["role"],
                "display_name": _text(value.get("display_name", ""), "Display name", 200),
                "email": _email(value.get("email", "")), "enabled": value.get("enabled", True),
                "created_at": stamp(), "updated_at": stamp(), "last_login_at": None}

    def _consume_state(self, form, headers):
        if not isinstance(form, dict) or set(form) - {"SAMLResponse", "RelayState"}:
            raise AuthDenied("Invalid SAML sign-in response")
        normalized = {}
        for key in ("SAMLResponse", "RelayState"):
            value = form.get(key)
            if isinstance(value, list) and len(value) == 1:
                value = value[0]
            if not isinstance(value, str):
                raise AuthDenied("Invalid SAML sign-in response")
            normalized[key] = value
        relay = normalized["RelayState"]
        binding = _cookie(headers, STATE_COOKIE)
        if not TOKEN_PATTERN.fullmatch(relay) or not binding:
            raise AuthDenied("SAML sign-in state or browser binding is missing; start again")
        with self.store.lock, self.store.meta() as db:
            self._assert_current(db)
            value = self.store._get(db, "auth_states", "saml-request:" + _sha(relay))
            if (not value or value.get("consumed") or value.get("purpose") != "saml_login"
                    or parse_time(value["expires_at"]) <= now() or value.get("config") != self.fingerprint
                    or not hmac.compare_digest(value["binding_hash"], _sha(binding))):
                raise AuthDenied("SAML sign-in expired, was already used or belongs to another browser")
            result = copy.deepcopy(value)
            value.update(consumed=True, consumed_at=stamp())
            self.store._put(db, "auth_states", value)
        return normalized, result

    def _verified_response(self, encoded, request_id, headers):
        if len(encoded) > MAX_RESPONSE_BYTES * 2:
            raise AuthDenied("SAML sign-in response exceeds the allowed size")
        try:
            raw = base64.b64decode("".join(encoded.split()), validate=True)
            tree = _xml(raw, MAX_RESPONSE_BYTES)
            if tree.tag != "{" + NS["samlp"] + "}Response" or tree.get("Destination") != self.config.acs_url or tree.get("InResponseTo") != request_id:
                raise ValueError()
            assertions = tree.xpath("./saml:Assertion", namespaces=NS)
            if len(assertions) != 1 or len(tree.xpath(".//saml:Assertion", namespaces=NS)) != 1 or tree.xpath(".//saml:EncryptedAssertion", namespaces=NS):
                raise ValueError()
            assertion = assertions[0]
            for parent in (tree, assertion):
                issued = parse_time(parent.get("IssueInstant"))
                if not now() - timedelta(minutes=15) <= issued <= now() + timedelta(seconds=30):
                    raise ValueError()
            # Exact bindings close the toolkit's more permissive URL matching.
            for parent in (tree, assertion):
                issuers = parent.xpath("./saml:Issuer", namespaces=NS)
                if len(issuers) != 1 or issuers[0].text != self.config.idp_entity_id:
                    raise ValueError()
            conditions = assertion.xpath("./saml:Conditions", namespaces=NS)
            if len(conditions) != 1:
                raise ValueError()
            start, end = (parse_time(conditions[0].get(field)) for field in ("NotBefore", "NotOnOrAfter"))
            at = now()
            if start > at + timedelta(seconds=30) or not at < end <= at + timedelta(seconds=MAX_ASSERTION_SECONDS) or start >= end:
                raise ValueError()
            audiences = conditions[0].xpath("./saml:AudienceRestriction", namespaces=NS)
            if not audiences or any(self.config.sp_entity_id not in group.xpath("./saml:Audience/text()", namespaces=NS) for group in audiences):
                raise ValueError()
            confirmation = assertion.xpath("./saml:Subject/saml:SubjectConfirmation", namespaces=NS)
            names = assertion.xpath("./saml:Subject/saml:NameID", namespaces=NS)
            if (len(names) != 1 or names[0].get("Format") != "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
                    or names[0].get("NameQualifier", self.config.idp_entity_id) != self.config.idp_entity_id
                    or names[0].get("SPNameQualifier", self.config.sp_entity_id) != self.config.sp_entity_id):
                raise ValueError()
            if len(confirmation) != 1 or confirmation[0].get("Method") != "urn:oasis:names:tc:SAML:2.0:cm:bearer":
                raise ValueError()
            data = confirmation[0].xpath("./saml:SubjectConfirmationData", namespaces=NS)
            if len(data) != 1 or data[0].get("Recipient") != self.config.acs_url or data[0].get("InResponseTo") != request_id:
                raise ValueError()
            if not at < parse_time(data[0].get("NotOnOrAfter")) <= end:
                raise ValueError()
            signatures = tree.xpath(".//ds:Signature", namespaces=NS)
            if len(signatures) != 2:
                raise ValueError()
            methods = {"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"}
            digests = {"http://www.w3.org/2001/04/xmlenc#sha256", "http://www.w3.org/2001/04/xmldsig-more#sha384", "http://www.w3.org/2001/04/xmlenc#sha512"}
            for signature in signatures:
                method = signature.xpath("./ds:SignedInfo/ds:SignatureMethod/@Algorithm", namespaces=NS)
                references = signature.xpath("./ds:SignedInfo/ds:Reference", namespaces=NS)
                if len(method) != 1 or method[0] not in methods or len(references) != 1:
                    raise ValueError()
                if references[0].get("URI") != "#" + signature.getparent().get("ID", "") or not signature.getparent().get("ID"):
                    raise ValueError()
                algorithms = references[0].xpath("./ds:DigestMethod/@Algorithm", namespaces=NS)
                if len(algorithms) != 1 or algorithms[0] not in digests:
                    raise ValueError()
            runtime = _runtime()
            response = runtime[2](runtime[3](self.config.settings()), base64.b64encode(raw).decode())
            if not response.is_valid(self._request(headers), request_id):
                raise ValueError()
            subject = response.get_nameid()
            if not isinstance(subject, str) or not subject or len(subject) > 512:
                raise ValueError()
            # All extraction is from the exact response verified by the toolkit.
            session_end = response.get_session_not_on_or_after()
            expires = min(now() + timedelta(seconds=SESSION_SECONDS), datetime.fromtimestamp(session_end, timezone.utc)) if session_end else now() + timedelta(seconds=SESSION_SECONDS)
            return response, subject, end, expires
        except AuthUnavailable:
            raise
        except Exception:
            raise AuthDenied("SAML response is invalid, expired or does not match this sign-in") from None

    def callback(self, form, headers):
        self._configured()
        normalized, state = self._consume_state(form, headers)
        response, subject, assertion_end, session_end = self._verified_response(normalized["SAMLResponse"], state["request_id"], headers)
        identifier = self.config.realm_id + ":" + str(uuid.uuid5(uuid.UUID(self.config.realm_id), subject))
        raw_session = secrets.token_urlsafe(32)
        with self.store.lock, self.store.meta() as db:
            self._assert_current(db)
            # Replayed assertion/response IDs are rejected even across a second
            # independently valid login request or another controller process.
            replay_ids = ["saml-replay:" + _sha(self.config.idp_entity_id + "\n" + kind + "\n" + value)
                          for kind, value in (("response", response.get_id()), ("assertion", response.get_assertion_id()))]
            if any(self.store._get(db, "auth_states", key) for key in replay_ids):
                raise AuthDenied("SAML response was already used; start sign-in again")
            for key in replay_ids:
                self.store._put(db, "auth_states", {"id": key, "purpose": "saml_replay", "expires_at": stamp(assertion_end + timedelta(seconds=30))})
            user = self.store._get(db, "auth_users", identifier)
            if (not user or user.get("provider") != "saml" or not user.get("enabled") or user.get("role") not in ROLES
                    or user.get("subject") != subject or user.get("tenant_id") != self.config.realm_id):
                self.store.audit("auth.login.denied", "saml:" + identifier, {"reason": "Application access is not provisioned or is disabled"}, db)
                user = None
            else:
                user["last_login_at"] = stamp()
                self.store._put(db, "auth_users", user)
                self.store._put(db, "auth_sessions", {"id": _sha(raw_session), "user_id": identifier,
                                "provider": "saml", "config": self.fingerprint,
                                "created_at": stamp(), "expires_at": stamp(session_end)})
                self.store.audit("auth.login.succeeded", "saml:" + identifier,
                                 {"user_id": identifier, "role": user["role"], "provider": "saml"}, db)
        if user is None:
            raise AuthDenied("Your SAML identity has no enabled Prṛthak account; contact a Super Admin")
        seconds = max(1, int((session_end - now()).total_seconds()))
        principal = self.authenticate({"Cookie": SESSION_COOKIE + "=" + raw_session})
        return {"location": "/overview", "cookies": [_state_cookie(), _set_cookie(SESSION_COOKIE, raw_session, seconds)], "principal": principal}

    def authenticate(self, headers):
        raw = _cookie(headers, SESSION_COOKIE)
        if raw is None:
            return None
        with self.store.read_meta() as db:
            session = self.store._get(db, "auth_sessions", _sha(raw))
            if not session or session.get("provider") != "saml":
                return None
            if not self.enabled:
                return None
            self._assert_current(db)
            if parse_time(session["expires_at"]) <= now() or session.get("config") != self.fingerprint:
                return None
            user = self.store._get(db, "auth_users", session["user_id"])
            if (not user or user.get("provider") != "saml" or not user.get("enabled") or user.get("role") not in ROLES
                    or user.get("tenant_id") != self.config.realm_id
                    or user.get("id") != self.config.realm_id + ":" + str(uuid.uuid5(uuid.UUID(self.config.realm_id), user.get("subject", "")))):
                return None
        return {"role": user["role"], "actor": "saml:" + user["id"], "auth_type": "session", "auth_provider": "saml",
                "user": public_user(user), "csrf_token": _b64(hmac.new(raw.encode(), b"prthak-csrf-v1", hashlib.sha256).digest()),
                "_session_id": session["id"], "_origin": self.config.origin, "password_change_required": False}

    def metadata(self):
        self._configured()
        with self.store.read_meta() as db:
            self._assert_current(db)
        settings = _runtime()[3](self.config.settings())
        result = settings.get_sp_metadata()
        if settings.validate_metadata(result):
            raise AuthUnavailable("SAML service-provider metadata could not be generated")
        return result.decode() if isinstance(result, bytes) else result
