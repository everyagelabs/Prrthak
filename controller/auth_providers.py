"""GUI-owned public SAML trust configuration, shared across controllers.

IdP metadata contains public signing certificates. Password hashes and local
accounts remain in the authentication store; no directory password or private
IdP signing key is accepted by this configuration API.
"""
from __future__ import annotations

import time
import secrets

from .auth import AuthDenied, AuthUnavailable
from .store import stamp


def _revision(value):
    revision = value.get("revision", 0) if isinstance(value, dict) else 0
    return revision if type(revision) is int and revision >= 0 else 0


def _configuration(value):
    if not isinstance(value, dict):
        return None
    config = value.get("config", value)
    return config if isinstance(config, dict) else None


def refresh(app):
    from .authentication import Authentication
    if not isinstance(app.auth, Authentication):
        return
    from .approval_views import _expression
    with app.store.read_meta() as db:
        row = db.execute("SELECT " + _expression(db, ("revision",)) +
                         " FROM maintenance_settings WHERE id=?", ("saml_configuration",)).fetchone()
        revision = (str(row[0]) if row else "absent")
        if (getattr(app, "_saml_config_revision", None) == revision
                and time.monotonic() < getattr(app, "_saml_recheck_at", 0)):
            return
        value = app.store._get(db, "maintenance_settings", "saml_configuration")
    from .saml_auth import SAMLAuth, SAMLConfig
    raw_config = _configuration(value) if value else {}
    app._saml_requested_enabled = bool(raw_config.get("enabled")) if isinstance(raw_config, dict) else True
    try:
        if raw_config is None:
            raise ValueError("Invalid stored SAML configuration")
        config = SAMLConfig.from_value(raw_config)
        app.auth.saml = SAMLAuth(app.store, config)
        app._saml_configuration_error = None
    except (ValueError, AuthDenied, AuthUnavailable):
        # An expired IdP certificate or unavailable XML runtime must not disable
        # the independent local account used to repair that configuration.
        app.auth.saml = SAMLAuth(app.store, SAMLConfig())
        app._saml_configuration_error = "SAML configuration is unavailable; review IdP metadata, signing certificates and controller dependencies"
    app._saml_config_revision = revision
    app._saml_recheck_at = time.monotonic() + 60


def _status(app):
    with app.store.read_meta() as db:
        value = app.store._get(db, "maintenance_settings", "saml_configuration") or {}
    refresh(app)
    from .saml_auth import SAMLAuth, SAMLConfig
    saml = getattr(app.auth, "saml", None) or SAMLAuth(app.store, SAMLConfig())
    config = _configuration(value) or {}
    return {"local": {"enabled": bool(getattr(app.auth, "local", None)), "bootstrap_username": "admin",
                      "password_min_length": 12, "password_max_length": 256},
            "entra": getattr(app.auth, "entra", app.auth).status(),
            "saml": {**saml.status(), "origin": config.get("origin") or None,
                     "sp_entity_id": config.get("sp_entity_id") or None,
                     "error": getattr(app, "_saml_configuration_error", None),
                     "revision": _revision(value)}}


def status(app, principal):
    with app.store.read_meta() as db:
        app.auth._require_super(principal, db)
    return _status(app)


def save_saml(app, body, principal):
    if app.demo:
        raise AuthUnavailable("SAML configuration requires an installed HTTPS controller")
    with app.store.read_meta() as db:
        app.auth._require_super(principal, db)
        old = app.store._get(db, "maintenance_settings", "saml_configuration") or {}
    if not isinstance(body, dict) or set(body) - {"enabled", "sp_entity_id", "origin", "idp_metadata_xml", "display_name", "expected_revision"}:
        raise ValueError("Provide enabled, SP entity ID, HTTPS origin, IdP metadata and the current revision")
    if type(body.get("expected_revision")) is not int or body["expected_revision"] < 0:
        raise ValueError("The current SAML configuration revision is required")
    # Validate the actor before processing an XML upload, then revalidate at
    # publication. Certificate parsing performs no outbound network access.
    if body["expected_revision"] != _revision(old):
        from .auth import AuthConflict
        raise AuthConflict("SAML configuration changed; reload the provider settings before saving")
    previous = _configuration(old) or {}
    requested = {key: value for key, value in body.items() if key != "expected_revision"}
    if not requested.get("idp_metadata_xml") and previous.get("idp_metadata_xml"):
        requested["idp_metadata_xml"] = previous["idp_metadata_xml"]
    from .saml_auth import SAMLConfig
    config = SAMLConfig.from_value(requested)
    normalized = {key: getattr(config, key) for key in ("enabled", "sp_entity_id", "origin", "idp_metadata_xml", "display_name")}
    with app.store.lock, app.store.meta() as db:
        from .local_auth import write_fence
        write_fence(db)
        app.auth._require_super(principal, db)
        current = app.store._get(db, "maintenance_settings", "saml_configuration") or {}
        if current != old:
            from .auth import AuthConflict
            raise AuthConflict("SAML configuration changed; reload the provider settings before saving")
        revision = _revision(old) + 1
        from .store import digest
        epoch = secrets.token_hex(32)
        fingerprint = digest({"configuration_fingerprint": config.fingerprint, "epoch": epoch})
        app.store._put(db, "maintenance_settings", {"id": "saml_configuration", "revision": revision,
                       "config": normalized, "config_digest": digest(normalized),
                       "configuration_fingerprint": config.fingerprint, "epoch": epoch,
                       "fingerprint": fingerprint, "realm_id": config.realm_id, "updated_at": stamp(),
                       "updated_by": principal["actor"]})
        # Invalidate pending SAML handshakes and sessions immediately. Local and
        # OIDC sessions retain their own independently bound authority.
        from .approval_views import _expression
        db.execute("DELETE FROM auth_sessions WHERE " + _expression(db, ("provider",)) + "=?", ("saml",))
        db.execute("DELETE FROM auth_states WHERE " + _expression(db, ("purpose",)) + " IN (?,?)", ("saml_login", "saml_replay"))
        app.store.audit("access.saml.configured", principal["actor"],
                        {"enabled": config.enabled, "revision": revision, "fingerprint": fingerprint,
                         "sp_entity_id": config.sp_entity_id, "idp_entity_id": config.idp_entity_id,
                         "origin": config.origin}, db)
    refresh(app)
    return {**_status(app), "signed_out": principal.get("auth_provider") == "saml"}


def saml(app):
    refresh(app)
    provider = getattr(app.auth, "saml", None)
    if provider is None or not provider.enabled:
        raise AuthUnavailable("SAML single sign-on is not configured")
    return provider
