"""Password enrollment of appliance controllers, before or after shared PG.

The first untrusted contact obtains a public certificate only. Passwords leave
the joining controller only after an operator has approved that pinned identity.
All private enrollment replies are sealed to that node's persistent RSA key.
"""
from __future__ import annotations

import base64
import copy
from contextlib import contextmanager
import fcntl
import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import socket
import ssl
import stat
import uuid
from datetime import timedelta
from urllib.parse import urlsplit

from .appliance import CONFIG_ID, Appliance, ManagerUnavailable, NodeClient, origin, verify_password
from .firewall import WorkflowConflict
from .platform import _private_json, _read_json
from .store import digest, now, parse_time, stamp


@contextmanager
def _private_lifecycle_lock(api,name):
    # No Store/database locks are acquired while holding this local lock.
    # Callers that need metadata must snapshot it before entering.
    path=api.manager.root/('appliance-'+name+'.lock')
    descriptor=os.open(path,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    try:
        info=os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or info.st_mode&0o077:raise ValueError('Unsafe private appliance identity lock')
        fcntl.flock(descriptor,fcntl.LOCK_EX)
        try:yield
        finally:fcntl.flock(descriptor,fcntl.LOCK_UN)
    finally:os.close(descriptor)


def _keys(api):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    path = api.manager.root / "appliance-node-key.json"
    registered=False
    if not _read_json(path):
        registered=bool(getattr(api.manager,'active_profile',lambda:None)() or getattr(getattr(api.app,'store',None),'ha',False))
        if not registered:
            identity=api._identity()['id'];member=next((item for item in api._config().get('members',[]) if item['id']==identity),{})
            registered=bool(member.get('transport_public_key') or member.get('node_certificate') or api._local().get('node_certificate_ref'))
    with _private_lifecycle_lock(api,'node-key'):
        value = _read_json(path)
        if not value:
            if path.exists():raise ValueError('Protected node key pointer is invalid; reviewed private-state recovery is required')
            if registered:raise ValueError('Protected registered node identity is missing; restore its matching private key instead of generating a replacement')
            key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
            raw = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
            value = {"key_ref": api.manager.vault.put(raw)}
            _private_json(path, value)
    return serialization.load_pem_private_key(api.manager.vault.get(value["key_ref"]).encode(), None)


def _public_key(key):
    from cryptography.hazmat.primitives import serialization
    return key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()


def _material(api):
    saved=_read_json(api.manager.root/'appliance-material.json')
    legacy=False
    if saved:
        value=json.loads(api.manager.vault.get(saved['material_ref']))
        legacy=not value.get('sync_key')
    previous_authority=False
    if not saved:
        store=getattr(api.app,'store',None)
        profile=getattr(api.manager,'active_profile',lambda:None)()
        previous_authority=bool(profile or getattr(store,'ha',False))
        if not previous_authority:
            config=api._config()
            previous_authority=any(member.get('node_certificate') or member.get('certificate_binding') or member.get('internal_certificate') for member in config.get('members',[]))
        if not previous_authority and store is not None:
            with store.read_meta() as db:
                previous_authority=bool(db.execute("SELECT 1 FROM maintenance_settings WHERE id LIKE 'internal-cert-%' LIMIT 1").fetchone())
    # Snapshot this before the file lock: enroll may already hold the Store
    # lock, so taking it in the opposite order would deadlock worker processes.
    can_seed=api._config().get('bootstrap_seed_id')==api._identity()['id'] if legacy else False
    with _private_lifecycle_lock(api,'material'):
        return _material_locked(api,can_seed,previous_authority)


def _material_locked(api,can_seed,previous_authority):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    path = api.manager.root / "appliance-material.json"
    saved = _read_json(path)
    if saved:
        material = json.loads(api.manager.vault.get(saved["material_ref"]))
        if material.get("pki_purpose") != "internal-database-v1":
            raise ValueError("Legacy cluster material must be replaced through an explicit internal-CA setup; endpoint issuers cannot secure database members")
        if not material.get("sync_key"):
            if not can_seed:
                raise ValueError("Shared synchronization material must first be established by the bootstrap controller")
            material["sync_key"] = secrets.token_hex(32)
            _save_material_locked(api, material)
        else:
            _mark_authority(api,material,verify=True)
        return material
    if path.exists():raise ValueError('Protected internal authority pointer is invalid; reviewed matching PKI/vault recovery is required')
    if previous_authority or (api.manager.root/'appliance-authority.json').exists() or any((api.manager.root/'node-certificates').glob('*.json')) or any((api.manager.root/'policy-signing').glob('*.seed')):
        raise ValueError('Protected internal authority state is missing; reviewed matching PKI/vault recovery is required, never a new CA or synchronization seed')
    if not api.app or not api.app.signer:
        raise ValueError("The installed controller issuing identity is required before creating a cluster")
    local = api._local()
    replication = api.manager.vault.get(local["pending_replication_ref"]) if local.get("pending_replication_ref") else secrets.token_urlsafe(48)
    if len(replication) < 32:
        raise ValueError("Use at least 32 characters for the initial replication password")
    # Database/etcd/Patroni must never trust the endpoint enrollment issuer.
    # Sharing its key would let an enrolled endpoint impersonate a DB member.
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Prthak internal database CA")])
    certificate = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
                   .serial_number(x509.random_serial_number()).not_valid_before(now() - timedelta(minutes=2))
                   .not_valid_after(now() + timedelta(days=3650))
                   .add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
                   .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                                               data_encipherment=False, key_agreement=False, key_cert_sign=True,
                                               crl_sign=True, encipher_only=None, decipher_only=None), True)
                   .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
                   .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), False)
                   .sign(key, hashes.SHA256()))
    result = {"ca": certificate.public_bytes(serialization.Encoding.PEM).decode(),
              "ca_key": key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode(),
              "controller_ca": api.app.signer.ca.read_text(), "pki_purpose": "internal-database-v1",
              "sync_key": secrets.token_hex(32),
              "secrets": {"admin": secrets.token_urlsafe(48), "metadata": secrets.token_urlsafe(48), "traffic": secrets.token_urlsafe(48), "replication": replication}}
    _save_material_locked(api, result)
    return result


def _save_material(api, material):
    with _private_lifecycle_lock(api,'material'):_save_material_locked(api,material)


def _save_material_locked(api, material):
    path = api.manager.root / "appliance-material.json"
    saved = _read_json(path)
    if saved:
        try:
            if json.loads(api.manager.vault.get(saved["material_ref"])) == material:
                _mark_authority(api,material)
                return
        except (ValueError, KeyError, OSError):
            pass
    # Retain immutable evidence even if the pointer is lost after issuance.
    # Explicit reviewed join/material installation is the only writer allowed
    # to replace this authority marker; ordinary reads verify it.
    _mark_authority(api,material)
    _private_json(path, {"material_ref": api.manager.vault.put(json.dumps(material, sort_keys=True, separators=(",", ":")))})


def _mark_authority(api,material,verify=False):
    path=api.manager.root/'appliance-authority.json';expected={'ca_sha256':hashlib.sha256(material['ca'].encode()).hexdigest(),'sync_sha256':hashlib.sha256(material.get('sync_key','').encode()).hexdigest()};old=_read_json(path)
    if verify and old and old!=expected:raise ValueError('Protected internal authority pointer differs from its retained identity; reviewed recovery is required')
    if old!=expected:_private_json(path,expected)


def _sync_secret(material, deployment_id, member):
    try:
        secret = bytes.fromhex(material["sync_key"])
        if len(secret) != 32:
            raise ValueError()
    except (KeyError, TypeError, ValueError):
        raise ValueError("Shared synchronization material is unavailable") from None
    binding = {"kind": "prthak-appliance-sync-v1", "deployment_id": deployment_id,
               "member": {key: member[key] for key in ("id", "site", "ip", "transport_public_key")}}
    return hmac.new(secret, json.dumps(binding, sort_keys=True, separators=(",", ":")).encode(), hashlib.sha256).hexdigest()


def _node_certificate(material, member, public_key, controller_origin):
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization, hashes
    from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
    ca = x509.load_pem_x509_certificate(material["ca"].encode())
    if ca.not_valid_after_utc<=now()+timedelta(days=120):
        raise ValueError('Internal issuing CA needs reviewed offline rotation before new node identities can be issued')
    key = serialization.load_pem_private_key(material["ca_key"].encode(), None)
    names = [x509.IPAddress(ipaddress.ip_address(member["ip"])), x509.DNSName(member["id"]), x509.DNSName("router"), x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
    cert = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, member["id"])]))
            .issuer_name(ca.subject).public_key(public_key).serial_number(x509.random_serial_number())
            .not_valid_before(now() - timedelta(minutes=2)).not_valid_after(now() + timedelta(days=90))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
            .add_extension(x509.KeyUsage(digital_signature=True,content_commitment=False,key_encipherment=True,data_encipherment=False,key_agreement=False,key_cert_sign=False,crl_sign=False,encipher_only=None,decipher_only=None),True)
            .add_extension(x509.SubjectAlternativeName(names), False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]), False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca.public_key()), False)
            .sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def _cached_certificate(api, material, member, public_key, controller_origin, db=None, config=None):
    from cryptography.hazmat.primitives import serialization
    from .internal_certificates import assert_member_active,renewal_due,certificate_info
    assert_member_active(member)
    public_text = public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    if db is None:
        with api.app.store.lock, api.app.store.meta() as connection:
            config = api._config(connection)
            current = next((value for value in config.get("members", []) if value["id"] == member["id"]), None)
            if not current or any(current[key] != member[key] for key in ("id", "ip", "site")):
                raise ValueError("The current node membership changed before certificate lookup")
            certificate = _cached_certificate(api, material, current, public_key, controller_origin, db=connection, config=config)
            api.app.store._put(connection, "maintenance_settings", config)
            return certificate
    if member.get("transport_public_key") and member["transport_public_key"] != public_text:
        raise ValueError("The registered node key differs from its persistent local identity")
    member["transport_public_key"] = public_text
    binding = digest({"member": {key: member[key] for key in ("id", "ip")}, "origin": controller_origin, "ca": material["ca"],
                      "public_key": public_text})
    previous=member.get('node_certificate')
    if member.get("certificate_binding") == binding and previous and not renewal_due(previous):
        return member["node_certificate"]
    path = api.manager.root / "node-certificates" / (binding + ".json")
    existing = _read_json(path)
    if existing and not renewal_due(existing['certificate']):
        certificate = existing["certificate"]
    else:
        certificate = _node_certificate(material, member, public_key, controller_origin)
        _private_json(path, {"certificate": certificate})
    member.update(certificate_binding=binding, node_certificate=certificate)
    info=certificate_info(certificate);member.update(internal_certificate=info,certificate_revision=member.get('certificate_revision',0)+1)
    if previous and previous!=certificate:
        if config is None:config=api._config(db)
        config['revision']+=1
        api.app.store.audit('appliance.internal_certificate_renewed','system:internal-certificate-lifecycle',{'node_id':member['id'],'previous_fingerprint':certificate_info(previous)['fingerprint'],**info},db)
    history={'id':'internal-cert-'+info['fingerprint'],'node_id':member['id'],'issued_at':stamp(),**info}
    if not api.app.store._get(db,'maintenance_settings',history['id']):api.app.store._put(db,'maintenance_settings',history)
    return certificate


def _seal(value, public_key, node_id):
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    key, nonce = secrets.token_bytes(32), secrets.token_bytes(12)
    return {"encrypted_key": base64.b64encode(public_key.encrypt(key, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))).decode(),
            "nonce": base64.b64encode(nonce).decode(),
            "ciphertext": base64.b64encode(AESGCM(key).encrypt(nonce, json.dumps(value).encode(), node_id.encode())).decode()}


def _peer_origin(value):
    if not isinstance(value, str):
        raise ValueError("Provide the existing controller IP or HTTPS URL")
    if not value.startswith("https://"):
        try:
            address = ipaddress.ip_address(value)
            value = "https://" + ("[" + str(address) + "]" if address.version == 6 else str(address)) + ":8787"
        except ValueError:
            raise ValueError("Use an IP or a complete HTTPS URL including its port") from None
    value = origin(value)
    host = urlsplit(value).hostname
    try:
        ip = ipaddress.ip_address(host)
        if ip.is_link_local or ip.is_multicast or ip.is_unspecified:
            raise ValueError("The peer must be a normal unicast controller address")
    except ValueError:
        if re.fullmatch(r"[0-9.:]+", host):
            raise ValueError("Invalid controller address") from None
    return value


def _public_bundle(*values):
    """Never copy a combined PEM private-key block into shared public trust."""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization, hashes
    certificates = {}
    for value in values:
        if not value:
            continue
        for block in re.findall(r"-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----", value):
            certificate = x509.load_pem_x509_certificate(block.encode())
            certificates[certificate.fingerprint(hashes.SHA256()).hex()] = certificate.public_bytes(serialization.Encoding.PEM).decode()
    return "".join(certificates.values())


def _web_identity(api):
    from cryptography import x509
    from .certificates import _matches
    context, config, identity = api.manager.certificate_context(), api._config(), api._identity()
    if not context.get("cert_path"):
        return identity["id"], ""
    raw = Path(context["cert_path"]).read_text()
    certificate = x509.load_pem_x509_certificate(raw.encode())
    dns_names = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    candidates = [urlsplit(config.get("controller_origin", "")).hostname, identity["id"], *dns_names]
    name = None
    for candidate in candidates:
        if not candidate or "*" in candidate:
            continue
        try:
            ipaddress.ip_address(candidate)
            continue
        except ValueError:
            pass
        try:
            if _matches(certificate, candidate):
                name = candidate
                break
        except ValueError:
            continue
    if not name:
        raise ValueError("Managed router checks require a DNS SAN on the HTTPS certificate")
    issuer = Path(context["ca_path"]).read_text() if context.get("ca_path") else ""
    return name, _public_bundle(raw, issuer)


def _public_certificate(peer):
    """Fetch only a public TLS certificate; send no HTTP or credentials yet."""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization, hashes
    parsed = urlsplit(peer)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    try:
        with socket.create_connection((parsed.hostname, parsed.port or 443), timeout=8) as transport:
            with context.wrap_socket(transport, server_hostname=parsed.hostname) as tls:
                cert = x509.load_der_x509_certificate(tls.getpeercert(binary_form=True))
        current = now()
        if cert.not_valid_before_utc > current or cert.not_valid_after_utc <= current:
            raise ValueError("The existing controller certificate is expired or not yet valid")
        sans = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        values = {str(value.value).casefold() for value in sans}
        from .certificates import _matches
        if not _matches(cert, parsed.hostname):
            raise ValueError("Use an address covered by the existing controller certificate")
        return cert.public_bytes(serialization.Encoding.PEM).decode(), {"subject": cert.subject.rfc4514_string(), "issuer": cert.issuer.rfc4514_string(), "fingerprint_sha256": cert.fingerprint(hashes.SHA256()).hex(), "sans": sorted(values), "not_after": cert.not_valid_after_utc.isoformat()}
    except ValueError:
        raise
    except Exception:
        raise ValueError("The existing controller TLS identity could not be inspected; no password was sent") from None


def preview(api, body, actor):
    api.manager._production()
    if api.app and api.app.store.ha or api.manager.active_profile():
        raise ValueError("An active shared controller cannot be replaced by joining another deployment")
    api.manager._join_source_preflight()
    password = body.get("cluster_password")
    if not isinstance(password, str) or not 16 <= len(password) <= 256:
        raise ValueError("Provide the cluster password set on the existing deployment")
    peer = _peer_origin(body.get("peer_url", ""))
    identity = api._identity()
    api.manager._join_identity({"node_id": identity["id"], "site": identity["site"], "node_ip": identity["ip"]})
    ca, certificate = _public_certificate(peer)
    plan = {"id": secrets.token_hex(16), "operation": "password_join", "peer_url": peer, "identity": identity,
            "confirmation_nonce": secrets.token_urlsafe(24), "confirmation_phrase": "TRUST " + certificate["fingerprint_sha256"][:12] + " AND JOIN",
            "expires_at": stamp(now() + timedelta(minutes=10)), "blockers": [], "can_apply": True,
            "summary": {"peer_url": peer, "node": identity, "certificate": certificate, "trust_verified": False,
                        "message": "Compare this fingerprint with the existing controller through a trusted channel. The password has not been sent. Approving joins this controller and permits storage activation when the cluster is ready."},
            "private_ref": api.manager.vault.put(json.dumps({"password": password, "ca": ca}))}
    plan["digest"] = digest({key: value for key, value in plan.items() if key != "private_ref"})
    _private_json(api.manager.root / "password-join-plans" / (plan["id"] + ".json"), plan)
    return {key: value for key, value in plan.items() if key != "private_ref"}


def apply(api, body, actor):
    api.manager._production()
    identifier = body.get("preview_id", "")
    if not isinstance(identifier, str) or not re.fullmatch(r"[a-f0-9]{32}", identifier):
        raise ValueError("Review the peer certificate before joining")
    with api.manager.lock:
        path = api.manager.root / "password-join-plans" / (identifier + ".json")
        plan = _read_json(path)
        if not plan or parse_time(plan["expires_at"]) <= now() or any(body.get(key) != plan[key] for key in ("digest", "confirmation_nonce", "confirmation_phrase")):
            raise WorkflowConflict("The peer trust/join review expired or was not confirmed exactly", {})
        if plan.get("job_id"):
            return api.manager.job(plan["job_id"])
        if api._identity() != plan["identity"]:
            raise WorkflowConflict("This node identity changed after the peer review; no password was sent", {})
        if api.app and api.app.store.ha or api.manager.active_profile():
            raise ValueError("An active shared controller cannot replace its deployment through password joining")
        api.manager._join_source_preflight()
        private = json.loads(api.manager.vault.get(plan["private_ref"]))
        key = _keys(api)
        identity = plan["identity"]
        server_name, web_ca = _web_identity(api)
        payload = {"action": "password-bootstrap", "node_id": identity["id"], "site": identity["site"], "node_ip": identity["ip"],
                   "cluster_password": private["password"], "transport_public_key": _public_key(key), "tls_server_name": server_name, "controller_ca": web_ca}
        sealed = api.manager._peer_request(plan["peer_url"], private["ca"], payload)
        enrolled = api.manager._unseal(sealed, key, identity["id"])
        _install_enrollment(api, enrolled, plan["peer_url"], private["ca"], actor)
        request = {"action": "configure", "configuration": manifest(api), "expected_revision": api.client.status()["revision"], "request_id": identifier}
        queued = api.manager._queue("appliance", {"request_ref": api.manager.vault.put(json.dumps(request))}, actor)
        plan["job_id"] = queued["id"]
        _private_json(path, plan)
        return queued


def _install_enrollment(api, enrolled, peer, peer_ca, actor):
    identity = api._identity()
    config = enrolled.get("configuration")
    if not isinstance(config, dict) or not any(member["id"] == identity["id"] and member["ip"] == identity["ip"] and member["site"] == identity["site"] for member in config.get("members", [])):
        raise ValueError("The peer response did not authorize this installed node identity")
    _save_material(api, enrolled["material"])
    local = api._local()
    def retain(reference, value):
        if reference:
            try:
                if api.manager.vault.get(reference) == value:
                    return reference
            except (ValueError, KeyError, OSError):
                pass
        return api.manager.vault.put(value)
    local.update(seed_origin=peer, peer_ca_ref=retain(local.get("peer_ca_ref"), peer_ca), sync_secret_ref=retain(local.get("sync_secret_ref"), enrolled["sync_secret"]),
                 authorized_join_actor=actor, authorized_join=True, node_certificate_ref=retain(local.get("node_certificate_ref"), enrolled["node_certificate"]))
    if enrolled.get("join_code"):
        local["join_code_ref"] = retain(local.get("join_code_ref"), enrolled["join_code"])
    _private_json(api.manager.root / "appliance-local.json", local)
    with api.app.store.lock, api.app.store.meta() as db:
        api.app.store._put(db, "maintenance_settings", config)
        api.app.store.audit("appliance.password_join_authorized", actor, {"deployment_id": config["deployment_id"], "node_id": identity["id"]}, db)


def enroll(api, body, peer_ip):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    api.manager._production()
    if api.app.store.ha:
        from .replication_rotation import sync_completed_material
        sync_completed_material(api)
    node_id, site, node_ip = api.manager._join_identity(body)
    action = body.get("action")
    with api.app.store.lock, api.app.store.meta() as db:
        from .provider_lifecycle import assert_join_current
        assert_join_current(api.app, db)
        config = api._config(db)
        if not config.get("deployment_id"):
            raise PermissionError("Create the initial cluster settings before admitting another controller")
        if not api.app.store.ha and config.get("bootstrap_seed_id") != api._identity()["id"]:
            raise PermissionError("Until database activation, join through the original bootstrap controller")
        if api.app.store.ha:
            # Completion may race the pre-transaction refresh. Recheck against
            # this locked shared snapshot before returning any private material.
            sync_completed_material(api, db=db)
        member = next((member for member in config.get("members", []) if member["id"] == node_id), None)
        if member:
            from .internal_certificates import assert_member_active
            assert_member_active(member)
        if action == "password-bootstrap":
            key_id = "appliance_auth:" + hashlib.sha256(peer_ip.encode()).hexdigest()
            attempts = api.app.store._get(db, "maintenance_settings", key_id) or {"id": key_id, "count": 0, "until": stamp(now() + timedelta(minutes=5))}
            if parse_time(attempts["until"]) <= now():
                attempts.update(count=0, until=stamp(now() + timedelta(minutes=5)))
            if attempts["count"] >= 8:
                raise PermissionError("Cluster password attempts are temporarily limited")
            if not verify_password(body.get("cluster_password"), config.get("password_hash")):
                attempts["count"] += 1
                api.app.store._put(db, "maintenance_settings", attempts)
                # Commit the limiter independently of the rejected HTTP request.
                getattr(db, "connection", db).commit()
                raise PermissionError("Cluster enrollment credentials were not accepted")
            try:
                public = serialization.load_pem_public_key(body.get("transport_public_key", "").encode())
                if not isinstance(public, rsa.RSAPublicKey) or public.key_size < 3072:
                    raise ValueError()
            except Exception:
                raise ValueError("A strong persistent node transport key is required") from None
            public_text = public.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
            if member and (member.get("transport_public_key") != public_text or member["ip"] != node_ip or member["site"] != site):
                raise PermissionError("This node identity already belongs to another key, IP or site")
            if not member:
                if api.app.store.ha:
                    from .replication_rotation import in_progress
                    if in_progress(api, db):
                        raise ValueError("Wait for the current replication-password rotation before enrolling another controller")
                existing = config.get("members", [])
                if any(member["ip"] == node_ip for member in existing):
                    raise PermissionError("This management IP is already registered")
                role = "database_voter" if len(config.get("voters", [])) < 3 and not any(member["site"].casefold() == site.casefold() and member.get("role") == "database_voter" for member in existing) else "management"
                member = {"id": node_id, "site": site, "ip": node_ip, "origin": "https://" + ("[" + node_ip + "]" if ":" in node_ip else node_ip) + ":8787", "role": role,
                          "state": "registered", "transport_public_key": public_text, "sync_method": "hmac-sha256-v1", "created_at": stamp()}
                material = _material(api)
                sync_secret = _sync_secret(material, config["deployment_id"], member)
                member["sync_hash"] = hashlib.sha256(sync_secret.encode()).hexdigest()
                config.setdefault("members", []).append(member)
                config["voters"] = [{key: value[key] for key in ("id", "site", "ip")} for value in config["members"] if value.get("role") == "database_voter"]
                config["revision"] += 1
                api.app.store._put(db, "maintenance_settings", config)
            else:
                if member.get("sync_method") == "hmac-sha256-v1":
                    sync_secret = _sync_secret(_material(api), config["deployment_id"], member)
                    if not hmac.compare_digest(member.get("sync_hash", ""), hashlib.sha256(sync_secret.encode()).hexdigest()):
                        raise PermissionError("Shared synchronization authority does not match this member")
                else:
                    secret_record = _read_json(api.manager.root / "member-secrets" / (hashlib.sha256(node_id.encode()).hexdigest() + ".json"))
                    if not secret_record:
                        raise PermissionError("This legacy enrollment must be resumed on its original issuing controller")
                    sync_secret = api.manager.vault.get(secret_record["secret_ref"])
        elif action == "node-sync":
            supplied = body.get("sync_secret", "")
            if not member or not isinstance(supplied, str) or not hmac.compare_digest(member.get("sync_hash", ""), hashlib.sha256(supplied.encode()).hexdigest()) or member["ip"] != node_ip or member["site"] != site:
                raise PermissionError("Node synchronization identity was not accepted")
            public = serialization.load_pem_public_key(member["transport_public_key"].encode())
            sync_secret = supplied
        else:
            raise PermissionError("Unknown appliance enrollment operation")
        if "tls_server_name" in body or "controller_ca" in body:
            # Only an authenticated member may advertise its own public HTTPS
            # identity. Never accept keys or an arbitrary trust-only blob.
            from cryptography import x509
            from .certificates import _matches
            name, bundle = body.get("tls_server_name"), body.get("controller_ca")
            if not isinstance(name, str) or len(name) > 253 or not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?", name) or not isinstance(bundle, str) or len(bundle) > 256 * 1024 or "PRIVATE KEY" in bundle:
                raise ValueError("Provide this member's public DNS identity and certificate chain")
            public_bundle = _public_bundle(bundle)
            if not public_bundle or not _matches(x509.load_pem_x509_certificate(public_bundle.encode()), name):
                raise ValueError("The member HTTPS certificate does not cover its advertised DNS identity")
            member.update(tls_server_name=name.lower(), controller_ca=public_bundle)
        material = _material(api)
        cert = _cached_certificate(api, material, member, public, config["controller_origin"], db=db, config=config)
        member.update(last_seen=stamp())
        api.app.store._put(db, "maintenance_settings", config)
        response = {"configuration": config, "material": material, "node_certificate": cert, "sync_secret": sync_secret}
    if api.manager.active_profile() and not any(node["id"] == node_id for node in api.app.cluster()["nodes"]):
        response["join_code"] = api.manager.create_join_token({"node_id": node_id, "site": site, "node_ip": node_ip}, "cluster-password")["join_code"]
    return _seal(response, public, node_id)


def manifest(api):
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    config, local, identity = api._config(), api._local(), api._identity()
    material = _material(api)
    key = _keys(api)
    member = next((member for member in config.get("members", []) if member["id"] == identity["id"]), None)
    if not member:
        raise ValueError("The installed controller is not registered in this cluster")
    cert = _cached_certificate(api, material, member, key.public_key(), config["controller_origin"])
    config=api._config()
    server_name, local_web_ca = _web_identity(api)
    web_ca = _public_bundle(material["controller_ca"], local_web_ca, *(member.get("controller_ca", "") for member in config.get("members", [])))
    return {"schema_version": 1, "deployment_id": config["deployment_id"], "generation": config["revision"], "cluster_name": re.sub(r"[^a-z0-9_-]", "-", config["cluster_name"].lower())[:48],
            "controller_origin": config["controller_origin"], "local_node": {key: member[key] for key in ("id", "site", "ip", "role")},
            "voters": [{**member, "tls_server_name": member["id"]} for member in config.get("voters", [])], "controller_members": [{**{key: member[key] for key in ("id", "site", "ip", "role")}, "tls_server_name": server_name if member["id"] == identity["id"] else member.get("tls_server_name", member["id"])} for member in config.get("members", []) if member.get('state') not in ('suspended','revoked','decommissioning','decommissioned')],
            "database": {"metadata_name": "prthak_metadata", "traffic_name": "prthak_traffic", "metadata_user": "prthak_metadata", "traffic_user": "prthak_traffic", "synchronous_node_count": 1},
            "pki": {"ca": material["ca"], "certificate": cert, "private_key": key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()},
            "controller_ca": web_ca,
            "controller_tls_server_name": server_name,
            "secrets": material["secrets"], "watchdog": {"required": True, "approved": bool(local.get("watchdog_approved")), "device": "/dev/watchdog0"},
            "routing": {"preferred_controller_url": local.get("preferred_controller_url", ""), "fallback_controller_url": local.get("fallback_controller_url", "")}}


def reconcile(api):
    """One bounded reconciliation pass; startup and restart keep pending intent."""
    if not api._installed() or not api._config().get("deployment_id"):
        return
    if api.app.store.ha:
        from .replication_rotation import reconcile as reconcile_rotation
        if reconcile_rotation(api):
            return
    local, identity = api._local(), api._identity()
    server_name, web_ca = _web_identity(api)
    from .application_port import advertised_origin
    local_origin = advertised_origin(api.manager, identity["ip"])
    if api.app.store.ha or api._config().get("bootstrap_seed_id") == identity["id"]:
        with api.app.store.lock, api.app.store.meta() as db:
            current = api._config(db)
            own = next((member for member in current.get("members", []) if member["id"] == identity["id"]), None)
            if own:
                updates = {"tls_server_name": server_name, "controller_ca": web_ca}
                if local_origin:
                    updates["origin"] = local_origin
                if any(own.get(key) != value for key, value in updates.items()):
                    own.update(updates)
                    api.app.store._put(db, "maintenance_settings", current)
    if local.get("authorized_join") and local.get("seed_origin") and not api.app.store.ha:
        request = {"action": "node-sync", "node_id": identity["id"], "site": identity["site"], "node_ip": identity["ip"], "sync_secret": api.manager.vault.get(local["sync_secret_ref"]), "tls_server_name": server_name, "controller_ca": web_ca}
        response = api.manager._peer_request(local["seed_origin"], api.manager.vault.get(local["peer_ca_ref"]), request)
        enrolled = api.manager._unseal(response, _keys(api), identity["id"])
        _install_enrollment(api, enrolled, local["seed_origin"], api.manager.vault.get(local["peer_ca_ref"]), local["authorized_join_actor"])
        local = api._local()
    config = api._config()
    desired = manifest(api)
    from .internal_certificates import reconcile as reconcile_internal_certificates
    if reconcile_internal_certificates(api,desired):
        return
    config=api._config()
    desired_digest = digest(desired)
    if local.get("configured_manifest_digest") != desired_digest:
        identifier = digest({"kind": "configure", "node": identity["id"], "manifest": desired_digest})[:32]
        try:
            result = api.client.job(identifier)
        except KeyError:
            request = {"action": "configure", "configuration": desired, "request_id": identifier, "expected_revision": api.client.status()["revision"]}
            result = api.client.submit(request)
        if result.get("status") in ("queued", "running"):
            result = api.client.job(result["id"])
        if result.get("status") in ("completed", "applied"):
            local["configured_generation"] = config["revision"]
            local["configured_manifest_digest"] = desired_digest
            _private_json(api.manager.root / "appliance-local.json", local)
        return
    if api.app.store.ha:
        return
    state = api.client.status()
    member = next((member for member in config.get("members", []) if member["id"] == identity["id"]), {})
    if len(config.get("voters", [])) == 3 and member.get("role") == "database_voter" and local.get("watchdog_approved") and not local.get("auto_start_paused") and not local.get("services_initialized"):
        services = {service["id"]: service.get("state") for service in state.get("services", [])}
        service = "etcd" if services.get("etcd") != "running" else "database" if services.get("database") != "running" and state.get("health", {}).get("all_voters_healthy") is True else None
        if service:
            identifier = digest({"kind": "bootstrap_service_start", "service": service, "node": identity["id"], "manifest": desired_digest})[:32]
            try:
                result = api.client.job(identifier)
            except KeyError:
                api.client.submit({"action": "start", "service": service, "request_id": identifier})
            return
        if state.get("health", {}).get("database_ready") is True and services.get("database") == "running":
            local["services_initialized"] = True
            if local.get("pending_replication_ref") and api.manager.vault.get(local["pending_replication_ref"]) == _material(api)["secrets"]["replication"]:
                local.pop("pending_replication_ref", None)
            _private_json(api.manager.root / "appliance-local.json", local)
    if config.get("bootstrap_seed_id") == identity["id"] and state.get("health", {}).get("database_ready") is True and not local.get("runtime_activation_job_id"):
        _activate_source(api, config, local)
        return
    if local.get("join_code_ref") and not local.get("runtime_join_job_id"):
        identity_body = {"node_id": identity["id"], "site": identity["site"], "node_ip": identity["ip"], "peer_url": local["seed_origin"], "join_code": api.manager.vault.get(local["join_code_ref"])}
        review = api.manager.join_preview(identity_body, local["authorized_join_actor"])
        body = {key: review[key] for key in ("digest", "confirmation_nonce", "confirmation_phrase")}
        body["preview_id"] = review["id"]
        job = api.manager.join_apply(body, local["authorized_join_actor"])
        local["runtime_join_job_id"] = job["id"]
        _private_json(api.manager.root / "appliance-local.json", local)


def _activate_source(api, config, local):
    """Only the original authority imports its stopped SQLite state once."""
    from psycopg import connect
    from psycopg.conninfo import make_conninfo
    from .maintenance import backup_create
    material = _material(api)
    ca_path = api.manager.root / "database-cas" / (hashlib.sha256(material["ca"].encode()).hexdigest() + ".pem")
    api.manager._private_text(ca_path, material["ca"])
    hosts = ",".join(member["ip"] for member in config["voters"])
    dsns = {kind: make_conninfo(host=hosts, port=5432, dbname="prthak_" + kind, user="prthak_" + kind,
                               password=material["secrets"][kind], sslmode="verify-full", sslrootcert=str(ca_path),
                               target_session_attrs="read-write", connect_timeout=3) for kind in ("metadata", "traffic")}
    # Both independently authenticated application roles must reach the writer.
    for kind in ("metadata", "traffic"):
        with connect(dsns[kind]) as db:
            if db.execute("SELECT pg_is_in_recovery()").fetchone()[0]:
                raise ManagerUnavailable("The shared database writer is not ready")
    identity, context = api._identity(), api.manager.certificate_context()
    profile = {"metadata_dsn": dsns["metadata"], "traffic_dsn": dsns["traffic"], "deployment_id": config["deployment_id"], "epoch": 1,
               "active_revision": config["revision"], "controller_id": identity["id"], "site": identity["site"],
               "controller_origin": config["controller_origin"], "mode": "active_active", "spec": {"kind": "appliance", "cluster_id": config["deployment_id"], "name": config["cluster_name"], "controller_origin": config["controller_origin"], "nodes": []},
               "controller_tls": {"cert": context["cert_path"], "key": context["key_path"], "ca": str(api.app.signer.ca), "ca_key": str(api.app.signer.ca_key)}}
    backup = backup_create(api.app.store, "system:appliance-bootstrap", reason="before_appliance_activation")
    job = api.manager._queue("activate", {"profile_ref": api.manager.vault.put(json.dumps(profile)), "backup_id": backup["id"]}, "system:appliance-bootstrap")
    local["runtime_activation_job_id"] = job["id"]
    _private_json(api.manager.root / "appliance-local.json", local)

