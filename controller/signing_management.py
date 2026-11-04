"""GUI-managed online signing health and same-key local recovery.

Private keys never leave this process through an API. Checkpoints are encrypted
in the existing node-local Vault and are not an off-node disaster-recovery copy.
Rotation is unavailable until an explicit endpoint trust-adoption protocol exists.
"""
from __future__ import annotations

import base64
from contextlib import contextmanager
from datetime import timedelta
import fcntl
import hashlib
import json
import os
from pathlib import Path
import secrets
import stat
import tempfile
import uuid

from .firewall import WorkflowConflict
from .platform import _private_json
from .policy_signing import PACKAGE_DOMAIN, PolicySigner, _json, key_id
from .store import digest, now, parse_time, stamp

MAX_CHECKPOINTS = 10
MAX_REVIEWS = 20
STATE_FILE = 'signing-management.json'
LOCK_FILE = '.signing-management.lock'
CONFIRMATION = 'RESTORE THE SAME SIGNING KEY'


def _store(manager):
    store = getattr(getattr(manager, 'app', None), 'store', None)
    if store is None:
        raise ValueError('Configure private controller state before managing signing')
    return store


def _protected(manager, path, *, missing=False):
    path, base = Path(path), manager.root
    try:
        relative = path.relative_to(base)
    except ValueError:
        raise ValueError('Signing management cannot access an external path') from None
    current = base
    for component in (None, *relative.parts):
        if component is not None:
            current = current/component
        try:
            info = current.lstat()
        except FileNotFoundError:
            if missing and current == path:
                return None
            raise ValueError('Protected signing state is missing') from None
        if stat.S_ISLNK(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022 or current != path and not stat.S_ISDIR(info.st_mode):
            raise ValueError('Signing paths must be owned and protected without symlinks')
    return info


@contextmanager
def _lease(manager):
    with manager.lock:
        path = manager.root/LOCK_FILE
        _protected(manager, path, missing=True)
        descriptor = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, 'O_NOFOLLOW', 0), 0o600)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077 or info.st_nlink != 1:
                raise ValueError('Signing operation lock is not protected')
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise ValueError('Another signing lifecycle operation is in progress') from None
            yield
        finally:
            os.close(descriptor)


def _state(manager):
    path = manager.root/STATE_FILE
    info = _protected(manager, path, missing=True)
    if info is None:
        return {'schema_version': 1, 'checkpoints': [], 'reviews': [], 'last_check': None}
    if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_nlink != 1 or info.st_size > 262144:
        raise ValueError('Signing management state is unsafe or oversized')
    descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
    try:
        raw = os.read(descriptor, 262145)
    finally:
        os.close(descriptor)
    value = json.loads(raw)
    if not isinstance(value, dict) or value.get('schema_version') != 1 or not isinstance(value.get('checkpoints'), list) or len(value['checkpoints']) > MAX_CHECKPOINTS or not isinstance(value.get('reviews'), list) or len(value['reviews']) > MAX_REVIEWS:
        raise ValueError('Signing management state is invalid')
    return value


def _save(manager, value):
    _protected(manager, manager.root/STATE_FILE, missing=True)
    if len(_json(value)) > 262144:
        raise ValueError('Signing lifecycle state exceeds its bounded limit')
    _private_json(manager.root/STATE_FILE, value)


def _mode():
    if os.environ.get('SEG_POLICY_SIGNED_BUNDLES_DIR') or os.environ.get('SEG_POLICY_SIGNING_TRUST_FILE'):
        return 'offline_artifacts'
    return 'online_external_file' if os.environ.get('SEG_POLICY_SIGNING_KEY_FILE') else 'online_controller'


def _trust_from_seed(seed, deployment):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    if not isinstance(seed, bytes) or len(seed) != 32:
        raise ValueError('The current online signing authority is unavailable')
    public = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return {'deployment_id': deployment, 'keys': {key_id(public): base64.b64encode(public).decode()}}


def _expected(manager):
    if _mode() != 'online_controller':
        raise ValueError('Local recovery checkpoints support the managed online controller key only')
    # Never seed new deployment material as a side effect of recovery.
    marker = manager.root/('demo-shared-seed.json' if getattr(manager.app, 'demo', False) else 'appliance-material.json')
    info = _protected(manager, marker)
    if not stat.S_ISREG(info.st_mode):
        raise ValueError('Current online authority must be present before same-key recovery')
    _vault_ready(manager)
    seed = manager.shared_secret_key('policy-signing-v1')
    if not isinstance(seed, bytes) or len(seed) != 32:
        raise ValueError('The current online signing authority is unavailable')
    deployment = str(uuid.UUID(bytes=hashlib.sha256(b'prthak-policy-domain-v1'+seed).digest()[:16]))
    return manager.root/'policy-signing'/(deployment+'.seed'), seed, _trust_from_seed(seed, deployment)


def _vault_ready(manager):
    """Do not recreate or keep using a lost/replaced Vault key through a cache."""
    from cryptography.fernet import Fernet
    path = manager.root/'vault'/'vault.key'
    info = _protected(manager, path)
    if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_nlink != 1 or info.st_size != 44:
        raise ValueError('The current private Vault key is unavailable or unsafe')
    descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
    try: raw = os.read(descriptor, 45)
    finally: os.close(descriptor)
    actual = Fernet(raw)
    vault = manager.vault
    challenge = secrets.token_bytes(32)
    if actual.decrypt(vault.cipher.encrypt(challenge)) != challenge:
        raise ValueError('The current Vault identity changed')
    return vault


def _read_seed(manager, path):
    info = _protected(manager, path)
    if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1 or info.st_size != 32:
        raise ValueError('The signing key must be an owned private mode0600 regular file')
    descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
    try:
        current = os.fstat(descriptor)
        if (current.st_dev, current.st_ino, current.st_mode, current.st_uid, current.st_nlink, current.st_size) != (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_nlink, info.st_size):
            raise ValueError('Signing key changed while being inspected')
        value = os.read(descriptor, 33)
    finally:
        os.close(descriptor)
    if len(value) != 32:
        raise ValueError('The protected signing key has invalid length')
    return value


def _public_checkpoint(value):
    return {key: value.get(key) for key in ('id', 'created_at', 'created_by', 'deployment_id', 'key_ids', 'node_id', 'verified_at')}


def status(manager):
    mode = _mode()
    result = {'mode': mode, 'custody': 'Private signing authority is online inside this controller trust boundary.' if mode.startswith('online') else 'Exact offline artifacts are configured; this is not the selected online-controller workflow.',
              'private_key_download': False, 'rotation_available': False, 'rotation_reason': 'Agents pin signing trust. Rotation requires a separate endpoint trust-adoption and retirement workflow; this GUI never silently changes those pins.',
              'checkpoint_scope': 'This node only; encrypted in its local Vault. Preserve the complete protected DATA_ROOT/Vault separately. Database backups exclude private Vault/PKI; this is not off-node disaster recovery.',
              'checkpoint_limit': MAX_CHECKPOINTS, 'checkpoint_available': False, 'public_trust': None, 'key_ids': [], 'health': 'unavailable', 'blockers': []}
    try:
        with manager.lock:
            signer = manager.policy_signer()
            trust = signer.public_trust()
            result.update(public_trust=trust, key_ids=sorted(trust['keys']), deployment_id=trust['deployment_id'],
                          public_fingerprints={identifier: hashlib.sha256(base64.b64decode(public, validate=True)).hexdigest() for identifier, public in trust['keys'].items()})
            if mode.startswith('online'):
                if mode == 'online_controller':
                    path, expected, expected_trust = _expected(manager)
                    if signer.path != path or trust != expected_trust or _read_seed(manager, path) != expected:
                        raise ValueError('Online signing material does not match current authority')
                result['health'] = 'online_key_available'
                result['checkpoint_available'] = mode == 'online_controller'
            else:
                result['health'] = 'offline_provider_configured'
            value = _state(manager)
            result['last_check'] = value.get('last_check')
            result['checkpoints'] = [_public_checkpoint(item) for item in reversed(value['checkpoints'])]
    except Exception:
        result['health'] = 'unavailable'
        result['checkpoint_available'] = False
        result['blockers'] = ['Signing key, current authority or protected lifecycle state is unavailable or unsafe. Existing endpoint rules are retained; new deliveries cannot be assumed valid.']
        try:
            value = _state(manager)
            result['last_check'] = value.get('last_check')
            result['checkpoints'] = [_public_checkpoint(item) for item in reversed(value['checkpoints'])]
        except Exception:
            result['checkpoints'] = []
    return result


def _self_check(signer):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    if not hasattr(signer, 'sign_package'):
        raise ValueError('A local online signer is required for this self-check')
    challenge = {'kind': 'prthak-signing-self-check-v1', 'nonce': secrets.token_hex(32), 'deployment_id': signer.public_trust()['deployment_id'], 'created_at': stamp()}
    signed = signer.sign_package(challenge)
    trust = signer.public_trust()
    try:
        raw = base64.b64decode(signed['payload'], validate=True)
        signature = base64.b64decode(signed['signature'], validate=True)
        public = base64.b64decode(trust['keys'][signed['key_id']], validate=True)
        if signed.get('algorithm') != 'Ed25519' or key_id(public) != signed['key_id'] or json.loads(raw) != {'domain': PACKAGE_DOMAIN, 'manifest': challenge}:
            raise ValueError()
        Ed25519PublicKey.from_public_bytes(public).verify(signature, raw)
    except Exception:
        raise ValueError('Online signing self-check did not verify') from None
    return {'status': 'passed', 'checked_at': stamp(), 'deployment_id': trust['deployment_id'], 'key_ids': sorted(trust['keys'])}


def check(manager, actor):
    with _lease(manager):
        value = _state(manager)
        try:
            signer = manager.policy_signer()
            if _mode() == 'online_controller':
                path, expected, trust = _expected(manager)
                if signer.path != path or signer.public_trust() != trust or _read_seed(manager, path) != expected:
                    raise ValueError('Current signing key does not match deployment authority')
            result = _self_check(signer)
        except Exception:
            result = {'status': 'failed', 'checked_at': stamp(), 'error': 'Signing self-check failed; inspect protected key/current authority. No key was rotated and no firewall policy was changed.'}
        value['last_check'] = result; _save(manager, value)
    _store(manager).audit('policy_signing.self_checked', actor, {'status': result['status']})
    return result


def checkpoint(manager, actor):
    with _lease(manager):
        value = _state(manager)
        path, expected, trust = _expected(manager)
        signer = manager.policy_signer()
        if signer.path != path or signer.public_trust() != trust or _read_seed(manager, path) != expected:
            raise ValueError('Only the current verified online signing key can be checkpointed')
        _self_check(signer)
        if len(value['checkpoints']) >= MAX_CHECKPOINTS:
            raise ValueError('The bounded local signing checkpoint limit has been reached; existing checkpoints are preserved')
        identifier = uuid.uuid4().hex
        record = {'id': identifier, 'created_at': stamp(), 'created_by': actor, 'deployment_id': trust['deployment_id'], 'key_ids': sorted(trust['keys']),
                  'node_id': str(getattr(manager.app, 'controller_id', '') or 'standalone')[:128], 'verified_at': stamp()}
        record['secret_ref'] = manager.vault.put(json.dumps({'seed': base64.b64encode(expected).decode(), 'public_trust': trust, 'checkpoint_id': identifier, 'node_id': record['node_id']}))
        value['checkpoints'].append(record); _save(manager, value)
    _store(manager).audit('policy_signing.checkpoint_created', actor, {'checkpoint_id': identifier, 'key_ids': record['key_ids']})
    return _public_checkpoint(record)


def _recovery_candidate(manager, value, identifier):
    record = next((item for item in value['checkpoints'] if item.get('id') == identifier), None)
    if record is None:
        raise ValueError('Choose a local signing checkpoint')
    path, expected, trust = _expected(manager)
    if _protected(manager, path, missing=True) is not None:
        raise ValueError('Same-key recovery only recreates a missing key; an existing or unsafe key is preserved for review')
    current_node = str(getattr(manager.app, 'controller_id', '') or 'standalone')[:128]
    private = json.loads(manager.vault.get(record['secret_ref']))
    seed = base64.b64decode(private['seed'], validate=True)
    if seed != expected or private.get('public_trust') != trust or private.get('checkpoint_id') != identifier or private.get('node_id') != current_node or record.get('node_id') != current_node or record.get('deployment_id') != trust['deployment_id'] or record.get('key_ids') != sorted(trust['keys']):
        raise ValueError('The checkpoint does not match this node and current signing authority')
    return path, seed, trust


def recovery_preview(manager, body, actor):
    if not isinstance(body, dict) or set(body) != {'checkpoint_id'} or not isinstance(body['checkpoint_id'], str):
        raise ValueError('Choose exactly one local signing checkpoint')
    with _lease(manager):
        value = _state(manager)
        path, _, trust = _recovery_candidate(manager, value, body['checkpoint_id'])
        plan = {'id': uuid.uuid4().hex, 'checkpoint_id': body['checkpoint_id'], 'created_by': actor, 'created_at': stamp(), 'expires_at': stamp(now()+timedelta(minutes=10)),
                'deployment_id': trust['deployment_id'], 'key_ids': sorted(trust['keys']), 'confirmation_nonce': secrets.token_urlsafe(24), 'confirmation_phrase': CONFIRMATION,
                'can_apply': True, 'blockers': [], 'scope': 'Recreate only the missing current signing key. Public trust, deployment identity, endpoint pins and firewall policy remain unchanged.'}
        plan['digest'] = digest(plan)
        value['reviews'] = [item for item in value['reviews'] if parse_time(item['expires_at']) > now()][-(MAX_REVIEWS-1):] + [plan]
        _save(manager, value)
    _store(manager).audit('policy_signing.recovery_previewed', actor, {'review_id': plan['id'], 'checkpoint_id': plan['checkpoint_id']})
    return {key: item for key, item in plan.items() if key != 'created_by'}


def recovery_apply(manager, body, actor):
    allowed = {'preview_id', 'digest', 'confirmation_nonce', 'confirmation_phrase'}
    if not isinstance(body, dict) or set(body) != allowed:
        raise ValueError('Use the exact signing recovery review and confirmation')
    with _lease(manager):
        value = _state(manager)
        plan = next((item for item in value['reviews'] if item.get('id') == body.get('preview_id')), None)
        if not plan or plan.get('used_at') or plan['created_by'] != actor or parse_time(plan['expires_at']) <= now() or any(body.get(key) != plan[key] for key in ('digest', 'confirmation_nonce', 'confirmation_phrase')):
            raise WorkflowConflict('Use your fresh exact same-key recovery review', {})
        path, seed, trust = _recovery_candidate(manager, value, plan['checkpoint_id'])
        if plan['deployment_id'] != trust['deployment_id'] or plan['key_ids'] != sorted(trust['keys']):
            raise WorkflowConflict('The current signing authority changed; review again', {})
        # Publish complete, fsynced bytes atomically; a crash cannot leave a
        # partially written active seed and a racing key is never overwritten.
        descriptor, temporary = tempfile.mkstemp(prefix='.signing-recovery-', dir=path.parent)
        try:
            with os.fdopen(descriptor, 'wb') as output:
                output.write(seed); output.flush(); os.fsync(output.fileno())
            os.link(temporary, path)
            os.unlink(temporary)
            directory = os.open(path.parent, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
            try: os.fsync(directory)
            finally: os.close(directory)
            restored = PolicySigner(path, trust['deployment_id'])
            if restored.public_trust() != trust or _read_seed(manager, path) != seed:
                raise ValueError('Restored signing key read-back did not verify')
            result = _self_check(restored)
        except Exception:
            # Preserve uncertain material rather than pretending rollback succeeded.
            raise ValueError('Same-key recovery is incomplete; protected state requires review') from None
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
        plan['used_at'] = stamp(); value['last_check'] = result; _save(manager, value)
    _store(manager).audit('policy_signing.recovered', actor, {'review_id': plan['id'], 'checkpoint_id': plan['checkpoint_id'], 'key_ids': plan['key_ids']})
    return {'status': 'restored', 'deployment_id': trust['deployment_id'], 'key_ids': sorted(trust['keys']), 'self_check': result}
