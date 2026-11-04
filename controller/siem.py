"""Opt-in, reviewed HTTPS JSON audit/security export with a bounded durable outbox.

This is acknowledgement-based delivery, not a lossless connection ledger. Source
transactions never perform network I/O. The queue is bounded; overflow is counted
and surfaced, while the original audit/alert records stay in their own stores.
"""
from __future__ import annotations

import base64
from datetime import timedelta
import hashlib
import hmac
import ipaddress
import json
import re
import secrets
import ssl
from urllib.parse import urlsplit
import uuid

from . import notifications as net
from .firewall import WorkflowConflict
from .store import digest, now, parse_time, stamp

PURPOSE = 'siem-export-v1'
MAX_QUEUED = 50000
BATCH_SIZE = 100
MAX_ATTEMPTS = 8
HISTORY_LIMIT = 1000
LEASE_SECONDS = 120
SCHEMA = 'prthak.siem.v1'
ERRORS = {
    'connection': 'The reviewed SIEM destination could not be reached securely.',
    'destination_changed': 'SIEM destination addresses changed; review them again.',
    'provider_rejected': 'The SIEM receiver rejected this batch.',
    'provider_temporary': 'The SIEM receiver reported a temporary failure.',
    'ambiguous': 'Receiver acknowledgement is unknown; this batch may already have arrived.',
    'configuration_changed': 'The destination changed or export was disabled; explicitly review retry.',
    'exhausted': 'Automatic retry limit reached; review this batch.',
    'lease_expired': 'The sending controller stopped before recording acknowledgement.',
}


def initialize(db):
    for table in ('siem_settings', 'siem_reviews'):
        db.execute(f'CREATE TABLE IF NOT EXISTS {table} (id TEXT PRIMARY KEY,data TEXT NOT NULL)')
    db.executescript('''
      CREATE TABLE IF NOT EXISTS siem_cursor (
        id TEXT PRIMARY KEY,sequence BIGINT NOT NULL,queued BIGINT NOT NULL,
        overflow BIGINT NOT NULL,last_dropped_sequence BIGINT NOT NULL,
        acknowledged BIGINT NOT NULL,stream_id TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS siem_events (
        sequence BIGINT PRIMARY KEY,event_key TEXT NOT NULL UNIQUE,batch_id TEXT,
        configuration_revision BIGINT NOT NULL,binding TEXT NOT NULL,
        destination TEXT NOT NULL,data TEXT NOT NULL);
      CREATE INDEX IF NOT EXISTS siem_event_unbatched ON siem_events(batch_id,sequence);
      CREATE INDEX IF NOT EXISTS siem_event_revision ON siem_events(batch_id,configuration_revision,binding,sequence);
      CREATE TABLE IF NOT EXISTS siem_deliveries (
        id TEXT PRIMARY KEY,status TEXT NOT NULL,next_attempt_at TEXT NOT NULL,
        lease_until TEXT,created_at TEXT NOT NULL,data TEXT NOT NULL);
      CREATE INDEX IF NOT EXISTS siem_delivery_due ON siem_deliveries(status,next_attempt_at);
    ''')


def _store(manager):
    return net._store(manager)


def _settings(store, db):
    return store._get(db, 'siem_settings', 'settings') or {'id': 'settings', 'revision': 0, 'enabled': False, 'destination': None}


def _key(manager):
    try:
        key = manager.shared_secret_key(PURPOSE)
        if not isinstance(key, bytes) or len(key) != 32:
            raise ValueError()
        return key
    except Exception:
        raise ValueError('Encrypted SIEM destination state is unavailable') from None


def _seal(manager, value, label):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(_key(manager)).encrypt(nonce, json.dumps(value, sort_keys=True).encode(), (PURPOSE + ':' + label).encode())
    return {'nonce': base64.b64encode(nonce).decode(), 'ciphertext': base64.b64encode(ciphertext).decode()}


def _open(manager, value, label):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    try:
        return json.loads(AESGCM(_key(manager)).decrypt(base64.b64decode(value['nonce'], validate=True), base64.b64decode(value['ciphertext'], validate=True), (PURPOSE + ':' + label).encode()))
    except Exception:
        raise ValueError('Encrypted SIEM destination state is unavailable') from None


def _private(manager, config):
    return _open(manager, config['sealed'], 'config:' + str(config['revision'])) if config.get('sealed') else {}


def _public(channel):
    return {key: channel.get(key) for key in ('host', 'port', 'addresses', 'allow_private_network', 'idempotency_supported', 'audit_enabled', 'alerts_enabled', 'destination')} | {
        'credential_flags': {key + '_configured': bool(channel.get(key)) for key in ('auth_token', 'signing_secret', 'custom_ca_pem', 'url')}}


def _normalize(manager, body, current, resolver):
    allowed = {'expected_revision', 'enabled', 'url', 'auth_token', 'signing_secret', 'custom_ca_pem', 'allow_private_network', 'idempotency_supported', 'audit_enabled', 'alerts_enabled'}
    if not isinstance(body, dict) or set(body) - allowed or type(body.get('enabled')) is not bool:
        raise ValueError('Provide SIEM enabled state and the supported destination fields')
    previous = _private(manager, current)
    result = {}
    for name, default in (('allow_private_network', False), ('idempotency_supported', False), ('audit_enabled', True), ('alerts_enabled', True)):
        result[name] = body.get(name, previous.get(name, default))
        if type(result[name]) is not bool:
            raise ValueError('SIEM selections must be explicit booleans')
    for name in ('url', 'auth_token', 'signing_secret'):
        result[name] = net._secret(body, previous, name)
    if not result['url'] and not body['enabled']:
        return {'enabled': False, **result}
    parsed = urlsplit(result['url'])
    try:
        port = parsed.port if parsed.port is not None else 443
    except ValueError:
        raise ValueError('Use a complete HTTPS SIEM destination') from None
    if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or parsed.fragment or not 1 <= port <= 65535 or '\\' in result['url'] or any(char.isspace() for char in result['url']):
        raise ValueError('Use HTTPS without URL credentials, fragments or whitespace')
    if body['enabled'] and not (result['audit_enabled'] or result['alerts_enabled']):
        raise ValueError('Select audit events, security alerts or both')
    ca = body.get('custom_ca_pem') or previous.get('custom_ca_pem', '')
    if not isinstance(ca, str) or len(ca) > 65536:
        raise ValueError('Custom SIEM trust must be a bounded PEM CA bundle')
    if ca:
        try:
            ssl.create_default_context().load_verify_locations(cadata=ca)
        except Exception:
            raise ValueError('Custom SIEM CA certificates could not be verified') from None
    result.update(enabled=body['enabled'], host=parsed.hostname.lower(), port=port, custom_ca_pem=ca)
    result['addresses'] = net._addresses(result['host'], port, result['allow_private_network'], resolver)
    result['destination'] = 'https://' + result['host'] + (':' + str(port) if port != 443 else '') + '/…'
    result['binding'] = hmac.new(_key(manager), json.dumps(result, sort_keys=True).encode(), hashlib.sha256).hexdigest()
    return result


def get(manager):
    store = _store(manager)
    with store.read_meta() as db:
        config = _settings(store, db)
        row = db.execute('SELECT sequence,queued,overflow,last_dropped_sequence,acknowledged,stream_id FROM siem_cursor WHERE id=?', ('stream',)).fetchone() or (0, 0, 0, 0, 0, None)
        counts = {item[0]: item[1] for item in db.execute('SELECT status,COUNT(*) FROM siem_deliveries GROUP BY status')}
        oldest = db.execute('SELECT MIN(sequence) FROM siem_events').fetchone()[0]
    health = 'disabled' if not config['enabled'] else 'degraded' if row[2] or any(counts.get(key, 0) for key in ('held', 'failed', 'uncertain')) else 'queued' if row[1] else 'ready' if counts.get('delivered') else 'configured'
    return {key: config.get(key) for key in ('revision', 'enabled', 'destination', 'updated_at', 'updated_by')} | {
        'schema': SCHEMA, 'transport': 'https_json', 'health': health, 'queue_limit': MAX_QUEUED,
        'queued_events': row[1], 'last_sequence': row[0], 'overflow_events': row[2], 'last_dropped_sequence': row[3],
        'last_acknowledged_sequence': row[4], 'stream_id': row[5], 'oldest_pending_sequence': oldest,
        'delivery_counts': counts, 'history_limit': HISTORY_LIMIT, 'batch_size': BATCH_SIZE, 'disabled_by_default': True,
        'semantics': 'Future audit/security summaries only. HTTPS receiver acknowledgement is separate from SIEM indexing. Queue overflow is counted; original audit/alerts remain stored. No syslog transport or historical backfill.'}


def preview(manager, body, actor, *, resolver=None):
    store = _store(manager)
    with store.lock, store.meta() as db:
        current = _settings(store, db)
        if not isinstance(body, dict) or type(body.get('expected_revision')) is not int or body['expected_revision'] != current['revision']:
            raise WorkflowConflict('SIEM settings changed; reload before reviewing', {})
        private = _normalize(manager, body, current, resolver)
        identifier = uuid.uuid4().hex
        plan = {'id': identifier, 'expected_revision': current['revision'], 'summary': {'enabled': private['enabled'], 'destination': _public(private) if private.get('url') else None},
                'confirmation_nonce': secrets.token_urlsafe(24), 'confirmation_phrase': 'SAVE REVIEWED SIEM DESTINATION', 'created_by': actor,
                'expires_at': stamp(now() + timedelta(minutes=10)), 'blockers': [], 'can_apply': True}
        plan['digest'] = digest(plan)
        plan['sealed'] = _seal(manager, private, 'review:' + identifier)
        db.execute('DELETE FROM siem_reviews WHERE id IN (SELECT id FROM siem_reviews ORDER BY id DESC LIMIT 1000000 OFFSET 99)')
        store._put(db, 'siem_reviews', plan)
        store.audit('siem.reviewed', actor, {'review_id': identifier}, db)
    return {key: value for key, value in plan.items() if key not in ('sealed', 'created_by')}


def apply(manager, body, actor, *, resolver=None):
    store = _store(manager)
    with store.lock, store.meta() as db:
        plan = store._get(db, 'siem_reviews', body.get('preview_id')) if isinstance(body, dict) else None
        current = _settings(store, db)
        if not plan or plan.get('applied_revision') or plan['created_by'] != actor or parse_time(plan['expires_at']) <= now() or current['revision'] != plan['expected_revision'] or any(body.get(key) != plan[key] for key in ('digest', 'confirmation_nonce', 'confirmation_phrase')):
            raise WorkflowConflict('Use your fresh exact SIEM destination review', {})
        private = _open(manager, plan['sealed'], 'review:' + plan['id'])
        if private.get('url') and net._addresses(private['host'], private['port'], private['allow_private_network'], resolver) != private['addresses']:
            raise WorkflowConflict(ERRORS['destination_changed'], {})
        config = {'id': 'settings', 'revision': current['revision'] + 1, 'enabled': private['enabled'],
                  'destination': _public(private) if private.get('url') else None, 'binding': private.get('binding', ''), 'updated_at': stamp(), 'updated_by': actor}
        config['sealed'] = _seal(manager, private, 'config:' + str(config['revision']))
        store._put(db, 'siem_settings', config)
        plan['applied_revision'] = config['revision']; store._put(db, 'siem_reviews', plan)
        store.audit('siem.configured', actor, {'revision': config['revision'], 'enabled': config['enabled']}, db)
    return get(manager)


def _summary(category, value):
    """A fixed allowlist intentionally excludes arbitrary details and credentials."""
    fields = ('action', 'actor', 'created_at') if category == 'audit' else ('kind', 'severity', 'status', 'server_id', 'created_at', 'occurrence_id', 'resolved_at', 'acknowledged_at')
    event = {'category': 'audit' if category == 'audit' else 'security_alert', 'source_id': str(value.get('id', ''))[:128]}
    for key in fields:
        item = value.get(key)
        if isinstance(item, (str, int, bool)):
            event[key] = str(item)[:253].replace('\r', ' ').replace('\n', ' ')
    if category == 'alerts':
        event.update(_network_context(value))
    return event


def _network_context(value):
    """Read only typed network fields, never copy the alert's details object."""
    details = value.get('details') if isinstance(value.get('details'), dict) else {}
    def field(name):
        return value[name] if name in value else details.get(name)
    result = {}
    source = field('source_ip')
    if isinstance(source, str) and 1 <= len(source) <= 64 and '%' not in source:
        try:
            address = ipaddress.ip_address(source)
            family = 'ipv4' if address.version == 4 else 'ipv6'
            if not getattr(address, 'ipv4_mapped', None) and field('address_family') in (None, family):
                result.update(source_ip=str(address), address_family=family)
        except ValueError:
            pass
    port, protocol = field('port'), field('protocol')
    if type(port) is int and 1 <= port <= 65535 and isinstance(protocol, str) and protocol in ('tcp', 'udp'):
        result.update(port=port, protocol=protocol)
    return result


def record(db, category, value, previous=None):
    """Called inside the source transaction. Never resolve DNS or send traffic."""
    if category not in ('audit', 'alerts') or not isinstance(value, dict) or not value.get('id'):
        return False
    if category == 'audit' and str(value.get('action', '')).startswith('siem.'):
        return False
    from .store import Store
    config = _settings(Store, db)
    public = config.get('destination') or {}
    if not config['enabled'] or not public.get('audit_enabled' if category == 'audit' else 'alerts_enabled', False):
        return False
    event = _summary(category, value)
    if previous is not None and _summary(category, previous) == event:
        return False
    event_key = digest(event)
    if db.execute('SELECT sequence FROM siem_events WHERE event_key=?', (event_key,)).fetchone():
        return False
    row = db.execute('UPDATE siem_cursor SET sequence=sequence+1 WHERE id=? RETURNING sequence,queued,stream_id', ('stream',)).fetchone()
    if row is None:
        # Create the stream on the first eligible event. A disabled, unused
        # exporter must leave a new controller empty for HA join/migration.
        row = db.execute('''INSERT INTO siem_cursor(id,sequence,queued,overflow,last_dropped_sequence,acknowledged,stream_id)
            VALUES(?,1,0,0,0,0,?) ON CONFLICT(id) DO UPDATE SET sequence=siem_cursor.sequence+1
            RETURNING sequence,queued,stream_id''', ('stream', uuid.uuid4().hex)).fetchone()
    if row[1] >= MAX_QUEUED:
        db.execute('UPDATE siem_cursor SET overflow=overflow+1,last_dropped_sequence=? WHERE id=?', (row[0], 'stream'))
        return False
    event.update(schema=SCHEMA, stream_id=row[2], sequence=row[0], event_id=row[2] + ':' + str(row[0]), recorded_at=stamp())
    db.execute('INSERT INTO siem_events(sequence,event_key,batch_id,configuration_revision,binding,destination,data) VALUES(?,?,NULL,?,?,?,?)', (row[0], event_key, config['revision'], config['binding'], public['destination'], json.dumps(event, separators=(',', ':'))))
    db.execute('UPDATE siem_cursor SET queued=queued+1 WHERE id=?', ('stream',))
    return True


def _put_delivery(db, value):
    db.execute('INSERT INTO siem_deliveries(id,status,next_attempt_at,lease_until,created_at,data) VALUES(?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET status=excluded.status,next_attempt_at=excluded.next_attempt_at,lease_until=excluded.lease_until,data=excluded.data',
               (value['id'], value['status'], value['next_attempt_at'], value.get('lease_until'), value['created_at'], json.dumps(value, sort_keys=True)))


def _cas(db, original, value):
    return db.execute('UPDATE siem_deliveries SET status=?,next_attempt_at=?,lease_until=?,data=? WHERE id=? AND data=? RETURNING id', (value['status'], value['next_attempt_at'], value.get('lease_until'), json.dumps(value, sort_keys=True), value['id'], original)).fetchone() is not None


def _batch(db, at):
    first = db.execute('SELECT configuration_revision,binding,destination FROM siem_events WHERE batch_id IS NULL ORDER BY sequence LIMIT 1').fetchone()
    if not first:
        return
    rows = db.execute('SELECT sequence,data FROM siem_events WHERE batch_id IS NULL AND configuration_revision=? AND binding=? ORDER BY sequence LIMIT ?', (first[0], first[1], BATCH_SIZE)).fetchall()
    identifier = uuid.uuid4().hex
    events = [json.loads(row[1]) for row in rows]
    value = {'id': identifier, 'status': 'pending', 'attempts': 0, 'next_attempt_at': stamp(at), 'lease_until': None, 'created_at': stamp(at), 'updated_at': stamp(at),
             'configuration_revision': first[0], 'binding': first[1], 'destination': first[2], 'first_sequence': rows[0][0], 'last_sequence': rows[-1][0], 'event_count': len(events), 'events': events, 'error': ''}
    _put_delivery(db, value)
    db.executemany('UPDATE siem_events SET batch_id=? WHERE sequence=? AND batch_id IS NULL', [(identifier, row[0]) for row in rows])


def _public_delivery(value):
    return {key: value.get(key) for key in ('id', 'status', 'attempts', 'next_attempt_at', 'created_at', 'updated_at', 'destination', 'first_sequence', 'last_sequence', 'event_count', 'error', 'receipt')}


def deliveries(store, limit=50, offset=0):
    if type(limit) is not int or not 1 <= limit <= 200 or type(offset) is not int or offset < 0:
        raise ValueError('Choose a bounded SIEM delivery page')
    with store.read_meta() as db:
        rows = db.execute('SELECT data FROM siem_deliveries ORDER BY created_at DESC,id DESC LIMIT ? OFFSET ?', (limit, offset)).fetchall()
        total = db.execute('SELECT COUNT(*) FROM siem_deliveries').fetchone()[0]
    return {'items': [_public_delivery(json.loads(row[0])) for row in rows], 'total': total, 'limit': limit, 'offset': offset, 'has_more': offset + len(rows) < total}


def dispatch(channel, delivery):
    if net._addresses(channel['host'], channel['port'], channel['allow_private_network']) != channel['addresses']:
        raise net.DeliveryFailure('held', 'destination_changed')
    payload = json.dumps({'schema': SCHEMA, 'batch_id': delivery['id'], 'events': delivery['events']}, sort_keys=True, separators=(',', ':')).encode()
    timestamp = str(int(now().timestamp()))
    headers = {'Content-Type': 'application/json', 'User-Agent': 'Prthak-SIEM/1', 'Idempotency-Key': delivery['id'], 'X-Prthak-Timestamp': timestamp}
    if channel.get('auth_token'):
        headers['Authorization'] = 'Bearer ' + channel['auth_token']
    if channel.get('signing_secret'):
        headers['X-Prthak-Signature'] = 'v1=' + hmac.new(channel['signing_secret'].encode(), timestamp.encode() + b'.' + payload, hashlib.sha256).hexdigest()
    address = channel['addresses'][(delivery['attempts'] - 1) % len(channel['addresses'])]
    connection = net.PinnedHTTPS(channel['host'], channel['port'], address, net._tls(channel))
    parsed = urlsplit(channel['url']); transmitting = False
    try:
        connection.connect(); transmitting = True
        connection.request('POST', (parsed.path or '/') + ('?' + parsed.query if parsed.query else ''), payload, headers)
        response = connection.getresponse(); body = response.read(65537)
        if 200 <= response.status < 300 and len(body) <= 65536:
            return {'transport': 'https_json', 'status_code': response.status}
        if response.status in (408, 425, 429) or 500 <= response.status <= 599:
            raise net.DeliveryFailure('retry', 'provider_temporary', response.status)
        raise net.DeliveryFailure('failed', 'provider_rejected', response.status)
    except net.DeliveryFailure:
        raise
    except Exception:
        raise net.DeliveryFailure('retry' if not transmitting or channel['idempotency_supported'] else 'uncertain', 'connection' if not transmitting else 'ambiguous') from None
    finally:
        connection.close()


def run_once(manager, *, transport=None, limit=5, at=None):
    store, at = _store(manager), at or now()
    if getattr(manager.app, 'demo', False):
        return {'processed': 0, 'demo_blocked': True}
    processed = 0
    for _ in range(min(5, max(0, limit))):
        with store.lock, store.meta() as db:
            config = _settings(store, db)
            if not config.get('sealed'):
                return {'processed': processed}
            private = _private(manager, config)
            for row in db.execute("SELECT data FROM siem_deliveries WHERE status='in_flight' AND lease_until<=? LIMIT 5", (stamp(at),)):
                abandoned = json.loads(row[0])
                abandoned.update(status='retry' if private.get('idempotency_supported') and abandoned['binding'] == config.get('binding') else 'uncertain', error=ERRORS['lease_expired'], lease_until=None, updated_at=stamp(at))
                _cas(db, row[0], abandoned)
            row = db.execute("SELECT data FROM siem_deliveries WHERE status IN ('pending','retry') AND next_attempt_at<=? ORDER BY next_attempt_at,id LIMIT 1", (stamp(at),)).fetchone()
            if not row:
                _batch(db, at)
                row = db.execute("SELECT data FROM siem_deliveries WHERE status='pending' ORDER BY created_at,id LIMIT 1").fetchone()
            if not row:
                break
            delivery = json.loads(row[0])
            if not config['enabled'] or delivery['binding'] != config.get('binding'):
                delivery.update(status='held', error=ERRORS['configuration_changed'], updated_at=stamp(at)); _cas(db, row[0], delivery)
                continue
            if delivery['attempts'] >= delivery.get('retry_budget', MAX_ATTEMPTS):
                delivery.update(status='failed', error=ERRORS['exhausted'], updated_at=stamp(at)); _cas(db, row[0], delivery)
                continue
            lease = uuid.uuid4().hex
            delivery.update(status='in_flight', attempts=delivery['attempts'] + 1, lease_token=lease, lease_until=stamp(at + timedelta(seconds=LEASE_SECONDS)), updated_at=stamp(at))
            if not _cas(db, row[0], delivery):
                continue
        try:
            receipt = (transport or dispatch)(private, delivery)
            if not isinstance(receipt, dict) or type(receipt.get('status_code')) is not int or not 200 <= receipt['status_code'] < 300:
                raise ValueError('Unverified acknowledgement')
            result = {'status': 'delivered', 'receipt': {'transport': 'https_json', 'status_code': receipt['status_code']}, 'error': ''}
        except net.DeliveryFailure as error:
            outcome = error.outcome if error.outcome in ('retry', 'held', 'uncertain', 'failed') else 'uncertain'
            result = {'status': outcome, 'error': ERRORS.get(error.code, ERRORS['ambiguous'])}
            if outcome == 'retry' and delivery['attempts'] >= delivery.get('retry_budget', MAX_ATTEMPTS):
                result.update(status='failed', error=ERRORS['exhausted'])
        except Exception:
            result = {'status': 'uncertain', 'error': ERRORS['ambiguous']}
        with store.lock, store.meta() as db:
            saved = db.execute('SELECT data FROM siem_deliveries WHERE id=?', (delivery['id'],)).fetchone()
            current = json.loads(saved[0]) if saved else None
            if current and current['status'] == 'in_flight' and current.get('lease_token') == lease:
                current.update(result, lease_until=None, updated_at=stamp(at), next_attempt_at=stamp(at + timedelta(seconds=min(3600, 30 * 2 ** min(7, current['attempts'] - 1)))))
                if result['status'] == 'delivered':
                    current.pop('events', None)
                if _cas(db, saved[0], current):
                    if result['status'] == 'delivered':
                        count = db.execute('SELECT COUNT(*) FROM siem_events WHERE batch_id=?', (current['id'],)).fetchone()[0]
                        db.execute('DELETE FROM siem_events WHERE batch_id=?', (current['id'],))
                        db.execute('UPDATE siem_cursor SET queued=queued-?,acknowledged=CASE WHEN acknowledged<? THEN ? ELSE acknowledged END WHERE id=?', (count, current['last_sequence'], current['last_sequence'], 'stream'))
                        db.execute("DELETE FROM siem_deliveries WHERE id IN (SELECT id FROM siem_deliveries WHERE status='delivered' ORDER BY created_at DESC,id DESC LIMIT 1000000 OFFSET ?)", (HISTORY_LIMIT,))
                    store.audit('siem.delivery_outcome', 'siem-worker', {'delivery_id': current['id'], 'status': current['status'], 'attempts': current['attempts']}, db)
        processed += 1
    return {'processed': processed}


def retry(manager, body, actor):
    store = _store(manager)
    with store.lock, store.meta() as db:
        config = _settings(store, db)
        identifier = body.get('delivery_id') if isinstance(body, dict) else None
        value = store._get(db, 'siem_deliveries', identifier) if isinstance(identifier, str) else None
        if not value or value['status'] not in ('failed', 'uncertain', 'held') or not config['enabled'] or type(body.get('expected_revision')) is not int or body['expected_revision'] != config['revision'] or type(body.get('expected_attempts')) is not int or body['expected_attempts'] != value['attempts'] or body.get('confirm_possible_duplicate') is not True:
            raise WorkflowConflict('Review the current batch, enabled destination and possible duplicate before retrying', {})
        if value['attempts'] >= 20:
            raise ValueError('This SIEM batch reached its bounded operator retry limit')
        private = _private(manager, config)
        value.update(status='retry', next_attempt_at=stamp(), retry_budget=min(20, value['attempts'] + MAX_ATTEMPTS), binding=config['binding'], configuration_revision=config['revision'], destination=private['destination'], error='', updated_at=stamp())
        _put_delivery(db, value)
        store.audit('siem.retry_requested', actor, {'delivery_id': identifier, 'attempts': value['attempts']}, db)
    return _public_delivery(value)
