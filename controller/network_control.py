"""Explicit, signed outbound policies and expiring emergency quarantine.

Read-only assessment precedes review. Each application freezes exact endpoints,
native context and a separately bound single-Admin proof. Ordinary inbound
policy saves never activate either feature or opt future group members in.
"""
from __future__ import annotations

import copy
from datetime import timedelta
import json
import re
import secrets
import uuid

from . import approvals
from .firewall import WorkflowConflict
from .host_default_deny import _selection
from .network_addresses import network
from .review_limits import MAX_REVIEW_BYTES, encoded_size
from .store import digest, now, parse_time, stamp

KINDS = {'egress': ('egress_control_v1', 'egress_policy', 'egress_bundle'), 'quarantine': ('emergency_quarantine_v1', 'emergency_quarantine', 'quarantine')}
OPERATIONS = {'egress': {'assess', 'apply', 'remove'}, 'quarantine': {'assess', 'enable', 'disable'}}
STATUSES = {'unverified', 'ready', 'assessed', 'enforced', 'removed', 'quarantined', 'released', 'expired', 'rolled_back', 'error', 'blocked', 'pending', 'unknown', 'idle'}
DIGEST = re.compile(r'[a-f0-9]{64}\Z')
ID = re.compile(r'[A-Za-z0-9_.:-]{1,128}\Z')
MAX_PLANS = 1000
FRESH_SECONDS = 180
ZERO = '0'*64


def initialize(db):
    db.execute('CREATE TABLE IF NOT EXISTS network_control_plans (id TEXT PRIMARY KEY,created_at TEXT NOT NULL,status TEXT NOT NULL,data TEXT NOT NULL)')
    db.execute('CREATE INDEX IF NOT EXISTS network_control_plan_history ON network_control_plans(created_at,id)')
    db.execute('CREATE TABLE IF NOT EXISTS network_control_assignments (id TEXT PRIMARY KEY,data TEXT NOT NULL)')


def _plan(db, value):
    encoded_size(value)
    db.execute('INSERT INTO network_control_plans(id,created_at,status,data) VALUES(?,?,?,?) ON CONFLICT(id) DO UPDATE SET status=excluded.status,data=excluded.data', (value['id'], value['created_at'], value['status'], json.dumps(value, separators=(',', ':'))))


def _public(value):
    return {key: copy.deepcopy(value[key]) for key in ('id', 'kind', 'operation', 'status', 'created_at', 'created_by', 'expires_at', 'server_ids', 'group_ids', 'digest', 'confirmation_nonce', 'confirmation_phrase', 'preview', 'can_apply', 'blockers', 'confirmed_at', 'assessment') if key in value}


def get(store, identifier):
    with store.read_meta() as db:
        value = store._get(db, 'network_control_plans', identifier)
        if not value: raise KeyError(identifier)
        result = _public(value)
        for target in result.get('preview', {}).get('targets', []):
            server = store._get(db, 'servers', target['server_id']) or {}
            target['last_report'] = (server.get('network_control') or {}).get(value['kind'])
            target['last_report_at'] = (server.get('network_control') or {}).get('checked_at')
        return result


def listing(store, limit=50, offset=0):
    if type(limit) is not int or not 1 <= limit <= 100 or type(offset) is not int or offset < 0:
        raise ValueError('Choose a bounded network-control history page')
    with store.read_meta() as db:
        rows = db.execute('SELECT data FROM network_control_plans ORDER BY created_at DESC,id DESC LIMIT ? OFFSET ?', (limit, offset)).fetchall()
        total = db.execute('SELECT COUNT(*) FROM network_control_plans').fetchone()[0]
    return {'items': [_public(json.loads(row[0])) for row in rows], 'total': total, 'limit': limit, 'offset': offset, 'has_more': offset+len(rows)<total,
            'inbound_unchanged': True, 'disabled_by_default': True, 'quarantine_max_seconds': 3600}


def _fresh(value, seconds=FRESH_SECONDS):
    try: return now()-timedelta(seconds=seconds) <= parse_time(value) <= now()+timedelta(seconds=60)
    except (ValueError, TypeError): return False


def public_summary(server):
    metadata = server.get('network_control') or {}
    interval = server.get('control_interval_seconds', 60)
    interval = interval if type(interval) is int and 5<=interval<=3600 else 60
    stale = not _fresh(metadata.get('checked_at'), max(180, 3*interval)) or not _fresh(server.get('last_seen'), max(180, 3*interval))
    context_ok = not metadata.get('blockers') and all(isinstance(metadata.get(key), str) and DIGEST.fullmatch(metadata[key]) for key in ('context_digest', 'protection_digest', 'configuration_digest'))
    current_configuration = (server.get('configuration_state') or {}).get('digest')
    current_protection = (server.get('protection') or {}).get('digest') or server.get('protection_digest')
    context_ok = bool(context_ok and (not current_configuration or current_configuration==metadata.get('configuration_digest')) and (not current_protection or current_protection==metadata.get('protection_digest')))
    stale = stale or not context_ok
    result = {'checked_at': metadata.get('checked_at'), 'stale': stale}
    for kind in KINDS:
        feature = metadata.get(kind) or {}
        active = feature.get('active', feature.get('status')==('enforced' if kind=='egress' else 'quarantined'))
        verified = bool(context_ok and feature.get('ready') is True and feature.get('supported') is True and feature.get('status')!='unverified')
        result[kind] = {'status': feature.get('status', 'unknown'), 'last_operation_status': feature.get('status', 'unknown'), 'active': active,
                        'stale': stale or not verified, 'verified': verified and not stale, 'unverified': not verified, 'error': str(feature.get('error', ''))[:240]}
        if kind == 'quarantine':
            expires = feature.get('active_expires_at') if active and feature.get('active_expires_at') else feature.get('expires_at')
            result[kind]['expires_at'] = expires
            result[kind]['active_expires_at'] = feature.get('active_expires_at')
            try: expired = bool(expires and parse_time(expires)<=now() and (active or feature.get('status')=='quarantined'))
            except ValueError: expired = False
            result[kind]['expiry_unconfirmed'] = expired
            if expired: result[kind]['status'] = 'expiry_unconfirmed'
    return result


def _services(values):
    if not isinstance(values, list) or len(values)>100:
        raise ValueError('Provide at most 100 outbound destination/port rows')
    merged = {}
    for item in values:
        if not isinstance(item, dict) or set(item) != {'port', 'protocol', 'destinations'} or type(item['port']) is not int or not 1<=item['port']<=65535 or item['protocol'] not in ('tcp', 'udp') or not isinstance(item['destinations'], list) or not 0<=len(item['destinations'])<=1000:
            raise ValueError('Each outbound row needs a TCP/UDP port and at most 1000 destination CIDRs; an empty list denies the selected port')
        destinations = {str(network(value)) for value in item['destinations']}
        merged.setdefault((item['protocol'], item['port']), set()).update(destinations)
    result = [{'protocol': proto, 'port': port, 'destinations': sorted(values)} for (proto, port), values in sorted(merged.items())]
    if len(result)>64 or any(len(row['destinations'])>64 for row in result) or sum(len(row['destinations']) for row in result)>128:
        raise ValueError('The native outbound apply budget is 64 normalized rows, 64 destinations per row and 128 destination entries in total')
    return result


def _input(body, *, assessment=False):
    allowed = {'kind', 'server_ids', 'group_ids'} if assessment else {'kind', 'operation', 'server_ids', 'group_ids', 'default_deny', 'services', 'ttl_seconds'}
    if not isinstance(body, dict) or set(body)-allowed or not isinstance(body.get('kind'), str) or body['kind'] not in KINDS:
        raise ValueError('Choose outbound policy or emergency quarantine with explicit endpoints/groups')
    kind = body['kind']; operation = 'assess' if assessment else body.get('operation')
    if not isinstance(operation, str) or operation not in OPERATIONS[kind] or not assessment and operation=='assess':
        raise ValueError('Choose the supported operation; use fresh assessment separately')
    result = {'kind': kind, 'operation': operation, 'selection': {key: body.get(key, []) for key in ('server_ids', 'group_ids')}}
    if kind == 'egress':
        if 'ttl_seconds' in body: raise ValueError('Quarantine duration is not an outbound-policy field')
        default = body.get('default_deny', False)
        if type(default) is not bool: raise ValueError('Outbound default deny must be an explicit boolean')
        services = _services(body.get('services', []))
        if operation in ('assess', 'remove') and (default or services): raise ValueError('Assessment/removal cannot carry a new outbound grant matrix')
        result.update(default_deny=default, services=services)
    else:
        if any(key in body for key in ('default_deny', 'services')): raise ValueError('Quarantine is separate from an outbound grant matrix')
        ttl = body.get('ttl_seconds', 900)
        if type(ttl) is not int or not 60<=ttl<=3600: raise ValueError('Quarantine duration must be 60..3600 seconds')
        result['ttl_seconds'] = ttl
    return result


def _binding(store, db, server, kind):
    state = store._get(db, 'network_control_assignments', server['id']) or {'id': server['id']}
    feature = state.get(kind) or {}
    metadata = server.get('network_control') or {}
    return {'ips': server.get('ips', []), 'protection_digest': (server.get('protection') or {}).get('digest', ''),
            'configuration_digest': (server.get('configuration_state') or {}).get('digest', ''), 'context_digest': metadata.get('context_digest', ''),
            'generation_floor': feature.get('generation_floor', 0), 'assessment_id': (metadata.get(kind) or {}).get('id', '')}


def _blockers(store, db, server, kind, *, assessment=False):
    reasons = []
    capability = KINDS[kind][0]
    if capability not in server.get('capabilities', []) or 'signed_assignments_v1' not in server.get('capabilities', []): reasons.append('Upgrade to an agent reporting '+capability+' and signed assignments')
    if assessment: return reasons
    protected, configuration = server.get('protection') or {}, server.get('configuration_state') or {}
    metadata = server.get('network_control') or {}; feature = metadata.get(kind) or {}
    if not server.get('ips') or not _fresh(server.get('last_seen')): reasons.append('A fresh authenticated endpoint heartbeat and reported IPs are required')
    if protected.get('ready') is not True or not _fresh(server.get('protection_reported_at')): reasons.append('A fresh ready SSH/controller protection baseline is required')
    if not DIGEST.fullmatch(configuration.get('digest', '')) or any(configuration.get(key) is not True for key in ('enforce', 'allow_firewall_changes', 'allow_host_default_deny')): reasons.append('Enable all three existing local enforcement/firewall/whole-host opt-ins through a signed configuration kit')
    if not _fresh(metadata.get('checked_at')) or not DIGEST.fullmatch(metadata.get('context_digest', '')) or metadata.get('protection_digest') != protected.get('digest') or metadata.get('configuration_digest') != configuration.get('digest'): reasons.append('Request a new native assessment for the exact current configuration and protection')
    if feature.get('supported') is not True or feature.get('ready') is not True: reasons.append('The endpoint has not reported a supported, ready '+kind+' adapter')
    reasons.extend(metadata.get('blockers') or [])
    current = store._get(db, 'network_control_assignments', server['id']) or {}
    request = (current.get(kind) or {}).get('descriptor') or {}
    if not request or feature.get('id') != request.get('id') or feature.get('plan_digest') != request.get('plan_digest') or feature.get('generation') != request.get('generation') or not _fresh(metadata.get('checked_at')) or parse_time(metadata['checked_at']) < parse_time(request['issued_at']):
        reasons.append('Complete the latest signed assessment or current operation before preparing another change')
    return reasons


def _descriptor(store, db, server, request, at):
    kind, operation = request['kind'], request['operation']
    binding = _binding(store, db, server, kind)
    generation = binding['generation_floor']+1
    if not 1<=generation<=2147483647: raise ValueError('Network-control generation limit reached; controlled recovery is required')
    value = {'schema_version': 1, 'id': uuid.uuid4().hex, 'generation': generation, 'operation': operation,
             'protection_digest': binding['protection_digest'] if DIGEST.fullmatch(binding['protection_digest']) else ZERO,
             'context_digest': binding['context_digest'] if DIGEST.fullmatch(binding['context_digest']) else ZERO,
             'issued_at': stamp(at), 'approval_expires_at': stamp(at+timedelta(minutes=15)), 'downtime_ack': operation!='assess'}
    if kind == 'egress': value.update(default_deny=request['default_deny'], services=request['services'])
    else: value['expires_at'] = stamp(at+timedelta(seconds=request['ttl_seconds'] if operation=='enable' else 3600))
    value['plan_digest'] = digest(value)
    return value, binding


def _publish(store, db, server_id, kind, descriptor, parent_id):
    state = store._get(db, 'network_control_assignments', server_id) or {'id': server_id}
    state[kind] = {'generation_floor': descriptor['generation'], 'descriptor': descriptor, 'parent_id': parent_id, 'queued_at': stamp(), 'status': 'pending'}
    store._put(db, 'network_control_assignments', state)


def _prune(db):
    # Assignment floors live separately and are never rewound by history pruning.
    db.execute('DELETE FROM network_control_plans WHERE id IN (SELECT id FROM network_control_plans ORDER BY created_at DESC,id DESC LIMIT 1000000 OFFSET ?)', (MAX_PLANS,))


def _prepare(store, body, actor, principal, *, assessment=False):
    request = _input(body, assessment=assessment); at = now()
    with store.lock, store.meta() as db:
        person = approvals.identity(store, db, actor, principal)
        ids, groups = _selection(store, db, request['selection'])
        identifier = uuid.uuid4().hex; targets, children, snapshots, blockers = [], {}, {}, []; remaining = MAX_REVIEW_BYTES
        for server_id in ids:
            server = store._get(db, 'servers', server_id)
            if not server: raise ValueError('A selected endpoint no longer exists')
            reasons = _blockers(store, db, server, request['kind'], assessment=assessment)
            descriptor, binding = _descriptor(store, db, server, request, at)
            child = {'id': descriptor['id'], 'plan_digest': descriptor['plan_digest'], 'created_at': stamp(at)}
            approvals.request(store, db, child, actor, principal, endpoint_ids=[server_id], scope_kind=KINDS[request['kind']][1])
            children[server_id] = {'descriptor': descriptor, 'approval_plan': child}
            snapshots[server_id] = binding
            target = {'server_id': server_id, 'hostname': server['hostname'], 'ips': server.get('ips', []), 'descriptor': descriptor,
                      'protected_egress': (server.get('network_control') or {}).get('protected_egress', []), 'management': server.get('protection') or {}, 'blockers': reasons}
            remaining -= encoded_size({'target': target, 'child': children[server_id], 'snapshot': binding}, remaining)
            targets.append(target)
            blockers.extend(server_id+': '+reason for reason in reasons)
        plan = {'id': identifier, 'kind': request['kind'], 'operation': request['operation'], 'status': 'draft', 'assessment': assessment,
                'request': request, 'selection_snapshot': groups, 'snapshots': snapshots, 'children': children, 'server_ids': ids, 'group_ids': sorted(set(body.get('group_ids', []))),
                'preview': {'targets': targets}, 'blockers': blockers, 'can_apply': not blockers, 'created_at': stamp(at), 'created_by': actor,
                'expires_at': stamp(at+timedelta(minutes=10)), 'confirmation_nonce': secrets.token_urlsafe(24),
                'confirmation_phrase': ('APPLY OUTBOUND CHANGE TO ' if request['kind']=='egress' else 'APPLY QUARANTINE CHANGE TO ')+str(len(ids))+' SERVERS'}
        if request['kind']=='quarantine' and request['operation']=='enable': plan['expires_at'] = min(plan['expires_at'], stamp(at+timedelta(seconds=request['ttl_seconds']-30)))
        plan['digest'] = digest({**{key: plan[key] for key in ('id', 'request', 'selection_snapshot', 'snapshots')}, 'descriptors': {key: child['descriptor'] for key, child in children.items()}})
        if assessment and not blockers:
            for server_id, child in children.items():
                proof = approvals.decide(store, db, child['approval_plan'], actor, principal)
                descriptor = {**child['descriptor'], 'approval_proof': proof}
                _publish(store, db, server_id, request['kind'], descriptor, identifier)
            plan.update(status='queued', confirmed_at=stamp(), confirmation_nonce='')
        _plan(db, plan); _prune(db)
        store.audit('network_control.assessment_queued' if assessment else 'network_control.previewed', actor, {'plan_id': identifier, 'kind': request['kind'], 'operation': request['operation'], 'server_ids': ids}, db)
    return _public(plan)


def assess(store, body, actor, principal):
    return _prepare(store, body, actor, principal, assessment=True)


def preview(store, body, actor, principal):
    return _prepare(store, body, actor, principal)


def confirm(store, identifier, body, actor, principal):
    expected = {'digest', 'confirmation_nonce', 'confirmation_phrase', 'acknowledge_downtime'}
    if not isinstance(body, dict) or set(body)!=expected or body.get('acknowledge_downtime') is not True:
        raise ValueError('Manually acknowledge downtime and type the exact current review phrase')
    with store.lock, store.meta() as db:
        approvals.identity(store, db, actor, principal)
        plan = store._get(db, 'network_control_plans', identifier)
        if not plan: raise KeyError(identifier)
        if plan.get('confirmed_request_digest')==digest(body) and plan.get('created_by')==actor and plan['status']=='queued': return {**_public(plan), 'duplicate': True}
        if plan['assessment'] or plan['created_by']!=actor or plan['status']!='draft' or parse_time(plan['expires_at'])<=now() or any(body.get(key)!=plan[key] for key in ('digest', 'confirmation_nonce', 'confirmation_phrase')):
            raise WorkflowConflict('Use your fresh exact network-control review and downtime acknowledgement', {})
        ids, groups = _selection(store, db, plan['request']['selection'])
        if ids!=plan['server_ids'] or groups!=plan['selection_snapshot']: raise WorkflowConflict('Selected group membership changed; review again', {})
        for server_id, child in plan['children'].items():
            server = store._get(db, 'servers', server_id)
            if not server or _binding(store, db, server, plan['kind'])!=plan['snapshots'][server_id]: raise WorkflowConflict('Endpoint IPs, configuration, context or generation changed; review again', {})
            blockers = _blockers(store, db, server, plan['kind'])
            if blockers: raise ValueError(blockers[0])
            descriptor = child['descriptor']
            if parse_time(descriptor['approval_expires_at'])<=now() or plan['operation']=='enable' and parse_time(descriptor['expires_at'])<=now()+timedelta(seconds=30): raise WorkflowConflict('The exact operation validity window expired; review again', {})
            proof = approvals.decide(store, db, child['approval_plan'], actor, principal)
            _publish(store, db, server_id, plan['kind'], {**descriptor, 'approval_proof': proof}, identifier)
        plan.update(status='queued', confirmed_at=stamp(), confirmation_nonce='', confirmed_request_digest=digest(body))
        _plan(db, plan)
        store.audit('network_control.pushed', actor, {'plan_id': identifier, 'kind': plan['kind'], 'operation': plan['operation'], 'server_ids': ids, 'acknowledge_downtime': True}, db)
    return _public(plan)


def assignment(store, db, server):
    state = store._get(db, 'network_control_assignments', server['id']) or {}
    result = {}
    for kind, (_, scope, field) in KINDS.items():
        descriptor = (state.get(kind) or {}).get('descriptor')
        if not descriptor or parse_time(descriptor['approval_expires_at'])<=now(): continue
        proof = descriptor.get('approval_proof') or {}
        if proof.get('scope', {}).get('kind')!=scope or not approvals.authorized(store, db, proof, plan_id=descriptor['id'], plan_digest=descriptor['plan_digest'], server_id=server['id']): continue
        if kind=='quarantine' and descriptor['operation']=='enable' and parse_time(descriptor['expires_at'])<=now(): continue
        result[field] = copy.deepcopy(descriptor)
    return result


def report(store, db, server, value):
    required = {'schema_version', 'checked_at', 'protection_digest', 'context_digest', 'configuration_digest', 'protected_egress', 'egress', 'quarantine', 'blockers'}
    if not isinstance(value, dict) or set(value)!=required or type(value.get('schema_version')) is not int or value['schema_version']!=1 or not all(isinstance(value.get(key), str) and (not value[key] or DIGEST.fullmatch(value[key])) for key in ('protection_digest', 'context_digest', 'configuration_digest')) or not isinstance(value['blockers'], list) or len(value['blockers'])>100 or any(not isinstance(item, str) or len(item)>500 for item in value['blockers']):
        raise ValueError('Invalid bounded network-control assessment report')
    parse_time(value['checked_at'])
    if parse_time(value['checked_at'])>now()+timedelta(seconds=60): raise ValueError('Network-control assessment time is in the future')
    routes = value['protected_egress']
    if not isinstance(routes, list) or len(routes)>256: raise ValueError('Too many protected outbound routes')
    for route in routes:
        if not isinstance(route, dict) or set(route)!={'destination', 'port', 'protocol', 'kind'} or route['kind'] not in ('controller', 'dns', 'dhcp') or route['protocol'] not in ('tcp', 'udp') or type(route['port']) is not int or not 1<=route['port']<=65535:
            raise ValueError('Invalid protected outbound route')
        network(route['destination'])
    for kind in KINDS:
        feature = value[kind]
        fields = {'supported', 'ready', 'status', 'id', 'plan_digest', 'generation', 'expires_at', 'error'}
        active_fields = {'active', 'active_id', 'active_plan_digest', 'active_generation', 'active_expires_at'}
        if not isinstance(feature, dict) or not fields<=set(feature) or set(feature)-fields-active_fields or set(feature)&active_fields and not active_fields<=set(feature) or type(feature['supported']) is not bool or type(feature['ready']) is not bool or not isinstance(feature['status'], str) or feature['status'] not in STATUSES or type(feature['generation']) is not int or not 0<=feature['generation']<=2147483647 or not isinstance(feature['error'], str) or len(feature['error'])>1024 or not isinstance(feature['id'], str) or feature['id'] and not ID.fullmatch(feature['id']) or not isinstance(feature['plan_digest'], str) or feature['plan_digest'] and not DIGEST.fullmatch(feature['plan_digest']):
            raise ValueError('Invalid network-control feature receipt')
        if feature['expires_at'] is not None: parse_time(feature['expires_at'])
        if 'active' in feature:
            if type(feature['active']) is not bool or type(feature['active_generation']) is not int or not 0<=feature['active_generation']<=2147483647 or not isinstance(feature['active_id'], str) or feature['active_id'] and not ID.fullmatch(feature['active_id']) or not isinstance(feature['active_plan_digest'], str) or feature['active_plan_digest'] and not DIGEST.fullmatch(feature['active_plan_digest']):
                raise ValueError('Invalid owned active network-control state')
            if feature['active'] and (not feature['active_id'] or not feature['active_plan_digest'] or feature['active_generation']<1): raise ValueError('Active network control needs its owned identity and generation')
            if feature['active_expires_at'] is not None: parse_time(feature['active_expires_at'])
            if kind=='quarantine' and feature['active'] and feature['active_expires_at'] is None: raise ValueError('Active quarantine needs its original owned expiry')
            if kind=='egress' and feature['active_expires_at'] is not None: raise ValueError('Outbound policy does not use a quarantine expiry')
    encoded_size(value, 65536)
    previous_report = server.get('network_control')
    if isinstance(previous_report, dict) and previous_report.get('checked_at'):
        previous_time, current_time = parse_time(previous_report['checked_at']), parse_time(value['checked_at'])
        if current_time < previous_time:
            return copy.deepcopy(previous_report)
        if current_time == previous_time:
            if previous_report != value:
                raise ValueError('A network-control timestamp cannot be reused for a divergent receipt')
            return copy.deepcopy(previous_report)
    server['network_control'] = copy.deepcopy(value)
    state = store._get(db, 'network_control_assignments', server['id']) or {}
    for kind in KINDS:
        feature = value[kind]; current = state.get(kind) or {}; descriptor = current.get('descriptor') or {}
        if descriptor and all(feature.get(key)==descriptor.get(key) for key in ('id', 'plan_digest', 'generation')):
            if kind=='quarantine' and descriptor['operation']=='enable' and feature['status']=='quarantined' and feature['expires_at']!=descriptor['expires_at']:
                raise ValueError('A quarantine receipt cannot omit or renew the original reviewed expiry')
            previous = current.get('receipt') or {}
            current.update(status=feature['status'], reported_at=stamp(), receipt=feature); state[kind] = current
            if _fresh(value['checked_at']):
                key = 'network-control:'+kind+':'+server['id']
                if feature['status'] in ('error', 'rolled_back', 'blocked'):
                    store._event(db, key, kind+'_control_error', 'warning' if feature['status']=='blocked' else 'critical', server['id'],
                                 kind.title()+' operation '+feature['status']+' on '+server['hostname'], {'operation_id': descriptor['id'], 'generation': descriptor['generation'], 'error': feature['error']})
                elif feature['status'] in ('enforced', 'removed', 'quarantined', 'released', 'expired') or feature['status']=='assessed' and feature['ready']:
                    store._resolve(db, key, server['id'], kind.title()+' operation recovered on '+server['hostname'])
                if kind=='quarantine':
                    active_key='quarantine-active:'+server['id']
                    if feature['status']=='quarantined' and descriptor['operation']=='enable' and feature['expires_at'] and parse_time(feature['expires_at'])>now():
                        store._event(db,active_key,'server_quarantined','critical',server['id'],'Emergency quarantine reported active on '+server['hostname'],{'operation_id':descriptor['id'],'expires_at':feature['expires_at']})
                    elif feature['status'] in ('released','expired'):
                        store._resolve(db,active_key,server['id'],'Quarantine release reported by '+server['hostname'])
                if any(previous.get(key)!=feature.get(key) for key in ('id','plan_digest','generation','status','error')):
                    store.audit('network_control.receipt','agent:'+server['id'],{'kind':kind,'operation_id':descriptor['id'],'generation':descriptor['generation'],'status':feature['status']},db)
    if state.get('id'): store._put(db, 'network_control_assignments', state)
    return server['network_control']


def witness(store, server_id, body):
    fields = {'kind', 'id', 'plan_digest', 'generation', 'protection_digest', 'context_digest', 'nonce', 'ssh_ports'}
    if not isinstance(body, dict) or set(body)!=fields or not isinstance(body.get('kind'), str) or body['kind'] not in KINDS:
        raise ValueError('Provide the exact network-control transaction and management nonce')
    with store.read_meta() as db:
        server = store._get(db, 'servers', server_id)
        if not server: raise KeyError(server_id)
        descriptor = assignment(store, db, server).get(KINDS[body['kind']][2])
        if not descriptor or descriptor['operation']=='assess' or any(body.get(key)!=descriptor[key] for key in ('id', 'plan_digest', 'generation', 'protection_digest', 'context_digest')):
            raise PermissionError('Network-control authority is absent, changed, revoked or expired')
        if type(body.get('generation')) is not int: raise ValueError('Network-control generation must be an integer')
        protected = server.get('protection') or {}
        metadata = server.get('network_control') or {}
        configuration = server.get('configuration_state') or {}
        if protected.get('digest')!=descriptor['protection_digest'] or protected.get('ready') is not True or not _fresh(metadata.get('checked_at')) or not _fresh(server.get('protection_reported_at')) or metadata.get('context_digest')!=descriptor['context_digest'] or metadata.get('configuration_digest')!=configuration.get('digest') or any(configuration.get(key) is not True for key in ('enforce', 'allow_firewall_changes', 'allow_host_default_deny')):
            raise PermissionError('Current protection/configuration differs from the reviewed network context')
        return {key: body[key] for key in ('kind', 'id', 'plan_digest', 'generation', 'protection_digest', 'context_digest')} | {
            'server_id': server_id, 'ips': server.get('ips', []), 'ssh_ports': protected.get('ssh_ports', []), 'management_sources': protected.get('management_sources', []),
            'configuration_digest': configuration['digest'], 'controller_origin': protected.get('controller_url', ''), 'controller_addresses': protected.get('controller_addresses', [])}


def invalidate_after_recovery(store, db):
    """Retain high-water/history, hold delivery; never undo native rules or TTL."""
    from .inventory_views import rows
    if store is None:
        from .store import Store
        store = Store
    count = 0
    for row in rows(db, 'SELECT data FROM network_control_assignments'):
        state = json.loads(row[0])
        changed = False
        for kind in KINDS:
            feature = state.get(kind)
            if not isinstance(feature, dict): continue
            descriptor = feature.pop('descriptor', None)
            floor = max(feature.get('generation_floor', 0), (descriptor or {}).get('generation', 0), (feature.get('receipt') or {}).get('generation', 0))
            feature.update(generation_floor=floor, status='requires_fresh_review', invalidated_at=stamp())
            if descriptor:
                feature['held_descriptor'] = descriptor
                count += 1
            changed = True
        if changed: store._put(db, 'network_control_assignments', state)
    for row in rows(db, "SELECT data FROM network_control_plans WHERE status IN ('draft','queued')"):
        plan = json.loads(row[0])
        plan.update(status='requires_fresh_review', can_apply=False, confirmation_nonce='',
                    blockers=['Database recovery retained generation floors but held delivery. Request a fresh native assessment and review. Existing endpoint rules and quarantine expiry were not changed.'])
        _plan(db, plan)
    return {'held_descriptors': count, 'generation_floors_preserved': True, 'native_rules_unchanged': True}
