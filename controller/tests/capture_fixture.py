"""Explicit current typed-event fixtures; metadata-free history stays separate."""
import hashlib

from controller.store import stamp


def typed_event(source, port, *, identity, at=None, protocol='tcp', kind='accepted_connection'):
    point=stamp() if at is None else (at if isinstance(at,str) else stamp(at))
    backend,unit,verdict={
        'accepted_connection':('conntrack','connections','allowed'),
        'denied_packet':('nflog','packets','denied'),
    }[kind]
    return {'event_id':hashlib.sha256(identity.encode()).hexdigest(), 'source_ip':source,
            'port':port, 'protocol':protocol, 'verdict':verdict, 'count':1,
            'first_seen':point, 'last_seen':point, 'capture_kind':kind,
            'capture_backend':backend, 'count_unit':unit,
            'address_family':'ipv6' if ':' in source else 'ipv4'}
