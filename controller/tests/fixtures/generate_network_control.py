#!/usr/bin/env python3
"""Generate public Python→Go network-control wire vectors, without native writes.

Uses real disposable Store/current single-Admin review proofs. No passwords,
session tokens, private keys, network sends or firewall commands are exported.
Run from the repository root with the controller development dependencies.
"""
import json
from pathlib import Path
import sys
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))

from controller import network_control
from controller.store import now
from controller.tests.test_network_control import NetworkControlTests


def generate():
    fixture = NetworkControlTests()
    try:
        fixture.setUp()
        at = now()
        with patch.object(network_control, 'now', return_value=at):
            fixture.assess('egress')
            fixture.apply(fixture.body(default_deny=True))
            fixture.assess('quarantine')
            fixture.apply(fixture.body('quarantine', ttl_seconds=900))
            assigned = fixture.assignment()
        result = {'server_id': 'target', 'issued_at': assigned['egress_bundle']['issued_at'], **assigned}
        encoded = json.dumps(result, sort_keys=True, indent=2)+'\n'
        if 'isolated-identity-fixture' in encoded or '_session_id' in encoded:
            raise ValueError('Private fixture credentials must never be exported')
        return encoded
    finally:
        fixture.doCleanups()


if __name__ == '__main__':
    target = Path(__file__).with_name('network-control-wire.json')
    target.write_text(generate(), encoding='utf-8')
    print('Wrote public network-control wire vectors; no native operations performed.')
