#!/usr/bin/env python3
"""Regenerate public Python -> Go host-deny interoperability vectors.

From the repository root (never builds or starts an agent):
  SEG_AGENT_BINARY=/path/to/current/native/seg-agent \
    python controller/tests/fixtures/generate_host_default_deny.py

The real Store, Entra fixture principals, dedicated preview/confirmation,
PolicySigner and ManagementHealth.check produce these fields. Only _ssh is a
bounded deterministic actuator: this proves wire/hash interoperability, not
native firewall, network reachability, live Entra or an SSH deployment.
All CA/endpoint/signing private keys are generated outside the source tree and
deleted with the disposable SQLite fixture. No private material is exported.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))

from controller import endpoint_configuration
from controller.management_health import ManagementHealth
from controller.pki import Signer, init_ca
from controller.policy_signing import PolicySigner
from controller.store import now, stamp
from controller.tests.test_host_default_deny import HostDefaultDenyTests


def native_receipt(binary, root, config, name):
    path = root / (name + '-native-config.json')
    path.write_text(json.dumps(config), encoding='utf-8')
    path.chmod(0o600)
    process = subprocess.run([str(binary), '--configuration-state', '--config', str(path)],
                             capture_output=True, text=True, timeout=15, check=True)
    value = json.loads(process.stdout)
    endpoint_configuration.report(value)
    return value


def endpoint_public_identity(root):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    pki = init_ca(root / 'ephemeral-identity')
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = (x509.CertificateSigningRequestBuilder()
           .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'target')]))
           .sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode())
    certificate, ca = Signer(pki / 'ca.pem', pki / 'ca-key.pem')('target', csr)
    return certificate, ca


def generate(binary):
    binary = Path(binary).resolve(strict=True)
    version = subprocess.run([str(binary), '--version'], capture_output=True, text=True,
                             timeout=10, check=True).stdout.strip()
    if 'agent 0.8.' not in version:
        raise ValueError('Regeneration requires a current native 0.8 agent helper')
    fixture = HostDefaultDenyTests()
    try:
        fixture.setUp()
        root, store = fixture.store.path, fixture.store
        signer = PolicySigner(root / 'ephemeral-assignment-seed',
                              '00000000-0000-4000-8000-000000000008', create=True)
        trust = signer.public_trust()
        certificate, endpoint_ca = endpoint_public_identity(root)
        config = json.loads((ROOT / 'agent/config.example.json').read_text())
        protected = store.get('servers', 'target')['protection']
        config.update(controller_url=protected['controller_url'],
                      control_url='', discovery_url='', management_probe_url=protected['management_probe_url'],
                      management_probe_ca_cert='', policy_signing_trust_file='',
                      policy_signing_keys=trust['keys'], policy_signing_deployment_id=trust['deployment_id'],
                      enforce=True, allow_host_default_deny=True, learning_auto_allow=False,
                      management_sources=protected['management_sources'], protected_ssh_ports=protected['ssh_ports'],
                      zone=protected['zone'])
        policy = copy.deepcopy(fixture.policy)
        policy['services'][0]['sources'].append('2001:db8::8/128')
        fixture.policy = store.save_policy(policy, fixture.maker['actor'], policy['id'], principal=fixture.maker)

        cases = []
        for action in ('enable', 'disable'):
            current = copy.deepcopy(config)
            if action == 'disable':
                # Explicitly exercise removal with the new local opt-in off.
                current['allow_host_default_deny'] = False
            receipt = native_receipt(binary, root, current, action)
            with store.meta() as db:
                server = store._get(db, 'servers', 'target')
                server['configuration_state'] = endpoint_configuration.report(receipt)
                store._put(db, 'servers', server)
            fixture.push(action)
            assignment = store.assignment('target')[0]
            protection = store.get('servers', 'target')['protection']
            nonce = 'host-deny-interop-' + action + '-nonce'
            authority = assignment['enforcement']
            payload = {key: authority[key] for key in ('approval_id', 'protection_digest', 'binding_digest')}
            payload.update(version=assignment['version'], digest=assignment['digest'], nonce=nonce,
                           ssh_ports=protection['ssh_ports'])
            health = ManagementHealth('10.90.0.5', ['10.70.0.0/24'])

            def ssh_actuator(target, port, deadline):
                if target != '10.70.0.1' or port != 2022:
                    raise AssertionError('The real management verifier selected an unexpected target')
                return {'target_ip': target, 'port': port, 'source_ip': '10.90.0.5', 'ssh_banner_verified': True}

            with patch.object(health, '_ssh', side_effect=ssh_actuator) as actuator:
                witness = health.check(store, 'target', payload)
                if actuator.call_count != 1:
                    raise AssertionError('A management witness must use its approved SSH actuator')
            at = int(now().timestamp())
            signed = signer.sign(assignment, at=at)
            cases.append({'name': action, 'at': at, 'nonce': nonce, 'removal': action == 'disable',
                          'config': current, 'configuration_state': receipt, 'trust': trust,
                          'protection': protection, 'policy': signed, 'witness': witness,
                          'certificate_pem': certificate, 'endpoint_ca_pem': endpoint_ca})
            if action == 'enable':
                fixture.receipt()
                # Pending edits must not silently enter the reviewed removal.
                changed = copy.deepcopy(fixture.policy)
                changed['services'] = [{'port': 9443, 'protocol': 'tcp', 'sources': ['10.60.0.0/24']}]
                store.save_policy(changed, fixture.maker['actor'], changed['id'], principal=fixture.maker)
                if store.assignment('target')[0]['enforcement']['authorized']:
                    raise AssertionError('A changed deny-bearing policy bypassed a fresh manual acknowledgement')
        if cases[0]['policy']['services'] != cases[1]['policy']['services']:
            raise AssertionError('Removal widened or replaced the last applied allowed matrix')
        return {'schema_version': 1, 'provenance': {
            'generated_at': stamp(), 'generator': 'controller/tests/fixtures/generate_host_default_deny.py',
            'native_helper_version': version, 'native_helper_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
            'pipeline': ['Store.report', 'host_default_deny.preview', 'host_default_deny.confirm',
                         'Store.assignment', 'PolicySigner.sign', 'ManagementHealth.check'],
            'configuration_digest': 'Actual native --configuration-state receipt, not a Python approximation',
            'management_actuator': 'Deterministic approved SSH actuator; real Store verification before and after it',
            'identity': 'Public endpoint leaf issued by a disposable development CA',
            'prior_apply': 'Synthetic authenticated fixture receipt, not a native firewall application',
            'pending_edit_held': True, 'private_material_exported': False,
            'limits': 'Wire/hash/proof interoperability only; no native firewall, live Entra, SSH path or DC acceptance'},
            'cases': cases}
    finally:
        fixture.doCleanups()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--agent-binary', default=os.environ.get('SEG_AGENT_BINARY'))
    parser.add_argument('--output', type=Path, default=Path(__file__).with_name('host-default-deny.json'))
    args = parser.parse_args()
    if not args.agent_binary:
        parser.error('--agent-binary or SEG_AGENT_BINARY must name an existing native0.8 helper')
    document = generate(args.agent_binary)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=args.output.parent,
                                         prefix='.host-deny-public-', delete=False) as output:
            temporary = Path(output.name)
            json.dump(document, output, indent=2, ensure_ascii=False)
            output.write('\n')
            output.flush()
            os.fsync(output.fileno())
        temporary.chmod(0o644)  # Public fixture only; private material stays in the discarded temporary Store.
        os.replace(temporary, args.output)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    print('Wrote public enable/disable interop vectors:', args.output)


if __name__ == '__main__':
    main()
