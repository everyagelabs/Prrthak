#!/usr/bin/env python3
"""Package only public agent artifacts, never local state or credentials."""
import hashlib
import os
import re
from pathlib import Path
import tarfile
import subprocess
import sys

root = Path(__file__).resolve().parent.parent
out = root / 'dist'
out.mkdir(exist_ok=True)
checksums = []
version = re.search(r'const Version = "([0-9]+\.[0-9]+\.[0-9]+)"', (root / 'agent/internal/agent/types.go').read_text()).group(1)
for arch in ('amd64', 'arm64'):
    binary = root / 'agent' / 'bin' / f'seg-agent-linux-{arch}'
    if not binary.is_file():
        raise SystemExit('Run make build-agent before packaging.')
    stem = f'prthak-agent-{version}-linux-{arch}'
    archive = out / f'{stem}.tar.gz'
    files = [(binary, 'seg-agent'),
             (root / 'agent' / 'config.example.json', 'agent/config.example.json'),
             (root / 'agent' / 'README.md', 'agent/README.md'),
             (root / 'docs' / 'managed-enforcement.md', 'docs/managed-enforcement.md'),
             (root / 'docs' / 'whole-server-default-deny.md', 'docs/whole-server-default-deny.md'),
             (root / 'docs' / 'traffic-capture.md', 'docs/traffic-capture.md'),
             (root / 'docs' / 'fleet-enrollment.md', 'docs/fleet-enrollment.md'),
             (root / 'docs' / 'endpoint-discovery-and-preparation.md', 'docs/endpoint-discovery-and-preparation.md'),
             (root / 'docs' / 'source-bank-preparation.md', 'docs/source-bank-preparation.md'),
             (root / 'docs' / 'policy-rollout-verification.md', 'docs/policy-rollout-verification.md'),
             (root / 'docs' / 'linux-validation.md', 'docs/linux-validation.md'),
             (root / 'docs' / 'scale-validation.md', 'docs/scale-validation.md'),
             (root / 'docs' / 'ipset-enforcement.md', 'docs/ipset-enforcement.md'),
             (root / 'docs' / 'policy-signing.md', 'docs/policy-signing.md'),
             (root / 'docs' / 'linux-agent-installation.md', 'docs/linux-agent-installation.md'),
             (root / 'docs' / 'pilot-gui-installation.md', 'docs/pilot-gui-installation.md'),
             (root / 'docs' / 'authentication.md', 'docs/authentication.md'),
             (root / 'deploy' / 'systemd' / 'seg-agent.service', 'deploy/systemd/seg-agent.service'),
             (root / 'scripts' / 'install-agent.sh', 'scripts/install-agent.sh')]
    files.extend((root / 'scripts' / name, 'scripts/' + name) for name in ('prepare-managed-ipsets.py', 'verify-release.py', 'install-agent-linux.sh', 'install-agent-rhel.sh', 'install-agent-ubuntu.sh'))
    signing_key = os.environ.get('PRTHAK_RELEASE_SIGNING_KEY_FILE')
    if signing_key:
        integrity = out / (stem + '-runtime-integrity.json')
        subprocess.run([sys.executable, str(root / 'scripts/sign-runtime.py'), '--key-file', signing_key,
                        '--agent-binary', str(binary), '--output', str(integrity)], check=True)
        files.extend(((integrity, 'runtime-integrity.json'), (root / 'deploy/release-public-trust.json', 'deploy/release-public-trust.json')))
    guide = out / f'{stem}-INSTALL.txt'
    guide.write_text(f'''Prṛthak · पृथक् — Linux {arch} endpoint bundle

1. Before extraction/install in production, verify its detached signature using
   an independently obtained public release-signing manifest and an approved
   copy of scripts/verify-release.py. Adjacent downloaded public keys alone are
   not a trust decision. Unsigned packages are for isolated lab use only.
   Then extract and enter the {stem}/ directory.
2. In the installed controller choose Install agent > Fleet setup. Set common
   origins/polling and enrollment expiry (default24hours). Download one private
   setup JSON and reuse it across the fleet; no per-host package/kit is needed.
   Transfer it privately as root-owned mode0600 to /root/prthak-agent-setup.json.
   Each endpoint automatically creates its own private key and certificate.
   The optional Individual setup remains single-use/15minutes. See
   docs/fleet-enrollment.md for GUI profile revocation and identity boundaries.
   Optional unchecked GUI choices can install missing OS dependencies with
   service-start suppression and export private UFW evidence. UFW is preserved;
   no firewall activation or migration is performed. See
   docs/endpoint-discovery-and-preparation.md before selecting preparation.
   Source banks are prepared later in Servers > Source-set preparation through
   a separate exact maintenance review. No additional bank-preparation CLI is
   required. Set restricted management source IPs/CIDRs in the GUI setup when
   this workflow is intended; setup remains monitor-only.
3. From this extracted release directory run exactly one matching installer:

   sudo ./scripts/install-agent-rhel.sh --setup-file /root/prthak-agent-setup.json
   or sudo ./scripts/install-agent-ubuntu.sh --setup-file /root/prthak-agent-setup.json

   No hand-editing agent JSON, token or CA configuration is required. Public CA
   material and monitor-only settings are prepared by the validated Go helper.
   Without explicit GUI preparation, OS prerequisites must already exist.
   No firewall manager is switched or activated. See
   docs/pilot-gui-installation.md for the full GUI workflow.

ADVANCED COMPATIBILITY: explicit reviewed config/token/CA files remain supported.
The following older workflow is optional, not needed for GUI-configured pilots:

A. Review agent/config.example.json. Set controller_url to the stable HTTPS
   controller/load-balancer origin, interval_seconds (default 60), and
   discovery_interval_seconds (default 900). Use the stock credential paths.
   ca_cert pins the HTTPS server CA. If the endpoint issuing CA is different,
   set endpoint_ca_cert=/etc/seg-agent/endpoint-ca.crt and securely preinstall
   that public CA there before preflight. The installer --ca-file copies only
   HTTPS trust. Leave endpoint_ca_cert empty only when the same CA is used.
B. Obtain the trusted controller CA and a private, single-use enrollment token
   from your Prṛthak administrator. Preserve existing firewall/management access.
C. Run the matching read-only platform check:
   ./scripts/install-agent-rhel.sh --check-only
   or ./scripts/install-agent-ubuntu.sh --check-only
   Supported entrypoints are RHEL8/9 and Ubuntu26.04, Linux amd64/arm64.
   Ensure systemd, firewalld and iproute/iproute2 are available. Missing package
   instructions are printed, but package installation/service activation and
   existing UFW/firewall migration remain separate reviewed operations.
   The static agent and shell installer need no Python. Optional source-bank
   preparation needs Python3.6+ standard library. The release verifier needs
   Python3.8+ and a compatible Ed25519 cryptography package (>=44); use approved
   Python3.10+ administration tooling. RHEL8's default Python3.6 cannot run it.
D. Install the enrollment token with root ownership:

   sudo install -d -m 0700 /etc/seg-agent
   sudo install -o root -g root -m 0600 /path/to/token /etc/seg-agent/enrollment-token
   sudo ./scripts/install-agent-rhel.sh --ca-file /path/to/controller-ca.crt \\
     --token-file /etc/seg-agent/enrollment-token \\
     ./agent/config.example.json

   On Ubuntu use install-agent-ubuntu.sh instead. The entrypoint selects the
   bundled binary automatically. Review docs/linux-agent-installation.md.

The installer enables/starts seg-agent. The endpoint enrolls and reports its
services automatically. Check: sudo journalctl -u seg-agent.service -f

For later configuration changes use Platform > Setup. Review the exact endpoint
change and download its private signed configuration kit, then run the matching
family installer once with --configuration-file /root/prthak-endpoint-configuration.json.
The agent tests fresh mTLS on the candidate endpoints and commits the confirmed
configuration or restores its previous configuration. Agent JSON editing is not
part of this GUI workflow. Polling is managed separately under Agent polling.

Initial installation remains monitor-only. An authorized Entra Admin's normal
Save/Apply directly publishes exact signed policy intent; configured endpoints
pull and apply it after local enforce/firewall/learning opt-ins, restricted
management_sources, actual SSH/controller health checks and rollback guards.
No second person, selectable approval mode or expiring pilot consent is needed.
Explicit imported deny/restrictive actions, restrictive learned edits/removal
and destructive recovery retain extra confirmations by the same actor. Super
Admin manages application users and privileged platform settings.
Agent {version} verifies independently pinned Ed25519 assignment signatures. Enrollment
may pin the initial public manifest; it never silently rotates existing trust.
Large managed/learned source lists require reviewed empty source-bank preparation
and maintenance activation; policy application never reloads firewalld. Review
docs/ipset-enforcement.md in the repository before enabling large source sets.
Failed transactions restore exact owned changes and require review before retry.
For a fresh pilot install the {version} controller and then the {version} agents. Upgrade any
older endpoints before relying on current direct-Admin deliveries; unsupported
authority/schema is refused safely. Signed assignments
require enrolled identity binding and a durable monotonic assignment_generation.
For this pilot, leave enforcement/automatic learning off controller, database
and load-balancer infrastructure pending native ingress-protection acceptance.
Supported imported-rule changes independently require allow_firewall_changes=true
plus the authorized Admin action and any explicit restrictive confirmation. The 20-server pilot has not started.
New learning and continuous port-hit monitoring use native conntrack accepted
transport evidence and verified terminal NFLOG denied-packet evidence. They
report unsupported paths, gaps and losses and do not silently use journal logs.
Separate unexpected-port monitoring retains bounded log-only instrumentation.
See docs/traffic-capture.md and agent/README.md before enabling capture.
See agent/README.md for capabilities, credential handling and limitations.
''', encoding='utf-8')
    files.append((guide, 'INSTALL.txt'))
    with tarfile.open(archive, 'w:gz') as tar:
        for source, target in files:
            entry = tar.gettarinfo(str(source), arcname=f'{stem}/{target}')
            if not entry.isfile():
                raise SystemExit('Package only reviewed regular public files: ' + str(source))
            # Release ownership must not inherit a workstation UID on endpoints.
            entry.uid = entry.gid = 0
            entry.uname = entry.gname = ''
            entry.mtime = 0
            entry.mode = 0o755 if source.stat().st_mode & 0o111 else 0o644
            with source.open('rb') as incoming:
                tar.addfile(entry, incoming)
    checksums.append(f'{hashlib.sha256(archive.read_bytes()).hexdigest()}  {archive.name}\n')
    print(f'Created {archive.name} ({archive.stat().st_size:,} bytes)')
(out / 'SHA256SUMS').write_text(''.join(checksums))
print('Created dist/SHA256SUMS')
signing_key = os.environ.get('PRTHAK_RELEASE_SIGNING_KEY_FILE')
if signing_key:
    subprocess.run([sys.executable, str(root / 'scripts/sign-release.py'), '--key-file', signing_key,
                    *[str(out / f'prthak-agent-{version}-linux-{arch}.tar.gz') for arch in ('amd64', 'arm64')]], check=True)
else:
    print('Unsigned lab packages only. For production set PRTHAK_RELEASE_SIGNING_KEY_FILE to an independently provisioned private Ed25519 seed.')
