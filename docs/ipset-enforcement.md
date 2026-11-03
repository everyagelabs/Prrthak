# Bounded source sets for managed and learned policies

Agent 0.6 adds `managed_ipsets_v1` and `learning_ipsets_v1`. A managed policy
with thousands of sources uses a per-service IPv4/IPv6 source set instead of
one rich rule per address. Identical source lists share sets within that
generation; different ports keep their own lists. Source sets never create
business tags or DC membership.

For up to 64 ordinary rules the existing adapter remains compatible. Larger
managed bundles use a bounded 128-rich-rule adapter, at most 32 distinct source
sets per address family, 10,000 entries per set and 40,000 entries in one bundle.
Learning remains accepts-only and admits at most 10,000 exact source/port
tuples across 64 services. Legacy agents retain their 64-tuple learning limit;
the controller checks the reported capability before preparing a larger overlay.

## Initial bank provisioning

Use **Servers → Source-set preparation** or an endpoint's source-set panel.
The 0.12 GUI requests a read-only assessment, freezes an exact fresh maintenance
review and requires the same Admin's typed phrase plus manually checked downtime
acknowledgement. The agent creates missing owned empty definitions and safely
activates them with management checks and an independent rollback watchdog.
No extra CLI command is required. See [the complete GUI workflow](source-bank-preparation.md).

The official [firewall-cmd interface](https://firewalld.org/documentation/man-pages/firewall-cmd.html)
creates ipsets in permanent configuration; activation therefore requires a
controlled maintenance reload. Unsupported runtime/permanent drift or foreign
contexts block this action. Ordinary large policy changes still never reload.
The old `prepare-managed-ipsets.py` helper remains a compatibility tool, not a
required part of the GUI workflow.

Normal managed banks are `prthak_a4_00`…`31`, `prthak_b4_00`…`31` and their
IPv6 `6` equivalents. Learned additive banks use the separate `prthak_la*`
and `prthak_lb*` namespaces. These canonical namespaces are reserved for Prṛthak.

## Transaction and recovery

Before mutation the agent verifies exact type/family/options and rejects
unexpected references from zones and policy objects. It checks the committed
bank for drift. A new generation fills the inactive bank, reads every entry
back, installs higher-priority staged rules, verifies management access, commits
permanent state and reads both scopes back. The previous bank stays unchanged.
Each bulk entry mutation records its complete prior entries before executing.
The independent rollback journal restores rule references first and then the
unused bank's exact prior contents. A partial bulk command, process interruption
or failed readback cannot be treated as a successful commit.
Existing connections follow firewalld's normal connection tracking behavior;
the agent does not flush connection state. The network acceptance checks below
exercise new TCP connections after each policy change.

Learning banks add accepts only, preserve exact source-to-port authority and
local observations, and cannot add SSH/controller grants. Stopping or expiring
learning ends new grants; committed accepts remain until reviewed removal.

## Evidence boundary

`scripts/smoke-ipsets.py` passed against actual firewalld/nftables in an isolated
Docker network: 5,000-source bank switch, two real allowed/blocked TCP clients,
failed-staging rollback, separate learned accepts, reviewed learned cleanup and
managed cleanup restoring the legacy allowance. IPv4/IPv6 set contents were read
back. Its management witness/systemd timer were explicit test callbacks. Native
RHEL/Ubuntu systemd, kernel traffic-learning, SSH witnesses and reset/fencing
still require the deployment platform acceptance matrix. This is not a
5,000-agent capacity certification.

The same six phases also passed on the official Ubuntu 26.04 image with the
distribution's firewalld 2.3.1 on 31 October 2026. Reproduce that disposable
userland/backend check after building the ARM64 Go test executable:

```sh
docker build -f deploy/testing/Dockerfile.firewalld-ubuntu26 \
  -t prthak-private-firewall-smoke26:latest deploy/testing
PRTHAK_DISPOSABLE_IPSET_LAB=1 \
PRTHAK_PRIVATE_FIREWALL_IMAGE=prthak-private-firewall-smoke26:latest \
python3 scripts/smoke-ipsets.py
```

Its containers share the disposable VM's kernel; it does not certify the native
Ubuntu 26.04 kernel, systemd timers or RHEL SELinux/polkit behavior. Separately,
`scripts/smoke-linux-container.sh ubuntu26` passed unprivileged real SSH-2022
discovery, mTLS enrollment and identity reuse with the 0.6 agent. No fixture
container or labeled network was retained after either run.

<sub>Created by Pratik Srivastava</sub>
