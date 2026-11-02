# 0.10.0-pilot.1 · Reusable fleet enrollment

2 November 2026. Generate one fleet setup in the GUI and reuse it with the same
matching CPU agent package across your servers. No per-host agent generation,
hostname list, CSV or pre-created server record is required. The default workflow
has no fixed enrollment-count limit. Installation still runs on each prepared
host, directly or through the operator's deployment tooling.

## Delivered behavior

- **Install agent → Fleet setup** is the default. Set common trusted URLs,
  polling, profile name and validity once; download one private setup file.
  Validity defaults to 24 hours and can be 1 hour through 30 days.
- Each host creates a separate ECDSA private key/CSR. The controller issues its
  own server ID and certificate, then authenticated discovery populates the
  dashboard. The shared bootstrap file contains no endpoint private key.
- Fleet profiles show public expiry/status/registration counts with bounded
  pagination. An Admin can revoke future enrollment without disconnecting
  existing endpoint mTLS identities or changing their firewall rules.
- Profiles, hashed credentials and per-public-key receipts use separate indexed
  namespaces. Current-profile checks, canonical public-key binding, idempotent
  retry and mutation transactions prevent duplicate/rebound identities.
  Retired/revoked identities are refused; recovery discards bootstrap authority
  while retaining consumed key claims.
- Schema-1 individual one-use/15-minute kits and existing identities remain
  compatible. Schema-2 fleet kits need the upgraded agent. Initial setup remains
  monitor-only; local enforcement/learning protections and single-Admin policy
  behavior are unchanged.
- GUI async results are fenced across identity, modal, mode and draft changes.
  Shared secrets are downloaded once, never listed/rendered/stored in browser
  storage. The archive guidance now uses the actual current release version.

See [the fleet workflow and diagram](fleet-enrollment.md) and
[GUI installation](pilot-gui-installation.md).

## Validation

| Check | Result |
| --- | --- |
| Full controller with real private PostgreSQL | 938 passed; zero skips/failures |
| Full private-PostgreSQL/HTTPS/native integration | 292 passed; one Linux-kernel-only case skipped on macOS |
| Final immutable Linux Python 3.13 integration | 258 passed; 35 PostgreSQL-only skips covered by the separate PostgreSQL run |
| Dashboard | 315 passed, including shared-shell CSRF and stale-download/revoke races |
| Go | Full native race suite and vet passed; both Linux CPU builds passed |
| Enrollment lifecycle security | New/historical recovery and rotated-renewal keys, conflicting claims, profile/certificate revocation, retirement and transactional recovery passed |
| Release runtime integrity | Signed controller/appliance/manager startup and modified-byte rejection before import passed |
| 5,000 virtual identities | Actual Admin edit + publication + full 30-second polling window **32.097 seconds**; zero final failures; all 10,000 typed observations retained |
| Static security | Bandit reported zero HIGH findings; lower-severity findings retained for review |

The targeted real HTTPS/mTLS check used **one identical setup file and 20 isolated native-agent state directories**:
20 different keys/certificates/server IDs, preserved identity on rerun, new
enrollment refused after profile revocation, and existing mTLS sync retained.
No native OS installer, systemd service or real endpoint firewall was changed.

Final Linux evidence preserves its immutable snapshot and ARM64 binary SHA-256
`78eec4a1b4980a0fc11aaff10d835f211ca9e2d1e06547329515b6cbf325866c`.
Later edits were documentation and one controller-test fixture's independent
key; runtime hashes did not change. The final PostgreSQL runs preserved existing
databases/roles and dropped only their owned disposable fixtures.

The [fresh capacity record](controller-capacity-5000.md) measures current-runtime
policy delivery and synthetic ingestion. Certificate preparation is outside its
timers; legacy registry migration and simultaneous native enrollment are not
qualified by that result.

The [candidate tag](https://github.com/everyagelabs/Prrthak/tree/v0.10.0-pilot.1)
and detached package-signature provenance bind the exact clean source. The
[CI workflow](https://github.com/everyagelabs/Prrthak/actions/workflows/ci.yml)
records independent Linux regression, source security, image assessment and
unsigned tagged candidates. Local signed payloads use the existing development
authority; organization-approved production signing remains separate.

## Boundaries

Enrollment has no artificial host-count cap; that does not make deployment
capacity unbounded. Policy delivery and synthetic ingestion benchmarks do not
measure simultaneous native enrollment storms, 5,000 collectors or endurance.
The fleet setup is a private enrollment credential: holders can enroll while it
is active. Revoke/replace it if exposed. Never distribute initialized endpoint
identity/state in an image or clone.

Upgrade/drain every controller before enabling this feature; mixed-version
certificate issuance is unsupported. Missing pre-0.10 public certificate history
blocks profile creation until a reviewed census can establish its key claims.
Fresh pilot deployments do not require this historical migration.

Native RHEL 8/9, Ubuntu 26.04, live Entra/MFA, DC/WAN/LB/HA/fencing and real pilot
acceptance remain deferred operator checks. Historical passive agent resource
measurements are not current active-capture CPU/RAM guarantees. Vendor image
advisories remain open; a successful CI gate does not establish a clean VA or
production certification.
