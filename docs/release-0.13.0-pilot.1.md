# 0.13.0-pilot.1 · Bulk rollout status and native traffic witnesses

2 November 2026. Policies retain one OS-neutral sources/ports/targets form.
One current Admin publishes ordinary changes; no second-person approval mode
is introduced. Whole-server default-deny still requires its dedicated manually
checked downtime acknowledgement.

## Delivered behavior

- The top-right **Rollouts** panel tracks complete frozen deployments across
  pages, with exact counts and bounded server/port detail. Application and
  traffic verification are independent. Pending indicators stop on a recorded
  outcome; reduced-motion preferences are respected.
- Each endpoint must report fresh exact owned-rule readback before **Applied**.
  A truthful **Already present** receipt identifies an identical installed
  bundle that required no access-rule write. Canonical duplicate policy rows,
  sources and overlapping group permissions are merged without a GUI duplicate
  blocker. Conflicts and uncertain foreign ownership remain distinct.
- Each applicable allow/deny case on each port needs its own first native
  witness after the observation arm. No traffic stays Awaiting, then Unverified;
  missing provenance stays Unavailable. Old connections, generic flow history,
  another port/source/endpoint/generation and replayed receipts cannot qualify.
- Signed ten-minute observation leases grant no access, create no learning
  sessions and generate no business verification probes. Existing SSH/controller
  safety witnesses run before arming and cannot validate the business checks.
  Timestamp capability is not enabled automatically.
- Direct policy saves, the immediate single-Admin selected-server apply path,
  revision restores, default-deny pushes and authorized automatic tag/group/
  service-group/address resolution produce durable tracking. Monitor/new
  baselines and no-op metadata do not create automatic tracker noise.
- **Observe again** creates a fresh passive window for one unchanged target,
  without a policy edit. Read Only can inspect; current Admin roles can recheck.
  Identity, page and modal races cannot reopen or overwrite another session's
  results. Controller errors leave old results visibly stale.
- Restart, context changes and database recovery invalidate current observation
  authority conservatively. Historical first witnesses remain inspectable as
  **Previously observed**, rather than a current green pass. Lost initial
  reports and later polling preserve the genuine immutable readback anchor.

The [workflow and diagram](policy-rollout-verification.md),
[API contract](api-contract.md) and [requirement map](requirements-delivery-map.md)
describe exact bounds and semantics.

## Validation

| Check | Result |
| --- | --- |
| Full controller with private PostgreSQL and native configuration helper | **1,073 passed**, zero skips/failures |
| Dashboard | **380 passed**, zero skips/failures, including actual one-Admin Save/bulk-submit paths |
| Native-agent/HTTPS/private-PostgreSQL integration | **300 passed**, one Linux-kernel-only skip on macOS |
| Immutable Linux Python 3.13 integration | **266 passed**, 35 PostgreSQL/HA fixture skips covered separately |
| Go | Final full race suite **89.806 s**, native/Linux vet, native + Linux AMD64/ARM64 builds passed |
| Native kernel capture | Real dual-stack **8** and IPv4-only **4** TCP/UDP allow/deny combinations, exact birth GET and scoped NFLOG classifier passed |
| Linux focused checks | Two GET parser/adversarial tests and 17 verification tests passed in each isolated kernel profile |
| Interoperability | Actual Python signed single-Admin assignment accepted by Go; actual Go witness fixture admitted by Python |
| Runtime integrity | Signed base/appliance/manager startup passed; tampered application rejected before import |
| 5,000 current virtual mTLS identities | Actual Admin edit + publication + full polling window **33.743 s**, zero final failures; exact signed observation leases verified for every identity |
| Bandit | Zero HIGH; 234 MEDIUM and 311 LOW findings retained for review |

Native capture used test-binary SHA-256
`fc986eddc53afe3df582ff82ab98f14983c34c503b94973951526adce50ae092`
on Linux 6.8.0-117 ARM64 with firewalld 2.3.1 in an isolated Ubuntu 26.04
container image. Docker configured the namespace's timestamp capability for
the test; its value was unchanged during execution. Management-health and
signed-arm safety were exercised separately with fixtures. One external
Python-assignment fixture was deliberately skipped in each offline kernel
profile and passed separately in the cross-language run. No native host
firewall, systemd, package or DC change was performed.

The immutable Linux integration used executable SHA-256
`9dc178bbae1f5d9e599d6351352192e777090f9df27fe0af7073063c366f31d8`.
Runtime source hashes remained unchanged during the final successful runs.
Test-only canonical-policy expectations were updated for the new transient
deployment response; retained business data and metadata migration remained
exact. PostgreSQL fixtures preserved pre-existing databases/roles. Containers,
anonymous volumes and fixture databases were removed only within their owned
test scopes.

The [capacity record](controller-capacity-5000.md) states the exact workload and
limits. Native verification success was not fabricated in that fixture; real
kernel witnessing was exercised separately in the isolated Linux profiles.

The [candidate tag](https://github.com/everyagelabs/Prrthak/tree/v0.13.0-pilot.1)
and [CI workflow](https://github.com/everyagelabs/Prrthak/actions/workflows/ci.yml)
bind independent Linux regression/security and image assessment to exact source.
Local signed payloads and unsigned CI candidates remain separate artifacts.

## Boundaries

One witnessed transport decision does not prove every possible source,
application response, business dependency or future connection. Verification
covers up to 64 exact TCP/UDP pairs per endpoint. Large or unsupported
observation contexts remain explicit without blocking valid policy delivery.

Native RHEL 8/9 and Ubuntu 26.04 packages/systemd/SELinux, actual SSH/controller
reachability, live Entra/MFA, DC/WAN/LB/quorum/fencing, workload endurance and the
real 20-server enforcement pilot remain deferred acceptance. Kernel capture in
an isolated container does not replace these checks. Controller sizing and old
agent CPU/RSS measurements remain planning/historical evidence, respectively.

Vendor image advisories remain open. Passing tests or CI does not establish a
clean VA or production certification. Local signed payloads use the existing
development authority; production signing and independent trust distribution
remain operational responsibilities.

<sub>Created by Pratik Srivastava</sub>
