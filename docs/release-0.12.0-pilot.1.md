# 0.12.0-pilot.1 · Complete history and GUI source-set preparation

2 November 2026. This closes the five code and GUI gaps identified after the
endpoint-discovery release. Ordinary policies retain direct publication by one
current Admin. Whole-server deny and source-set activation retain their own
explicit maintenance acknowledgement; no second-person approval is required.

## Delivered behavior

- Read Only users can page and filter alerts through the actual dashboard API
  wrapper. Its exceptions permit exact read-query/export routes, while mutation
  permissions, session identity, CSRF and origin checks remain enforced.
- Traffic filters run against retained database observations before aggregation
  and pagination. Combined server/tag/group, port, search and time scopes show
  exact matching totals rather than filtering a global 500-row preview. Separate
  connection and denied-packet units remain visible. Graphs explicitly describe
  their loaded-page scope. CSV exports cover the requested retained scope or
  return an explicit size-limit error before sending a partial file.
- Audit history has database pagination, exact totals, action/actor/date/search
  filters and bounded complete CSV export. Details and exports redact sensitive
  legacy fields; CSV cells are protected against formula execution. Export
  concurrency and temporary-file size are bounded.
- **Servers → Source-set preparation** assesses selected servers or saved groups,
  freezes their exact current membership and baseline, and requests controlled
  activation through signed agent assignments. Typed confirmation and an
  initially unchecked downtime acknowledgement belong to the same Admin.
  Assessment, assignment and a verified prepared outcome are distinct states.
  Read Only can inspect the results.
- The GUI agent setup accepts restricted management-source IPs/CIDRs, so the
  protection prerequisite needs no additional endpoint command. Initial setup
  remains monitor-only. Source-set preparation does not change local enforcement
  opt-ins or allow/deny policy. Previously authorized intent can resume on a later
  normal poll once its source banks are ready.
- Stale policy wording and operator documentation now describe direct Admin
  publication and the separate source-set maintenance operation accurately.

## Firewall activation and recovery

Ordinary managed policies update runtime and permanent configuration without
restarting or routinely reloading firewalld. Initial creation of the owned
source-set definitions requires a controlled reload. The agent first verifies
supported runtime/permanent equivalence, interface bindings, loaded global
configuration, ownership, fresh authorization and SSH/controller connectivity.
Unsupported or uncertain contexts block activation.

An independent ten-minute watchdog protects a nine-minute operation deadline.
Progress is reported during longer phases. Failed health or activation restores
only the transaction's owned changes and verifies both scopes. Uncertain or
refused recovery remains an error and cannot be cleared by an expired review or
new assessment. Foreign or populated objects are not deleted to force recovery.

See the [GUI workflow and communication diagram](source-bank-preparation.md),
[source-set adapter](ipset-enforcement.md) and [API contracts](api-contract.md).

## Validation

| Check | Result |
| --- | --- |
| Full controller with private PostgreSQL | **1,024 passed**, zero skips/failures |
| Native-agent/HTTPS/private-PostgreSQL integration | **297 passed**, one Linux-kernel-only skip on macOS |
| Immutable Linux Python 3.13 integration | **263 passed**, 35 PostgreSQL/HA fixture skips covered by the private-PostgreSQL run |
| Dashboard | **357 passed**, zero skips/failures, including actual shared API-wrapper and maintenance-consent checks |
| Go | Full race suite (**98.775 s**) and vet passed; native + Linux AMD64/ARM64 builds passed |
| Linux source-bank/global-metadata checks | **32 passed**, zero skips/failures |
| Isolated Ubuntu 26.04.1 / firewalld 2.3.1 | Forced post-reload health failure restored exact zero-bank baseline; successful activation verified all 256 runtime/permanent banks |
| Runtime integrity | Signed base/appliance/manager startup passed; changed application rejected before import |
| 5,000 virtual identities | Actual Admin edit + publication + full polling window **35.079 s**, zero final failures |
| Bandit | Zero HIGH; 229 MEDIUM and 310 LOW findings retained for review |

The isolated real-firewalld test used test-binary SHA-256
`89235e45998ce59343db957f0d20cdec1394fd30c0cb0ad9400dc1b37dde1432`.
It exercised actual firewalld creation, reload, readback and inverse removal in
an owned network namespace, with management-health witnesses, loaded-daemon
metadata, watchdog and configuration-lease callbacks stubbed. Its failed-health
and successful phases took 175.95 and 173.42 seconds. Only its own container and
network were removed. This is adapter/recovery evidence, not native systemd,
management-path or distribution acceptance.

The immutable Linux integration used executable SHA-256
`4eb6a8b5e044cfeb3ba40416513d11c152d5761bed49a34562fd37e1d7482737`.
Runtime sources remained unchanged during execution; only operator/release
documentation changed afterward. PostgreSQL runs preserved pre-existing
databases/roles and removed their owned fixtures. Linux validation removed only
its own containers, network and anonymous volumes.

The [capacity record](controller-capacity-5000.md) includes exact workload and
source hashes. This verifies ordinary delivery and synthetic ingestion rather
than native enforcement, source-set maintenance or large-history endurance.

Detached signatures bind the clean tagged source and all seven
agent/controller/native payloads. The [candidate tag](https://github.com/everyagelabs/Prrthak/tree/v0.12.0-pilot.1)
and [CI workflow](https://github.com/everyagelabs/Prrthak/actions/workflows/ci.yml)
identify independent Linux regression/security and image-assessment results.
Unsigned CI candidates and locally signed payloads are separate artifacts.

## Deployment boundaries

Native RHEL 8/9 and Ubuntu 26.04 package hooks, systemd/SELinux, actual management
reachability, live Entra/MFA, DC/WAN/LB/quorum/fencing and the real 20-server
enforcement pilot remain deferred acceptance. Isolated Linux kernel/firewalld
tests do not replace native endpoint testing. Lockout protection checks SSH and
the controller; it cannot establish that every business dependency is allowed.

Vendor image advisories remain open. Passing source tests, image-integrity
checks or capacity measurements does not establish a clean VA or production
certification. Local payload signatures use the existing development authority;
production signing and independent trust distribution remain operational work.

<sub>Created by Pratik Srivastava</sub>
