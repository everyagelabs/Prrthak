# 0.11.0-pilot.1 · Endpoint discovery and reliable health visibility

2 November 2026. This builds on reusable fleet enrollment and keeps the
single-Admin, OS-neutral policy workflow. No second-person approval mode is
introduced. Business tags and DC assignments remain dashboard-owned.

## Delivered behavior

- Every agent process starts with fresh OS/version, interface, firewalld and
  service inventory under its existing enrolled identity.
- Native Linux socket snapshots check every five seconds. Verified changes
  trigger process/systemd identification and an immediate report, normally in
  about 5–10 seconds plus delivery. Full inventory retains its separate
  configurable 900-second fallback. Failed/incomplete/unsupported checks do not
  erase last good listeners or relabel old firewall snapshots as fresh.
- The server drawer shows fast-check state/errors, full fallback and the latest
  preparation receipt. OS details remain inventory/compatibility information;
  policy forms stay sources/ports/targets across supported Linux hosts.
- Independent missed-heartbeat evaluation raises critical agent-offline alerts
  after max(180 seconds, three control intervals), then records recovery. Fixed
  a real visibility gap where more than 500 newer historical events could hide
  an unresolved outage. Alerts now use bounded pages and exact scoped counts,
  with recovery history, combined filters and Read Only navigation.
- Both dependency installation and UFW assessment options start unchecked in
  **Install agent**. The same family installer consumes strict schema-3 data,
  validates signed runtime/private setup before preparation, and takes the
  configuration plus managed command leases. Missing dependencies can be
  installed with verified service-start suppression and package removal
  protection. Existing UFW configuration/activity is preserved and assessed;
  raw rules stay in the endpoint's private export.
- Staging/read-only/no-start modes skip package preparation. Uncertain package
  state, unmanaged startup overrides or unfinished firewall transactions block
  preparation. Partial package installation and refused cleanup remain errors;
  no package rollback or live UFW migration is claimed.
- Monitoring guidance now describes bounded conntrack connection observations
  and NFLOG packet observations with separate units and coverage gaps; the
  obsolete 20-events/second description was removed.

See [workflow, safeguards and diagram](endpoint-discovery-and-preparation.md),
[fleet setup](fleet-enrollment.md) and [GUI pilot installation](pilot-gui-installation.md).

## Validation

| Check | Result |
| --- | --- |
| Full controller with private PostgreSQL | **962 passed**, zero skips/failures |
| Native-agent/HTTPS/private-PostgreSQL integration | **296 passed**, one Linux-kernel-only skip |
| Immutable Linux Python 3.13 integration | **262 passed**, 35 PostgreSQL/HA fixture skips covered separately |
| Dashboard | **328 passed**, including exact alert totals, pagination, scopes, identity races and diagnostic escaping |
| Go | Full race suite (**39.184 s**) and vet passed; native + Linux AMD64/ARM64 builds passed |
| Native listener checks | Real isolated Linux IPv4/IPv6 TCP/UDP start/stop tests passed |
| Preparation safety | Fake-command Linux tests cover leases, startup suppression, cleanup, UFW preservation and strict setup; no real OS package hooks invoked |
| Runtime integrity | Signed base/appliance/manager startup passed; changed application rejected before import |
| 5,000 virtual identities | Actual Admin edit + publication + full polling window **31.869 s**, zero final failures |
| Bandit | Zero HIGH; 220 MEDIUM and 304 LOW findings retained for review |

The immutable Linux snapshot and ARM64 agent SHA-256
`6a22898bf73a11d31ba610b21efb874dbc6a23a9e44152ad510f62f37c5985af`
remained unchanged during execution. Subsequent changes were documentation and
public evidence only. PostgreSQL runs preserved pre-existing databases/roles
and removed only their owned fixtures. The private test cluster was not a DC
or deployment database. See [the exact capacity record](controller-capacity-5000.md).

Detached signatures bind the clean tagged source and all agent/controller/native
payloads. The [candidate tag](https://github.com/everyagelabs/Prrthak/tree/v0.11.0-pilot.1)
and [CI workflow](https://github.com/everyagelabs/Prrthak/actions/workflows/ci.yml)
identify independent Linux regression/security and image-assessment results;
unsigned CI candidates and locally signed payloads are separate artifacts.

## Boundaries

Native RHEL 8/9 and Ubuntu 26.04 installers, real package hooks, systemd/SELinux,
live Entra/MFA, DC/WAN/LB/quorum/fencing and the actual 20-server enforcement
pilot remain deferred deployment acceptance. The new kernel checks are bounded
polling, not a guaranteed event stream or a fixed application-outage SLA.

The isolated socket microbenchmark (~1.17 ms, 66.6 KB allocated per scan with
very few listeners) is not current whole-agent CPU/RSS/endurance qualification.
Controller sizing remains a planning allocation. Vendor image advisories remain
open; successful code tests or CI do not establish a clean VA or production
certification. Local detached signatures use the existing development authority;
organization-approved production signing and independent trust distribution
remain operational responsibilities.
