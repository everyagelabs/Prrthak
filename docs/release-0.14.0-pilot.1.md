# 0.14 pilot audit remediation

2 November 2026. This candidate addresses the ten confirmed findings from the requirements audit. [The remediation record](audit-remediation-0.14.md) identifies each behavior and its regressions.

Policies remain OS-neutral. One current Admin publishes ordinary changes; exactly three global roles remain. Whole-server default deny retains its separate exact review and manually checked downtime acknowledgement. Endpoint opt-ins, current contributing authority, protected health, journaling and rollback remain mandatory.

The release includes complete paginated metadata review, fenced browser operations, current-actor policy cleanup, indexed learning leases, reliable configuration restart recovery, learned-rule-aware denied capture and truthful opt-out state. Its signed manifest and normal CI source guard cover the current Airtel Payments Bank branding. Current installer guides and the illustrated PDF/HTML describe this candidate.

## Validation and release evidence

| Check | Final result |
| --- | --- |
| Controller with private PostgreSQL and native helper | 1,105 passed; zero skips/failures |
| Dashboard | 395 passed; zero skips/failures |
| Native-agent / HTTPS / private PostgreSQL integration | 306 passed; one Linux-kernel-only macOS skip |
| Immutable Linux Python 3.13 integration | 272 passed; 35 external PostgreSQL/HA fixture skips covered separately |
| Go | Full race suite 103.027 s and vet passed; native + Linux AMD64/ARM64 builds passed |
| Isolated kernel capture | Real dual-stack 8 and IPv4-only 4 TCP/UDP combinations; exact GET and 19 focused verification/learned-capture checks passed in each profile |
| Interoperability | Actual signed Python cleanup from the current Admin accepted by Go after the former author was disabled |
| Integrity and images | Current 133-file signature check, base/appliance/host-manager startup and tamper-before-import refusal passed |
| Retained-history capacity | 5,000 exact virtual mTLS identities, 100 expired full-fleet sessions / 500,000 memberships; policy publication + full polling window 33.792 s; zero final failures |

The isolated kernel test binary SHA-256 is
`6dd85b47d47d0fa295a44d4b3006699a90c27fdf1a094a55e2a9e3bc62bdc05b`;
the Linux ARM64 executable is
`48ea2362f5c32cb1562c384961f99fea94060a28fbe3ebb01d964ff7b9334ce9`.
One external Python fixture was deliberately skipped in each offline kernel
profile and passed separately in cross-language validation. Management health
was fixture-based; these profiles do not certify native systemd or RHEL.

Full migration tests caught and corrected empty-store checkpoint behavior;
admission fences and exact replay checks were retained. Native macOS fixtures
used canonical temporary paths, preserving the no-symlink security guard.
Source hashes remained unchanged during final runs; only owned test databases,
containers and anonymous volumes were removed. Existing databases/roles were
preserved. See the [capacity record](controller-capacity-5000.md) for bounds.
 Exact source provenance is bound by the [candidate tag](https://github.com/everyagelabs/Prrthak/tree/v0.14.0-pilot.1), detached payload signatures and [CI workflow](https://github.com/everyagelabs/Prrthak/actions/workflows/ci.yml). The development signing authority is unchanged; its public pin still requires independent approval and distribution.

## Acceptance limits

The 20-server enforcement pilot has not started. Native RHEL 8/9 and Ubuntu 26.04 systemd/firewalld/SELinux, genuine management routes, live Entra/MFA, real notification providers, DC/WAN/LB/quorum/watchdog/fencing, production recovery and workload endurance remain deferred acceptance. Isolated kernel capture and temporary database fixtures do not replace those checks.

Vendor appliance advisories remain open. The broader roadmap was explicitly excluded from this ten-finding pass. Passing tests or a release gate does not certify production or organizational compliance.
