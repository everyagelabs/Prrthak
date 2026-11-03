# 0.8.0-pilot.1 · Whole-server default deny

1 November 2026. This candidate adds the explicitly requested whole-server ingress option to selected servers or current members of saved groups. No endpoint is enabled by installation or an ordinary policy save.

## Delivered behavior

- A dedicated GUI preview shows exact enforce-mode source/port grants, endpoint identities, versions, protected SSH/controller paths and declared network-control exceptions.
- A new review starts with its downtime checkbox unchecked. An authenticated Entra Admin must manually acknowledge that exact review before pushing. No second person is required. Changed intent, configuration, context or membership cannot reuse an earlier acknowledgement.
- Compatible agents need a separate signed local opt-in. They stage IPv4/IPv6 rules, protect management paths, arm independent rollback, check fresh management connections and read back runtime/permanent rules.
- Global rejection applies to new host-ingress connections. Loopback, existing tracked sessions, protected SSH and declared ICMP/DHCP client controls remain reachable. Outbound, forwarding and container segmentation are outside this adapter; unsupported network contexts are blocked.
- Later changed deny-bearing bundles stay pending. Disable removes the global fallback while retaining last-applied grants; explicit ordinary cleanup can subsequently remove remaining owned controls. Future group members are not enabled silently.
- Late historical receipts remain auditable without regressing current status or last-good state. Concurrent reviews, never-applied cancellation, empty application matrices and opt-in removal are covered.

See [the workflow and diagram](whole-server-default-deny.md). Upgrade controller and selected endpoints together; ordinary disabled/omitted flags preserve legacy configuration and policy hashes.

## Validation

| Check | Result |
| --- | --- |
| Full controller with real private PostgreSQL | 855 passed; zero skipped |
| Full private-PostgreSQL/HTTPS/installer integration | 287 passed; one Linux-kernel-only case skipped on macOS |
| Linux Python 3.13 integration | 253 passed; 35 PostgreSQL-only skips, covered by the separate private-PostgreSQL run; the Linux peer-credential case passed |
| Dashboard | 289 passed |
| Go | Full local suite/vet and Linux ARM64 race/vet passed |
| Feature Go cases | 15 top-level / 51 including subtests passed |
| Python-to-Go compatibility | Real signed enable/disable assignments, approvals, configuration digest and health witness verified, with negative mutations |
| Isolated Linux firewalld packets | IPv6 enabled and disabled; approved/denied sources, legacy-open override, SSH banner, network controls, staged replacement, health-failure rollback, global-only removal and unchanged forwarding passed |
| 5,000 virtual certificate identities | Admin edit + publication + full 30-second poll window 32.157 seconds; zero final failures |
| Release integrity | Signed image startup and modified-byte rejection before import passed |
| Source/dependencies | Bandit zero HIGH; eight pinned Python dependencies and Go source scan zero known advisories |

The five new Bandit B608 reports in the controller feature module were reviewed: dynamic SQL fragments are fixed internal expressions/paths; identifiers, search values, limits and selected IDs use parameters. This is a disposition of those findings, not a claim that every static warning is a false positive.

The passive agent resource baseline is historical and excludes this enforcement workload; see [resource evidence](agent-resources.md) and [controller VM sizing](controller-vm-requirements.md). No installed DC server or real endpoint firewall was changed during development.

## Remaining deployment acceptance

Native RHEL 8/9 and Ubuntu 26.04 VMs, SELinux/systemd, real Entra sign-in, bastion routes, DC/WAN/LB/quorum/fencing and endurance acceptance remain deferred. The real 20-server enforcement pilot starts after those operator-run checks, with a small canary. Existing upstream/vendor image findings remain open as documented in [the security assessment](security-assessment-2026-10-31.md). Development release trust is documented in [release integrity](release-integrity.md); organization-approved distribution is separate.

<sub>Created by Pratik Srivastava</sub>
