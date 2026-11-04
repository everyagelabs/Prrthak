# Prṛthak v0.18.0-pilot.1

4 November 2026 · Airtel Payments Bank · code and GUI pilot candidate.

This update adds policy impact preview, native packet/byte rule counters, reviewed HTTPS SIEM export, nightly appliance image scans and broader **agent** OS profiles. The separate Network controls and Firewall preparation workflows provide reviewed host outbound rules, expiring quarantine, protected service activation, supported UFW conversion and compatible counter enablement. [How to use each workflow](observability-and-network-controls.md).

Signing remains automatic inside the controller. **Settings → Policy signing** can check the actual key, create an encrypted node-local checkpoint and repair a missing key using the same pinned identity. This is online signing. The checkpoint is not off-node DR, and the GUI does not rotate endpoint trust or export private keys.

| Installer | Accepted profiles |
|---|---|
| Controller | RHEL 9 or Ubuntu 26.04 |
| Agent | RHEL, Rocky Linux, AlmaLinux and Oracle Linux 8/9; Ubuntu 22.04, 24.04 and 26.04 |

Both use AMD64/ARM64 verified release artifacts. Follow the [current command sheets](installation-commands.md) and generate one reusable private fleet setup in the GUI. The agent installer prepares missing utilities with journaled startup protection and leaves existing firewall activity intact. Agent enrollment remains monitor-only. Existing 0.17 picture guides explain the setup flow; use the 0.18 archive names and OS table in the current written commands.

## Local validation of the frozen runtime

| Check | Result |
|---|---|
| Full controller suite on isolated SQLite and PostgreSQL 16 | 1,327 passed; one native-helper case ran in the integration suite |
| Full HTTPS, installer and controller-to-agent integration suite | 390 passed; one Linux kernel peer-credential check skipped on macOS |
| Dashboard | 462 passed; live synthetic GUI inspected for signing, SIEM, impact, counters, quarantine and firewall preparation |
| Agent | Full Go race suite and `go vet` passed; Linux AMD64 and ARM64 builds succeeded |
| Integrity | 148 public runtime files matched the independently verified signed controller manifest; staged source and syntax checks passed |

The controller suite includes real private PostgreSQL backup, restore, join and exact data migration. The SIEM stream is created only on the first eligible event, so an unused exporter does not make a new controller look populated. PostgreSQL backup verification hashes the SIEM sequence in numeric order. Both private suite runs preserved pre-existing databases and roles and removed their owned fixtures. No external receiver or real endpoint firewall was contacted.

## 5,000 virtual identities

The current frozen 0.18 source delivered the changed policy to all 5,000 virtual mTLS identities in **34.955 seconds**, including 4.429 seconds of publication and a complete 30-second polling window. Initial delivery took 23.554 seconds, and the mixed discovery/observation phase took 23.501 seconds. All phases completed with zero final failures. The [measurement record](../output/capacity/controller-5000-0.18-local-result.json) binds the exact controller source, signed runtime, test profile and private fixture cleanup. This is local controller delivery evidence, not native firewall application or a DC endurance result.

The [Pilot validation workflow](https://github.com/everyagelabs/Prrthak/actions/workflows/ci.yml) records GitHub regression, source security, image assessment and tagged build results for this source. The nightly schedule is 02:00 IST, with the same four-image vulnerability gate on a tag or manual run. Consult the exact run and retained raw reports for its findings.

## Before using live enforcement

Start with monitor-only enrollment. Check actual discovered services and endpoint IPs. Review protected SSH and controller paths before using any firewall mutation. The same Admin approves a dangerous change using the exact typed confirmation and a fresh downtime tick. Unsupported native contexts refuse rather than assume equivalent behavior. Quarantine has a fixed local expiry and the dashboard keeps unverified outcomes visible.

Native RHEL/Ubuntu firewalld/systemd/SELinux, real SIEM/SSO, DC failover and the actual 20-server pilot remain deferred. These test results do not certify native enforcement or compliance. The local delivery fixture measures controller policy delivery, not the time to apply rules across a real network.

<sub>Created by Pratik Srivastava</sub>
