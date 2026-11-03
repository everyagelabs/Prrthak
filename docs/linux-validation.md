# Prṛthak (पृथक्) disposable Linux smoke validation

## v0.4 exact-port learning and additive auto-allow: genuine Ubuntu VM

The separate task-created `prthak-learning-lab` profile passed on **Ubuntu 24.04.4 LTS ARM64**, genuine systemd PID1 and official-repository **firewalld 2.1.1**. It had no host-folder mounts, SSH-agent forwarding or application-port forwarding. Public sources/binaries were staged; temporary enrollment credentials, PKI and SSH keys stayed inside the VM. The existing default profile/context remained unchanged.

`TestRealLearningAllowSystemdLab` passed in **37.66 seconds**. It verified actual kernel source-IP → TCP443 evidence with no 22/80/2022 instrumentation; exact source-specific runtime/permanent accept-only commit; stopped-session persistence; another source still blocked; SSH2022 unaffected; staged-health rollback; explicit SIGKILL fencing by a separate systemd service and a completed independent rollback journal before agent recovery; and reviewed deletion restoring closed443. This engine fixture uses a controller-health callback with real SSH, so the complete wire was tested separately.

`scripts/lab-learning-allow-controller.py` passed all five phases, then passed its final rerun after host-membership hardening. The real Python traffic worker received a real kernel hit through the Go flow spool, retained durable evidence, generated the visible443 policy and delivered it over mTLS. The actual `/api/v1/agent/learning-allow/check` HTTP/SSH witness validated the exact grant before the agent committed runtime/permanent accepts. Session stop removed observation instrumentation while the accepted source stayed allowed and another source stayed blocked. Reviewed deletion removed both scopes, closed443 and remained removed on later polls. The normal managed bundle was unchanged.

Real nftables output exposed an adjacent-prefix parser case (`PREFIX:IN=interface`); both learning and unexpected-port parsers now strip their exact owned prefix before interpreting ingress fields. Regression tests cover it. Final Go regular/race tests and vet pass. Controller/dashboard/integration acceptance passes **217 / 130 / 50** tests, including exact443-only selection, full601-pair CSV export, role boundaries, durable replay/retention, two-node PostgreSQL behavior and real native-client enrollment.

Cleanup verified empty test namespaces and runtime/permanent public rich-rule lists, then stopped/deleted only the task-created profile and its data disk. The local validation record is `.local/learning-lab/RESULTS.md`. No RHEL or 5,000-endpoint throughput certification follows from these Ubuntu tests. Genuine RHEL systemd/SELinux/polkit enforcement and live Entra acceptance remain pilot gates.

## v0.2 managed enforcement: genuine Ubuntu systemd VM

The managed adapter passed a separate disposable **Ubuntu 24.04.4 ARM64 VM** with genuine systemd PID1 and firewalld 2.1.1. The VM was a separate Colima profile, with no host folder mounts, forwarded application ports or SSH-agent forwarding. All temporary credentials were generated inside that VM. Its firewall and private test namespaces were separate from the macOS host and other projects.

`TestRealManagedSystemdLab` passed in 43.68 seconds, then passed the final reviewed rerun in 46.94 seconds. It proved new TCP connections from an allowed source succeed and a second source is blocked despite an existing broad port allowance; actual SSH 2022 retains only the approved management source; runtime/permanent read-back succeeds; staged-health failure restores the exact previous rules; and a **separate systemd timer/service kills a blocked apply subprocess and restores the prior policy independently**. The test used a shortened 25-second deadline for this failure case; production uses 120 seconds. Cleanup removed its exact rules and fixtures and left the VM's existing SSH 22 unchanged.

The additional `scripts/lab-managed-controller.py` fixture passed with the real Python controller, compiled Go agent, development CA/mTLS enrollment, a controller in a private source network namespace and a real standalone SSH 2022 daemon. It verified:

- One automatic enrollment, actual custom-port SSH discovery and protected-config reporting.
- Two-step exact policy authorization; source accepts and rejects override legacy broad allows; a real newly established controller mTLS connection and source-bound SSH-banner probes pass before permanent success.
- Stopping the actual controller process after runtime staging causes exact rollback. After both sides restart, the failed approval remains held and the previous applied version remains visible.
- Restoring policy revision 1 creates a new higher version, requires new approval and retains immutable bundle/outcome history.
- Reviewed cleanup removes only owned rules and resumes the original legacy allowances.

The first runs exposed a missing fixture SSH runtime directory, a test racing incomplete compensation, incompatible summary status strings and missing last-good metadata in the Go/Python contract. These were corrected and the complete scenarios were rerun successfully. The real network test is valuable alongside mocks: unit success alone did not reveal those integration gaps.

The lab wrapper is `scripts/test-managed-lab.sh`. It refuses ordinary execution unless explicitly opted in with `PRTHAK_DISPOSABLE_LAB=1` and a disposable VM marker. Stage only public binaries/controller sources, never repository state or host credentials. The Python end-to-end fixture likewise requires root, systemd, a detected VM and the marker.

These checks cover this Ubuntu VM and private test networking. They do not certify every RHEL/Ubuntu release, SELinux enforcing mode, a production bastion topology, all IPv6 failure cases or a 5,000-host soak. The 20-server pilot has not started.

On 2026-10-30 the compiled Linux ARM64 endpoint agent passed a real process/socket discovery and mTLS smoke in both of these official base images:

| Base image | Reported userland | Architecture | Result |
| --- | --- | --- | --- |
| `ubuntu:24.04` | Ubuntu 24.04 | ARM64 | PASS |
| `registry.access.redhat.com/ubi9/ubi:latest` | RHEL UBI 9.8 | ARM64 | PASS |

The Ubuntu image resolved to `sha256:fe81560990fae86dc4743202b2cb4d3df98d0bcf949173cecef15ce1127ef852`. The public UBI image resolved to `sha256:5f08e80aa970ae77712e75e5e857ac0b396abc900823c4d041c1150a9538a13f`. Tags may move; these identify the bases used for this run.

## What the smoke proved

Each disposable container ran an actual OpenSSH daemon listening on **2022/tcp**, a temporary TLS controller, and the compiled agent in `--once` mode. The agent:

- Generated its own key/CSR and enrolled using a private one-time token over verified HTTPS.
- Discovered the actual SSH listener with Linux `ss`, including owning `sshd` process and PID.
- Reported the service as **SSH** on port 2022 through process identity.
- Created exactly one server record automatically; a second start reused the mTLS identity and kept one record.
- Reported a 900-second discovery interval and the expected preview policy state with `applied_version=0`.

Representative result from each run:

```json
{
  "result": "PASS",
  "architecture": "arm64",
  "runtime_uid": 65534,
  "server_count": 1,
  "ssh_port": 2022,
  "service": "SSH",
  "process": "sshd",
  "mTLS": "enrolled",
  "second_start_reuses_identity": true,
  "policy_state": "preview",
  "firewalld_state": "not-running",
  "discovery_interval_seconds": 900
}
```

## Isolation and reproduction

The runtime was non-root UID 65534 with all capabilities dropped, `no-new-privileges`, a read-only root filesystem, no published ports, and `--network none`. SSH and controller communication used only container loopback. Only a staging directory containing public controller Python sources, compiled Linux binaries and the smoke script was mounted read-only. The repository itself, host credentials, development PKI, host sockets and host firewall were not mounted. Runtime TLS keys, enrollment token, SQLite state and SSH key lived in disposable container `/tmp` and were removed with the container.

The package-install image build needs network access to the official distribution repositories. The subsequent runtime has none. The wrapper limits each profile to about three minutes, removes its runtime container, and keeps only local build-cache images plus ignored public staging files.

With Docker available and fresh Linux binaries built, run from the project root:

```sh
make build-agent
scripts/smoke-linux-container.sh ubuntu
scripts/smoke-linux-container.sh ubi9
```

The wrapper stages only `controller/*.py`, the two compiled Linux binaries and its generated public runner under `.local/linux-smoke/public`. It chooses the binary matching the container architecture. On UBI it installs Python 3.11 for the test controller; the endpoint binary itself has no Python dependency. The smoke uses a temporary SQLite controller store, not a deployment database.

## Boundary

These are container userland checks sharing the Docker Linux kernel. They do not validate booting the endpoint systemd unit, SELinux/polkit/D-Bus permissions, firewalld rule installation, kernel traffic-learning logs, access enforcement, a full RHEL VM, every supported OS release, or production throughput. Firewalld was not running and no access rules were changed. Socket-activation/cgroup enrichment remains covered by parser/unit tests rather than a systemd-booted container here. Actual RHEL/Ubuntu lab machines are still needed for the firewall and service-management matrix.

Shared PostgreSQL/controller-node acceptance and HAProxy syntax validation are documented separately in [the HA runbook](ha.md).

## Separate private firewalld adapter smoke

A separate Ubuntu 24.04 container with firewalld 2.1.1 also passed the approved-change adapter test. It retained the original `allow-host-ipv6` policy. The adapter recognized that policy only through its exact full definition: target CONTINUE, priority -15000, ANY-to-HOST bindings, empty service/port/protocol/NAT fields, and the four known IPv6 ICMP accept rules. Mutated or unknown definitions remain view-only.

The test applied a twice-confirmed **18080/tcp → 18081/tcp** replacement in runtime and permanent configuration, verified both scopes, then injected an old-rule removal failure during **18081 → 18082**. It verified that the exact temporary addition was removed and the original 18081 rule survived. The combined test passed in 8.13 seconds. The test entrypoint is `TestRealApprovedFirewallPrivateLinuxSmoke`, disabled by default and reserved for a disposable prepared namespace.

This additional runtime used root **inside the container**, with all capabilities dropped except NET_ADMIN, `--network none`, no published ports, a read-only root/public-artifact mount, and writable ephemeral `/tmp`, `/run` and `/etc/firewalld`. A private D-Bus/firewalld instance configured only that container's isolated network namespace. No host network, host firewall, host credentials or privileged container mode was used. The adapter performed no reload, flush, target changes or runtime-to-permanent copy. That earlier imported-rule smoke did not exercise managed compiled-policy enforcement. The later genuine VM managed tests are described above; the full RHEL/Ubuntu systemd/SELinux/polkit matrix remains required.

## RHEL managed-enforcement validation gate

The prior official UBI 9.8 discovery/enrollment check remains valid. A new enforcement fixture attempted to install Red Hat firewalld from both official UBI 9 and UBI 8 BaseOS/AppStream/CodeReady Builder repositories on 30 October 2026. The repositories were reachable, but both package builds returned `No match for argument: firewalld`. No RHEL enforcement runtime was run, and no alternate distribution daemon was substituted.

The UBI 9 base digest was `sha256:5f08e80aa970ae77712e75e5e857ac0b396abc900823c4d041c1150a9538a13f`; UBI 8 was `sha256:c322aa68f2d630b36b9faab64094357f62720be2f56f7099376ca2d6c4fe389b`. These identify attempted inputs, not successful enforcement results. An authorized RHEL lab VM/repository providing its firewalld package is required before the 20-server pilot. RHEL kernel, systemd, SELinux and polkit behavior must be tested there; cross-compilation or another distribution's daemon cannot certify those paths.

<sub>Created by Pratik Srivastava</sub>
