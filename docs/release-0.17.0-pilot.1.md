# 0.17 Universal installers and refreshed picture guides

3 November 2026. This candidate adds one installer command per component across the supported Linux families. Application configuration remains in the GUI. Run from independently verified, extracted, root-owned release files; neither bootstrap can establish its own authenticity before execution.

## Resulting behavior

| Component | One command | Automatic preparation |
|---|---|---|
| Controller · RHEL 9 / Ubuntu 26.04 | `sudo ./scripts/install-controller.sh` | Protected Python 3.9+, local rootful Docker Engine and Compose v2; then the existing GUI setup manager |
| Endpoint · RHEL 8/9 / Ubuntu 26.04 | `sudo ./scripts/install-agent-auto.sh --setup-file /root/prthak-agent-setup.json` | OS/CPU checks, signed binary/unit and GUI kit validation, missing OS packages, then the systemd agent |

The VM still needs systemd, root/sudo, approved repositories, DNS/time, suitable storage and approved network paths. A server team or deployment tool stages the verified media first; minimal machines need ordinary transfer/extraction tools for that step. The installer does not configure an external load balancer or host/network firewall exposure. The running application and endpoint do not need Git. The static endpoint needs no separate Python or Go runtime.

Compatible controller dependencies are reused. A stopped existing Docker service may be started without changing its enablement. Fresh Docker is enabled/started and read back. Existing container stacks, foreign repositories/keys and unsafe privileged plugin paths block rather than being overwritten or removed. Dependency operations use bounded fixed commands and clean environments; repository public keys and packages retain authenticated vendor checks. The controller validates GUI/default configuration before Docker/package operations. The minimal missing-Python bootstrap necessarily precedes Python validation. Existing `--env-file`, `--validate-only` and `--no-start` prepared-host paths remain available and skip dependency provisioning.

The endpoint prepares packages only after complete setup and signed runtime validation. Its existing service-start suppression journal preserves UFW/firewalld activity, including on package failure. It never activates firewalld or migrates UFW. Optional GUI UFW assessment remains unchecked by default. Automatic dependency consent is local to the explicit installer invocation and never rewrites an older GUI setup or enables enforcement, learned access or monitoring. Read-only and staged/no-start paths install no packages. Legacy family installers remain available.

The GUI removes the Linux-family choice and manual dependency checkbox, retains matching CPU selection, and shows the universal command. One valid reusable fleet setup can enroll the pilot or a larger fleet, with a distinct local key/certificate per endpoint. Origin, polling and other application settings stay in existing GUI workflows; manual `.env` or JSON editing is not required.

## Guides and packaging

The separate [controller](guide/simple/controller-installation.pdf) and [agent](guide/simple/agent-installation.pdf) guides now each have nine illustrated steps and two reference sheets. Updated synthetic screenshots show the actual 0.17 preview. Ports, authentication, GUI settings, onboarding, discovery, tags, optional transfer, troubleshooting and expected resource allowances are included. All 22 pages have the author note. Browser editions embed all pictures and provide copyable commands. Render/text/browser checks are recorded in [guide verification](guide/simple/verification.json). Historical guide exports remain unchanged.

Signed outer archives include the new controller shell/Python prerequisites and universal agent script. Controller archives also include the exact allowlisted simple-guide assets. Runtime signatures continue covering their existing binary/unit or controller runtime scope; the shell prerequisites are not falsely presented as self-verifying runtime members. Native RPM/DEB payload delivery requires the universal entrypoint for versions 0.17 and later; the previous archive format remains accepted. RPM/DEB payloads are inert and do not perform configuration or activate firewall policy.

## Validation

| Check | Result |
|---|---|
| Full private PostgreSQL/controller suite | **1,188 passed**, no failures/errors/skips; final source unchanged |
| Full PostgreSQL/HTTPS/native-helper integration | **389 passed**, one expected Linux-kernel-only macOS skip; final source unchanged |
| Dashboard | **417 passed**, no failures/skips |
| Controller dependency/bootstrap + packaging checks | **67 passed** (27 dependency, 6 shell dispatch, 34 packaging); mocked host changes only |
| Endpoint installer family/auto checks | **26 passed**, no skips with fresh native helper |
| Go | Full race suite and vet passed; native, Linux AMD64 and ARM64 builds passed |
| Runtime, syntax and guide QA | 137 signed public files match; make check, shell syntax, all-page PDF/text and browser image/layout checks passed |
| Python dependencies | Pinned controller requirements audit found zero known vulnerabilities |
| Static review | No HIGH Bandit findings; all 247 MEDIUM and 371 LOW findings retained for review |

These tests use isolated local fixtures, including real private PostgreSQL and a native administration-host helper. Package-manager/service outcomes in installer tests are mocked; no RHEL/Ubuntu OS installation or real server firewall changes were performed. Shell transfer blocks pass syntax checks. Both current PDF editions were rendered and inspected; all browser images load without horizontal overflow at the checked viewport. The controller signed runtime matches 137 public files.

## Acceptance limits

Native RHEL 8/9 and Ubuntu 26.04, package repository availability/hooks, host systemd/firewalld, SSH/controller rollback, DC/DR/fencing and the actual 20-server pilot remain deployment acceptance, deferred at the user's request. Start with one endpoint in monitor-only mode. The [0.16 image scans and 5,000-identity measurements](release-0.16.0-pilot.1.md) remain historical results for those exact builds and workloads; this installer change does not relabel them as fresh 0.17 evidence. Existing pinned image recipes and tagged CI assessment remain in place. A passing code test or a zero-finding scan is not a production approval.

Controller pilot allocation starts at 4 vCPU / 8 GiB; 5,000-server management-only controllers at 8 vCPU / 16 GiB, and combined database voters at 8 vCPU / 32 GiB. These are starting allocations, not constant utilization. Agent planning allowances and historical passive measurements are distinguished in the guides and [resource note](agent-resources.md). Native workload measurement is still needed.

© 2026 Airtel Payments Bank. All rights reserved.

<sub>Created by Pratik Srivastava</sub>
