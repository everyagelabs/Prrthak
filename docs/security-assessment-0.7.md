# 0.7 pilot-candidate security assessment

1 November 2026. This is a scoped engineering assessment and remediation record, not an independent penetration-test certificate or a claim that the application has no vulnerabilities. Native RHEL 8/9, Ubuntu 26.04, live Microsoft Entra, physical fencing and DC/WAN testing remain deferred.

## Application checks

- Bandit 1.9.4 scanned controller, appliance and scripts, including test fixtures. No high-severity findings. Lower-severity findings remain recorded, rather than suppressed. The high-confidence medium findings are fixed local-test HTTP calls and intentional manager/socket directory permissions; dynamic SQL/process warnings still require contextual review.
- pip-audit 2.10.1 found no known advisories in the eight resolved controller dependencies. The deployed dependency set must be reassessed when rebuilt.
- govulncheck 1.9.0 found no known affected vulnerabilities in the project's Go source/compiled agent with Go 1.27.3.
- Local adversarial HTTPS tests cover individual role checks, CSRF, exact mutation scope, mTLS identity, real listener isolation, stale/revoked authority, direct Admin changes and rollback/recovery fencing. These do not replace external testing of an installed bank environment.
- Linux CI exposed a command-lease file-close/startup race in the first candidate. Candidate `.2` uses an independently owned CLOEXEC descriptor, retains the inherited lock until process-tree drain and adds concurrent-close/start-error regressions. See B4 in the remediation map and the selected tag’s CI results.
- A joined-controller leaf failed strict issuer-identifier verification before the certificate fix. Candidate `.3` supplies key usage and issuer/subject identifiers; the actual issued leaf and recovery transport pass strict checks. Independent Linux checks cover eight generated certificate paths. TLS verification remains enabled.
- Signed startup, installed manager-byte checks and a deliberately modified application were exercised in disposable containers. Modified application code was rejected before its import marker could execute.
- Staged source is checked for complete credential/private-key patterns and prohibited runtime paths. No private state is included in release contexts. This pattern check is not a general data-loss-prevention guarantee.

## Complete appliance image assessment

The counts below describe the local Linux/ARM64 image build; the selected tag’s CI artifacts record its own build and advisories. The scan retains all vulnerability rows, including unpatched and unknown-severity advisories. Rows may repeat the same advisory across packages/binaries; they are not a count of independently exploitable attacks.

| Image | Advisory rows | Critical | High | Rows with a listed fix |
| --- | ---: | ---: | ---: | ---: |
| Controller |435|1|85|0|
| PostgreSQL/Patroni database |424|1|87|0|
| HAProxy router |164|0|43|0|
| etcd 3.6.16 |12|0|0|10, all reported unknown severity |

The two critical IDs are [OpenSSH CVE-2026-60002](https://security-tracker.debian.org/tracker/CVE-2026-60002) in the controller and [libxml2 CVE-2026-6653](https://security-tracker.debian.org/tracker/CVE-2026-6653) in the database image. They remain vendor-package findings in the scanned patched/pinned inputs. The controller still contains the SSH client needed by the supported legacy cluster provisioner; removing it would break that workflow.

The etcd assessment also reports outdated CA/timezone packages and x/net HTML-parser advisories with available upstream dependency fixes. A binary-symbol govulncheck reports GO-2026-6866, GO-2026-6860 and the unmaintained OpenPGP package advisory GO-2026-5932. Symbol presence is not an end-to-end network exploit demonstration; these findings remain open. The [upstream 3.6.16 release notice](https://etcd.io/blog/2026/oct-22-patch-release/) documents that additional reports await subsequent patches. This candidate does not introduce an unvalidated vendor fork to relabel that risk as closed.

CI keeps complete image reports. It gates available high/critical fixes; unknown-severity findings and findings without vendor fixes still require disposition. Therefore a green build is not a clean-VA certificate. Restricting infrastructure to approved management networks is a deployment control, not a code fix or a reason to erase the advisories.

## Release and acceptance boundary

The release signer is a development authority outside the source/Documents tree, not an organizational offline/HSM signer. Public trust must be independently approved and delivered. Online policy signing remains a controller trust boundary. See [release integrity](release-integrity.md).

Use the [review remediation map](review-remediation-0.7.md) for B1–B5, M1–M8 and S1–S6. The 20-server pilot should begin with inventory/monitoring and complete the deferred native lockout, kernel, systemd and firewalld checks before enforcement. Review remaining vendor findings and organization-specific regulatory evidence with the deployment/security owner.
