# 0.16 Appliance hardening and permanent built-in admin

3 November 2026. This candidate addresses the reported appliance image advisories and makes the original local bootstrap `admin` a permanent account. Local, Microsoft Entra OIDC and SAML sign-in retain the same three application roles and single-Admin policy workflow.

## Resulting behavior

The built-in admin cannot be deleted, disabled, renamed, demoted or have its profile/provider edited, including by another Super Admin. The backend checks its durable bootstrap identity; removing a GUI annotation does not bypass protection. The GUI labels it **Built-in admin · Password changes only** and offers the supported password/reset and session-revocation actions. First-login password replacement, credential/session rotation and ordinary local/SSO account management remain available. Existing seeded accounts gain protection without resetting passwords, creating users or reactivating disabled credentials. See [local accounts](local-and-saml-login.md).

The controller/database use supported digest-pinned PostgreSQL 16.15 / Alpine 3.24 images with Python 3.14; HAProxy remains on supported 3.2 with an Alpine base. The quorum image is a checksum-verified etcd 3.6.16 security rebuild with the two exact patched module versions recorded in [build inputs](../deploy/appliance/etcd-build-inputs.json). Go build metadata and complete package inventories are retained. The installer builds the pinned recipes and records immutable local image IDs.

| Production image | Prior candidate advisory rows | New ARM64 image advisory rows |
| --- | ---: | ---: |
| Controller | 459 | **0** |
| Database | 448 | **0** |
| Router | 183 | **0** |
| etcd | 12 | **0** |
| Total | **1,102** | **0** |

The [public assessment](../output/security/appliance-0.16-scan-summary.json) records exact index/configuration digests, verified filesystem bindings, complete-report hashes, scanner 0.76.1 and the actual vulnerability database version. The reports use the same pinned scanner as CI, without advisory exceptions or metadata removal. Tagged-build CI now rejects every severity, including UNKNOWN/unfixed rows, and rejects missing, malformed, incomplete or end-of-life OS scan evidence. The actual AMD64 tagged-build scan is retained separately by the [CI workflow](https://github.com/everyagelabs/Prrthak/actions/workflows/ci.yml).

## Existing database safety

Alpine/musl is not an in-place physical-data upgrade from Debian/glibc. The fixed manager refuses unmarked nonempty PGDATA before configuration/service activation and preserves existing files. Database-voter enrollment, manifest production and activation require matching runtime profiles from authenticated manager/enrollment state; GUI labels cannot authorize mixed physical replication. Management-only members remain distinct from database voters.

For an existing appliance, create/download a verified logical backup in its GUI before upgrading, preserve the original appliance, then use fresh compatible storage and GUI Recovery. Recovery retains the destination's current authentication and trust/security identity; existing enrollment/CA/DNS/IdP migration still needs explicit acceptance. See [hardening and migration](appliance-image-hardening-0.16.md). The fresh 20-server pilot uses the new runtime directly. Native SSH-managed database deployment remains a separate workflow.

## Validation

| Check | Result |
| --- | --- |
| Full private controller / PostgreSQL suite | **1,186 passed**, zero failures or skips |
| Dashboard | **416 passed**, zero failures or skips |
| Full HTTPS / PostgreSQL / native-helper integration | **344 passed**, one Linux-kernel-only macOS skip |
| Full Alpine Python 3.14 controller suite | **1,005 passed**, 181 external PostgreSQL fixture skips covered by the private PostgreSQL suite |
| Full Alpine Python 3.14 integration | **310 passed**, 35 external PostgreSQL fixture skips; Linux kernel path covered |
| Local/SAML HTTPS replay on fresh PostgreSQL | **19 passed**, zero skips; 38 owned databases created/dropped |
| Agent | Race suite **160.253 s** and vet passed; native, Linux AMD64 and ARM64 builds passed |
| Runtime integrity | 137 signed public files; controller/base startup, host-manager verification and tamper-before-import rejection passed |
| Source dependency/static review | Zero known Python dependency vulnerabilities; no HIGH Bandit findings, all lower-severity findings retained |
| etcd actual container acceptance | Nine checks passed: three-voter mTLS, wrong/absent certificate rejection, quorum operations, leader loss/rejoin and snapshot status/restore |
| Composite appliance modes | Bootstrap/corporate TLS, replication-password rotation, shared coordinator barriers, internal TLS rollover/rollback and logical restore all passed |
| Actual-image 5,000-identity delivery | Local changed policy **45.476 s**; SAML **53.021 s**, including the complete 30-second polling window; zero final failures |

The signed production runtime manifest is `2fb15f937bbc7b279ecd5d3b23f22be6df4d9efdbefd52b5ead9901c6aea6114`. Production image IDs and runtime bytes remained unchanged while test fixtures were corrected. These corrections add valid CA/leaf extensions to synthetic certificates, compare complete initial manager state including the new immutable database-runtime marker, and align the coordinator fixture with the existing shared CA/synchronization-material schema. Initial failing runs are retained separately; their results are not relabeled as passing.

The offline Linux harness uses a resolvable local hostname to prevent unowned hostname lookup from delaying SMTP EHLO. Git and GNU `ps` are test-only tools layered on the exact appliance image for provenance repositories and process-tree assertions. Production notification code, destination IP pinning, TLS verification and credential protections were not weakened. The complete integration suites were rerun after the corrections. Corporate-CA, HA and capacity evidence is retained with the exact image and fixture provenance described in the accompanying records.

The final capacity pair used the unchanged public workload, 5,000 virtual mTLS identities per provider, 100 expired full-fleet sessions / 500,000 memberships, two workers × 32 threads, 64 clients and pools 8/2. The actual shared ARM64 Docker VM had 4 vCPUs / 5.77 GiB; controller plus generator and database were capped at 3 GiB and 1.5 GiB. Every phase verified exact current human authority and passive leases; each mixed phase retained 10,000 typed observations with no pending batches. Three earlier private harness startup failures ran no timed workload and remain separate from the successful pair's zero final failures. Source/runtime hashes, sampled resources, transient retries, scoped cleanup and the post-measurement documentation-only change are in the [capacity record](controller-capacity-5000.md).

## Acceptance limits

A zero-finding scan applies to the recorded images, architecture, scanner and vulnerability database; it does not establish absence of unknown or future vulnerabilities. Local container/shared-database tests do not certify a live organization IdP/MFA, native RHEL/Ubuntu hosts, physical DC/quorum/fencing, an existing-estate identity migration or the real 20-server enforcement pilot. Those deployment/native OS acceptance steps remain deferred as requested. Existing 0.14/0.15 endpoints remain protocol-compatible; this controller hardening does not require an endpoint reinstall by itself. Newly packaged payloads are stamped 0.16.0.

© 2026 Airtel Payments Bank. All rights reserved.

<sub>Created by Pratik Srivastava</sub>
