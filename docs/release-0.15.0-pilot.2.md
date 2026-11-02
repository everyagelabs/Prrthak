# 0.15 Local accounts and SSO · candidate 2

3 November 2026. This candidate adds Local username/password accounts alongside Microsoft Entra OIDC and GUI-configured SAML 2.0. Both account sources use Read Only, Admin and Super Admin. Ordinary policy changes still use one authenticated Admin; this release introduces no second-approver mode.

On an empty, GUI-first installation, local `admin` / `admin` is a one-time Super Admin bootstrap. First login permits only password replacement, auth status and logout. Every created/reset local account also requires replacement before workspace access. Super Admin alone provisions accounts, assigns roles, disables users, resets other local credentials and revokes sessions. Any local role can change its own password after current-password verification.

Passwords use salted, bounded scrypt; attempts are shared and throttled, sessions rotate on password changes and credential versions retire old access. No password goes to an endpoint, browser storage, audit details or `.env`. Local/SAML settings live in the metadata database and propagate to controllers through that shared store. SAML errors do not remove local repair access; quarantined controllers retain their business-API barrier.

SAML uses uploaded public IdP metadata and SP-initiated login, with both response and assertion signatures, exact issuer/audience/recipient/destination/request matching, bounded time validity, browser binding and replay protection. Trust saves require the current GUI revision and advance a new provider epoch. Claims do not create users or grant roles: a Super Admin provisions the exact persistent NameID. The current profile uses unsigned AuthnRequests and rejects IdP-initiated login. See [operator instructions](local-and-saml-login.md) and [API contracts](api-contract.md).

The installer remains one command with GUI configuration. Existing Entra accounts are retained; upgrades never seed default credentials into a populated estate. Reviewed initial Entra bootstrap can coexist with local users. Tenant migration retires previous-tenant Entra users while retaining Local/SAML accounts. The GUI listener and restart workflows distinguish local availability from actual directory configuration and preserve the configured SSO origin.

## Validation

Candidate 2 fixes a nondeterministic learning test: a buffered observation now has an explicit capture time before the recorded stop boundary, and a separate case rejects observations captured after that boundary. The production capture-window check is unchanged. The same source passed that test on the previous tag but failed it on the parallel main run when the wall clock crossed a second; the failed run is retained as evidence. Agent package instructions now correctly describe Local/SSO Admins and 0.14-agent compatibility.

The 137 signed runtime files, runtime manifest (`792d9309e02441d6abb790444cd2d93135e56ea9cefbc8395d93bf3b4844d2fb`) and all three compiled binaries are unchanged from candidate 1. The published Local/SAML capacity records retain their actual candidate-1 source/test hashes; they measure these same controller/endpoint runtime bytes. Candidate 2 changes test fixtures, generated package instructions and current documentation only.

| Check | Result |
| --- | --- |
| Full private controller / PostgreSQL suite | 1,170 passed; zero skips or failures |
| Dashboard | 413 passed; zero skips or failures |
| Full native-helper / HTTPS / PostgreSQL integration | 330 passed; one Linux-kernel-only macOS skip, covered on Linux |
| Go | Race suite 108.763 s and vet passed; native + Linux AMD64/ARM64 builds passed |
| Final-source password / SAML HTTPS cases | 17 passed on PostgreSQL and all 17 on Linux; no external IdP used |
| Full isolated Linux baseline | Controller 989 passed / 181 external-fixture skips; integration 296 passed / 35 external-fixture skips |
| Final-source isolated Linux follow-up | Controller 137 passed / 14 PostgreSQL skips; integration 51 passed with zero skips or failures |
| Packaging / integrity | 13 controller-package cases, 4 runtime-manifest cases, signed 137-file startup, host-manager and tamper-before-import checks passed |
| Source dependency audit | No known Python dependency vulnerabilities; all static findings retained, no high-severity Bandit finding |
| Local-authorized 5,000-identity delivery | Changed policy + complete 30-second polling window: **34.325 s**; zero final failures |
| SAML-authorized 5,000-identity delivery | Changed policy + complete 30-second polling window: **35.345 s**; zero final failures |

The final production-only token restriction and generated installation instructions received the focused final-source checks above after the complete baseline suites. Those checks include four actual CLI application-port restart/rollback cases and 13 native endpoint-configuration cases. Baseline results are retained separately rather than relabeled as later runs. The exact tagged source is also checked by the [CI workflow](https://github.com/everyagelabs/Prrthak/actions/workflows/ci.yml).

Each final fleet fixture retained 100 expired full-fleet sessions / 500,000 memberships before measurement, then verified 5,000 exact current Admin authorities and signed passive observation leases in each of three phases. All 10,000 mixed observations were retained as separate connection/packet units; queues drained. These are persisted canonical human-session fixtures, not real IdP exchanges, 5,000 agent processes or native enforcement receipts. [Capacity results](controller-capacity-5000.md) bind exact hashes, workload, timing and owned database cleanup.

All 488 frozen code/test files, the runtime signature and three compiled binaries remained unchanged during the final measurements. Source identity and detached artifacts bind the [candidate tag](https://github.com/everyagelabs/Prrthak/tree/v0.15.0-pilot.2); the existing development signing authority still requires independently approved public-pin distribution.

The exact 0.14 production agent source also accepts the new provider-attributed proofs and rejects changed bindings in a disposable compiled regression. Existing 0.14 endpoints therefore need no reinstall for this human-login feature. Newly built payloads are stamped 0.15.0.

The unchanged [0.14 illustrated guide](guide/prthak-pilot-0.14.0.html) remains an installation/operations baseline. It does not illustrate the new login screens; use the current authentication guide above.

## Acceptance limits

No organization IdP/Conditional Access/MFA, native RHEL/Ubuntu host, DC deployment or real 20-server enforcement pilot was used. Shared-database and isolated Linux fixtures do not certify WAN/LB/quorum/fencing or native OS behavior. Vendor appliance advisories remain retained; a passing gate is not a clean VA claim. The broader roadmap remains outside this change.

© 2026 Airtel Payments Bank. All rights reserved.
