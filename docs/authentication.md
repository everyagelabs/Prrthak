# Local accounts, SSO and application access

Prṛthak supports two account sources: **Local** username/password accounts and **SSO** identities authenticated by Microsoft Entra ID OIDC or SAML 2.0. Both sources use the same three application roles. A Super Admin provisions each account and its role; email, directory groups and IdP role claims never create or promote users automatically.

The [Local and SAML login guide](local-and-saml-login.md) gives the current GUI steps. The existing [GUI pilot installation](pilot-gui-installation.md) supplies the unchanged one-command installer procedure. Authentication changes do not require an endpoint-agent installation or new agent protocol; the 0.14 agents remain compatible. The 0.14 illustrated pilot guide is a baseline and has not been regenerated for the new login screens.

## Prerequisites

- Use the independently verified controller release. Its managed image supplies the controller authentication dependencies; source-development environments install `controller/requirements.txt`.
- Prepare a stable HTTPS application origin, trusted certificate, DNS and time synchronization. Local password login and browser sessions require HTTPS; an HTTP synthetic preview does not activate production accounts or provider configuration.
- Use the same shared metadata database across HA controllers. Accounts, password hashes, sessions, role assignments, local bootstrap state and SAML configuration are durable database state.
- For SAML, obtain the intended IdP's **public metadata XML** and permission to configure its enterprise application. Configure the exact SP Entity ID, HTTPS reply/ACS URL and persistent NameID. The IdP must sign both the response and assertion and accept unsigned SP authentication requests. SAML metadata is uploaded in the GUI, not fetched from a user-supplied URL.
- For Entra OIDC, prepare a single-tenant confidential Web application, its client secret, exact HTTPS callback and the intended Entra Super Admin Object ID. The controller needs outbound HTTPS to `login.microsoftonline.com:443` for discovery, token exchange and signing keys; browsers need the organization's approved sign-in/MFA endpoints. Directory assignment and Conditional Access/MFA remain IdP-owned configuration.

No manual `.env`, JSON or password-file editing is part of the supported GUI procedure. The fixed manager still writes protected deployment settings; local password hashes and SAML configuration live in the shared metadata database. Password values are not stored in `.env`, returned by user listings or written into audit details.

## Fresh local bootstrap and password changes

On the **first start of an empty account database**, Prṛthak creates local username **`admin`** with temporary password **`admin`** and role **Super Admin**. The username does not imply the lower Admin role. The first login issues a restricted password-change session: no inventory, policy, user-management or platform operation is available until the password is replaced.

Enter the current password, a new password of **12–256 characters** and its confirmation. Passwords are case-sensitive and not trimmed; control characters are rejected and the encoded value is limited to 1,024 UTF-8 bytes. A successful change rotates the session, revokes other sessions for that account and opens the workspace. The forced-change screen cannot be dismissed to bypass the server-side restriction.

The initial account is seeded once. A durable bootstrap marker prevents its recreation on restart, after SSO configuration or after later account changes. The built-in `admin` is protected by its stable bootstrap identity: no account deletion, disable, rename, role, profile or provider edits are allowed, including from another Super Admin. Password change/reset and session revocation remain available. Earlier seeded accounts gain this protection without recreating missing users or reactivating disabled credentials. Any retained account record, including a disabled one, makes the database an existing deployment: upgrading an Entra estate does **not** add an `admin`/`admin` backdoor. Its existing Super Admin can create an explicitly chosen local account through **Users & access**.

Every newly created or reset local account receives a temporary password and must change it at its next login. Any enabled local user, including Read Only, can change their own password through the top-right **Account → Change password** menu by supplying the current password. Only Super Admin can reset another local user's password; reset revokes that user's sessions and restores the mandatory next-login change. Directory passwords remain managed by the IdP.

Local credentials use salted, bounded **scrypt** hashes. Login attempts and password verification are rate-limited, with shared per-account attempt state and generic sign-in errors. Raw passwords are never kept in browser storage or application account records. Session tokens are random and stored hashed; role, enabled status, provider configuration and local credential version are checked on subsequent requests.

## Exactly three roles for both account sources

| Capability | `read_only` | `admin` | `super_admin` |
| --- | --- | --- | --- |
| View permitted infrastructure, policies, traffic, alerts and activity | Yes | Yes | Yes |
| Change own local password after verifying current password | Yes | Yes | Yes |
| Create/update/retire servers; manage locations, tags and groups | No | Yes | Yes |
| Manage policies, learning, enrollment and reviewed firewall operations | No | Yes | Yes |
| List/create any application user; assign any of the three roles | No | No | Yes |
| Change/disable/reactivate users; reset local passwords; revoke sessions | No | No | Yes |
| Change platform, sign-in, certificate and notification settings; perform guarded database recovery | No | No | Yes |

Admin and Read Only cannot create even another Read Only account or promote themselves. Super Admin cannot change their own role or disable their own account; the last enabled Super Admin is protected. Changing an account's role or enabled status revokes its sessions. Password changes and resets affect only local passwords; they do not modify Microsoft or SAML directory credentials.

In **Users & access → Add user**, choose **Local account**, **SSO · Microsoft Entra ID** or **SSO · SAML**. Enter a local username and temporary password, an existing Entra Object ID, or the exact SAML subject/NameID respectively, then choose one role. Existing identity bindings cannot be edited into another account type. Display name and email are labels, not identity or role authority. SSO provisioning creates an application access record, not a directory account.

## Configure SAML in the GUI

A fully authenticated Super Admin opens **Users & access → Configure SAML**, enters the stable HTTPS origin and SP Entity ID, then uploads or pastes the IdP metadata XML. Supply public metadata and certificates only, never a private key. The GUI validates and saves the configuration to the shared database. There is no separate service restart or CLI configuration step.

The default routes are:

| Purpose | URL relative to the approved application origin |
| --- | --- |
| SP metadata XML | `/api/v1/auth/saml/metadata` |
| Start an SP-initiated sign-in | `/api/v1/auth/saml/login` |
| Assertion Consumer Service / Reply URL | `/api/v1/auth/saml/callback` |

Configure the IdP with the exact Entity ID and ACS URL. Select a persistent NameID, enable **signed SAML response and signed assertion**, and allow unsigned AuthnRequests. IdP-initiated/unsolicited login is not accepted. A Super Admin must add the exact NameID as an SSO user and choose its role before that person can enter Prṛthak. No email alias, group membership or role attribute substitutes for this record.

The SAML toolkit validates XML structure and signatures against the reviewed metadata certificates. The controller also binds issuer, audience, destination, recipient, `InResponseTo`, time and one-use request/response identifiers. Browser-bound RelayState prevents an assertion from being consumed in another browser. The SAML callback's temporary cookie uses `SameSite=None; Secure` for the cross-site POST; ordinary application sessions remain `SameSite=Lax; Secure; HttpOnly`.

Changing the SAML configuration invalidates existing SAML sign-in state, sessions and future authority from the old configuration. A SAML Super Admin who changes their own provider is returned to sign-in. Local accounts remain available. Invalid or unavailable SAML dependencies hold SAML sign-in without silently disabling local access. Existing installed firewall rules are not deleted merely because an IdP configuration changes; future actions still require current authority.

## Register and configure Microsoft Entra OIDC

The existing Microsoft sign-in remains available alongside local accounts and configured SAML. It uses OIDC, not the SAML callback described above.

1. In Microsoft Entra admin center, create an **App registration** for accounts in this organizational directory only.
2. Add a confidential **Web** redirect URI matching `https://prthak.example.internal/api/v1/auth/callback`, replacing the hostname with the approved origin. Do not select a SPA callback or implicit grant for this adapter.
3. Record the Directory tenant ID and Application client ID, create a client secret and obtain the intended Entra user's immutable Object ID. Email, an application object ID and a client ID cannot replace a user's Object ID.
4. Configure enterprise-application assignment and Conditional Access/MFA under organizational policy. Prṛthak requests `openid profile email`; it does not use Microsoft Graph directory-write permissions or import IdP role/group claims as application roles.

Microsoft references: [register an application](https://learn.microsoft.com/en-us/entra/identity-platform/quickstart-register-app?tabs=client-secret), [Web redirect configuration](https://learn.microsoft.com/en-us/entra/identity-platform/how-to-add-redirect-uri), and [application access management](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/what-is-access-management).

### GUI setup and existing deployments

After the one-command controller install, change the fresh local bootstrap password, then use **Settings → Setup** for Entra tenant/client/callback, client-secret and candidate Super Admin configuration. The fixed manager writes private settings and supervises readiness and rollback. Candidate sign-in proves the exact reviewed Entra identity without creating an ordinary session or activating pending settings.

After initial activation, the exact configured Entra Super Admin completes normal sign-in. That identity can receive the first Entra Super Admin record only when there are no retained Entra accounts; local/SAML records do not block this explicit flow. Retained Entra records, including disabled ones, prevent repeat bootstrap. Candidate verification alone creates no application account before activation.

A local or SAML operator must enter the candidate's **actual Entra Object ID**. Their own local/SAML object identifier is not reused as an Entra identity. Existing Entra accounts remain provisioned when local authentication is introduced; a Super Admin can add local users without replacing or relinking directory users.

The legacy environment-based Entra configuration remains a compatibility path, documented in the [environment example](../.env.example). It is not an instruction to hand-edit production files for this GUI flow. Never move client secrets into JavaScript, Git, URLs or command arguments, or configure both raw and file-based client secrets.

## Active provider changes, rotation and joined convergence

Use **Settings → Setup** for existing Entra tenant/client/callback or client-secret changes. A current Super Admin reviews the exact public values and hidden credential replacement, verifies the expected candidate, then applies the exact digest/nonce/phrase. No Admin or Read Only user can authorize provider changes. A saved review, candidate proof or queued job is not activation.

For a same-tenant change by an Entra Super Admin, the candidate must identify that same directory person. A local/SAML operator or a new-tenant migration supplies the explicit reviewed candidate Object ID. Candidate verification grants no general just-in-time access; activation admits only the exact reviewed SSO target. Retain previous credentials and HTTPS aliases through verified completion so rollback remains usable.

For a changed callback origin, the original authenticated GUI provides a two-minute one-use verification code. Open the candidate origin's verification page, enter that code there, complete Microsoft sign-in and refresh the original review. The code is not placed in a URL. Normal login on an old alias redirects to the canonical origin before creating its host-only browser-binding cookie.

The registered controller set is frozen. Each node prepares its local revision/digest, applies through its fixed manager and verifies before shared authority flips. Runtime/port changes affect the review creator; peers retain their own runtime settings. A failed or unavailable member cannot supply a success receipt. The retained native context supports rollback, and joined encrypted profiles use reviewed convergence into protected local provider files rather than manual repair.

Entra provider fingerprints and authority epochs fence current login/control admission and future joins. Cutover invalidates old sessions and unfinished authority; new-tenant migration retires previous-tenant Entra records and admits the exact reviewed SSO Super Admin. Local and SAML account records are not converted into Entra users. Live provider/MFA, site partitions and native rollback remain deployment acceptance work.

## Session and operational behavior

Local login posts credentials to `/api/v1/auth/local`. Microsoft OIDC starts at `/api/v1/auth/login` with authorization code, PKCE S256, state, nonce and browser binding. SAML starts at its separate login route and accepts only a matching SP-initiated POST response. Successful full sign-in creates an application session; initial/reset local passwords receive the restricted change-only session first.

Application session cookies are Secure, HttpOnly, host-only and SameSite=Lax. Mutations require session CSRF protection and approved origins. Credential changes rotate sessions, and logout removes the application session. An IdP browser session may remain signed in after local application logout. Legacy shared role tokens remain explicit lab/compatibility mechanisms and do not authorize installed production firewall changes.

Role authority is the shared database. Account disablement, role changes, password reset and session revocation apply across controllers. IdP-side disablement and Conditional Access changes apply at next SSO sign-in; no Continuous Access Evaluation or background directory password synchronization is claimed.

Repository tests use locally signed OIDC and SAML fixtures, browser/CSRF integration fixtures and isolated databases. They do not contact a live organization IdP. Deployment acceptance must check all three roles, first-password/reset flows, disabled/unprovisioned users, actual metadata/certificates, SSO and MFA, wrong issuer/audience, replay, expiry and HA session behavior against the intended environment. See the [API contract](api-contract.md).

## Direct administrative changes

An authenticated **Admin** or **Super Admin** saves policies, server groups,
service groups and central metadata directly. Saving a managed policy publishes
its effective desired rules; there is no separate rollout approval, checker,
pilot-mode switch, 20-host authorization limit or seven-day consent expiry.
Saved symbolic selectors and group references authorize later source/target
membership resolution. The compiler issues exact per-host versions from that
intent, including newly tagged servers. Every agent still checks its signed
assignment, local opt-ins, protected SSH/controller baseline and rollback health.

A reviewed learned-policy suggestion applies in one Admin action. Starting
explicit automatic learning authorizes the selected hosts and port filter;
a fresh discovery freezes the actual eligible ports, then observed sources can
be allowed automatically within that learning window. No second person approves
initial learning. Protected SSH/controller ports and local auto-allow opt-ins
still apply. Ordinary policy deletion retains its normal confirmation and
revision check.

Explicit deny/destructive imported firewall changes, restrictive learned-policy
removal and database recovery retain **two distinct explicit confirmations by
the same current actor**, with fresh nonces and the exact final typed phrase.
Database recovery is Super Admin only. An active-provider change uses one current
Super Admin's verified candidate and exact Apply action; all-node preparation,
authority cutover and rollback protections remain.

Audit/signed delivery uses `single_admin` evidence bound to the current local or SSO
identity, exact intent/digest and provider authority epoch. Live role revocation,
stale previews and changed provider authority stop new admission. Old pending
maker/checker or retired pilot reviews cannot be promoted; historical evidence
is retained. Shared bearer tokens cannot authorize installed production firewall
changes. Only Super Admin creates or changes application users and platform
configuration; direct workflow changes no RBAC permission.

## Endpoint security configuration and release trust

Human sessions and endpoint identity have separate purposes. Install the signed
matching verified endpoint package once using its GUI-generated, private monitor-only setup
file and the matching RHEL/Ubuntu family installer. That bootstrap grants no
managed-enforcement, imported-rule, auto-allow or unexpected-port opt-in.

For later changes, use **Install agent → Configure an enrolled endpoint**: choose the exact fresh
host, local flags, protected management CIDRs/SSH ports, zone and management/
control/discovery origins in the GUI. The current local or SSO Admin/Super Admin saves
that exact reviewed configuration directly. Transfer the signed
`prthak-endpoint-configuration.json` privately as root-owned 0600. Run one matching
verified family installer, for example:

```sh
sudo ./scripts/install-agent-rhel.sh --configuration-file /root/prthak-endpoint-configuration.json
```

Use `install-agent-ubuntu.sh` for Ubuntu. The wrapper invokes the fixed
`--apply-configuration` helper. Do not edit JSON. The exact endpoint receipt
commits the transition; a 90-second independent timer restores old config/trust
if confirmation fails. This local opt-in is separate from subsequent policy or
learning authority. Existing identity/assignment trust stay pinned, and old/new
control origins must authorize the same deployment through the transition.

With an existing fleet, changing controller control/discovery publishers also
requires the GUI alias acknowledgment. Keep both old/new agent URLs available
through an externally configured LB until signed endpoint kits are verified.
The controller does not configure external routing or claim seamless direct-port
migration. See the [single-command pilot steps](pilot-gui-installation.md).

Independently approve the release-signing pin and verifier before extracting or
executing an archive; adjacent downloaded keys are not a trust decision. Runtime
checks cover signed public application source, agent/service bytes, Docker
bootstrap and configured host-manager startup verification. Mutable settings,
PKI and inventory are separate. Integrity checking does not encrypt application
code or defeat host root/signing-key compromise. Protect private signing-key
custody independently; endpoints receive public release and assignment trust.

## Expected CPU, RAM and storage

These are planning allocations, not measured limits or a production sizing guarantee.

| Endpoint agent item | Historical evidence / starting allowance |
| --- | --- |
| Agent RSS | **10.42 MiB median; 12.50 MiB maximum** |
| Agent plus active read helpers | **56.79 MiB sampled memory peak** |
| Stabilized CPU | Agent **0.046% of one core**; including completed helpers **0.216% of one core** |
| Monitoring allowance | Start with **128 MiB RAM** for the agent and helpers |
| Temporary-learning allowance | Start with **256 MiB RAM**; source cardinality and event rate affect usage |
| CPU allocation | The passive sample did not require a dedicated core; discovery/learning bursts and current-release utilization remain unqualified |

The historical sample was **95 seconds in an Ubuntu 26 ARM64 container**, with
an empty policy and **60/900-second** control/discovery timing. It predates 0.7,
used no enforcement or learning, and excludes firewalld/D-Bus, kernel/source-set
memory and journal storage. It is not native RHEL/systemd acceptance. The current
GUI profile is 30/900 seconds, so these numbers do not measure that workload.
Peaks are sampled observations, not enforced resource limits. Application and
host firewall resources need their own allowance. Preserve the original
[agent resource method and evidence](agent-resources.md) when interpreting them.

| Controller deployment role | Starting CPU | Starting RAM | Persistent allocation |
| --- | ---: | ---: | --- |
| Single-controller 20-server pilot | **4 vCPU** | **8 GiB** | **100 GiB SSD**, plus an **80 GiB OS/Docker disk** |
| 5,000-endpoint management-only controller | **8 vCPU** | **16 GiB** | **100 GiB SSD per node**; size OS/images separately |
| Combined controller/PostgreSQL/etcd voter | **8 vCPU** | **32 GiB** | **300 GiB SSD per node**; size OS/images separately |

Controller CPU utilization has no qualified fixed percentage. Polling, discovery,
policy/source cardinality, concurrent observations, retention, synchronous DB
writes and backups affect CPU, RAM and disk. Monitor the pilot and size backup
storage separately. HA uses three distinct-site DB/quorum voters; the managed
installer co-locates controller/PostgreSQL/etcd on voter VMs. Additional members
can be management-only. A separately dedicated DB topology is not a drop-in
change to this installer. These allocations match the [README sizing scope](../README.md#expected-cpu-ram-and-storage).

## Separate endpoint and signing identities

Human local or SSO sessions do not enroll agents. Endpoint mTLS leaves last 90 days, support authenticated renewal in the 30-day window and tracked 24-hour overlap, and have exact registry revocation plus separately issued one-time recovery credentials. `ca_cert` pins controller web HTTPS; when its corporate/public issuer differs from the endpoint issuer, set `endpoint_ca_cert` to the independently trusted public enrollment CA. Install it before agent preflight: the stock `--ca-file` copies only web trust. Neither renewal nor recovery may replace locally pinned roots using response material.

Ed25519 assignment public keys are pinned separately from both CA chains. A TLS certificate change does not authorize an assignment-signer change. Settings → Certificates displays the public trust/fingerprints; use an independent approved distribution path for initial trust. See [policy and release signing](policy-signing.md) and [the illustrated pilot baseline](guide/prthak-pilot-0.14.0.html).


© 2026 Airtel Payments Bank. All rights reserved.
