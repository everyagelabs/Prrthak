# Microsoft Entra ID sign-in and application access

This is the implemented organizational sign-in path. It requires a real, single-tenant Entra application and HTTPS origin configured by the deployment owner. Repository tests use synthetic identities and locally signed RSA tokens; no live organization tenant is connected by those tests.

## Prerequisites

- Use the verified controller release. Its managed image supplies the Python/PyJWT dependencies; a separate source-development environment must install `controller/requirements.txt`.
- A stable application origin, for example `https://prthak.example.internal`, with DNS and TLS trusted by browsers and agents.
- Permission in the intended tenant to configure the Web application and enterprise application, plus an approved Conditional Access/MFA policy.
- Controller egress to `login.microsoftonline.com:443` for discovery, token exchange and signing keys. Browser access to the organization's approved Microsoft sign-in/MFA endpoints over HTTPS is also required. Proxy/firewall owners supply the current Microsoft endpoint allowlist.
- An existing Entra user Object ID for the initial Super Admin. Use the tenant user's Object ID, not email, application object ID or client ID.
- GUI-generated private provider/secret files and the same committed provider authority on every HA controller; joined profiles converge through the reviewed manager flow.

## Register and configure Entra

1. In Microsoft Entra admin center, open **App registrations > New registration**. Choose accounts in this organizational directory only (single tenant).
2. Add a **Web** redirect URI matching `https://prthak.example.internal/api/v1/auth/callback`, replacing the hostname with the stable origin. This is a confidential Web client even though the dashboard uses JavaScript; do not configure a SPA redirect or implicit grant for this implementation.
3. Record **Directory (tenant) ID** and **Application (client) ID**. Create a client secret in **Certificates & secrets** and protect its value through approved secret management. The implementation supports a client secret, not certificate-based client assertions.
4. Configure enterprise-application assignment and Conditional Access/MFA under organizational policy. These complement the application access table; directory assignment or app-role claims alone do not grant a Prṛthak role. Requested scopes are `openid profile email`; Microsoft Graph directory write permissions are not used.

Microsoft references: [register an application](https://learn.microsoft.com/en-us/entra/identity-platform/quickstart-register-app?tabs=client-secret), [Web redirect configuration](https://learn.microsoft.com/en-us/entra/identity-platform/how-to-add-redirect-uri), and [application access management](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/what-is-access-management).

## GUI configuration and bootstrap (0.7.0)

The supported pilot procedure is [GUI pilot installation](pilot-gui-installation.md):
run the verified controller installer once with `--gui-setup`, then configure
certificates, the stable hostname/origin and provider in **Settings → Setup**.
The fixed manager generates private settings and the service-readable secret
file. No `.env`/JSON editing, secret command argument or manual environment
cleanup belongs in this flow. Retrieve the initial private Super Admin credential
through the approved privileged channel; the installer prints its path only.
There is no anonymous remote configuration wizard.

Enter tenant/client IDs, exact Web callback, client-secret value and first
existing user's Object ID in the GUI. Candidate OIDC verifies that identity
without creating a user/session or activating SSO. After exact review and
activation, the first normal login creates the initial Super Admin; a nonempty
access table stops further bootstrap grants. Provision additional users as needed
in **Users & access**; only Super Admin can do so. Initial provider activation is standalone/pre-HA.

Legacy environment-based deployments remain a compatibility path; the
[environment example](../.env.example) documents that format. They are not the
GUI pilot instructions. Never move secrets into JavaScript, source control,
URLs or command arguments, or configure both raw and file-based client secrets.
Existing joined controllers use the reviewed convergence path below instead of
manual repair. Directory registration, assignment and MFA still happen in Entra.

## Active provider changes, rotation and joined convergence

Use **Settings → Setup** for an existing provider's tenant/client/callback or
client-secret change. The requesting current Super Admin reviews the exact
public values and hidden credential replacement, then verifies the candidate.
Same-tenant verification must identify that requesting Super Admin. A tenant
migration freezes an explicit target-tenant Object ID; its candidate login is
identity proof only, not just-in-time provisioning.

After candidate verification, the same live, enabled current-tenant Super Admin
applies the exact reviewed digest/nonce/phrase in one action.
Admin and Read Only cannot authorize provider changes. Keep the previous
credentials and callbacks valid through verified completion so rollback remains
usable. Candidate proof, a saved review or a queued job is not activation.

For a changed callback origin, retain both HTTPS aliases and certificate trust.
The original authenticated GUI supplies a two-minute, one-use verification code.
Open the candidate origin's verification page and enter the code there; the code
is never placed in a URL. Complete Microsoft sign-in and return to refresh the
original exact review. Normal login on an old alias redirects to the reviewed
canonical origin before creating a host-only browser-binding cookie.

The registered controller set is frozen. Each node prepares its local
revision/digest, applies through its fixed manager and verifies before shared
authority flips. Runtime/port changes affect the review creator; peers preserve
their own runtime settings. A failed or unavailable member cannot supply a
success receipt; retained native context supports verified rollback.

A public provider fingerprint **and opaque authority epoch** gate human/control
admission, readiness and future joins. Old reviews cannot be reused after a
secret-only epoch change. Cutover removes old sessions and invalidates unfinished
approval authority. New-tenant cutover grants the exact reviewed target Super
Admin and retires previous-tenant accounts; it does not copy directory roles.
Provision any additional target-tenant users after normal sign-in. Live provider/MFA,
site partitions and native rollback still need deployment acceptance.

For joined controllers running from an encrypted cluster profile, Setup can
review convergence into protected local provider files after a fresh current
Super Admin candidate sign-in. Effective provider/epoch values then win over
retained profile overrides; the old protected material remains rollback context.
Convergence does not silently replace a different provider or disable guards.

## Exactly three roles

| Capability | `read_only` | `admin` | `super_admin` |
| --- | --- | --- | --- |
| View infrastructure, policies, traffic, alerts and activity | Yes | Yes | Yes |
| Create/update/retire servers; manage locations, tags and groups | No | Yes | Yes |
| Manage policies, learning, enrollment and reviewed firewall operations | No | Yes | Yes |
| List/create any application user; assign any of the three roles | No | No | Yes |
| Change/disable/reactivate users; revoke sessions | No | No | Yes |
| Change platform settings, certificates, notifications; request/approve database recovery | No | No | Yes |

Read Only is view-only. Admin and Read Only cannot create even another Read Only user or promote themselves. Super Admin additionally owns exclusive user management and sensitive platform/certificate/notification/recovery operations. A Super Admin cannot change their own role or disable themselves; the last enabled Super Admin is protected.

In **Users & access**, a Super Admin chooses **Add Entra user**, enters an existing user's Entra Object ID, selects a role and creates the application access record. Display name/email are labels, not identity or role authority. This does not create a person in Entra and does not call Microsoft Graph. There is no general just-in-time provisioning. Disabled records may be reactivated. Local role/enablement changes revoke existing sessions immediately.

## Session and operational behavior

The browser starts at `GET /api/v1/auth/login`. The controller uses authorization code + PKCE S256, one-use state, nonce and browser binding. The callback validates Microsoft's signature, tenant, issuer, audience and time, then finds enabled access by `tid:oid`. Successful sign-in creates a hashed, fixed eight-hour local session. Cookies are Secure, HttpOnly and SameSite=Lax. Mutations require CSRF protection. Legacy bearer tokens are ignored in Entra mode.

Role authority is the shared database, never Entra role/group/email claims. Local disablement, role changes and session revocation apply across HA nodes. Entra-side disablement/policy changes apply at next sign-in; no Continuous Access Evaluation or token refresh is implemented. Sign out removes the local session; the Microsoft browser session may remain signed in.

For acceptance, test all three roles, unprovisioned/disabled identities, wrong tenant, state/nonce replay, role changes and revocation, secret rotation, expiry, both controller backends and actual tenant Conditional Access/MFA. Signed test tokens and synthetic UI screenshots do not replace this exercise. See [API contract](api-contract.md).


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

Audit/signed delivery uses `single_admin` evidence bound to the current Entra
identity, exact intent/digest and provider authority epoch. Live role revocation,
stale previews and changed provider authority stop new admission. Old pending
maker/checker or retired pilot reviews cannot be promoted; historical evidence
is retained. Shared bearer tokens cannot authorize installed production firewall
changes. Only Super Admin creates or changes application users and platform
configuration; direct workflow changes no RBAC permission.

## Endpoint security configuration and release trust

Human sessions and endpoint identity have separate purposes. Install the signed
0.7 endpoint package once using its GUI-generated, private monitor-only setup
file and the matching RHEL/Ubuntu family installer. That bootstrap grants no
managed-enforcement, imported-rule, auto-allow or unexpected-port opt-in.

For later changes, use **Install agent → Configure an enrolled endpoint**: choose the exact fresh
host, local flags, protected management CIDRs/SSH ports, zone and management/
control/discovery origins in the GUI. The current Entra Admin/Super Admin saves
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

Human Entra sessions do not enroll agents. Endpoint mTLS leaves last 90 days, support authenticated renewal in the 30-day window and tracked 24-hour overlap, and have exact registry revocation plus separately issued one-time recovery credentials. `ca_cert` pins controller web HTTPS; when its corporate/public issuer differs from the endpoint issuer, set `endpoint_ca_cert` to the independently trusted public enrollment CA. Install it before agent preflight: the stock `--ca-file` copies only web trust. Neither renewal nor recovery may replace locally pinned roots using response material.

Ed25519 assignment public keys are pinned separately from both CA chains. A TLS certificate change does not authorize an assignment-signer change. Settings → Certificates displays the public trust/fingerprints; use an independent approved distribution path for initial trust. See [policy and release signing](policy-signing.md) and [the illustrated guide](guide/prthak-deployment-guide.html).
