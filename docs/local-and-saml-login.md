# Local accounts and SAML SSO

This is the operator guide for Local + SSO authentication in controller **0.16.0**, candidate **v0.16.0-pilot.1**. The current source supports **Local** accounts and **SSO** through either Microsoft Entra OIDC or SAML 2.0. Every account receives one of the same three application roles. The installer remains one command; all account, password and sign-in-provider configuration is done in the GUI.

The [0.14 illustrated pilot guide](guide/prthak-pilot-0.14.0.html) remains an unchanged installation/operations baseline. Its older sign-in screens do not illustrate this addition. Current authentication steps are below and in [authentication](authentication.md). Native RHEL/Ubuntu, DC deployment and live organization IdP/MFA acceptance remain separate work.

## Before signing in

Use an independently verified controller release on the prepared HTTPS origin. Trust its hostname and certificate, provide correct time synchronization and preserve the approved LB/DNS origin. An HTTP synthetic preview does not provide production password or SAML setup.

The controller installer command is unchanged:

```sh
sudo ./scripts/install-controller.sh --gui-setup
```

The installer prepares protected platform configuration and displays the setup URL. Open that HTTPS URL; do not edit `.env`, create a password file or change an agent to configure human login. Local accounts, password hashes, sessions and SAML settings are shared database state. The existing fixed-manager GUI continues to own protected deployment files and Entra client-secret storage.

## First login on a fresh installation

1. Sign in with local username **`admin`** and temporary password **`admin`**.
2. Replace the temporary password immediately. Supply the current password, a new password of **12–256 characters**, and matching confirmation. Passwords are case-sensitive, are not trimmed, reject control characters and are limited to 1,024 UTF-8 bytes.
3. After a successful change, Prṛthak rotates your session and opens the workspace. Other sessions for that account are revoked.

The initial `admin` username receives **Super Admin** so it can create users and configure SSO. Until its password changes, the account has a restricted change-only session: it cannot read inventory or perform policy, user or platform operations. Closing a dialog or making a direct API request does not bypass that restriction.

This built-in account is permanent: it cannot be deleted, disabled, renamed, demoted or have its profile/sign-in source edited, even by another Super Admin. The GUI labels it **Built-in admin · Password changes only**. Its stable bootstrap identity is protected in the API as well as the GUI. Change its own password through **Account → Change password**, or have another Super Admin reset its temporary password. Session revocation remains available. These protections also apply to an existing account created by the earlier local bootstrap; an unrelated user named `admin` is not mistaken for that identity.

The default account is created **once, only when the retained account database is empty**. Its durable bootstrap marker prevents recreation after a restart or SSO activation. A missing or disabled legacy account is never recreated or reactivated by this upgrade. Any retained account, including a disabled one, identifies an existing estate. Upgrading an existing Entra installation therefore does not add `admin`/`admin`; sign in with an existing enabled Super Admin and explicitly create a local account if required.

## Account sources and roles

| Account source | Credentials and identity | Role authority |
| --- | --- | --- |
| Local | A Prṛthak username and password. Usernames are case-insensitive; passwords are case-sensitive. | A Super Admin chooses Read Only, Admin or Super Admin. |
| SSO · Microsoft Entra ID | An existing user's immutable tenant/Object ID, authenticated by the configured OIDC provider. | The provisioned application account, not directory groups or token roles. |
| SSO · SAML | The exact persistent NameID from the reviewed IdP, authenticated by signed SAML. | The provisioned application account, not email, group or role attributes. |

| Role | Allowed work |
| --- | --- |
| Read Only | View permitted infrastructure and history; change its own local password. |
| Admin | Read Only capabilities plus servers, locations, tags, groups, policies, learning, enrollment and supported firewall operations. |
| Super Admin | Admin capabilities plus all application user/role management and privileged platform/sign-in settings. |

Only Super Admin can create users of any role, change their access, reset local credentials or revoke sessions. Admin cannot create even a Read Only account. A Super Admin cannot disable themselves or change their own role; the last enabled Super Admin is protected. Sign-in source does not create an additional permission tier.

## Add and manage local users

1. Open **Users & access → Add user**.
2. Select **Local account**, enter a username, display information and a temporary password, and confirm the password. Choose one role and save.
3. Deliver that temporary credential through your approved private channel. Prṛthak does not send it to a directory or expose it later in the user list.
4. At first login, the new user must choose a personal password before entering the workspace.

For a password reset, a Super Admin selects **Reset password** for another local account and supplies a new temporary password and confirmation. Reset revokes that user's active sessions and requires another first-login password change. Enabled/disabled status and role changes have their own session-revocation behavior; changing a role does not reveal or return a password.

An enabled local user of any role selects **Account → Change password** in the top-right menu to change their own password. The current password is required. A successful change rotates that browser session and signs out other sessions for the same account. SSO profiles identify their provider and direct password management to that IdP; they do not display a local-password editor.

A local password change or reset also retires prior credential-bound pending policy authority. Installed firewall rules stay in place. Use a current Admin to review/save affected intent before further delivery or automation; a new password does not silently rearm an old grant.

Local passwords are stored as salted **scrypt hashes**, not plaintext or reversible passwords. Session tokens are random, hashed in the database and bound to the current credential version. Login/password attempts are bounded and throttled with shared per-account state. Passwords are not written to browser storage, user-list responses, `.env` or audit details.

## Configure SAML SSO

Local accounts stay available when SAML is configured. Begin with a fully authenticated Super Admin; the default account must have completed its password change.

1. In your IdP, prepare a SAML application. Obtain its **public metadata XML** containing the intended Entity ID, HTTPS sign-in service and current signing certificate(s). Do not upload a private key.
2. Open **Users & access → Configure SAML**. Enter the approved **Application HTTPS origin**, the **SP Entity ID**, and the sign-in button name. Paste or upload the public IdP metadata, enable SAML and save.
3. Configure the IdP's Entity ID/Audience and Reply/ACS URL to match Prṛthak exactly. The GUI displays the ACS URL and provides SP metadata after configuration.
4. Set a **persistent NameID** and require the IdP to **sign both the SAML response and assertion**. This SP sends unsigned AuthnRequests; an IdP that requires signed requests must be configured accordingly before use.
5. Add the intended SAML users as described below. Sign out and choose the configured SSO button to test the real IdP flow.

For origin `https://prthak.example.internal`, the URLs are:

| Setting | Value |
| --- | --- |
| Application origin | `https://prthak.example.internal` |
| Reply URL / ACS | `https://prthak.example.internal/api/v1/auth/saml/callback` |
| Download SP metadata | `https://prthak.example.internal/api/v1/auth/saml/metadata` |
| SP-initiated sign-in | `https://prthak.example.internal/api/v1/auth/saml/login` |

Replace the example origin with the trusted hostname and port in your deployment. The Entity ID is the exact value you choose in the GUI; do not assume it is automatically the ACS URL. This is SP-initiated SSO: unsolicited/IdP-initiated assertions are rejected.

SAML settings are validated and saved to the shared database without a manual `.env` edit or a service-restart command. Saves bind the revision captured when the form was opened. If another Super Admin changes the provider first, a stale save is rejected and its draft is kept; close it, refresh Users & access, and review the current trust configuration before resubmitting. This is concurrency protection, not an additional approver workflow.

A saved configuration change invalidates previous SAML sessions, unfinished login states and future authority tied to the old configuration. If the caller used SAML, the GUI returns them to sign-in. Local accounts remain usable. Provider errors are shown without claiming SAML is available or removing local access. Entra's separate supervised provider-cutover workflow may revoke application sessions during convergence; account availability does not promise that an old session survives every platform change.

## Grant SAML users application access

1. Open **Users & access → Add user** and select **SSO · SAML**.
2. Enter the exact persistent **SAML subject/NameID** used by the IdP. It is case-sensitive and must match the provisioned subject; email display information is not an alias. The backend accepts 1–512 characters and rejects surrounding whitespace and control characters.
3. Enter optional display information, choose Read Only, Admin or Super Admin, and save.
4. The user starts sign-in from Prṛthak's SSO button. A valid assertion without an enabled provisioned account still receives no workspace access.

There is no general just-in-time provisioning and no automatic role grant from SAML groups, email addresses or role claims. Updating an account's display email does not change its sign-in binding. An existing local account is not silently linked to an SSO account with the same email.

The controller validates XML structure and reviewed signing certificates, exact issuer/audience/destination/recipient, request matching and time conditions. State and response/assertion replay checks prevent repeated or cross-browser consumption. The SAML POST callback uses its separate short-lived `SameSite=None; Secure` browser-binding cookie; full application sessions use Secure, HttpOnly, host-only, SameSite=Lax cookies and CSRF protection for mutations.

## Keep or add Microsoft Entra OIDC

Existing Microsoft sign-in remains supported. Use **Settings → Setup** for initial Entra tenant/client/callback, secret and candidate verification, or for reviewed provider changes. Its callback remains `/api/v1/auth/callback`, separate from SAML's ACS route.

For initial activation, configure and verify the intended Entra Super Admin Object ID in the GUI, activate the reviewed settings, then complete that exact person's normal Entra sign-in. Only that configured identity can receive the first Entra Super Admin grant when there are no retained Entra accounts. Local/SAML users do not block that explicit initial Entra flow; retained Entra records, including disabled ones, prevent repeat bootstrap. Local accounts remain separate and are not converted into directory users.

A local or SAML Super Admin operating Setup must enter the candidate's **actual Entra Object ID**. Its own application identifier cannot replace an Entra object ID. On later tenant migration, only previous-tenant Entra records are retired; local/SAML records are retained, while sessions and pending reviews may be invalidated by the coordinated cutover. See [the Entra provider lifecycle](authentication.md#active-provider-changes-rotation-and-joined-convergence).

## Agents, enforcement and acceptance

This addition changes human sign-in and application authorization. Endpoint enrollment, mTLS, assignment signatures and policy formats continue through the existing protocol; **0.14 agents remain compatible** and do not need a reinstall to support local/SAML users. Human credentials are never sent to endpoints. All Admin identities retain the same local opt-in, exact scope, SSH/controller protection, rollback and actual-outcome requirements. Whole-server default deny still needs its dedicated manually checked downtime acknowledgement.

Repository tests exercise real locally signed SAML fixtures, wrong trust/identity/time/replay cases, local credential and first-login restrictions, role/session revocation and shared GUI workflows. They do not connect to your live IdP or prove its MFA/Conditional Access, reverse-proxy cookie behavior, cross-site HA operation or native endpoint/DC behavior. Validate the actual organization configuration before using it in the real pilot.

© 2026 Airtel Payments Bank. All rights reserved.

<sub>Created by Pratik Srivastava</sub>
