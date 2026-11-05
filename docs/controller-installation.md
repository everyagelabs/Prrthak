# Install the controller from a verified release

New to Linux? Use the [simple controller picture guide](guide/simple/controller-installation.pdf), or its [browser edition with copyable commands](guide/simple/controller-installation.html). The [end-to-end command sheets](installation-commands.md#controller) include fresh RHEL 9/10 and Ubuntu dependency installation, file transfer, verification, extraction and startup checks.

**Preferred 0.17.0 flow:** after verified extraction on a supported Linux systemd
host, run `sudo ./scripts/install-controller.sh` once. It detects the OS and
prepares dependencies automatically; complete application configuration
through the GUI. At the trusted HTTPS URL, a fresh empty account database uses
local **admin** / **admin** as Super Admin and requires a password change before
workspace access. Local users and optional SAML are managed in **Users & access**;
verified Entra OIDC remains in **Settings → Setup**. No manually prepared `.env`
or initial-token-file retrieval is needed. See
[GUI pilot installation](pilot-gui-installation.md). The file-based procedure
below remains an advanced compatibility path for existing installations.

Git is an optional way for an administrator to obtain approved source. The installed controller, local manager and containers do not invoke Git. A verified controller installation archive carries the required public source and setup files, so Git is not required on a management VM or an endpoint. Use the reviewed candidate from https://github.com/everyagelabs/Prrthak and pin its exact release commit when choosing the source-checkout route.

## Host preparation and automatic dependencies

Use the [VM sizing and layout requirements](controller-vm-requirements.md) for the intended fleet and retention. Automatic preparation supports **RHEL 9/10 and Ubuntu 26.04**, on AMD64/ARM64. It defaults to GUI setup. Provide these foundations:

- A real Linux host with systemd as PID1 and root/sudo access. The installer prepares a protected root-owned Python **3.9+** interpreter when missing; the host manager uses it and the image supplies the application runtime. An older/custom interpreter is not silently replaced. Do not use a user-writable virtual environment for the privileged manager.
- Approved OS and Docker package repositories for connected installation. The installer prepares local Docker Engine and **Compose v2 or v5**, then starts Docker when needed. An existing compatible installation is reused. Conflicting Docker/Podman/containerd packages or uncertain runtime contexts block automatic preparation; the installer does not remove another container stack. Remote/rootless Docker is not supported. No host Node.js, Go or PostgreSQL installation is required. For offline x86_64 installation, use the signed bundle built for the host’s exact RHEL major version. RHEL 10 requires an explicit matching dependency target and EL10 RPMs. Existing RHEL 9 bundles are refused on RHEL 10. See [offline release installation](offline-controller-installation.md).
- A dedicated persistent `DATA_ROOT`, such as `/var/lib/prthak` or `/mnt/prthak`, with protected root-owned ancestors. The installer rejects symlinks, traversal, unsafe roots and unrelated contents. Docker image/build/log storage remains in Docker's configured storage location.
- Reserved UID/GID **10001** for the locked no-login `prthak-controller` host identity. The installer creates it when safe and rejects collisions, aliases or unrelated group members. The application container runs as UID10001 and never receives the Docker socket.
- Approved registry and package access: the installer builds images using pinned PostgreSQL 16/Alpine bases and OS/Python packages, builds the pinned etcd source with its reviewed dependency fixes, and pulls the configured HAProxy image. The etcd builder fetches a checksum-verified upstream archive from `codeload.github.com` and verified Go modules through the Go module/checksum services over HTTPS. These are build-time downloads inside Docker; Git and Go are not required on the host. An approved mirror can be part of the deployment environment. This source archive is **not an offline image installer**, and an unattended offline-image import workflow is not supplied.

Dependency preparation runs only after protected release/OS/systemd checks and uses fixed package/repository actions. Keep SELinux enabled. Installation does not disable UFW/firewalld or open host firewall ports. Arrange DNS, TLS, LB routing, approved access paths and Docker-aware publication filtering in your deployment phase. Local code/fixture tests do not certify RHEL/Ubuntu, SELinux/polkit, hardware watchdogs or physical DC/DR failover.

The prepared-host compatibility paths `--env-file`, `--validate-only` and `--no-start` do **not** install packages or start Docker. They require existing protected Python 3.9+ and the dependencies applicable to that operation. `PRTHAK_INSTALL_PYTHON` may select an approved absolute root-owned interpreter path for such deployments. RHEL 8's default Python 3.6 is insufficient; RHEL 8 is not an automatic controller-preparation target.

## Existing PostgreSQL appliances

This candidate changes the database libc/runtime profile. **Create and download a verified logical backup in the old GUI before upgrading.** Use fresh appliance/storage and GUI Recovery; do not reuse Debian/glibc physical PGDATA with Alpine/musl. The manager preserves and rejects incompatible storage, and database-voter admission requires matching authenticated runtime profiles. See [image hardening and logical migration](appliance-image-hardening-0.16.md). The fresh 20-server pilot uses the new runtime directly.

## Obtain and verify a release

The source archive is named `prthak-controller-0.17.0.tar.gz`. It contains public runtime Python modules, browser assets, Dockerfiles, fixed local manager/helpers, `.env.example`, installer/verifier and these guides. It excludes tests, populated environment files, keys, certificates, databases, private state and agent binaries.

Top-level public Markdown runbooks and `agent/README.md` are included to preserve installation and operational references. The unchanged illustrated 0.14.0 HTML/PDF baseline is included under docs/guide; use [Local/SAML login](local-and-saml-login.md) for the new authentication screens. Source-local evidence links can also refer to private assessment artifacts, generated capacity results, historical illustrated guides or development fixtures; those historical/private artifacts are not part of this runtime installation archive. Obtain the separately retained assessment/source evidence when reviewing those historical measurements. Agent installers and binaries are distributed in their separate verified endpoint packages.

Before extraction, use an independently approved copy of `verify-release.py`, a separately provisioned trusted public release pin, and the detached signature:

```sh
python3 /approved/tools/verify-release.py \
  --public-trust-file /approved/trust/prthak-release-public-trust.json \
  --signature prthak-controller-0.17.0.tar.gz.signature.json \
  prthak-controller-0.17.0.tar.gz
```

Use an approved administration tool environment supporting Ed25519 verification. Python3.10+ with the compatible `cryptography` requirement is recommended; the running installed endpoint needs neither. A public key downloaded next to an untrusted archive does not establish authenticity. The included `deploy/release-public-trust.json` describes the current **local project** public authority; it is not independent organizational approval.

Place the verified archive and extracted release in protected root-owned locations before privileged execution. Do not run the root installer from a shared writable checkout. The tar has only regular relative files under one versioned directory. For a protected archive already verified through your approved process:

```sh
sudo install -d -o root -g root -m 0755 /opt/prthak/releases
sudo tar --no-same-owner --no-same-permissions \
  -xzf /protected/releases/prthak-controller-0.17.0.tar.gz \
  -C /opt/prthak/releases
cd /opt/prthak/releases/prthak-controller-0.17.0
sudo ./scripts/install-controller.sh
```

The alternative is an approved source checkout, pinned to a reviewed release commit. Prepare a protected release copy before running the same installer. No real repository URL is invented here; Git is a source-distribution choice, not a runtime prerequisite.

## Complete setup in the GUI

The installer prepares protected state/build contexts, builds or pulls images,
initializes the local setup identity and starts the fixed manager/controller/router.
Open the displayed HTTPS setup URL and verify its hostname/certificate through
the approved private channel. No token-file or CLI password retrieval is needed
for this normal new-installation flow. A legacy private setup token may still be
prepared internally; it is not the local-user login procedure.

On a fresh empty account database, sign in as local **admin** with temporary
password **admin** and complete the mandatory **12–256-character** password
change. Until then the session cannot read inventory or perform workspace
operations. Bootstrap is durable and never repeated on restart, SSO activation
or later account changes. The built-in admin cannot be deleted, disabled, renamed or demoted; its password can be changed or reset. Existing estates retain their users; their enabled
Super Admin creates any additional local accounts explicitly.

Use **Settings** for node/site/IP, data root, stable HTTPS origin, approved
certificates, management/control/discovery publication and worker/database pools.
The default published ports are 8787/8788/8789 respectively. The fixed manager
writes protected deployment files and supervises any required restart/readback.
Users do not edit `.env` or secret files manually. Use **Users & access** for
local accounts, all three roles, local password reset and optional SAML from
public IdP metadata. **Settings → Setup** retains candidate-verified Microsoft
Entra OIDC configuration. See [current authentication](local-and-saml-login.md).

Initial setup is separate from shared PostgreSQL HA activation. Management-only
nodes are not DB voters; managed promotion requires three approved voters,
verified native watchdog/fencing and the intended quorum/replication layout.
A cluster password does not replace verified HTTPS identity. Use the GUI for
supported joins, TLS, port, backup, storage and service operations. The real
20-server pilot and native/DC/IdP acceptance remain deployment work.

Reinstallation preserves installed identity and GUI-owned settings. Stop the
fixed manager for the reviewed reinstall procedure; a changed DATA_ROOT needs
the explicit GUI storage migration. Keep separately protected backups and the
original trusted release for recovery, and do not replace source/images during
an active recovery or firewall transaction.

## Advanced compatibility: existing environment-based installations

`--env-file`, `.env.example`, `--validate-only` and `--no-start` remain available
for existing or explicitly reviewed compatibility workflows. They are not
required for the GUI-first installation above. An existing private environment
file must have protected ownership/mode and contain the correct node, site,
origin, bind/port and storage values. Reinstallation preserves configured
credentials and refuses silent provider/secret rotation. Use the supported GUI
for later changes instead of editing live managed files.

For an already prepared compatibility file, read-only validation is:

```sh
sudo ./scripts/install-controller.sh --env-file /root/prthak-node.env --validate-only
```

It parses the file as data and redacts secrets. It does not test Docker, native
OS packages, routing, live SSO/MFA, DB quorum or fencing. `--no-start` stages the
installation and still needs genuine host prerequisites/image preparation.
Neither option bypasses current GUI authentication or HA safety checks.

## Release publisher commands

From a frozen reviewed source tree, preview inputs without creating an archive:

```sh
python3 scripts/package-controller.py --dry-run
```

Build the signed Linux agent archives first, then pass their directory when creating a controller release that hosts both agent downloads in **Agent setup**.

```sh
python3 scripts/package-controller.py --agent-dist /private/signed-agents --output-dir /private/release-output
```

The agent input directory must contain matching AMD64 and ARM64 archives and both detached signatures. The packager verifies the archives with the controller release trust pin before embedding them. The installer stages them for download from the controller, alongside the GUI workflow for creating a private setup JSON. Omit `--agent-dist` to produce a source-only build candidate for isolated lab use or later packaging.

Set `PRTHAK_RELEASE_SIGNING_KEY_FILE` to the separately provisioned private seed to sign the controller archive. The seed is never packaged. Existing output is refused unless `--overwrite` is explicitly supplied for a reviewed unpublished rebuild. The builder uses allowlisted public inputs, refuses selected symlinks/special files and populated secret fields in `.env.example`, normalizes archive paths/modes, and writes a per-file manifest plus checksum. These controls do not replace source review or the independent signature-verification decision.

<sub>Created by Pratik Srivastava</sub>
