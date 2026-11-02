# Install the controller from a verified release

**Preferred 0.14.0 pilot flow:** after prerequisites and verified extraction, run
`sudo ./scripts/install-controller.sh --gui-setup` once and complete configuration
in **Settings → Setup**. No manually prepared `.env` is needed. See
[GUI pilot installation](pilot-gui-installation.md). The file-based procedure
below remains an advanced compatibility path for existing installations.

Git is an optional way for an administrator to obtain approved source. The installed controller, local manager and containers do not invoke Git. A verified controller installation archive carries the required public source and setup files, so Git is not required on a management VM or an endpoint. Use the reviewed candidate from https://github.com/everyagelabs/Prrthak and pin its exact release commit when choosing the source-checkout route.

## Host prerequisites

Use the [VM sizing and layout requirements](controller-vm-requirements.md) for the intended fleet and retention. The controller installer requires:

- A real Linux host with systemd as PID1, root access, and a protected root-owned Python **3.9+** interpreter and ancestors. The image supplies the controller Python runtime/dependencies; the host manager uses the system interpreter. Do not run the privileged manager with a user-writable virtual environment.
- Local Docker Engine and the **Compose v2** plugin, prepared through your approved OS/vendor procedure. Remote Docker endpoints are not accepted by the fixed manager. No Node.js or Go compiler is required on the controller VM.
- A dedicated persistent `DATA_ROOT`, such as `/var/lib/prthak` or `/mnt/prthak`, with protected root-owned ancestors. The installer rejects symlinks, traversal, unsafe roots and unrelated contents. Docker image/build/log storage remains in Docker's configured storage location.
- Reserved UID/GID **10001** for the locked no-login `prthak-controller` host identity. The installer creates it when safe and rejects collisions, aliases or unrelated group members. The application container runs as UID10001 and never receives the Docker socket.
- Approved registry and package access: the installer builds images using PostgreSQL/Debian bases and OS/Python packages, and pulls the configured etcd and HAProxy images. An approved mirror can be part of the deployment environment. This source archive is **not an offline image installer**, and an unattended offline-image import workflow is not supplied.

Installation does not disable UFW/firewalld or open host firewall ports. Arrange DNS, TLS, LB routing, approved access paths and native OS behavior in your deployment phase. Local code/fixture tests do not certify RHEL/Ubuntu, SELinux/polkit, hardware watchdogs or physical DC/DR failover.

RHEL 8's default Python3.6 is insufficient for this host manager. Prepare an approved root-owned Python3.9+ interpreter without replacing the OS Python. If it is not the `python3` selected by root's PATH, set `PRTHAK_INSTALL_PYTHON` to its absolute path when invoking the installer, for example `/usr/bin/python3.11` if that approved interpreter is installed.

## Obtain and verify a release

The source archive is named `prthak-controller-0.14.0.tar.gz`. It contains public runtime Python modules, browser assets, Dockerfiles, fixed local manager/helpers, `.env.example`, installer/verifier and these guides. It excludes tests, populated environment files, keys, certificates, databases, private state and agent binaries.

Top-level public Markdown runbooks and `agent/README.md` are included to preserve installation and operational references. The current illustrated 0.14.0 HTML/PDF guide is included under docs/guide. Source-local evidence links can also refer to private assessment artifacts, generated capacity results, historical illustrated guides or development fixtures; those historical/private artifacts are not part of this runtime installation archive. Obtain the separately retained assessment/source evidence when reviewing those historical measurements. Agent installers and binaries are distributed in their separate verified endpoint packages.

Before extraction, use an independently approved copy of `verify-release.py`, a separately provisioned trusted public release pin, and the detached signature:

```sh
python3 /approved/tools/verify-release.py \
  --public-trust-file /approved/trust/prthak-release-public-trust.json \
  --signature prthak-controller-0.14.0.tar.gz.signature.json \
  prthak-controller-0.14.0.tar.gz
```

Use an approved administration tool environment supporting Ed25519 verification. Python3.10+ with the compatible `cryptography` requirement is recommended; the running installed endpoint needs neither. A public key downloaded next to an untrusted archive does not establish authenticity. The included `deploy/release-public-trust.json` describes the current **local project** public authority; it is not independent organizational approval.

Place the verified archive and extracted release in protected root-owned locations before privileged execution. Do not run the root installer from a shared writable checkout. The tar has only regular relative files under one versioned directory. For a protected archive already verified through your approved process:

```sh
sudo install -d -o root -g root -m 0755 /opt/prthak/releases
sudo tar --no-same-owner --no-same-permissions \
  -xzf /protected/releases/prthak-controller-0.14.0.tar.gz \
  -C /opt/prthak/releases
cd /opt/prthak/releases/prthak-controller-0.14.0
sudo install -o root -g root -m 0600 .env.example /root/prthak-node.env
sudoedit /root/prthak-node.env
```

The alternative is an approved source checkout, pinned to a reviewed release commit. Prepare a protected release copy before running the same installer. No real repository URL is invented here; Git is a source-distribution choice, not a runtime prerequisite.

## Configure and validate

The same `.env.example` and installer are used at Noida, Pune, cloud and other management sites. Give each node a unique `NODE_ID`, `SITE` and reachable `NODE_IP`. Set `DATA_ROOT`, a stable HTTPS `CONTROLLER_ORIGIN`, approved bind/port values and initial worker/database-pool settings appropriate to the VM plan. The default dashboard/API publication is 8787. The installed profile separates management HTTPS 8787, policy/control HTTPS 8788 and enrollment/discovery HTTPS 8789. The legacy combined profile is an explicit compatibility option.

Keep all enrollment, cluster, replication, signing and Entra secrets out of source control. Blank optional bootstrap secrets are generated privately by the installer. A cluster join still requires verified HTTPS trust; the cluster password alone does not establish node identity. Joining/HA setup and operational configuration are managed through the Platform GUI after authenticated setup.

Configure the complete Entra tenant/client/callback/first-Super-Admin identity and a protected client-secret file for organizational SSO. Setup-token access is distinct from a completed live Entra login. Maintain appropriate Super Admin continuity for operations. Normal Admin actions do not require a second person; destructive recovery requires two explicit confirmations by the same authorized Super Admin. The installer preserves existing credentials/auth and refuses silent secret rotation.

Run the non-mutating configuration validation first:

```sh
sudo ./scripts/install-controller.sh --env-file /root/prthak-node.env --validate-only
```

This parses the private environment file as data, never as shell. It excludes secret values from output. It does not test Docker availability, OS packages, external routing, live Entra, database quorum or native fencing.

## Install and operate

```sh
sudo ./scripts/install-controller.sh --env-file /root/prthak-node.env
```

The installer creates protected state/build contexts, builds/pulls the images, initializes local setup identity and starts its fixed manager plus controller/router. The command prints the private initial-admin-token **file path**, never the token. Verify the configured controller's TLS trust before sign-in. `--no-start` stages the installation without starting services; it still requires real host prerequisites and performs image preparation.

Initial setup is distinct from shared PostgreSQL HA activation. A management member does not automatically become a database voter. Three approved database/etcd voters, verified native watchdog/fencing and the intended quorum/replication layout are required before database promotion; a single `.env` cannot bypass those checks. Use the GUI for the supported cluster, TLS, port, backup, storage and service workflows. The real 20-server pilot and native/DC validation remain deployment work.

Reinstall preserves existing private identity and GUI-owned settings. Stop the fixed manager for the reviewed reinstall procedure; a different `DATA_ROOT` requires the explicit GUI storage-migration workflow. Keep separately protected backups and the original trusted release for recovery. Do not replace source/images during an active recovery or firewall transaction.

## Release publisher commands

From a frozen reviewed source tree, preview inputs without creating an archive:

```sh
python3 scripts/package-controller.py --dry-run
```

Create the source archive in a private output directory:

```sh
python3 scripts/package-controller.py --output-dir /private/release-output
```

Unsigned output is for isolated lab use. Set `PRTHAK_RELEASE_SIGNING_KEY_FILE` to the separately provisioned private seed to invoke the existing detached-signature tool. The seed is never packaged. Existing output is refused unless `--overwrite` is explicitly supplied for a reviewed unpublished rebuild. The builder uses allowlisted public inputs, refuses selected symlinks/special files and populated secret fields in `.env.example`, normalizes archive paths/modes, and writes a per-file manifest plus checksum. These controls do not replace source review or the independent signature-verification decision.
