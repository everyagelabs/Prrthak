# End to end installation commands

Use these command sheets with the picture guides. Choose the section matching the machine you are using. Product configuration stays in the GUI; do not edit `.env` or agent JSON.

**These are commands for fresh dedicated Linux machines.** They have been checked against the installers and official package instructions, and checked for shell syntax. Native RHEL/Ubuntu execution and DC deployment remain pending. Existing installations need the documented upgrade/recovery procedure.

You need sudo/root, approved repositories, working DNS/time, the supplied signed pilot packages and independent release trust. Your infrastructure team must provide the approved network paths and persistent storage. Docker-published ports need approved upstream or Docker-aware filtering; ordinary UFW rules alone do not establish isolation.

The current private Git repository does not by itself supply built agent binaries. Use the signed pilot ZIP provided with the release. Its `payloads` folder contains the archives. The GUI downloads the private agent setup file separately.

## Controller

### Prepare a fresh RHEL 9 controller

**Run on the new RHEL 9 controller VM.** Sign in with your Linux account and sudo access. Use a dedicated systemd VM with approved repositories, fixed IP/DNS, correct time and mounted persistent storage. Keep SELinux enabled. Your server team provides this login and SSH host identity. Run the dependency commands below inside the resulting SSH window.

**On your laptop first - replace YOUR_USER and CONTROLLER_IP**

```sh
ssh YOUR_USER@CONTROLLER_IP
```

**RHEL 9 only - prepare Python and Docker**

```sh
set -eu
sudo dnf install -y python3 tar curl ca-certificates dnf-plugins-core
sudo dnf config-manager --add-repo \
  https://download.docker.com/linux/rhel/docker-ce.repo
sudo dnf install -y docker-ce docker-ce-cli containerd.io \
  docker-buildx-plugin docker-compose-plugin
sudo systemctl enable --now docker
python3 --version
sudo docker version
sudo docker compose version
```

Python must be **3.9 or newer**; Compose must be **v2**. If packages conflict with an existing container stack, stop and ask your server team. Do not remove working services to force installation.

Allow approved browser access to **8787** and agent access to **8788/8789**. Ask the network team to restrict Docker-published ports and private backends; do not assume ordinary host firewall rules alone protect published container ports. Native RHEL acceptance remains pending.

### Prepare a fresh Ubuntu controller

**Run on the new Ubuntu 26.04 controller VM.** Skip this page if you used RHEL. Use a dedicated systemd VM, sudo access and approved download access. The commands add Docker's official package repository. Your server team provides this login and SSH host identity. Run the dependency commands below inside the resulting SSH window.

**On your laptop first - replace YOUR_USER and CONTROLLER_IP**

```sh
ssh YOUR_USER@CONTROLLER_IP
```

**Ubuntu 26.04 only - prepare Python and Docker**

```sh
set -eu
sudo apt-get update
sudo apt-get install -y python3 tar ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
  -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc
. /etc/os-release
PRTHAK_DOCKER_ARCH=$(dpkg --print-architecture)
sudo tee /etc/apt/sources.list.d/docker.sources >/dev/null <<EOF
Types: deb
URIs: https://download.docker.com/linux/ubuntu
Suites: $VERSION_CODENAME
Components: stable
Architectures: $PRTHAK_DOCKER_ARCH
Signed-By: /etc/apt/keyrings/docker.asc
EOF
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io \
  docker-buildx-plugin docker-compose-plugin
sudo systemctl enable --now docker
python3 --version
sudo docker version
sudo docker compose version
```

If an existing container installation conflicts, stop for review. Keep current firewall protection enabled. Restrict public **8787/8788/8789** and private backends through approved network/Docker controls. Native Ubuntu acceptance remains pending.

### Copy the controller release to the VM

First obtain **prthak-controller-0.16.0.tar.gz** from your release administrator. They must approve its signature using independently trusted release identity before transfer. A Git source ZIP is not this installation archive; no GitHub release download URL is assumed.

**On your laptop - replace YOUR_USER and CONTROLLER_IP**

```sh
ssh YOUR_USER@CONTROLLER_IP
```

**In that controller SSH window - create a private upload folder**

```sh
mkdir -p "$HOME/prthak-media"
chmod 0700 "$HOME/prthak-media"
```

**In a SECOND laptop terminal - replace the file path and address**

```sh
scp "/PATH/TO/prthak-controller-0.16.0.tar.gz" \
  YOUR_USER@CONTROLLER_IP:prthak-media/
```

An approved graphical file-transfer tool can do the same copy. Keep the original archive name. Return to the first SSH window for the next page. You do not need Git on the controller.

### Check the bytes and install the controller

These checks apply only to the signed **0.16.0** archive supplied with this guide. The checksum detects changed bytes; it does not replace independent signature/publisher approval. Stop if the check does not print **OK**.

**RHEL 9 or Ubuntu 26.04 - protect, check, extract and install**

```sh
set -eu
sudo install -d -o root -g root -m 0700 /var/tmp/prthak-media
sudo install -o root -g root -m 0600 \
  "$HOME/prthak-media/prthak-controller-0.16.0.tar.gz" \
  /var/tmp/prthak-media/prthak-controller-0.16.0.tar.gz
PRTHAK_SUM=56742a9c77bbef803e6a17bfd048494070db37b8f35d19cdb21bd8995a2f92bb
printf '%s  %s\n' "$PRTHAK_SUM" \
  /var/tmp/prthak-media/prthak-controller-0.16.0.tar.gz \
  | sudo sha256sum -c -
sudo install -d -o root -g root -m 0755 /opt/prthak/releases
sudo tar --no-same-owner --no-same-permissions \
  -xzf /var/tmp/prthak-media/prthak-controller-0.16.0.tar.gz \
  -C /opt/prthak/releases
cd /opt/prthak/releases/prthak-controller-0.16.0
sudo ./scripts/install-controller.sh --gui-setup
sudo systemctl status prthak-appliance-manager.service --no-pager
sudo docker ps
```

Open the printed **HTTPS setup URL** after verifying certificate trust. A fresh empty installation uses **admin / admin** and forces a password change. Finish settings in the GUI; no manual .env file is needed. Initial setup uses SQLite; PostgreSQL HA is a separate later stage.

## Agent

### Prepare the endpoint and copy the files

In the controller GUI, choose **Fleet setup · reusable** and tick **Install missing OS dependencies** BEFORE downloading the private setup. This authorizes the signed helper to install firewalld/network packages while preserving existing firewall activity. Existing UFW stays active; no firewall cutover occurs.

**On your laptop - open the endpoint SSH session**

```sh
ssh YOUR_USER@SERVER_IP
```

**In the endpoint SSH window - prepare tar and a private upload folder**

```sh
set -eu
. /etc/os-release
case "$ID:$VERSION_ID" in
  rhel:8|rhel:8.*|rhel:9|rhel:9.*) sudo dnf install -y tar ;;
  ubuntu:26.04)
    sudo apt-get update
    sudo apt-get install -y tar ;;
  *) printf '%s\n' 'Unsupported endpoint OS'; exit 1 ;;
esac
mkdir -p "$HOME/prthak-media"
chmod 0700 "$HOME/prthak-media"
```

**In a SECOND laptop terminal - copy the approved files**

```sh
scp "/PATH/TO/prthak-agent-0.16.0-linux-amd64.tar.gz" \
  "/PATH/TO/prthak-agent-0.16.0-linux-arm64.tar.gz" \
  "/PATH/TO/prthak-agent-setup.json" \
  YOUR_USER@SERVER_IP:prthak-media/
```

The release administrator must verify both archive signatures before transfer. Copying both CPU archives lets the next page choose automatically; unused archive bytes are not installed. The GUI supplies JSON only, not the agent binary. Keep this setup private and use an unexpired profile.

### Select the CPU and check the agent package

Use the exact **0.16.0** archives from this guide. The block detects the CPU, protects the matching package and checks its bytes. It also protects the private setup. Checksum approval is separate from the release administrator's signature/publisher approval.

**Choose and verify automatically - same commands on RHEL and Ubuntu**

```sh
set -eu
case "$(uname -m)" in
  x86_64|amd64)
    PRTHAK_ARCH=amd64
    PRTHAK_SUM=df54b6e023c10900d811e231986809c96c896bd97c73df0b72f3fd90bacc362b
    ;;
  aarch64|arm64)
    PRTHAK_ARCH=arm64
    PRTHAK_SUM=2a6bcb36a44e5d6514d2084beecc6416e79d4a4e3f274f8115c9924c70fa46fd
    ;;
  *) printf '%s\n' 'Unsupported CPU'; exit 1 ;;
esac
PRTHAK_AGENT="prthak-agent-0.16.0-linux-$PRTHAK_ARCH"
sudo install -d -o root -g root -m 0700 /var/tmp/prthak-media
sudo install -o root -g root -m 0600 \
  "$HOME/prthak-media/$PRTHAK_AGENT.tar.gz" \
  "/var/tmp/prthak-media/$PRTHAK_AGENT.tar.gz"
printf '%s  %s\n' "$PRTHAK_SUM" \
  "/var/tmp/prthak-media/$PRTHAK_AGENT.tar.gz" \
  | sudo sha256sum -c -
sudo install -o root -g root -m 0600 \
  "$HOME/prthak-media/prthak-agent-setup.json" \
  /root/prthak-agent-setup.json
```

Continue only after the package check prints **OK**. Do not hand-edit the JSON or copy another endpoint's initialized keys/state. These commands are for a fresh agent installation; pending enforcement/recovery or an existing changed configuration needs its reviewed workflow.

### Extract and run the matching agent installer

The block chooses the CPU and Linux family automatically. The setup file must already contain the approved **Install missing OS dependencies** choice. Genuine systemd, sudo access and working approved package repositories are required.

**RHEL 8/9 or Ubuntu 26.04 - one matching installer per host**

```sh
set -eu
case "$(uname -m)" in
  x86_64|amd64) PRTHAK_ARCH=amd64 ;;
  aarch64|arm64) PRTHAK_ARCH=arm64 ;;
  *) printf '%s\n' 'Unsupported CPU'; exit 1 ;;
esac
PRTHAK_AGENT="prthak-agent-0.16.0-linux-$PRTHAK_ARCH"
sudo install -d -o root -g root -m 0755 /opt/prthak/agent-releases
sudo tar --no-same-owner --no-same-permissions \
  -xzf "/var/tmp/prthak-media/$PRTHAK_AGENT.tar.gz" \
  -C /opt/prthak/agent-releases
cd "/opt/prthak/agent-releases/$PRTHAK_AGENT"
. /etc/os-release
case "$ID" in
  rhel)
    sudo ./scripts/install-agent-rhel.sh \
      --setup-file /root/prthak-agent-setup.json ;;
  ubuntu)
    sudo ./scripts/install-agent-ubuntu.sh \
      --setup-file /root/prthak-agent-setup.json ;;
  *) printf '%s\n' 'Unsupported endpoint OS'; exit 1 ;;
esac
```

Wait for the result. The signed preparation helper handles missing packages without activating firewalld or disabling UFW. The installer enables **seg-agent** only. Initial access-policy enforcement stays **off**. No Python, Go or Git installation is needed for the agent binary.

### Confirm the agent is connected

**On the endpoint - service and recent status**

```sh
set +e
sudo systemctl status seg-agent.service --no-pager
sudo /usr/local/bin/seg-agent \
  --config /etc/seg-agent/config.json --status
sudo journalctl -u seg-agent.service -n 40 --no-pager
```

These read-only checks continue so you can see every result, even if one reports a problem. A nonzero status is not a pass; inspect the message and the dashboard receipt.

In the GUI, open **Servers** and search for this hostname/IP. Confirm a recent heartbeat, correct Linux version and discovered services. A completed file installation does not prove the first authenticated report arrived.

If missing, check the exact control/discovery URLs, approved **8788/8789** access, HTTPS CA trust, server clock and fleet-profile expiry. Ask your server team to review any preparation error; do not disable UFW, SELinux or certificate checks.

Reuse the same valid fleet setup for the other servers. Each creates its own identity. Assign the one DC/location and business tags in the dashboard. Start with monitoring; live firewall enforcement and default deny require separate guarded configuration.

These command sheets describe the current installers. Native RHEL/Ubuntu package hooks, firewalld/rollback and the real 20-server/DC deployment remain to be tested in your environment.

## Package sources and detailed procedures

Docker preparation follows the official [RHEL procedure](https://docs.docker.com/engine/install/rhel/) and [Ubuntu procedure](https://docs.docker.com/engine/install/ubuntu/). Package versions come from the configured approved repositories; the commands do not pin an untested host package release.

Read the [controller picture guide](guide/simple/controller-installation.pdf), [agent picture guide](guide/simple/agent-installation.pdf), [release trust procedure](controller-installation.md#obtain-and-verify-a-release) and [safe endpoint preparation](endpoint-discovery-and-preparation.md). Application settings, certificates, users and polling stay in the GUI.

<sub>Created by Pratik Srivastava</sub>
