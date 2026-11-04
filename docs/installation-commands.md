# End to end installation commands

Use these command sheets with the picture guides. The installation command is the same on both supported Linux families. Product configuration stays in the GUI; do not edit `.env` or agent JSON.

**These are commands for fresh dedicated Linux machines.** Installer logic and mocked package/service outcomes are tested; transfer commands are syntax-checked. Native RHEL/Ubuntu execution and DC deployment remain pending. Existing installations need the documented upgrade/recovery procedure.

You need sudo/root, approved repositories, working DNS/time, the supplied signed pilot packages and independent release trust. Your infrastructure team must provide the approved network paths and persistent storage. Docker-published ports need approved upstream or Docker-aware filtering; ordinary UFW rules alone do not establish isolation.

The current private Git repository does not by itself supply built agent binaries. Use the signed pilot ZIP provided with the release. Its `payloads` folder contains the archives. The GUI downloads the private agent setup file separately.

## Controller

### Optional: copy the approved release

Your release administrator supplies and verifies **prthak-controller-0.18.0.tar.gz** using independently trusted release identity. A source ZIP is not the installation archive. An approved graphical file-transfer tool can copy it to your Linux home folder.

**On your laptop - replace the path, user and address**

```sh
scp /PATH/TO/prthak-controller-0.18.0.tar.gz \
  YOUR_USER@CONTROLLER_IP:
```

**Open the controller terminal**

```sh
ssh YOUR_USER@CONTROLLER_IP
```

**Extract the verified archive into a protected release folder**

```sh
sudo install -d -o root -g root -m 0755 /opt/prthak/releases
sudo tar --no-same-owner --no-same-permissions \
  -xzf "$HOME/prthak-controller-0.18.0.tar.gz" \
  -C /opt/prthak/releases
cd /opt/prthak/releases/prthak-controller-0.18.0
```

Now run the **one installer command in Step 3**. It prepares missing dependencies automatically. Root/sudo, systemd and working approved repositories are required. No Git or manual .env file is needed.

### Plan capacity and confirm installation

**20-server pilot:** start with **4 vCPU, 8 GiB RAM**, 80 GiB OS/Docker disk and a separate 100 GiB data SSD. These are VM allocations, not constant CPU or memory consumption.

**5,000 servers:** begin with **8 vCPU / 16 GiB** per management-only controller. A combined database voter starts at **8 vCPU / 32 GiB**, 80 GiB OS/Docker and 300 GiB data SSD. Managed database HA needs **three eligible voters** and real fencing.

Actual utilization depends on policy size, discovery, traffic learning, retention and site latency. The previous **0.16 capacity benchmark** is historical evidence; these new installers do not create a fresh 5,000-server performance measurement.

**Optional read-only checks - ask your server team if needed**

```sh
sudo systemctl status prthak-appliance-manager.service --no-pager
sudo docker ps
```

**GUI completion:** trusted HTTPS opens, the temporary password was changed, and controller readiness is healthy. Then install the first agent and confirm its heartbeat before the rest of the pilot.

Native OS, live firewalld/rollback, DC/DR and actual pilot acceptance remain pending. See the detailed VM and capacity runbooks for connection budgeting and failover sizing.

## Agent

### Optional: copy the package and setup

Your release administrator verifies the signed **0.18.0 agent archive** for the CPU. Use **amd64** for x86_64 or **arm64** for aarch64. The GUI supplies the private **prthak-agent-setup.json**. Keep it private.

**On your laptop - example for AMD64; use arm64 if required**

```sh
scp /PATH/TO/prthak-agent-0.18.0-linux-amd64.tar.gz \
  /PATH/TO/prthak-agent-setup.json YOUR_USER@SERVER_IP:
```

**Open the endpoint terminal**

```sh
ssh YOUR_USER@SERVER_IP
```

**Protect and extract - AMD64 example; substitute arm64 in both paths**

```sh
sudo install -o root -g root -m 0600 \
  "$HOME/prthak-agent-setup.json" /root/prthak-agent-setup.json
sudo install -d -o root -g root -m 0755 /opt/prthak/agent-releases
sudo tar --no-same-owner --no-same-permissions \
  -xzf "$HOME/prthak-agent-0.18.0-linux-amd64.tar.gz" \
  -C /opt/prthak/agent-releases
cd /opt/prthak/agent-releases/prthak-agent-0.18.0-linux-amd64
```

Then run the **one universal command in Step 6**. Your minimal OS must already supply tar/file-transfer tools to unpack media; an approved deployment tool can perform that step. Runtime dependencies are installed by Prṛthak. Do not edit the JSON.

### Agent footprint and completion checks

**Package:** one static Go binary per CPU, its systemd unit, signed manifests and install scripts. There is no separately installed Go, Python or Git runtime. RPM/DEB packages are optional inert payload delivery; the GUI kit and installer activate the agent.

**Planning allowance:** start with **128 MiB** for ordinary monitoring/helpers or **256 MiB** during learning. These are allowances to evaluate, not enforced limits. Current release CPU/memory must be measured in the pilot.

**Historical passive baseline:** an older Linux ARM64 fixture measured roughly **10-13 MiB agent RSS**, about **57 MiB** sampled with helper processes, and **0.22% of one core** after startup including helpers. This excludes firewalld, kernel sets and capture load; it is not a current-release guarantee.

**Optional read-only checks - installation is complete only after review**

```sh
sudo systemctl status seg-agent.service --no-pager
sudo /usr/local/bin/seg-agent \
  --config /etc/seg-agent/config.json --status
```

In **Servers**, confirm this hostname/IP, fresh heartbeat, OS version and discovered services. A completed file copy does not prove a successful authenticated report. Reuse the same valid fleet setup for the other endpoints; each creates a unique identity.

## Package sources and detailed procedures

The automatic Docker preparation follows the official [RHEL procedure](https://docs.docker.com/engine/install/rhel/) and [Ubuntu procedure](https://docs.docker.com/engine/install/ubuntu/). Package versions come from the configured approved repositories; the commands do not pin an untested host package release.

Read the [controller picture guide](guide/simple/controller-installation.pdf), [agent picture guide](guide/simple/agent-installation.pdf), [release trust procedure](controller-installation.md#obtain-and-verify-a-release) and [safe endpoint preparation](endpoint-discovery-and-preparation.md). Application settings, certificates, users and polling stay in the GUI.

<sub>Created by Pratik Srivastava</sub>
