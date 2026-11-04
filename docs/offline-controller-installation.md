# Install the controller on offline RHEL 9

Use a dedicated RHEL 9 x86_64 systemd VM with its stock system Python and DNF. Download the signed offline controller archive and its detached signature from the Prṛthak GitHub Release on a connected workstation. Verify the archive with your independently trusted Prṛthak release key before transferring it to the VM. The [release verification procedure](controller-installation.md#obtain-and-verify-a-release) applies to the offline archive as well.

Copy `prthak-controller-0.18.1-offline-rhel9-x86_64.tar.gz` to your home directory on the VM. If you are in a root shell, run the following commands as written. From an authorized non-root shell, use `sudo` for `install`, `tar`, and `install-controller.sh`.

```sh
install -d -m 0755 /opt/prthak/releases/offline
tar --no-same-owner --no-same-permissions \
  -xzf "$HOME/prthak-controller-0.18.1-offline-rhel9-x86_64.tar.gz" \
  -C /opt/prthak/releases/offline
cd /opt/prthak/releases/offline/prthak-controller-0.18.1
./scripts/install-controller.sh
```

Open the HTTPS setup URL printed by the installer and finish configuration in the GUI. For endpoint enrollment and dashboard access, keep the required internal network paths between the controller, operators, and agents available. Features such as external SSO and notification services still need connectivity to the services you configure.

The archive contains the controller source release, vendor-signed Docker and host dependency RPMs from Docker and public Red Hat UBI 9 repositories, and prebuilt Linux AMD64 images for the controller, PostgreSQL/Patroni, etcd, and HAProxy. The installer detects the offline release and uses its local DNF repository with signature checks. It verifies the image archive before import and pins the appliance services to the loaded image IDs. A partial offline extraction stops at preflight. Use the same installer with `--offline` to explicitly require offline mode or to install the original v0.18.0-offline.1 bundle.

The current offline bundle includes both signed Linux agent archives and detached signatures. In **Agent setup**, choose the archive for the endpoint's architecture and download its private setup JSON separately. Transfer the verified archive and setup JSON to the endpoint, then follow the [agent installation guide](linux-agent-installation.md). Endpoint prerequisites still need approved RHEL or Ubuntu repositories or prior offline preparation.

Build and review new offline media for upgrades so the package and image security updates stay current. Source repositories for the RPMs are [Docker for RHEL](https://download.docker.com/linux/rhel/) and [Red Hat UBI](https://access.redhat.com/articles/4238681). See [controller VM requirements](controller-vm-requirements.md) for runtime sizing.

<sub>Created by Pratik Srivastava</sub>
