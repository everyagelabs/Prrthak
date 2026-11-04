# Install the controller on offline RHEL 9

Use a dedicated RHEL 9 x86_64 systemd VM with its stock system Python and DNF. Download the signed offline controller archive and its detached signature from the Prṛthak GitHub Release on a connected workstation. Verify the archive with your independently trusted Prṛthak release key before transferring it to the VM. The [release verification procedure](controller-installation.md#obtain-and-verify-a-release) applies to the offline archive as well.

Copy `prthak-controller-0.18.7-offline-rhel9-x86_64.tar.gz` to your home directory on the VM. If you are in a root shell, run the following commands as written. From an authorized non-root shell, use `sudo` for `install`, `tar`, and `install-controller.sh`.

```sh
install -d -m 0755 /opt/prthak/releases/offline
tar --no-same-owner --no-same-permissions \
  -xzf "$HOME/prthak-controller-0.18.7-offline-rhel9-x86_64.tar.gz" \
  -C /opt/prthak/releases/offline
cd /opt/prthak/releases/offline/prthak-controller-0.18.7
./scripts/install-controller.sh
```

Open the HTTPS setup URL printed by the installer and finish configuration in the GUI. For endpoint enrollment and dashboard access, keep the required internal network paths between the controller, operators, and agents available. Features such as external SSO and notification services still need connectivity to the services you configure.

The archive contains the controller source release, vendor-signed Docker and host dependency RPMs from Docker and public Red Hat UBI 9 repositories, and prebuilt Linux AMD64 images for the controller, PostgreSQL/Patroni, etcd, and HAProxy. The installer detects the offline release and uses its local DNF repository with signature checks. It verifies the image archive before import and pins the appliance services to the loaded image IDs. A partial offline extraction stops at preflight. Use the same installer with `--offline` to explicitly require offline mode or to install the original v0.18.0-offline.1 bundle.

The current offline bundle includes both signed Linux agent archives and detached signatures. In **Agent setup**, choose the archive for the endpoint's architecture and download its private setup JSON separately. Transfer the verified archive and setup JSON to the endpoint, then follow the [agent installation guide](linux-agent-installation.md). Endpoint prerequisites still need approved RHEL or Ubuntu repositories or prior offline preparation.

## Update an installed standalone controller

On an appliance with update support, sign in as a Super Admin and open **Platform settings → Updates**. Upload the signed RHEL 9 x86_64 offline controller archive and its matching detached `.signature.json` file. Review the verified release and confirm the restart from the same screen. The browser can briefly lose its connection during the restart. Reopen **Updates** to see the final outcome.

Use the **v0.18.10 GUI update** asset for an existing standalone appliance, including one running v0.18.4. The smaller archive includes the signed appliance images and a minimal repository for compatibility with earlier updaters. The GUI uses the installed Docker, Compose, and RHEL packages. Fresh installation uses the full offline installer described above. [Download the GUI update](https://github.com/everyagelabs/Prrthak/releases/tag/v0.18.10-pilot.1)

The update replaces the bundled controller runtime and images and refreshes the agent downloads. Its review checks the existing host prerequisites. Changes to installed host RPMs and updates to HA clusters require separate host or cluster maintenance.

An older controller without **Updates** needs one installer upgrade from a verified release that includes the updater. Use the installed data path and follow the existing-appliance reinstall procedure. Later supported updates can use the GUI. [Controller installation](controller-installation.md)

Build and review new offline media for upgrades so the package and image security updates stay current. Source repositories for the RPMs are [Docker for RHEL](https://download.docker.com/linux/rhel/) and [Red Hat UBI](https://access.redhat.com/articles/4238681). See [controller VM requirements](controller-vm-requirements.md) for runtime sizing.

<sub>Created by Pratik Srivastava</sub>
