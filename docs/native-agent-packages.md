# Optional RPM and DEB endpoint delivery

Prṛthak can wrap an independently verified signed endpoint release as an inert RPM or DEB. Files stay under `/opt/prthak-agent/<version>-linux-<arch>/`. Package installation does not enroll an endpoint, write `/etc/seg-agent`, replace `/usr/local/bin/seg-agent`, install an active unit, install dependencies, start services, change UFW or change firewalld. There are no RPM scriptlets/triggers or DEB maintainer scripts.

The reviewed family installer remains the activation path, with its protected credentials, signed runtime validation, configuration-generation lease, upgrade checks and rollback protections. Removing a delivery package leaves the activated endpoint unchanged.

## Build on an administration workstation

Requirements: Python 3.10+ with the release-verification `cryptography` dependency, an approved copy of these source tools, Docker Engine and an approved packaging image. Git is optional for obtaining the tools. Endpoints need neither Git nor Docker to receive these packages.

Use independently approved release public trust. Each input `.tar.gz` is verified against its adjacent `.tar.gz.signature.json` before extraction. A key downloaded beside an untrusted archive is not independent trust. Unsigned or legacy bundles missing signed runtime sidecars are rejected.

Inspect without Docker or output mutation:

```sh
python3 scripts/build-agent-native-packages.py \
  --public-trust-file /approved/prthak-release-public-trust.json \
  --output-dir /approved/build-output/prthak-0.10.0-native \
  --dry-run \
  dist/prthak-agent-0.10.0-linux-amd64.tar.gz \
  dist/prthak-agent-0.10.0-linux-arm64.tar.gz
```

Build both formats and architectures:

```sh
python3 scripts/build-agent-native-packages.py \
  --public-trust-file /approved/prthak-release-public-trust.json \
  --output-dir /approved/build-output/prthak-0.10.0-native \
  --build-builder \
  dist/prthak-agent-0.10.0-linux-amd64.tar.gz \
  dist/prthak-agent-0.10.0-linux-arm64.tar.gz
```

`--build-builder` explicitly builds the tools image described in the packaging script and requires approved registry/OS-package access. Its temporary context contains only a generated Dockerfile. To use a prepared or privately mirrored image, omit that flag and pass `--builder-image YOUR_APPROVED_IMAGE`, preferably with an approved digest. Offline tools-image distribution is not included.

Packaging containers use the invoking UID/GID, read-only root filesystems, no network and dropped capabilities. Only public release inputs and the output mount enter Docker. When `PRTHAK_RELEASE_SIGNING_KEY_FILE` identifies a protected seed outside the source tree, the existing signer adds detached Ed25519 signature/public-trust sidecars to the resulting RPM/DEB on the workstation. The seed never enters Docker. Without it, outputs are explicitly unsigned and require separate signing before production distribution. These are detached Prṛthak signatures, not RPM/APT repository signatures.

| CPU | RPM | DEB |
| --- | --- | --- |
| amd64 / x86_64 | `prthak-agent-payload-0.10.0-1.x86_64.rpm` | `prthak-agent-payload_0.10.0_amd64.deb` |
| arm64 / aarch64 | `prthak-agent-payload-0.10.0-1.aarch64.rpm` | `prthak-agent-payload_0.10.0_arm64.deb` |

RPM uses gzip payload compression and disables automatic dependency discovery for RHEL 8 compatibility. DEB uses gzip, explicit CPU architecture and root ownership. The packager checks ELF architecture without executing the target binary. It rejects unrecognized/missing files, traversal, duplicates, links, special files, directories, PAX metadata, oversized inputs, CPU mismatch and existing output targets.

## Deliver and explicitly activate

Verify the native package using approved verification tooling and independently obtained public trust before giving it to a package manager:

```sh
python3 /approved/tools/verify-release.py \
  --public-trust-file /approved/prthak-release-public-trust.json \
  --signature prthak-agent-payload_0.10.0_amd64.deb.signature.json \
  prthak-agent-payload_0.10.0_amd64.deb
```

Use the established OS packaging process for the matching verified delivery package, for example `sudo dpkg -i PACKAGE.deb` or `sudo rpm -Uvh PACKAGE.rpm` under the approved signature policy. Detached verification above remains required. A repository-native signing workflow can be added by the packaging team. Neither install command activates Prṛthak.

Download one reusable **Fleet setup** from **Install agent** and copy the same private file to your servers as root-owned mode `0600` at `/root/prthak-agent-setup.json`. Each host creates its own key and certificate automatically. Run the matching family command on each host:

```sh
# RHEL 8/9 amd64
sudo /opt/prthak-agent/0.10.0-linux-amd64/scripts/install-agent-rhel.sh \
  --setup-file /root/prthak-agent-setup.json

# Ubuntu 26.04 amd64
sudo /opt/prthak-agent/0.10.0-linux-amd64/scripts/install-agent-ubuntu.sh \
  --setup-file /root/prthak-agent-setup.json
```

For arm64 use the matching `0.10.0-linux-arm64` directory. OS dependencies, running firewalld, UFW migration and preservation of management access remain explicit prerequisites. Initial GUI kits remain monitor-only; later signed configuration/policy reviews explicitly authorize firewall opt-ins.

See [GUI pilot installation](pilot-gui-installation.md), [family prerequisites](linux-agent-installation.md) and [managed enforcement](managed-enforcement.md). Package construction and payload inspection do not establish native firewalld behavior. Native RHEL 8/9, Ubuntu 26.04 and DC/DR acceptance remain deferred until disposable test hosts are provided.
