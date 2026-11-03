# RHEL and Ubuntu endpoint installers

New to Linux? Use the [simple agent picture guide](guide/simple/agent-installation.pdf), or its [browser edition with copyable commands](guide/simple/agent-installation.html). The [end-to-end command sheets](installation-commands.md#agent) include safe dependencies, private file transfer, CPU selection, checksum verification, extraction, installation and status checks.

**Preferred 0.16 GUI flow:** download one private **Fleet setup** through **Install
agent**, copy the same file to the servers as root-owned 0600 at `/root/prthak-agent-setup.json`, then run
`sudo ./scripts/install-agent-rhel.sh --setup-file /root/prthak-agent-setup.json`
or the Ubuntu wrapper on each host. No manual JSON/token/CA editing or per-host
package generation is needed. Fleet keys default to 24 hours, are revocable in
the GUI and have no fixed enrollment-count limit. Each host creates its own
private key/certificate. Optional individual kits remain single-use/15-minute.
All bootstrap kits are monitor-only. See [fleet enrollment](fleet-enrollment.md)
and [GUI pilot installation](pilot-gui-installation.md).
The explicit-config examples below remain compatible advanced workflows. Current payloads are stamped 0.16.0; existing 0.14 endpoints remain protocol-compatible with the controller’s local/SAML human-login addition and need no reinstall solely for it.

Prṛthak supplies two entrypoints over the same credential/upgrade-safe agent installer:

| Target | Entrypoint | Runtime packages |
| --- | --- | --- |
| RHEL 8 or 9, amd64/arm64 | `scripts/install-agent-rhel.sh` | `systemd`, `iproute`, `firewalld`, `ca-certificates`, `util-linux` (`flock`) |
| Ubuntu 26.04, amd64/arm64 | `scripts/install-agent-ubuntu.sh` | `systemd`, `iproute2`, `firewalld`, `ca-certificates`, `util-linux` (`flock`) |

These entrypoints detect the OS/version and CPU architecture, check required commands, select the bundled binary and call `install-agent.sh`. Endpoint installation needs no Git, Python installation, Go compiler or Go runtime. The controller and endpoint are installed separately.

The scripts have staged/mocked acceptance checks. Native RHEL 8/9 and Ubuntu host testing is deferred to the deployment phase; passing the platform check does not certify kernel, systemd, SELinux/polkit, firewalld or rollback behavior.

## Prepare the endpoint and release

1. In the GUI, optionally tick **Install missing OS dependencies** and/or **Assess/export UFW for migration**; both start unchecked. The same verified installer command validates the private schema-3 kit, uses bounded native apt/dnf operations with journaled service-start suppression, and preserves UFW and existing firewalld activity. Existing unsafe/uncertain startup overrides block preparation. Without those options, entrypoints only check prerequisites and print missing commands. RHEL requires approved repository/subscription access. UFW migration remains separate. See [preparation safeguards and private receipt](endpoint-discovery-and-preparation.md).
2. Use the matching `linux-amd64` archive for `uname -m` = `x86_64`/`amd64`, or `linux-arm64` for `aarch64`/`arm64`. An extracted bundle has one `seg-agent` binary; source checkouts select `agent/bin/seg-agent-linux-ARCH`. `--binary FILE` is available for an explicitly reviewed build.
3. Verify the exact archive's detached Ed25519 signature **before extraction**, using an independently distributed public trust manifest and approved verifier. Downloading a public key next to an untrusted archive does not establish trust. Verification can run on an administration workstation; the static installed agent has no Python dependency. The current local project release key is not an independently approved organizational release authority. See [release signing and trust](policy-signing.md).

An administration-workstation verification example, using approved Python 3.10+ and the compatible `cryptography` dependency:

```sh
python3 /approved/tools/verify-release.py \
  --public-trust-file /approved/trust/prthak-release-public-trust.json \
  --signature prthak-agent-0.16.0-linux-amd64.tar.gz.signature.json \
  prthak-agent-0.16.0-linux-amd64.tar.gz
sudo install -d -o root -g root -m 0755 /opt/prthak/agent-releases
sudo tar --no-same-owner --no-same-permissions \
  -xzf /protected/releases/prthak-agent-0.16.0-linux-amd64.tar.gz \
  -C /opt/prthak/agent-releases
cd /opt/prthak/agent-releases/prthak-agent-0.16.0-linux-amd64
```

Use the ARM64 filenames on ARM64. Transfer the already verified archive through your protected release path before extraction; execute privileged installers from protected root-owned release files. Obtain the verifier and public pin through the approved independent channel. RHEL 8's default Python 3.6 cannot run this verifier.

## Advanced compatibility: explicit configuration and enrollment

Create a reviewed config from `agent/config.example.json` with these values:

- `controller_url`: stable HTTPS origin of your controller/LB, including the configured port. The current application defaults to 8787; separate discovery/policy listener ports are not implied.
- `interval_seconds: 60` and `discovery_interval_seconds: 900`, or approved values. These can later be centrally assigned through polling profiles.
- Keep the stock `/etc/seg-agent` and `/var/lib/seg-agent` credential/state paths for the systemd service. `ca_cert` is the HTTPS server trust; an independent endpoint issuer uses `endpoint_ca_cert` and its separately preinstalled public certificate.
- Keep `enforce`, `allow_firewall_changes`, `learning_auto_allow` and `unexpected_port_monitor_enabled` false until their specific review/opt-in process. Tags and location are assigned centrally, not in this config.

An administrator provides the trusted controller CA and a private single-use enrollment token. Protect them locally:

```sh
sudo install -o root -g root -m 0600 agent/config.example.json /root/prthak-agent.json
sudoedit /root/prthak-agent.json
# Set your actual controller URL and reviewed settings in that private config.
sudo install -d -m 0700 /etc/seg-agent
sudo install -o root -g root -m 0600 /path/to/enrollment-token \
  /etc/seg-agent/enrollment-token
```

RHEL:

```sh
./scripts/install-agent-rhel.sh --check-only
sudo ./scripts/install-agent-rhel.sh \
  --ca-file /path/to/trusted-controller-ca.pem \
  --token-file /etc/seg-agent/enrollment-token \
  /root/prthak-agent.json
```

Ubuntu:

```sh
./scripts/install-agent-ubuntu.sh --check-only
sudo ./scripts/install-agent-ubuntu.sh \
  --ca-file /path/to/trusted-controller-ca.pem \
  --token-file /etc/seg-agent/enrollment-token \
  /root/prthak-agent.json
```

The platform check is read-only and does not validate enrollment credentials or running service health. The actual install runs the agent's read-only configuration/CA/token and pending-transaction preflight before replacement. Token values never enter command-line arguments. The common installer enables/starts **seg-agent only**; it does not enable firewalld. Keep existing identity/state on upgrades. A pending enforcement/rollback transaction blocks replacement.

The running agent enrolls and reports its actual hostname, addresses and listeners; the server then appears automatically in the dashboard. Full discovery happens at each process startup/restart. Native socket checks run every 5 seconds; verified listener changes normally report in about 5–10 seconds plus delivery. Full OS/firewall discovery remains on its separately configured 15-minute default; failed/unsupported fast scans retain that fallback. Inspect:

```sh
sudo systemctl status seg-agent.service
sudo journalctl -u seg-agent.service -f
sudo /usr/local/bin/seg-agent --config /etc/seg-agent/config.json --status
```

If the controller is temporarily unavailable, the installed service retries enrollment/reporting with bounded backoff. Successful file installation is distinct from a confirmed first report; the installer states whether dashboard readiness is confirmed or pending.

Use `--replace-config` only after reviewing a changed config; the old file is retained as `config.json.previous`. `--no-start` stages an enabled but stopped service and requires a stopped existing agent. `--root /absolute/staging-root --no-start` validates the target's `etc/os-release` and executable dependency files, then stages only under that root. A staging install still executes the selected binary for credential preflight and needs a compatible administration host. It never operates live systemd. No unsupported-version bypass is supplied.

Full enforcement, bank preparation, rollback and protected management prerequisites are in [managed enforcement](managed-enforcement.md), [source-set preparation](ipset-enforcement.md) and the [agent guide](../agent/README.md). Leave endpoint enforcement/automatic learning off controller, database-voter and LB infrastructure for this pilot until native ingress-protection acceptance.

<sub>Created by Pratik Srivastava</sub>
