# Prṛthak offline controller upgrade SOP

This procedure covers standalone Prṛthak controllers on RHEL 9 x86_64. The target release is **0.18.18**. Keep the active data path, the existing dashboard address and the current controller identity. Schedule a maintenance window for the controller and TLS router restart.

## 1. Choose the package

| Starting point | Package and path |
| --- | --- |
| A standalone controller with **Platform settings → Updates** | If the release includes `prthak-controller-0.18.18-offline-rhel9-x86_64.tar.gz` and its detached signature, use those two files for the browser update. |
| A standalone controller using the full host installer | Use `prthak-controller-0.18.18-offline-rhel9-x86_64-full.tar.gz` and its detached signature. The CLI archive includes the offline host RPM repository and appliance images. |
| A standalone 0.18.0 controller without **Updates** | Follow the published 0.18.0 to 0.18.14 full-installer migration first. Verify the intermediate version, take a new snapshot, and then continue to 0.18.18. |
| A PostgreSQL or HA controller | Follow the cluster and database runbook. |

The browser updater checks the exact signed filename. Use the full archive from the RHEL shell.

[0.18.18 release](https://github.com/everyagelabs/Prrthak/releases/tag/v0.18.18-pilot.1) · [0.18.0 to 0.18.14 migration guide](https://github.com/everyagelabs/Prrthak/releases/download/v0.18.14-pilot.2/prthak-rhel9-migration-0.18.0-to-0.18.14.pdf) · [HA runbook](ha.md)

## 2. Verify the download and prepare recovery

1. Download the archive and its matching `.signature.json` on a connected workstation. Use the approved verifier and independently trusted Prṛthak release public key.
2. Record the installed controller version, HTTPS address and appliance data path. Confirm that the dashboard is reachable and the node uses standalone SQLite.
3. Download a GUI backup if available. Before cutover, take a recoverable VM snapshot that includes the RHEL system disk, the appliance data mount and Docker storage. Record its ID.

Run the following on the connected workstation from the download folder. For the full 0.18.14 bridge, set `version=0.18.14`. Use the exact filename from the release for a browser update.

```sh
(
  set -eu
  version=0.18.18
  package="prthak-controller-${version}-offline-rhel9-x86_64-full.tar.gz"
  python3 /approved/tools/verify-release.py \
    --public-trust-file /approved/trust/prthak-release-public-trust.json \
    --signature "$package.signature.json" "$package"
  shasum -a 256 "$package" > "$package.sha256"
)
```

The `/approved/` paths are your organisation’s copies. Proceed when the verifier confirms the archive bytes and Ed25519 signature. For the CLI path, transfer the verified archive and its generated `.sha256` file to `/root` on the offline host through your approved transfer method. Keep the detached signature with your release records.

## 3. Full archive upgrade from the RHEL shell

Use an authorized root shell. Confirm RHEL 9 and `x86_64`. Stage the archive and validate it while the existing controller is available. If you are preparing the documented 0.18.0 bridge, use `version=0.18.14` in both blocks.

```sh
(
  set -eu
  version=0.18.18
  package="prthak-controller-${version}-offline-rhel9-x86_64-full.tar.gz"
  stage="/opt/prthak/releases/migrate-$version"
  cd /root
  sha256sum -c "$package.sha256"
  data_root=$(cat /etc/prthak/data-root)
  test -n "$data_root"
  test -f "$data_root/config/installed.json"
  if [ -e "$data_root/config/manifest.json" ] || [ -e "$data_root/config/desired.json" ]; then
    echo "Cluster configuration found. Use the HA runbook."
    exit 1
  fi
  install -d -m 0755 /opt/prthak/releases
  mkdir -m 0700 "$stage"
  tar --no-same-owner --no-same-permissions -xzf "$package" -C "$stage"
  cd "$stage/prthak-controller-$version"
  ./scripts/install-controller.sh --gui-setup --data-root "$data_root" --validate-only
)
```

Expect `OK` for the archive and `"status": "validated"` for the existing data path. If a previously verified extraction already occupies the staging path, reuse it only after confirming its exact release. Validation checks installer inputs. Use the post-restart checks below to verify the appliance.

Run the next block after the snapshot completes. It stops the appliance manager and only the controller and router in this appliance’s Compose project, then runs the offline installer.

```sh
(
  set -eu
  version=0.18.18
  data_root=$(cat /etc/prthak/data-root)
  test -f "$data_root/runtime/compose.json"
  test ! -e "$data_root/config/manifest.json"
  test ! -e "$data_root/config/desired.json"
  cd "/opt/prthak/releases/migrate-$version/prthak-controller-$version"
  project=$(python3 - "$data_root/config/installed.json" <<'PYTHON'
import json, sys
with open(sys.argv[1]) as config:
    print("prthak-" + json.load(config)["appliance_id"][:12])
PYTHON
  )
  systemctl stop prthak-appliance-manager.service
  docker --host unix:///var/run/docker.sock compose -p "$project" \
    --project-directory "$data_root/runtime" \
    -f "$data_root/runtime/compose.json" stop --timeout 90 router controller
  ./scripts/install-controller.sh --offline --gui-setup --data-root "$data_root"
)
```

The installer reports the existing data path and a **Setup URL** after it starts the appliance. Sign in with the existing account.

## 4. Browser upgrade when a GUI asset is available

1. Sign in as a Super Admin. Open **Platform settings → Updates**.
2. Choose the signed GUI archive and its matching signature. Click **Upload and check package**. If the transfer is interrupted, reselect the same files and click **Resume upload and check package**.
3. Open **Review controller update**. Verify the package name and target version. Confirm the installation and restart.
4. Reopen **Updates** after the dashboard reconnects. Verify **Update verified** and the new sidebar version. If the status says **Previous controller restored**, verify the old version and readiness before retrying.

## 5. Verify service and recover if needed

Run these checks from the RHEL host. If the configured hostname is reachable only from your workstation, check `/readyz` there using the independently trusted appliance HTTPS CA.

```sh
(
  set -eu
  systemctl is-active prthak-appliance-manager.service
  data_root=$(cat /etc/prthak/data-root)
  origin=$(python3 - "$data_root/config/installed.json" <<'PYTHON'
import json, sys
with open(sys.argv[1]) as config:
    print(json.load(config)["controller_origin"])
PYTHON
  )
  curl --fail --silent --show-error --max-time 15 \
    --cacert "$data_root/config/router/controller-ca.pem" "${origin%/}/readyz"
  printf '\n'
)
```

Expect `active` and a successful readiness response. Confirm the expected version, server inventory, policies and settings in the dashboard. If the CLI installation fails or the GUI reports an unverified rollback, retain the error and manager logs. Restore the pre-upgrade snapshot with all included disks, then verify the previous version and its data.

```sh
journalctl -u prthak-appliance-manager.service --since '-15 minutes' -n 80 --no-pager
```

## 6. Use the separate discovery workflows

| Open | Use it to |
| --- | --- |
| **Traffic → Discover traffic** | Collect traffic metadata for selected endpoints and listening services. Turn on **Count traffic hits** when you need counts and observed rates. Leave it off for at most one communication sample per source and destination service per minute. Use the Traffic session history and CSV for those observations. |
| **Policies → Discover policy** | Review observed sources for access or explicitly enable automatic allowances, according to the selected policy workflow. Review the endpoint and port scope and monitor actual application in Policies. |

Traffic discovery leaves access rules unchanged. Each endpoint has one active discovery session slot. End the current session or wait for expiry before starting a different discovery mode on that endpoint.

For an editable discovered rule, use **Policies → Discovered policies → Details → Review action**. **Allow** permits traffic that matches the reviewed rule. **Reject** denies it and sends a rejection response. **Drop** silently discards matching traffic. Review the existing match, endpoint list and runtime or permanent scope before creating the plan. Permanent zone targets take effect on a later reload or restart. Restrictive changes require the same Admin to complete both confirmation steps. Check the endpoint result after applying.

Complex named services such as `dhcpv6-client` show a read-only reason. Their native definitions can constrain addresses as well as ports. [Firewalld rich rules](https://firewalld.org/documentation/man-pages/firewalld.richlanguage.html)

<sub>Created by Pratik Srivastava</sub>
