#!/bin/sh
# Distro/architecture preflight for an independently verified, extracted bundle.
# Optional package preparation is explicit GUI data; UFW is always preserved.
set -eu
umask 077

FAMILY=${1:-}
case "$FAMILY" in auto|rhel|ubuntu) shift ;; *) echo 'Choose install-agent-auto.sh, install-agent-rhel.sh or install-agent-ubuntu.sh.' >&2; exit 2 ;; esac
PROGRAM=install-agent-$FAMILY.sh
AUTO_DEPENDENCIES=0
[ "$FAMILY" != auto ] || AUTO_DEPENDENCIES=1
usage() {
  cat <<USAGE
Usage: $PROGRAM --setup-file /root/prthak-agent-setup.json [--binary FILE]
       [--replace-config] [--no-start] [--wait-seconds 10] [--root STAGING_DIR]
   or: $PROGRAM [--check-only] [--binary FILE] [--ca-file CA.pem]
       [--endpoint-ca-file ENDPOINT_CA.pem]
       [--token-file PRIVATE_FILE] [--replace-config] [--no-start]
       [--wait-seconds 10] [--root STAGING_DIR] /path/to/reviewed-agent.json
   or: $PROGRAM --configuration-file /root/prthak-endpoint-configuration.json

--check-only checks the OS, architecture, required commands and bundled binary;
             no configuration argument is required and nothing is installed.
Live installation requires root and Linux. --root staging requires --no-start
and reads the target's etc/os-release and installed command files.
Read-only checks/staging never install packages or change a firewall service.
The shared installer enables/starts only seg-agent after credential validation.
--setup-file consumes the private data-only GUI download; no config/token/CA editing.
Explicit GUI preparation can install missing dependencies with startup suppression
and export a private UFW assessment. It never disables UFW or activates firewalld.
The auto entrypoint detects the OS and installs missing dependencies automatically
after validating the private setup and signed release. It requires --setup-file
for a new install; --check-only and staging/--no-start never prepare packages.
USAGE
}
CHECK_ONLY=0
BINARY=
CA_SOURCE=
ENDPOINT_CA_SOURCE=
TOKEN_SOURCE=
SETUP_FILE=
CONFIGURATION_FILE=
SETUP_WORK=
REPLACE_CONFIG=0
NO_START=0
WAIT_SECONDS=10
TARGET_ROOT=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --help|-h) usage; exit 0 ;;
    --check-only) CHECK_ONLY=1; shift ;;
    --binary) [ "$#" -ge 2 ] || { usage >&2; exit 2; }; BINARY=$2; shift 2 ;;
    --ca-file) [ "$#" -ge 2 ] || { usage >&2; exit 2; }; CA_SOURCE=$2; shift 2 ;;
    --endpoint-ca-file) [ "$#" -ge 2 ] || { usage >&2; exit 2; }; ENDPOINT_CA_SOURCE=$2; shift 2 ;;
    --token-file) [ "$#" -ge 2 ] || { usage >&2; exit 2; }; TOKEN_SOURCE=$2; shift 2 ;;
    --setup-file) [ "$#" -ge 2 ] || { usage >&2; exit 2; }; SETUP_FILE=$2; shift 2 ;;
    --configuration-file) [ "$#" -ge 2 ] || { usage >&2; exit 2; }; CONFIGURATION_FILE=$2; shift 2 ;;
    --replace-config) REPLACE_CONFIG=1; shift ;;
    --no-start) NO_START=1; shift ;;
    --wait-seconds) [ "$#" -ge 2 ] || { usage >&2; exit 2; }; WAIT_SECONDS=$2; shift 2 ;;
    --root) [ "$#" -ge 2 ] || { usage >&2; exit 2; }; TARGET_ROOT=$2; shift 2 ;;
    --) shift; break ;;
    -*) usage >&2; exit 2 ;;
    *) break ;;
  esac
done
if [ -n "$CONFIGURATION_FILE" ]; then
  if [ "$#" -ne 0 ] || [ "$CHECK_ONLY" -ne 0 ] || [ "$NO_START" -ne 0 ] || [ "$REPLACE_CONFIG" -ne 0 ] || [ -n "$SETUP_FILE$CA_SOURCE$ENDPOINT_CA_SOURCE$TOKEN_SOURCE$TARGET_ROOT" ] || [ -n "${SEG_ENROLLMENT_TOKEN:-}${SEG_ENROLLMENT_TOKEN_FILE:-}" ]; then
    echo '--configuration-file requires one live independently approved kit and cannot mix bootstrap, staging or manual inputs.' >&2; exit 2
  fi
elif [ -n "$SETUP_FILE" ]; then
  if [ "$#" -ne 0 ] || [ "$CHECK_ONLY" -ne 0 ] || [ -n "$CA_SOURCE$ENDPOINT_CA_SOURCE$TOKEN_SOURCE" ] || [ -n "${SEG_ENROLLMENT_TOKEN:-}${SEG_ENROLLMENT_TOKEN_FILE:-}" ]; then
    echo '--setup-file cannot be combined with manual config/CA/token inputs or --check-only.' >&2; exit 2
  fi
elif [ "$CHECK_ONLY" -eq 1 ]; then
  [ "$#" -le 1 ] || { usage >&2; exit 2; }
else
  [ "$#" -eq 1 ] || { usage >&2; exit 2; }
fi
CONFIG_SOURCE=${1:-}
if [ "$AUTO_DEPENDENCIES" -eq 1 ] && [ "$CHECK_ONLY" -eq 0 ] && [ -z "$SETUP_FILE$CONFIGURATION_FILE" ]; then
  echo 'The automatic installer requires the GUI --setup-file; manual configuration inputs use a family entrypoint.' >&2; exit 2
fi
case "$WAIT_SECONDS" in ''|*[!0-9]*) usage >&2; exit 2 ;; esac
[ "$WAIT_SECONDS" -le 60 ] || { usage >&2; exit 2; }

if [ -n "$TARGET_ROOT" ]; then
  case "$TARGET_ROOT" in /*) ;; *) echo 'Staging --root must be absolute.' >&2; exit 1 ;; esac
  [ -d "$TARGET_ROOT" ] || { echo 'Staging root must already contain the target OS filesystem.' >&2; exit 1; }
  TARGET_ROOT=$(CDPATH= cd -- "$TARGET_ROOT" && pwd -P)
  [ "$TARGET_ROOT" != / ] || { echo 'Use no --root for a live installation.' >&2; exit 1; }
  if [ "$CHECK_ONLY" -eq 0 ] && [ "$NO_START" -ne 1 ]; then
    echo 'Staging --root requires --no-start; no live service is controlled.' >&2; exit 1
  fi
else
  [ "$(uname -s)" = Linux ] || { echo 'Live agent installation requires Linux.' >&2; exit 1; }
  if [ "$CHECK_ONLY" -eq 0 ]; then
    [ "$(id -u)" -eq 0 ] || { echo 'Run the installer as root; --check-only is read-only.' >&2; exit 1; }
  fi
fi

case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) echo 'Supported agent architectures are Linux amd64 and arm64.' >&2; exit 1 ;;
esac
RELEASE_FILE=$TARGET_ROOT/etc/os-release
[ -r "$RELEASE_FILE" ] || { echo 'Cannot read target etc/os-release.' >&2; exit 1; }
# Never source os-release: staging content must not execute shell substitutions.
release_field() {
  awk -v wanted="$1" '
    $0 ~ "^" wanted "=" {
      count++; value=substr($0,index($0,"=")+1); quote=sprintf("%c",39);
      if ((substr(value,1,1)=="\"" && substr(value,length(value),1)=="\"") ||
          (substr(value,1,1)==quote && substr(value,length(value),1)==quote))
        value=substr(value,2,length(value)-2);
    }
    END { if(count!=1) exit 1; print value }
  ' "$RELEASE_FILE"
}
DISTRO=$(release_field ID) || { echo 'Target os-release must contain one literal ID.' >&2; exit 1; }
RELEASE=$(release_field VERSION_ID) || { echo 'Target os-release must contain one literal VERSION_ID.' >&2; exit 1; }
case "$RELEASE" in
  ''|*[!0-9.]*|.*|*.|*..*) echo 'Target VERSION_ID must be a literal numeric release.' >&2; exit 1 ;;
esac
# Explicit agent profiles only. ID_LIKE never grants compatibility to an unknown OS.
case "$DISTRO" in
  rhel|rocky|almalinux|ol)
    case "$RELEASE" in 8|8.*|9|9.*) DETECTED_FAMILY=rhel ;; *) DETECTED_FAMILY=unsupported ;; esac ;;
  ubuntu)
    case "$RELEASE" in 22.04|24.04|26.04) DETECTED_FAMILY=ubuntu ;; *) DETECTED_FAMILY=unsupported ;; esac ;;
  *) DETECTED_FAMILY=unsupported ;;
esac
if [ "$FAMILY" = auto ]; then FAMILY=$DETECTED_FAMILY; fi
if [ "$FAMILY" = unsupported ] || [ "$FAMILY" != "$DETECTED_FAMILY" ]; then
  printf '%s\n' "$PROGRAM supports agent profiles RHEL/Rocky/Alma/Oracle Linux 8/9 and Ubuntu 22.04/24.04/26.04; this target is unsupported by the selected entrypoint." >&2
  exit 1
fi

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROJECT_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
if [ -z "$BINARY" ]; then
  if [ -f "$PROJECT_ROOT/seg-agent" ]; then
    BINARY=$PROJECT_ROOT/seg-agent
  else
    BINARY=$PROJECT_ROOT/agent/bin/seg-agent-linux-$ARCH
  fi
fi
[ -f "$BINARY" ] && [ -x "$BINARY" ] || { printf '%s\n' "Missing executable Linux $ARCH agent. Extract the matching verified release, or use --binary FILE for a reviewed build." >&2; exit 1; }
[ -f "$SCRIPT_DIR/install-agent.sh" ] || { echo 'Shared secure installer is missing from this bundle.' >&2; exit 1; }

# Private kit validation and signed runtime verification precede every optional
# package action. Never source/evaluate data downloaded from the controller.
if [ -n "$SETUP_FILE" ]; then
  MANIFEST=$PROJECT_ROOT/runtime-integrity.json
  TRUST=$PROJECT_ROOT/deploy/release-public-trust.json
  if [ -f "$TARGET_ROOT/etc/seg-agent/release-public-trust.json" ]; then TRUST=$TARGET_ROOT/etc/seg-agent/release-public-trust.json; fi
  if [ -z "$TARGET_ROOT" ] || [ -f "$MANIFEST" ]; then
    [ -f "$MANIFEST" ] && [ -f "$TRUST" ] || { echo 'A signed runtime manifest and independently established public release trust are required.' >&2; exit 1; }
    "$BINARY" --check-release --release-manifest "$MANIFEST" --release-trust "$TRUST" --release-binary "$BINARY" --release-unit "$PROJECT_ROOT/deploy/systemd/seg-agent.service"
  fi
  SETUP_WORK=$(mktemp -d "${TMPDIR:-/tmp}/prthak-agent-setup.XXXXXXXX")
  SETUP_WORK=$(CDPATH= cd -- "$SETUP_WORK" && pwd -P)
  trap 'rm -rf -- "$SETUP_WORK"' 0
  trap 'exit 1' 1 2 15
  "$BINARY" --prepare-setup "$SETUP_FILE" --setup-output "$SETUP_WORK"
  CONFIG_SOURCE=$SETUP_WORK/agent.json
  CA_SOURCE=$SETUP_WORK/controller-ca.crt
  TOKEN_SOURCE=$SETUP_WORK/enrollment-token
  if [ -f "$SETUP_WORK/endpoint-ca.crt" ]; then ENDPOINT_CA_SOURCE=$SETUP_WORK/endpoint-ca.crt; fi
  if [ -f "$SETUP_WORK/preparation-options.json" ] || [ "$AUTO_DEPENDENCIES" -eq 1 ]; then
    if [ -z "$TARGET_ROOT" ] && [ "$NO_START" -eq 0 ]; then
      if [ "$AUTO_DEPENDENCIES" -eq 1 ]; then
        "$BINARY" --prepare-host "$SETUP_FILE" --prepare-family "$FAMILY" --install-dependencies --release-manifest "$MANIFEST" --release-trust "$TRUST" --release-binary "$BINARY" --release-unit "$PROJECT_ROOT/deploy/systemd/seg-agent.service"
      else
        "$BINARY" --prepare-host "$SETUP_FILE" --prepare-family "$FAMILY" --release-manifest "$MANIFEST" --release-trust "$TRUST" --release-binary "$BINARY" --release-unit "$PROJECT_ROOT/deploy/systemd/seg-agent.service"
      fi
    else
      printf '%s\n' 'Staging/--no-start: explicit host preparation skipped; no package/service/firewall action is permitted.'
    fi
  fi
fi

available() {
  if [ -z "$TARGET_ROOT" ]; then
    command -v "$1" >/dev/null 2>&1
  else
    for directory in usr/bin usr/sbin bin sbin; do
      if [ -f "$TARGET_ROOT/$directory/$1" ] && [ -x "$TARGET_ROOT/$directory/$1" ]; then return 0; fi
    done
    return 1
  fi
}
MISSING=
for command_name in systemctl systemd-run journalctl ss firewall-cmd flock nft sysctl; do
  if ! available "$command_name"; then MISSING="$MISSING $command_name"; fi
done
if [ -n "$MISSING" ]; then
  printf '%s\n' "Missing target commands:$MISSING" >&2
  if [ "$FAMILY" = rhel ]; then
    printf '%s\n' 'Required packages: systemd, iproute, firewalld, ca-certificates, util-linux, nftables, procps-ng (approved RHEL repositories/subscription).' >&2
  else
    printf '%s\n' 'Required packages: systemd, iproute2, firewalld, ca-certificates, util-linux, nftables, procps (approved Ubuntu repositories).' >&2
  fi
  printf '%s\n' 'Use the automatic installer with a GUI-generated setup file to prepare dependencies with startup suppression. Check-only and staging do not install packages. Firewall activation remains a separate reviewed GUI operation.' >&2
  exit 1
fi
printf '%s\n' "Platform preflight passed: $DISTRO $RELEASE, $ARCH; required commands are installed."
if available ufw; then
  printf '%s\n' 'UFW is installed. Its state/rules are retained; review coexistence/migration before enabling firewalld enforcement.'
fi
printf '%s\n' 'Firewall service state and rules are unchanged. Git, Python and a Go runtime are not required by this endpoint installer.'
if [ "$CHECK_ONLY" -eq 1 ]; then
  printf '%s\n' 'Platform check only; credentials, running service health and native firewall behavior were not validated.'
  exit 0
fi
if [ -n "$CONFIGURATION_FILE" ]; then
  exec "$BINARY" --apply-configuration "$CONFIGURATION_FILE"
fi
# Reconstruct argv with quoted values; never evaluate or log token contents.
set -- "$SCRIPT_DIR/install-agent.sh"
[ -z "$TARGET_ROOT" ] || set -- "$@" --root "$TARGET_ROOT"
[ "$NO_START" -eq 0 ] || set -- "$@" --no-start
[ "$REPLACE_CONFIG" -eq 0 ] || set -- "$@" --replace-config
[ -z "$CA_SOURCE" ] || set -- "$@" --ca-file "$CA_SOURCE"
[ -z "$ENDPOINT_CA_SOURCE" ] || set -- "$@" --endpoint-ca-file "$ENDPOINT_CA_SOURCE"
[ -z "$TOKEN_SOURCE" ] || set -- "$@" --token-file "$TOKEN_SOURCE"
set -- "$@" --wait-seconds "$WAIT_SECONDS" "$BINARY" "$CONFIG_SOURCE"
if [ -n "$SETUP_WORK" ]; then
  sh "$@"
else
  exec sh "$@"
fi
