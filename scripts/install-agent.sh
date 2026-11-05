#!/bin/sh
# Install a reviewed Prṛthak (पृथक्) bootstrap configuration; enroll/report automatically.
set -eu
umask 077
usage() {
  cat >&2 <<'USAGE'
Usage: install-agent.sh [--ca-file CA.pem] [--endpoint-ca-file ENDPOINT_CA.pem]
       [--token-file PRIVATE_FILE]
       [--replace-config] [--no-start] [--wait-seconds 10]
       [--resource-limits [--require-state-volume]]
       [--root STAGING_DIR --no-start] /path/to/seg-agent-linux-ARCH /path/to/agent.json

The token is read from a protected file or SEG_ENROLLMENT_TOKEN/SEG_ENROLLMENT_TOKEN_FILE.
Token values are never command-line arguments. Configuration uses canonical paths from agent/config.example.json.
Installation starts/enables the service; enrollment and inventory reporting then create the server automatically.
--resource-limits applies verified Linux cgroup CPU and memory limits.
--require-state-volume also verifies the existing dedicated agent filesystem is at most 10 GB.
USAGE
  exit 2
}
NO_START=0
REPLACE_CONFIG=0
ROOT=
CA_SOURCE=
ENDPOINT_CA_SOURCE=
TOKEN_SOURCE=
WAIT_SECONDS=10
RESOURCE_LIMITS=0
REQUIRE_STATE_VOLUME=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --no-start) NO_START=1; shift ;;
    --replace-config) REPLACE_CONFIG=1; shift ;;
    --ca-file) [ "$#" -ge 2 ] || usage; CA_SOURCE=$2; shift 2 ;;
    --endpoint-ca-file) [ "$#" -ge 2 ] || usage; ENDPOINT_CA_SOURCE=$2; shift 2 ;;
    --token-file) [ "$#" -ge 2 ] || usage; TOKEN_SOURCE=$2; shift 2 ;;
    --root) [ "$#" -ge 2 ] || usage; ROOT=$2; shift 2 ;;
    --wait-seconds) [ "$#" -ge 2 ] || usage; WAIT_SECONDS=$2; shift 2 ;;
    --resource-limits) RESOURCE_LIMITS=1; shift ;;
    --require-state-volume) REQUIRE_STATE_VOLUME=1; shift ;;
    --) shift; break ;;
    -*) usage ;;
    *) break ;;
  esac
done
[ "$#" -eq 2 ] || usage
case "$WAIT_SECONDS" in ''|*[!0-9]*) usage ;; esac
[ "$WAIT_SECONDS" -le 60 ] || usage
if [ "$REQUIRE_STATE_VOLUME" -eq 1 ] && [ "$RESOURCE_LIMITS" -ne 1 ]; then usage; fi
if [ "$RESOURCE_LIMITS" -eq 1 ] && { [ "$NO_START" -eq 1 ] || [ -n "$ROOT" ]; }; then
  echo 'Resource limits require a live install so the native systemd controls can be verified.' >&2
  exit 1
fi
BINARY_SOURCE=$1
CONFIG_SOURCE=$2
[ -f "$BINARY_SOURCE" ] && [ -x "$BINARY_SOURCE" ] || { echo 'Agent binary must be a regular executable file for this host architecture.' >&2; exit 1; }
[ -f "$CONFIG_SOURCE" ] || { echo 'Reviewed configuration file is missing.' >&2; exit 1; }
if [ -n "$ROOT" ]; then
  case "$ROOT" in /*) ;; *) echo 'Staging --root must be absolute.' >&2; exit 1 ;; esac
  [ "$NO_START" -eq 1 ] || { echo 'A staging --root requires --no-start; it never controls live systemd.' >&2; exit 1; }
  mkdir -p -- "$ROOT"
  ROOT=$(CDPATH= cd -- "$ROOT" && pwd -P)
  [ "$ROOT" != / ] || { echo 'Use no --root for a live installation.' >&2; exit 1; }
else
  [ "$(uname -s)" = Linux ] || { echo 'Install on a RHEL or Ubuntu Linux host, or use --root DIR --no-start for staging.' >&2; exit 1; }
  [ "$(id -u)" -eq 0 ] || { echo 'Installation requires root for /etc, /var/lib and systemd.' >&2; exit 1; }
  command -v systemctl >/dev/null
  if [ "$NO_START" -eq 1 ] && systemctl is-active --quiet seg-agent.service; then
    echo '--no-start requires a stopped service; stop it for maintenance or omit --no-start to restart with the reviewed configuration. Nothing was changed.' >&2
    exit 1
  fi
fi
PROJECT_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
ETC_DIR=$ROOT/etc/seg-agent
STATE_DIR=$ROOT/var/lib/seg-agent
BIN_DIR=$ROOT/usr/local/bin
UNIT_DIR=$ROOT/etc/systemd/system
RESOURCE_DIR=$UNIT_DIR/seg-agent.service.d
RESOURCE_DROPIN=$RESOURCE_DIR/50-prthak-resource-limits.conf
ACTIVE_CONFIG=$ETC_DIR/config.json
RUNTIME_MANIFEST=$PROJECT_ROOT/runtime-integrity.json
RELEASE_TRUST=$PROJECT_ROOT/deploy/release-public-trust.json
SELINUX_ACTIVE=0
if [ -z "$ROOT" ]; then
  if command -v getenforce >/dev/null 2>&1; then
    if ! SELINUX_MODE=$(getenforce); then
      echo 'Cannot determine the SELinux state. No installation files were replaced.' >&2; exit 1
    fi
    case "$SELINUX_MODE" in
      Enforcing|Permissive) SELINUX_ACTIVE=1 ;;
      Disabled) ;;
      *) echo 'Unrecognized SELinux state. No installation files were replaced.' >&2; exit 1 ;;
    esac
  elif [ -e /sys/fs/selinux/enforce ] || [ -e /selinux/enforce ]; then
    SELINUX_ACTIVE=1
  fi
  if [ "$SELINUX_ACTIVE" -eq 1 ] && ! command -v restorecon >/dev/null 2>&1; then
    echo 'SELinux is enabled but restorecon is unavailable. Install policycoreutils from the approved OS repository and retry. No installation files were replaced.' >&2
    exit 1
  fi
fi
if [ -f "$RUNTIME_MANIFEST" ] && [ -f "$RELEASE_TRUST" ]; then
  TRUST_SOURCE=$RELEASE_TRUST
  if [ -f "$ETC_DIR/release-public-trust.json" ]; then TRUST_SOURCE=$ETC_DIR/release-public-trust.json; fi
  "$BINARY_SOURCE" --check-release --release-manifest "$RUNTIME_MANIFEST" --release-trust "$TRUST_SOURCE" --release-binary "$BINARY_SOURCE" --release-unit "$PROJECT_ROOT/deploy/systemd/seg-agent.service"
elif [ -z "$ROOT" ]; then
  echo 'An installed daemon requires the signed runtime manifest and independently verified release trust. Use the signed endpoint bundle.' >&2
  exit 1
fi
if [ -L "$ACTIVE_CONFIG" ]; then
  echo 'Refusing to replace a symlink at the active configuration path.' >&2
  exit 1
fi
if [ -f "$ACTIVE_CONFIG" ] && ! cmp -s "$CONFIG_SOURCE" "$ACTIVE_CONFIG"; then
  [ "$REPLACE_CONFIG" -eq 1 ] || { echo 'Existing active configuration differs. Review it and use --replace-config to replace it; nothing was started or changed.' >&2; exit 1; }
fi
INSTALLATION_LEASE_FD=
if [ -z "$ROOT" ]; then
  command -v flock >/dev/null 2>&1 || { echo 'Install util-linux (flock) through the approved OS package process before installation.' >&2; exit 1; }
  [ ! -L "$STATE_DIR" ] && [ ! -L "$STATE_DIR/configuration-transitions" ] || { echo 'Agent state and lease directories must not be symlinks.' >&2; exit 1; }
  install -d -m 0700 "$STATE_DIR" "$STATE_DIR/configuration-transitions"
  [ "$(stat -c %u -- "$STATE_DIR")" = 0 ] && [ "$(stat -c %u -- "$STATE_DIR/configuration-transitions")" = 0 ] || { echo 'Agent state and lease directories must be owned by root.' >&2; exit 1; }
  [ ! -L "$STATE_DIR/configuration-transitions/lock" ] || { echo 'Installation lease must not be a symlink.' >&2; exit 1; }
  if [ -e "$STATE_DIR/configuration-transitions/lock" ] && [ ! -f "$STATE_DIR/configuration-transitions/lock" ]; then echo 'Installation lease must be a regular file.' >&2; exit 1; fi
  exec 9>>"$STATE_DIR/configuration-transitions/lock"
  flock --exclusive --timeout 5 9 || { echo 'Endpoint configuration or recovery is active; installation lease wait exceeded five seconds. Nothing was replaced.' >&2; exit 1; }
  INSTALLATION_LEASE_FD=9
fi
WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/psegra-install.XXXXXX")
RESOURCE_TEMP=
KEEP_WORK_DIR=0
trap 'if [ "$KEEP_WORK_DIR" -eq 0 ]; then rm -rf -- "$WORK_DIR"; else printf "%s\n" "Installation did not complete. Private recovery files were retained at $WORK_DIR; restore the previous installation before retrying." >&2; fi; if [ -n "$RESOURCE_TEMP" ]; then rm -f -- "$RESOURCE_TEMP"; fi' 0
trap 'exit 1' 1 2 15
# Preserve exact prior files, including security xattrs, before a live SELinux
# install stops the service. Standard labels are restored only on these fixed
# final destinations; no recursive relabeling or hardcoded SELinux types.
snapshot_agent_context_files() {
  printf '%s\n' "$ACTIVE_CONFIG" "$ETC_DIR/config.json.previous" \
    "$ETC_DIR/controller-ca.crt" "$ETC_DIR/endpoint-ca.crt" \
    "$ETC_DIR/enrollment-token" "$ETC_DIR/bootstrap.env" \
    "$ETC_DIR/release-public-trust.json" "$BIN_DIR/seg-agent" \
    "$UNIT_DIR/seg-agent.service" "$RESOURCE_DROPIN" \
    "$ROOT/usr/share/doc/seg-agent/README.md" \
    "$ROOT/usr/share/seg-agent/runtime-integrity.json" \
    "$ROOT/usr/share/seg-agent/upgrade-helper" \
    "$ROOT/usr/share/seg-agent/upgrade-helper-integrity.json" > "$WORK_DIR/context-files"
  SNAPSHOT_INDEX=0
  while IFS= read -r CONTEXT_PATH; do
    SNAPSHOT_INDEX=$((SNAPSHOT_INDEX + 1))
    if [ -L "$CONTEXT_PATH" ] || { [ -e "$CONTEXT_PATH" ] && [ ! -f "$CONTEXT_PATH" ]; }; then
      echo 'SELinux installation requires regular, non-symlink destination files. Nothing was replaced.' >&2
      return 1
    fi
    if [ -f "$CONTEXT_PATH" ]; then
      if ! cp --preserve=mode,ownership,timestamps,context,xattr -- "$CONTEXT_PATH" "$WORK_DIR/original-$SNAPSHOT_INDEX"; then
        echo 'Cannot preserve the previous installation and its SELinux context for recovery. Nothing was replaced; check filesystem xattr/context support before retrying.' >&2
        return 1
      fi
    fi
  done < "$WORK_DIR/context-files"
}
restore_agent_contexts() {
  set --
  while IFS= read -r CONTEXT_PATH; do
    if [ -e "$CONTEXT_PATH" ]; then set -- "$@" "$CONTEXT_PATH"; fi
  done < "$WORK_DIR/context-files"
  restorecon -F -- "$@"
}
restore_prior_agent_files() {
  SNAPSHOT_INDEX=0
  CONTEXT_RESTORE_FAILED=0
  while IFS= read -r CONTEXT_PATH; do
    SNAPSHOT_INDEX=$((SNAPSHOT_INDEX + 1))
    if [ -f "$WORK_DIR/original-$SNAPSHOT_INDEX" ]; then
      CONTEXT_RESTORE_TEMP=$(mktemp "$(dirname -- "$CONTEXT_PATH")/.prthak-context-restore.XXXXXX") || { CONTEXT_RESTORE_FAILED=1; continue; }
      if cp --preserve=mode,ownership,timestamps,context,xattr -- "$WORK_DIR/original-$SNAPSHOT_INDEX" "$CONTEXT_RESTORE_TEMP" && mv -f -- "$CONTEXT_RESTORE_TEMP" "$CONTEXT_PATH"; then :
      else rm -f -- "$CONTEXT_RESTORE_TEMP"; CONTEXT_RESTORE_FAILED=1; fi
    elif ! rm -f -- "$CONTEXT_PATH"; then CONTEXT_RESTORE_FAILED=1; fi
  done < "$WORK_DIR/context-files"
  [ "$CONTEXT_RESTORE_FAILED" -eq 0 ] || return 1
  systemctl daemon-reload || return 1
  if [ "$WAS_RUNNING" -eq 1 ]; then
    systemctl start seg-agent.service || return 1
    systemctl is-active --quiet seg-agent.service || return 1
  fi
}
VERIFY_RESOURCES=0
if [ -z "$ROOT" ] && { [ "$RESOURCE_LIMITS" -eq 1 ] || [ -e "$RESOURCE_DROPIN" ] || [ -L "$RESOURCE_DROPIN" ]; }; then
  VERIFY_RESOURCES=1
  if [ "$RESOURCE_LIMITS" -eq 1 ]; then
    if [ -e "$RESOURCE_DIR" ] || [ -L "$RESOURCE_DIR" ]; then
      if [ -L "$RESOURCE_DIR" ] || [ ! -d "$RESOURCE_DIR" ] || [ "$(stat -c %u -- "$RESOURCE_DIR")" != 0 ]; then
        echo 'Agent resource drop-in directory must be a protected root-owned directory.' >&2; exit 1
      fi
      MODE=$(stat -c %a -- "$RESOURCE_DIR")
      [ "$((0$MODE & 0022))" -eq 0 ] || { echo 'Agent resource drop-in directory must not be group or world writable.' >&2; exit 1; }
    fi
    if [ -f "$UNIT_DIR/seg-agent.service" ]; then
      LOADED_DROPINS=$(systemctl show --property=DropInPaths --value seg-agent.service)
      if [ -n "$LOADED_DROPINS" ] && [ "$LOADED_DROPINS" != "$RESOURCE_DROPIN" ]; then
        echo 'Resource limits require the stock agent unit without unrelated systemd overrides. Nothing was replaced.' >&2; exit 1
      fi
    fi
    if [ "$REQUIRE_STATE_VOLUME" -eq 1 ]; then
      "$BINARY_SOURCE" --prepare-agent-resource-limits --require-state-volume > "$WORK_DIR/resource-limits.conf"
    else
      "$BINARY_SOURCE" --prepare-agent-resource-limits > "$WORK_DIR/resource-limits.conf"
    fi
  else
    "$BINARY_SOURCE" --verify-agent-resource-unit
  fi
fi
if [ -n "${SEG_ENROLLMENT_TOKEN:-}" ]; then
  [ -z "$TOKEN_SOURCE" ] || { echo 'Choose either --token-file or SEG_ENROLLMENT_TOKEN.' >&2; exit 1; }
  printf '%s' "$SEG_ENROLLMENT_TOKEN" > "$WORK_DIR/enrollment-token"
  chmod 0600 "$WORK_DIR/enrollment-token"
  TOKEN_SOURCE=$WORK_DIR/enrollment-token
elif [ -z "$TOKEN_SOURCE" ] && [ -n "${SEG_ENROLLMENT_TOKEN_FILE:-}" ]; then
  TOKEN_SOURCE=$SEG_ENROLLMENT_TOKEN_FILE
fi
unset SEG_ENROLLMENT_TOKEN SEG_ENROLLMENT_TOKEN_FILE
if [ -z "$TOKEN_SOURCE" ] && [ -f "$ETC_DIR/enrollment-token" ]; then
  TOKEN_SOURCE=$ETC_DIR/enrollment-token
fi
# The agent validates HTTPS, the actual CA and either a private token or matching
# existing identity. This performs no controller request or firewall operation.
set -- "$BINARY_SOURCE" --config "$CONFIG_SOURCE" --check-config --install-check
[ -z "$INSTALLATION_LEASE_FD" ] || set -- "$@" --installation-lease-fd "$INSTALLATION_LEASE_FD"
[ -z "$ROOT" ] || set -- "$@" --check-root "$ROOT"
[ -z "$CA_SOURCE" ] || set -- "$@" --check-ca "$CA_SOURCE"
[ -z "$ENDPOINT_CA_SOURCE" ] || set -- "$@" --check-endpoint-ca "$ENDPOINT_CA_SOURCE"
[ -z "$TOKEN_SOURCE" ] || set -- "$@" --check-token-file "$TOKEN_SOURCE"
"$@"
if [ "$SELINUX_ACTIVE" -eq 1 ]; then
  snapshot_agent_context_files
  # An interruption after this point must not delete the only prior copies.
  KEEP_WORK_DIR=1
fi
# Stop only the ordinary agent, never an independent rollback unit. Repeat the
# read-only guard after stop so no newly armed transaction can race the copy.
# Credentials/configuration/binary remain unchanged until both checks pass.
WAS_RUNNING=0
if [ -z "$ROOT" ] && systemctl is-active --quiet seg-agent.service; then
  WAS_RUNNING=1
  if ! systemctl stop seg-agent.service; then
    echo 'Could not stop the current agent safely; no replacement was performed.' >&2
    exit 1
  fi
fi
if [ -z "$ROOT" ]; then
  if ! "$BINARY_SOURCE" --config "$CONFIG_SOURCE" --check-upgrade --installation-lease-fd "$INSTALLATION_LEASE_FD"; then
    if [ "$WAS_RUNNING" -eq 1 ]; then systemctl start seg-agent.service || true; fi
    echo 'Agent upgrade refused after stopping: pending enforcement/rollback must finish using the previous binary. Nothing was replaced.' >&2
    exit 1
  fi
fi
install -d -m 0700 "$ETC_DIR" "$STATE_DIR"
install -d -m 0755 "$BIN_DIR" "$UNIT_DIR" "$ROOT/usr/share/doc/seg-agent"
if [ -f "$ACTIVE_CONFIG" ] && ! cmp -s "$CONFIG_SOURCE" "$ACTIVE_CONFIG"; then
  install -m 0600 "$ACTIVE_CONFIG" "$ETC_DIR/config.json.previous"
fi
install -m 0600 "$CONFIG_SOURCE" "$ETC_DIR/config.json.next"
mv -f -- "$ETC_DIR/config.json.next" "$ACTIVE_CONFIG"
if [ -n "$CA_SOURCE" ]; then
  install -m 0644 "$CA_SOURCE" "$ETC_DIR/controller-ca.crt.next"
  mv -f -- "$ETC_DIR/controller-ca.crt.next" "$ETC_DIR/controller-ca.crt"
fi
if [ -n "$ENDPOINT_CA_SOURCE" ]; then
  install -m 0644 "$ENDPOINT_CA_SOURCE" "$ETC_DIR/endpoint-ca.crt.next"
  mv -f -- "$ETC_DIR/endpoint-ca.crt.next" "$ETC_DIR/endpoint-ca.crt"
fi
if [ -n "$TOKEN_SOURCE" ]; then
  install -m 0600 "$TOKEN_SOURCE" "$ETC_DIR/enrollment-token.next"
  mv -f -- "$ETC_DIR/enrollment-token.next" "$ETC_DIR/enrollment-token"
  printf '%s\n' 'SEG_ENROLLMENT_TOKEN_FILE=/etc/seg-agent/enrollment-token' > "$ETC_DIR/bootstrap.env"
  chmod 0600 "$ETC_DIR/bootstrap.env"
fi
install -m 0755 "$BINARY_SOURCE" "$BIN_DIR/seg-agent.next"
mv -f -- "$BIN_DIR/seg-agent.next" "$BIN_DIR/seg-agent"
install -m 0644 "$PROJECT_ROOT/agent/README.md" "$ROOT/usr/share/doc/seg-agent/README.md"
install -m 0644 "$PROJECT_ROOT/deploy/systemd/seg-agent.service" "$UNIT_DIR/seg-agent.service"
if [ -f "$RUNTIME_MANIFEST" ] && [ -f "$RELEASE_TRUST" ]; then
  install -d -m 0755 "$ROOT/usr/share/seg-agent"
  install -m 0644 "$RUNTIME_MANIFEST" "$ROOT/usr/share/seg-agent/runtime-integrity.json"
  # Independent root worker survives upgrades of the running agent binary.
  install -m 0755 "$BINARY_SOURCE" "$ROOT/usr/share/seg-agent/upgrade-helper.next"
  mv -f -- "$ROOT/usr/share/seg-agent/upgrade-helper.next" "$ROOT/usr/share/seg-agent/upgrade-helper"
  install -m 0644 "$RUNTIME_MANIFEST" "$ROOT/usr/share/seg-agent/upgrade-helper-integrity.json.next"
  mv -f -- "$ROOT/usr/share/seg-agent/upgrade-helper-integrity.json.next" "$ROOT/usr/share/seg-agent/upgrade-helper-integrity.json"
  if [ ! -f "$ETC_DIR/release-public-trust.json" ]; then install -m 0644 "$RELEASE_TRUST" "$ETC_DIR/release-public-trust.json"; fi
fi
if [ "$RESOURCE_LIMITS" -eq 1 ]; then
  if [ ! -d "$RESOURCE_DIR" ]; then install -d -m 0755 "$RESOURCE_DIR"; fi
  RESOURCE_TEMP=$(mktemp "$RESOURCE_DIR/.prthak-resource.XXXXXX")
  install -m 0644 "$WORK_DIR/resource-limits.conf" "$RESOURCE_TEMP"
  mv -fT -- "$RESOURCE_TEMP" "$RESOURCE_DROPIN"
  RESOURCE_TEMP=
fi
if [ "$SELINUX_ACTIVE" -eq 1 ] && ! restore_agent_contexts; then
  if restore_prior_agent_files; then
    KEEP_WORK_DIR=0
    echo 'SELinux policy context restoration failed. Previous files and service state were restored; installation did not complete. Check restorecon diagnostics and the installed SELinux policy before retrying.' >&2
  else
    KEEP_WORK_DIR=1
    printf '%s\n' "SELinux policy context restoration failed and recovery is incomplete. Do not start the candidate installation. Preserve the private recovery files at $WORK_DIR and restore the previous installation before retrying." >&2
  fi
  exit 1
fi
# Validate the exact effective installed configuration before starting a service.
set -- "$BIN_DIR/seg-agent" --config "$ACTIVE_CONFIG" --check-config --install-check
[ -z "$INSTALLATION_LEASE_FD" ] || set -- "$@" --installation-lease-fd "$INSTALLATION_LEASE_FD"
[ -z "$ROOT" ] || set -- "$@" --check-root "$ROOT"
[ ! -f "$ETC_DIR/enrollment-token" ] || set -- "$@" --check-token-file "$ETC_DIR/enrollment-token"
"$@"
if [ -n "$ROOT" ]; then
  install -d -m 0755 "$UNIT_DIR/multi-user.target.wants"
  LINK=$UNIT_DIR/multi-user.target.wants/seg-agent.service
  if [ ! -e "$LINK" ] && [ ! -L "$LINK" ]; then ln -s ../seg-agent.service "$LINK"; fi
  printf '%s\n' 'Prṛthak (पृथक्) staged and enabled for the target boot; no live service was started.' 'At target boot the endpoint enrolls and appears in the dashboard automatically.'
  exit 0
fi
systemctl daemon-reload
if [ "$VERIFY_RESOURCES" -eq 1 ]; then
  "$BIN_DIR/seg-agent" --verify-agent-resource-unit
fi
systemctl enable seg-agent.service
if [ "$NO_START" -eq 1 ]; then
  KEEP_WORK_DIR=0
  printf '%s\n' 'Prṛthak (पृथक्) installed and enabled. --no-start leaves the service stopped until target boot or an explicit start.'
  exit 0
fi
"$BIN_DIR/seg-agent" --config "$ACTIVE_CONFIG" --prepare-start
if ! systemctl restart seg-agent.service; then
  echo 'Prṛthak (पृथक्) installed, but systemd could not start it. Inspect: journalctl -u seg-agent.service' >&2
  exit 1
fi
if [ "$VERIFY_RESOURCES" -eq 1 ]; then
  printf '%s\n' 'Prṛthak agent hard CPU and memory controls verified by the systemd startup guard.'
fi
ELAPSED=0
STATUS_OUTPUT='Prṛthak (पृथक्) registration pending; automatic retries are active.'
while :; do
  if STATUS_OUTPUT=$("$BIN_DIR/seg-agent" --config "$ACTIVE_CONFIG" --status 2>&1); then
    KEEP_WORK_DIR=0
    printf '%s\n' "$STATUS_OUTPUT"
    exit 0
  fi
  [ "$ELAPSED" -lt "$WAIT_SECONDS" ] || break
  sleep 1
  ELAPSED=$((ELAPSED + 1))
done
if systemctl is-active --quiet seg-agent.service; then
  printf '%s\n' 'Prṛthak (पृथक्) installed, enabled and running; enrollment/reporting is still pending.' "$STATUS_OUTPUT" 'It will retry automatically with backoff. Inspect progress: journalctl -u seg-agent.service -f'
else
  printf '%s\n' 'Prṛthak (पृथक्) installed and enabled; systemd is restarting the agent.' 'Inspect bootstrap configuration and progress: journalctl -u seg-agent.service -f'
fi
KEEP_WORK_DIR=0
