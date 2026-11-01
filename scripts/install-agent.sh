#!/bin/sh
# Install a reviewed Prṛthak (पृथक्) bootstrap configuration; enroll/report automatically.
set -eu
umask 077
usage() {
  cat >&2 <<'USAGE'
Usage: install-agent.sh [--ca-file CA.pem] [--endpoint-ca-file ENDPOINT_CA.pem]
       [--token-file PRIVATE_FILE]
       [--replace-config] [--no-start] [--wait-seconds 10]
       [--root STAGING_DIR --no-start] /path/to/seg-agent-linux-ARCH /path/to/agent.json

The token is read from a protected file or SEG_ENROLLMENT_TOKEN/SEG_ENROLLMENT_TOKEN_FILE.
Token values are never command-line arguments. Configuration uses canonical paths from agent/config.example.json.
Installation starts/enables the service; enrollment and inventory reporting then create the server automatically.
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
while [ "$#" -gt 0 ]; do
  case "$1" in
    --no-start) NO_START=1; shift ;;
    --replace-config) REPLACE_CONFIG=1; shift ;;
    --ca-file) [ "$#" -ge 2 ] || usage; CA_SOURCE=$2; shift 2 ;;
    --endpoint-ca-file) [ "$#" -ge 2 ] || usage; ENDPOINT_CA_SOURCE=$2; shift 2 ;;
    --token-file) [ "$#" -ge 2 ] || usage; TOKEN_SOURCE=$2; shift 2 ;;
    --root) [ "$#" -ge 2 ] || usage; ROOT=$2; shift 2 ;;
    --wait-seconds) [ "$#" -ge 2 ] || usage; WAIT_SECONDS=$2; shift 2 ;;
    --) shift; break ;;
    -*) usage ;;
    *) break ;;
  esac
done
[ "$#" -eq 2 ] || usage
case "$WAIT_SECONDS" in ''|*[!0-9]*) usage ;; esac
[ "$WAIT_SECONDS" -le 60 ] || usage
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
ACTIVE_CONFIG=$ETC_DIR/config.json
RUNTIME_MANIFEST=$PROJECT_ROOT/runtime-integrity.json
RELEASE_TRUST=$PROJECT_ROOT/deploy/release-public-trust.json
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
trap 'rm -rf -- "$WORK_DIR"' 0
trap 'exit 1' 1 2 15
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
  if [ ! -f "$ETC_DIR/release-public-trust.json" ]; then install -m 0644 "$RELEASE_TRUST" "$ETC_DIR/release-public-trust.json"; fi
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
systemctl enable seg-agent.service
if [ "$NO_START" -eq 1 ]; then
  printf '%s\n' 'Prṛthak (पृथक्) installed and enabled. --no-start leaves the service stopped until target boot or an explicit start.'
  exit 0
fi
"$BIN_DIR/seg-agent" --config "$ACTIVE_CONFIG" --prepare-start
if ! systemctl restart seg-agent.service; then
  echo 'Prṛthak (पृथक्) installed, but systemd could not start it. Inspect: journalctl -u seg-agent.service' >&2
  exit 1
fi
ELAPSED=0
STATUS_OUTPUT='Prṛthak (पृथक्) registration pending; automatic retries are active.'
while :; do
  if STATUS_OUTPUT=$("$BIN_DIR/seg-agent" --config "$ACTIVE_CONFIG" --status 2>&1); then
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
