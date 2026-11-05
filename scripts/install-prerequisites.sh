#!/bin/sh
# Minimal bootstrap for an independently verified, protected controller release.
# Python and Docker are host prerequisites; application configuration is GUI-owned.
set -eu
umask 077
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
unset PYTHONPATH PYTHONHOME PYTHONUSERBASE PYTHONSTARTUP
unset LD_LIBRARY_PATH LD_PRELOAD ENV BASH_ENV

fail() { printf '%s\n' "Prṛthak installation stopped: $*" >&2; exit 1; }
usage() {
  cat <<'USAGE'
Usage: sudo ./scripts/install-controller.sh
       sudo ./scripts/install-controller.sh --offline

Detect RHEL 9/10 or Ubuntu 26.04, install required Python/Docker/Compose packages,
then open the printed HTTPS URL to finish configuration in the GUI.
Use a fresh dedicated Linux systemd VM and an independently verified release.
The installer never removes another container stack or opens host firewall ports.
The RHEL 9 x86_64 offline bundle automatically uses its local RPMs and images.
--offline remains available to explicitly require that bundle.

Compatibility: --gui-setup, --data-root PATH, --env-file FILE,
               --validate-only, --no-start.
--env-file, --validate-only and --no-start require prepared host prerequisites;
they do not automatically install packages or start Docker.
USAGE
}

[ "$#" -ge 2 ] && [ "$1" = --release-root ] || fail 'Use install-controller.sh from the extracted release.'
release_root=$2
shift 2
if [ -e "$release_root/OFFLINE-UPDATE-ONLY" ] || [ -L "$release_root/OFFLINE-UPDATE-ONLY" ]; then
  fail 'Use Platform settings > Updates to upload this GUI-only archive and its detached signature.'
fi
prepare=1
offline=0
expect_value=
gui=0
env_file=0
seen_flags='|'
for argument do
  if [ -n "$expect_value" ]; then
    case "$argument" in ''|--*) fail "Missing value for $expect_value." ;; esac
    expect_value=
    continue
  fi
  case "$seen_flags" in *"|$argument|"*) fail 'Duplicate installer option.' ;; esac
  seen_flags=$seen_flags$argument'|'
  case "$argument" in
    --help|-h) usage; exit 0 ;;
    --gui-setup) gui=1 ;;
    --offline) offline=1 ;;
    --env-file) env_file=1; prepare=0; expect_value=$argument ;;
    --data-root) expect_value=$argument ;;
    --validate-only|--no-start) prepare=0 ;;
    *) fail 'Unsupported installer argument.' ;;
  esac
done
[ -z "$expect_value" ] || fail "Missing value for $expect_value."
[ "$gui:$env_file" != 1:1 ] || fail 'Choose GUI setup or an existing environment file, not both.'
[ "$offline:$prepare" != 1:0 ] || fail 'Offline setup must use the automatic GUI installer.'

# Pick offline mode before any command can contact a package repository. The
# marker is the first archive entry so a partial extraction also stays offline.
if [ "$prepare" -eq 1 ] && [ "$offline" -eq 0 ]; then
  for marker in "$release_root/OFFLINE-CONTROLLER" "$release_root/offline"; do
    if [ -e "$marker" ] || [ -L "$marker" ]; then
      offline=1
      set -- "$@" --offline
      break
    fi
  done
fi

# Check every existing ancestor before executing privileged release/interpreter
# bytes. Symlinked system interpreters are resolved, then their target and both
# ancestor chains must remain root-owned and non-writable by other users.
protected_chain() {
  candidate=$1
  allow_leaf_link=${2:-0}
  first_component=1
  case "$candidate" in /*) ;; *) fail 'Privileged paths must be absolute.' ;; esac
  while :; do
    [ -e "$candidate" ] || fail 'A required protected path is missing.'
    if [ -L "$candidate" ]; then
      [ "$allow_leaf_link:$first_component" = 1:1 ] || fail 'A privileged path ancestor is a symlink.'
      owner=$(stat -c '%u' -- "$candidate") || fail 'Cannot inspect protected symlink ownership.'
      [ "$owner" = 0 ] || fail 'The selected system tool symlink is not root-owned.'
      candidate=$(dirname -- "$candidate")
      first_component=0
      continue
    fi
    owner=$(stat -c '%u' -- "$candidate") || fail 'Cannot inspect protected path ownership.'
    mode=$(stat -c '%a' -- "$candidate") || fail 'Cannot inspect protected path permissions.'
    [ "$owner" = 0 ] || fail 'Run from a root-owned release with a protected system interpreter.'
    case "$mode" in ''|*[!0-7]*) fail 'Unsafe path permissions.' ;; esac
    [ "$((0$mode & 022))" -eq 0 ] || fail 'A privileged path is writable by another user.'
    [ "$candidate" != / ] || break
    candidate=$(dirname -- "$candidate")
    first_component=0
  done
}

protected_tool() {
  protected_chain "$1" 1
  resolved_tool=$(readlink -f -- "$1") || fail 'Cannot resolve a protected system tool.'
  protected_chain "$resolved_tool"
  [ -f "$resolved_tool" ] && [ -x "$resolved_tool" ] || fail 'A protected executable system tool is required.'
}

platform=$(uname -s)
uid=$(id -u)
if [ "$prepare" -eq 1 ]; then
  [ "$platform" = Linux ] || fail 'Automatic controller installation requires Linux.'
  [ "$uid" = 0 ] || fail 'Run the controller installer with sudo.'
  [ -r /etc/os-release ] || fail 'Cannot detect the Linux release.'
  release_field() {
    awk -v wanted="$1" '
      $0 ~ "^" wanted "=" {
        count++; value=substr($0,index($0,"=")+1); quote=sprintf("%c",39);
        if ((substr(value,1,1)=="\"" && substr(value,length(value),1)=="\"") ||
            (substr(value,1,1)==quote && substr(value,length(value),1)==quote))
          value=substr(value,2,length(value)-2);
      }
      END { if(count!=1) exit 1; print value }
    ' /etc/os-release
  }
  distro=$(release_field ID) || fail 'Linux ID is missing or ambiguous.'
  version=$(release_field VERSION_ID) || fail 'Linux version is missing or ambiguous.'
  case "$version" in ''|*[!0-9.]*|.*|*.|*..*) fail 'Linux version must contain only canonical numeric components.' ;; esac
  case "$distro:$version" in
    rhel:9|rhel:9.*|rhel:10|rhel:10.*) family=rhel ;;
    ubuntu:26.04) family=ubuntu ;;
    *) fail 'Automatic controller setup supports RHEL 9/10 and Ubuntu 26.04.' ;;
  esac
  case "$(uname -m)" in x86_64|amd64|aarch64|arm64) ;; *) fail 'Supported controller CPUs are AMD64 and ARM64.' ;; esac
  if [ "$offline" -eq 1 ]; then
    case "$family:$version:$(uname -m)" in
      rhel:9:x86_64|rhel:9.*:x86_64) ;;
      rhel:10:x86_64|rhel:10.*:x86_64)
        [ -f "$release_root/offline/target.json" ] || fail 'RHEL 10 requires its own dependency bundle with an explicit target.' ;;
      *) fail 'The offline controller bundle requires RHEL 9/10 x86_64.' ;;
    esac
  fi
  [ -d /run/systemd/system ] && [ -r /proc/1/comm ] || fail 'Use a genuine systemd VM.'
  [ "$(cat /proc/1/comm)" = systemd ] || fail 'systemd must run as PID 1.'
  [ -x /usr/bin/systemctl ] || fail 'The systemd control tools are required.'
  case "${DOCKER_HOST:-}" in ''|unix:///var/run/docker.sock) ;; *) fail 'Remote/rootless Docker endpoints are not supported.' ;; esac
  [ -z "${DOCKER_CONTEXT:-}" ] || fail 'Inherited Docker contexts are not supported.'
fi

if [ "$uid" = 0 ]; then
  [ "$platform" = Linux ] || fail 'Privileged controller setup requires Linux.'
  for selected in "$release_root" "$release_root/scripts/install-controller.sh" \
    "$release_root/scripts/install-prerequisites.sh" \
    "$release_root/deploy/appliance/install_prerequisites.py" \
    "$release_root/deploy/appliance/node_manager.py"; do
    [ ! -L "$selected" ] || fail 'Privileged release paths cannot be symlinks.'
    protected_chain "$selected"
  done
fi

python_bin=${PRTHAK_INSTALL_PYTHON:-/usr/bin/python3}
case "$python_bin" in /*) ;; *) fail 'PRTHAK_INSTALL_PYTHON must be an absolute protected interpreter path.' ;; esac
if [ ! -x "$python_bin" ]; then
  [ "$offline" -eq 0 ] || fail 'Offline setup requires the stock RHEL system Python used by DNF.'
  [ "$prepare" -eq 1 ] && [ -z "${PRTHAK_INSTALL_PYTHON:-}" ] || fail 'A protected Python 3.9+ interpreter is required for this prepared-host operation.'
  printf '%s\n' 'Installing the required system Python interpreter...'
  if [ "$family" = rhel ]; then
    [ -x /usr/bin/dnf ] || fail 'RHEL requires working approved dnf repositories.'
    protected_tool /usr/bin/dnf
    /usr/bin/dnf -y --setopt=install_weak_deps=False install python3
  else
    [ -x /usr/bin/apt-get ] || fail 'Ubuntu requires working approved apt repositories.'
    protected_tool /usr/bin/apt-get
    /usr/bin/apt-get update
    /usr/bin/env DEBIAN_FRONTEND=noninteractive APT_LISTCHANGES_FRONTEND=none \
      /usr/bin/apt-get -y --no-install-recommends --no-upgrade --no-remove install python3
  fi
fi
[ -x "$python_bin" ] || fail 'Python installation did not provide the required system interpreter.'
if [ "$uid" = 0 ]; then
  protected_tool "$python_bin"
fi
"$python_bin" -I -c 'import sys; raise SystemExit(0 if sys.version_info >= (3,9) else 1)' \
  || fail 'Python 3.9+ is required; an older OS interpreter was not replaced.'
exec "$python_bin" -I "$release_root/deploy/appliance/install_prerequisites.py" \
  --release-root "$release_root" -- "$@"
