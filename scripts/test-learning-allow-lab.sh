#!/usr/bin/env bash
# Run ONLY inside the dedicated disposable prthak-lab VM. No host firewall test.
set -euo pipefail
if [[ "${PRTHAK_DISPOSABLE_LAB:-}" != "1" || ! -f /run/prthak-disposable-lab ]]; then
  echo "Refusing: dedicated disposable VM marker and explicit lab opt-in required" >&2
  exit 2
fi
systemd-detect-virt --vm >/dev/null
[[ "$(id -u)" == "0" && "$(cat /proc/1/comm)" == "systemd" ]]
LAB_PUBLIC="$(cd "$(dirname "$0")" && pwd)"
[[ -x "$LAB_PUBLIC/managed.test" && -x "$LAB_PUBLIC/seg-agent" ]]
for command in ip python3 ssh-keygen firewall-cmd systemd-run; do command -v "$command" >/dev/null; done
TASK_DIRECTORY="$(mktemp -d /tmp/prthak-learning-lab.XXXXXX)"
SSH_PID=""
ADDED_PORTS=()
cleanup() {
  [[ ! -f "$TASK_DIRECTORY/sshd.log" ]] || cat "$TASK_DIRECTORY/sshd.log" >&2
  [[ -z "$SSH_PID" ]] || kill "$SSH_PID" 2>/dev/null || true
  while read -r unit _; do [[ -z "$unit" ]] || systemctl stop "$unit" 2>/dev/null || true; done < <(systemctl list-units --all 'seg-agent-rollback-*' --no-legend --no-pager)
  python3 - <<'CLEAN_RULES'
import re, subprocess
for scope in ([], ['--permanent']):
    result=subprocess.run(['firewall-cmd',*scope,'--zone=public','--list-rich-rules'],capture_output=True,text=True)
    for rule in result.stdout.splitlines():
        if (re.search(r'prefix="PRT[ML][0-9a-f]{12}:"',rule) and re.search(r'priority="-(?:31000|30999|31002|31001|31003|31004)"',rule)) or (re.search(r'prefix="SEG[0-9a-f]{12}:"',rule) and 'priority="-32760"' in rule):
            subprocess.run(['firewall-cmd',*scope,'--zone=public','--remove-rich-rule='+rule],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
CLEAN_RULES
  for scope_port in "${ADDED_PORTS[@]}"; do
    scope="${scope_port%%:*}"; port="${scope_port#*:}"
    if [[ "$scope" == permanent ]]; then firewall-cmd --permanent --zone=public --remove-port="$port" >/dev/null 2>&1 || true; else firewall-cmd --zone=public --remove-port="$port" >/dev/null 2>&1 || true; fi
  done
  firewall-cmd --zone=public --remove-interface=prthak-host >/dev/null 2>&1 || true
  ip link del prthak-host 2>/dev/null || true
  ip netns del prthak-managed-client 2>/dev/null || true
  rm -rf "$TASK_DIRECTORY"
}
trap cleanup EXIT
ip netns add prthak-managed-client
ip link add prthak-host type veth peer name prthak-client
ip link set prthak-client netns prthak-managed-client
ip addr add 10.231.0.1/24 dev prthak-host
ip link set prthak-host up
ip netns exec prthak-managed-client ip link set lo up
ip netns exec prthak-managed-client ip addr add 10.231.0.2/24 dev prthak-client
ip netns exec prthak-managed-client ip addr add 10.231.0.3/24 dev prthak-client
ip netns exec prthak-managed-client ip link set prthak-client up
firewall-cmd --zone=public --add-interface=prthak-host >/dev/null
for port in 2022/tcp; do
 if ! firewall-cmd --zone=public --query-port="$port" >/dev/null; then firewall-cmd --zone=public --add-port="$port" >/dev/null; ADDED_PORTS+=("runtime:$port"); fi
 if ! firewall-cmd --permanent --zone=public --query-port="$port" >/dev/null; then firewall-cmd --permanent --zone=public --add-port="$port" >/dev/null; ADDED_PORTS+=("permanent:$port"); fi
done
ssh-keygen -q -t ed25519 -N '' -f "$TASK_DIRECTORY/ssh_host_ed25519_key"
cat > "$TASK_DIRECTORY/sshd_config" <<SSHD
Port 2022
ListenAddress 10.231.0.1
HostKey $TASK_DIRECTORY/ssh_host_ed25519_key
PidFile $TASK_DIRECTORY/sshd.pid
PasswordAuthentication no
KbdInteractiveAuthentication no
UsePAM no
AuthorizedKeysFile /dev/null
SSHD
mkdir -p /run/sshd
/usr/sbin/sshd -D -e -f "$TASK_DIRECTORY/sshd_config" >"$TASK_DIRECTORY/sshd.log" 2>&1 &
SSH_PID="$!"
for attempt in {1..30}; do if [[ "$(ss -H -lntp)" == *":2022 "* ]]; then break; fi; sleep 0.1; done
[[ "$(ss -H -lntp)" == *":2022 "* ]] || { echo "SSH2022 fixture did not start" >&2; exit 1; }
export PRTHAK_MANAGED_SYSTEMD_LAB=1 PRTHAK_WATCHDOG_BINARY="$LAB_PUBLIC/seg-agent"
"$LAB_PUBLIC/managed.test" -test.run '^TestRealLearningAllowSystemdLab$' -test.v -test.timeout 180s
