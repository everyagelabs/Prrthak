#!/usr/bin/env python3
"""Explicit disposable Docker source-set adapter/network acceptance.

No host ports, host networks, host credentials, Docker socket mounts or existing
firewalls are used. Management witness and systemd timer are test callbacks;
native RHEL/systemd/fencing remain a separate acceptance matrix.
"""
import json
import os
import re
from pathlib import Path
import shutil
import subprocess
import time
import uuid

if os.environ.get("PRTHAK_DISPOSABLE_IPSET_LAB") != "1":
    raise SystemExit("Set PRTHAK_DISPOSABLE_IPSET_LAB=1 only for a disposable local Docker fixture")
root = Path(__file__).resolve().parent.parent
firewall_image = os.environ.get("PRTHAK_PRIVATE_FIREWALL_IMAGE", "prthak-private-firewall-smoke:latest")
public = root / ".local/ipset-smoke/public"
public.mkdir(parents=True, exist_ok=True)
binary = root / ".local/ipset-smoke.test"
if not binary.is_file():
    raise SystemExit("Build the Linux ARM64 Go agent test executable at .local/ipset-smoke.test first")
shutil.copy2(binary, public / "ipsets.test")
script = r'''#!/bin/sh
set -eu
export DBUS_SYSTEM_BUS_ADDRESS=unix:path=/tmp/private-system-bus
mkdir -p /run/firewalld /run/sshd
printf '%s\n' 'FirewallBackend=nftables' 'LogDenied=off' > /etc/firewalld/firewalld.conf
dbus-daemon --session --nofork --address="$DBUS_SYSTEM_BUS_ADDRESS" >/tmp/dbus.log 2>&1 &
firewalld --nofork --nopid --log-target=file --log-file=/tmp/firewalld.log >/tmp/firewalld-stdout.log 2>&1 &
count=0
while ! firewall-cmd --state >/dev/null 2>&1; do count=$((count+1)); if [ "$count" -ge 20 ]; then cat /tmp/firewalld.log; exit 1; fi; sleep 1; done
ssh-keygen -q -t ed25519 -N '' -f /tmp/private-ssh-hostkey
/usr/sbin/sshd -D -e -p 2022 -h /tmp/private-ssh-hostkey >/tmp/sshd.log 2>&1 &
# This fresh isolated fixture has no management sessions or imported state.
# Its single bootstrap reload is before the agent test, never policy-time.
for bank in a b la lb; do
 for digit in 4 6; do
  family=inet; if [ "$digit" = 6 ]; then family=inet6; fi
  firewall-cmd --permanent --new-ipset="prthak_${bank}${digit}_00" --type=hash:net --option="family=$family" --option=hashsize=1024 --option=maxelem=16384 >/dev/null
 done
done
firewall-cmd --permanent --zone=public --add-interface=eth0 >/dev/null
firewall-cmd --permanent --zone=public --add-port=18080/tcp >/dev/null
firewall-cmd --reload >/dev/null
cat /etc/os-release
firewall-cmd --version
PRTHAK_PRIVATE_IPSET_LINUX=1 /public/ipsets.test -test.run '^TestRealPrivateManagedIPSetLinux$' -test.v
'''
(public / "run.sh").write_text(script)
docker = shutil.which("docker") or "/opt/homebrew/bin/docker"
tag = "prthak-ipsets-" + uuid.uuid4().hex[:10]
network = tag + "-network"
server = tag + "-server"
clients = {"a": tag + "-a", "b": tag + "-b"}
created = []


def run(*args, check=True, timeout=90):
    return subprocess.run([docker, *args], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=check, timeout=timeout)


try:
    run("network", "create", "--internal", "--subnet", "10.254.231.0/24", "--label", "io.prthak.fixture=" + tag, network)
    for label, ip in (("a", "10.254.231.3"), ("b", "10.254.231.4")):
        run("run", "-d", "--name", clients[label], "--label", "io.prthak.fixture=" + tag, "--network", network, "--ip", ip, "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges", "prthak-linux-smoke:ubuntu", "sleep", "300")
        created.append(clients[label])
    args = ["run", "-d", "--name", server, "--label", "io.prthak.fixture=" + tag, "--network", network, "--ip", "10.254.231.2", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges"]
    for capability in ("NET_ADMIN", "NET_RAW", "SETUID", "SETGID", "CHOWN", "DAC_OVERRIDE", "SYS_CHROOT"):
        args.append("--cap-add=" + capability)
    for directory in ("/tmp", "/run", "/etc/firewalld", "/var/log", "/var/lib/firewalld"):
        args.extend(("--tmpfs", directory + ":rw,nosuid,size=128m"))
    args.extend(("--mount", "type=bind,src=" + str(public) + ",dst=/public,readonly", firewall_image, "/bin/sh", "/public/run.sh"))
    run(*args)
    created.append(server)
    phases = [("managed-a", True, False), ("managed-b", False, True), ("managed-rollback", False, True), ("learning-allow", True, True), ("learning-cleanup", False, True), ("managed-cleanup", True, True)]
    for phase, allowed_a, allowed_b in phases:
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            logs = run("logs", server).stdout
            state = run("inspect", "--format", "{{.State.Running}}", server).stdout.strip()
            if "PRTHAK_IPSET_PHASE=" + phase in logs:
                break
            if state != "true":
                raise RuntimeError("Isolated server stopped: " + logs[-2500:])
            time.sleep(.25)
        else:
            raise RuntimeError("Timed out awaiting isolated phase " + phase)
        for client, allowed in (("a", allowed_a), ("b", allowed_b)):
            probe = run("exec", clients[client], "python3", "-c", "import urllib.request; r=urllib.request.urlopen('http://10.254.231.2:18080',timeout=2); assert r.read()==b'private-source-set-ok'", check=False, timeout=8)
            if (probe.returncode == 0) != allowed:
                raise RuntimeError("Real source reachability mismatch in " + phase + ", client " + client + ": " + probe.stdout[-600:])
        print(json.dumps({"phase": phase, "allowed_source_a": allowed_a, "allowed_source_b": allowed_b, "result": "PASS"}), flush=True)
        run("exec", server, "touch", "/tmp/advance-" + phase)
    code = run("wait", server, timeout=25).stdout.strip()
    logs = run("logs", server).stdout
    if code != "0" or "--- PASS: TestRealPrivateManagedIPSetLinux" not in logs:
        raise RuntimeError("Source-set test did not finish: " + logs[-3000:])
    print(json.dumps({"fixture_image":firewall_image,"os_version":next((line.split("=",1)[1].strip('"') for line in logs.splitlines() if line.startswith("VERSION_ID=")),"unknown"),"firewalld_version":next((line.strip() for line in logs.splitlines() if re.fullmatch(r"[0-9]+\.[0-9]+(?:\.[0-9]+)?",line.strip())),"unknown")}),flush=True)
    print("Real Linux firewalld/nftables IPv4/IPv6 source-set readback, source isolation, bank switch, rollback, additive learning and reviewed cleanup: PASS", flush=True)
finally:
    for name in reversed(created):
        run("rm", "-f", name, check=False, timeout=20)
    run("network", "rm", network, check=False, timeout=20)
