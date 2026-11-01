#!/usr/bin/env python3
"""Destructive integration fixture for an explicitly marked disposable Linux VM.

Uses a private veth/network namespace, real learning/traffic worker, controller mTLS, SSH2022 and
the compiled agent. Never run on an enrolled endpoint or ordinary development OS.
"""
from __future__ import annotations

import argparse
import http.client
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def command(*args, check=True, timeout=20):
    return subprocess.run(args, check=check, capture_output=True, text=True, timeout=timeout)


def worker(configuration):
    from controller.app import App, Server
    from controller.management_health import ManagementHealth
    from controller.pki import Signer
    from controller.store import Store
    config = json.loads(Path(configuration).read_text())
    pki = Path(config["pki"])
    store = Store(config["database"])
    app = App(store, signer=Signer(pki / "ca.pem", pki / "ca-key.pem"), tokens={"admin": config["admin"]},
        management_health=ManagementHealth("10.232.0.2", ["10.232.0.1/32"]))
    app.start_jobs()
    server = Server(("10.232.0.2", 8787), app)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.minimum_version = ssl.TLSVersion.TLSv1_2
    tls.load_cert_chain(pki / "controller.pem", pki / "controller-key.pem")
    tls.load_verify_locations(pki / "ca.pem")
    tls.verify_mode = ssl.CERT_OPTIONAL
    server.socket = tls.wrap_socket(server.socket, server_side=True, do_handshake_on_connect=False)
    server.serve_forever()


def main(binary):
    if os.geteuid() != 0 or os.environ.get("PRTHAK_DISPOSABLE_LAB") != "1" or not Path("/run/prthak-disposable-lab").is_file() or Path("/proc/1/comm").read_text().strip() != "systemd":
        raise SystemExit("Refusing: root, systemd and explicit disposable VM marker/opt-in are required")
    command("systemd-detect-virt", "--vm")
    command("firewall-cmd", "--state")
    from controller.pki import init_ca, run as openssl
    from controller.store import Store
    namespace, interface = "prthak-controller-source", "ptk-e2e-host"
    if command("ip", "link", "show", interface, check=False).returncode == 0 or namespace in command("ip", "netns", "list").stdout:
        raise SystemExit("Refusing to reuse an existing fixture namespace/interface")
    process = ssh = agent_process = None
    added_ports = []
    directory = tempfile.TemporaryDirectory(prefix="prthak-controller-lab-")
    root = Path(directory.name)
    controller_log = (root / "controller.log").open("w")
    results = []
    def stage(message):
        results.append(message)
        print(message, flush=True)
    try:
        command("ip", "netns", "add", namespace)
        command("ip", "link", "add", interface, "type", "veth", "peer", "name", "ptk-e2e-client")
        command("ip", "link", "set", "ptk-e2e-client", "netns", namespace)
        command("ip", "addr", "add", "10.232.0.1/24", "dev", interface)
        command("ip", "link", "set", interface, "up")
        for *args, in [
            ["link", "set", "lo", "up"], ["addr", "add", "10.232.0.2/24", "dev", "ptk-e2e-client"],
            ["addr", "add", "10.232.0.3/24", "dev", "ptk-e2e-client"], ["link", "set", "ptk-e2e-client", "up"]]:
            command("ip", "netns", "exec", namespace, "ip", *args)
        command("firewall-cmd", "--zone=public", "--add-interface=" + interface)
        for scope in ([], ["--permanent"]):
            for port in ("2022/tcp",):
                if command("firewall-cmd", *scope, "--zone=public", "--query-port=" + port, check=False).returncode:
                    command("firewall-cmd", *scope, "--zone=public", "--add-port=" + port)
                    added_ports.append((scope, port))
        Path("/run/sshd").mkdir(exist_ok=True)
        command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(root / "ssh-key"))
        ssh_config = root / "sshd.conf"
        ssh_config.write_text(f"Port 2022\nListenAddress 10.232.0.1\nHostKey {root / 'ssh-key'}\nPidFile {root / 'sshd.pid'}\nUsePAM no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nAuthorizedKeysFile /dev/null\n")
        ssh = subprocess.Popen(["/usr/sbin/sshd", "-D", "-e", "-f", str(ssh_config)], stdout=controller_log, stderr=controller_log)
        service = socket.socket()
        service.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        service.bind(("10.232.0.1", 443)); service.listen(16); service.settimeout(.5)
        stop = threading.Event()
        def accept():
            while not stop.is_set():
                try:
                    connection, _ = service.accept(); connection.close()
                except socket.timeout:
                    continue
                except OSError:
                    break
        threading.Thread(target=accept, daemon=True).start()
        pki = init_ca(root / "controller")
        # Reissue only this disposable server certificate with the private-veth SAN.
        openssl("req", "-new", "-key", str(pki / "controller-key.pem"), "-out", str(pki / "lab.csr"), "-subj", "/CN=prthak-lab-controller")
        ext = pki / "lab.ext"
        ext.write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=IP:10.232.0.2\n")
        openssl("x509", "-req", "-in", str(pki / "lab.csr"), "-CA", str(pki / "ca.pem"), "-CAkey", str(pki / "ca-key.pem"), "-set_serial", str(secrets.randbits(128)), "-out", str(pki / "controller.pem"), "-days", "1", "-extfile", str(ext))
        store = Store(root / "database")
        admin = secrets.token_urlsafe(40)
        token = store.create_token("Disposable managed integration", "lab-admin")
        token_file = root / "enrollment.token"; token_file.write_text(token["token"]); token_file.chmod(0o600)
        worker_config = root / "worker.json"
        worker_config.write_text(json.dumps({"pki": str(pki), "database": str(root / "database"), "admin": admin})); worker_config.chmod(0o600)
        tls = ssl.create_default_context(cafile=str(pki / "ca.pem"))
        def api(method, path, value=None):
            connection = http.client.HTTPSConnection("10.232.0.2", 8787, context=tls, timeout=15)
            connection.request(method, path, body=json.dumps(value) if value is not None else None,
                headers={"Authorization": "Bearer " + admin, "Content-Type": "application/json"})
            response = connection.getresponse(); data = response.read(); connection.close()
            result = json.loads(data) if data else None
            if response.status >= 400:
                raise AssertionError(f"Controller API {method} {path}: {response.status} {result}")
            return result
        def start_controller():
            nonlocal process
            process = subprocess.Popen(["ip", "netns", "exec", namespace, sys.executable, str(Path(__file__).resolve()), "--worker", str(worker_config)], stdout=controller_log, stderr=controller_log)
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                try:
                    api("GET", "/readyz"); return
                except (OSError, ssl.SSLError):
                    if process.poll() is not None:
                        raise AssertionError("Lab controller failed to start")
                    time.sleep(.1)
            raise AssertionError("Lab controller startup timed out")
        start_controller()
        config = root / "agent.json"
        config.write_text(json.dumps({"controller_url": "https://10.232.0.2:8787", "state_dir": str(root / "endpoint"), "ca_cert": str(pki / "ca.pem"),
            "enrollment_token_file": str(token_file), "zone": "public", "management_sources": ["10.232.0.2/32"], "enforce": True, "learning_auto_allow": True, "interval_seconds": 5})); config.chmod(0o600)
        def run_agent(expect_success=True):
            result = command(str(binary), "--config", str(config), "--once", check=False, timeout=120)
            if expect_success and result.returncode:
                raise AssertionError("Real agent failed: " + result.stderr[-1500:])
            return result
        run_agent()
        servers = api("GET", "/api/v1/servers")["items"]
        assert len(servers) == 1
        identifier = servers[0]["id"]
        assert 2022 in servers[0]["protection"]["ssh_ports"] and servers[0]["protection"]["ready"]
        stage("PASS: actual SSH2022 discovery, one automatic enrollment and mTLS report/policy delivery")
        ordinary = store.assignment(identifier)[0]
        session = api("POST", "/api/v1/learning", {"server_ids": [identifier], "selection_mode": "discovered", "port_filter": [{"port": 443, "protocol": "tcp"}], "duration_seconds": 180, "policy_action": "auto_allow", "auto_allow_confirmed": True})
        agent_process = subprocess.Popen([str(binary), "--config", str(config)], stdout=controller_log, stderr=controller_log)
        import hashlib
        prefix = "SEG" + hashlib.sha256(session["id"].encode()).hexdigest()[:12] + ":"
        def until(predicate, message, timeout=50):
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                result = predicate()
                if result:
                    return result
                if agent_process.poll() is not None:
                    raise AssertionError("Agent exited: " + (root / "controller.log").read_text()[-2000:])
                time.sleep(.2)
            raise AssertionError(message)
        def probe(source, port):
            script = "import socket,sys\ns=socket.socket();s.settimeout(2);s.bind((sys.argv[1],0))\ntry:s.connect(('10.232.0.1',int(sys.argv[2])))\nexcept OSError:sys.exit(1)\ns.close()"
            return command("ip", "netns", "exec", namespace, "python3", "-c", script, source, str(port), check=False).returncode == 0
        def selected_rules():
            return [line for line in command("firewall-cmd", "--zone=public", "--list-rich-rules").stdout.splitlines() if prefix in line]
        rules = until(selected_rules, "Fresh443 learning instrumentation did not appear")
        assert len(rules) == 1 and 'port="443"' in rules[0] and 'port="22"' not in rules[0] and 'port="2022"' not in rules[0] and 'port="80"' not in rules[0], rules
        current_session = next(item for item in api("GET", "/api/v1/learning")["items"] if item["id"] == session["id"])
        assert current_session["server_ports"][identifier] == [{"port": 443, "protocol": "tcp"}], current_session
        stage("PASS: actual fresh discovery freezes selected443 only; no22/80/2022 learning instrumentation")
        assert not probe("10.232.0.2", 443), "443 was already open before a learned grant"
        def applied():
            row = api("GET", "/api/v1/servers/" + identifier)
            outcome = row.get("learning_allow_outcome", {})
            return row if outcome.get("status") == "applied" and outcome.get("applied_generation", 0) > 0 else None
        row = until(applied, "Actual flow worker/mTLS assignment/health/Go overlay did not commit", timeout=75)
        policies = api("GET", "/api/v1/learning-policies")["items"]
        assert len(policies) == 1 and policies[0]["services"] == [{"port": 443, "protocol": "tcp", "sources": ["10.232.0.2/32"]}], policies
        local = json.loads((root / "endpoint" / "state.json").read_text())
        assert local["policy"]["services"] == ordinary["services"] and local["policy"]["version"] == ordinary["version"]
        assert local["learning_allow_bundle"]["assignment"]["services"] == policies[0]["services"]
        assert probe("10.232.0.2", 443)
        for scope in ([], ["--permanent"]):
            current = command("firewall-cmd", *scope, "--zone=public", "--list-rich-rules").stdout
            assert "PRTL" in current and "reject" not in "\n".join(line for line in current.splitlines() if "PRTL" in line)
        stage("PASS: real kernel source443 hit → durable traffic worker → visible exact learned policy → mTLS learning assignment → real fresh controller/SSH witness → Go runtime/permanent accept-only commit")
        api("POST", "/api/v1/learning/" + session["id"] + "/stop", {})
        until(lambda: not selected_rules(), "Stopped learning log rule was not removed")
        time.sleep(6)
        assert probe("10.232.0.2", 443) and not probe("10.232.0.3", 443)
        assert len(api("GET", "/api/v1/learning-policies")["items"]) == 1
        stage("PASS: stop removes temporary collection, committed learned policy persists, other source stays blocked")
        policy = api("GET", "/api/v1/learning-policies")["items"][0]
        api("DELETE", "/api/v1/learning-policies/" + policy["id"], {"expected_revision": policy["revision"]})
        until(lambda: "PRTL" not in command("firewall-cmd", "--zone=public", "--list-rich-rules").stdout, "Reviewed learned policy deletion did not remove runtime accepts")
        until(lambda: "PRTL" not in command("firewall-cmd", "--permanent", "--zone=public", "--list-rich-rules").stdout, "Reviewed learned policy deletion did not remove permanent accepts")
        assert not probe("10.232.0.2", 443)
        time.sleep(6)
        assert api("GET", "/api/v1/servers/" + identifier)["learning_allow_outcome"]["status"] == "applied"
        stage("PASS: reviewed deletion uses real health-checked Go reconciliation, closes443 and survives subsequent polling")
        print(json.dumps({"result": "PASS", "os": command("lsb_release", "-ds").stdout.strip(), "firewalld": command("firewall-cmd", "--version").stdout.strip(), "real_kernel_learning": True, "real_traffic_worker": True, "real_mtls": True, "real_controller_ssh_health": True, "selected_port": 443, "checks": results, "pilot_started": False}), flush=True)
    except BaseException:
        controller_log.flush()
        print("Lab diagnostics: " + (root / "controller.log").read_text()[-5000:], file=sys.stderr)
        if (root / "endpoint" / "state.json").exists():
            local = json.loads((root / "endpoint" / "state.json").read_text())
            print("Learning outcome: " + json.dumps(local.get("learning_allow_outcome")), file=sys.stderr)
        raise
    finally:
        if agent_process is not None:
            agent_process.terminate()
            try: agent_process.wait(timeout=15)
            except subprocess.TimeoutExpired: agent_process.kill(); agent_process.wait(timeout=5)
        if process is not None:
            process.terminate(); process.wait(timeout=5)
        if ssh is not None:
            ssh.terminate(); ssh.wait(timeout=5)
        owned = set()
        for family in ("managed", "learning-allow"):
            for path in (root / "endpoint" / family / "transactions").glob("*.json"):
                journal = json.loads(path.read_text())
                command("systemctl", "stop", "seg-agent-rollback-" + journal["nonce"] + ".timer", check=False)
                command("systemctl", "stop", "seg-agent-rollback-" + journal["nonce"] + ".service", check=False)
                for mutation in journal.get("mutations", []):
                    owned.add((mutation["scope"], mutation["zone"], mutation["rule"]))
        if (root / "endpoint" / "state.json").exists():
            for rule in json.loads((root / "endpoint" / "state.json").read_text()).get("rules", []):
                owned.add(("runtime", rule["zone"], rule["rule"]))
        for scope, zone, rule in owned:
            command("firewall-cmd", *(["--permanent"] if scope == "permanent" else []), "--zone=" + zone, "--remove-rich-rule=" + rule, check=False)
        for scope, port in added_ports:
            command("firewall-cmd", *scope, "--zone=public", "--remove-port=" + port, check=False)
        command("firewall-cmd", "--zone=public", "--remove-interface=" + interface, check=False)
        command("ip", "link", "del", interface, check=False)
        command("ip", "netns", "del", namespace, check=False)
        controller_log.close()
        directory.cleanup()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker", type=Path)
    parser.add_argument("--binary", type=Path)
    arguments = parser.parse_args()
    if arguments.worker: worker(arguments.worker)
    elif arguments.binary: main(arguments.binary.resolve())
    else: parser.error("--binary required for disposable VM test")
