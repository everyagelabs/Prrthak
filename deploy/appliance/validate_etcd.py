#!/usr/bin/env python3
"""Exercise the reviewed etcd image in a disposable, private mTLS quorum.

Requires Docker and the controller's cryptography dependency. Uses no host
ports, production data, external PKI, privileged container or Docker socket
mount. Generated private keys exist only in memory and an owned named volume.
This is container acceptance, not native host/DC failure or watchdog testing.
"""
import argparse
from datetime import datetime, timedelta, timezone
import io
import ipaddress
import json
from pathlib import Path
import secrets
import subprocess
import tarfile
import time
import uuid


def fixture_archive(ips, names):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    now = datetime.now(timezone.utc)

    def authority(name):
        key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
        certificate = (x509.CertificateBuilder().subject_name(subject)
                       .issuer_name(subject).public_key(key.public_key())
                       .serial_number(x509.random_serial_number())
                       .not_valid_before(now - timedelta(minutes=5))
                       .not_valid_after(now + timedelta(days=1))
                       .add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
                       .sign(key, hashes.SHA256()))
        return key, certificate

    ca_key, ca = authority("Disposable etcd acceptance CA")
    _, untrusted = authority("Untrusted disposable CA")
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as archive:
        def add(name, value=None, mode=0o600):
            info = tarfile.TarInfo(name)
            info.uid = info.gid = 10002
            info.mode = mode
            if value is None:
                info.type = tarfile.DIRTYPE
                archive.addfile(info)
            else:
                info.size = len(value)
                archive.addfile(info, io.BytesIO(value))

        for index, address in enumerate(ips):
            prefix = "node" + str(index)
            for directory in (prefix, prefix + "/data", prefix + "/config"):
                add(directory, mode=0o700)
            key = ec.generate_private_key(ec.SECP256R1())
            leaf = (x509.CertificateBuilder()
                    .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[index])]))
                    .issuer_name(ca.subject).public_key(key.public_key())
                    .serial_number(x509.random_serial_number())
                    .not_valid_before(now - timedelta(minutes=5))
                    .not_valid_after(now + timedelta(days=1))
                    .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
                    .add_extension(x509.SubjectAlternativeName([
                        x509.DNSName(names[index]), x509.DNSName("localhost"),
                        x509.IPAddress(ipaddress.ip_address(address)),
                        x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), False)
                    .add_extension(x509.ExtendedKeyUsage([
                        ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]), False)
                    .sign(ca_key, hashes.SHA256()))
            add(prefix + "/config/ca.pem", ca.public_bytes(serialization.Encoding.PEM), 0o444)
            add(prefix + "/config/untrusted-ca.pem", untrusted.public_bytes(serialization.Encoding.PEM), 0o444)
            add(prefix + "/config/node.pem", leaf.public_bytes(serialization.Encoding.PEM), 0o444)
            add(prefix + "/config/node-key.pem", key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()))
            config = {
                "name": names[index], "data-dir": "/etcd-data",
                "listen-client-urls": "https://0.0.0.0:2379",
                "advertise-client-urls": "https://" + address + ":2379",
                "listen-peer-urls": "https://0.0.0.0:2380",
                "initial-advertise-peer-urls": "https://" + address + ":2380",
                "initial-cluster": ",".join(name + "=https://" + ip + ":2380" for name, ip in zip(names, ips)),
                "initial-cluster-token": names[0], "initial-cluster-state": "new",
                "tls-min-version": "TLS1.2",
            }
            for kind in ("client", "peer"):
                config[kind + "-transport-security"] = {
                    "cert-file": "/config/node.pem", "key-file": "/config/node-key.pem",
                    "trusted-ca-file": "/config/ca.pem", "client-cert-auth": True,
                }
            add(prefix + "/config/etcd.json", json.dumps(config).encode())
    return stream.getvalue()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--context", required=True)
    parser.add_argument("--image", default="prthak-etcd:appliance-base")
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    prefix = "prthak-etcd-check-" + uuid.uuid4().hex[:12]
    network, volume = prefix + "-network", prefix + "-state"
    names = [prefix + "-" + str(index) for index in range(3)]
    subnet = "10.250." + str(secrets.randbelow(200) + 20)
    ips = [subnet + "." + str(index + 11) for index in range(3)]
    cases = []
    started = time.monotonic()

    def run(arguments, *, data=None, check=True, timeout=30):
        result = subprocess.run(["docker", "--context", args.context, *arguments],
                                input=data, capture_output=True, timeout=timeout)
        if check and result.returncode:
            raise RuntimeError("Private etcd check failed: " + str(arguments[:3]) + "\n" +
                               result.stderr.decode(errors="replace")[-2000:])
        return result

    def ctl(index, command, *, active=None, credentials=True, ca="ca.pem", check=True):
        addresses = [ips[i] for i in (active if active is not None else [index])]
        command_line = ["exec", names[index], "/usr/local/bin/etcdctl",
                        "--endpoints=" + ",".join("https://" + ip + ":2379" for ip in addresses),
                        "--cacert=/config/" + ca, "--dial-timeout=2s", "--command-timeout=3s"]
        if credentials:
            command_line += ["--cert=/config/node.pem", "--key=/config/node-key.pem"]
        return run(command_line + command, check=check)

    def healthy(active):
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            if ctl(active[0], ["endpoint", "health"], active=active, check=False).returncode == 0:
                return
            time.sleep(1)
        raise RuntimeError("Private authenticated etcd quorum readiness deadline expired")

    def passed(name):
        cases.append(name)
        print(name + ": PASS", flush=True)

    cleanup = []
    try:
        inspection = json.loads(run(["image", "inspect", args.image]).stdout)[0]
        assert inspection["Config"]["User"] == "10002:10002"
        passed("image declares the fixed nonroot service UID")
        run(["network", "create", "--internal", "--subnet", subnet + ".0/24", network])
        run(["volume", "create", volume])
        run(["run", "--rm", "--network", "none", "--user", "0:0", "-i",
             "--mount", "type=volume,source=" + volume + ",target=/fixture",
             "--entrypoint", "/bin/sh", args.image, "-ec", "tar -xpf - -C /fixture"],
            data=fixture_archive(ips, names))
        for index, name in enumerate(names):
            run(["run", "-d", "--name", name, "--network", network, "--ip", ips[index],
                 "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
                 "--user", "10002:10002", "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m",
                 "--mount", "type=volume,source=" + volume + ",target=/config,volume-subpath=node" + str(index) + "/config,readonly",
                 "--mount", "type=volume,source=" + volume + ",target=/etcd-data,volume-subpath=node" + str(index) + "/data",
                 args.image, "/usr/local/bin/etcd", "--config-file=/config/etcd.json"])
        healthy([0, 1, 2])
        passed("three real read-only rootfs mutual-TLS voters form healthy quorum")
        for binary, command in (("etcd", "--version"), ("etcdctl", "version"), ("etcdutl", "version")):
            result = run(["exec", names[0], "/usr/local/bin/" + binary, command])
            assert b"3.6.16" in result.stdout
            metadata = run(["exec", names[0], "/bin/cat", "/opt/prthak/etcd-build/" + binary + ".txt"]).stdout
            assert b"golang.org/x/net\tv0.62.0" in metadata
            if binary != "etcdctl":
                assert b"golang.org/x/crypto\tv0.58.1-0.20261009181718-2f1f834330b2" in metadata
        passed("all three CLI tools and retained exact patched module metadata")
        assert ctl(0, ["endpoint", "health"], credentials=False, check=False).returncode != 0
        passed("client without certificate is refused")
        assert ctl(0, ["endpoint", "health"], ca="untrusted-ca.pem", check=False).returncode != 0
        passed("untrusted server CA is refused")
        key = "prthak-validation/" + prefix
        ctl(0, ["put", key, "before-leader-change"])
        for index in range(3):
            assert ctl(index, ["get", key, "--print-value-only"]).stdout.strip() == b"before-leader-change"
        passed("linearizable writes and reads succeed at every voter")
        status = json.loads(ctl(0, ["endpoint", "status", "--write-out=json"], active=[0, 1, 2]).stdout)
        leaders = {item["Status"]["leader"] for item in status}
        assert len(leaders) == 1
        leader = next(index for index, item in enumerate(status) if item["Status"]["header"]["member_id"] in leaders)
        run(["stop", "--time", "5", names[leader]])
        survivors = [index for index in range(3) if index != leader]
        healthy(survivors)
        ctl(survivors[0], ["put", key, "after-leader-change"], active=survivors)
        assert ctl(survivors[1], ["get", key, "--print-value-only"]).stdout.strip() == b"after-leader-change"
        passed("surviving two voters elect leader and commit a new write")
        run(["start", names[leader]])
        healthy([0, 1, 2])
        assert ctl(leader, ["get", key, "--print-value-only"]).stdout.strip() == b"after-leader-change"
        passed("stopped voter rejoins from its persisted data and sees committed write")
        ctl(0, ["snapshot", "save", "/etcd-data/validation.snapshot"])
        snapshot = json.loads(run(["exec", names[0], "/usr/local/bin/etcdutl", "snapshot", "status",
                                   "/etcd-data/validation.snapshot", "--write-out=json"]).stdout)
        assert snapshot["revision"] >= 3 and snapshot["totalKey"] >= 1
        run(["exec", names[0], "/usr/local/bin/etcdutl", "snapshot", "restore", "/etcd-data/validation.snapshot",
             "--data-dir=/etcd-data/validation-restore", "--name=validation-restore",
             "--initial-cluster=validation-restore=https://127.0.0.1:2380",
             "--initial-advertise-peer-urls=https://127.0.0.1:2380"])
        passed("snapshot save, independent status and checksum-verified offline restore")
        report = {"status": "passed", "image": args.image, "image_id": inspection["Id"],
                  "cases": cases, "case_count": len(cases),
                  "elapsed_seconds": round(time.monotonic() - started, 3),
                  "scope": "Disposable container mTLS quorum; no DC/native host or watchdog validation"}
    finally:
        for name in names:
            result = run(["rm", "-f", "-v", name], check=False)
            cleanup.append(result.returncode == 0 or b"No such container" in result.stderr)
        for kind, name in (("network", network), ("volume", volume)):
            result = run([kind, "rm", name], check=False)
            cleanup.append(result.returncode == 0 or b"not found" in result.stderr or b"No such" in result.stderr)
    assert all(cleanup), "Owned acceptance resources were not completely removed"
    report["owned_containers_network_volume_removed"] = True
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n")
        args.report.chmod(0o600)
    print(json.dumps(report), flush=True)


if __name__ == "__main__":
    main()
