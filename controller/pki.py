"""Small development CA. Keep CA private key off public-facing hosts in production."""
from __future__ import annotations

import os
import secrets
import subprocess
import tempfile
from pathlib import Path


def run(*args):
    try:
        return subprocess.run(["openssl", *args], check=True, capture_output=True, timeout=20).stdout.decode()
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        raise ValueError("Certificate request could not be verified or signed") from error


def init_ca(data_dir):
    directory = Path(data_dir) / "pki"
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    if any(directory.iterdir()):
        raise ValueError("PKI directory already contains files; refusing to replace keys")
    previous = os.umask(0o077)
    try:
        run("req", "-x509", "-newkey", "rsa:3072", "-nodes", "-keyout", str(directory / "ca-key.pem"), "-out", str(directory / "ca.pem"), "-days", "3650", "-subj", "/CN=PSegra development CA", "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign")
        run("req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", str(directory / "controller-key.pem"), "-out", str(directory / "controller.csr"), "-subj", "/CN=localhost")
        ext = directory / "server.ext"
        ext.write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1\n")
        run("x509", "-req", "-in", str(directory / "controller.csr"), "-CA", str(directory / "ca.pem"), "-CAkey", str(directory / "ca-key.pem"), "-set_serial", str(secrets.randbits(128)), "-out", str(directory / "controller.pem"), "-days", "365", "-extfile", str(ext))
        (directory / "controller.csr").unlink()
        ext.unlink()
        for path in directory.iterdir():
            path.chmod(0o600)
    finally:
        os.umask(previous)
    return directory


class Signer:
    def __init__(self, ca, ca_key):
        self.ca = Path(ca)
        self.ca_key = Path(ca_key)

    def __call__(self, server_id, csr):
        with tempfile.TemporaryDirectory(prefix="seg-csr-") as temp:
            directory = Path(temp)
            request = directory / "request.pem"
            request.write_text(csr)
            request.chmod(0o600)
            run("req", "-in", str(request), "-noout", "-verify")
            ext = directory / "client.ext"
            ext.write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n")
            cert = directory / "client.pem"
            # Override CSR subject and ignore CSR-supplied extensions.
            run("x509", "-req", "-in", str(request), "-CA", str(self.ca), "-CAkey", str(self.ca_key), "-set_serial", str(secrets.randbits(128)), "-subj", f"/CN={server_id}", "-days", "90", "-extfile", str(ext), "-out", str(cert))
            return cert.read_text(), self.ca.read_text()
