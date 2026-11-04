#!/usr/bin/env python3
"""Build and export the Prṛthak appliance images on a connected Docker host."""

import argparse
import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

PROJECT = Path(__file__).resolve().parents[1]
PLATFORM = "linux/amd64"


def public_snapshot(source):
    # Use the same public input allowlist as the signed controller archive.
    spec = importlib.util.spec_from_file_location(
        "prthak_controller_packager", PROJECT / "scripts/package-controller.py"
    )
    packager = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(packager)
    return packager.snapshot(source.resolve(strict=True))


def build_contexts(staging, payload):
    def copy(component, source, name=None):
        destination = staging / component / (name or Path(source).name)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(payload[source])

    for path in payload:
        if path.startswith(("controller/", "dashboard/")):
            copy("controller", path, path)
    for path in (
        "deploy/cluster/node_helper.py", "deploy/runtime-integrity.json",
        "deploy/release-public-trust.json", "deploy/verify_runtime_entrypoint.py",
    ):
        copy("controller", path, path)

    base = payload["deploy/Dockerfile.controller"].decode("utf-8")
    base, count = re.subn(r"^FROM ([^ \n]+)$", r"FROM \1 AS appliance_base", base,
                          count=1, flags=re.MULTILINE)
    appliance = payload["deploy/appliance/Dockerfile.controller"].decode("utf-8")
    original_base = "FROM prthak-controller:appliance-base\n"
    if count != 1 or not appliance.startswith(original_base):
        raise ValueError("The appliance controller base image definition changed")
    copy("controller", "deploy/appliance/controller_entrypoint.py")
    (staging / "controller/Dockerfile").write_text(
        base.rstrip() + "\n\nFROM appliance_base\n" + appliance[len(original_base):],
        encoding="utf-8",
    )
    for name in ("database", "etcd"):
        copy(name, f"deploy/appliance/Dockerfile.{name}", "Dockerfile")
    for name in ("bootstrap_roles.py", "rotation_helper.py", "restore_helper.py"):
        copy("database", f"deploy/appliance/{name}")
    copy("etcd", "deploy/appliance/etcd-build-inputs.json")

    manager_source = "deploy/appliance/node_manager.py"
    manager = payload[manager_source].decode("utf-8")
    router = re.search(
        r"^ROUTER_IMAGE = ['\"](haproxy:[a-z0-9.\-]+@sha256:[a-f0-9]{64})['\"]$",
        manager, re.MULTILINE,
    )
    if not router:
        raise ValueError("Expected a digest-pinned HAProxy image in the appliance manager")
    if payload["deploy/appliance/Dockerfile.router"].splitlines()[0] != f"FROM {router.group(1)}".encode():
        raise ValueError("Offline router must use the same pinned HAProxy base as the appliance manager")
    copy("router", "deploy/appliance/Dockerfile.router", "Dockerfile")
    copy("router", "deploy/appliance/router-entrypoint.sh")
    copy("host", manager_source)
    copy("host", "deploy/appliance/offline_update.py")


def image_id(docker, name):
    details = json.loads(subprocess.check_output(
        [*docker, "image", "inspect", "--format", "{{json .}}", name],
        text=True,
    ))
    identifier = details["Id"]
    if ((details["Os"], details["Architecture"]) != ("linux", "amd64")
            or not re.fullmatch(r"sha256:[a-f0-9]{64}", identifier)):
        raise ValueError(f"Expected a Linux AMD64 image with an immutable ID for {name}")
    return identifier


def save_images(docker, tags, path):
    with path.open("xb") as raw:
        with gzip.GzipFile(filename="", mode="wb", compresslevel=6, fileobj=raw, mtime=0) as archive:
            with subprocess.Popen(
                [*docker, "image", "save", "--platform", PLATFORM, *tags],
                stdout=subprocess.PIPE,
            ) as process:
                shutil.copyfileobj(process.stdout, archive, 1024 * 1024)
                if process.wait():
                    raise ValueError("Docker could not export the four appliance images")

    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def build(source, output, docker):
    version, payload = public_snapshot(source)
    tags = {name: f"prthak-offline-{name}:{version}"
            for name in ("controller", "database", "etcd", "router")}
    output.mkdir(parents=True, exist_ok=True)
    output = output.resolve()
    filenames = ("images.tar.gz", "images.json")
    if any(os.path.lexists(output / name) for name in filenames):
        raise ValueError("Offline image outputs already exist in the selected directory")
    with tempfile.TemporaryDirectory(prefix=".prthak-offline-images-", dir=output) as temporary:
        staging = Path(temporary)
        build_contexts(staging, payload)
        for name, tag in tags.items():
            subprocess.run(
                [*docker, "buildx", "build", "--platform", PLATFORM, "--load",
                 "--provenance=false", "--sbom=false", "--tag", tag, str(staging / name)],
                check=True,
            )
        identifiers = {name: image_id(docker, tag) for name, tag in tags.items()}

        # Exercise the exact signed host/app pairing before exporting it.
        container = [*docker, "run", "--rm", "--platform", PLATFORM, "--pull", "never",
                     "--network", "none", "--read-only"]
        controller = identifiers["controller"]
        subprocess.run([*container, "-i", controller, "--validate-initial-env"],
                       input=b"{}\n", check=True)
        for filename, check in (("node_manager.py", "--check-host"), ("offline_update.py", "--check-host-update")):
            # The verifier expects Linux root ownership and a single link, which
            # a Docker Desktop bind mount may not preserve.
            subprocess.run(
                [*container, "-i", "--user", "0", "--tmpfs", "/prthak-host:mode=0755",
                 "--entrypoint", "sh", controller, "-ec",
                 'umask 022; cat > "$2"; exec python3 /opt/prthak-integrity/launch.py "$1" "$2"',
                 "verify-host", check, "/prthak-host/" + filename],
                input=(staging / "host" / filename).read_bytes(), check=True,
            )
        digest = save_images(docker, tags.values(), staging / filenames[0])
        manifest = {"platform": PLATFORM, "images": identifiers, "archive_sha256": digest}
        metadata = staging / filenames[1]
        metadata.write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        metadata.chmod(0o600)
        os.link(staging / filenames[0], output / filenames[0])
        try:
            os.link(staging / filenames[1], output / filenames[1])
        except OSError:
            (output / filenames[0]).unlink()
            raise
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, default=PROJECT)
    parser.add_argument("--output-dir", type=Path, required=True,
                        help="Offline payload directory that will receive images.tar.gz and images.json")
    parser.add_argument("--context", help="Docker context for a connected AMD64-capable builder")
    args = parser.parse_args()
    docker = ["docker", "--context", args.context] if args.context else ["docker"]
    try:
        manifest = build(args.source_root, args.output_dir, docker)
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        parser.exit(1, f"Offline image build stopped: {error}\n")
    print(json.dumps(manifest, sort_keys=True))


if __name__ == "__main__":
    main()
