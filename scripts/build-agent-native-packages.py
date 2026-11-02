#!/usr/bin/env python3
"""Build inert RPM/DEB payloads from independently verified endpoint releases.

All payload files stay under /opt/prthak-agent/<version>-linux-<arch>. There
are no maintainer scripts or service/firewall actions. GUI-reviewed activation
still uses the existing family installer. Signing keys never enter Docker.
"""
import argparse
import gzip
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]
NAME = "prthak-agent-payload"
BUNDLE_NAME = re.compile(r"prthak-agent-([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})-linux-(amd64|arm64)\.tar\.gz")
MAX_ARCHIVE = 64 * 1024 * 1024
MAX_TAR = 96 * 1024 * 1024
MAX_FILE = 64 * 1024 * 1024
MAX_ENTRIES = 64
HOST_DENY_GUIDE = "docs/whole-server-default-deny.md"
TRAFFIC_CAPTURE_GUIDE = "docs/traffic-capture.md"
FLEET_GUIDE = "docs/fleet-enrollment.md"
PREPARATION_GUIDE = "docs/endpoint-discovery-and-preparation.md"
ALLOWED = {
    "seg-agent", "INSTALL.txt", "runtime-integrity.json", "deploy/release-public-trust.json",
    "agent/config.example.json", "agent/README.md", "deploy/systemd/seg-agent.service",
    *{"scripts/" + name for name in ("install-agent.sh", "install-agent-linux.sh", "install-agent-rhel.sh", "install-agent-ubuntu.sh", "prepare-managed-ipsets.py", "verify-release.py")},
    *{"docs/" + name for name in ("managed-enforcement.md", "linux-validation.md", "scale-validation.md", "ipset-enforcement.md", "policy-signing.md", "linux-agent-installation.md", "pilot-gui-installation.md", "authentication.md")},
    HOST_DENY_GUIDE,
    TRAFFIC_CAPTURE_GUIDE,
    FLEET_GUIDE,
    PREPARATION_GUIDE,
}
BUILDER_DOCKERFILE = """FROM debian:trixie-slim@sha256:f6b08b09a05725f9431502d3b5714f5c4576e82c1a84fa1debe0c24a7e0c3ec4
RUN apt-get update && apt-get install --no-install-recommends -y python3 rpm dpkg-dev gzip coreutils && rm -rf /var/lib/apt/lists/*
"""
BUILDER_CODE = r'''import json, pathlib, shutil, subprocess, tempfile
p=json.loads(pathlib.Path('/input/build.json').read_text())
work=pathlib.Path(tempfile.mkdtemp(prefix='prthak-native-',dir='/tmp'))
prefix='/opt/prthak-agent/'+p['version']+'-linux-'+p['arch']
for kind in p['formats']:
    if kind=='deb':
        tree=work/'deb'
        target=tree/prefix.lstrip('/')
        target.parent.mkdir(parents=True)
        shutil.copytree('/input/payload',target)
        control=tree/'DEBIAN';control.mkdir()
        (control/'control').write_text('Package: prthak-agent-payload\nVersion: '+p['version']+'\nArchitecture: '+p['arch']+'\nMaintainer: Prthak Operations <prthak@localhost>\nSection: admin\nPriority: optional\nDescription: Verified inert Prthak agent release payload\n Requires a separately reviewed GUI setup kit and explicit family installer.\n')
        subprocess.run(['dpkg-deb','--build','--root-owner-group','--uniform-compression','-Zgzip','-z9',str(tree),'/output/'+p['outputs']['deb']],check=True)
    else:
        top=work/'rpm'
        for d in ('BUILD','BUILDROOT','RPMS','SOURCES','SPECS','SRPMS'):(top/d).mkdir(parents=True)
        arch={'amd64':'x86_64','arm64':'aarch64'}[p['arch']]
        spec=top/'SPECS'/'payload.spec'
        spec.write_text('%global _binary_payload w9.gzdio\n%global _build_id_links none\n%global __os_install_post %{nil}\nName: prthak-agent-payload\nVersion: '+p['version']+'\nRelease: 1\nSummary: Verified inert Prthak agent release payload\nLicense: Proprietary\nAutoReqProv: no\n%description\nRequires a separately reviewed GUI setup kit and explicit family installer.\n%prep\n%build\n%install\nmkdir -p %{buildroot}'+prefix+'\ncp -a /input/payload/. %{buildroot}'+prefix+'/\n%files\n%defattr(-,root,root,-)\n'+prefix+'\n')
        subprocess.run(['rpmbuild','-bb','--target',arch,'--nodeps','--define','_topdir '+str(top),'--define','_tmppath /tmp',str(spec)],check=True)
        packages=list((top/'RPMS').rglob('*.rpm'))
        if len(packages)!=1:raise SystemExit('Expected exactly one inert RPM')
        shutil.copyfile(packages[0],'/output/'+p['outputs']['rpm'])
'''


def regular(path, maximum):
    path = Path(path)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > maximum:
        raise ValueError("Expected a bounded regular file: " + str(path))
    return path


def copy_bounded(source, destination, maximum):
    descriptor = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(descriptor, "rb") as incoming, destination.open("xb") as outgoing:
        info = os.fstat(incoming.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > maximum:
            raise ValueError("Packaging input changed or exceeded its bound")
        total = 0
        while True:
            chunk = incoming.read(min(65536, maximum - total + 1))
            if not chunk:
                break
            total += len(chunk)
            if total > maximum:
                raise ValueError("Packaging input grew beyond its bound")
            outgoing.write(chunk)


def inspect_bundle(archive, payload):
    """Validate the complete tar before extracting only fixed public files."""
    match = BUNDLE_NAME.fullmatch(archive.name)
    if not match:
        raise ValueError("Use an exact versioned Linux endpoint release filename")
    version, arch = match.groups()
    stem = archive.name[:-7]
    plain = payload.parent / "bounded-release.tar"
    total = 0
    with gzip.open(archive, "rb") as incoming, plain.open("xb") as outgoing:
        while True:
            chunk = incoming.read(65536)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_TAR:
                raise ValueError("Expanded release archive exceeds its bound")
            outgoing.write(chunk)
    found = {}
    with tarfile.open(plain, "r:") as incoming:
        for index, item in enumerate(incoming):
            if index >= MAX_ENTRIES:
                raise ValueError("Release has too many archive entries")
            parts = PurePosixPath(item.name).parts
            if item.name.startswith("/") or len(parts) < 2 or parts[0] != stem or any(part in (".", "..") or not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", part) for part in parts):
                raise ValueError("Unsafe or unexpected release path")
            relative = "/".join(parts[1:])
            if item.name != stem + "/" + relative or relative not in ALLOWED or relative in found or item.type not in (tarfile.REGTYPE, tarfile.AREGTYPE) or not 0 <= item.size <= MAX_FILE or item.pax_headers:
                raise ValueError("Release must contain unique allowlisted regular files only")
            found[relative] = item
        release = tuple(map(int, version.split('.')))
        required = ALLOWED - ({HOST_DENY_GUIDE} if release < (0, 8, 0) else set()) - ({TRAFFIC_CAPTURE_GUIDE} if release < (0, 9, 0) else set()) - ({FLEET_GUIDE} if release < (0, 10, 0) else set()) - ({PREPARATION_GUIDE} if release < (0, 11, 0) else set())
        if not required <= found.keys():
            raise ValueError("Release is missing installation or signed-runtime files")
        payload.mkdir(mode=0o755)
        payload.chmod(0o755)
        for relative, item in sorted(found.items()):
            target = payload / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            parent = target.parent
            while parent != payload:
                parent.chmod(0o755)
                parent = parent.parent
            with incoming.extractfile(item) as source, target.open("xb") as destination:
                shutil.copyfileobj(source, destination, 65536)
            target.chmod(0o755 if relative == "seg-agent" or relative.startswith("scripts/") else 0o644)
    with (payload / "seg-agent").open("rb") as source:
        elf = source.read(20)
    if len(elf) != 20 or elf[:6] != b"\x7fELF\x02\x01" or struct.unpack("<H", elf[18:20])[0] != {"amd64": 62, "arm64": 183}[arch]:
        raise ValueError("Release binary must be a 64-bit ELF for its named Linux architecture")
    return {"version": version, "arch": arch, "files": sorted(found), "install_prefix": "/opt/prthak-agent/" + version + "-linux-" + arch}


def output_names(version, arch):
    rpm_arch = {"amd64": "x86_64", "arm64": "aarch64"}[arch]
    return {"deb": f"{NAME}_{version}_{arch}.deb", "rpm": f"{NAME}-{version}-1.{rpm_arch}.rpm"}


def docker_command(image, stage, output):
    return ["docker", "run", "--rm", "--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--user", f"{os.getuid()}:{os.getgid()}", "--tmpfs", "/tmp:rw,nosuid,nodev,size=768m", "--mount", f"type=bind,source={stage},target=/input,readonly", "--mount", f"type=bind,source={output},target=/output", "--entrypoint", "/usr/bin/python3", image, "/input/build_native.py"]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--public-trust-file", required=True, help="independently obtained approved release public trust")
    parser.add_argument("--output-dir", default=str(ROOT / "dist/native"))
    parser.add_argument("--format", choices=("all", "rpm", "deb"), default="all")
    parser.add_argument("--builder-image", default="prthak-agent-native-builder:1")
    parser.add_argument("--build-builder", action="store_true", help="explicitly build the tools image; needs approved registry/OS-package access")
    parser.add_argument("--dry-run", action="store_true", help="verify/inspect and print metadata/commands; no Docker, output or signing")
    parser.add_argument("bundles", nargs="+")
    args = parser.parse_args(argv)
    if not 1 <= len(args.bundles) <= 4 or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9./_:@-]{0,199}", args.builder_image):
        parser.error("Choose up to four releases and a valid prepared builder image")
    formats = ["rpm", "deb"] if args.format == "all" else [args.format]
    trust = regular(args.public_trust_file, 16384).absolute()
    if trust.stat().st_mode & 0o022:
        raise ValueError("Approved public release trust must not be group/world writable")
    output = Path(args.output_dir).absolute()
    if "," in str(output) or any(part.is_symlink() for part in (output, *output.parents)):
        raise ValueError("Use an output directory without symlink aliases or Docker mount separators")
    planned = []
    with tempfile.TemporaryDirectory(prefix="prthak-native-") as temporary:
        work = Path(temporary).resolve()
        if "," in str(work):
            raise ValueError("Use a temporary directory without Docker mount separators")
        for value in args.bundles:
            source = regular(value, MAX_ARCHIVE)
            if not BUNDLE_NAME.fullmatch(source.name):
                raise ValueError("Expected an exact Linux release bundle name")
            stage = work / str(len(planned)); stage.mkdir()
            archive = stage / source.name
            copy_bounded(source, archive, MAX_ARCHIVE)
            signature = regular(str(source) + ".signature.json", 16384).absolute()
            pinned = stage / "input-public-trust.json"
            detached = stage / "input-signature.json"
            copy_bounded(trust, pinned, 16384)
            copy_bounded(signature, detached, 16384)
            pinned.chmod(0o444)
            subprocess.run([sys.executable, str(ROOT / "scripts/verify-release.py"), "--public-trust-file", str(pinned), "--signature", str(detached), str(archive)], check=True)
            plan = inspect_bundle(archive, stage / "payload")
            plan.update(formats=formats, outputs=output_names(plan["version"], plan["arch"]))
            destinations = [output / plan["outputs"][kind] for kind in formats]
            previous = {prior["outputs"][kind] for prior in planned for kind in prior["formats"]}
            if any(path.exists() or path.is_symlink() or path.name in previous for path in destinations):
                raise ValueError("Native output exists or targets overlap; choose a fresh output directory")
            (stage / "build.json").write_text(json.dumps(plan, sort_keys=True))
            (stage / "build_native.py").write_text(BUILDER_CODE)
            plan["command"] = docker_command(args.builder_image, stage, output)
            planned.append(plan)
        if args.dry_run:
            print(json.dumps({"dry_run": True, "packages": planned}, indent=2, sort_keys=True))
            return 0
        output.mkdir(parents=True, exist_ok=True)
        if args.build_builder:
            context = work / "builder"; context.mkdir()
            (context / "Dockerfile").write_text(BUILDER_DOCKERFILE)
            subprocess.run(["docker", "build", "--tag", args.builder_image, str(context)], check=True)
        produced = []
        for plan in planned:
            subprocess.run(plan["command"], check=True)
            produced.extend(regular(output / plan["outputs"][kind], MAX_TAR) for kind in formats)
        signing_key = os.environ.get("PRTHAK_RELEASE_SIGNING_KEY_FILE")
        if signing_key:
            subprocess.run([sys.executable, str(ROOT / "scripts/sign-release.py"), "--key-file", signing_key, *map(str, produced)], check=True)
        else:
            print("UNSIGNED native packages: do not distribute for production until separately signed and verified.")
        for path in produced:
            print("Created inert payload: " + str(path))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, OSError, tarfile.TarError, subprocess.CalledProcessError) as error:
        raise SystemExit("Native packaging refused: " + str(error)) from None
