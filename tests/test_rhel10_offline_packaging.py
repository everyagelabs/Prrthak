"""Release-specific offline payload checks without Docker or real signing."""
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("rhel_offline_packager", ROOT / "scripts/package-offline-controller.py")
packager = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(packager)


class OfflineTargetPackagingTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="prthak-offline-target-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.payload = self.root / "payload"
        for name in packager.REQUIRED:
            target = self.payload / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(b"fixture")

    def target(self, major):
        identity = {"id": "rhel", "version_id": major, "architecture": "x86_64"}
        (self.payload / "target.json").write_text(json.dumps(identity))
        return identity

    def rpm(self, major, package="docker-ce"):
        (self.payload / "rpms" / f"{package}-1.0-1.el{major}.x86_64.rpm").write_bytes(b"fixture RPM")

    def test_legacy_rhel9_payload_stays_compatible_without_target_metadata(self):
        self.rpm("9")
        self.assertNotIn("target.json", packager.payload_files(self.payload))

    def test_rhel10_requires_matching_explicit_target_and_rhel10_rpms(self):
        self.rpm("10")
        with self.assertRaisesRegex(ValueError, "explicit offline target"):
            packager.payload_files(self.payload, "10")
        self.target("9")
        with self.assertRaisesRegex(ValueError, "does not match"):
            packager.payload_files(self.payload, "10")
        self.target("10")
        self.assertIn("target.json", packager.payload_files(self.payload, "10"))
        with self.assertRaisesRegex(ValueError, "does not match"):
            packager.payload_files(self.payload)
        self.rpm("9", "python3")
        with self.assertRaisesRegex(ValueError, "RHEL 10 dependency RPMs"):
            packager.payload_files(self.payload, "10")

    def test_rhel9_cannot_relabel_rhel10_rpms_even_without_target_metadata(self):
        self.rpm("10")
        with self.assertRaisesRegex(ValueError, "another RHEL release"):
            packager.payload_files(self.payload)

    def test_rhel10_target_metadata_is_bounded_and_malformed_values_are_rejected(self):
        self.rpm("10")
        for content in ("x" * 4097, "not JSON", '["rhel", "10"]',
                        '{"id":"rhel","version_id":"10","architecture":"aarch64"}'):
            with self.subTest(content=content[:50]):
                (self.payload / "target.json").write_text(content)
                with self.assertRaises(ValueError):
                    packager.payload_files(self.payload, "10")

    def test_rhel10_full_and_gui_archives_bind_target_filename_and_install_instructions(self):
        self.target("10")
        controller = self.root / "prthak-controller-1.0.0.tar.gz"
        with tarfile.open(controller, "w:gz") as bundle:
            member = tarfile.TarInfo("prthak-controller-1.0.0/INSTALL.txt")
            member.mode, member.size = 0o644, 7
            bundle.addfile(member, io.BytesIO(b"fixture"))

        def fake_sign(arguments, **kwargs):
            if arguments[1].endswith("sign-release.py"):
                candidate = Path(arguments[-1])
                Path(str(candidate) + ".signature.json").write_bytes(b"signature fixture")
                Path(str(candidate) + ".public-trust.json").write_bytes(b"trust fixture")
            return subprocess.CompletedProcess(arguments, 0)

        for gui in (False, True):
            with self.subTest(gui=gui):
                for package in (self.payload / "rpms").glob("*.rpm"):
                    package.unlink()
                self.rpm("10", "docker-compose-plugin" if gui else "docker-ce")
                with patch.object(packager, "verified_agents", return_value={}), \
                        patch.object(packager.subprocess, "run", side_effect=fake_sign):
                    archive = packager.pack(controller, self.payload, self.root / str(gui),
                                            "unused", gui_update_only=gui, rhel_major="10")
                self.assertEqual(archive.name, "prthak-controller-1.0.0-offline-rhel10-x86_64.tar.gz")
                with tarfile.open(archive) as bundle:
                    stem = "prthak-controller-1.0.0/"
                    identity = json.load(bundle.extractfile(stem + "offline/target.json"))
                    self.assertEqual(identity, self.target("10"))
                    self.assertIn(b"RHEL 10 x86_64", bundle.extractfile(stem + "INSTALL.txt").read())
                    self.assertIn(b"RHEL 10 x86_64", bundle.extractfile(stem + "OFFLINE-CONTROLLER").read())
                    self.assertEqual(stem + "OFFLINE-UPDATE-ONLY" in bundle.getnames(), gui)


class OfflineRPMBuilderTests(unittest.TestCase):
    def test_builder_uses_selected_ubi_and_repositories_and_never_relabels_rhel9_packages(self):
        with tempfile.TemporaryDirectory(prefix="prthak-builder-target-") as temporary:
            root = Path(temporary)
            fakebin = root / "bin"
            fakebin.mkdir()
            docker = fakebin / "docker"
            docker.write_text("#!" + sys.executable + "\n" + '''
import io, json, os, sys, tarfile
from pathlib import Path
body = sys.stdin.read()
with Path(os.environ["PRTHAK_TEST_CALLS"]).open("a") as log:
    log.write(json.dumps({"args": sys.argv[1:], "body": body}) + "\\n")
major = os.environ["PRTHAK_TEST_PACKAGE_MAJOR"]
files = {"repodata/repomd.xml": b"metadata"} if "createrepo_c" in body else {
    "keys/docker.asc": b"public fixture", "rpms/docker-ce-1.0-1.el" + major + ".x86_64.rpm": b"package"}
with tarfile.open(fileobj=sys.stdout.buffer, mode="w|") as bundle:
    for name, data in files.items():
        item = tarfile.TarInfo(name)
        item.size = len(data)
        bundle.addfile(item, io.BytesIO(data))
''')
            docker.chmod(0o755)
            for selected, package_major in (("9", "9"), ("10", "10"), ("10", "9")):
                with self.subTest(selected=selected, package_major=package_major):
                    calls = root / (selected + package_major + ".calls")
                    output = root / (selected + package_major)
                    args = ["bash", str(ROOT / "scripts/build-offline-controller-rpms.sh")]
                    if selected == "10":
                        args += ["--rhel-major", selected]
                    args.append(str(output))
                    env = {**os.environ, "PATH": str(fakebin) + os.pathsep + os.environ.get("PATH", ""),
                           "PRTHAK_TEST_CALLS": str(calls), "PRTHAK_TEST_PACKAGE_MAJOR": package_major}
                    result = subprocess.run(args, capture_output=True, text=True, env=env, timeout=10)
                    if selected != package_major:
                        self.assertNotEqual(result.returncode, 0)
                        self.assertFalse(output.exists())
                        continue
                    self.assertEqual(result.returncode, 0, result.stderr)
                    first = json.loads(calls.read_text().splitlines()[0])
                    self.assertTrue(any(f"/ubi{selected}/ubi@sha256:" in arg for arg in first["args"]))
                    self.assertEqual(first["args"][-3], selected)
                    self.assertIn('rhel/$rhel_major/x86_64/stable', first["body"])
                    self.assertEqual((output / "target.json").exists(), selected == "10")
                    if selected == "10":
                        self.assertEqual(first["args"][-2:],
                                         ["ubi-10-for-x86_64-baseos-rpms", "ubi-10-for-x86_64-appstream-rpms"])


if __name__ == "__main__":
    unittest.main()
