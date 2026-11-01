"""Real offline release signing/verification through the public CLI scripts."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent


class ReleaseSigningTests(unittest.TestCase):
    def run_script(self, name, *args):
        return subprocess.run([sys.executable, str(ROOT / "scripts" / name), *map(str, args)], cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=15)

    def test_exact_archive_and_independently_pinned_key_verify_before_extraction(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            archive = root / "synthetic-release.tar.gz"
            archive.write_bytes(b"private disposable archive bytes")
            signed = self.run_script("sign-release.py", "--key-file", root / "release.seed", "--create-key", archive)
            self.assertEqual(signed.returncode, 0, signed.stdout)
            signature = root / (archive.name + ".signature.json")
            trust = root / (archive.name + ".public-trust.json")
            verified = self.run_script("verify-release.py", "--public-trust-file", trust, "--signature", signature, archive)
            self.assertEqual(verified.returncode, 0, verified.stdout)
            self.assertEqual((root / "release.seed").stat().st_mode & 0o777, 0o600)
            self.assertNotIn((root / "release.seed").read_bytes().hex(), signature.read_text())
            archive.write_bytes(archive.read_bytes() + b"modified")
            rejected = self.run_script("verify-release.py", "--public-trust-file", trust, "--signature", signature, archive)
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("do not extract or install", rejected.stdout)

    def test_unpinned_signer_and_writable_public_trust_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            archive = root / "release.tar.gz"
            archive.write_bytes(b"synthetic")
            self.assertEqual(self.run_script("sign-release.py", "--key-file", root / "release.seed", "--create-key", archive).returncode, 0)
            signature = root / (archive.name + ".signature.json")
            trust = root / (archive.name + ".public-trust.json")
            original = trust.read_text()
            trust.write_text(json.dumps({"keys": {}}))
            self.assertNotEqual(self.run_script("verify-release.py", "--public-trust-file", trust, "--signature", signature, archive).returncode, 0)
            trust.write_text(original)
            trust.chmod(0o666)
            self.assertNotEqual(self.run_script("verify-release.py", "--public-trust-file", trust, "--signature", signature, archive).returncode, 0)
