import base64
from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from controller import agent_release_downloads as releases


class AgentReleaseDownloadsTest(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        filename = "prthak-agent-0.18.0-linux-amd64.tar.gz"
        self.archive = root / filename
        self.signature = root / (filename + ".signature.json")
        self.trust = root / "public-trust.json"
        self.contents = b"agent release fixture"
        self.archive.write_bytes(self.contents)

        signer = Ed25519PrivateKey.generate()
        public = signer.public_key().public_bytes_raw()
        key_id = hashlib.sha256(public).hexdigest()[:32]
        encoded = lambda value: base64.b64encode(value).decode("ascii")
        self.trust.write_text(json.dumps({"keys": {key_id: encoded(public)}}))
        payload = json.dumps({"domain": releases.DOMAIN, "manifest": {
            "filename": filename, "bytes": len(self.contents),
            "sha256": hashlib.sha256(self.contents).hexdigest(),
        }}).encode()
        self.signature.write_text(json.dumps({
            "algorithm": "Ed25519", "key_id": key_id, "payload": encoded(payload),
            "signature": encoded(signer.sign(payload)),
        }))

        @contextmanager
        def local_fixture(path, maximum):
            with path.open("rb") as source:
                yield source, path.stat().st_size

        # Production only admits the root-owned mount. The CI fixture runs as
        # its test user and exercises the signed file/stream contract.
        patches = patch.multiple(releases, RELEASE_DIR=root, PUBLIC_TRUST=self.trust, _protected_file=local_fixture)
        patches.start()
        self.addCleanup(patches.stop)

    def test_signed_exact_archive_and_signature_stream(self):
        self.assertEqual(releases.available(), {"amd64": "0.18.0"})
        for asset, path in (("archive", self.archive), ("signature", self.signature)):
            with releases.open_download("amd64", asset) as (filename, size, source):
                self.assertEqual(filename, path.name)
                self.assertEqual(size, path.stat().st_size)
                self.assertEqual(source.read(), path.read_bytes())
        for architecture, asset in (("arm64", "archive"), ("../amd64", "archive"), ("amd64", "../../trust")):
            with self.assertRaises(FileNotFoundError), releases.open_download(architecture, asset):
                self.fail("A foreign download must never open a stream")

    def test_same_size_archive_tampering_is_rejected_before_streaming(self):
        self.archive.write_bytes(b"x" * len(self.contents))
        with self.assertRaises(FileNotFoundError), releases.open_download("amd64", "archive"):
            self.fail("Changed archive bytes must never open a stream")

    def test_untrusted_signature_is_not_advertised(self):
        self.trust.write_text('{"keys":{}}')
        self.assertEqual(releases.available(), {})
        with self.assertRaises(FileNotFoundError), releases.open_download("amd64", "signature"):
            self.fail("Untrusted signature must never open a stream")
