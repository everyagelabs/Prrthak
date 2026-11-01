"""Actual disposable Git repositories; no credentials or remote operations."""
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('release_provenance_review', Path(__file__).resolve().parents[2] / 'scripts/release_provenance.py')
provenance_module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(provenance_module)


class ReleaseProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='prthak-provenance-')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.actual, self.foreign = (self.base / name for name in ('actual', 'foreign'))
        for root in (self.actual, self.foreign):
            root.mkdir(); (root / 'runtime.py').write_text(root.name + '\n')
            self.git(root, '-c', 'init.templateDir=', 'init', '-q')
            self.git(root, 'add', 'runtime.py')
            self.git(root, '-c', 'user.name=Isolated fixture', '-c', 'user.email=fixture@localhost', '-c', 'commit.gpgsign=false', '-c', 'core.hooksPath=/dev/null', 'commit', '-qm', 'fixture')

    def git(self, root, *arguments):
        env = {key: value for key, value in os.environ.items() if not key.startswith('GIT_')}
        return subprocess.run(['git', *arguments], cwd=root, env=env, check=True, capture_output=True, text=True).stdout.strip()

    def test_foreign_repository_environment_cannot_change_actual_clean_source_identity(self):
        expected = self.git(self.actual, 'rev-parse', 'HEAD')
        foreign = self.git(self.foreign, 'rev-parse', 'HEAD')
        self.assertNotEqual(expected, foreign)
        self.git(self.actual, 'tag', 'v1.2.3-fixture')
        with patch.dict(os.environ, {'GIT_DIR': str(self.foreign / '.git'), 'GIT_WORK_TREE': str(self.foreign),
                                    'GIT_COMMON_DIR': str(self.foreign / '.git'), 'GIT_INDEX_FILE': str(self.foreign / '.git/index'),
                                    'GIT_OBJECT_DIRECTORY': str(self.foreign / '.git/objects'),
                                    'GIT_ALTERNATE_OBJECT_DIRECTORIES': str(self.foreign / '.git/objects'), 'GIT_NAMESPACE': 'foreign'}):
            value = provenance_module.provenance(self.actual)
        self.assertEqual(value['source_commit'], expected)
        self.assertEqual(value['source_base_commit'], expected)
        self.assertEqual(value['source_tag'], 'v1.2.3-fixture')
        self.assertFalse(value['source_dirty'])

    def test_nested_or_nonrepository_root_never_claims_parent_or_ambient_commit(self):
        nested = self.actual / 'not-the-checkout-root'; nested.mkdir()
        empty = self.base / 'not-a-repository'; empty.mkdir()
        with patch.dict(os.environ, {'GIT_DIR': str(self.foreign / '.git'), 'GIT_WORK_TREE': str(self.foreign)}):
            for root in (nested, empty):
                value = provenance_module.provenance(root)
                self.assertIsNone(value['source_commit']); self.assertIsNone(value['source_base_commit'])
                self.assertIsNone(value['source_tag']); self.assertTrue(value['source_dirty'])

    def test_dirty_real_checkout_retains_only_its_base_commit_and_no_release_tag_claim(self):
        expected = self.git(self.actual, 'rev-parse', 'HEAD')
        (self.actual / 'runtime.py').write_text('modified public bytes\n')
        value = provenance_module.provenance(self.actual)
        self.assertIsNone(value['source_commit']); self.assertIsNone(value['source_tag'])
        self.assertEqual(value['source_base_commit'], expected); self.assertTrue(value['source_dirty'])
