"""Fixtures for signed archive handling and offline upgrade compensation."""
import copy
import io
import json
import os
from pathlib import Path
import stat
import tarfile
import tempfile
import time
import unittest
from unittest.mock import patch

from tests.test_appliance_installer import appliance

updater = appliance.offline_update_module()


class ArchiveTests(unittest.TestCase):
    def test_rhel10_update_requires_its_own_signed_target_metadata(self):
        stem = 'prthak-controller-0.19.0'
        required = ('OFFLINE-CONTROLLER', 'offline/rpms/repodata/repomd.xml',
                    'offline/rpms/docker-compose-plugin-1.el10.x86_64.rpm', 'offline/keys/docker.asc',
                    'deploy/appliance/node_manager.py', 'deploy/appliance/offline_update.py',
                    *(f'agent-releases/prthak-agent-0.19.0-linux-{arch}.tar.gz{suffix}'
                      for arch in ('amd64', 'arm64') for suffix in ('', '.signature.json')))
        matching = {'id': 'rhel', 'version_id': '10', 'architecture': 'x86_64'}
        with tempfile.TemporaryDirectory() as temporary:
            for index, target in enumerate((None, {**matching, 'version_id': '9'}, matching)):
                staging = Path(temporary)/str(index)
                staging.mkdir()
                archive = staging/'update.tar.gz'
                files = {name: b'fixture' for name in required}
                if target is not None:
                    files['offline/target.json'] = json.dumps(target).encode()
                with tarfile.open(archive, 'w:gz') as output:
                    for name, data in files.items():
                        entry = tarfile.TarInfo(stem+'/'+name)
                        entry.mode, entry.size = 0o644, len(data)
                        output.addfile(entry, io.BytesIO(data))
                if target == matching:
                    result = updater._extract(archive, staging, stem, appliance, rhel_major='10')
                    self.assertEqual(json.loads((result/'offline/target.json').read_text()), matching)
                else:
                    with self.assertRaises(appliance.Blocked):
                        updater._extract(archive, staging, stem, appliance, rhel_major='10')

    def test_host_refuses_cross_major_update_before_signature_or_staging(self):
        with tempfile.TemporaryDirectory() as temporary:
            manager = unittest.mock.Mock(root=Path(temporary))
            request = {'action': 'controller-update-review', 'request_id': 'c'*32, 'upload_id': 'd'*32,
                       'name': 'prthak-controller-0.19.0-offline-rhel9-x86_64.tar.gz', 'size': 10, 'signature': {}}
            with patch.object(updater, '_idle'), patch.object(updater, 'host_rhel_major', return_value='10'), \
                    patch.object(updater, '_signature') as signature:
                with self.assertRaisesRegex(appliance.Blocked, 'RHEL major version'):
                    updater.review(manager, request, appliance)
                signature.assert_not_called()
            self.assertFalse(updater.directory(manager.root).exists())

    def test_host_major_accepts_literal_rhel10_and_refuses_unknown_or_ambiguous_identity(self):
        for raw, expected in (('ID=rhel\nVERSION_ID="10.1"\n', '10'),
                              ('ID=rhel\nVERSION_ID=9.8\n', '9'),
                              ('ID=rhel\nVERSION_ID=11\n', None),
                              ('ID=rocky\nVERSION_ID=10\n', None),
                              ('ID=rhel\nID=ubuntu\nVERSION_ID=10\n', None)):
            with self.subTest(raw=raw), patch.object(Path, 'read_text', return_value=raw):
                self.assertEqual(updater.host_rhel_major(), expected)

    def test_regular_archive_accepts_the_offline_layout_and_rejects_links_and_traversal(self):
        stem = 'prthak-controller-0.19.0'
        required = (
            'OFFLINE-CONTROLLER', 'offline/rpms/repodata/repomd.xml',
            'offline/rpms/compat+vendor~next.rpm', 'offline/keys/vendor.gpg',
            'deploy/appliance/node_manager.py', 'deploy/appliance/offline_update.py',
            'agent-releases/prthak-agent-0.19.0-linux-amd64.tar.gz',
            'agent-releases/prthak-agent-0.19.0-linux-amd64.tar.gz.signature.json',
            'agent-releases/prthak-agent-0.19.0-linux-arm64.tar.gz',
            'agent-releases/prthak-agent-0.19.0-linux-arm64.tar.gz.signature.json',
        )
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            for index, (name, kind) in enumerate([
                ('ordinary', None), (stem + '/bad-link', tarfile.SYMTYPE),
                (stem + '/../../outside', tarfile.REGTYPE), (stem + '/OFFLINE-CONTROLLER', tarfile.REGTYPE),
            ]):
                with self.subTest(name=name):
                    staging = directory / str(index)
                    staging.mkdir()
                    archive = staging / 'upload.tar.gz'
                    with tarfile.open(archive, 'w:gz') as output:
                        for relative in required:
                            entry = tarfile.TarInfo(stem + '/' + relative)
                            entry.mode = 0o644
                            entry.size = 7
                            output.addfile(entry, io.BytesIO(b'fixture'))
                        if kind is not None:
                            entry = tarfile.TarInfo(name)
                            entry.type = kind
                            entry.linkname = '/etc/passwd'
                            output.addfile(entry)
                    if kind is None:
                        release = updater._extract(archive, staging, stem, appliance)
                        self.assertEqual((release / required[2]).read_bytes(), b'fixture')
                    else:
                        with self.assertRaises(appliance.Blocked):
                            updater._extract(archive, staging, stem, appliance)
            self.assertFalse((directory / 'outside').exists())

    def test_verify_candidate_refuses_same_or_older_version(self):
        class Manager:
            installed = {'images': {'controller': 'sha256:' + '1' * 64}}
            engine = unittest.mock.Mock()

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            host = root / 'deploy/appliance'
            host.mkdir(parents=True)
            for filename in ('node_manager.py', 'offline_update.py'):
                (host / filename).write_text('candidate')
            with patch.object(appliance, 'offline_appliance_images', return_value={'controller': 'sha256:' + '2' * 64}), \
                    patch.object(updater, '_image_python'), \
                    patch.object(updater, '_version', side_effect=['0.19.1', '0.19.0']):
                with self.assertRaisesRegex(appliance.Blocked, 'newer'):
                    updater._verify_candidate(Manager(), root, '0.19.0', appliance)


class UpdateFenceTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.journal = updater.directory(self.root) / 'active.json'
        self.fence = self.root / 'runtime/controller-update-fence'
        self.marker = self.fence / 'pending'
        self.record = {'job_id': 'a' * 32, 'phase': 'applying'}
        self.fence.parent.mkdir()
        appliance.atomic(self.journal, self.record)
        self.use_patch(appliance, 'safe_path', lambda _: self.root)
        self.use_patch(appliance, 'protected_release_directory', lambda _: None)
        self.use_patch(Path, 'lstat', self.as_root(Path.lstat))
        self.use_patch(os, 'fstat', self.as_root(os.fstat))

    def use_patch(self, target, name, value):
        replacement = patch.object(target, name, value)
        replacement.start()
        self.addCleanup(replacement.stop)

    @staticmethod
    def as_root(operation):
        def stat_as_root(*args, **kwargs):
            fields = list(operation(*args, **kwargs))
            fields[4] = 0
            return os.stat_result(fields)
        return stat_as_root

    def test_new_fence_is_traversable_even_with_service_umask(self):
        previous = os.umask(0o077)
        try:
            updater._install_fence(self.root, self.record, appliance)
        finally:
            os.umask(previous)
        self.assertEqual(stat.S_IMODE(self.fence.stat().st_mode), 0o755)
        self.assertEqual(self.marker.read_text(), self.record['job_id'])

    def test_candidate_repairs_only_the_exact_legacy_fence(self):
        self.fence.mkdir(mode=0o700)
        appliance.atomic(self.marker, 'b' * 32, 0o644)
        with self.assertRaisesRegex(appliance.Blocked, 'does not match'):
            updater.repair_fence(self.root, self.record, appliance)
        self.assertEqual(stat.S_IMODE(self.fence.stat().st_mode), 0o700)
        appliance.atomic(self.marker, self.record['job_id'], 0o644)
        with self.assertRaisesRegex(appliance.Blocked, 'journal is unsafe'):
            updater.repair_fence(self.root, {**self.record, 'phase': 'publishing'}, appliance)
        self.assertEqual(stat.S_IMODE(self.fence.stat().st_mode), 0o700)
        updater.repair_fence(self.root, self.record, appliance)
        self.assertEqual(stat.S_IMODE(self.fence.stat().st_mode), 0o755)
        self.assertEqual(self.marker.read_text(), self.record['job_id'])


class UpdateTransactionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.code = self.root / 'host-code'
        self.units = self.root / 'host-units'
        self.identifier = '2' * 32
        self.job = '1' * 32
        self.base = updater.directory(self.root)
        self.journal = self.base / 'active.json'
        self.backup = self.base / ('backup-' + self.identifier)
        self.staged = self.base / ('review-' + self.identifier)
        self.release = self.staged / 'prthak-controller-0.19.1'
        self.data = self.root / 'controller'
        self.agents = self.root / 'runtime/agent-releases'
        for folder in (self.code, self.units, self.release / 'deploy/appliance', self.data,
                       self.agents, self.root / 'config', self.root / 'manager/jobs'):
            folder.mkdir(parents=True, exist_ok=True)
        for filename in ('node_manager.py', 'offline_update.py'):
            (self.code / filename).write_text('old host')
            (self.release / 'deploy/appliance' / filename).write_text('new host')
        (self.units / updater.MANAGER_UNIT).write_text('old unit')
        (self.data / 'database.sqlite').write_text('old data')
        (self.agents / 'release').write_text('old agent')
        self.installed = {
            'appliance_id': 'fixture',
            'bind_ip': '192.0.2.10',
            'images': {name: 'sha256:' + '1' * 64 for name in appliance.SERVICES},
        }
        self.images = {name: 'sha256:' + '2' * 64 for name in appliance.SERVICES}
        self.compose = {'services': {name: {'image': image, 'restart': 'unless-stopped',
                                           'ports': ['192.0.2.10:8787:8787'], 'volumes': []}
                                    for name, image in self.installed['images'].items()}}
        appliance.atomic(self.root / 'config/installed.json', self.installed)
        appliance.atomic(self.root / 'runtime/compose.json', self.compose)
        appliance.atomic(self.root / 'manager/jobs' / self.job, {'id': self.job, 'status': 'running'})
        self.record = {'phase': 'queued', 'job_id': self.job, 'review_id': self.identifier, 'version': '0.19.1',
                       'images': self.images, 'base': appliance.digest(self.installed), 'revision': 0,
                       'expires_at': time.time() + 600}
        appliance.atomic(self.journal, self.record)
        self.manager = unittest.mock.Mock()
        self.manager.root = self.root
        self.manager.installed = copy.deepcopy(self.installed)
        self.manager.state.return_value = {'revision': 0}
        self.manager.engine.states.return_value = {}
        self.manager._controller_configuration_material.return_value = {}
        self._original_manager = appliance.Manager
        self.manager._tree.side_effect = lambda path: self._original_manager._tree(self.manager, path)
        self.probes = []
        self.starts = []
        self.service_calls = []
        self.manager.engine.compose.side_effect = self.record_service_call
        self.use_patch(updater, 'HOST_CODE', self.code)
        self.use_patch(updater, 'UNITS', self.units)
        self.use_patch(updater, '_idle', lambda *_: None)
        self.use_patch(updater, '_fixed_run', lambda command: self.service_calls.append(command))
        self.use_patch(updater, '_start_manager', lambda *_: None)
        self.use_patch(updater, '_wait_manager', lambda *_: None)
        self.use_patch(updater, '_install_fence', self.install_fence)
        self.use_patch(updater, '_release_fence', self.release_fence)
        self.use_patch(updater, '_wait_health', self.record_probe)
        self.use_patch(updater, '_system_snapshot', self.snapshot)
        self.use_patch(appliance, 'Manager', lambda *_, **__: self.manager)
        self.use_patch(appliance, 'safe_path', lambda _: self.root)
        self.use_patch(appliance, 'acquire_lease', lambda: os.open(self.journal, os.O_RDONLY))
        self.use_patch(appliance, 'stage_agent_releases', self.stage_agents)
        self.use_patch(appliance, 'write_manager_unit', lambda *_: (self.units / updater.MANAGER_UNIT).write_text('new unit'))

    def use_patch(self, target, name, value):
        replacement = patch.object(target, name, value)
        replacement.start()
        self.addCleanup(replacement.stop)

    def record_service_call(self, arguments, **_):
        if arguments[0] == 'up':
            controller = appliance.load(self.root / 'runtime/compose.json')['services']['controller']
            self.starts.append((controller['image'], controller['restart'], controller['ports']))

    def record_probe(self, manager, material, host, *, fenced=False):
        self.probes.append((manager.installed['bind_ip'], fenced))
        self.assertEqual(self.fence.exists(), fenced)

    @property
    def fence(self):
        return self.root / 'runtime/controller-update-fence/pending'

    def install_fence(self, root, record, host):
        self.fence.parent.mkdir()
        self.fence.write_text(record['job_id'])

    def release_fence(self, root, record, host):
        self.fence.unlink(missing_ok=True)

    def snapshot(self, manager, backup, host):
        backup.mkdir(exist_ok=True)
        for filename in ('node_manager.py', 'offline_update.py'):
            appliance.atomic(backup / filename, (self.code / filename).read_bytes())
        appliance.atomic(backup / 'manager.service', (self.units / updater.MANAGER_UNIT).read_bytes())
        appliance.atomic(backup / 'installed.json', self.installed)
        appliance.atomic(backup / 'compose.json', self.compose)

    def stage_agents(self, release, root):
        self.agents.mkdir()
        (self.agents / 'release').write_text('new agent')

    def test_fences_candidate_until_verified_then_restores_restart_and_retains_backup(self):
        updater.run(self.root, appliance)
        self.assertEqual(self.starts, [
            (self.images['controller'], 'no', ['127.0.0.1:8787:8787']),
            (self.images['controller'], 'no', ['192.0.2.10:8787:8787']),
            (self.images['controller'], 'unless-stopped', ['192.0.2.10:8787:8787']),
        ])
        self.assertEqual(self.probes, [('192.0.2.10', False), ('127.0.0.1', True),
                                       ('192.0.2.10', True), ('192.0.2.10', True)])
        self.assertFalse(self.fence.exists())
        self.assertEqual((self.backup / 'controller/database.sqlite').read_text(), 'old data')
        self.assertEqual((self.agents / 'release').read_text(), 'new agent')
        self.assertEqual(appliance.load(self.journal)['phase'], 'committed')
        receipt = appliance.load(self.root / 'manager/jobs' / self.job)
        self.assertTrue(receipt['result']['verified'])
        appliance.atomic(self.root / 'manager/jobs' / self.job, {'id': self.job, 'status': 'running'})
        updater.run(self.root, appliance)
        self.assertTrue(appliance.load(self.root / 'manager/jobs' / self.job)['result']['verified'])

    def test_failed_candidate_restores_original_files_and_keeps_failed_candidate_data(self):
        def failed_candidate(manager, material, host, **_):
            if manager.installed['bind_ip'] == '127.0.0.1':
                (self.data / 'database.sqlite').write_text('candidate data')
                raise appliance.Blocked('candidate not ready')

        with patch.object(updater, '_wait_health', failed_candidate):
            updater.run(self.root, appliance)
        self.assertEqual((self.data / 'database.sqlite').read_text(), 'old data')
        self.assertEqual((self.backup / 'failed-controller/database.sqlite').read_text(), 'candidate data')
        self.assertEqual((self.code / 'node_manager.py').read_text(), 'old host')
        self.assertEqual((self.agents / 'release').read_text(), 'old agent')
        self.assertEqual(appliance.load(self.root / 'config/installed.json'), self.installed)
        self.assertEqual(appliance.load(self.journal)['phase'], 'rolled_back')
        receipt = appliance.load(self.root / 'manager/jobs' / self.job)
        self.assertTrue(receipt['result']['rolled_back'])
        self.assertEqual(receipt['result']['failure_stage'], 'candidate_health')
        self.assertNotIn('candidate not ready', json.dumps(receipt))

    def test_failed_recovery_reports_both_fixed_steps(self):
        failed = False

        def failed_health(manager, material, host, *, fenced=False):
            nonlocal failed
            if fenced or failed:
                failed = True
                raise appliance.Blocked('sensitive output from the failed health probe')

        with patch.object(updater, '_wait_health', failed_health):
            with self.assertRaises(appliance.Blocked):
                updater.run(self.root, appliance)
        receipt = appliance.load(self.root / 'manager/jobs' / self.job)
        self.assertEqual(receipt['result']['phase'], 'rollback_failed')
        self.assertEqual(receipt['result']['failure_stage'], 'candidate_health')
        self.assertEqual(receipt['result']['recovery_stage'], 'verify_previous')
        self.assertFalse(receipt['result']['verified'])
        self.assertFalse(receipt['result']['rolled_back'])
        self.assertNotIn('sensitive output', json.dumps(receipt))

    def test_boot_compensates_interrupted_stop_apply_and_publish(self):
        for phase in ('stopping', 'applying', 'publishing'):
            with self.subTest(phase=phase):
                self.snapshot(self.manager, self.backup, appliance)
                if phase != 'stopping':
                    os.replace(self.data, self.backup / 'controller')
                    self.data.mkdir()
                    (self.data / 'database.sqlite').write_text('interrupted data')
                appliance.atomic(self.journal, {**self.record, 'phase': phase})
                updater.run(self.root, appliance)
                self.assertEqual((self.data / 'database.sqlite').read_text(), 'old data')
                self.assertEqual(appliance.load(self.journal)['phase'], 'rolled_back')
                receipt = appliance.load(self.root / 'manager/jobs' / self.job)
                self.assertEqual(receipt['result']['failure_stage'], 'interrupted')
                failed = self.backup / 'failed-controller'
                if failed.exists():
                    (failed / 'database.sqlite').unlink()
                    failed.rmdir()
