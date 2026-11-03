"""Automatic entrypoint delivery using disposable public tar fixtures only."""
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest


PROJECT=Path(__file__).resolve().parents[1]
SCRIPTS=('package-agent.py','prepare-managed-ipsets.py','verify-release.py',
         'install-agent.sh','install-agent-auto.sh','install-agent-linux.sh',
         'install-agent-rhel.sh','install-agent-ubuntu.sh')


class AgentPackageTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory(prefix='prthak-agent-package-')
        self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name)/'public-source';self.root.mkdir()
        for directory in ('docs','scripts','agent','agent/bin','agent/internal/agent','deploy/systemd'):
            (self.root/directory).mkdir(parents=True,exist_ok=True)
        for source in (PROJECT/'docs').glob('*.md'):
            shutil.copyfile(source,self.root/'docs'/source.name)
        for name in SCRIPTS:
            shutil.copyfile(PROJECT/'scripts'/name,self.root/'scripts'/name)
        shutil.copyfile(PROJECT/'agent/config.example.json',self.root/'agent/config.example.json')
        shutil.copyfile(PROJECT/'agent/README.md',self.root/'agent/README.md')
        shutil.copyfile(PROJECT/'deploy/systemd/seg-agent.service',self.root/'deploy/systemd/seg-agent.service')
        (self.root/'agent/internal/agent/types.go').write_text('package agent\nconst Version = "0.17.0"\n')
        for arch in ('amd64','arm64'):
            (self.root/'agent/bin'/('seg-agent-linux-'+arch)).write_bytes(b'public-'+arch.encode())
        # Source execute bits must not decide whether the published installer works.
        (self.root/'scripts/install-agent-auto.sh').chmod(0o600)
        self.environment=dict(os.environ)
        self.environment.pop('PRTHAK_RELEASE_SIGNING_KEY_FILE',None)

    def run_package(self):
        return subprocess.run([sys.executable,str(self.root/'scripts/package-agent.py')],
                              cwd=self.root,env=self.environment,capture_output=True,text=True,timeout=20)

    def test_both_cpu_archives_deliver_automatic_entrypoint_and_compatibility_without_private_state(self):
        sentinel=b'private-fixture-do-not-include'
        (self.root/'.env').write_bytes(sentinel)
        (self.root/'scripts/unreviewed-installer.sh').write_bytes(sentinel)
        result=self.run_package()
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        for arch in ('amd64','arm64'):
            stem='prthak-agent-0.17.0-linux-'+arch
            archive=self.root/'dist'/(stem+'.tar.gz')
            with tarfile.open(archive) as incoming:
                entries={member.name[len(stem)+1:]:(member,incoming.extractfile(member).read())
                         for member in incoming.getmembers()}
            for name in ('install-agent-auto.sh','install-agent-linux.sh',
                         'install-agent-rhel.sh','install-agent-ubuntu.sh'):
                member,raw=entries['scripts/'+name]
                self.assertEqual(member.mode,0o755)
                self.assertEqual(member.uid,0);self.assertEqual(member.gid,0)
                self.assertEqual(raw,(self.root/'scripts'/name).read_bytes())
            guide=entries['INSTALL.txt'][1].decode()
            self.assertIn('sudo ./scripts/install-agent-auto.sh --setup-file /root/prthak-agent-setup.json',guide)
            self.assertIn('detects RHEL8/9 or Ubuntu26.04',guide)
            self.assertTrue(guide.rstrip().endswith('Created by Pratik Srivastava'))
            self.assertFalse(any(sentinel in raw for member,raw in entries.values()))
            self.assertNotIn('scripts/unreviewed-installer.sh',entries)
            self.assertNotIn('.env',entries)
            digest=hashlib.sha256(archive.read_bytes()).hexdigest()
            self.assertIn(digest+'  '+archive.name,(self.root/'dist/SHA256SUMS').read_text())

    def test_missing_or_linked_automatic_entrypoint_cannot_produce_a_complete_release(self):
        entry=self.root/'scripts/install-agent-auto.sh'
        entry.unlink()
        missing=self.run_package()
        self.assertNotEqual(missing.returncode,0)
        foreign=self.root/'private-input';foreign.write_text('unrelated bytes')
        entry.symlink_to(foreign)
        linked=self.run_package()
        self.assertNotEqual(linked.returncode,0)
        self.assertIn('Package only reviewed regular public files',linked.stderr)


if __name__=='__main__':unittest.main()
