"""Allowlisted controller distribution; isolated files, no Docker/host installation."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

PROJECT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('prthak_controller_package', PROJECT/'scripts/package-controller.py')
package = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(package)


class ControllerPackageTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory(prefix='prthak-controller-package-')
        self.addCleanup(temporary.cleanup)
        self.base=Path(temporary.name)
        self.source=self.base/'source'
        self.output=self.base/'output'
        for name in package.FIXED_FILES:
            destination=self.source/name;destination.parent.mkdir(parents=True,exist_ok=True)
            if name in package.SIMPLE_GUIDE_FILES or name=='docs/guide/README.md':
                destination.write_bytes(('public guide fixture '+name+'\n').encode())
            elif name=='docs/controller-vm-requirements.md':
                destination.write_text('# Private fixture sizing document\n')
            else:
                shutil.copy2(PROJECT/name,destination)
        self.put('controller/__init__.py','__version__ = "0.6.0"\n')
        self.put('controller/__main__.py','"""public runtime entrypoint fixture"""\n')
        self.put('controller/app.py','"""public application fixture"""\n')
        self.put('dashboard/app.js','// public runtime fixture\n')
        self.put('dashboard/styles.css','@font-face{font-family:fixture;src:url(/assets/fonts/example.woff2)}\n')
        self.put('dashboard/unreferenced-runtime-helper.js','const generatedImage="/assets/generated/extra.svg";\n')
        self.put('dashboard/assets/fonts/example.woff2',b'public-font-fixture')
        self.put('dashboard/assets/generated/extra.svg','<svg xmlns="http://www.w3.org/2000/svg"/>')
        self.put('dashboard/assets/README.md','public asset documentation excluded from runtime')
        self.put('docs/public-runbook.md','# Public operational runbook\n')
        self.put('docs/private-not-shipped.html','excluded rendered guide\n')
        self.put('docs/private-not-shipped.pdf',b'excluded generated PDF')
        self.put('docs/nested/not-in-top-level-allowlist.md','excluded nested development documentation\n')
        self.put('docs/guide/prthak-pilot-0.14.0.pdf', b'public illustrated fixture')
        self.put('docs/guide/prthak-pilot-0.14.0.html', 'public current guide fixture')
        self.signing=patch.dict(os.environ,{},clear=False)
        self.signing.start();self.addCleanup(self.signing.stop)
        os.environ.pop('PRTHAK_RELEASE_SIGNING_KEY_FILE',None)

    def put(self,name,value):
        path=self.source/name;path.parent.mkdir(parents=True,exist_ok=True)
        path.write_bytes(value if isinstance(value,bytes) else value.encode())
        return path

    def build(self,**kwargs):
        return package.build(self.source,self.output,**kwargs)

    def members(self,archive):
        with tarfile.open(archive) as bundle:
            return {str(Path(*Path(item.name).parts[1:])):(item,bundle.extractfile(item).read()) for item in bundle.getmembers()}

    def test_archive_contains_required_runtime_and_indirect_assets_without_private_inputs(self):
        sentinel=b'private-material-must-never-enter-the-archive'
        for name in ['.env','.local/ca.key','state/inventory.sqlite3','controller/tests/private.pem',
                     'controller/tests.py','controller/conftest.py','controller/test_helpers.py',
                     'controller/identity.key','dashboard/tests/client.key','dashboard/.env','deploy/appliance/private.env']:
            self.put(name,sentinel)
        result=self.build()
        contents=self.members(result['archive'])
        for name in package.FIXED_FILES:
            self.assertIn(name,contents)
        for name in ['dashboard/assets/fonts/example.woff2','dashboard/assets/generated/extra.svg','dashboard/unreferenced-runtime-helper.js']:
            self.assertIn(name,contents)
        for name,(member,data) in contents.items():
            self.assertTrue(member.isfile());self.assertFalse(member.issym());self.assertFalse(member.islnk())
            self.assertNotIn('..',Path(member.name).parts);self.assertFalse(member.name.startswith('/'))
            self.assertNotIn(sentinel,data);self.assertNotIn('/tests/',name)
            self.assertEqual(member.uid,0);self.assertEqual(member.gid,0)
            self.assertEqual(member.mode,0o755 if name in package.EXECUTABLES else 0o644)
        self.assertNotIn('scripts/sign-release.py',contents)
        self.assertNotIn('dashboard/assets/README.md',contents)
        self.assertIn('docs/public-runbook.md',contents)
        self.assertIn('agent/README.md',contents)
        self.assertNotIn('docs/private-not-shipped.html',contents)
        self.assertNotIn('docs/private-not-shipped.pdf',contents)
        self.assertNotIn('docs/nested/not-in-top-level-allowlist.md',contents)
        self.assertIn('docs/guide/prthak-pilot-0.14.0.pdf', contents)
        self.assertIn('docs/guide/prthak-pilot-0.14.0.html', contents)
        manifest=json.loads(contents['MANIFEST.json'][1])
        for name,item in manifest['files'].items():
            self.assertEqual(hashlib.sha256(contents[name][1]).hexdigest(),item['sha256'])
        self.assertEqual(result['sha256'],hashlib.sha256(Path(result['archive']).read_bytes()).hexdigest())
        self.assertFalse(result['signed'])

    def test_dry_run_cli_validates_without_creating_output_and_reports_no_contents(self):
        result=subprocess.run([sys.executable,str(PROJECT/'scripts/package-controller.py'),
                               '--source-root',str(self.source),'--output-dir',str(self.output),'--dry-run'],capture_output=True,text=True,timeout=15)
        self.assertEqual(result.returncode,0,result.stderr)
        manifest=json.loads(result.stdout)
        self.assertTrue(manifest['dry_run']);self.assertFalse(self.output.exists())
        self.assertEqual(manifest['archive'],'prthak-controller-0.6.0.tar.gz')
        self.assertIn('deploy/appliance/node_manager.py',manifest['manifest']['files'])

    def test_automatic_installer_and_prerequisite_helper_ship_as_signed_public_inputs(self):
        result=self.build()
        contents=self.members(result['archive'])
        manifest=json.loads(contents['MANIFEST.json'][1])
        for name in ('scripts/install-controller.sh','scripts/install-prerequisites.sh',
                     'deploy/appliance/install_prerequisites.py'):
            member,raw=contents[name]
            self.assertEqual(member.mode,0o755 if name.startswith('scripts/') else 0o644)
            self.assertEqual(raw,(self.source/name).read_bytes())
            self.assertEqual(manifest['files'][name]['sha256'],hashlib.sha256(raw).hexdigest())
        guide=contents['INSTALL.txt'][1].decode()
        self.assertIn('sudo ./scripts/install-controller.sh\n',guide)
        self.assertIn('detects RHEL or Ubuntu',guide)
        self.assertIn('No token-file retrieval or manual .env editing',guide)
        self.assertTrue(guide.rstrip().endswith('Created by Pratik Srivastava'))

    def test_current_simple_guides_use_exact_public_file_allowlist(self):
        excluded=('docs/guide/private-capture.jpg','docs/guide/simple/private.env',
                  'docs/guide/simple/unreviewed.html','docs/guide/simple/arbitrary.json',
                  'docs/guide/simple/images/unreviewed.png',
                  'docs/guide/simple/images/private/architecture.svg',
                  'docs/guide/simple/nested/controller-installation.pdf')
        for name in excluded:
            self.put(name,b'private guide material must not be published')
        contents=self.members(self.build()['archive'])
        manifest=json.loads(contents['MANIFEST.json'][1])
        expected={'docs/guide/README.md',*package.SIMPLE_GUIDE_FILES}
        self.assertTrue({'docs/guide/simple/controller-installation.html',
                         'docs/guide/simple/agent-installation.pdf',
                         'docs/guide/simple/installation-commands.json',
                         'docs/guide/simple/verification.json',
                         'docs/guide/simple/images/architecture.svg'}<=expected)
        for name in expected:
            member,raw=contents[name]
            self.assertEqual(member.mode,0o644)
            self.assertEqual(raw,(self.source/name).read_bytes())
            self.assertEqual(manifest['files'][name]['sha256'],hashlib.sha256(raw).hexdigest())
        self.assertTrue(set(excluded).isdisjoint(contents))
        self.assertTrue(set(excluded).isdisjoint(manifest['files']))

    def test_missing_current_guide_prevents_partial_distribution(self):
        (self.source/'docs/guide/simple/controller-installation.pdf').unlink()
        with self.assertRaises(OSError):
            self.build()
        self.assertFalse(self.output.exists())

    def test_selected_leaf_and_ancestor_symlinks_never_read_external_material(self):
        external=self.base/'external-secret';external.write_text('external source material')
        for name in ['controller/app.py','deploy/appliance/rotation_helper.py','dashboard/assets/fonts/example.woff2',
                     'scripts/install-controller.sh','scripts/install-prerequisites.sh',
                     'deploy/appliance/install_prerequisites.py','docs/guide/README.md',
                     'docs/guide/simple/agent-installation.html',
                     'docs/guide/simple/verification.json',
                     'docs/guide/simple/images/architecture.svg']:
            with self.subTest(path=name):
                path=self.source/name;original=path.read_bytes();path.unlink();path.symlink_to(external)
                with self.assertRaises((OSError,package.PackageError)):
                    self.build()
                self.assertFalse(any(self.output.glob('*.tar.gz')))
                path.unlink();path.write_bytes(original)
        directory=self.source/'docs/guide/simple/images'
        directory.rename(directory.with_name('saved-images'))
        directory.symlink_to(directory.with_name('saved-images'),target_is_directory=True)
        with self.assertRaises((OSError,package.PackageError)):
            self.build()
        directory.unlink();directory.with_name('saved-images').rename(directory)
        directory=self.source/'deploy/cluster';directory.rename(directory.with_name('saved-cluster'))
        directory.symlink_to(directory.with_name('saved-cluster'),target_is_directory=True)
        with self.assertRaises((OSError,package.PackageError)):
            self.build()

    def test_selected_hard_link_to_unrelated_material_is_not_packaged(self):
        external=self.base/'unrelated-material';external.write_text('do not publish')
        path=self.source/'controller/app.py';path.unlink();os.link(external,path)
        with self.assertRaises(package.PackageError):self.build()
        self.assertFalse(self.output.exists())

    def test_asset_unknown_files_directory_symlinks_and_special_sources_block_build(self):
        for name in ['dashboard/assets/private.key','dashboard/assets/.env']:
            path=self.put(name,'private')
            with self.assertRaises(package.PackageError):self.build()
            path.unlink()
        directory=self.source/'dashboard/assets/linked';directory.symlink_to(self.base,target_is_directory=True)
        with self.assertRaises(package.PackageError):self.build()
        directory.unlink()
        if hasattr(os,'mkfifo'):
            path=self.source/'controller/app.py';path.unlink();os.mkfifo(path)
            with self.assertRaises(package.PackageError):self.build()

    def test_populated_env_secrets_and_private_trust_fields_block_without_secret_output(self):
        original=(self.source/'.env.example').read_text()
        for key in ['CLUSTER_PASSWORD','SUPER_ADMIN_TOKEN','SEG_ENTRA_CLIENT_SECRET','SEG_ENTRA_CLIENT_SECRET_FILE']:
            value='\n'.join(line for line in original.splitlines() if not line.startswith(key+'='))
            (self.source/'.env.example').write_text(value+'\n'+key+'=never-publish-this-secret\n')
            with self.assertRaises(package.PackageError) as raised:self.build()
            self.assertNotIn('never-publish',str(raised.exception))
        (self.source/'.env.example').write_text(original)
        trust=self.source/'deploy/release-public-trust.json';value=json.loads(trust.read_text());value['private_key']='never-publish'
        trust.write_text(json.dumps(value))
        with self.assertRaises(package.PackageError):self.build()
        self.assertFalse(self.output.exists())

    def test_required_vm_document_and_payload_size_are_checked_before_archive_publish(self):
        sizing=self.source/'docs/controller-vm-requirements.md';data=sizing.read_bytes();sizing.unlink()
        with self.assertRaises(OSError):self.build()
        sizing.write_bytes(data)
        with patch.object(package,'MAX_FILE_BYTES',32):
            with self.assertRaises(package.PackageError):self.build()
        with patch.object(package,'MAX_PAYLOAD_BYTES',32):
            with self.assertRaises(package.PackageError):self.build()
        self.assertFalse(self.output.exists())

    def test_missing_bootstrap_dependency_helper_prevents_partial_distribution(self):
        for name in ('scripts/install-prerequisites.sh','deploy/appliance/install_prerequisites.py'):
            with self.subTest(path=name):
                path=self.source/name;original=path.read_bytes();path.unlink()
                with self.assertRaises(OSError):self.build()
                self.assertFalse(self.output.exists())
                path.write_bytes(original)

    def test_repeated_build_is_reproducible_but_requires_explicit_overwrite(self):
        first=self.build()
        with self.assertRaises(package.PackageError):self.build()
        second=self.build(overwrite=True)
        self.assertEqual(first['sha256'],second['sha256'])
        checksum=Path(first['archive']+'.sha256').read_text()
        self.assertEqual(checksum,first['sha256']+'  '+Path(first['archive']).name+'\n')

    def test_output_symlinks_and_public_write_directories_are_rejected(self):
        self.output.mkdir();self.output.chmod(0o777)
        with self.assertRaises(package.PackageError):self.build()
        self.output.chmod(0o700)
        external=self.base/'unchanged';external.write_text('must survive')
        (self.output/'prthak-controller-0.6.0.tar.gz').symlink_to(external)
        with self.assertRaises(package.PackageError):self.build(overwrite=True)
        self.assertEqual(external.read_text(),'must survive')

    def test_source_change_during_build_refuses_mixed_archive(self):
        original=package.snapshot;calls=0
        def moving(root):
            nonlocal calls
            result=original(root);calls+=1
            if calls==1:self.put('controller/app.py','changed while packaging\n')
            return result
        with patch.object(package,'snapshot',side_effect=moving):
            with self.assertRaises(package.PackageError):self.build()
        self.assertFalse(any(self.output.glob('*.tar.gz')))

    def test_unsigned_rebuild_removes_stale_signatures_and_private_seed_is_never_packaged(self):
        first=self.build()
        for suffix in ['.signature.json','.public-trust.json']:
            Path(first['archive']+suffix).write_text('stale detached authority')
        self.build(overwrite=True)
        for suffix in ['.signature.json','.public-trust.json']:
            self.assertFalse(Path(first['archive']+suffix).exists())

    def test_extracted_bundle_runs_real_validate_only_without_git_docker_or_root_install(self):
        result=self.build()
        extraction=self.base/'extracted';extraction.mkdir()
        with tarfile.open(result['archive']) as archive:archive.extractall(extraction,filter='data')
        release=extraction/'prthak-controller-0.6.0'
        env=self.base/'private.env';env.write_text('DATA_ROOT=/mnt/prthak-package-fixture\nNODE_ID=package-test\nSITE=PackageTest\nNODE_IP=127.0.0.1\n');env.chmod(0o600)
        commands=self.base/'forbidden-commands';commands.mkdir()
        marker=self.base/'external-command-was-called'
        for name in ['git','docker','systemctl']:
            path=commands/name;path.write_text('#!/bin/sh\ntouch "'+str(marker)+'"\nexit 99\n');path.chmod(0o755)
        environment=dict(os.environ,PRTHAK_INSTALL_PYTHON=sys.executable,PATH=str(commands)+os.pathsep+os.environ.get('PATH',''))
        validation=subprocess.run(['sh',str(release/'scripts/install-controller.sh'),'--env-file',str(env),'--validate-only'],cwd=release,env=environment,capture_output=True,text=True,timeout=15)
        self.assertEqual(validation.returncode,0,validation.stderr)
        self.assertEqual(json.loads(validation.stdout)['status'],'validated')
        self.assertFalse(marker.exists())

    def test_optional_signing_uses_existing_verifier_and_independent_source_pin(self):
        from controller.policy_signing import PolicySigner
        seed=self.base/'private-release.seed'
        signer=PolicySigner(seed,'00000000-0000-0000-0000-000000000000',create=True)
        pin=self.base/'independent-public-trust.json';pin.write_text(json.dumps(signer.public_trust()));pin.chmod(0o600)
        with patch.dict(os.environ,{'PRTHAK_RELEASE_SIGNING_KEY_FILE':str(seed)}):
            result=self.build()
        self.assertTrue(result['signed'])
        verified=subprocess.run([sys.executable,str(PROJECT/'scripts/verify-release.py'),
                                 '--public-trust-file',str(pin),'--signature',result['archive']+'.signature.json',result['archive']],capture_output=True,text=True,timeout=15)
        self.assertEqual(verified.returncode,0,verified.stdout+verified.stderr)
        contents=self.members(result['archive'])
        self.assertFalse(any(seed.read_bytes() in data for item,data in contents.values()))
        self.assertNotIn('private-release.seed',contents)

    def test_connected_package_embeds_only_both_verified_agent_archives_and_signatures(self):
        from controller.policy_signing import PolicySigner

        seed = self.base / 'private-release.seed'
        signer = PolicySigner(seed, '00000000-0000-0000-0000-000000000000', create=True)
        self.put('deploy/release-public-trust.json', json.dumps(signer.public_trust()))
        archives = [self.put(f'agents/prthak-agent-0.6.0-linux-{arch}.tar.gz', arch)
                    for arch in ('amd64', 'arm64')]
        subprocess.run([sys.executable, str(PROJECT/'scripts/sign-release.py'), '--key-file', str(seed),
                        *map(str, archives)], check=True, capture_output=True, timeout=15)

        result = self.build(agent_dist=archives[0].parent)
        contents = self.members(result['archive'])
        manifest = json.loads(contents['MANIFEST.json'][1])
        names = {archive.name + suffix for archive in archives for suffix in ('', '.signature.json')}
        self.assertFalse(manifest['source_only'])
        self.assertEqual({name for name in contents if name.startswith('agent-releases/')},
                         {'agent-releases/' + name for name in names})
        for name in names:
            data = (archives[0].parent / name).read_bytes()
            archive_path = 'agent-releases/' + name
            self.assertEqual(contents[archive_path][1], data)
            self.assertEqual(manifest['files'][archive_path]['sha256'], hashlib.sha256(data).hexdigest())

        archives[0].write_bytes(b'AMD64')
        with self.assertRaisesRegex(package.PackageError, 'Signed Linux agent artifact did not verify'):
            self.build(agent_dist=archives[0].parent, overwrite=True)
