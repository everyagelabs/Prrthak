"""Native packaging safety without installing packages or controlling a host."""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import struct
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

PROJECT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("prthak_agent_native_packages",PROJECT/"scripts/build-agent-native-packages.py")
package=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(package)


class AgentNativePackageTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory(prefix="prthak-native-test-")
        self.addCleanup(temporary.cleanup);self.base=Path(temporary.name).resolve()
        self.output=self.base/"output"

    def bundle(self,arch="amd64",extra=(),omit=(),binary_arch=None):
        stem="prthak-agent-0.7.0-linux-"+arch
        target=self.base/(stem+".tar.gz")
        elf=bytearray(64);elf[:6]=b"\x7fELF\x02\x01";elf[18:20]=struct.pack("<H",{"amd64":62,"arm64":183}[binary_arch or arch])
        with tarfile.open(target,"w:gz",format=tarfile.USTAR_FORMAT) as outgoing:
            for name in sorted(package.ALLOWED-set(omit)):
                data=bytes(elf) if name=="seg-agent" else ("public fixture "+name+"\n").encode()
                info=tarfile.TarInfo(stem+"/"+name);info.size=len(data);info.mode=0o777
                outgoing.addfile(info,io.BytesIO(data))
            for name,kind,data in extra:
                info=tarfile.TarInfo(name.replace("{stem}",stem));info.type=kind
                if kind in (tarfile.SYMTYPE,tarfile.LNKTYPE):info.linkname="../../secret"
                else:info.size=len(data)
                outgoing.addfile(info,io.BytesIO(data) if info.size else None)
        target.chmod(0o644)
        return target

    def inspect(self,archive):
        stage=self.base/("stage-"+str(len(list(self.base.glob("stage-*")))));stage.mkdir()
        return package.inspect_bundle(archive,stage/"payload"),stage/"payload"

    def sign(self,archive):
        from controller.policy_signing import PolicySigner
        signer=PolicySigner(self.base/"outside-source-release-key","00000000-0000-0000-0000-000000000000",create=True)
        trust=self.base/"approved-public-trust.json";trust.write_text(json.dumps(signer.public_trust()));trust.chmod(0o644)
        manifest={"filename":archive.name,"bytes":archive.stat().st_size,"sha256":hashlib.sha256(archive.read_bytes()).hexdigest()}
        Path(str(archive)+".signature.json").write_text(json.dumps(signer.sign_package(manifest)))
        return trust

    def test_both_architectures_preserve_bytes_and_normalize_payload_modes(self):
        for arch in ("amd64","arm64"):
            with self.subTest(arch=arch):
                plan,payload=self.inspect(self.bundle(arch))
                self.assertEqual(plan["install_prefix"],"/opt/prthak-agent/0.7.0-linux-"+arch)
                self.assertEqual(set(plan["files"]),package.ALLOWED)
                for name in plan["files"]:
                    path=payload/name
                    self.assertTrue(path.is_file());self.assertFalse(path.is_symlink())
                    self.assertEqual(path.stat().st_mode&0o777,0o755 if name=="seg-agent" or name.startswith("scripts/") else 0o644)
                self.assertEqual(payload.stat().st_mode&0o777,0o755)
                for directory in payload.rglob("*"):
                    if directory.is_dir():self.assertEqual(directory.stat().st_mode&0o777,0o755)

    def test_traversal_absolute_and_noncanonical_paths_are_rejected(self):
        for name in ("{stem}/../escape","/root/secret","{stem}//docs/scale-validation.md","{stem}/./seg-agent"):
            with self.subTest(name=name),self.assertRaises(ValueError):
                self.inspect(self.bundle(extra=[(name,tarfile.REGTYPE,b"x")]))
        self.assertFalse((self.base/"escape").exists())

    def test_links_devices_directories_and_secret_files_are_rejected(self):
        for name,kind in (("{stem}/rogue",tarfile.SYMTYPE),("{stem}/rogue",tarfile.LNKTYPE),("{stem}/rogue",tarfile.FIFOTYPE),("{stem}/docs",tarfile.DIRTYPE),("{stem}/.env",tarfile.REGTYPE),("{stem}/deploy/ca.key",tarfile.REGTYPE)):
            with self.subTest(name=name,kind=kind),self.assertRaises(ValueError):
                self.inspect(self.bundle(extra=[(name,kind,b"")]))

    def test_duplicates_missing_runtime_and_wrong_elf_arch_are_rejected(self):
        with self.assertRaises(ValueError):self.inspect(self.bundle(extra=[("{stem}/seg-agent",tarfile.REGTYPE,b"x")]))
        with self.assertRaisesRegex(ValueError,"missing"):self.inspect(self.bundle(omit=["runtime-integrity.json"]))
        with self.assertRaisesRegex(ValueError,"ELF"):self.inspect(self.bundle(binary_arch="arm64"))

    def test_compressed_expansion_and_entry_bounds_are_enforced(self):
        archive=self.bundle()
        with patch.object(package,"MAX_TAR",512),self.assertRaisesRegex(ValueError,"Expanded"):self.inspect(archive)
        with patch.object(package,"MAX_ENTRIES",2),self.assertRaisesRegex(ValueError,"too many"):self.inspect(archive)

    def test_private_copy_rejects_links_special_files_and_oversized_inputs(self):
        source=self.base/"input";source.write_bytes(b"public-data")
        alias=self.base/"alias";alias.symlink_to(source)
        with self.assertRaises(OSError):package.copy_bounded(alias,self.base/"copied-alias",100)
        with self.assertRaises(ValueError):package.copy_bounded(source,self.base/"copied-oversize",2)
        self.assertEqual((self.base/"copied-oversize").read_bytes(),b"")
        fifo=self.base/"fifo";os.mkfifo(fifo)
        with self.assertRaises(ValueError):package.copy_bounded(fifo,self.base/"copied-fifo",100)

    def test_dry_run_verifies_real_signature_without_docker_or_output_mutation(self):
        archive=self.bundle();trust=self.sign(archive)
        buffer=io.StringIO()
        with patch.dict(os.environ,{"PRTHAK_RELEASE_SIGNING_KEY_FILE":"must-never-be-read-in-dry-run"}),contextlib.redirect_stdout(buffer):
            self.assertEqual(package.main(["--public-trust-file",str(trust),"--output-dir",str(self.output),"--dry-run",str(archive)]),0)
        plan=json.loads(buffer.getvalue())
        self.assertTrue(plan["dry_run"]);self.assertFalse(self.output.exists())
        self.assertEqual(plan["packages"][0]["formats"],["rpm","deb"])
        command=plan["packages"][0]["command"]
        for flag in ("--network=none","--read-only","--cap-drop=ALL","--security-opt=no-new-privileges"):self.assertIn(flag,command)
        self.assertNotIn("--env",command);self.assertNotIn("--privileged",command)
        self.assertNotIn("must-never-be-read",buffer.getvalue())

    def test_untrusted_archive_fails_before_docker(self):
        archive=self.bundle();trust=self.sign(archive)
        with archive.open("ab") as outgoing:outgoing.write(b"altered-after-signature")
        with self.assertRaises(package.subprocess.CalledProcessError):
            package.main(["--public-trust-file",str(trust),"--output-dir",str(self.output),"--dry-run",str(archive)])
        self.assertFalse(self.output.exists())

    def test_outer_signer_stays_outside_builder_and_signs_exact_mock_outputs(self):
        archive=self.bundle();trust=self.sign(archive)
        key=self.base/"outside-source-release-key"
        secret=key.read_bytes();real_run=package.subprocess.run;docker_calls=[]
        def run(command,**kwargs):
            if command[:2]==["docker","run"]:
                docker_calls.append(command)
                mount=next(item for item in command if item.startswith("type=bind,source=") and item.endswith(",target=/input,readonly"))
                stage=Path(mount[len("type=bind,source="):-len(",target=/input,readonly")])
                self.assertNotIn(str(key),command);self.assertNotIn("--env",command)
                for path in stage.rglob("*"):
                    if path.is_file():self.assertNotIn(secret,path.read_bytes())
                plan=json.loads((stage/"build.json").read_text())
                for name in plan["outputs"].values():(self.output/name).write_bytes(b"mock-container-native-artifact")
                return None
            return real_run(command,**kwargs)
        with patch.dict(os.environ,{"PRTHAK_RELEASE_SIGNING_KEY_FILE":str(key)}),patch.object(package.subprocess,"run",side_effect=run):
            package.main(["--public-trust-file",str(trust),"--output-dir",str(self.output),str(archive)])
        self.assertEqual(len(docker_calls),1)
        for name in package.output_names("0.7.0","amd64").values():
            artifact=self.output/name
            self.assertTrue(Path(str(artifact)+".signature.json").is_file())
            real_run([sys.executable,str(PROJECT/"scripts/verify-release.py"),"--public-trust-file",str(trust),"--signature",str(artifact)+".signature.json",str(artifact)],check=True,capture_output=True)

    def test_output_aliases_existing_packages_and_duplicate_targets_are_refused(self):
        archive=self.bundle();trust=self.sign(archive)
        alias=self.base/"alias";alias.symlink_to(self.base,target_is_directory=True)
        with self.assertRaises(ValueError):package.main(["--public-trust-file",str(trust),"--output-dir",str(alias/"output"),"--dry-run",str(archive)])
        self.output.mkdir();(self.output/package.output_names("0.7.0","amd64")["rpm"]).write_text("previous")
        with self.assertRaises(ValueError):package.main(["--public-trust-file",str(trust),"--output-dir",str(self.output),"--dry-run",str(archive)])
        (self.output/package.output_names("0.7.0","amd64")["rpm"]).unlink()
        with self.assertRaises(ValueError):package.main(["--public-trust-file",str(trust),"--output-dir",str(self.output),"--dry-run",str(archive),str(archive)])

    def test_builder_generates_only_inert_metadata_and_arch_correct_payload(self):
        for arch in ("amd64","arm64"):
            with self.subTest(arch=arch):
                plan,payload=self.inspect(self.bundle(arch))
                stage=payload.parent;out=stage/"output";out.mkdir();scratch=stage/"scratch";scratch.mkdir()
                plan.update(formats=["deb","rpm"],outputs=package.output_names("0.7.0",arch))
                (stage/"build.json").write_text(json.dumps(plan))
                code=package.BUILDER_CODE.replace("'/input","'"+str(stage)).replace("'/output","'"+str(out)).replace("dir='/tmp'","dir="+repr(str(scratch)))
                observed=[]
                def run(command,check):
                    observed.append(command)
                    if command[0]=="dpkg-deb":
                        tree=Path(command[-2]);control=tree/"DEBIAN"
                        self.assertEqual([item.name for item in control.iterdir()],["control"])
                        self.assertIn("Architecture: "+arch,(control/"control").read_text())
                        self.assertNotIn("Depends:",(control/"control").read_text())
                        files={str(path.relative_to(tree)) for path in tree.rglob("*") if path.is_file() and "DEBIAN" not in path.parts}
                        self.assertEqual(files,{plan["install_prefix"].lstrip("/")+"/"+name for name in package.ALLOWED})
                        Path(command[-1]).write_bytes(b"mock-deb-container-output")
                    else:
                        spec=Path(command[-1]);text=spec.read_text()
                        self.assertIn("AutoReqProv: no",text);self.assertIn("_binary_payload w9.gzdio",text)
                        self.assertIn("%global __os_install_post %{nil}",text)
                        self.assertNotIn("BuildArch:",text)
                        self.assertIn("_tmppath /tmp",command)
                        for hook in ("%pre\n","%post\n","%preun","%postun","%trigger"):self.assertNotIn(hook,text)
                        self.assertTrue(text.endswith(plan["install_prefix"]+"\n"))
                        self.assertEqual(command[command.index("--target")+1],{"amd64":"x86_64","arm64":"aarch64"}[arch])
                        result=spec.parents[1]/"RPMS"/"fixture";result.mkdir();(result/"payload.rpm").write_bytes(b"mock-rpm-container-output")
                with patch("subprocess.run",side_effect=run):exec(compile(code,"native-builder-fixture","exec"),{})
                self.assertEqual(len(observed),2)
                self.assertEqual({path.name for path in out.iterdir()},set(plan["outputs"].values()))


if __name__=="__main__":unittest.main()
