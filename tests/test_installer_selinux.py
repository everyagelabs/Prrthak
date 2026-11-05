"""SELinux installer transactions on redirected paths; no native OS changes."""
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import unittest

from tests import test_installer as fixtures


class AgentSELinuxInstallerTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.AgentInstallerTests("test_staging_installs_enabled_unit_without_touching_live_systemd")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        f = self.fixture
        self.events = f.base / "native-events.jsonl"
        self.service_state = f.base / "service-state"
        self.service_state.write_text("1")
        self.environment = {**f.env, "PSEGRA_FIXTURE_ROOT": str(f.root), "SELINUX_EVENTS": str(self.events),
                            "SELINUX_SERVICE_STATE": str(self.service_state), "SELINUX_MODE": "Enforcing",
                            "TMPDIR": str(f.base)}
        self.private = f.base / "private-selinux-installer.sh"
        value = fixtures.INSTALLER.read_text()
        for line, path in {
            "ETC_DIR=$ROOT/etc/seg-agent": f.root / "etc/seg-agent",
            "STATE_DIR=$ROOT/var/lib/seg-agent": f.root / "var/lib/seg-agent",
            "BIN_DIR=$ROOT/usr/local/bin": f.root / "usr/local/bin",
            "UNIT_DIR=$ROOT/etc/systemd/system": f.root / "etc/systemd/system",
        }.items():
            value = value.replace(line, line.split("=", 1)[0] + "=" + shlex.quote(str(path)))
        value = value.replace("$ROOT/usr/", "$PSEGRA_FIXTURE_ROOT/usr/")
        value = value.replace("/sys/fs/selinux/enforce", str(f.base / "no-selinuxfs/enforce"))
        value = value.replace("/selinux/enforce", str(f.base / "no-legacy-selinux/enforce"))
        value = value.replace('PROJECT_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)',
                              "PROJECT_ROOT=" + shlex.quote(str(fixtures.PROJECT)))
        for variable in ("RUNTIME_MANIFEST", "RELEASE_TRUST"):
            source = f.base / (variable + ".json")
            source.write_text("{}")
            original = "RUNTIME_MANIFEST=$PROJECT_ROOT/runtime-integrity.json" if variable == "RUNTIME_MANIFEST" else "RELEASE_TRUST=$PROJECT_ROOT/deploy/release-public-trust.json"
            value = value.replace(original, variable + "=" + shlex.quote(str(source)))
        self.private.write_text(value)
        fakebin = f.base / "fake-bin"
        for name, output in (("uname", "Linux"), ("id", "0"), ("stat", "0")):
            self.program(fakebin / name, '#!/bin/sh\nprintf "%s\\n" ' + shlex.quote(output) + "\n")
        self.program(fakebin / "flock", '#!/bin/sh\n[ -e /dev/fd/9 ]\n')
        self.python_program(fakebin / "getenforce", """
record('getenforce', args)
print(os.environ['SELINUX_MODE'])
""")
        self.python_program(fakebin / "restorecon", """
record('restorecon', args)
assert all(Path(value).exists() for value in args if not value.startswith('-'))
sys.exit(int(os.environ.get('SELINUX_RELABEL_FAIL', '0')))
""")
        # GNU cp preserves the old security context during actual Linux rollback.
        # This shim supplies its attribute-preserving semantics on macOS fixtures.
        self.python_program(fakebin / "cp", """
import shutil
record('cp', args)
preserve='--preserve=mode,ownership,timestamps,context,xattr'
paths=[value for value in args if value not in (preserve, '--')]
assert preserve in args
if os.environ.get('SELINUX_BACKUP_CONTEXT_FAIL') and '/original-' in paths[1]:
    sys.exit(8)
if os.environ.get('SELINUX_RESTORE_COPY_FAIL') and '/original-' in paths[0]:
    sys.exit(9)
if os.environ.get('SELINUX_SIGNAL_DURING_RESTORE') and '/original-' in paths[0]:
    import signal
    os.kill(os.getppid(), signal.SIGTERM)
shutil.copy2(*paths)
""")
        self.python_program(fakebin / "systemctl", """
record('systemctl', args)
state=Path(os.environ['SELINUX_SERVICE_STATE'])
if args[0]=='is-active':sys.exit(0 if state.read_text()=='1' else 3)
if args[0]=='stop':state.write_text('0')
if args[0] in ('start','restart'):
    if os.environ.get('SELINUX_RESTART_FAIL'):sys.exit(7)
    state.write_text('0' if os.environ.get('SELINUX_START_NOT_ACTIVE') else '1')
""")
        self.python_program(f.binary, """
record('agent', [sys.argv[0], *args])
if '--status' in args:print('Endpoint registered')
""")

    @staticmethod
    def program(path, content):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        path.chmod(0o755)

    def python_program(self, path, body):
        self.program(path, "#!" + sys.executable + "\nimport json,os,sys\nfrom pathlib import Path\nargs=sys.argv[1:]\n"
                     "def record(name, values):\n"
                     "    with open(os.environ['SELINUX_EVENTS'],'a') as output:output.write(json.dumps([name,values])+'\\n')\n" + body)

    def prior_files(self):
        f = self.fixture
        previous = {
            "etc/seg-agent/config.json": b'{"prior":"configuration"}',
            "etc/seg-agent/config.json.previous": b"older configuration backup",
            "etc/seg-agent/controller-ca.crt": b"prior controller trust",
            "etc/seg-agent/endpoint-ca.crt": b"prior endpoint trust",
            "etc/seg-agent/enrollment-token": b"private prior token",
            "etc/seg-agent/bootstrap.env": b"prior bootstrap settings",
            "etc/seg-agent/release-public-trust.json": b"prior release trust",
            "usr/local/bin/seg-agent": b"#!/bin/sh\nexit 0\n",
            "etc/systemd/system/seg-agent.service": b"prior reviewed unit",
            "usr/share/doc/seg-agent/README.md": b"prior guide",
            "usr/share/seg-agent/runtime-integrity.json": b"prior runtime manifest",
            "usr/share/seg-agent/upgrade-helper": b"prior upgrade worker",
            "usr/share/seg-agent/upgrade-helper-integrity.json": b"prior worker manifest",
        }
        for relative, content in previous.items():
            path = f.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
            path.chmod(0o755 if relative.endswith(("/seg-agent", "/upgrade-helper")) else 0o600)
        return {relative: (content, (f.root / relative).stat().st_mode & 0o777) for relative, content in previous.items()}

    def run_native(self, **environment):
        f = self.fixture
        return subprocess.run(["/bin/sh", str(self.private), "--replace-config", "--wait-seconds", "0",
                               "--ca-file", str(f.ca), "--token-file", str(f.token), str(f.binary), str(f.config)],
                              capture_output=True, text=True, env={**self.environment, **environment}, timeout=15)

    def calls(self):
        return [json.loads(line) for line in self.events.read_text().splitlines()] if self.events.exists() else []

    def test_enforcing_and_permissive_relabel_final_paths_before_validation_reload_and_start(self):
        for mode in ("Enforcing", "Permissive"):
            with self.subTest(mode=mode):
                self.events.unlink(missing_ok=True)
                result = self.run_native(SELINUX_MODE=mode)
                self.assertEqual(result.returncode, 0, result.stderr)
                calls = self.calls()
                relabel = next(index for index, (name, _) in enumerate(calls) if name == "restorecon")
                paths = calls[relabel][1]
                self.assertIn(str(self.fixture.root / "etc/systemd/system/seg-agent.service"), paths)
                self.assertIn(str(self.fixture.root / "usr/local/bin/seg-agent"), paths)
                self.assertIn(str(self.fixture.root / "etc/seg-agent/config.json"), paths)
                self.assertIn(str(self.fixture.root / "usr/share/seg-agent/upgrade-helper"), paths)
                self.assertFalse(any(value in ("-R", "-r") for value in paths))
                self.assertTrue(all(Path(value).is_file() for value in paths if not value.startswith('-')), 'do not relabel unbacked directories or the installation lock')
                self.assertNotIn(str(self.fixture.root / 'var/lib/seg-agent/configuration-transitions/lock'), paths)
                validate = next(index for index, (name, args) in enumerate(calls) if name == "agent" and args[0] == str(self.fixture.root / "usr/local/bin/seg-agent") and "--check-config" in args)
                reload = calls.index(["systemctl", ["daemon-reload"]])
                restart = calls.index(["systemctl", ["restart", "seg-agent.service"]])
                self.assertLess(relabel, validate)
                self.assertLess(validate, reload)
                self.assertLess(reload, restart)

    def test_disabled_and_non_selinux_hosts_do_not_require_or_run_restorecon(self):
        result = self.run_native(SELINUX_MODE="Disabled")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(any(name == "restorecon" for name, _ in self.calls()))
        self.events.unlink()
        self.private.write_text(self.private.read_text().replace("command -v getenforce", "command -v prthak-test-no-getenforce"))
        result = self.run_native()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(any(name in ("getenforce", "restorecon") for name, _ in self.calls()))

    def test_kernel_enabled_selinux_still_relabels_when_getenforce_is_missing(self):
        kernel = self.fixture.base / "no-selinuxfs/enforce"
        kernel.parent.mkdir()
        kernel.write_text("0")  # Permissive still has a live SELinux filesystem.
        self.private.write_text(self.private.read_text().replace("command -v getenforce", "command -v prthak-test-no-getenforce"))
        result = self.run_native()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(any(name == "restorecon" for name, _ in self.calls()))

    def test_unknown_selinux_state_blocks_without_touching_agent_or_service(self):
        previous = self.prior_files()
        result = self.run_native(SELINUX_MODE="unavailable")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Unrecognized SELinux state", result.stderr)
        self.assertEqual(self.calls(), [["getenforce", []]])
        for relative, (content, _) in previous.items():
            self.assertEqual((self.fixture.root / relative).read_bytes(), content)

    def test_missing_restorecon_blocks_before_stop_or_replacement(self):
        previous = self.prior_files()
        self.private.write_text(self.private.read_text().replace("command -v restorecon", "command -v prthak-test-missing-restorecon"))
        result = self.run_native()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Install policycoreutils", result.stderr)
        self.assertEqual(self.calls(), [["getenforce", []]])
        for relative, (content, mode) in previous.items():
            self.assertEqual((self.fixture.root / relative).read_bytes(), content)
            self.assertEqual((self.fixture.root / relative).stat().st_mode & 0o777, mode)

    def test_failed_relabel_restores_all_prior_files_modes_and_running_service(self):
        previous = self.prior_files()
        result = self.run_native(SELINUX_RELABEL_FAIL="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Previous files and service state were restored", result.stderr)
        self.assertIn("installation did not complete", result.stderr)
        for relative, (content, mode) in previous.items():
            path = self.fixture.root / relative
            self.assertEqual(path.read_bytes(), content, relative)
            self.assertEqual(path.stat().st_mode & 0o777, mode, relative)
        self.assertEqual(self.service_state.read_text(), "1")
        self.assertIn(["systemctl", ["start", "seg-agent.service"]], self.calls())
        self.assertNotIn(["systemctl", ["enable", "seg-agent.service"]], self.calls())
        self.assertNotIn(["systemctl", ["restart", "seg-agent.service"]], self.calls())

    def test_failed_fresh_install_relabel_removes_new_files_and_leaves_service_stopped(self):
        self.service_state.write_text("0")
        result = self.run_native(SELINUX_RELABEL_FAIL="1")
        self.assertNotEqual(result.returncode, 0)
        for relative in ("etc/seg-agent/config.json", "etc/systemd/system/seg-agent.service", "usr/local/bin/seg-agent", "usr/share/seg-agent/upgrade-helper"):
            self.assertFalse((self.fixture.root / relative).exists(), relative)
        self.assertEqual(self.service_state.read_text(), "0")
        self.assertNotIn(["systemctl", ["start", "seg-agent.service"]], self.calls())

    def test_failed_relabel_keeps_an_existing_stopped_service_stopped(self):
        previous = self.prior_files()
        self.service_state.write_text("0")
        result = self.run_native(SELINUX_RELABEL_FAIL="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Previous files and service state were restored", result.stderr)
        self.assertEqual(self.service_state.read_text(), "0")
        self.assertNotIn(["systemctl", ["start", "seg-agent.service"]], self.calls())
        for relative, (content, _) in previous.items():
            self.assertEqual((self.fixture.root / relative).read_bytes(), content)

    def test_failed_recovery_keeps_private_backup_and_never_claims_success(self):
        self.prior_files()
        result = self.run_native(SELINUX_RELABEL_FAIL="1", SELINUX_RESTORE_COPY_FAIL="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("recovery is incomplete", result.stderr)
        backups = list(self.fixture.base.glob("psegra-install.*"))
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].stat().st_mode & 0o777, 0o700)
        self.assertTrue(list(backups[0].glob("original-*")))
        self.assertEqual(self.service_state.read_text(), "0")
        self.assertNotIn(["systemctl", ["start", "seg-agent.service"]], self.calls())

    def test_signal_during_recovery_never_deletes_private_prior_files(self):
        self.prior_files()
        result = self.run_native(SELINUX_RELABEL_FAIL="1", SELINUX_SIGNAL_DURING_RESTORE="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Private recovery files were retained", result.stderr)
        backups = list(self.fixture.base.glob("psegra-install.*"))
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].stat().st_mode & 0o777, 0o700)
        self.assertTrue(list(backups[0].glob("original-*")))
        self.assertEqual(self.service_state.read_text(), "0")
        self.assertNotIn(["systemctl", ["start", "seg-agent.service"]], self.calls())

    def test_context_backup_failure_blocks_before_stopping_or_replacing(self):
        previous = self.prior_files()
        result = self.run_native(SELINUX_BACKUP_CONTEXT_FAIL="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Cannot preserve the previous installation and its SELinux context", result.stderr)
        for relative, (content, _) in previous.items():
            self.assertEqual((self.fixture.root / relative).read_bytes(), content)
        self.assertNotIn(["systemctl", ["stop", "seg-agent.service"]], self.calls())

    def test_recovery_requires_previous_service_to_be_active_not_just_start_command_success(self):
        self.prior_files()
        result = self.run_native(SELINUX_RELABEL_FAIL="1", SELINUX_START_NOT_ACTIVE="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("recovery is incomplete", result.stderr)
        self.assertEqual(self.service_state.read_text(), "0")
        self.assertTrue(list(self.fixture.base.glob("psegra-install.*/original-*")))

    def test_symlink_destination_refused_before_stopping_service(self):
        unit = self.fixture.root / "etc/systemd/system/seg-agent.service"
        unit.parent.mkdir(parents=True)
        foreign = self.fixture.base / "foreign-unit"
        foreign.write_text("leave this unit alone")
        unit.symlink_to(foreign)
        result = self.run_native()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("non-symlink destination", result.stderr)
        self.assertEqual(foreign.read_text(), "leave this unit alone")
        self.assertTrue(unit.is_symlink())
        self.assertNotIn(["systemctl", ["stop", "seg-agent.service"]], self.calls())

    def test_staging_does_not_probe_or_relabel_the_host_selinux_state(self):
        result = self.fixture.run_install(env=self.environment)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(any(name in ("getenforce", "restorecon", "systemctl") for name, _ in self.calls()))


if __name__ == "__main__":
    unittest.main()
