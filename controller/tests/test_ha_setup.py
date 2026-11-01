import base64
import contextlib
import copy
from datetime import datetime, timedelta, timezone
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from controller.ha_setup import (FileMaterialProvider, JoinAuthorization, NodeUnavailable,
    Provisioner, SetupBlocked, SSHRunner, canonical_digest, ca_fingerprint, topology, validate)


HOST_KEY = "ssh-ed25519 " + base64.b64encode(len(b"ssh-ed25519").to_bytes(4, "big") + b"ssh-ed25519" + (32).to_bytes(4, "big") + b"k" * 32).decode()


def specification():
    return {"cluster_id": "df47ac59-b054-4d23-a202-361967730ab4", "name": "prthak_test", "controller_origin": "https://prthak.example.internal", "mode": "dc_dr", "rpo": "synchronous_strict",
        "nodes": [{"id": "db-a", "ip": "10.70.0.11", "site": "dc-a", "role": "database", "ssh": {"user": "ubuntu", "port": 22, "host_key": HOST_KEY, "private_key_ref": "ssh-key-1"}},
            {"id": "db-b", "ip": "10.71.0.11", "site": "dc-b", "role": "database", "ssh": {"user": "root", "port": 2222, "host_key": HOST_KEY, "private_key_ref": "ssh-key-2"}},
            {"id": "witness", "ip": "10.72.0.11", "site": "cloud", "role": "witness", "ssh": {"user": "ubuntu", "port": 22, "host_key": HOST_KEY, "private_key_ref": "ssh-key-1"}}],
        "controller_cidrs": ["10.80.0.0/24"], "watchdog": {"mode": "required", "device": "/dev/watchdog", "approved": True}}


def helper_module():
    path = Path(__file__).resolve().parents[2] / "deploy/cluster/node_helper.py"
    spec = importlib.util.spec_from_file_location("prthak_fixed_node_helper", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeRunner:
    def __init__(self):
        self.calls = []
        self.blocked = None
        self.bad_quorum = False
        self.two_primaries = False
        self.bad_watchdog = False
        self.roles = False
        self.fail_action = None
        self.ca_pin = "f" * 64

    def run(self, node, action, payload):
        self.calls.append((node["id"], action, copy.deepcopy(payload)))
        if self.fail_action == action:
            raise NodeUnavailable("redacted transport failure")
        value = {"node_id": node["id"], "cluster_id": payload["spec"]["cluster_id"], "topology_digest": payload["topology_digest"], "status": "ok", "blockers": []}
        if action == "inspect" and self.blocked == node["id"]:
            value.update(status="blocked", blockers=["Foreign data exists"])
        if action == "status":
            value.update(etcd_healthy=not self.bad_quorum, ca_fingerprint=self.ca_pin, database_healthy=True, watchdog_ready=not self.bad_watchdog,
                database_role="primary" if node["id"] == "db-a" or self.two_primaries else "replica", synchronous_replica=True, roles_ready=self.roles)
        if action == "create_roles":
            self.roles = True
            value["roles_ready"] = True
        return value


class ValidationTests(unittest.TestCase):
    def test_normalizes_defaults_and_does_not_mutate_input(self):
        value = specification()
        original = copy.deepcopy(value)
        result = validate(value)
        self.assertEqual(value, original)
        self.assertEqual(result["database"]["metadata_name"], "prthak_metadata")
        self.assertEqual(result["schema_version"], 1)

    def test_rejects_two_voters_duplicate_sites_and_three_databases(self):
        for mutate in (lambda s: s["nodes"].pop(), lambda s: s["nodes"][2].update(site="dc-a"), lambda s: s["nodes"][2].update(role="database")):
            value = specification()
            mutate(value)
            with self.assertRaises(SetupBlocked):
                validate(value)

    def test_rejects_ip_only_join_wildcard_network_and_watchdog_optout(self):
        for mutate in (lambda s: s["nodes"][0]["ssh"].pop("host_key"), lambda s: s.update(controller_cidrs=["0.0.0.0/0"]), lambda s: s["watchdog"].update(mode="automatic"), lambda s: s["watchdog"].update(approved=False)):
            value = specification()
            mutate(value)
            with self.assertRaises(SetupBlocked):
                validate(value)

    def test_rejects_commands_in_identity_and_key_references(self):
        for mutate in (lambda s: s.update(name="x;reboot"), lambda s: s["nodes"][0]["ssh"].update(user="root;id"), lambda s: s["nodes"][0]["ssh"].update(private_key_ref="../../key"), lambda s: s["nodes"][0].update(ip="10.1.1.1;id")):
            value = specification()
            mutate(value)
            with self.assertRaises(SetupBlocked):
                validate(value)

    def test_rejects_reserved_database_names_and_async_rpo(self):
        for field in ("metadata_name", "traffic_name", "metadata_user", "traffic_user"):
            value = specification()
            value["database"] = {field: "postgres"}
            with self.assertRaises(SetupBlocked):
                validate(value)
        value = specification()
        value["rpo"] = "async"
        with self.assertRaises(SetupBlocked):
            validate(value)

    def test_requires_stable_https_origin_and_real_unicast_ip(self):
        for origin in ("http://example.test", "https://x/y", "https://u:p@x", "https://x?secret=1"):
            value = specification()
            value["controller_origin"] = origin
            with self.assertRaises(SetupBlocked):
                validate(value)
        for address in ("127.0.0.1", "0.0.0.0", "169.254.1.1", "224.0.0.1", "255.255.255.255", "::1"):
            value = specification()
            value["nodes"][0]["ip"] = address
            with self.assertRaises(SetupBlocked):
                validate(value)

    def test_topology_excludes_ssh_secrets_and_binds_site_role_and_addresses(self):
        value = validate(specification())
        original = canonical_digest(topology(value))
        value["nodes"][0]["ssh"]["private_key_ref"] = "other-key"
        self.assertEqual(original, canonical_digest(topology(value)))
        value["nodes"][0]["ip"] = "10.70.0.12"
        self.assertNotEqual(original, canonical_digest(topology(value)))


class SSHTests(unittest.TestCase):
    def test_pins_host_and_delivers_secret_only_in_stdin(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            key = root / "ssh.key"
            key.write_text("PRIVATE_KEY_SENTINEL")
            key.chmod(0o600)
            calls = []
            def execute(argv, **kwargs):
                calls.append((argv, kwargs))
                return subprocess.CompletedProcess(argv, 0, b'{"node_id":"db-a","status":"ok"}', b"")
            runner = SSHRunner(lambda ref: key, root / "ssh", command=execute)
            runner.run(validate(specification())["nodes"][0], "configure", {"secret": "DATABASE_SECRET_SENTINEL"})
            argv, arguments = calls[0]
            joined = " ".join(argv)
            self.assertIn("StrictHostKeyChecking=yes", joined)
            self.assertIn("ForwardAgent=no", joined)
            self.assertIn("ClearAllForwardings=yes", joined)
            self.assertIn("IdentitiesOnly=yes", joined)
            self.assertEqual(argv[-1], "sudo -n /usr/bin/python3 -")
            self.assertNotIn("DATABASE_SECRET_SENTINEL", joined)
            self.assertNotIn("PRIVATE_KEY_SENTINEL", joined)
            self.assertNotIn("shell", arguments)
            script = arguments["input"].decode()
            self.assertIn(base64.b64encode(b'{"action":"configure","secret":"DATABASE_SECRET_SENTINEL"}').decode(), script)
            known = next((root / "ssh").iterdir())
            self.assertEqual(stat.S_IMODE(known.stat().st_mode), 0o600)
            self.assertEqual(known.read_text(), "prthak-db-a " + HOST_KEY + "\n")

    def test_rejects_insecure_key_unknown_action_and_identity_response(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            key = root / "key"
            key.write_text("key")
            key.chmod(0o644)
            runner = SSHRunner(lambda ref: key, root / "ssh", command=lambda *args, **kwargs: None)
            with self.assertRaises(SetupBlocked):
                runner.run(validate(specification())["nodes"][0], "status", {})
            with self.assertRaises(SetupBlocked):
                runner.run(validate(specification())["nodes"][0], "shell", {})
            key.chmod(0o600)
            runner.command = lambda *args, **kwargs: subprocess.CompletedProcess([], 0, b'{"node_id":"other"}', b"")
            with self.assertRaises(NodeUnavailable):
                runner.run(validate(specification())["nodes"][0], "status", {})

    def test_redacts_ssh_stderr_and_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            key = root / "key"
            key.write_text("key")
            key.chmod(0o600)
            runner = SSHRunner(lambda ref: key, root / "ssh", command=lambda *args, **kwargs: subprocess.CompletedProcess([], 255, b"", b"password=secret driver details"))
            with self.assertRaises(NodeUnavailable) as raised:
                runner.run(validate(specification())["nodes"][0], "status", {})
            self.assertNotIn("secret", str(raised.exception))

    def test_raw_vault_key_is_ephemeral_and_never_on_command_line(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            key_data = b"-----BEGIN OPENSSH PRIVATE KEY-----\nPRIVATE_KEY_SENTINEL\n-----END OPENSSH PRIVATE KEY-----\n"
            seen = []
            def execute(argv, **kwargs):
                key = Path(argv[argv.index("-i") + 1])
                self.assertEqual(key.read_bytes(), key_data)
                self.assertEqual(stat.S_IMODE(key.stat().st_mode), 0o600)
                self.assertNotIn("PRIVATE_KEY_SENTINEL", " ".join(argv))
                seen.append(key)
                return subprocess.CompletedProcess(argv, 0, b'{"node_id":"db-a"}', b"")
            runner = SSHRunner(lambda ref: key_data, root / "ssh", command=execute)
            runner.run(validate(specification())["nodes"][0], "status", {})
            self.assertTrue(seen)
            self.assertFalse(seen[0].exists())


class ProvisionerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Real OpenSSL, local-only: proves the generated identities/key pairs and
        # private atomic material persist correctly. No SSH or service is touched.
        cls.directory = tempfile.TemporaryDirectory()
        cls.provider = FileMaterialProvider(cls.directory.name)
        cls.material = cls.provider(specification())

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def setUp(self):
        self.runner = FakeRunner()
        self.runner.ca_pin = self.material["ca_fingerprint"]
        self.provisioner = Provisioner(self.runner, lambda spec: copy.deepcopy(self.material), wait_seconds=0)

    def test_material_generation_is_private_persisted_and_bound_to_topology(self):
        self.assertEqual(self.provider(specification()), self.material)
        path = Path(self.directory.name) / specification()["cluster_id"] / "material.json"
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(ca_fingerprint(self.material["ca"]), self.material["ca_fingerprint"])
        value = specification()
        value["nodes"][1]["ip"] = "10.71.0.12"
        with self.assertRaises(SetupBlocked):
            self.provider(value)

    def test_blocked_inspection_prevents_all_mutations(self):
        self.runner.blocked = "db-b"
        result = self.provisioner.apply(specification())
        self.assertEqual(result["status"], "blocked")
        self.assertTrue(all(action == "inspect" for _, action, _ in self.runner.calls))

    def test_installs_configures_all_voters_before_starting_database(self):
        progress = []
        result = self.provisioner.apply(specification(), lambda value: progress.append(copy.deepcopy(value)))
        self.assertEqual(result["status"], "ready")
        actions = [action for _, action, _ in self.runner.calls]
        first_db = actions.index("start_database")
        self.assertEqual(actions[:first_db].count("start_etcd"), 3)
        self.assertEqual(actions[:first_db].count("configure"), 3)
        self.assertEqual(actions.count("start_database"), 2)
        self.assertNotIn("ca_key", json.dumps(self.runner.calls))
        self.assertTrue(all(not payload["material"]["passwords"] for node_id, action, payload in self.runner.calls if node_id == "witness" and "material" in payload))
        self.assertNotIn(self.material["passwords"]["admin"], json.dumps(result))
        self.assertNotIn(self.material["passwords"]["admin"], json.dumps(progress))

    def test_no_quorum_prevents_database_startup(self):
        self.runner.bad_quorum = True
        result = self.provisioner.apply(specification())
        self.assertEqual(result["status"], "blocked")
        self.assertNotIn("start_database", [action for _, action, _ in self.runner.calls])

    def test_two_primaries_or_unarmed_watchdog_never_reports_ready(self):
        self.runner.roles = True
        self.runner.two_primaries = True
        self.assertEqual(self.provisioner.status(specification())["status"], "degraded")
        self.runner.two_primaries = False
        self.runner.bad_watchdog = True
        self.assertEqual(self.provisioner.status(specification())["status"], "degraded")

    def test_missing_application_roles_do_not_report_cluster_ready(self):
        self.assertEqual(self.provisioner.status(specification())["status"], "degraded")
        self.runner.roles = True
        self.assertEqual(self.provisioner.status(specification())["status"], "ready")

    def test_failure_stops_later_phases_and_does_not_claim_rollback(self):
        self.runner.fail_action = "configure"
        result = self.provisioner.apply(specification())
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["phase"], "configure")
        self.assertNotIn("start_etcd", [action for _, action, _ in self.runner.calls])
        self.assertIn("No data directories were deleted", result["blockers"][0])

    def test_private_connections_use_both_nodes_verify_full_and_writer_selection(self):
        private = self.provisioner.private_connection_fields(specification())
        self.assertEqual(private["metadata"]["host"], "10.70.0.11,10.71.0.11")
        for name in ("metadata", "traffic"):
            self.assertEqual(private[name]["sslmode"], "verify-full")
            self.assertEqual(private[name]["target_session_attrs"], "read-write")
        self.assertNotEqual(private["metadata"]["password"], private["traffic"]["password"])

    def authorization(self, **override):
        spec = validate(specification())
        return JoinAuthorization(**{"cluster_id": spec["cluster_id"], "node_id": "db-b", "existing_node_ip": "10.70.0.11", "ca_fingerprint": self.material["ca_fingerprint"], "topology_digest": canonical_digest(topology(spec)), "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(), **override})

    def test_join_requires_consumed_code_not_json_or_existing_ip_alone(self):
        with self.assertRaises(SetupBlocked):
            self.provisioner.join_dr(specification(), "db-b", {"existing_node_ip": "10.70.0.11"})
        self.assertEqual(self.runner.calls, [])

    def test_join_rejects_expiry_foreign_ca_topology_or_ip(self):
        for change in ({"expires_at": (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()}, {"ca_fingerprint": "bad"}, {"existing_node_ip": "10.70.0.99"}, {"topology_digest": "bad"}):
            with self.assertRaises(SetupBlocked):
                self.provisioner.join_dr(specification(), "db-b", self.authorization(**change))

    def test_join_only_installs_predeclared_dr_and_never_changes_dcs_membership(self):
        self.runner.roles = True
        result = self.provisioner.join_dr(specification(), "db-b", self.authorization())
        self.assertEqual(result["status"], "ready")
        mutated = [(node, action) for node, action, _ in self.runner.calls if action not in ("inspect", "status", "create_roles")]
        self.assertTrue(mutated)
        self.assertTrue(all(node == "db-b" for node, _ in mutated))
        self.assertTrue(all(action in ("install", "configure", "start_etcd", "start_database") for _, action in mutated))

    def _interrupted_provisioner(self, corrupt=False):
        helper = helper_module()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = root / "state"
            existing = root / "owned.conf"
            existing.write_text("KNOWN_ORIGINAL_CONFIGURATION")
            selected = validate(specification())["nodes"][2]
            restored = []
            def configure_actuator(*args):
                restored.append(existing.read_text())
                existing.write_text("RETRIED_CONFIGURATION")
                return {"status": "configured"}
            class LocalHelperRunner(FakeRunner):
                def run(runner, node, action, payload):
                    response = super().run(node, action, payload)
                    if node["id"] == selected["id"]:
                        if action == "inspect":
                            return {**response, **helper.inspect(payload["spec"], node)}
                        if action == "install":
                            return {**response, **helper.install(payload["spec"], node)}
                        if action == "configure":
                            return {**response, **helper.configure(payload["spec"], node, payload["material"], payload.get("expected_recovery_snapshot"))}
                    return response
            runner = LocalHelperRunner()
            runner.ca_pin = self.material["ca_fingerprint"]
            provisioner = Provisioner(runner, lambda spec: copy.deepcopy(self.material), wait_seconds=0)
            with patch.object(helper, "STATE", state), patch.object(helper, "BASE", root / "config"), patch.object(helper, "JOURNAL", state / "setup.json"), patch.object(helper, "_configuration_paths", return_value=[existing]), patch.object(helper, "platform_check"), patch.object(helper.socket, "socket") as socket_factory, patch.object(helper, "_configure", side_effect=configure_actuator), patch.object(helper, "command") as command:
                socket_factory.return_value.__enter__.return_value.connect_ex.return_value = 1
                helper.checkpoint(validate(specification()), selected, "installed", installed=True)
                helper.begin_configuration(validate(specification()), selected)
                existing.write_text("INTERRUPTED_WRITE")
                if corrupt:
                    path = state / "config-transaction.json"
                    value = json.loads(path.read_text())
                    value["node_id"] = "foreign-node"
                    path.write_text(json.dumps(value))
                preview = provisioner.preview(specification())
                # Preview must never restore or mutate even a valid owned snapshot.
                self.assertEqual(existing.read_text(), "INTERRUPTED_WRITE")
                self.assertTrue(helper.load_journal(validate(specification()), selected)["config_pending"])
                if not corrupt:
                    unreviewed = provisioner.apply(specification())
                    self.assertEqual(unreviewed["status"], "blocked")
                    self.assertEqual(existing.read_text(), "INTERRUPTED_WRITE")
                result = provisioner.apply(specification(), expected_recovery_snapshots=preview.get("configuration_recovery", []))
                command.assert_not_called()
                if corrupt:
                    self.assertEqual(preview["status"], "blocked")
                    self.assertEqual(result["status"], "blocked")
                    self.assertFalse(any(action != "inspect" for _, action, _ in runner.calls))
                    self.assertEqual(existing.read_text(), "INTERRUPTED_WRITE")
                    self.assertEqual(restored, [])
                else:
                    self.assertEqual(preview["status"], "preview")
                    self.assertEqual(preview["configuration_recovery"][0]["node_id"], "witness")
                    self.assertEqual(len(preview["configuration_recovery"][0]["snapshot_digest"]), 64)
                    self.assertEqual(result["status"], "ready")
                    self.assertEqual(restored, ["KNOWN_ORIGINAL_CONFIGURATION"])
                    self.assertFalse(helper.load_journal(validate(specification()), selected)["config_pending"])

    def test_interrupted_owned_provisioner_preview_then_apply_recovers_exact_snapshot(self):
        self._interrupted_provisioner()

    def test_foreign_or_changed_pending_snapshot_blocks_provisioner_before_mutations(self):
        self._interrupted_provisioner(corrupt=True)


class FixedHelperTests(unittest.TestCase):
    def setUp(self):
        self.helper = helper_module()
        self.spec = validate(specification())
        self.node = self.spec["nodes"][0]

    def test_remote_helper_revalidates_digest_and_rejects_unknown_action(self):
        request = {"action": "inspect", "schema_version": 1, "spec": self.spec, "node_id": "db-a", "topology_digest": canonical_digest(topology(self.spec))}
        self.assertEqual(self.helper.validate_request(request)[1]["id"], "db-a")
        for changed in ({"action": "shell"}, {"topology_digest": "bad"}, {"node_id": "untrusted"}):
            with self.assertRaises(self.helper.Blocked):
                self.helper.validate_request({**request, **changed})

    def test_etcd_is_mutual_tls_on_both_channels_and_unique_cluster_token(self):
        config = self.helper.etcd_config(self.spec, self.node)
        self.assertFalse(config["enable-v2"])
        self.assertEqual(config["tls-min-version"], "TLS1.2")
        self.assertTrue(config["client-transport-security"]["client-cert-auth"])
        self.assertTrue(config["peer-transport-security"]["client-cert-auth"])
        self.assertIn(self.spec["cluster_id"], config["initial-cluster-token"])
        self.assertNotIn("http://", json.dumps(config))

    def test_patroni_requires_watchdog_strict_sync_scram_and_verified_replication(self):
        config = self.helper.patroni_config(self.spec, self.node, {"passwords": {"admin": "a" * 64, "replication": "r" * 64}})
        self.assertEqual(config["watchdog"], {"mode": "required", "device": "/dev/watchdog", "safety_margin": -1})
        self.assertTrue(config["bootstrap"]["dcs"]["synchronous_mode_strict"])
        self.assertTrue(config["bootstrap"]["dcs"]["check_timeline"])
        self.assertEqual(config["postgresql"]["authentication"]["replication"]["sslmode"], "verify-full")
        self.assertEqual(config["restapi"]["verify_client"], "required")
        self.assertEqual(config["postgresql"]["listen"], "10.70.0.11,127.0.0.1:5432")
        self.assertTrue(config["postgresql"]["pg_hba"][-1].endswith("reject"))
        self.assertFalse(any(line.endswith(" trust") for line in config["postgresql"]["pg_hba"]))

    def test_journal_refuses_other_cluster_and_remains_private(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary) / "state"
            with patch.object(self.helper, "STATE", state), patch.object(self.helper, "JOURNAL", state / "setup.json"):
                self.helper.checkpoint(self.spec, self.node, "installed", installed=True)
                self.assertEqual(stat.S_IMODE((state / "setup.json").stat().st_mode), 0o600)
                self.assertEqual(stat.S_IMODE(state.stat().st_mode), 0o711)
                changed = copy.deepcopy(self.spec)
                changed["cluster_id"] = "ee302cc8-2198-4c25-ab4c-bbcb961073dd"
                with self.assertRaises(self.helper.Blocked):
                    self.helper.load_journal(changed, self.node)

    def test_apt_origins_reject_third_party_and_local_packages(self):
        for url in ("https://packages.evil.test/etcd.deb", "file:///tmp/etcd.deb"):
            with patch.object(self.helper, "command", return_value="'" + url + "' file 1 SHA256:x\n"):
                with self.assertRaises(self.helper.Blocked):
                    self.helper.apt_origin_check(["etcd-server"])
        with patch.object(self.helper, "command", return_value="'http://ports.ubuntu.com/ubuntu-ports/pool/main/e/etcd.deb' file 1 SHA256:x\n"):
            self.helper.apt_origin_check(["etcd-server"])

    def test_no_secret_exception_or_traceback_is_returned(self):
        request = {"action": "status", "schema_version": 1, "spec": self.spec, "node_id": "db-a", "topology_digest": canonical_digest(topology(self.spec))}
        stream = io.StringIO()
        with patch.object(self.helper.os, "geteuid", return_value=0), patch.object(self.helper, "platform_check"), patch.object(self.helper, "status", side_effect=RuntimeError("PASSWORD_SENTINEL")), contextlib.redirect_stdout(stream):
            self.helper.main(request)
        self.assertNotIn("PASSWORD_SENTINEL", stream.getvalue())
        self.assertEqual(json.loads(stream.getvalue())["status"], "blocked")

    def test_scram_verifier_does_not_contain_password_and_salts_each_hash(self):
        first = self.helper.scram_password("PASSWORD_SENTINEL")
        second = self.helper.scram_password("PASSWORD_SENTINEL")
        self.assertTrue(first.startswith("SCRAM-SHA-256$4096:"))
        self.assertNotEqual(first, second)
        self.assertNotIn("PASSWORD_SENTINEL", first)

    def test_arm64_package_architecture_is_explicitly_blocked(self):
        def read(path, *args, **kwargs):
            return 'ID=ubuntu\nVERSION_ID="24.04"\n' if str(path) == "/etc/os-release" else "systemd\n"
        with patch.object(self.helper.Path, "read_text", read), patch.object(self.helper.os, "uname", return_value=SimpleNamespace(machine="aarch64")):
            with self.assertRaisesRegex(self.helper.Blocked, "AMD64"):
                self.helper.platform_check()

    def test_watchdog_alias_must_match_the_configured_watchdog0_without_opening_it(self):
        def device(path, *args, **kwargs):
            return SimpleNamespace(st_mode=stat.S_IFCHR | 0o600, st_rdev=11 if str(path) == "/dev/watchdog" else 12)
        with patch.object(self.helper.Path, "stat", device), patch.object(self.helper.os, "access", return_value=True), patch.object(self.helper.Path, "open", side_effect=AssertionError("Inspection must not arm a watchdog")):
            self.assertFalse(self.helper.device_ready(self.spec, self.node))
        with patch.object(self.helper.Path, "stat", return_value=SimpleNamespace(st_mode=stat.S_IFCHR | 0o600, st_rdev=11)), patch.object(self.helper.os, "access", return_value=True), patch.object(self.helper.Path, "open", side_effect=AssertionError("Inspection must not arm a watchdog")):
            self.assertTrue(self.helper.device_ready(self.spec, self.node))

    def test_configuration_failure_restores_exact_old_files_and_removes_new_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = root / "state"
            existing, new = root / "old.conf", root / "new.conf"
            existing.write_text("ORIGINAL_PRIVATE_CONFIGURATION")
            existing.chmod(0o600)
            node = self.spec["nodes"][2]  # witness: no real watchdog access
            def fail(*args):
                self.helper.atomic(existing, "PARTIAL_REPLACEMENT")
                self.helper.atomic(new, "NEW_PRIVATE_CONFIGURATION")
                raise self.helper.Blocked("Injected configuration failure")
            with patch.object(self.helper, "STATE", state), patch.object(self.helper, "JOURNAL", state / "setup.json"), patch.object(self.helper, "_configuration_paths", return_value=[existing, new]), patch.object(self.helper, "_configure", side_effect=fail), patch.object(self.helper, "validate_material"):
                self.helper.checkpoint(self.spec, node, "installed", installed=True)
                with self.assertRaisesRegex(self.helper.Blocked, "Injected"):
                    self.helper.configure(self.spec, node, {"ca": "ca", "certificate": "certificate", "private_key": "key", "passwords": {}})
                self.assertEqual(existing.read_text(), "ORIGINAL_PRIVATE_CONFIGURATION")
                self.assertFalse(new.exists())
                self.assertEqual(stat.S_IMODE(existing.stat().st_mode), 0o600)
                self.assertFalse(self.helper.load_journal(self.spec, node)["config_pending"])

    def test_interrupted_configuration_recovers_before_retry_and_cannot_start(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state, existing = root / "state", root / "old.conf"
            existing.write_text("ORIGINAL")
            node = self.spec["nodes"][2]
            def finish(*args):
                self.assertEqual(existing.read_text(), "ORIGINAL")
                return {"status": "configured"}
            with patch.object(self.helper, "STATE", state), patch.object(self.helper, "JOURNAL", state / "setup.json"), patch.object(self.helper, "_configuration_paths", return_value=[existing]), patch.object(self.helper, "_configure", side_effect=finish), patch.object(self.helper, "validate_material"), patch.object(self.helper, "command") as command:
                self.helper.checkpoint(self.spec, node, "installed", installed=True)
                self.helper.begin_configuration(self.spec, node)
                existing.write_text("INTERRUPTED_PRIVATE_WRITE")
                with self.assertRaises(self.helper.Blocked):
                    self.helper.start(self.spec, node)
                command.assert_not_called()
                self.helper.configure(self.spec, node, {"ca": "ca", "certificate": "certificate", "private_key": "key", "passwords": {}}, self.helper.load_journal(self.spec, node)["config_snapshot_digest"])
                self.assertEqual(existing.read_text(), "ORIGINAL")
                self.assertFalse(self.helper.load_journal(self.spec, node)["config_pending"])

    def test_idempotent_install_never_upgrades_running_owned_cluster(self):
        with patch.object(self.helper, "inspect", return_value={"blockers": []}), patch.object(self.helper, "load_journal", return_value={"installed": True}), patch.object(self.helper, "command") as command:
            self.assertEqual(self.helper.install(self.spec, self.node)["status"], "installed")
            command.assert_not_called()

    def test_retry_cannot_silently_rotate_established_database_credentials(self):
        with patch.object(self.helper, "load_journal", return_value={"material_digest": "old-credentials"}), patch.object(self.helper, "validate_material"), patch.object(self.helper, "begin_configuration") as begin:
            with self.assertRaisesRegex(self.helper.Blocked, "credential rotation"):
                self.helper.configure(self.spec, self.node, {"ca": "ca", "certificate": "certificate", "private_key": "key", "passwords": {"admin": "new-secret"}})
            begin.assert_not_called()

    def test_interrupted_package_guard_restores_original_on_owned_retry(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state, policy = root / "state", root / "policy-rc.d"
            policy.write_text("ORIGINAL_OPERATOR_SERVICE_POLICY")
            policy.chmod(0o700)
            with patch.object(self.helper, "STATE", state), patch.object(self.helper, "JOURNAL", state / "setup.json"), patch.object(self.helper, "PACKAGE_POLICY", policy), patch.object(self.helper, "inspect", return_value={"blockers": []}), patch.object(self.helper, "command") as command:
                self.helper.checkpoint(self.spec, self.node, "installed", installed=True)
                self.helper.begin_package_policy(self.spec, self.node)
                self.assertEqual(policy.read_bytes(), self.helper.TEMPORARY_POLICY)
                self.helper.read_package_policy_recovery(self.spec, self.node)
                self.assertEqual(policy.read_bytes(), self.helper.TEMPORARY_POLICY)  # read-only check
                self.assertEqual(self.helper.install(self.spec, self.node)["status"], "installed")
                self.assertEqual(policy.read_text(), "ORIGINAL_OPERATOR_SERVICE_POLICY")
                self.assertEqual(stat.S_IMODE(policy.stat().st_mode), 0o700)
                self.assertFalse(self.helper.load_journal(self.spec, self.node)["package_policy_pending"])
                command.assert_not_called()

    def test_temporary_package_guard_is_removed_when_no_original_existed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state, policy = root / "state", root / "policy-rc.d"
            with patch.object(self.helper, "STATE", state), patch.object(self.helper, "JOURNAL", state / "setup.json"), patch.object(self.helper, "PACKAGE_POLICY", policy):
                self.helper.checkpoint(self.spec, self.node, "installing")
                self.helper.begin_package_policy(self.spec, self.node)
                self.assertTrue(policy.exists())
                self.helper.restore_package_policy(self.spec, self.node)
                self.assertFalse(policy.exists())

    def test_package_guard_recovery_never_overwrites_operator_changes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state, policy = root / "state", root / "policy-rc.d"
            with patch.object(self.helper, "STATE", state), patch.object(self.helper, "JOURNAL", state / "setup.json"), patch.object(self.helper, "PACKAGE_POLICY", policy):
                self.helper.checkpoint(self.spec, self.node, "installing")
                self.helper.begin_package_policy(self.spec, self.node)
                policy.write_text("NEW_OPERATOR_POLICY")
                with self.assertRaisesRegex(self.helper.Blocked, "changed after interruption"):
                    self.helper.restore_package_policy(self.spec, self.node)
                self.assertEqual(policy.read_text(), "NEW_OPERATOR_POLICY")


if __name__ == "__main__":
    unittest.main()
