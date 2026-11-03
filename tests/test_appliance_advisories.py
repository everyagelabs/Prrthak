"""The release scan gate retains and rejects findings without severity exceptions."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('appliance_advisories', ROOT / 'scripts/check-appliance-advisories.py')
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)


class ApplianceAdvisoryGateTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.clean = {'SchemaVersion': 2, 'ArtifactType': 'container_image',
                      'Metadata': {'OS': {'Family': 'alpine', 'Name': '3.24.3'}},
                      'Results': [{'Target': 'alpine', 'Class': 'os-pkgs', 'Vulnerabilities': []}]}
        for component in gate.COMPONENTS:
            self.write(component, self.clean)

    def write(self, component, value):
        (self.directory / (component + '.json')).write_text(json.dumps(value))

    def cli(self):
        return subprocess.run([sys.executable, str(ROOT / 'scripts/check-appliance-advisories.py'), str(self.directory)],
                              capture_output=True, text=True, timeout=10)

    def test_complete_zero_finding_reports_pass_without_rewriting_evidence(self):
        before = {path.name: path.read_bytes() for path in self.directory.iterdir()}
        result = self.cli()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)['total_advisory_rows'], 0)
        self.assertEqual(before, {path.name: path.read_bytes() for path in self.directory.iterdir()})

    def test_all_severities_and_unfixed_advisories_fail_and_remain_visible(self):
        for severity in ('UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'):
            with self.subTest(severity=severity):
                report = copy.deepcopy(self.clean)
                report['Results'][0]['Vulnerabilities'] = [{'VulnerabilityID': 'CVE-test', 'PkgName': 'retained-package',
                                                          'Severity': severity, 'Status': 'affected'}]
                self.write('database', report)
                result = self.cli()
                self.assertEqual(result.returncode, 1)
                assessment = json.loads(result.stdout)
                self.assertEqual(assessment['total_advisory_rows'], 1)
                self.assertEqual(assessment['images']['database']['findings'][0]['Severity'], severity)

    def test_missing_or_extra_reports_fail_closed(self):
        (self.directory / 'etcd.json').unlink()
        with self.assertRaises(ValueError):
            gate.assess(self.directory)
        self.write('etcd', self.clean)
        self.write('unreviewed', self.clean)
        self.assertNotEqual(self.cli().returncode, 0)

    def test_empty_malformed_or_non_container_evidence_fails_closed(self):
        invalid = [{}, {**self.clean, 'Results': []}, {**self.clean, 'Metadata': {}},
                   {**self.clean, 'ArtifactType': 'filesystem'},
                   {**self.clean, 'Results': [{'Vulnerabilities': {'unexpected': 'mapping'}}]},
                   {**self.clean, 'Results': [{'Vulnerabilities': [{}]}]}]
        for report in invalid:
            with self.subTest(report=report):
                self.write('controller', report)
                self.assertNotEqual(self.cli().returncode, 0)

    def test_symlinked_report_is_not_accepted(self):
        path = self.directory / 'controller.json'
        path.unlink()
        path.symlink_to(self.directory / 'database.json')
        with self.assertRaises(ValueError):
            gate.assess(self.directory)

    def test_unknown_os_version_or_end_of_support_cannot_pass_with_zero_findings(self):
        for os_info in ({'Family': 'alpine'}, {'Family': 'alpine', 'Name': 'old', 'EOSL': True}):
            with self.subTest(os_info=os_info):
                report = copy.deepcopy(self.clean)
                report['Metadata']['OS'] = os_info
                self.write('database', report)
                result = self.cli()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('supported container/OS', result.stderr)


if __name__ == '__main__':
    unittest.main()
