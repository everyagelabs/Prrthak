#!/usr/bin/env python3
"""Fail closed on missing scan evidence or any appliance vulnerability finding.

Raw Trivy JSON remains the review artifact. There are no ignored severities,
unfixed exceptions, package exclusions, VEX overrides or advisory allowlists.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

COMPONENTS = ('controller', 'database', 'router', 'etcd')


def assess(directory: Path) -> dict:
    paths = {path.name for path in directory.glob('*.json')}
    if paths != {component + '.json' for component in COMPONENTS}:
        raise ValueError('Complete controller, database, router and etcd scan reports are required')
    reports = {}
    for component in COMPONENTS:
        path = directory / (component + '.json')
        if path.is_symlink() or not path.is_file():
            raise ValueError('Each scan report must be a regular JSON file')
        report = json.loads(path.read_text())
        if (not isinstance(report, dict) or report.get('SchemaVersion') != 2
                or report.get('ArtifactType') != 'container_image'
                or not isinstance(report.get('Metadata', {}).get('OS'), dict)
                or not report['Metadata']['OS'].get('Family')
                or not report['Metadata']['OS'].get('Name')
                or report['Metadata']['OS'].get('EOSL') is True
                or not isinstance(report.get('Results'), list) or not report['Results']):
            raise ValueError('A complete supported container/OS vulnerability scan is required for ' + component)
        rows = []
        for result in report['Results']:
            if not isinstance(result, dict):
                raise ValueError('Malformed scanner result for ' + component)
            findings = result.get('Vulnerabilities')
            if findings is not None and not isinstance(findings, list):
                raise ValueError('Malformed vulnerability rows for ' + component)
            for finding in findings or []:
                if not isinstance(finding, dict) or not finding.get('VulnerabilityID'):
                    raise ValueError('Malformed vulnerability evidence for ' + component)
                rows.append({key: finding.get(key) for key in (
                    'VulnerabilityID', 'PkgName', 'InstalledVersion', 'FixedVersion', 'Severity', 'Status')})
        reports[component] = {'advisory_rows': len(rows), 'findings': rows}
    return {'images': reports, 'total_advisory_rows': sum(item['advisory_rows'] for item in reports.values())}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    args = parser.parse_args()
    try:
        result = assess(args.directory)
    except (OSError, ValueError, TypeError, AttributeError) as error:
        parser.exit(1, 'Appliance assessment blocked: ' + str(error) + '\n')
    print(json.dumps(result, sort_keys=True))
    return int(result['total_advisory_rows'] != 0)


if __name__ == '__main__':
    raise SystemExit(main())
