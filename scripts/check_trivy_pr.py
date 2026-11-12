"""Summarize pull request Trivy scans without publishing raw findings."""

import argparse
from collections import Counter
import json
from pathlib import Path
import sys

FIELDS = {'Vulnerabilities': 'Dependencies', 'Secrets': 'Secrets',
          'Misconfigurations': 'Infrastructure'}
SEVERITIES = ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN')


def count_findings(path, allowed):
    if not path.is_file() or path.stat().st_size > 32 * 1024 * 1024:
        raise ValueError('Missing or oversized Trivy report')
    report = json.loads(path.read_text())
    if not isinstance(report, dict) or type(report.get('SchemaVersion')) is not int or report['SchemaVersion'] != 2:
        raise ValueError('Invalid Trivy report')
    results = report.get('Results', [])
    if not isinstance(results, list):
        raise ValueError('Invalid Trivy results')
    counts = Counter()
    for result in results:
        if not isinstance(result, dict):
            raise ValueError('Invalid Trivy result')
        for field, label in FIELDS.items():
            findings = result.get(field) or []
            if not isinstance(findings, list) or (field not in allowed and findings):
                raise ValueError('Unexpected finding category')
            for finding in findings:
                if not isinstance(finding, dict) or finding.get('Severity') not in SEVERITIES:
                    raise ValueError('Invalid finding severity')
                counts[label, finding['Severity']] += 1
    return counts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--code', type=Path, required=True)
    parser.add_argument('--infrastructure', type=Path, required=True)
    parser.add_argument('--code-outcome', required=True)
    parser.add_argument('--infrastructure-outcome', required=True)
    args = parser.parse_args()
    try:
        if args.code_outcome != 'success' or args.infrastructure_outcome != 'success':
            raise ValueError('Scanner step failed')
        counts = count_findings(args.code, {'Vulnerabilities', 'Secrets'})
        counts.update(count_findings(args.infrastructure, {'Misconfigurations'}))
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        print('Security scan incomplete. Inspect scanner steps; no clean result is established.')
        return 2

    print('## Pull request security scan\n')
    print('| Category | Critical | High | Medium | Low | Unknown |')
    print('| --- | ---: | ---: | ---: | ---: | ---: |')
    for label in FIELDS.values():
        values = ' | '.join(str(counts[label, severity]) for severity in SEVERITIES)
        print(f'| {label} | {values} |')
    blocked = sum(counts[label, severity] for label in FIELDS.values()
                  for severity in ('CRITICAL', 'HIGH'))
    print(f'\nHIGH or CRITICAL findings: {blocked}.')
    return int(blocked > 0)


if __name__ == '__main__':
    sys.exit(main())
