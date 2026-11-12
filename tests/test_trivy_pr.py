import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/check_trivy_pr.py'


class PullRequestSecurityScanTests(unittest.TestCase):
    def run_check(self, code, infrastructure, code_outcome='success'):
        with tempfile.TemporaryDirectory() as directory:
            code_path = Path(directory) / 'code.json'
            infra_path = Path(directory) / 'infrastructure.json'
            code_path.write_text(json.dumps(code))
            infra_path.write_text(json.dumps(infrastructure))
            return subprocess.run(
                [sys.executable, str(SCRIPT), '--code', str(code_path),
                 '--infrastructure', str(infra_path), '--code-outcome', code_outcome,
                 '--infrastructure-outcome', 'success'],
                capture_output=True, text=True, check=False)

    def test_high_finding_blocks_without_exposing_details(self):
        code = {'SchemaVersion': 2, 'Results': [
            {'Target': 'private-file', 'Vulnerabilities': [
                {'Severity': 'HIGH', 'Title': 'private-detail'}]}]}
        result = self.run_check(code, {'SchemaVersion': 2})
        self.assertEqual(result.returncode, 1)
        self.assertIn('| Dependencies | 0 | 1 |', result.stdout)
        self.assertNotIn('private-file', result.stdout)
        self.assertNotIn('private-detail', result.stdout)

    def test_failed_scan_never_reports_clean(self):
        result = self.run_check({'SchemaVersion': 2}, {'SchemaVersion': 2}, 'failure')
        self.assertEqual(result.returncode, 2)
        self.assertIn('incomplete', result.stdout)

    def test_unexpected_category_is_rejected(self):
        code = {'SchemaVersion': 2, 'Results': [{'Misconfigurations': [
            {'Severity': 'LOW'}]}]}
        result = self.run_check(code, {'SchemaVersion': 2})
        self.assertEqual(result.returncode, 2)


if __name__ == '__main__':
    unittest.main()
