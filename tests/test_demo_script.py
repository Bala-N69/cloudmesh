import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class DemoScriptTests(unittest.TestCase):
    def test_writes_mixed_report_and_explains_gate(self):
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(["bash", str(ROOT / "scripts/run-demo.sh")],
                                    cwd=directory, env=dict(os.environ, TMPDIR=directory),
                                    capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("CI gate: FAIL as expected", result.stdout)
            report_line = next(line for line in result.stdout.splitlines() if line.startswith("Demo report: "))
            report = Path(report_line.removeprefix("Demo report: "))
            self.assertEqual(report.parent, Path(directory))
            content = report.read_text()
            self.assertIn("gcp&#45;identity&#45;risk&#45;plan&#46;json", content)
            self.assertIn("kubernetes&#45;risky&#46;json", content)
            self.assertIn("kubernetes&#45;safe&#46;json", content)
            self.assertIn("HIGH", content)
