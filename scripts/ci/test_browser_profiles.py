"""Protect daily browser coverage against accidentally dropped matrix cells."""

from pathlib import Path
import unittest

import yaml
from check_workflows import matrix_rows, validate

ROOT = Path(__file__).resolve().parents[2]


class BrowserProfileWorkflowTests(unittest.TestCase):
    def test_daily_covers_both_cli_modes_and_every_implemented_protocol(self):
        path = ROOT / ".github/workflows/CI-platforms-daily.yml"
        workflow = yaml.safe_load(path.read_text())
        validate(workflow, path)
        job = workflow["jobs"]["test-browser-profiles"]
        actual = {
            (row["browser"], row["protocol"], row["mode"])
            for row in matrix_rows(job["strategy"]["matrix"])
        }
        required = {
            (browser, protocol, mode)
            for browser, protocol in [
                ("chrome", "h1"),
                ("firefox", "h1"),
                ("firefox", "h2"),
                ("chrome", "h2"),
                ("chrome", "h3"),
            ]
            for mode in ("debug", "release")
        }
        self.assertEqual(actual, required)
        self.assertFalse(job.get("continue-on-error", False))
        self.assertTrue(
            any(
                step.get("run") == "python scripts/ci/check_browser_automation.py"
                for step in job["steps"]
            )
        )
        runtime = next(
            step
            for step in job["steps"]
            if step.get("name") == "Capture and verify all six operations"
        )
        self.assertFalse(runtime.get("continue-on-error", False))
        self.assertIn("--flows all", runtime["run"])
        self.assertIn("examples/tests/browser_profile/run.py", runtime["run"])
        self.assertIn('--protocol "$PROTOCOL"', runtime["run"])
        self.assertIn('--browser "$BROWSER"', runtime["run"])
        self.assertNotIn("_h1.py", runtime["run"])


if __name__ == "__main__":
    unittest.main()
