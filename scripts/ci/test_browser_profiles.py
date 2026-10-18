"""Protect daily browser coverage against accidentally dropped matrix cells."""

from pathlib import Path
import unittest

import yaml
from check_workflows import matrix_rows, validate

ROOT = Path(__file__).resolve().parents[2]


class BrowserProfileWorkflowTests(unittest.TestCase):
    def test_regular_ci_runs_the_fast_shared_tools(self):
        workflow = yaml.safe_load((ROOT / ".github/workflows/CI.yml").read_text())
        steps = workflow["jobs"]["precheck-docs"]["steps"]
        step = next(
            step for step in steps if step.get("run") == "just test-profile-tools"
        )
        self.assertFalse(step.get("continue-on-error", False))

    def test_daily_native_uses_the_local_recipe_and_export_directory(self):
        workflow = yaml.safe_load(
            (ROOT / ".github/workflows/CI-platforms-daily.yml").read_text()
        )
        job = workflow["jobs"]["test-native-relay-contract"]
        commands = [step.get("run", "") for step in job["steps"]]
        command = next(
            command
            for command in commands
            if "just test-native-relay-contract" in command
        )
        for argument in (
            "$RUNNER_TEMP/native-relay",
            "matrix.scenario.protocol",
            "matrix.mode",
            "matrix.scenario.quic_version",
        ):
            self.assertIn(argument, command)
        self.assertFalse(any("native_relay/run.py" in command for command in commands))
        upload = next(
            step
            for step in job["steps"]
            if step.get("uses", "").startswith("actions/upload-artifact@")
        )
        self.assertEqual(
            upload["with"]["path"], "${{ runner.temp }}/native-relay/artifacts/"
        )
        self.assertEqual(upload["if"], "always()")

    def test_browserstack_checks_shared_automation_before_remote_sessions(self):
        path = ROOT / ".github/workflows/BrowserStack.yml"
        workflow = yaml.safe_load(path.read_text())
        validate(workflow, path)
        steps = workflow["jobs"]["run"]["steps"]
        preflight = next(
            index
            for index, step in enumerate(steps)
            if step.get("run") == "python scripts/ci/check_browser_automation.py"
        )
        journey = next(
            index
            for index, step in enumerate(steps)
            if "just browserstack-rama-fp" in step.get("run", "")
        )
        self.assertLess(preflight, journey)
        recipe = (ROOT / "justfile").read_text()
        self.assertIn("browserstack-rama-fp OUTPUT:", recipe)
        self.assertIn(
            "python3 rama-fp/browserstack/main.py --output {{quote(OUTPUT)}}", recipe
        )
        self.assertTrue(
            any(
                step.get("uses", "").startswith("taiki-e/install-action@")
                and step.get("with", {}).get("tool") == "just"
                for step in steps
            )
        )
        self.assertEqual(
            steps[journey]["run"],
            'just browserstack-rama-fp "$RUNNER_TEMP/browserstack-evidence"',
        )
        uploads = [
            step for step in steps if step.get("name") == "Preserve per-cell receipts"
        ]
        self.assertEqual(len(uploads), 1)
        upload = uploads[0]
        self.assertEqual(upload["if"], "always()")
        self.assertEqual(
            upload["with"]["path"], "${{ runner.temp }}/browserstack-evidence/"
        )
        self.assertFalse(steps[preflight].get("continue-on-error", False))
        self.assertNotIn("env", steps[preflight])

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
