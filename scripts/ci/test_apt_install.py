"""Exercise the apt action's retries without network or root access."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest

ACTION = Path(__file__).resolve().parents[2] / ".github/actions/apt-install/action.yml"

MOCK = r"""
import json
import os
from pathlib import Path
import sys

state = Path(os.environ["APT_CALLS"])
calls = json.loads(state.read_text()) if state.exists() else []
args = sys.argv[1:]
calls.append(args)
state.write_text(json.dumps(calls))
if "update" in args:
    updates = sum("update" in call for call in calls)
    if updates <= int(os.environ["FAILED_UPDATES"]):
        print("W: Failed to fetch PPA index: 503 Service Unavailable", file=sys.stderr)
        # apt treats incomplete index downloads as warnings by default.
        sys.exit(100 if "--error-on=any" in args else 0)
"""


class AptInstallTests(unittest.TestCase):
    def run_action(self, failed_updates):
        script = textwrap.dedent(ACTION.read_text().split("      run: |\n", 1)[1])
        with tempfile.TemporaryDirectory() as directory:
            mock = Path(directory) / "apt.py"
            mock.write_text(MOCK)
            calls = Path(directory) / "calls.json"
            env = dict(os.environ, PACKAGES="tshark", FAILED_UPDATES=str(failed_updates),
                       APT_CALLS=str(calls), MOCK_APT=str(mock), PYTHON=sys.executable)
            # Keep the actual action, including argument construction and retry
            # bounds; replace only privileged/network operations and sleeps.
            shell = r'''
set -euo pipefail
sudo() {
    if [[ "$1" != env ]]; then return 0; fi
    while [[ "$1" != apt-get ]]; do shift; done
    shift
    "$PYTHON" "$MOCK_APT" "$@"
}
sleep() { :; }
'''
            result = subprocess.run(["bash", "-c", shell + script], env=env,
                                    capture_output=True, text=True, timeout=10)
            return result, json.loads(calls.read_text())

    def test_partial_index_failure_retries_before_installing(self):
        result, calls = self.run_action(1)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("update", calls[0])
        self.assertIn("update", calls[1])
        self.assertEqual(sum("update" in call for call in calls), 2)
        self.assertEqual(sum("install" in call for call in calls), 2)
        self.assertIn("--download-only", calls[2])
        self.assertNotIn("--download-only", calls[3])

    def test_unavailable_index_exhausts_retries_without_installing(self):
        result, calls = self.run_action(4)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(len(calls), 4)
        self.assertTrue(all("update" in call for call in calls))
        self.assertIn("could not fetch packages after 4 attempts", result.stdout)


if __name__ == "__main__":
    unittest.main()
