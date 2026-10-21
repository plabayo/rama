"""A stale or cancelled workflow run must not hide the latest main failure."""

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class StatusMirrorTests(unittest.TestCase):
    def test_badge_mirrors_the_newest_finished_main_push_run(self):
        command = (ROOT / "scripts/ci/mirror-status.sh").read_text()
        repo = "plabayo/rama"

        def run(number, conclusion, attempt=1, event="push", branch="main",
                status="completed", owner=repo):
            return {"id": number * 10 + attempt, "workflow_id": 7, "run_number": number,
                    "run_attempt": attempt, "event": event, "head_branch": branch,
                    "status": status, "conclusion": conclusion,
                    "head_repository": {"full_name": owner}}

        def mirror(trigger, listed, failures=0, pages=None):
            with tempfile.TemporaryDirectory() as tmp:
                bin_dir = Path(tmp)
                for number, page in enumerate(pages or [listed], start=1):
                    (bin_dir / f"runs_{number}.json").write_text(json.dumps({"workflow_runs": page}))
                (bin_dir / "event.json").write_text(json.dumps({"workflow_run": trigger}))
                (bin_dir / "gh").write_text(
                    "#!/usr/bin/env bash\n"
                    f'n=$(cat "{tmp}/calls" 2>/dev/null || echo 0); echo $((n + 1)) > "{tmp}/calls"\n'
                    f"(( n < {failures} )) && exit 1\n"
                    'page=$(sed -n "s/.*[?&]page=\\([0-9]*\\).*/\\1/p" <<<"$2")\n'
                    f'cat "{tmp}/runs_${{page:-1}}.json" 2>/dev/null || echo \'{{"workflow_runs": []}}\'\n')
                (bin_dir / "sleep").write_text("#!/usr/bin/env bash\n")
                for stub in ("gh", "sleep"):
                    (bin_dir / stub).chmod(0o755)
                result = subprocess.run(
                    ["bash", "-e", "-c", command], capture_output=True, text=True,
                    env={"PATH": f"{tmp}:{os.environ['PATH']}", "GITHUB_REPOSITORY": repo,
                         "GITHUB_EVENT_PATH": str(bin_dir / "event.json")})
                return result.returncode == 0

        cases = [
            # The listing has not caught up with the run that triggered this.
            ("fresh payload", run(5, "success"), [run(4, "failure")], True),
            ("cancelled payload, older success", run(5, "cancelled"), [run(4, "success")], True),
            ("cancelled payload, older failure", run(5, "cancelled"), [run(4, "failure")], False),
            ("newer finished run", run(4, "success"), [run(5, "failure")], False),
            ("newer finished attempt", run(4, "success"), [run(4, "failure", attempt=2)], False),
            ("stale listed attempt", run(4, "success", attempt=2), [run(4, "failure")], True),
            ("newer run in progress", run(4, "success"),
             [run(5, None, status="in_progress")], True),
            ("non-push trigger", run(6, "success", event="workflow_dispatch"),
             [run(5, "failure")], False),
            ("fork branch named main", run(4, "success"),
             [run(5, "failure", owner="someone/rama")], True),
            ("nothing finished", run(4, "cancelled"), [], False),
        ]
        for name, trigger, listed, success in cases:
            with self.subTest(case=name):
                self.assertEqual(mirror(trigger, listed), success)
        # A hundred newer pull request runs push the newest main push to the next page.
        pulls = [run(100 + n, "failure", event="pull_request", branch=f"pr-{n}") for n in range(100)]
        for name, older, success in [
            ("second page success", [run(4, "success")], True),
            ("second page failure", [run(4, "failure")], False),
            ("nothing on the second page", [], False),
        ]:
            with self.subTest(case=name):
                self.assertEqual(mirror(run(5, "cancelled"), None, pages=[pulls, older]), success)
        with self.subTest(case="listing retried"):
            self.assertTrue(mirror(run(5, "success"), [], failures=2))
        with self.subTest(case="listing unavailable"):
            self.assertFalse(mirror(run(5, "success"), [], failures=3))

if __name__ == "__main__":
    unittest.main()
