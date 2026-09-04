#!/usr/bin/env python3

import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile
import textwrap
import unittest


SCRIPT_DIR = Path(__file__).resolve().parent
STRESS_SCRIPT = SCRIPT_DIR / "stress_traffic.sh"
SOAK_SCRIPT = SCRIPT_DIR / "soak_test.sh"


class StressTrafficValidationTests(unittest.TestCase):
    def run_stress(self, log_dir: Path, **overrides: str) -> subprocess.CompletedProcess:
        env = os.environ.copy()
        env.update(STRESS_LOG_DIR=str(log_dir), **overrides)
        return subprocess.run(
            ["bash", str(STRESS_SCRIPT)],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=10,
        )

    def test_rejects_ambiguous_overflowing_and_impractical_values_before_io(self):
        cases = (
            ({"STRESS_DURATION": ""}, "canonical"),
            ({"STRESS_DURATION": "08"}, "canonical"),
            ({"STRESS_DURATION": "999999999999999999999999"}, "at most 86400"),
            ({"STRESS_CONCURRENCY": "513"}, "at most 512"),
            ({"STRESS_LARGE_BYTES": "1073741825"}, "at most 1073741824"),
            ({"STRESS_POST_BYTES": "00"}, "canonical"),
            ({"STRESS_MONITOR_PID": "0"}, "greater than zero"),
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            for index, (overrides, expected) in enumerate(cases):
                log_dir = root / f"invalid-{index}"
                result = self.run_stress(log_dir, **overrides)
                self.assertEqual(result.returncode, 2, result.stdout)
                self.assertIn(expected, result.stdout)
                self.assertFalse(log_dir.exists(), result.stdout)

    def test_rejects_non_boolean_liveness_flag(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            log_dir = Path(temp_dir) / "invalid-boolean"
            result = self.run_stress(log_dir, STRESS_SKIP_LIVENESS="true")
            self.assertEqual(result.returncode, 2, result.stdout)
            self.assertIn("must be 0 or 1", result.stdout)
            self.assertFalse(log_dir.exists(), result.stdout)

    def test_every_enabled_worker_reports_progress(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            fake_curl = fake_bin / "curl"
            fake_curl.write_text(
                textwrap.dedent(
                    """\
                    #!/usr/bin/env bash
                    sleep 0.05
                    printf '204'
                    """
                )
            )
            fake_curl.chmod(0o755)
            log_dir = root / "logs"
            result = self.run_stress(
                log_dir,
                PATH=f"{fake_bin}{os.pathsep}{os.environ['PATH']}",
                STRESS_DURATION="1",
                STRESS_CONCURRENCY="1",
                STRESS_POST_BYTES="1024",
                STRESS_SKIP_LIVENESS="1",
            )
            self.assertEqual(result.returncode, 0, result.stdout)
            summaries = sorted(log_dir.glob("*.summary"))
            self.assertEqual(len(summaries), 8, result.stdout)
            for summary in summaries:
                match = re.fullmatch(
                    r"\S+ done: iters=(\d+) ok=(\d+) fail=(\d+)\n?",
                    summary.read_text(),
                )
                self.assertIsNotNone(match, summary.read_text())
                iterations, ok, failed = map(int, match.groups())
                self.assertGreater(iterations, 0, summary.read_text())
                self.assertEqual(iterations, ok + failed, summary.read_text())


class SoakConfigurationValidationTests(unittest.TestCase):
    @staticmethod
    def soak_function(shell: str, name: str) -> str:
        start = shell.index(f"{name}() {{")
        end = shell.index("\n}\n", start) + 3
        return shell[start:end]

    def test_rejects_invalid_numeric_and_boolean_configuration_before_io(self):
        cases = (
            ({"STRESS_SECONDS": ""}, "canonical"),
            ({"STRESS_SECONDS": "08"}, "canonical"),
            ({"IDLE_TAIL": "999999999999999999999999"}, "at most 86400"),
            ({"FANOUT_TARGET": "1025"}, "at most 1024"),
            ({"SKIP_SLEEP": "yes"}, "must be 0 or 1"),
            (
                {"STRESS_SECONDS": "0", "SKIP_STRESS": "0"},
                "greater than zero when the stress phase is enabled",
            ),
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            for index, (overrides, expected) in enumerate(cases):
                output_dir = root / f"invalid-{index}"
                env = os.environ.copy()
                env.update(OUT=str(output_dir), **overrides)
                result = subprocess.run(
                    ["bash", str(SOAK_SCRIPT)],
                    env=env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    timeout=5,
                )
                self.assertEqual(result.returncode, 2, result.stdout)
                self.assertIn(expected, result.stdout)
                self.assertFalse(output_dir.exists(), result.stdout)

    def test_bounded_child_join_accepts_term_and_rejects_forced_kill(self):
        shell = SOAK_SCRIPT.read_text()
        start = shell.index("child_job_is_active() {")
        end = shell.index("# ── Helpers", start)
        helpers = shell[start:end]
        python = shlex.quote(sys.executable)

        def join_result(child: str, timeout: int) -> tuple[str, str, str, str]:
            program = (
                helpers
                + "\n"
                + child
                + " &\npid=$!\nsleep 0.1\n"
                + f'bounded_stop_and_join "$pid" {timeout} direct\n'
                + "printf '%s %s %s %s\\n' \"$BOUNDED_CHILD_RC\" "
                + '"$BOUNDED_CHILD_OK" "$BOUNDED_CHILD_REAPED" '
                + '"$BOUNDED_CHILD_FORCED"\n'
            )
            result = subprocess.run(
                ["bash", "-c", program],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=6,
            )
            self.assertEqual(result.returncode, 0, result.stdout)
            return tuple(result.stdout.splitlines()[-1].split())

        self.assertEqual(
            join_result(f"{python} -c 'import time; time.sleep(30)'", 2),
            ("143", "1", "1", "0"),
        )
        self.assertEqual(
            join_result(f"{python} -c 'pass'", 2),
            ("0", "1", "1", "0"),
        )
        self.assertEqual(
            join_result(
                f"{python} -c 'import signal,time; "
                "signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(30)'",
                1,
            ),
            ("137", "0", "1", "1"),
        )

    def test_equal_caps_use_effective_headroom_and_reachable_auto_targets(self):
        shell = SOAK_SCRIPT.read_text()
        helpers = "\n".join(
            self.soak_function(shell, name)
            for name in (
                "cap_validation_hard_limited",
                "flow_pool_expected_contribution",
                "auto_target",
            )
        )
        program = helpers + textwrap.dedent(
            """
            classify() {
              if cap_validation_hard_limited "$@"; then
                printf 'limited\\n'
              else
                printf 'validate\\n'
              fi
            }
            classify 80 80 5 5
            classify 80 80 5 6
            classify 80 79 5 5
            classify 80 90 5 6
            flow_pool_expected_contribution 100 80 80 5 5
            flow_pool_expected_contribution 100 80 80 5 6
            flow_pool_expected_contribution 100 80 79 5 5

            SOFTCAP_KNOWN=1; MAX_SAFE_FLOWS=200
            SOFTCAP=80; HARDCAP=80; BASELINE_TOTAL=5; auto_target
            SOFTCAP=80; HARDCAP=80; BASELINE_TOTAL=6; auto_target
            SOFTCAP=80; HARDCAP=90; BASELINE_TOTAL=5; auto_target
            SOFTCAP=80; HARDCAP=0; BASELINE_TOTAL=5; auto_target
            SOFTCAP=10; HARDCAP=10; BASELINE_TOTAL=5; auto_target
            SOFTCAP=80; HARDCAP=80; BASELINE_TOTAL=80
            if auto_target; then printf 'unsafe\\n'; else printf 'unavailable\\n'; fi
            """
        )
        result = subprocess.run(
            ["bash", "-c", program],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=5,
        )
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual(
            result.stdout.splitlines(),
            [
                "validate",
                "limited",
                "limited",
                "validate",
                "75",
                "74",
                "0",
                "75",
                "74",
                "85",
                "100",
                "5",
                "unavailable",
            ],
        )


if __name__ == "__main__":
    unittest.main()
