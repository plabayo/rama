#!/usr/bin/env python3

import os
from pathlib import Path
import re
import signal
import shlex
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest


SCRIPT_DIR = Path(__file__).resolve().parent
STRESS_SCRIPT = SCRIPT_DIR / "stress_traffic.sh"
SOAK_SCRIPT = SCRIPT_DIR / "soak_test.sh"


class StressTrafficValidationTests(unittest.TestCase):
    @staticmethod
    def stress_function(shell: str, name: str) -> str:
        start = shell.index(f"{name}() {{")
        end = shell.index("\n}\n", start) + 3
        return shell[start:end]

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
            ({"STRESS_DURATION": "1", "STRESS_POST_BYTES": "0"}, "greater than zero"),
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
                    downloaded=1
                    uploaded=0
                    version=1.1
                    output=/dev/null
                    body=""
                    previous=""
                    for argument in "$@"; do
                      [[ "$argument" == --http2 ]] && version=2
                      if [[ "$argument" == *'size=1024'* ]]; then
                        downloaded=1024
                      fi
                      if [[ "$previous" == --data-binary ]]; then
                        body="${argument#@}"
                        uploaded="$(wc -c < "$body" | tr -d ' ')"
                        downloaded="$uploaded"
                      fi
                      [[ "$previous" == --output ]] && output="$argument"
                      previous="$argument"
                    done
                    if [[ -n "$body" && "$output" != /dev/null ]]; then
                      cp "$body" "$output"
                    fi
                    printf '204\t%s\t%s\t%s' "$downloaded" "$uploaded" "$version"
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
                STRESS_LARGE_BYTES="1024",
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
                self.assertGreater(ok, 0, summary.read_text())
                self.assertEqual(failed, 0, summary.read_text())
                self.assertEqual(iterations, ok + failed, summary.read_text())

    def test_status_only_curl_cannot_fake_transfer_or_protocol_evidence(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            fake_curl = fake_bin / "curl"
            fake_curl.write_text("#!/usr/bin/env bash\nprintf '204'\n")
            fake_curl.chmod(0o755)
            result = self.run_stress(
                root / "logs",
                PATH=f"{fake_bin}{os.pathsep}{os.environ['PATH']}",
                STRESS_DURATION="1",
                STRESS_CONCURRENCY="1",
                STRESS_LARGE_BYTES="1024",
                STRESS_POST_BYTES="1024",
                STRESS_SKIP_LIVENESS="1",
            )
            self.assertEqual(result.returncode, 1, result.stdout)

    def test_post_echo_requires_exact_response_bytes_not_only_matching_counts(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            fake_curl = fake_bin / "curl"
            fake_curl.write_text(
                textwrap.dedent(
                    """\
                    #!/usr/bin/env bash
                    output=/dev/null
                    body=""
                    version=1.1
                    previous=""
                    downloaded=1
                    uploaded=0
                    for argument in "$@"; do
                      [[ "$argument" == --http2 ]] && version=2
                      [[ "$argument" == *'size=1024'* ]] && downloaded=1024
                      [[ "$previous" == --output ]] && output="$argument"
                      if [[ "$previous" == --data-binary ]]; then
                        body="${argument#@}"
                        uploaded="$(wc -c < "$body" | tr -d ' ')"
                        downloaded="$uploaded"
                      fi
                      previous="$argument"
                    done
                    if [[ -n "$body" && "$output" != /dev/null ]]; then
                      tr '\\000' '\\001' < "$body" > "$output"
                    fi
                    printf '204\t%s\t%s\t%s' "$downloaded" "$uploaded" "$version"
                    """
                )
            )
            fake_curl.chmod(0o755)
            result = self.run_stress(
                root / "logs",
                PATH=f"{fake_bin}{os.pathsep}{os.environ['PATH']}",
                STRESS_DURATION="1",
                STRESS_CONCURRENCY="1",
                STRESS_LARGE_BYTES="1024",
                STRESS_POST_BYTES="1024",
                STRESS_SKIP_LIVENESS="1",
            )
            self.assertEqual(result.returncode, 1, result.stdout)
            self.assertRegex(
                (root / "logs" / "post_large.summary").read_text(),
                r"fail=[1-9][0-9]*",
            )

    def test_analysis_only_rejects_an_empty_artifact_directory(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            log_dir = Path(temp_dir) / "logs"
            result = self.run_stress(log_dir, STRESS_DURATION="0")
            self.assertEqual(result.returncode, 2, result.stdout)
            status = (log_dir / "stress-status.tsv").read_text()
            self.assertIn("evidence_mode\tartifact-analysis-only\n", status)
            self.assertIn("proxy_attributed\t0\n", status)
            self.assertIn("complete\t0\n", status)
            self.assertIn("passed\t0\n", status)
            self.assertNotIn("proxy_attributed\t1", status)

    def test_analysis_only_requires_a_successful_source_status_and_worker_artifacts(self):
        workers = (
            "small_https", "small_http1", "plain_http", "large_get",
            "post_large", "head_only", "churn_close", "parallel_pool",
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            log_dir = Path(temp_dir) / "logs"
            log_dir.mkdir()
            (log_dir / "stress-status.tsv").write_text(
                "complete\t1\npassed\t1\nexit_code\t0\n"
                "evidence_mode\ttraffic-only\nproxy_attributed\t0\n"
                "schema_complete\t1\n"
            )
            for worker in workers:
                (log_dir / f"{worker}.summary").write_text(
                    f"{worker} done: iters=1 ok=1 fail=0\n"
                )
                (log_dir / f"{worker}.log").write_text(
                    "204 curl_exit=0 downloaded=1 uploaded=0 http_version=1.1\n"
                )
            result = self.run_stress(log_dir, STRESS_DURATION="0")
            self.assertEqual(result.returncode, 0, result.stdout)
            status = (log_dir / "stress-status.tsv").read_text()
            self.assertIn("evidence_mode\tartifact-analysis-only\n", status)
            self.assertIn("complete\t1\n", status)
            self.assertIn("passed\t1\n", status)

    def test_term_exits_143_and_reaps_owned_descendant_tree(self):
        probe = subprocess.Popen(["sleep", "30"])
        try:
            try:
                pgrep = subprocess.run(
                    ["pgrep", "-P", str(os.getpid())],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    text=True,
                )
                process_snapshot = subprocess.run(
                    [
                        "ps", "-ww", "-o", "pid=", "-o", "lstart=",
                        "-o", "command=", "-p", str(probe.pid),
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    text=True,
                )
            except OSError:
                self.skipTest(
                    "host sandbox does not permit pgrep/ps process-tree inspection"
                )
        finally:
            probe.terminate()
            probe.wait(timeout=5)
        if (
            str(probe.pid) not in pgrep.stdout.splitlines()
            or process_snapshot.returncode != 0
            or not process_snapshot.stdout.strip()
        ):
            self.skipTest("host sandbox does not permit pgrep/ps process-tree inspection")

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            pids = root / "curl-pids"
            fake_curl = fake_bin / "curl"
            fake_curl.write_text(
                textwrap.dedent(
                    f"""\
                    #!/usr/bin/env bash
                    trap '' TERM
                    sleep 30 &
                    child=$!
                    printf '%s\\n%s\\n' "$$" "$child" >> {shlex.quote(str(pids))}
                    wait "$child"
                    """
                )
            )
            fake_curl.chmod(0o755)
            log_dir = root / "logs"
            env = os.environ.copy()
            env.update(
                PATH=f"{fake_bin}{os.pathsep}{os.environ['PATH']}",
                STRESS_LOG_DIR=str(log_dir),
                STRESS_DURATION="30",
                STRESS_CONCURRENCY="1",
                STRESS_POST_BYTES="1",
                STRESS_SKIP_LIVENESS="1",
            )
            process = subprocess.Popen(
                ["bash", str(STRESS_SCRIPT)],
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                pid_count = len(pids.read_text().splitlines()) if pids.exists() else 0
                if pid_count >= 16:
                    break
                time.sleep(0.05)
            self.assertTrue(
                pids.exists()
                and len(pids.read_text().splitlines()) >= 16,
                "stress workers did not start",
            )
            process.send_signal(signal.SIGTERM)
            output, _ = process.communicate(timeout=20)
            self.assertEqual(process.returncode, 143, output)
            for pid_text in pids.read_text().splitlines():
                pid = int(pid_text)
                gone_deadline = time.monotonic() + 2
                while time.monotonic() < gone_deadline:
                    try:
                        os.kill(pid, 0)
                    except ProcessLookupError:
                        break
                    time.sleep(0.05)
                else:
                    detail = subprocess.run(
                        ["ps", "-ww", "-o", "pid,ppid,state,command", "-p", str(pid)],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        text=True,
                    ).stdout.strip()
                    self.fail(f"pid {pid} survived bounded cleanup: {detail}")
            status = (log_dir / "stress-status.tsv").read_text()
            self.assertIn("complete\t0\n", status)
            self.assertIn("stress run interrupted by signal", status)

    def test_monitored_provider_death_is_a_run_failure(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            fake_curl = fake_bin / "curl"
            fake_curl.write_text(
                textwrap.dedent(
                    """\
                    #!/usr/bin/env bash
                    output=/dev/null
                    body=""
                    downloaded=1
                    uploaded=0
                    version=1.1
                    previous=""
                    for argument in "$@"; do
                      [[ "$argument" == --http2 ]] && version=2
                      [[ "$argument" == *'size=1024'* ]] && downloaded=1024
                      [[ "$previous" == --output ]] && output="$argument"
                      if [[ "$previous" == --data-binary ]]; then
                        body="${argument#@}"
                        uploaded="$(wc -c < "$body" | tr -d ' ')"
                        downloaded="$uploaded"
                      fi
                      previous="$argument"
                    done
                    if [[ -n "$body" && "$output" != /dev/null ]]; then
                      cp "$body" "$output"
                    fi
                    printf '204\t%s\t%s\t%s' "$downloaded" "$uploaded" "$version"
                    """
                )
            )
            fake_curl.chmod(0o755)
            fake_ps = fake_bin / "ps"
            fake_ps.write_text(
                textwrap.dedent(
                    """\
                    #!/usr/bin/env bash
                    pid=""
                    previous=""
                    for argument in "$@"; do
                      [[ "$previous" == -p ]] && pid="$argument"
                      previous="$argument"
                    done
                    [[ "$pid" =~ ^[1-9][0-9]*$ ]] || exit 1
                    kill -0 "$pid" 2>/dev/null || exit 1
                    if [[ " $* " == *" -ww "* ]]; then
                      printf '%s Wed Jan  1 00:00:00 2025 fake-provider\n' "$pid"
                    else
                      printf 'PID RSS VSZ %%CPU STAT\n%s 1 1 0.0 S\n' "$pid"
                    fi
                    """
                )
            )
            fake_ps.chmod(0o755)
            provider = subprocess.Popen(["sleep", "30"])
            process = None
            try:
                log_dir = root / "logs"
                env = os.environ.copy()
                env.update(
                    STRESS_LOG_DIR=str(log_dir),
                    PATH=f"{fake_bin}{os.pathsep}{os.environ['PATH']}",
                    STRESS_DURATION="3",
                    STRESS_CONCURRENCY="1",
                    STRESS_LARGE_BYTES="1024",
                    STRESS_POST_BYTES="1024",
                    STRESS_SKIP_LIVENESS="1",
                    STRESS_MONITOR_PID=str(provider.pid),
                )
                process = subprocess.Popen(
                    ["bash", str(STRESS_SCRIPT)],
                    env=env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                )
                identity_file = log_dir / "monitor.identity.sha256"
                monitor_log = log_dir / f"monitor.{provider.pid}.log"
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline and not (
                    identity_file.exists()
                    and monitor_log.exists()
                    and monitor_log.stat().st_size > 0
                ):
                    time.sleep(0.05)
                self.assertTrue(
                    identity_file.exists()
                    and monitor_log.exists()
                    and monitor_log.stat().st_size > 0,
                    "stress monitor did not become ready",
                )
                provider.terminate()
                provider.wait(timeout=5)
                output, _ = process.communicate(timeout=20)
            finally:
                if provider.poll() is None:
                    provider.terminate()
                    provider.wait(timeout=5)
                if process is not None and process.poll() is None:
                    process.terminate()
                    process.wait(timeout=10)
            self.assertEqual(process.returncode, 1, output)
            self.assertIn("died or changed identity", output)
            status = (root / "logs" / "stress-status.tsv").read_text()
            self.assertIn("evidence_mode\tprovider-monitored-traffic-only", status)
            self.assertIn("passed\t0", status)

    def test_monitor_uses_the_documented_five_second_heavy_sampling_cadence(self):
        shell = STRESS_SCRIPT.read_text()
        start = shell.index("monitor_pid() {")
        end = shell.index("# ── Plan + launch", start)
        monitor = shell[start:end]
        self.assertIn("sleep 5", monitor)
        self.assertNotIn("sleep 1\n", monitor)

    def test_identity_mismatch_does_not_retain_signal_authority(self):
        shell = STRESS_SCRIPT.read_text()
        helpers = self.stress_function(shell, "pid_identity") + self.stress_function(
            shell, "signal_owned_identity"
        )
        program = textwrap.dedent(
            """
            ps() {
              local pid="" previous="" argument
              for argument in "$@"; do
                [[ "$previous" == -p ]] && pid="$argument"
                previous="$argument"
              done
              kill -0 "$pid" 2>/dev/null || return 1
              printf '%s Wed Jan  1 00:00:00 2025 test-child\n' "$pid"
            }
            """
        ) + helpers + textwrap.dedent(
            """
            sleep 30 & child=$!
            trap 'kill -TERM "$child" 2>/dev/null || true; wait "$child" 2>/dev/null || true' EXIT
            identity="$(pid_identity "$child")" || exit 3
            wrong_identity="$(printf '%064d' 0)"
            [[ "$wrong_identity" != "$identity" ]] || wrong_identity="$(printf '%064d' 1)"
            if signal_owned_identity "$child" "$wrong_identity" KILL; then exit 4; fi
            kill -0 "$child" || exit 5
            signal_owned_identity "$child" "$identity" TERM || exit 6
            wait "$child" 2>/dev/null || true
            trap - EXIT
            echo identity-safe
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
        self.assertEqual(result.stdout, "identity-safe\n")


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

    def test_real_download_requires_exact_successful_byte_count(self):
        function = self.soak_function(SOAK_SCRIPT.read_text(), "real_download_matches")

        def matches(
            curl_rc: str,
            code: str,
            downloaded: str,
            expected: str,
            speed: str = "1048576",
            elapsed: str = "32.000001",
        ) -> bool:
            result = subprocess.run(
                [
                    "bash", "-c",
                    function
                    + "\nreal_download_matches \"$1\" \"$2\" \"$3\" \"$4\" \"$5\" \"$6\"",
                    "test", curl_rc, code, downloaded, expected, speed, elapsed,
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=2,
            )
            return result.returncode == 0

        self.assertTrue(matches("0", "200", "33554432", "33554432"))
        self.assertFalse(matches("0", "204", "0", "33554432"))
        self.assertFalse(matches("0", "302", "33554432", "33554432"))
        self.assertFalse(matches("18", "200", "33554432", "33554432"))
        self.assertFalse(matches("0", "200", "33554431", "33554432"))
        self.assertFalse(matches("0", "200", "33554432", "33554432", "0"))
        self.assertFalse(
            matches("0", "200", "33554432", "33554432", elapsed="nan")
        )

    def test_bounded_child_join_accepts_term_and_rejects_forced_kill(self):
        shell = SOAK_SCRIPT.read_text()
        start = shell.index("child_job_is_active() {")
        end = shell.index("# ── Helpers", start)
        helpers = shell[start:end]
        python = shlex.quote(sys.executable)

        def join_result(
            child: str, timeout: int, readiness_file=None
        ) -> tuple[str, str, str, str]:
            readiness = "sleep 0.1\n"
            if readiness_file is not None:
                quoted_ready = shlex.quote(str(readiness_file))
                readiness = (
                    f"for _ in $(seq 1 200); do [[ -e {quoted_ready} ]] && break; "
                    "sleep 0.01; done\n"
                    f"[[ -e {quoted_ready} ]] || exit 9\n"
                )
            program = (
                helpers
                + "\n"
                + child
                + " &\npid=$!\n"
                + readiness
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
        with tempfile.TemporaryDirectory() as temp_dir:
            ready = Path(temp_dir) / "ready"
            child_program = (
                "import signal,time,pathlib; "
                "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
                f"pathlib.Path({str(ready)!r}).touch(); time.sleep(30)"
            )
            self.assertEqual(
                join_result(
                    f"{python} -c {shlex.quote(child_program)}", 1, ready
                ),
                ("137", "0", "1", "1"),
            )

    def test_holder_cleanup_is_pid_scoped_and_joins_the_batch(self):
        shell = SOAK_SCRIPT.read_text()
        cleanup = self.soak_function(shell, "kill_holders")
        active = self.soak_function(shell, "child_job_is_active")
        signal = self.soak_function(shell, "signal_child")
        self.assertNotIn("pkill -f", cleanup)
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            pidfile = root / "holders.tsv"
            program = (
                active + signal + cleanup
                + f"\nOUT={shlex.quote(str(root))}\n"
                + f"HOLDER_PIDFILE={shlex.quote(str(pidfile))}\n"
                + "FLOW_POOL_LABEL=test\nHOLDER_CLEANUP_OK=1\n"
                + "sleep 30 & first=$!\nsleep 30 & second=$!\n"
                + "printf '%s\\tmarker\\n%s\\tmarker\\n' \"$first\" \"$second\" "
                + '> "$HOLDER_PIDFILE"\nkill_holders\n'
                + "printf 'ok=%s jobs=%s\\n' \"$HOLDER_CLEANUP_OK\" "
                + '"$(jobs -p | wc -l | tr -d \' \')"\n'
                + 'cat "$OUT/holder-cleanup.tsv"\n'
            )
            result = subprocess.run(
                ["bash", "-c", program],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=5,
            )
            self.assertEqual(result.returncode, 0, result.stdout)
            self.assertIn("ok=1 jobs=0", result.stdout)
            self.assertIn(
                "test\ttotal=2\treaped=2\tforced=0\tunreaped=0",
                result.stdout,
            )

    def test_sustained_hold_resets_on_the_pre_topup_recount(self):
        helper = self.soak_function(SOAK_SCRIPT.read_text(), "update_sustained_hold")
        with tempfile.TemporaryDirectory() as temp_dir:
            program = helper + textwrap.dedent(
                f"""
                OUT={shlex.quote(temp_dir)}
                FLOW_POOL_LABEL=fanout
                FLOW_POOL_ATTAINED=0
                sustained_since_seconds=""
                sustained_since_epoch=""
                last_established_epoch=""
                : > "$OUT/pool-intervals.tsv"
                update_sustained_hold 1 1 100 100.000000 5
                update_sustained_hold 1 0 103 103.000000 5
                update_sustained_hold 1 1 104 104.000000 5
                update_sustained_hold 1 1 108 108.000000 5
                printf 'attained=%s since=%s\\n' "$FLOW_POOL_ATTAINED" "$sustained_since_seconds"
                cat "$OUT/pool-intervals.tsv"
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
            self.assertIn("attained=0 since=104", result.stdout)
            self.assertIn("fanout\t100.000000\t100.000000", result.stdout)

    def test_soak_signal_handler_terminates_with_conventional_status(self):
        handler = self.soak_function(SOAK_SCRIPT.read_text(), "handle_signal")
        for exit_code in (130, 143):
            result = subprocess.run(
                [
                    "bash",
                    "-c",
                    handler
                    + "\ncleanup() { printf 'cleaned\\n'; }\n"
                    + f"handle_signal {exit_code}\nprintf 'continued\\n'\n",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=2,
            )
            self.assertEqual(result.returncode, exit_code, result.stdout)
            self.assertEqual(result.stdout, "cleaned\n")

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

    def test_explicit_targets_are_clamped_by_safe_and_hard_cap_headroom(self):
        helper = self.soak_function(SOAK_SCRIPT.read_text(), "clamp_safe")
        program = helper + textwrap.dedent(
            """
            warn() { :; }
            MAX_SAFE_FLOWS=300
            BASELINE_TOTAL=5

            ALLOW_UNSAFE_LOAD=0; HARDCAP=0
            clamp_safe 1024 FANOUT_TARGET

            ALLOW_UNSAFE_LOAD=1; HARDCAP=0
            clamp_safe 1024 FANOUT_TARGET

            ALLOW_UNSAFE_LOAD=1; HARDCAP=80
            clamp_safe 1024 FANOUT_TARGET

            HARDCAP=5
            if clamp_safe 1 FANOUT_TARGET; then echo unsafe; else echo unavailable; fi
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
            result.stdout.splitlines(), ["300", "1024", "75", "unavailable"]
        )

    def test_active_holder_marker_requires_an_http_2xx_header(self):
        helper = self.soak_function(
            SOAK_SCRIPT.read_text(), "holder_marker_established"
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            ok = root / "ok.active.headers"
            failed = root / "failed.active.headers"
            silent = root / "silent.connected"
            ok.write_text("HTTP/2 200\r\ncontent-type: application/octet-stream\r\n")
            failed.write_text("HTTP/2 503\r\ncontent-length: 0\r\n")
            silent.write_text("connected\n")
            program = helper + textwrap.dedent(
                f"""
                holder_marker_established {shlex.quote(str(ok))} && echo ok
                holder_marker_established {shlex.quote(str(failed))} || echo rejected
                holder_marker_established {shlex.quote(str(silent))} && echo silent
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
            self.assertEqual(result.stdout.splitlines(), ["ok", "rejected", "silent"])

    def test_noninteractive_ceiling_requires_explicit_assume_yes(self):
        shell = SOAK_SCRIPT.read_text()
        self.assertIn(
            'die "non-interactive ceiling-finder requires ASSUME_YES=1"', shell
        )
        self.assertIn(
            "refusing to generate load with unknown live-flow headroom", shell
        )


class SignedUdpGateWiringTests(unittest.TestCase):
    def test_explicit_full_gate_requires_the_signed_udp_e2e(self):
        justfile = SCRIPT_DIR.parent / "justfile"
        full_recipe = next(
            line for line in justfile.read_text().splitlines()
            if line.startswith("test-full:")
        )
        self.assertIn("test-modern-udp-signed", full_recipe.split())

    def test_signed_udp_evidence_requires_all_runtime_probes(self):
        shell = (SCRIPT_DIR / "test_modern_udp_flow.sh").read_text()
        self.assertEqual(
            shell.count("UDP_PROBE_COUNT=$((UDP_PROBE_COUNT + 1))"), 5
        )
        self.assertIn('[[ "$UDP_PROBE_COUNT" != 5 ]]', shell)
        final_check = shell.index('[[ "$UDP_PROBE_COUNT" != 5 ]]')
        final_green = shell.index("write_evidence_status 1 1 0")
        self.assertLess(final_check, final_green)


if __name__ == "__main__":
    unittest.main()
