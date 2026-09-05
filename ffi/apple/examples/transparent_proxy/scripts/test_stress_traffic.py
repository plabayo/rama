#!/usr/bin/env python3

import json
import os
from pathlib import Path
import re
import signal
import shlex
import shutil
import socket
import subprocess
import struct
import sys
import tempfile
import textwrap
import time
import unittest
import uuid
from unittest import mock

import stress_compare
from modern_udp_e2e_probe import (
    PRESSURE_MARKER_PREFIX,
    ProductViolation,
    dns_query,
    ntp_query,
    pressure_burst,
)
from modern_udp_evidence import (
    parse_signed_udp_status_lines,
    pressure_window_observation,
)
from stress_evidence import (
    seal as seal_stress_evidence,
    sha256_file,
    verify as verify_stress_evidence,
    write_metrics as write_stress_metrics,
)
from stress_compare import (
    create_comparison,
    create_series,
    verify_comparison,
    verify_series,
)


SCRIPT_DIR = Path(__file__).resolve().parent
STRESS_SCRIPT = SCRIPT_DIR / "stress_traffic.sh"
SOAK_SCRIPT = SCRIPT_DIR / "soak_test.sh"


def write_self_attested_traffic_run(
    log_dir: Path, *, monitored=False, role="direct-baseline",
    start=100000, end=101000, duration="0.050", workload_identity="b" * 64,
    ndjson_pid=42,
) -> tuple[str, bytes]:
    """Build a syntactically honest fixture; it never claims external authenticity."""
    workers = (
        "small_https", "small_http1", "plain_http", "large_get",
        "post_large", "head_only", "churn_close", "parallel_pool",
    )
    log_dir.mkdir()
    for worker in workers:
        (log_dir / f"{worker}.summary").write_text(
            f"{worker} done: iters=1 ok=1 fail=0\n"
        )
        (log_dir / f"{worker}.log").write_text(
            "204 curl_exit=0 downloaded=1 uploaded=0 "
            f"http_version=1.1 duration_seconds={duration}\n"
        )
    (log_dir / "source-stress_traffic.sh").write_bytes(STRESS_SCRIPT.read_bytes())
    helper = SCRIPT_DIR / "stress_evidence.py"
    (log_dir / "source-stress_evidence.py").write_bytes(helper.read_bytes())
    git_head = "a" * 40
    (log_dir / "git-head.txt").write_text(git_head + "\n")
    (log_dir / "git-status.txt").write_text("")
    mode = "provider-monitored-traffic-only" if monitored else "traffic-only"
    provider_pid = "42" if monitored else "none"
    provider_identity = "c" * 64 if monitored else "none"
    executable_hash = "d" * 64 if monitored else "none"
    signing_identifier = "org.example.provider" if monitored else "none"
    signing_team = "TEAM123" if monitored else "none"
    signing_cdhash = "e" * 40 if monitored else "none"
    if monitored:
        (log_dir / "monitor.identity.sha256").write_text(provider_identity + "\n")
        (log_dir / "preflight.txt").write_text(
            "PID RSS VSZ %CPU STATE\n42 1000 2000 5.0 S\n"
        )
        (log_dir / "postflight.txt").write_text(
            "PID RSS VSZ %CPU STATE\n42 1050 2000 6.0 S\n"
        )
        (log_dir / "monitor.42.log").write_text(
            "monitoring pid=42\n42 1025 2000 20.0 S\n"
        )
        (log_dir / "provider-codesign.txt").write_text(
            "Identifier=org.example.provider\nTeamIdentifier=TEAM123\nCDHash="
            + signing_cdhash + "\n"
        )
        (log_dir / "provider-identity.tsv").write_text(
            f"pid\t42\nidentity\t{provider_identity}\n"
            "executable\t/fixture/provider\n"
            f"executable_sha256\t{executable_hash}\n"
            f"signing_identifier\t{signing_identifier}\n"
            f"signing_team\t{signing_team}\nsigning_cdhash\t{signing_cdhash}\n"
        )
        timestamp = time.strftime(
            "%Y-%m-%dT%H:%M:%S", time.gmtime((start + 500) / 1000)
        ) + ".000000+00:00"
        (log_dir / "system.ndjson").write_text(
            json.dumps({"timestamp": timestamp, "processID": ndjson_pid}) + "\n"
        )
        (log_dir / "system-log-capture.err").write_text("")
        (log_dir / "system-log-tool.tsv").write_text(
            f"path\t/fixture/log\nsha256\t{'f' * 64}\n"
        )
    metrics = write_stress_metrics(
        log_dir, str(start), str(end), "10000", "100", "67108864",
        "400", mode, provider_pid,
    )
    run_uuid = str(uuid.uuid4())
    manifest_hash = seal_stress_evidence(
        log_dir, run_uuid, str(start), str(end), mode, provider_pid,
        role, workload_identity,
    )
    status = (
        "complete\t1\npassed\t1\nexit_code\t0\n"
        f"evidence_mode\t{mode}\nproxy_attributed\t0\n"
        "evidence_claim\tself-attested-local-integrity-not-authenticity\n"
        f"traffic_role\t{role}\n"
        f"workload_identity\t{workload_identity}\n"
        f"run_uuid\t{run_uuid}\nrun_start_epoch\t{start}\nrun_end_epoch\t{end}\n"
        f"artifact_manifest_sha256\t{manifest_hash}\n"
        "max_p95_ms\t10000\nmin_throughput_milli_rps\t100\n"
        "max_rss_growth_bytes\t67108864\nmax_cpu_percent\t400\n"
        f"observed_p95_ms\t{metrics[2]}\n"
        f"observed_throughput_milli_rps\t{metrics[4]}\n"
        f"observed_rss_growth_bytes\t{metrics[6]}\n"
        f"observed_max_cpu_percent\t{metrics[8]}\n"
        f"git_head\t{git_head}\ngit_dirty\t0\n"
        f"stress_script_sha256\t{sha256_file(log_dir / 'source-stress_traffic.sh')}\n"
        f"evidence_helper_sha256\t{sha256_file(log_dir / 'source-stress_evidence.py')}\n"
        f"provider_pid\t{provider_pid}\nprovider_identity\t{provider_identity}\n"
        f"provider_executable_sha256\t{executable_hash}\n"
        f"provider_signing_identifier\t{signing_identifier}\n"
        f"provider_signing_team\t{signing_team}\n"
        f"provider_signing_cdhash\t{signing_cdhash}\n"
        f"ndjson_included\t{1 if monitored else 0}\n"
        f"system_log_started\t{1 if monitored else 0}\n"
        f"system_log_alive_end\t{1 if monitored else 0}\n"
        f"system_log_joined\t{1 if monitored else 0}\n"
        f"system_log_child_rc\t{'143' if monitored else 'none'}\n"
        f"system_log_tool_sha256\t{'f' * 64 if monitored else 'none'}\n"
        "schema_complete\t1\n"
    ).encode()
    (log_dir / "stress-status.tsv").write_bytes(status)
    return run_uuid, status


class StressTrafficValidationTests(unittest.TestCase):
    @staticmethod
    def stress_function(shell: str, name: str) -> str:
        start = shell.index(f"{name}() {{")
        end = shell.index("\n}\n", start) + 3
        return shell[start:end]

    def run_stress(
        self,
        log_dir: Path,
        *,
        timeout_seconds: float = 45,
        **overrides: str,
    ) -> subprocess.CompletedProcess:
        env = os.environ.copy()
        env.update(STRESS_LOG_DIR=str(log_dir), **overrides)
        arguments = ["bash", str(STRESS_SCRIPT)]
        process = subprocess.Popen(
            arguments,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            start_new_session=True,
        )
        try:
            output, _ = process.communicate(timeout=timeout_seconds)
        except subprocess.TimeoutExpired as error:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                output, _ = process.communicate(timeout=2)
            except subprocess.TimeoutExpired:
                pass
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            output, _ = process.communicate()
            error.output = output
            raise
        return subprocess.CompletedProcess(
            arguments,
            process.returncode,
            output,
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
                    printf '204\t%s\t%s\t%s\t0.050' "$downloaded" "$uploaded" "$version"
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
            run_uuid, start, end, manifest_hash = verify_stress_evidence(log_dir)
            self.assertEqual(str(uuid.UUID(run_uuid)), run_uuid)
            self.assertGreaterEqual(end, start)
            self.assertRegex(manifest_hash, r"^[0-9a-f]{64}$")

    def test_status_only_curl_cannot_fake_transfer_or_protocol_evidence(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            fake_curl = fake_bin / "curl"
            fake_curl.write_text(
                "#!/usr/bin/env bash\nsleep 0.01\nprintf '204'\n"
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

    def test_timeout_terminates_stress_process_group(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            pid_log = root / "curl-pids"
            fake_curl = fake_bin / "curl"
            fake_curl.write_text(
                "#!/usr/bin/env bash\n"
                "printf '%s\\n' \"$$\" >> \"$CURL_PID_LOG\"\n"
                "while :; do sleep 1; done\n"
            )
            fake_curl.chmod(0o755)
            with self.assertRaises(subprocess.TimeoutExpired):
                self.run_stress(
                    root / "logs",
                    timeout_seconds=2,
                    PATH=f"{fake_bin}{os.pathsep}{os.environ['PATH']}",
                    CURL_PID_LOG=str(pid_log),
                    STRESS_DURATION="60",
                    STRESS_CONCURRENCY="1",
                    STRESS_LARGE_BYTES="1024",
                    STRESS_POST_BYTES="1024",
                    STRESS_SKIP_LIVENESS="1",
                )
            pids = {int(pid) for pid in pid_log.read_text().splitlines()}
            self.assertGreater(len(pids), 0)
            deadline = time.monotonic() + 2
            alive = pids
            while alive and time.monotonic() < deadline:
                time.sleep(0.01)
                alive = {
                    pid
                    for pid in alive
                    if self.process_exists(pid)
                }
            self.assertEqual(alive, set())

    @staticmethod
    def process_exists(pid: int) -> bool:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        return True

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
                    printf '204\t%s\t%s\t%s\t0.050' "$downloaded" "$uploaded" "$version"
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
            self.assertFalse((log_dir / "stress-status.tsv").exists())
            status = (log_dir / "stress-analysis-status.tsv").read_text()
            self.assertIn("evidence_mode\tartifact-analysis-only\n", status)
            self.assertIn("proxy_attributed\t0\n", status)
            self.assertIn("complete\t0\n", status)
            self.assertIn("passed\t0\n", status)
            self.assertNotIn("proxy_attributed\t1", status)

    def test_analysis_only_requires_a_successful_source_status_and_worker_artifacts(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            log_dir = Path(temp_dir) / "logs"
            _, source_status = write_self_attested_traffic_run(log_dir)
            result = self.run_stress(log_dir, STRESS_DURATION="0")
            self.assertEqual(result.returncode, 0, result.stdout)
            self.assertEqual((log_dir / "stress-status.tsv").read_bytes(), source_status)
            status = (log_dir / "stress-analysis-status.tsv").read_text()
            self.assertIn("evidence_mode\tartifact-analysis-only\n", status)
            self.assertIn("complete\t1\n", status)
            self.assertIn("passed\t1\n", status)
            self.assertIn(
                "evidence_claim\tself-attested-local-integrity-not-authenticity\n",
                status,
            )

    def test_analysis_only_rejects_artifacts_changed_after_sealing(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            log_dir = Path(temp_dir) / "logs"
            write_self_attested_traffic_run(log_dir)
            (log_dir / "small_https.log").write_text("tampered log\n")
            with self.assertRaisesRegex(ValueError, "changed after sealing"):
                verify_stress_evidence(log_dir)
            result = self.run_stress(log_dir, STRESS_DURATION="0")
            self.assertEqual(result.returncode, 2, result.stdout)

    def test_paired_gate_requires_adjacent_identical_direct_and_monitored_runs(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            baseline = root / "baseline"
            candidate = root / "candidate"
            comparison = root / "stress-comparison.tsv"
            write_self_attested_traffic_run(baseline)
            write_self_attested_traffic_run(
                candidate, monitored=True, role="proxy-candidate",
                start=102000, end=103000, duration="0.075",
            )
            self.assertEqual(
                create_comparison(baseline, candidate, comparison), 0
            )
            self.assertEqual(verify_comparison(baseline, candidate, comparison), 0)
            contents = comparison.read_text()
            sealed_comparator = comparison.with_name(
                comparison.name + ".source-stress_compare.py"
            )
            self.assertEqual(
                sealed_comparator.read_bytes(),
                stress_compare.current_source_path().read_bytes(),
            )
            self.assertIn(
                f"comparison_helper_sha256\t{sha256_file(sealed_comparator)}\n",
                contents,
            )
            self.assertIn("observed_p95_ratio_milli\t1500\n", contents)
            self.assertIn("observed_throughput_ratio_milli\t1000\n", contents)
            self.assertIn("candidate_rss_growth_bytes\t51200\n", contents)
            self.assertIn("candidate_max_cpu_percent\t20\n", contents)

    def test_absolute_latency_throughput_rss_and_cpu_thresholds_are_enforced(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            direct = root / "direct"
            monitored = root / "monitored"
            write_self_attested_traffic_run(direct)
            failed_latency = write_stress_metrics(
                direct, "100000", "101000", "49", "100", "67108864",
                "400", "traffic-only", "none",
            )
            self.assertEqual(failed_latency[0], "FAILED")
            failed_throughput = write_stress_metrics(
                direct, "100000", "101000", "10000", "8001", "67108864",
                "400", "traffic-only", "none",
            )
            self.assertEqual(failed_throughput[0], "FAILED")
            write_self_attested_traffic_run(
                monitored, monitored=True, role="proxy-candidate",
                start=102000, end=103000,
            )
            failed_resources = write_stress_metrics(
                monitored, "102000", "103000", "10000", "100", "51199",
                "19", "provider-monitored-traffic-only", "42",
            )
            self.assertEqual(failed_resources[0], "FAILED")
            self.assertEqual(failed_resources[6], "51200")
            self.assertEqual(failed_resources[8], "20")

    def test_monitored_bundle_requires_sealed_signing_monitor_and_log_window(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            missing_signing = root / "missing-signing"
            wrong_log_pid = root / "wrong-log-pid"
            write_self_attested_traffic_run(
                missing_signing, monitored=True, role="proxy-candidate"
            )
            (missing_signing / "provider-codesign.txt").unlink()
            with self.assertRaisesRegex(ValueError, "provider-codesign.txt"):
                verify_stress_evidence(missing_signing)
            write_self_attested_traffic_run(
                wrong_log_pid, monitored=True, role="proxy-candidate", ndjson_pid=99
            )
            with self.assertRaisesRegex(ValueError, "no provider row"):
                verify_stress_evidence(wrong_log_pid)

    def test_paired_gate_enforces_ratios_and_rejects_tampered_verdict(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            baseline = root / "baseline"
            candidate = root / "candidate"
            comparison = root / "stress-comparison.tsv"
            write_self_attested_traffic_run(baseline)
            write_self_attested_traffic_run(
                candidate, monitored=True, role="proxy-candidate",
                start=102000, end=103000, duration="0.075",
            )
            self.assertEqual(
                create_comparison(
                    baseline, candidate, comparison, "1400", "900", "600000"
                ),
                1,
            )
            self.assertEqual(verify_comparison(baseline, candidate, comparison), 1)
            comparison.write_text(
                comparison.read_text().replace(
                    "observed_p95_ratio_milli\t1500",
                    "observed_p95_ratio_milli\t1000",
                )
            )
            with self.assertRaisesRegex(ValueError, "does not match"):
                verify_comparison(baseline, candidate, comparison)

    def test_paired_gate_rejects_tampered_or_alternate_comparator_source(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            baseline = root / "baseline"
            candidate = root / "candidate"
            comparison = root / "stress-comparison.tsv"
            write_self_attested_traffic_run(baseline)
            write_self_attested_traffic_run(
                candidate, monitored=True, role="proxy-candidate",
                start=102000, end=103000,
            )
            self.assertEqual(create_comparison(baseline, candidate, comparison), 0)
            sealed_source = comparison.with_name(
                comparison.name + ".source-stress_compare.py"
            )
            original = sealed_source.read_bytes()
            sealed_source.write_bytes(original + b"\n# changed after verdict\n")
            with self.assertRaisesRegex(ValueError, "changed after comparison"):
                verify_comparison(baseline, candidate, comparison)
            sealed_source.write_bytes(original)

            alternate = root / "alternate-stress_compare.py"
            alternate.write_bytes(original + b"\n# alternate verifier semantics\n")
            with mock.patch.object(stress_compare, "__file__", str(alternate)):
                with self.assertRaisesRegex(ValueError, "differs from sealed"):
                    stress_compare.verify_comparison(
                        baseline, candidate, comparison
                    )

    def test_paired_gate_rejects_wrong_role_workload_and_stale_ordering(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            cases = (
                ({"workload_identity": "f" * 64}, {}, "different workloads"),
                ({"start": 800000, "end": 801000}, {}, "not adjacent"),
                ({}, {"role": "unpaired-diagnostic"}, "not an explicit"),
            )
            for index, (candidate_kwargs, baseline_kwargs, expected) in enumerate(cases):
                baseline = root / f"baseline-{index}"
                candidate = root / f"candidate-{index}"
                write_self_attested_traffic_run(baseline, **baseline_kwargs)
                candidate_options = {
                    "monitored": True, "role": "proxy-candidate",
                    "start": 102000, "end": 103000,
                }
                candidate_options.update(candidate_kwargs)
                write_self_attested_traffic_run(
                    candidate, **candidate_options,
                )
                with self.subTest(expected=expected), self.assertRaisesRegex(
                    ValueError, expected
                ):
                    create_comparison(
                        baseline, candidate, root / f"comparison-{index}.tsv"
                    )

    def test_release_series_requires_three_interleaved_strict_pairs(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            pairs = []
            durations = ("0.060", "0.075", "0.050")
            for index, duration in enumerate(durations, start=1):
                baseline = root / f"baseline-{index}"
                candidate = root / f"candidate-{index}"
                comparison = root / f"comparison-{index}.tsv"
                baseline_start = 100000 + (index - 1) * 4000
                write_self_attested_traffic_run(
                    baseline, start=baseline_start, end=baseline_start + 1000
                )
                write_self_attested_traffic_run(
                    candidate, monitored=True, role="proxy-candidate",
                    start=baseline_start + 2000, end=baseline_start + 3000,
                    duration=duration,
                )
                self.assertEqual(
                    create_comparison(baseline, candidate, comparison), 0
                )
                pairs.append((baseline, candidate, comparison))

            series = root / "stress-series.tsv"
            self.assertEqual(create_series(pairs, series), 0)
            self.assertEqual(verify_series(pairs, series), 0)
            contents = series.read_text()
            self.assertIn("pair_count\t3\n", contents)
            self.assertIn("median_p95_ratio_milli\t1200\n", contents)
            self.assertIn("worst_p95_ratio_milli\t1500\n", contents)
            self.assertIn("worst_throughput_ratio_milli\t1000\n", contents)
            self.assertIn("worst_candidate_rss_growth_bytes\t51200\n", contents)
            self.assertEqual(
                series.with_name(
                    series.name + ".source-stress_compare.py"
                ).read_bytes(),
                stress_compare.current_source_path().read_bytes(),
            )

            with self.assertRaisesRegex(ValueError, "at least three"):
                create_series(pairs[:2], root / "too-short.tsv")
            reordered = [pairs[0], pairs[2], pairs[1]]
            with self.assertRaisesRegex(ValueError, "interleaved and adjacent"):
                create_series(reordered, root / "reordered.tsv")

            self.assertEqual(
                create_comparison(*pairs[2], "1600", "667", "600000"), 0
            )
            with self.assertRaisesRegex(ValueError, "weakened the p95"):
                create_series(pairs, root / "weakened.tsv")
            self.assertEqual(create_comparison(*pairs[2]), 0)

            series.write_text(
                contents.replace("median_p95_ratio_milli\t1200", "median_p95_ratio_milli\t1")
            )
            with self.assertRaisesRegex(ValueError, "does not match"):
                verify_series(pairs, series)

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
                    printf '204\t%s\t%s\t%s\t0.050' "$downloaded" "$uploaded" "$version"
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
                    if [[ " $* " == *" comm= "* ]]; then
                      printf '/bin/sleep\n'
                    elif [[ " $* " == *" -ww "* ]]; then
                      printf '%s Wed Jan  1 00:00:00 2025 fake-provider\n' "$pid"
                    else
                      printf 'PID RSS VSZ %%CPU STAT\n%s 1 1 0.0 S\n' "$pid"
                    fi
                    """
                )
            )
            fake_ps.chmod(0o755)
            fake_log = fake_bin / "log"
            fake_log.write_text(
                "#!/usr/bin/env bash\n"
                "trap 'exit 143' TERM\n"
                "printf '{}\\n'\n"
                "while :; do sleep 1; done\n"
            )
            fake_log.chmod(0o755)
            provider = subprocess.Popen(["sleep", "30"])
            process = None
            try:
                log_dir = root / "logs"
                ndjson = root / "system.ndjson"
                ndjson.write_text("")
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
                    STRESS_NDJSON=str(ndjson),
                    STRESS_LOG_TOOL=str(fake_log),
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

    def test_sanitizer_docs_do_not_claim_asan_or_swift_tsan_race_coverage(self):
        justfile = (SCRIPT_DIR.parent / "justfile").read_text()
        readme = (SCRIPT_DIR.parent / "README.md").read_text()
        self.assertIn("ASan does not detect data races", justfile)
        self.assertIn("Rust static library is not instrumented", justfile)
        self.assertIn("ASan\ndoes not detect data races", readme)
        self.assertIn("does not instrument the linked Rust static library", readme)

    @staticmethod
    def status_lines(verdict=(1, 1, 0), attempts=5, passes=5, diagnostics=()):
        complete, passed, exit_code = verdict
        rows = [
            ("complete", complete), ("passed", passed), ("exit_code", exit_code),
            ("udp_probe_attempt_count", attempts), ("udp_probe_pass_count", passes),
            ("udp_pressure_log_checked", 1),
            ("rust_udp_drop_transitions", 1),
            ("rust_udp_resume_transitions", 1),
            ("swift_udp_staging_drop_samples", 0),
            ("log_stream_started", 1), ("log_stream_alive_end", 1),
            ("log_stream_joined", 1), ("profile_restored", 1),
            ("callback_generation", "modern"),
            ("run_uuid", "12345678-1234-4234-8234-123456789abc"),
            ("provider_pid", 123),
            ("provider_identity", "a" * 64),
            ("provider_identity_stable", 1),
            ("http3_source_pid", 456),
            ("http3_flow_id", 88),
            ("http3_remote_endpoint", "1.1.1.1:443"),
            ("pressure_probe_attempted", 1),
            ("pressure_probe_passed", 1),
            ("pressure_drop_transitions", 1),
            ("pressure_resume_transitions", 1),
            ("pressure_drop_reasons", "channel_count"),
            ("pressure_recovered_reasons", "channel_count"),
            ("passthrough_dns_source_pid", 451),
            ("passthrough_dns_flow_id", 75),
            ("control_dns_source_pid", 452),
            ("control_dns_flow_id", 76),
            ("ntp_source_pid", 453),
            ("ntp_flow_id", 77),
            ("pressure_source_pid", 454),
            ("pressure_flow_id", 78),
            ("blocked_dns_source_pid", 455),
            ("blocked_dns_flow_id", 79),
            ("dial9_baseline_max_index", 8),
            ("dial9_required_flow_id", 77),
            ("dial9_current_segment_count", 1),
            ("dial9_required_pair_count", 1),
            ("dial9_required_close_reason", 1),
            ("dial9_required_close_reason_name", "shutdown"),
            ("dial9_required_close_age_ms", 2),
            ("dial9_close_age_bound_ms", 100),
            ("dial9_required_bytes_in", 48),
            ("dial9_required_bytes_out", 48),
            ("schema_version", 3),
            *diagnostics,
            ("schema_complete", 1),
        ]
        return [f"{key}\t{value}\n" for key, value in rows]

    def test_signed_udp_evidence_requires_terminal_cleanup_and_exact_trace_pair(self):
        shell = (SCRIPT_DIR / "test_modern_udp_flow.sh").read_text()
        self.assertIn("UDP_PROBE_ATTEMPT_COUNT", shell)
        self.assertIn("UDP_PROBE_PASS_COUNT", shell)
        self.assertIn("stop_log_capture", shell)
        self.assertIn("restore_profile", shell)
        self.assertIn("check_udp_pressure_logs", shell)
        self.assertIn("close_pressure_probe_window", shell)
        self.assertIn("required_flow_id=pressure_flow_id", shell)
        self.assertIn("swift_udp_staging_drop_samples", shell)
        self.assertIn("--flow-id \"$NTP_FLOW_ID\" --protocol 2", shell)
        self.assertIn("modern_udp_evidence.py", shell)

    def test_pressure_window_waits_for_exact_flow_recovery_and_rejects_late_rows(self):
        decision = (
            "udp_e2e_decision rama_decision=intercept flow_id=78 "
            "remote_endpoint=162.159.200.1:123 source_app=com.apple.python3 "
            "source_pid=454"
        )
        drop = (
            'UDP ingress pressure dropped datagram flow_id=78 '
            'pressure="channel_count" cumulative_drops=1 '
            'global_retained_bytes=64 global_max_retained_bytes=64'
        )
        recovery = (
            'UDP ingress pressure resumed flow flow_id=78 '
            'pressure="channel_count" cumulative_resumptions=1 '
            'global_retained_bytes=0 global_max_retained_bytes=64'
        )

        identity = (454, "162.159.200.1:123", "com.apple.python3")
        decision_only = pressure_window_observation(
            ["before", decision], 1, *identity
        )
        self.assertFalse(decision_only["terminal"])
        dropped = pressure_window_observation(
            ["before", decision, drop], 1, *identity
        )
        self.assertFalse(dropped["terminal"])
        self.assertEqual(dropped["summary"]["unrecovered"], ["channel_count"])
        complete = pressure_window_observation(
            ["before", decision, drop, recovery], 1, *identity
        )
        self.assertTrue(complete["terminal"])
        self.assertEqual(complete["flow_id"], 78)

        delayed_duplicate = pressure_window_observation(
            ["before", decision, drop, recovery, decision], 1, *identity
        )
        self.assertFalse(delayed_duplicate["terminal"])
        self.assertEqual(delayed_duplicate["matching_decisions"], 2)
        foreign_recovery = pressure_window_observation(
            ["before", decision, drop, recovery.replace("flow_id=78", "flow_id=79")],
            1,
            *identity,
        )
        self.assertFalse(foreign_recovery["terminal"])
        self.assertTrue(foreign_recovery["summary"]["issues"])

    def test_signed_udp_preflight_failure_still_writes_terminal_incomplete_status(self):
        result = subprocess.run(
            [str(SCRIPT_DIR / "test_modern_udp_flow.sh"), "/definitely/missing/app"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=5,
        )
        self.assertEqual(result.returncode, 2, result.stdout)
        match = re.search(r"modern UDP E2E artifacts: (.+)", result.stdout)
        self.assertIsNotNone(match, result.stdout)
        artifact_dir = Path(match.group(1))
        try:
            with (artifact_dir / "udp-evidence-status.tsv").open() as status_input:
                self.assertEqual(parse_signed_udp_status_lines(status_input), 2)
        finally:
            shutil.rmtree(artifact_dir)

    def test_signed_udp_status_parser_distinguishes_pass_failure_and_incomplete(self):
        self.assertEqual(parse_signed_udp_status_lines(self.status_lines()), 0)
        failure = self.status_lines(
            verdict=(1, 0, 1), passes=4,
            diagnostics=(("failure", "blocked DNS replied"),),
        )
        self.assertEqual(parse_signed_udp_status_lines(failure), 1)
        incomplete = self.status_lines(
            verdict=(0, 0, 2), passes=4,
            diagnostics=(
                ("issue", "provider log stream died"),
                ("observed_failure", "blocked DNS replied"),
            ),
        )
        self.assertEqual(parse_signed_udp_status_lines(incomplete), 2)
        early = self.status_lines(
            verdict=(0, 0, 2), attempts=0, passes=0,
            diagnostics=(("issue", "preflight failed"),),
        )
        replacements = {
            "callback_generation": "unknown", "provider_pid": "none",
            "run_uuid": "none",
            "provider_identity": "none", "provider_identity_stable": "0",
            "http3_source_pid": "none",
            "http3_flow_id": "none", "http3_remote_endpoint": "none",
            "pressure_probe_attempted": "0", "pressure_probe_passed": "0",
            "pressure_drop_transitions": "0", "pressure_resume_transitions": "0",
            "pressure_drop_reasons": "none", "pressure_recovered_reasons": "none",
            "passthrough_dns_source_pid": "none", "passthrough_dns_flow_id": "none",
            "control_dns_source_pid": "none", "control_dns_flow_id": "none",
            "ntp_source_pid": "none", "ntp_flow_id": "none",
            "pressure_source_pid": "none", "pressure_flow_id": "none",
            "blocked_dns_source_pid": "none", "blocked_dns_flow_id": "none",
            "dial9_required_flow_id": "none", "dial9_required_close_reason": "none",
            "dial9_required_close_reason_name": "none", "dial9_close_age_bound_ms": "0",
            "dial9_required_close_age_ms": "none", "dial9_required_bytes_in": "none",
            "dial9_required_bytes_out": "none",
        }
        early = [
            f"{key}\t{replacements.get(key, value)}\n"
            for key, value in (row.rstrip("\n").split("\t") for row in early)
        ]
        self.assertEqual(parse_signed_udp_status_lines(early), 2)
        self.assertIsNone(parse_signed_udp_status_lines(self.status_lines(passes=4)))
        duplicate = self.status_lines()[:-1] + ["complete\t1\n", "schema_complete\t1\n"]
        self.assertIsNone(parse_signed_udp_status_lines(duplicate))

        for invalid in ("-1", "+1", "01", "1.0", str(2**64)):
            with self.subTest(invalid=invalid):
                malformed = self.status_lines()
                malformed[3] = f"udp_probe_attempt_count\t{invalid}\n"
                self.assertIsNone(parse_signed_udp_status_lines(malformed))
        def replace(rows, key, value):
            return [
                f"{row_key}\t{value if row_key == key else row_value}\n"
                for row_key, row_value in (
                    row.rstrip("\n").split("\t") for row in rows
                )
            ]

        malformed_baseline = replace(
            self.status_lines(), "dial9_baseline_max_index", "01"
        )
        self.assertIsNone(parse_signed_udp_status_lines(malformed_baseline))
        duplicate_required_pair = replace(
            self.status_lines(), "dial9_required_pair_count", "2"
        )
        self.assertIsNone(parse_signed_udp_status_lines(duplicate_required_pair))
        sampled_drop_count_is_not_recovery_semantics = replace(
            self.status_lines(), "rust_udp_drop_transitions", "2"
        )
        self.assertEqual(
            parse_signed_udp_status_lines(sampled_drop_count_is_not_recovery_semantics), 0
        )
        pressure_loss_failure = self.status_lines(
            verdict=(1, 0, 1),
            diagnostics=(("failure", "UDP ingress pressure loss"),),
        )
        pressure_loss_failure = replace(
            pressure_loss_failure, "swift_udp_staging_drop_samples", "1"
        )
        self.assertEqual(parse_signed_udp_status_lines(pressure_loss_failure), 1)
        dial9_fault_failure = self.status_lines(
            verdict=(1, 0, 1),
            diagnostics=(("failure", "NTP Dial9 service panic"),),
        )
        dial9_fault_failure = replace(
            dial9_fault_failure, "dial9_required_close_reason", "14"
        )
        dial9_fault_failure = replace(
            dial9_fault_failure, "dial9_required_close_reason_name", "service_panic"
        )
        self.assertEqual(parse_signed_udp_status_lines(dial9_fault_failure), 1)
        unsupported_schema = replace(self.status_lines(), "schema_version", "4")
        self.assertIsNone(parse_signed_udp_status_lines(unsupported_schema))

        for key, value in (
            ("provider_identity_stable", "0"),
            ("http3_source_pid", "none"),
            ("run_uuid", "not-a-uuid"),
            ("http3_remote_endpoint", "cloudflare.com:443"),
            ("pressure_resume_transitions", "0"),
            ("pressure_recovered_reasons", "flow_bytes"),
            ("ntp_flow_id", "78"),
            ("dial9_required_close_reason", "15"),
            ("dial9_required_close_reason_name", "idle_timeout"),
            ("dial9_required_close_age_ms", "101"),
            ("dial9_required_bytes_out", "47"),
        ):
            with self.subTest(key=key):
                self.assertIsNone(parse_signed_udp_status_lines(
                    replace(self.status_lines(), key, value)
                ))

    def test_blocked_dns_requires_timeout_or_a_valid_matching_response(self):
        transaction_id = 0x1234
        valid = struct.pack(
            "!HHHHHH", transaction_id, 0x8180, 1, 1, 0, 0
        ) + b"\0" * 16

        class FakeSocket:
            def __init__(self, outcome):
                self.outcome = outcome

            def settimeout(self, _):
                pass

            def sendto(self, *_):
                pass

            def recvfrom(self, _):
                if isinstance(self.outcome, BaseException):
                    raise self.outcome
                return self.outcome, ("8.8.8.8", 53)

            def close(self):
                pass

        with mock.patch("modern_udp_e2e_probe.secrets.randbits", return_value=transaction_id):
            with mock.patch(
                "modern_udp_e2e_probe.socket.socket",
                return_value=FakeSocket(socket.timeout("timeout")),
            ):
                dns_query("8.8.8.8", "example.com", 0.01, True)
            with mock.patch(
                "modern_udp_e2e_probe.socket.socket",
                return_value=FakeSocket(valid),
            ):
                with self.assertRaises(ProductViolation):
                    dns_query("8.8.8.8", "example.com", 0.01, True)
            with mock.patch(
                "modern_udp_e2e_probe.socket.socket",
                return_value=FakeSocket(b"short"),
            ):
                with self.assertRaisesRegex(RuntimeError, "truncated"):
                    dns_query("8.8.8.8", "example.com", 0.01, True)
            with mock.patch(
                "modern_udp_e2e_probe.socket.socket",
                return_value=FakeSocket(OSError("network down")),
            ):
                with self.assertRaises(OSError):
                    dns_query("8.8.8.8", "example.com", 0.01, True)

    def test_ntp_response_is_bound_to_request_and_exact_peer(self):
        class FakeSocket:
            def __init__(self, peer):
                self.peer = peer
                self.packet = None

            def settimeout(self, _):
                pass

            def sendto(self, packet, _):
                self.packet = packet

            def recvfrom(self, _):
                response = bytearray(48)
                response[0] = 0x24  # NTPv4, server mode
                response[1] = 1
                response[24:32] = self.packet[40:48]
                return bytes(response), self.peer

            def close(self):
                pass

        with mock.patch(
            "modern_udp_e2e_probe.socket.socket",
            return_value=FakeSocket(("162.159.200.1", 123)),
        ):
            ntp_query("162.159.200.1", 0.01)
        with mock.patch(
            "modern_udp_e2e_probe.socket.socket",
            return_value=FakeSocket(("162.159.200.2", 123)),
        ):
            with self.assertRaisesRegex(RuntimeError, "unexpected peer"):
                ntp_query("162.159.200.1", 0.01)

    def test_pressure_burst_sends_one_bounded_flow_and_waits_for_recovery(self):
        class FakeSocket:
            def __init__(self):
                self.packets = []
                self.closed = False

            def settimeout(self, timeout):
                self.timeout = timeout

            def sendto(self, packet, peer):
                self.packets.append((bytes(packet), peer))

            def close(self):
                self.closed = True

        fake = FakeSocket()
        with mock.patch("modern_udp_e2e_probe.socket.socket", return_value=fake), \
             mock.patch("modern_udp_e2e_probe.time.sleep") as sleep:
            pressure_burst("162.159.200.1", 512, 4096, 0.25)
        self.assertTrue(fake.closed)
        self.assertEqual(len(fake.packets), 512)
        self.assertEqual({peer for _, peer in fake.packets}, {("162.159.200.1", 123)})
        marker = PRESSURE_MARKER_PREFIX + b"162.159.200.1:123\0"
        self.assertEqual(
            [
                int.from_bytes(packet[len(marker):len(marker) + 8], "big")
                for packet, _ in fake.packets
            ],
            list(range(512)),
        )
        self.assertTrue(all(packet.startswith(marker) for packet, _ in fake.packets))
        sleep.assert_called_once_with(0.25)
        for arguments in ((63, 64, 0), (64, 63, 0), (64, 64, -1)):
            with self.assertRaises(ValueError):
                pressure_burst("162.159.200.1", *arguments)
        with self.assertRaisesRegex(ValueError, "IPv4 literal"):
            pressure_burst("2001:db8::1", 64, 64, 0)


if __name__ == "__main__":
    unittest.main()
