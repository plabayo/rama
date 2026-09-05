#!/usr/bin/env python3

import json
import hashlib
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
import signed_run_evidence
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
    parse_transfers,
    post_response_sha256,
    seal as seal_stress_evidence,
    sha256_file,
    verify as verify_stress_evidence,
    write_workload as write_stress_workload,
    write_metrics as write_stress_metrics,
    zero_body_sha256,
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


def write_fixture_generation_samples(
    log_dir: Path, generation: str, start: int, end: int, cdhash: str
) -> None:
    command = "/fixture/provider"
    command_hash = __import__("hashlib").sha256(command.encode()).hexdigest()
    path_hash = __import__("hashlib").sha256(command.encode()).hexdigest()
    epochs = sorted({
        start,
        start + (end - start) // 2,
        end,
        end + 1,
        *range(start, end + 1, 2000),
    })
    tail = f"42|{start}|{start * 1000}|{cdhash}|{command_hash}|{path_hash}"
    fixed = (
        ("schema_version", "1"),
        ("provider_generation_identity", generation),
        ("running_pid", "42"),
        ("running_start_epoch_ms", str(start)),
        ("running_start_epoch_us", str(start * 1000)),
        ("running_dynamic_cdhash", cdhash),
        ("running_command_sha256", command_hash),
        ("running_executable_path_sha256", path_hash),
        ("cadence_ms", "2000"),
        ("max_gap_ms", "5000"),
        ("sample_count", str(len(epochs))),
    )
    rows = [*fixed, *(
        (f"sample_{index:06d}", f"{epoch_ms}|{tail}")
        for index, epoch_ms in enumerate(epochs, start=1)
    ), ("schema_complete", "1")]
    (log_dir / signed_run_evidence.GENERATION_SAMPLES_NAME).write_text(
        "".join(f"{key}\t{value}\n" for key, value in rows)
    )


def write_self_attested_traffic_run(
    log_dir: Path, *, monitored=False, role="direct-baseline",
    start=100000, end=160000, duration="0.050", workload_identity="b" * 64,
    ndjson_pid=42, workload_duration=60, workload_concurrency=16,
    large_bytes=16777216, post_bytes=8388608,
) -> tuple[str, bytes]:
    """Build a syntactically honest fixture; it never claims external authenticity."""
    workers = (
        "small_https", "small_http1", "plain_http", "large_get",
        "post_large", "head_only", "churn_close", "parallel_pool",
    )
    log_dir.mkdir()
    run_uuid = str(uuid.uuid4())
    worker_counts = {
        worker: (
            workload_concurrency
            if worker == "parallel_pool"
            else max(1, workload_duration // 10)
        )
        for worker in workers
    }
    request_ids = {
        worker: [
            f"{run_uuid.replace('-', '')}{index:02x}{ordinal:030x}"
            for ordinal in range(1, worker_counts[worker] + 1)
        ]
        for index, worker in enumerate(workers, start=1)
    }
    workload_identity = write_stress_workload(
        log_dir, str(workload_duration), str(workload_concurrency),
        str(large_bytes), str(post_bytes),
        "http://http-test.ramaproxy.org/method",
        "https://http-test.ramaproxy.org/method",
        f"https://http-test.ramaproxy.org/bytes?size={large_bytes}",
        "https://http-test.ramaproxy.org/octet-stream"
        + ("" if workload_identity == "b" * 64 else f"?variant={workload_identity}"),
    )
    for worker in workers:
        (log_dir / f"{worker}.summary").write_text(
            f"{worker} done: iters={worker_counts[worker]} "
            f"ok={worker_counts[worker]} fail=0\n"
        )
        downloaded, uploaded = 1024, 0
        if worker == "large_get":
            downloaded = large_bytes
        elif worker == "post_large":
            downloaded = uploaded = post_bytes
        elif worker == "head_only":
            downloaded = 0
        http_version = "1.1" if worker in {
            "small_http1", "plain_http", "churn_close"
        } else "2"
        response_metadata = (
            f" response_sha256={zero_body_sha256(post_bytes)}"
            if worker == "post_large" else ""
        )
        (log_dir / f"{worker}.log").write_text("".join(
            f"request_id={request_id} status=200 curl_exit=0 "
            f"downloaded={downloaded} uploaded={uploaded} "
            f"http_version={http_version} duration_seconds={duration}{response_metadata}\n"
            for request_id in request_ids[worker]
        ))
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
    signing_identifier = (
        "org.ramaproxy.example.tproxy.dev.provider" if monitored else "none"
    )
    signing_team = "TEAM123" if monitored else "none"
    signing_cdhash = "e" * 40 if monitored else "none"
    log_tool_hash = sha256_file(Path("/usr/bin/log")) if monitored else "none"
    (log_dir / "stress-window.tsv").write_text(
        f"traffic_start_epoch_ms\t{start}\n"
        f"traffic_end_epoch_ms\t{end}\n"
        f"traffic_start_monotonic_ns\t{start * 1_000_000}\n"
        f"traffic_end_monotonic_ns\t{start * 1_000_000 + workload_duration * 1_000_000_000}\n"
        "schema_complete\t1\n"
    )
    if role in {"direct-baseline", "proxy-candidate"}:
        crash_generation = provider_identity if role == "proxy-candidate" else "absent"
        crashes = log_dir / "crashes"
        crashes.mkdir()
        (crashes / "crash-snapshot.tsv").write_text(
            "schema_version\t2\n"
            f"run_uuid\t{run_uuid}\n"
            f"provider_generation_identity\t{crash_generation}\n"
            f"since_epoch_ms\t{start}\n"
            f"snapshot_epoch_ms\t{end + 1}\n"
            "process_names\tRamaTransparentProxyExampleExtension,org.ramaproxy.example.tproxy.dev.provider,provider\n"
            "crash_count\t0\n"
            f"crash_names_sha256\t{__import__('hashlib').sha256(b'').hexdigest()}\n"
            "schema_complete\t1\n"
        )
    if monitored:
        (log_dir / "monitor.identity.sha256").write_text(provider_identity + "\n")
        (log_dir / "preflight.txt").write_text(
            f"resource_sample\t{start}\t{provider_identity}\t42\t1000\t2000\t5.0\tS\n"
        )
        (log_dir / "postflight.txt").write_text(
            f"resource_sample\t{end}\t{provider_identity}\t42\t1050\t2000\t6.0\tS\n"
        )
        (log_dir / "monitor.42.log").write_text(
            "".join(
                f"resource_sample\t{start + offset}\t{provider_identity}\t"
                "42\t1025\t2000\t20.0\tS\n"
                for offset in sorted({
                    100,
                    max(200, workload_duration * 1000 - 100),
                    *range(100, workload_duration * 1000, 5_000),
                })
            )
        )
        (log_dir / "provider-codesign.txt").write_text(
            f"Identifier={signing_identifier}\nTeamIdentifier=TEAM123\nCDHash="
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
        records = [
            {
                "timestamp": timestamp,
                "processID": ndjson_pid,
                "subsystem": signing_identifier,
                "eventMessage": (
                    "[rama_tproxy_example::stress_attribution] "
                    f"rama stress request attributed: run_uuid={run_uuid} "
                    f"request_id={request_id}"
                ),
            }
            for worker in (workers if role == "proxy-candidate" else ())
            for request_id in request_ids[worker]
        ]
        if not records:
            records.append({
                "timestamp": timestamp,
                "processID": ndjson_pid,
                "subsystem": signing_identifier,
                "eventMessage": "provider diagnostic",
            })
        (log_dir / "system.ndjson").write_text(
            "".join(json.dumps(record) + "\n" for record in records)
        )
        (log_dir / "system-log-capture.err").write_text("")
        (log_dir / "system-log-tool.tsv").write_text(
            f"path\t/usr/bin/log\nsha256\t{log_tool_hash}\n"
        )
        if role == "proxy-candidate":
            write_fixture_generation_samples(
                log_dir, provider_identity, start, end, signing_cdhash
            )
    metrics = write_stress_metrics(
        log_dir, str(start), str(end), "10000", "100", "67108864",
        "400", mode, provider_pid, provider_identity if monitored else None,
    )
    manifest_hash = seal_stress_evidence(
        log_dir, run_uuid, str(start), str(end), mode, provider_pid,
        role, workload_identity,
    )
    status = (
        "complete\t1\npassed\t1\nexit_code\t0\n"
        f"evidence_mode\t{mode}\n"
        f"proxy_attributed\t{1 if role == 'proxy-candidate' else 0}\n"
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
        f"system_log_tool_sha256\t{log_tool_hash}\n"
        f"attributed_request_count\t{sum(worker_counts.values()) if role == 'proxy-candidate' else 0}\n"
        "schema_complete\t1\n"
    ).encode()
    (log_dir / "stress-status.tsv").write_bytes(status)
    return run_uuid, status


def reseal_self_attested_traffic_run(log_dir: Path) -> None:
    status_path = log_dir / "stress-status.tsv"
    values = dict(
        line.split("\t", 1) for line in status_path.read_text().splitlines()
    )
    manifest_hash = seal_stress_evidence(
        log_dir,
        values["run_uuid"],
        values["run_start_epoch"],
        values["run_end_epoch"],
        values["evidence_mode"],
        values["provider_pid"],
        values["traffic_role"],
        values["workload_identity"],
    )
    rows = status_path.read_text().splitlines()
    rows = [
        f"artifact_manifest_sha256\t{manifest_hash}"
        if row.startswith("artifact_manifest_sha256\t")
        else row
        for row in rows
    ]
    status_path.write_text("\n".join(rows) + "\n")


def add_common_stress_envelope(log_dir: Path) -> None:
    legacy_path = log_dir / "stress-status.tsv"
    legacy = dict(line.split("\t", 1) for line in legacy_path.read_text().splitlines())
    role = legacy["traffic_role"]
    evidence_kind = {
        "direct-baseline": "stress-direct",
        "proxy-candidate": "stress-candidate",
        "unpaired-diagnostic": "stress-diagnostic",
    }[role]
    common_source = SCRIPT_DIR / "signed_run_evidence.py"
    (log_dir / "source-signed_run_evidence.py").write_bytes(common_source.read_bytes())
    provider_build = provider_generation = "absent"
    if role == "direct-baseline":
        absence_samples = [int(legacy["run_start_epoch"]) - 1]
        absence_samples.extend(range(
            int(legacy["run_start_epoch"]),
            int(legacy["run_end_epoch"]) + 1,
            1000,
        ))
        absence_samples.append(int(legacy["run_end_epoch"]) + 1)
        (log_dir / "provider-absence.tsv").write_text(
            "schema_version\t1\n"
            f"bundle_id\t{signed_run_evidence.DEV_PROVIDER_BUNDLE_ID}\n"
            "cadence_ms\t1000\n"
            "max_gap_ms\t2500\n"
            f"sample_count\t{len(absence_samples)}\n"
            + "".join(
                f"sample_{index:06d}\t{epoch_ms}|0|none\n"
                for index, epoch_ms in enumerate(absence_samples, start=1)
            )
            +
            "schema_complete\t1\n"
        )
    elif role == "proxy-candidate":
        command = "/fixture/provider"
        command_sha = __import__("hashlib").sha256(command.encode()).hexdigest()
        provider_build = signed_run_evidence.provider_build_identity(
            signed_run_evidence.DEV_PROVIDER_BUNDLE_ID,
            legacy["git_head"],
            signed_run_evidence.DEV_TEAM_ID,
            legacy["provider_signing_cdhash"],
            legacy["provider_executable_sha256"],
        )
        provider_start = int(legacy["run_start_epoch"])
        provider_generation = signed_run_evidence.provider_generation_identity(
            42, provider_start, command_sha
        )
        crash_snapshot = log_dir / "crashes" / "crash-snapshot.tsv"
        crash_snapshot.write_text(re.sub(
            r"provider_generation_identity\t[0-9a-f]{64}",
            f"provider_generation_identity\t{provider_generation}",
            crash_snapshot.read_text(),
        ))
        values = {
            "schema_version": "1",
            "expected_bundle_id": signed_run_evidence.DEV_PROVIDER_BUNDLE_ID,
            "expected_team_id": signed_run_evidence.DEV_TEAM_ID,
            "source_git_head": legacy["git_head"],
            "source_git_dirty": "0",
            "running_pid": "42",
            "running_start_epoch_ms": str(provider_start),
            "running_start_epoch_us": str(provider_start * 1000),
            "running_dynamic_cdhash": legacy["provider_signing_cdhash"],
            "running_command": command,
            "running_command_sha256": command_sha,
            "provider_build_identity": provider_build,
            "provider_generation_identity": provider_generation,
            "schema_complete": "1",
        }
        for prefix in ("built", "installed", "running"):
            values.update({
                f"{prefix}_bundle_id": signed_run_evidence.DEV_PROVIDER_BUNDLE_ID,
                f"{prefix}_git_head": legacy["git_head"],
                f"{prefix}_git_dirty": "0",
                f"{prefix}_team_id": signed_run_evidence.DEV_TEAM_ID,
                f"{prefix}_cdhash": legacy["provider_signing_cdhash"],
                f"{prefix}_executable_sha256": legacy["provider_executable_sha256"],
                f"{prefix}_bundle_version": "1",
                f"{prefix}_bundle_path": "/fixture/provider.systemextension",
                f"{prefix}_executable_path": "/fixture/provider",
                f"{prefix}_build_identity": provider_build,
            })
        (log_dir / "provider-identity.tsv").write_text(
            "".join(
                f"{key}\t{values[key]}\n"
                for key in signed_run_evidence.PROVIDER_IDENTITY_ORDER
            )
        )
        (log_dir / "monitor.identity.sha256").write_text(provider_generation + "\n")
        write_fixture_generation_samples(
            log_dir,
            provider_generation,
            int(legacy["run_start_epoch"]),
            int(legacy["run_end_epoch"]),
            legacy["provider_signing_cdhash"],
        )
        for resource_name in ("preflight.txt", "postflight.txt", "monitor.42.log"):
            resource_path = log_dir / resource_name
            resource_path.write_text(
                resource_path.read_text().replace("c" * 64, provider_generation)
            )
        (log_dir / "provider-codesign.txt").write_text(
            f"Identifier={signed_run_evidence.DEV_PROVIDER_BUNDLE_ID}\n"
            f"TeamIdentifier={signed_run_evidence.DEV_TEAM_ID}\n"
            f"CDHash={legacy['provider_signing_cdhash']}\n"
        )
        replacements = {
            "provider_identity": provider_generation,
            "provider_signing_identifier": signed_run_evidence.DEV_PROVIDER_BUNDLE_ID,
            "provider_signing_team": signed_run_evidence.DEV_TEAM_ID,
        }
        text = legacy_path.read_text()
        for key, value in replacements.items():
            text = re.sub(rf"(?m)^{key}\t.*$", f"{key}\t{value}", text)
        legacy_path.write_text(text)
        reseal_self_attested_traffic_run(log_dir)
        legacy = dict(line.split("\t", 1) for line in legacy_path.read_text().splitlines())

    claim_values = {
        key: legacy[key]
        for key in (
            "evidence_mode", "proxy_attributed", "evidence_claim", "traffic_role",
            "workload_identity", "artifact_manifest_sha256", "max_p95_ms",
            "min_throughput_milli_rps", "max_rss_growth_bytes", "max_cpu_percent",
            "observed_p95_ms", "observed_throughput_milli_rps",
            "observed_rss_growth_bytes", "observed_max_cpu_percent", "git_head",
            "git_dirty", "stress_script_sha256", "evidence_helper_sha256",
            "provider_pid", "provider_identity", "provider_executable_sha256",
            "provider_signing_identifier", "provider_signing_team",
            "provider_signing_cdhash", "ndjson_included", "system_log_started",
            "system_log_alive_end", "system_log_joined", "system_log_child_rc",
            "system_log_tool_sha256", "attributed_request_count",
        )
    }
    claim_values.update({
        "evidence_kind": evidence_kind,
        "run_uuid": legacy["run_uuid"],
        "traffic_start_epoch_ms": legacy["run_start_epoch"],
        "traffic_end_epoch_ms": legacy["run_end_epoch"],
        "signed_evidence_helper_sha256": sha256_file(
            log_dir / "source-signed_run_evidence.py"
        ),
        "provider_absent": "1" if role == "direct-baseline" else "0",
        "schema_complete": "1",
    })
    claims = log_dir / signed_run_evidence.CLAIMS_NAME
    claim_order = ["evidence_kind"] + sorted(
        set(claim_values) - {"evidence_kind", "schema_complete"}
    ) + ["schema_complete"]
    claims.write_text("".join(f"{key}\t{claim_values[key]}\n" for key in claim_order))
    status_values = {
        "complete": "1", "passed": "1", "exit_code": "0",
        "evidence_kind": evidence_kind, "run_uuid": legacy["run_uuid"],
        "run_start_epoch_ms": legacy["run_start_epoch"],
        "run_end_epoch_ms": legacy["run_end_epoch"],
        "git_head": legacy["git_head"], "git_dirty": legacy["git_dirty"],
        "provider_build_identity": provider_build,
        "provider_generation_identity": provider_generation,
        "workload_claims_sha256": sha256_file(claims), "schema_complete": "1",
    }
    (log_dir / signed_run_evidence.STATUS_NAME).write_text(
        "".join(
            f"{key}\t{status_values[key]}\n"
            for key in signed_run_evidence.STATUS_ORDER
        )
    )
    signed_run_evidence.seal(log_dir, actual_exit_code=0)


def reseal_common_stress_envelope(log_dir: Path) -> None:
    """Reseal both envelopes so semantic mutation tests bypass hash-only checks."""
    reseal_self_attested_traffic_run(log_dir)
    legacy = dict(
        line.split("\t", 1)
        for line in (log_dir / "stress-status.tsv").read_text().splitlines()
    )
    claims_path = log_dir / signed_run_evidence.CLAIMS_NAME
    claims = claims_path.read_text()
    claims = re.sub(
        r"artifact_manifest_sha256\t[0-9a-f]{64}",
        f"artifact_manifest_sha256\t{legacy['artifact_manifest_sha256']}",
        claims,
    )
    claims_path.write_text(claims)
    status_path = log_dir / signed_run_evidence.STATUS_NAME
    status_path.write_text(re.sub(
        r"workload_claims_sha256\t[0-9a-f]{64}",
        f"workload_claims_sha256\t{sha256_file(claims_path)}",
        status_path.read_text(),
    ))
    signed_run_evidence.seal(log_dir, actual_exit_code=0)


class StressTrafficValidationTests(unittest.TestCase):
    def test_capture_requires_group_drain_receipt_and_retires_reaped_auxiliary(self):
        helpers = "".join(self.stress_function(STRESS_SCRIPT.read_text(), name) for name in (
            "capture_drain_receipt_valid", "run_bounded_capture",
        ))
        for receipt, expected in (("42\t7\n", 7), ("", 125), ("42\t0\n", 125)):
            with self.subTest(receipt=receipt):
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    program = helpers + textwrap.dedent(f"""\
                        AUXILIARY_PIDS=(41) AUXILIARY_DRAIN_RECEIPTS=()
                        CLEANUP_INCOMPLETE=0 EVIDENCE_FAILED=0
                        python3() {{ return 0; }}
                        pid_identity() {{ printf '%s\\n' {'a' * 64}; }}
                        owned_job_has_exited() {{ return 0; }}
                        owned_tree_has_exited() {{ return 0; }}
                        wait() {{
                          printf '%s' {shlex.quote(receipt)} > "$receipt"
                          printf 'payload' > "$output"
                          return 7
                        }}
                        cat() {{
                          [[ "${{#AUXILIARY_PIDS[@]}}" == 1 && "${{AUXILIARY_PIDS[0]}}" == 41 ]] || return 90
                          command cat "$@"
                        }}
                        run_bounded_capture {shlex.quote(str(root / 'output'))} 3 unused-command
                        result=$?
                        printf 'rc=%s incomplete=%s failed=%s jobs=%s receipts=%s\\n' \\
                          "$result" "$CLEANUP_INCOMPLETE" "$EVIDENCE_FAILED" \\
                          "${{#AUXILIARY_PIDS[@]}}" "${{#AUXILIARY_DRAIN_RECEIPTS[@]}}"
                    """)
                    result = subprocess.run(["/bin/bash", "-c", program], capture_output=True, text=True, timeout=5)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    failed = int(expected == 125)
                    self.assertEqual(result.stdout, f"rc={expected} incomplete={failed} failed={failed} jobs=1 receipts=0\n")
                    self.assertEqual((root / "output").read_text(), "payload")
                    self.assertFalse(list(root.glob("*.drain.*")))

    def test_exit_cleanup_requires_receipt_for_already_exited_auxiliary(self):
        helpers = "".join(self.stress_function(STRESS_SCRIPT.read_text(), name) for name in (
            "capture_drain_receipt_valid", "cleanup_owned_jobs",
        ))
        for receipt, expected in (("42\t7\n", 0), ("", 1)):
            with self.subTest(receipt=receipt):
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    program = helpers + textwrap.dedent(f"""\
                        TMP_DIR={shlex.quote(str(root))}
                        MONITOR_STOP_FILE="$TMP_DIR/monitor-stop" GENERATION_STOP_FILE="$TMP_DIR/generation-stop"
                        RESPONSE_TMP_DIR="$TMP_DIR/responses"
                        SYSTEM_LOG_JOB_PID='' MONITOR_JOB_PID='' ABSENCE_MONITOR_JOB_PID='' GENERATION_MONITOR_JOB_PID=''
                        CLEANUP_STARTED=0 CLEANUP_INCOMPLETE=0
                        TRAFFIC_PIDS=() AUXILIARY_PIDS=(41) AUXILIARY_DRAIN_RECEIPTS=()
                        AUXILIARY_DRAIN_RECEIPTS[41]="$TMP_DIR/receipt"
                        printf '%s' {shlex.quote(receipt)} > "$TMP_DIR/receipt"
                        pid_identity() {{ return 1; }}
                        owned_job_is_active() {{ return 1; }}
                        owned_job_has_exited() {{ return 0; }}
                        owned_tree_has_exited() {{ return 0; }}
                        signal_owned_identity() {{ printf 'unexpected signal\\n' >&2; return 90; }}
                        wait() {{ [[ "$1" == 41 ]] || return 90; return 7; }}
                        cleanup_owned_jobs
                        set +u
                        printf 'incomplete=%s jobs=%s receipts=%s\\n' \\
                          "$CLEANUP_INCOMPLETE" "${{#AUXILIARY_PIDS[@]}}" "${{#AUXILIARY_DRAIN_RECEIPTS[@]}}"
                    """)
                    result = subprocess.run(["/bin/bash", "-c", program], capture_output=True, text=True, timeout=5)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertEqual(result.stderr, "")
                    self.assertEqual(result.stdout, f"incomplete={expected} jobs=0 receipts=0\n")
                    self.assertFalse((root / "receipt").exists())

    def test_empty_or_failed_ps_cannot_prove_owned_job_exit(self):
        helper = self.stress_function(STRESS_SCRIPT.read_text(), "owned_job_has_exited")
        for ps_status in (0, 1):
            with self.subTest(ps_status=ps_status):
                result = subprocess.run(
                    ["/bin/bash", "-c", helper + textwrap.dedent(f"""\
                        owned_job_is_active() {{ return 0; }}
                        ps() {{ return {ps_status}; }}
                        kill() {{ [[ "$1" == -0 && "$2" == 41 ]]; }}
                        owned_job_has_exited 41
                        printf 'exited=%s\\n' "$?"
                    """)], capture_output=True, text=True, timeout=5,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, "exited=1\n")

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
        if "STRESS_CURL_TOOL" not in env and "PATH" in overrides:
            injected_curl = Path(overrides["PATH"].split(os.pathsep, 1)[0]) / "curl"
            if injected_curl.is_file():
                env.update(
                    STRESS_CURL_TOOL=str(injected_curl),
                    STRESS_ALLOW_TEST_TOOLS="1",
                )
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

    def test_traffic_clock_has_a_shared_origin_across_processes(self):
        helper = self.stress_function(STRESS_SCRIPT.read_text(), "capture_traffic_clock")
        result = subprocess.run(
            ["bash", "-c", helper + "\ncapture_traffic_clock\nsleep 0.1\ncapture_traffic_clock\n"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=5,
        )
        self.assertEqual(result.returncode, 0, result.stdout)
        (start_epoch, start_clock), (end_epoch, end_clock) = [
            tuple(map(int, row.split())) for row in result.stdout.splitlines()
        ]
        elapsed_clock = end_clock - start_clock
        self.assertGreaterEqual(elapsed_clock, 100_000_000)
        self.assertLess(abs((end_epoch - start_epoch) * 1_000_000 - elapsed_clock), 10_000_000)

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
                    # Even one successful iteration must have nonzero integer
                    # byte throughput over the complete one-second run window.
                    downloaded=1024
                    uploaded=0
                    version=1.1
                    output=/dev/null
                    body=""
                    previous=""
                    for argument in "$@"; do
                      [[ "$argument" == --http2 ]] && version=2
                      [[ "$argument" == --head ]] && downloaded=0
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
                    printf '200\t%s\t%s\t%s\t0.050' "$downloaded" "$uploaded" "$version"
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
            post_rows = (log_dir / "post_large.log").read_text().splitlines()
            expected_hash = hashlib.sha256(bytes(1024)).hexdigest()
            self.assertTrue(all(
                row.endswith(f" response_sha256={expected_hash}") for row in post_rows
            ))
            self.assertEqual(list((log_dir / ".responses").glob("*")), [])

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
                      [[ "$argument" == --head ]] && downloaded=0
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
                    printf '200\t%s\t%s\t%s\t0.050' "$downloaded" "$uploaded" "$version"
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
            rows = (root / "logs" / "post_large.log").read_text().splitlines()
            self.assertGreater(len(rows), 0)
            wrong_hash = hashlib.sha256(b"\1" * 1024).hexdigest()
            self.assertNotEqual(wrong_hash, hashlib.sha256(bytes(1024)).hexdigest())
            self.assertTrue(all(
                row.endswith(f" response_sha256={wrong_hash}") for row in rows
            ))

    def test_post_checksum_measurement_failure_retains_rejecting_raw_record(self):
        shell = STRESS_SCRIPT.read_text()
        helpers = "".join(self.stress_function(shell, name) for name in (
            "http_status_is_ok", "transfer_matches_workload", "stress_request_id",
            "do_one_curl",
        ))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "post.body").write_bytes(bytes(8))
            (root / "responses").mkdir()
            program = helpers + textwrap.dedent(f"""\
                LOG_DIR={shlex.quote(str(root))}
                RESPONSE_TMP_DIR="$LOG_DIR/responses" POST_FILE="$LOG_DIR/post.body"
                POST_BYTES=8 TRAFFIC_ROLE=direct-baseline EVIDENCE_HELPER=unused
                RUN_UUID=00000000-0000-0000-0000-000000000001
                run_hermetic_curl() {{
                  local argument previous='' output=''
                  for argument in "$@"; do
                    [[ "$previous" == --output ]] && output="$argument"
                    previous="$argument"
                  done
                  cp "$POST_FILE" "$output"
                  printf '200\t8\t8\t2\t0.050'
                }}
                python3() {{ return 2; }}
                do_one_curl post_large unused-target 1 --http2
            """)
            result = subprocess.run(
                ["bash", "-c", program], capture_output=True, text=True, timeout=5,
            )
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            row = (root / "post_large.log").read_text()
            self.assertIn("status=200 curl_exit=0 downloaded=8 uploaded=8", row)
            self.assertTrue(row.endswith(" response_sha256=unavailable\n"))
            self.assertEqual(list((root / "responses").iterdir()), [])

    def test_post_response_checksum_requires_exact_bounded_regular_contents(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            response = root / "response"
            for length in (0, 7, 8, 9):
                with self.subTest(length=length):
                    response.write_bytes(bytes(length))
                    if length == 8:
                        self.assertEqual(
                            post_response_sha256(response, 8),
                            hashlib.sha256(bytes(8)).hexdigest(),
                        )
                    else:
                        with self.assertRaisesRegex(ValueError, "wrong byte count"):
                            post_response_sha256(response, 8)
            response.write_bytes(b"\1" * 8)
            self.assertEqual(
                post_response_sha256(response, 8), hashlib.sha256(b"\1" * 8).hexdigest()
            )
            # A larger regular file is read only through the expected body
            # and one trailing byte; its metadata is not the content proof.
            response.write_bytes(bytes(1024 * 1024))
            read_lengths = []
            real_fdopen = os.fdopen

            class ObservedFile:
                def __init__(self, *args, **kwargs):
                    self.source = real_fdopen(*args, **kwargs)

                def __enter__(self):
                    return self

                def __exit__(self, *args):
                    self.source.close()

                def fileno(self):
                    return self.source.fileno()

                def read(self, size):
                    chunk = self.source.read(size)
                    read_lengths.append(len(chunk))
                    return chunk

            with mock.patch("stress_evidence.os.fdopen", ObservedFile):
                with self.assertRaisesRegex(ValueError, "wrong byte count"):
                    post_response_sha256(response, 8)
            self.assertEqual(read_lengths, [8, 1])
            pipe = root / "pipe"
            os.mkfifo(pipe)
            with self.assertRaisesRegex(ValueError, "not a regular file"):
                post_response_sha256(pipe, 8)
            link = root / "link"
            link.symlink_to(response)
            with self.assertRaises(OSError):
                post_response_sha256(link, 8)
            for invalid_size in (0, 1_073_741_825):
                with self.assertRaisesRegex(ValueError, "invalid POST body size"):
                    post_response_sha256(response, invalid_size)

    def test_post_response_checksum_replay_rejects_invalid_raw_metadata(self):
        expected_hash = hashlib.sha256(bytes(1024)).hexdigest()
        cases = (
            ("post_large", "", "response SHA256 contract"),
            ("post_large", " response_sha256=unavailable", "malformed"),
            ("post_large", f" response_sha256={expected_hash.upper()}", "malformed"),
            ("post_large", f" response_sha256={expected_hash[:-1]}", "malformed"),
            ("post_large", f" response_sha256={expected_hash}0", "malformed"),
            ("post_large", f" response_sha256={hashlib.sha256(b'1' * 1024).hexdigest()}", "response SHA256 contract"),
            ("post_large", f" response_sha256={expected_hash} response_sha256={expected_hash}", "malformed"),
        ) + tuple(
            (worker, f" response_sha256={expected_hash}", "unexpected")
            for worker in (
                "small_https", "small_http1", "plain_http", "large_get",
                "head_only", "churn_close", "parallel_pool",
            )
        )
        with tempfile.TemporaryDirectory() as temporary:
            for index, (worker, metadata, error) in enumerate(cases):
                with self.subTest(worker=worker, metadata=metadata):
                    run = Path(temporary) / str(index)
                    run_uuid, _ = write_self_attested_traffic_run(run, post_bytes=1024)
                    raw = run / f"{worker}.log"
                    rows = [re.sub(r" response_sha256=[0-9a-f]{64}$", "", row)
                            for row in raw.read_text().splitlines()]
                    raw.write_text("".join(row + metadata + "\n" for row in rows))
                    # A passing summary cannot stand in for the raw content
                    # observation, even when byte counts and IDs are exact.
                    with self.assertRaisesRegex(ValueError, error):
                        parse_transfers(run, run_uuid)

    def test_post_response_checksum_is_replayed_by_source_and_common_verifiers(self):
        with tempfile.TemporaryDirectory() as temporary:
            for common in (False, True):
                with self.subTest(common=common):
                    run = Path(temporary) / str(common)
                    write_self_attested_traffic_run(run, post_bytes=1024)
                    if common:
                        add_common_stress_envelope(run)
                    raw = run / "post_large.log"
                    wrong_hash = hashlib.sha256(b"\1" * 1024).hexdigest()
                    raw.write_text(re.sub(
                        r"response_sha256=[0-9a-f]{64}",
                        f"response_sha256={wrong_hash}", raw.read_text(),
                    ))
                    if common:
                        reseal_common_stress_envelope(run)
                    else:
                        reseal_self_attested_traffic_run(run)
                    with self.assertRaisesRegex(ValueError, "response SHA256 contract"):
                        verify_stress_evidence(run)

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
                start=161000, end=221000, duration="0.075",
            )
            add_common_stress_envelope(baseline)
            add_common_stress_envelope(candidate)
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
            for worker in stress_compare.WORKERS:
                self.assertIn(
                    f"observed_{worker}_p95_ratio_milli\t1500\n", contents
                )
                self.assertIn(
                    f"observed_{worker}_request_throughput_ratio_milli\t1000\n",
                    contents,
                )
                self.assertIn(
                    f"observed_{worker}_byte_throughput_ratio_milli\t1000\n",
                    contents,
                )
            self.assertIn("candidate_rss_growth_bytes\t51200\n", contents)
            self.assertIn("candidate_max_cpu_percent\t20\n", contents)

    def test_common_envelopes_bind_direct_absence_and_candidate_provider_identity(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            baseline = root / "baseline"
            candidate = root / "candidate"
            comparison = root / "comparison.tsv"
            write_self_attested_traffic_run(baseline)
            write_self_attested_traffic_run(
                candidate, monitored=True, role="proxy-candidate",
                start=161000, end=221000,
            )
            add_common_stress_envelope(baseline)
            add_common_stress_envelope(candidate)
            self.assertEqual(create_comparison(baseline, candidate, comparison), 0)
            self.assertEqual(verify_comparison(baseline, candidate, comparison), 0)
            self.assertEqual(
                signed_run_evidence.verify(baseline)["provider_build_identity"],
                "absent",
            )
            self.assertRegex(
                signed_run_evidence.verify(candidate)["provider_build_identity"],
                r"^[0-9a-f]{64}$",
            )

    def test_pair_rejects_legacy_runs_without_common_signed_envelopes(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            baseline = root / "baseline"
            candidate = root / "candidate"
            write_self_attested_traffic_run(baseline)
            write_self_attested_traffic_run(
                candidate, monitored=True, role="proxy-candidate",
                start=161000, end=221000,
            )
            with self.assertRaisesRegex(ValueError, "common signed envelopes"):
                create_comparison(baseline, candidate, root / "comparison.tsv")

    def test_absolute_latency_throughput_rss_and_cpu_thresholds_are_enforced(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            direct = root / "direct"
            monitored = root / "monitored"
            write_self_attested_traffic_run(direct)
            failed_latency = write_stress_metrics(
                direct, "100000", "160000", "49", "100", "67108864",
                "400", "traffic-only", "none",
            )
            self.assertEqual(failed_latency[0], "FAILED")
            failed_throughput = write_stress_metrics(
                direct, "100000", "160000", "10000", "8001", "67108864",
                "400", "traffic-only", "none",
            )
            self.assertEqual(failed_throughput[0], "FAILED")
            write_self_attested_traffic_run(
                monitored, monitored=True, role="proxy-candidate",
                start=161000, end=221000,
            )
            failed_resources = write_stress_metrics(
                monitored, "161000", "221000", "10000", "100", "51199",
                "19", "provider-monitored-traffic-only", "42", "c" * 64,
            )
            self.assertEqual(failed_resources[0], "FAILED")
            self.assertEqual(failed_resources[6], "51200")
            self.assertEqual(failed_resources[8], "20")

    def test_verifier_rederives_metrics_and_exact_class_contracts_from_raw_transfers(self):
        mutations = {
            "wrong HTTP version": ("small_https.log", "http_version=2", "http_version=1.1"),
            "wrong download bytes": ("large_get.log", "downloaded=16777216", "downloaded=16777215"),
            "wrong upload bytes": ("post_large.log", "uploaded=8388608", "uploaded=8388607"),
            "duplicate request ID": ("small_http1.log", None, None),
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            for name, (artifact_name, old, new) in mutations.items():
                run = root / name.replace(" ", "-")
                write_self_attested_traffic_run(run)
                add_common_stress_envelope(run)
                artifact = run / artifact_name
                contents = artifact.read_text()
                if name == "duplicate request ID":
                    other_id = re.search(
                        r"request_id=([0-9a-f]{64})", (run / "small_https.log").read_text()
                    ).group(1)
                    contents = re.sub(r"request_id=[0-9a-f]{64}", f"request_id={other_id}", contents)
                else:
                    contents = contents.replace(old, new)
                artifact.write_text(contents)
                # Resealing the raw artifact and retaining the old metrics must
                # not let a fabricated metrics TSV stand in for raw evidence.
                reseal_common_stress_envelope(run)
                with self.subTest(mutation=name), self.assertRaisesRegex(
                    ValueError,
                    "wrong HTTP version|exact byte contract|globally unique",
                ):
                    verify_stress_evidence(run)

            forged = root / "forged-metrics"
            write_self_attested_traffic_run(forged)
            add_common_stress_envelope(forged)
            metrics = forged / "stress-metrics.tsv"
            metrics.write_text(metrics.read_text().replace(
                "class_small_https_p95_ms\t50",
                "class_small_https_p95_ms\t1",
            ))
            reseal_common_stress_envelope(forged)
            with self.assertRaisesRegex(ValueError, "does not match sealed raw transfers"):
                verify_stress_evidence(forged)

    def test_sealed_workload_and_monotonic_window_cannot_be_reinterpreted(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            workload_run = root / "workload"
            write_self_attested_traffic_run(workload_run)
            workload = workload_run / "stress-workload.tsv"
            workload.write_text(workload.read_text().replace(
                "large_bytes\t16777216", "large_bytes\t16777215"
            ))
            status = workload_run / "stress-status.tsv"
            status.write_text(status.read_text().replace(
                re.search(r"workload_identity\t([0-9a-f]{64})", status.read_text()).group(1),
                sha256_file(workload),
            ))
            reseal_self_attested_traffic_run(workload_run)
            with self.assertRaisesRegex(ValueError, "exact byte contract"):
                verify_stress_evidence(workload_run)

            timing_run = root / "timing"
            write_self_attested_traffic_run(timing_run)
            window = timing_run / "stress-window.tsv"
            window.write_text(window.read_text().replace(
                "traffic_end_monotonic_ns\t160000000000",
                "traffic_end_monotonic_ns\t100000000000",
            ))
            reseal_self_attested_traffic_run(timing_run)
            with self.assertRaisesRegex(ValueError, "monotonic|timing window"):
                verify_stress_evidence(timing_run)

            compressed_epoch = root / "compressed-epoch"
            write_self_attested_traffic_run(compressed_epoch)
            window = compressed_epoch / "stress-window.tsv"
            window.write_text(window.read_text().replace(
                "traffic_end_epoch_ms\t160000", "traffic_end_epoch_ms\t101000"
            ))
            reseal_self_attested_traffic_run(compressed_epoch)
            with self.assertRaisesRegex(ValueError, "timing window"):
                verify_stress_evidence(compressed_epoch)

    def test_resource_samples_bind_generation_window_order_and_cadence(self):
        mutations = {
            "wrong generation": lambda text: text.replace("c" * 64, "f" * 64, 1),
            "out of window": lambda text: re.sub(
                r"resource_sample\t100100", "resource_sample\t99999", text, count=1
            ),
            "clock rollback": lambda text: text.replace(
                "resource_sample\t105100", "resource_sample\t100050", 1
            ),
            "excessive gap": lambda text: text.replace(
                "resource_sample\t105100", "resource_sample\t108000", 1
            ),
            "one sample": lambda text: text.splitlines()[0] + "\n",
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            for name, mutation in mutations.items():
                run = root / name.replace(" ", "-")
                write_self_attested_traffic_run(
                    run, monitored=True, role="proxy-candidate"
                )
                monitor = run / "monitor.42.log"
                monitor.write_text(mutation(monitor.read_text()))
                reseal_self_attested_traffic_run(run)
                with self.subTest(name=name), self.assertRaisesRegex(
                    ValueError,
                    "generation changed|span the traffic window|unordered|cadence|lacks pre/monitor/post",
                ):
                    verify_stress_evidence(run)

            missing_post = root / "missing-post"
            write_self_attested_traffic_run(
                missing_post, monitored=True, role="proxy-candidate"
            )
            (missing_post / "postflight.txt").write_text("diagnostic only\n")
            reseal_self_attested_traffic_run(missing_post)
            with self.assertRaisesRegex(ValueError, "no provider resource sample"):
                verify_stress_evidence(missing_post)

    def test_same_contract_worker_records_cannot_be_swapped_and_resealed(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            run = Path(temp_dir) / "swapped"
            write_self_attested_traffic_run(run)
            add_common_stress_envelope(run)
            first = run / "small_https.log"
            second = run / "parallel_pool.log"
            first_rows = first.read_text().splitlines()
            second_rows = second.read_text().splitlines()
            first_rows[0], second_rows[0] = second_rows[0], first_rows[0]
            first.write_text("\n".join(first_rows) + "\n")
            second.write_text("\n".join(second_rows) + "\n")
            # The aggregate bytes/durations and global marker set are unchanged.
            reseal_common_stress_envelope(run)
            with self.assertRaisesRegex(ValueError, "canonical class/ordinal set"):
                verify_stress_evidence(run)

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
            with self.assertRaisesRegex(ValueError, "wrong provider pid"):
                verify_stress_evidence(wrong_log_pid)

    def test_diagnostic_monitored_log_requires_correlation_without_attribution(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "diagnostic"
            write_self_attested_traffic_run(root, monitored=True, role="unpaired-diagnostic")
            verify_stress_evidence(root)
            path = root / "system.ndjson"
            record = json.loads(path.read_text())
            for mutation, message in (
                ({"processID": 999}, "wrong provider pid"),
                ({"subsystem": "another.provider"}, "wrong provider subsystem"),
                ({"eventMessage": "[rama_tproxy_example::stress_attribution] "
                  "rama stress request attributed: run_uuid=broken"}, "attribution marker"),
            ):
                with self.subTest(mutation=mutation):
                    path.write_text(json.dumps(dict(record, **mutation)) + "\n")
                    reseal_self_attested_traffic_run(root)
                    with self.assertRaisesRegex(ValueError, message):
                        verify_stress_evidence(root)

    def test_diagnostic_capture_preserves_provider_logs_and_normalizes_codesign(self):
        shell = STRESS_SCRIPT.read_text()
        predicate = shell.split('    LOG_PREDICATE="processID', 1)[1].split(
            '    "$LOG_TOOL" stream', 1
        )[0]
        predicate = 'LOG_PREDICATE="processID' + predicate
        for role, marker_only in (("unpaired-diagnostic", False), ("proxy-candidate", True)):
            result = subprocess.run(
                ["bash", "-c", "MONITOR_PID=42; EXPECTED_PROVIDER_SUBSYSTEM=org.provider; "
                 "EXPECTED_STRESS_EVENT_PREFIX=attribution; TRAFFIC_ROLE=" + role + "\n"
                 + predicate + 'printf "%s\\n" "$LOG_PREDICATE"'],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            )
            self.assertEqual(result.returncode, 0, result.stdout)
            self.assertEqual(result.stdout.strip(),
                             "processID == 42 AND subsystem == 'org.provider'"
                             + (" AND eventMessage BEGINSWITH 'attribution'" if marker_only else ""))
        legacy = shell.split('      MONITOR_IDENTITY="$MONITOR_RUNTIME_IDENTITY"', 1)[1].split(
            '\n    fi\n    printf', 1
        )[0]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "provider").write_bytes(b"fixture executable")
            result = subprocess.run(
                ["bash", "-c", 'LOG_DIR="$1"; MONITOR_PID=42; MONITOR_IDENTITY=fixture\n'
                 'ps() { printf "%s/provider\\n" "$LOG_DIR"; }\n'
                 'codesign() { printf "Executable=/fixture/provider\\nIdentifier=org.provider\\n'
                 'Format=app bundle\\nTeamIdentifier=TEAM\\nCDHash=abc123\\n" >&2; }\n'
                 + legacy, "fixture", str(root)],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            )
            self.assertEqual(result.returncode, 0, result.stdout)
            self.assertEqual((root / "provider-codesign.txt").read_text(),
                             "Identifier=org.provider\nTeamIdentifier=TEAM\nCDHash=abc123\n")

    def test_request_attribution_rejects_missing_duplicate_wrong_uuid_and_emitter(self):
        mutations = {
            "missing": lambda rows: rows[:-1],
            "duplicate": lambda rows: rows + [rows[-1]],
            "wrong UUID": lambda rows: [
                {**row, "eventMessage": row["eventMessage"].replace(
                    re.search(r"run_uuid=([^ ]+)", row["eventMessage"]).group(1),
                    "12345678-1234-4234-8234-123456789abc",
                )}
                for row in rows
            ],
            "wrong request ID": lambda rows: [
                {**row, "eventMessage": re.sub(
                    r"request_id=[0-9a-f]{64}$",
                    f"request_id={'0' * 64}",
                    row["eventMessage"],
                )}
                if index == 0 else row
                for index, row in enumerate(rows)
            ],
            "wrong provider subsystem": lambda rows: [
                {**row, "subsystem": "org.example.wrong-emitter"} for row in rows
            ],
            "outside run window": lambda rows: [
                {**row, "timestamp": "1970-01-01T00:00:00.000000+00:00"}
                for row in rows
            ],
            "non-marker row": lambda rows: [
                {**row, "eventMessage": "provider diagnostic"} for row in rows
            ],
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            for name, mutate in mutations.items():
                candidate = root / name.replace(" ", "-")
                write_self_attested_traffic_run(
                    candidate, monitored=True, role="proxy-candidate"
                )
                add_common_stress_envelope(candidate)
                ndjson = candidate / "system.ndjson"
                rows = [json.loads(line) for line in ndjson.read_text().splitlines()]
                ndjson.write_text(
                    "".join(json.dumps(row) + "\n" for row in mutate(rows))
                )
                reseal_common_stress_envelope(candidate)
                with self.subTest(mutation=name), self.assertRaises(ValueError) as error:
                    verify_stress_evidence(candidate)
                self.assertRegex(
                    str(error.exception),
                    "marker set|duplicate stress request marker|wrong run UUID|wrong provider subsystem|exact run window|malformed stress attribution marker",
                )

    def test_sealed_ndjson_rejects_duplicate_keys_in_candidate_and_diagnostic_logs(self):
        with tempfile.TemporaryDirectory() as temporary:
            for role in ("proxy-candidate", "unpaired-diagnostic"):
                root = Path(temporary) / role
                write_self_attested_traffic_run(root, monitored=True, role=role)
                if role == "proxy-candidate":
                    add_common_stress_envelope(root)
                    reseal = reseal_common_stress_envelope
                else:
                    reseal = reseal_self_attested_traffic_run
                path = root / "system.ndjson"
                lines = path.read_text().splitlines()
                record = json.loads(lines[0])
                record["future_field"] = {"nested": [1, True, None]}
                encoded = json.dumps(record)

                def verify_line(line):
                    path.write_text("\n".join([line, *lines[1:]]) + "\n")
                    reseal(root)
                    return verify_stress_evidence(root)

                verify_line(encoded)
                for key, original in record.items():
                    for duplicate in (original, "foreign", 999, True, None, [], {}):
                        field = json.dumps(key) + ":" + json.dumps(duplicate)
                        for line in (
                            "{" + field + "," + encoded[1:],
                            encoded[:-1] + "," + field + "}",
                        ):
                            with self.subTest(role=role, key=key, duplicate=duplicate, line=line):
                                with self.assertRaisesRegex(ValueError, "malformed system.ndjson"):
                                    verify_line(line)
                for nested in ('{"key":0,"key":1}', '[{"key":0,"key":1}]'):
                    line = encoded[:-1] + ',"future_nested":' + nested + "}"
                    with self.subTest(role=role, nested=nested):
                        with self.assertRaisesRegex(ValueError, "malformed system.ndjson"):
                            verify_line(line)

    def test_pair_and_series_timing_caps_are_not_configurable_above_ten_minutes(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            baseline = root / "baseline"
            candidate = root / "candidate"
            write_self_attested_traffic_run(baseline)
            write_self_attested_traffic_run(
                candidate, monitored=True, role="proxy-candidate",
                start=161000, end=221000,
            )
            with self.assertRaisesRegex(ValueError, "integer overflow"):
                create_comparison(
                    baseline, candidate, root / "comparison.tsv",
                    "1500", "667", "600001",
                )

    def test_pair_rejects_dirty_mismatched_heads_and_reused_run_uuid(self):
        mutations = (
            ("git_dirty\t0", "git_dirty\t1", "same clean git head"),
            (f"git_head\t{'a' * 40}", f"git_head\t{'b' * 40}", "same clean git head"),
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            for index, (old, new, expected) in enumerate(mutations):
                baseline = root / f"baseline-{index}"
                candidate = root / f"candidate-{index}"
                write_self_attested_traffic_run(baseline)
                write_self_attested_traffic_run(
                    candidate, monitored=True, role="proxy-candidate",
                    start=161000, end=221000,
                )
                candidate_status = candidate / "stress-status.tsv"
                candidate_status.write_text(
                    candidate_status.read_text().replace(old, new)
                )
                if old.startswith("git_dirty"):
                    (candidate / "git-status.txt").write_text(" M fixture\n")
                else:
                    (candidate / "git-head.txt").write_text("b" * 40 + "\n")
                reseal_self_attested_traffic_run(candidate)
                with self.subTest(expected=expected), self.assertRaisesRegex(
                    ValueError, expected
                ):
                    create_comparison(
                        baseline, candidate, root / f"comparison-{index}.tsv"
                    )

            baseline = root / "baseline-uuid"
            candidate = root / "candidate-uuid"
            baseline_uuid, _ = write_self_attested_traffic_run(baseline)
            write_self_attested_traffic_run(
                candidate, monitored=True, role="proxy-candidate",
                start=161000, end=221000,
            )
            status_path = candidate / "stress-status.tsv"
            candidate_uuid = dict(
                row.split("\t", 1) for row in status_path.read_text().splitlines()
            )["run_uuid"]
            status_path.write_text(
                status_path.read_text().replace(candidate_uuid, baseline_uuid)
            )
            ndjson = candidate / "system.ndjson"
            ndjson.write_text(
                ndjson.read_text()
                .replace(candidate_uuid, baseline_uuid)
                .replace(
                    candidate_uuid.replace("-", ""), baseline_uuid.replace("-", "")
                )
            )
            for worker in stress_compare.WORKERS:
                worker_log = candidate / f"{worker}.log"
                worker_log.write_text(worker_log.read_text().replace(
                    candidate_uuid.replace("-", ""), baseline_uuid.replace("-", "")
                ))
            crash_snapshot = candidate / "crashes" / "crash-snapshot.tsv"
            crash_snapshot.write_text(
                crash_snapshot.read_text().replace(candidate_uuid, baseline_uuid)
            )
            reseal_self_attested_traffic_run(candidate)
            with self.assertRaisesRegex(ValueError, "reused a run UUID"):
                create_comparison(baseline, candidate, root / "same-uuid.tsv")

    def test_paired_gate_enforces_ratios_and_rejects_tampered_verdict(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            baseline = root / "baseline"
            candidate = root / "candidate"
            comparison = root / "stress-comparison.tsv"
            write_self_attested_traffic_run(baseline)
            write_self_attested_traffic_run(
                candidate, monitored=True, role="proxy-candidate",
                start=161000, end=221000, duration="0.075",
            )
            add_common_stress_envelope(baseline)
            add_common_stress_envelope(candidate)
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
                start=161000, end=221000,
            )
            add_common_stress_envelope(baseline)
            add_common_stress_envelope(candidate)
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
                ({"start": 800000, "end": 860000}, {}, "not adjacent"),
                ({}, {"role": "unpaired-diagnostic"}, "not an explicit"),
            )
            for index, (candidate_kwargs, baseline_kwargs, expected) in enumerate(cases):
                baseline = root / f"baseline-{index}"
                candidate = root / f"candidate-{index}"
                write_self_attested_traffic_run(baseline, **baseline_kwargs)
                candidate_options = {
                    "monitored": True, "role": "proxy-candidate",
                    "start": 161000, "end": 221000,
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

    def test_release_pair_rejects_weakened_workload_and_relaxed_resource_policy(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            weak_baseline = root / "weak-baseline"
            weak_candidate = root / "weak-candidate"
            weak = dict(
                workload_duration=1,
                workload_concurrency=1,
                large_bytes=1024,
                post_bytes=1024,
            )
            write_self_attested_traffic_run(
                weak_baseline, start=100000, end=101000, **weak
            )
            write_self_attested_traffic_run(
                weak_candidate, monitored=True, role="proxy-candidate",
                start=102000, end=103000, **weak,
            )
            add_common_stress_envelope(weak_baseline)
            add_common_stress_envelope(weak_candidate)
            with self.assertRaisesRegex(ValueError, "canonical load profile"):
                create_comparison(
                    weak_baseline, weak_candidate, root / "weak-comparison.tsv"
                )

            relaxed_baseline = root / "relaxed-baseline"
            relaxed_candidate = root / "relaxed-candidate"
            write_self_attested_traffic_run(relaxed_baseline)
            write_self_attested_traffic_run(
                relaxed_candidate, monitored=True, role="proxy-candidate",
                start=161000, end=221000,
            )
            for run, generation in (
                (relaxed_baseline, None),
                (relaxed_candidate, "c" * 64),
            ):
                status_path = run / "stress-status.tsv"
                status = dict(
                    row.split("\t", 1) for row in status_path.read_text().splitlines()
                )
                metrics = write_stress_metrics(
                    run,
                    status["run_start_epoch"],
                    status["run_end_epoch"],
                    "10000",
                    "100",
                    "10737418240",
                    "10000",
                    status["evidence_mode"],
                    status["provider_pid"],
                    generation,
                )
                replacements = {
                    "max_rss_growth_bytes": "10737418240",
                    "max_cpu_percent": "10000",
                    "observed_rss_growth_bytes": metrics[6],
                    "observed_max_cpu_percent": metrics[8],
                }
                text = status_path.read_text()
                for key, value in replacements.items():
                    text = re.sub(rf"(?m)^{key}\t.*$", f"{key}\t{value}", text)
                status_path.write_text(text)
                reseal_self_attested_traffic_run(run)
                add_common_stress_envelope(run)
            with self.assertRaisesRegex(ValueError, "hard threshold policy"):
                create_comparison(
                    relaxed_baseline,
                    relaxed_candidate,
                    root / "relaxed-comparison.tsv",
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
                baseline_start = 100000 + (index - 1) * 122000
                write_self_attested_traffic_run(
                    baseline, start=baseline_start, end=baseline_start + 60000
                )
                write_self_attested_traffic_run(
                    candidate, monitored=True, role="proxy-candidate",
                    start=baseline_start + 61000, end=baseline_start + 121000,
                    duration=duration,
                )
                add_common_stress_envelope(baseline)
                add_common_stress_envelope(candidate)
                self.assertEqual(
                    create_comparison(baseline, candidate, comparison), 0
                )
                pairs.append((baseline, candidate, comparison))

            with self.assertRaisesRegex(ValueError, "integer overflow"):
                stress_compare.series_rows(pairs, "600001")
            series = root / "stress-series"
            self.assertEqual(create_series(pairs, series), 0)
            self.assertEqual(verify_series(pairs, series), 0)
            self.assertEqual(verify_series(series), 0)
            self.assertEqual(
                signed_run_evidence.verify(series)["evidence_kind"],
                "stress-series",
            )
            self.assertTrue(
                (series / "members" / "pair-003" / "candidate"
                 / signed_run_evidence.MANIFEST_NAME).is_file()
            )
            series_artifact = series / stress_compare.SERIES_ARTIFACT_NAME
            contents = series_artifact.read_text()
            self.assertIn("pair_count\t3\n", contents)
            self.assertIn("median_p95_ratio_milli\t1200\n", contents)
            self.assertIn("worst_p95_ratio_milli\t1500\n", contents)
            self.assertIn("worst_throughput_ratio_milli\t1000\n", contents)
            for worker in stress_compare.WORKERS:
                self.assertIn(f"worst_{worker}_p95_ratio_milli\t1500\n", contents)
                self.assertIn(
                    f"worst_{worker}_request_throughput_ratio_milli\t1000\n",
                    contents,
                )
                self.assertIn(
                    f"worst_{worker}_byte_throughput_ratio_milli\t1000\n",
                    contents,
                )
            self.assertIn("worst_candidate_rss_growth_bytes\t51200\n", contents)
            self.assertEqual(
                stress_compare.comparison_source_path(series_artifact).read_bytes(),
                stress_compare.current_source_path().read_bytes(),
            )

            with self.assertRaisesRegex(ValueError, "exactly three"):
                create_series(pairs[:2], root / "too-short")
            reordered = [pairs[0], pairs[2], pairs[1]]
            with self.assertRaisesRegex(ValueError, "interleaved and adjacent"):
                create_series(reordered, root / "reordered")

            self.assertEqual(
                create_comparison(*pairs[2], "1600", "667", "600000"), 0
            )
            with self.assertRaisesRegex(ValueError, "weakened the p95"):
                create_series(pairs, root / "weakened")
            self.assertEqual(create_comparison(*pairs[2]), 0)

            series_artifact.write_text(
                contents.replace(
                    "worst_small_https_p95_ratio_milli\t1500",
                    "worst_small_https_p95_ratio_milli\t1",
                )
            )
            claims = series / signed_run_evidence.CLAIMS_NAME
            claim_text = claims.read_text()
            claim_text = re.sub(
                r"series_artifact_sha256\t[0-9a-f]{64}",
                f"series_artifact_sha256\t{sha256_file(series_artifact)}",
                claim_text,
            )
            claims.write_text(claim_text)
            common_status = series / signed_run_evidence.STATUS_NAME
            common_status.write_text(re.sub(
                r"workload_claims_sha256\t[0-9a-f]{64}",
                f"workload_claims_sha256\t{sha256_file(claims)}",
                common_status.read_text(),
            ))
            signed_run_evidence.seal(series, actual_exit_code=0)
            with self.assertRaisesRegex(ValueError, "does not match"):
                verify_series(pairs, series)
            cli = subprocess.run(
                [
                    sys.executable,
                    str(stress_compare.current_source_path()),
                    "verify-series",
                    str(series),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            self.assertEqual(cli.returncode, 2, cli.stdout)
            self.assertIn("does not match", cli.stdout)

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
                STRESS_CURL_TOOL=str(fake_curl),
                STRESS_ALLOW_TEST_TOOLS="1",
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
            self.assertIn("exit_code\t143\n", status)
            self.assertIn("stress run interrupted by signal", status)

    def test_early_exit_is_finalized_as_incomplete_with_the_actual_exit_code(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            fake_curl = fake_bin / "curl"
            private_error = "private-user-target.invalid/secret-token"
            fake_curl.write_text(
                "#!/usr/bin/env bash\n"
                f"printf '%s\\n' {shlex.quote(private_error)} >&2\n"
                "exit 7\n"
            )
            fake_curl.chmod(0o755)
            log_dir = root / "logs"
            result = self.run_stress(
                log_dir,
                PATH=f"{fake_bin}{os.pathsep}{os.environ['PATH']}",
                STRESS_DURATION="1",
                STRESS_CONCURRENCY="1",
                STRESS_POST_BYTES="1",
            )
            self.assertEqual(result.returncode, 2, result.stdout)
            status = (log_dir / "stress-status.tsv").read_text()
            self.assertIn("complete\t0\n", status)
            self.assertIn("passed\t0\n", status)
            self.assertIn("exit_code\t2\n", status)
            self.assertIn("exited before its terminal verdict", status)
            self.assertNotIn(private_error, result.stdout)
            for artifact in log_dir.rglob("*"):
                if artifact.is_file():
                    self.assertNotIn(
                        private_error,
                        artifact.read_text(encoding="utf-8", errors="ignore"),
                    )

    def test_terminal_seal_includes_cleanup_and_survives_exit_trap(self):
        from test_signed_run_evidence import make_run

        shell = STRESS_SCRIPT.read_text()
        functions = "".join(self.stress_function(shell, name) for name in (
            "pid_identity", "owned_job_is_active", "collect_owned_tree",
            "signal_owned_identity", "owned_job_has_exited",
            "owned_identity_has_exited", "owned_tree_has_exited",
            "capture_drain_receipt_valid", "cleanup_owned_jobs",
            "write_terminal_status", "seal_and_verify_common_evidence", "handle_exit",
        ))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "evidence"
            make_run(root, "modern_udp", claims=[
                ("dial9_workload_coverage", "1"),
                ("dial9_claim", "exact-workload"),
            ])
            program = functions + textwrap.dedent(f"""\
                set -eu
                LOG_DIR={shlex.quote(str(root))}
                COMMON_EVIDENCE_HELPER={shlex.quote(str(SCRIPT_DIR / 'signed_run_evidence.py'))}
                MONITOR_STOP_FILE="$LOG_DIR/.monitor.stop"
                GENERATION_STOP_FILE="$LOG_DIR/.generation.stop"
                RESPONSE_TMP_DIR="$LOG_DIR/responses"
                TRAFFIC_PIDS=() AUXILIARY_PIDS=() AUXILIARY_DRAIN_RECEIPTS=()
                MONITOR_JOB_PID="" ABSENCE_MONITOR_JOB_PID=""
                GENERATION_MONITOR_JOB_PID="" SYSTEM_LOG_JOB_PID=""
                CLEANUP_STARTED=0 CLEANUP_INCOMPLETE=0
                ANALYZE_ONLY=0 TRAFFIC_ROLE=direct-baseline
                TERMINAL_STATUS_WRITTEN=0 TERMINAL_EXIT_CODE=2
                # Keep the strict common fixture; exercise the actual writer's
                # cleanup/seal/EXIT composition without native traffic.
                write_stress_status() {{ [[ "$*" == '1 1 0' ]]; }}
                write_common_evidence() {{ [[ "$*" == '1 1 0' ]]; }}
                trap handle_exit EXIT
                write_terminal_status 1 1 0
                [[ "$CLEANUP_STARTED" == 1 && "$CLEANUP_INCOMPLETE" == 0 ]]
                [[ -f "$MONITOR_STOP_FILE" && -f "$GENERATION_STOP_FILE" ]]
                [[ -z "$(jobs -p)" ]]
                exit "$TERMINAL_EXIT_CODE"
            """)
            result = subprocess.run(
                ["bash", "-c", program], capture_output=True, text=True, timeout=10,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(signed_run_evidence.verify(root, actual_exit_code=0)["passed"], "1")

    def test_terminal_cleanup_failure_cannot_keep_a_passing_status(self):
        shell = STRESS_SCRIPT.read_text()
        program = self.stress_function(shell, "write_terminal_status") + textwrap.dedent("""\
            set -eu
            ANALYZE_ONLY=0 TRAFFIC_ROLE=direct-baseline CLEANUP_INCOMPLETE=0
            cleanup_owned_jobs() { CLEANUP_INCOMPLETE=1; }
            write_stress_status() { [[ "$1 $2 $3" == '0 0 2' ]]; }
            write_common_evidence() { [[ "$*" == '0 0 2' ]]; }
            seal_and_verify_common_evidence() { [[ "$1" == 2 ]]; }
            write_terminal_status 1 1 0
            [[ "$TERMINAL_EXIT_CODE" == 2 && "$TERMINAL_STATUS_WRITTEN" == 1 ]]
        """)
        result = subprocess.run(
            ["bash", "-c", program], capture_output=True, text=True, timeout=3,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_system_log_shutdown_preserves_generation_samples_through_forensics(self):
        shell = STRESS_SCRIPT.read_text()
        functions = "".join(
            self.stress_function(shell, name)
            for name in (
                "pid_identity", "owned_job_is_active", "collect_owned_tree",
                "signal_owned_identity", "owned_job_has_exited",
                "owned_identity_has_exited", "owned_tree_has_exited",
                "wait_proven_exited", "capture_drain_receipt_valid", "cleanup_owned_jobs",
                "monitor_provider_generation",
            )
        )
        start = shell.index(
            '  if [[ -n "$SYSTEM_LOG_JOB_PID" ]]; then\n',
            shell.index('  read -r TRAFFIC_END_EPOCH'),
        )
        end = shell.index('\n  fi\n', start) + len('\n  fi\n')
        shutdown = shell[start:end]
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            helper = root / "sample-generation"
            samples = root / "samples"
            helper.write_text(
                "#!/usr/bin/env bash\n"
                f"date +%s >> {shlex.quote(str(samples))}\n"
            )
            helper.chmod(0o755)
            program = functions + textwrap.dedent(f"""
                set -u
                LOG_DIR={shlex.quote(str(root))}
                COMMON_EVIDENCE_HELPER={shlex.quote(str(helper))}
                TRAFFIC_PIDS=()
                AUXILIARY_PIDS=()
                MONITOR_JOB_PID=""
                ABSENCE_MONITOR_JOB_PID=""
                MONITOR_STOP_FILE="$LOG_DIR/monitor.stop"
                GENERATION_STOP_FILE="$LOG_DIR/generation.stop"
                RESPONSE_TMP_DIR="$LOG_DIR/responses"
                CLEANUP_STARTED=0
                CLEANUP_INCOMPLETE=0
                EVIDENCE_FAILED=0
                SYSTEM_LOG_ALIVE_END=0
                SYSTEM_LOG_JOINED=0
                SYSTEM_LOG_CHILD_RC=none
                RED="" RESET=""
                say() {{ printf '%s\\n' "$*"; }}
                monitor_provider_generation &
                GENERATION_MONITOR_JOB_PID=$!
                sleep 30 &
                SYSTEM_LOG_JOB_PID=$!
                SYSTEM_LOG_JOB_IDENTITY="$(pid_identity "$SYSTEM_LOG_JOB_PID" generation || true)"
                [[ "$SYSTEM_LOG_JOB_IDENTITY" =~ ^[0-9a-f]{{64}}$ ]] || exit 77
                deadline=$((SECONDS + 4))
                while [[ ! -s {shlex.quote(str(samples))} ]] && (( SECONDS < deadline )); do
                  sleep 0.05
                done
                [[ -s {shlex.quote(str(samples))} ]] || exit 3
                {shutdown}
                [[ "$CLEANUP_STARTED" == 0 && "$CLEANUP_INCOMPLETE" == 0 \
                  && "$EVIDENCE_FAILED" == 0 && "$SYSTEM_LOG_JOINED" == 1 ]] || exit 4
                [[ ! -e "$GENERATION_STOP_FILE" ]] || exit 5
                kill -0 "$GENERATION_MONITOR_JOB_PID" 2>/dev/null || exit 6
                # Postflight/crash collection may outlast the 5-second allowed
                # sample gap. The same sampler must remain active throughout.
                sleep 6
                [[ $(wc -l < {shlex.quote(str(samples))}) -ge 3 ]] || exit 7
                : > "$GENERATION_STOP_FILE"
                wait_proven_exited "$GENERATION_MONITOR_JOB_PID" 4 || exit 8
                GENERATION_MONITOR_JOB_PID=""
                # Partial logger shutdown must not disable the final cleanup
                # of jobs started by subsequent forensic collection.
                sleep 30 & AUXILIARY_PIDS+=("$!")
                cleanup_owned_jobs
                [[ "$CLEANUP_STARTED" == 1 && "$CLEANUP_INCOMPLETE" == 0 ]] || exit 9
                [[ -z "$(jobs -p)" ]] || exit 10
                echo generation-sampler-preserved
            """)
            process = subprocess.Popen(
                ["bash", "-c", program], stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, text=True, start_new_session=True,
            )
            try:
                output, _ = process.communicate(timeout=20)
            finally:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=5)
            if process.returncode == 77:
                self.skipTest("host sandbox blocks process identity inspection")
            self.assertEqual(process.returncode, 0, output)
            self.assertEqual(output.splitlines()[-1], "generation-sampler-preserved")
            epochs = [int(value) for value in samples.read_text().splitlines()]
            self.assertGreaterEqual(len(epochs), 3)
            self.assertTrue(all(0 < right - left <= 5 for left, right in zip(epochs, epochs[1:])))

    def test_term_resistant_system_logger_is_forcibly_reaped_and_not_accepted(self):
        shell = STRESS_SCRIPT.read_text()
        functions = "".join(
            self.stress_function(shell, name)
            for name in (
                "pid_identity", "owned_job_is_active", "collect_owned_tree",
                "signal_owned_identity", "owned_job_has_exited",
                "owned_identity_has_exited", "owned_tree_has_exited",
                "capture_drain_receipt_valid", "cleanup_owned_jobs",
            )
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            stop_file = Path(temp_dir) / "monitor.stop"
            ready_file = Path(temp_dir) / "logger.ready"
            logger = (
                "import pathlib,signal,time; "
                "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
                f"pathlib.Path({str(ready_file)!r}).touch(); time.sleep(30)"
            )
            program = functions + textwrap.dedent(
                f"""
                set -u
                TRAFFIC_PIDS=()
                AUXILIARY_PIDS=()
                MONITOR_JOB_PID=""
                ABSENCE_MONITOR_JOB_PID=""
                GENERATION_MONITOR_JOB_PID=""
                MONITOR_STOP_FILE={shlex.quote(str(stop_file))}
                GENERATION_STOP_FILE={shlex.quote(str(Path(temp_dir) / 'generation.stop'))}
                RESPONSE_TMP_DIR={shlex.quote(str(Path(temp_dir) / 'responses'))}
                CLEANUP_STARTED=0
                CLEANUP_INCOMPLETE=0
                SYSTEM_LOG_ALIVE_END=0
                SYSTEM_LOG_JOINED=0
                SYSTEM_LOG_CHILD_RC=none
                python3 -c {shlex.quote(logger)} &
                SYSTEM_LOG_JOB_PID=$!
                for _ in $(seq 1 200); do
                  [[ -e {shlex.quote(str(ready_file))} ]] && break
                  sleep 0.01
                done
                [[ -e {shlex.quote(str(ready_file))} ]] || exit 9
                SYSTEM_LOG_JOB_IDENTITY="$(pid_identity "$SYSTEM_LOG_JOB_PID" generation || true)"
                if [[ ! "$SYSTEM_LOG_JOB_IDENTITY" =~ ^[0-9a-f]{{64}}$ ]]; then
                  kill -KILL "$SYSTEM_LOG_JOB_PID" 2>/dev/null || true
                  wait "$SYSTEM_LOG_JOB_PID" 2>/dev/null || true
                  exit 77
                fi
                cleanup_owned_jobs
                printf 'alive=%s joined=%s rc=%s jobs=%s\n' \
                  "$SYSTEM_LOG_ALIVE_END" "$SYSTEM_LOG_JOINED" \
                  "$SYSTEM_LOG_CHILD_RC" "$(jobs -p | wc -l | tr -d ' ')"
                """
            )
            result = subprocess.run(
                ["bash", "-c", program],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=12,
            )
            if result.returncode == 77 or (
                result.returncode != 0 and "Operation not permitted" in result.stdout
            ):
                self.skipTest("host sandbox blocks process identity inspection")
            self.assertEqual(result.returncode, 0, result.stdout)
            self.assertEqual(result.stdout.splitlines()[-1], "alive=1 joined=1 rc=137 jobs=0")

    def test_bounded_capture_reaps_a_term_resistant_descendant_tree(self):
        probe = subprocess.Popen(["sleep", "5"])
        try:
            try:
                pgrep = subprocess.run(
                    ["pgrep", "-P", str(os.getpid())],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    text=True,
                )
                snapshot = subprocess.run(
                    ["ps", "-ww", "-o", "pid=", "-o", "lstart=", "-o", "command=", "-p", str(probe.pid)],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    text=True,
                )
            except OSError:
                self.skipTest("host sandbox blocks process-tree inspection")
        finally:
            probe.terminate()
            probe.wait(timeout=5)
        if (
            pgrep.returncode != 0
            or str(probe.pid) not in pgrep.stdout.splitlines()
            or snapshot.returncode != 0
            or not snapshot.stdout.strip()
        ):
            self.skipTest("host sandbox blocks process-tree inspection")
        shell = STRESS_SCRIPT.read_text()
        functions = "".join(
            self.stress_function(shell, name)
            for name in (
                "pid_identity", "owned_job_is_active", "owned_job_has_exited",
                "owned_identity_has_exited", "owned_tree_has_exited",
                "collect_owned_tree", "signal_owned_identity", "capture_drain_receipt_valid", "run_bounded_capture",
            )
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            pids = root / "pids"
            wrapper = root / "hanging-attach"
            wrapper.write_text(textwrap.dedent(f"""\
                #!/usr/bin/env bash
                trap '' TERM
                printf '%s\\n' "$$" >> {shlex.quote(str(pids))}
                bash -c 'trap "" TERM; printf "%s\\n" "$$" >> "$1"; while :; do sleep 1; done' \
                  child {shlex.quote(str(pids))} &
                wait "$!"
                """))
            wrapper.chmod(0o755)
            program = functions + textwrap.dedent(f"""
                set +e
                AUXILIARY_PIDS=()
                CLEANUP_INCOMPLETE=0
                EVIDENCE_FAILED=0
                BOUNDED_CAPTURE_TIMED_OUT=0
                run_bounded_capture {shlex.quote(str(root / 'output'))} 1 \
                  {shlex.quote(str(wrapper))}
                rc=$?
                printf 'rc=%s incomplete=%s evidence=%s timeout=%s jobs=%s\n' \
                  "$rc" "$CLEANUP_INCOMPLETE" "$EVIDENCE_FAILED" \
                  "$BOUNDED_CAPTURE_TIMED_OUT" "$(jobs -p | wc -l | tr -d ' ')"
            """)
            result = subprocess.run(
                ["bash", "-c", program],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=12,
            )
            pid_values = [
                int(value) for value in pids.read_text().splitlines()
            ] if pids.exists() else []
            survivors = []
            for pid in pid_values:
                deadline = time.monotonic() + 2
                while time.monotonic() < deadline:
                    try:
                        os.kill(pid, 0)
                    except ProcessLookupError:
                        break
                    time.sleep(0.05)
                else:
                    survivors.append(pid)
            if result.returncode != 0 and "Operation not permitted" in result.stdout:
                for pid in survivors:
                    try:
                        os.kill(pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                self.skipTest("host sandbox blocks process-tree inspection")
            self.assertEqual(result.returncode, 0, result.stdout)
            self.assertEqual(
                result.stdout.splitlines()[-1],
                "rc=124 incomplete=0 evidence=1 timeout=1 jobs=0",
            )
            self.assertFalse(survivors, f"bounded capture descendants survived: {survivors}")

    def test_capture_preserves_terminal_session_and_drains_owned_group(self):
        from test_modern_udp_evidence import exercise_capture_terminal_context
        shell = STRESS_SCRIPT.read_text()
        helpers = "".join(self.stress_function(shell, name) for name in (
            "pid_identity", "owned_job_is_active", "owned_job_has_exited",
            "owned_identity_has_exited", "owned_tree_has_exited", "collect_owned_tree",
            "signal_owned_identity", "capture_drain_receipt_valid", "run_bounded_capture",
        ))
        exercise_capture_terminal_context(self, helpers, stress=True)

    def run_stopped_grandchild_cleanup_fixture(
        self, *, capture=False, deny_kill=False, early_orphan=False, expire_discovery=False
    ):
        shell = STRESS_SCRIPT.read_text()
        functions = "".join(
            self.stress_function(shell, name)
            for name in (
                "pid_identity", "owned_job_is_active", "owned_job_has_exited",
                "owned_identity_has_exited", "owned_tree_has_exited",
                "collect_owned_tree", "signal_owned_identity",
                "capture_drain_receipt_valid", "cleanup_owned_jobs", "run_bounded_capture",
            )
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            pids = root / "pids"
            leaf_file = root / "leaf"
            ready_file = root / "ready"
            tree = root / "tree.py"
            tree.write_text(textwrap.dedent(f"""\
                import os
                import pathlib
                import signal
                import time

                # Keep the test's output pipe open even when capture redirects
                # stdout. communicate() must wait for this grandchild to die.
                os.dup2(3, 1)
                os.dup2(3, 2)
                with open({str(pids)!r}, 'a') as output:
                    output.write(str(os.getpid()) + '\\n')
                leaf = False
                if os.fork() == 0:
                    with open({str(pids)!r}, 'a') as output:
                        output.write(str(os.getpid()) + '\\n')
                    if os.fork() == 0:
                        leaf = True
                        with open({str(pids)!r}, 'a') as output:
                            output.write(str(os.getpid()) + '\\n')
                        signal.signal(signal.SIGTERM, signal.SIG_IGN)
                        pathlib.Path({str(leaf_file)!r}).write_text(str(os.getpid()))
                        pathlib.Path({str(ready_file)!r}).touch()
                        os.kill(os.getpid(), signal.SIGSTOP)
                if {early_orphan!r} and not leaf:
                    os._exit(0)
                time.sleep(30)
                """))
            wrapper = root / "exec-tree"
            wrapper.write_text(
                "#!/usr/bin/env bash\nsleep 0.2\n"
                f"exec {shlex.quote(sys.executable)} {shlex.quote(str(tree))}\n"
            )
            wrapper.chmod(0o755)
            program = functions + textwrap.dedent(f"""
                set -u
                exec 3>&1
                TRAFFIC_PIDS=()
                AUXILIARY_PIDS=()
                MONITOR_JOB_PID=""
                ABSENCE_MONITOR_JOB_PID=""
                GENERATION_MONITOR_JOB_PID=""
                SYSTEM_LOG_JOB_PID=""
                SYSTEM_LOG_JOB_IDENTITY=""
                MONITOR_STOP_FILE={shlex.quote(str(root / 'monitor.stop'))}
                GENERATION_STOP_FILE={shlex.quote(str(root / 'generation.stop'))}
                RESPONSE_TMP_DIR={shlex.quote(str(root / 'responses'))}
                CLEANUP_STARTED=0
                CLEANUP_INCOMPLETE=0
                EVIDENCE_FAILED=0
                SYSTEM_LOG_ALIVE_END=0
                SYSTEM_LOG_JOINED=0
                SYSTEM_LOG_CHILD_RC=none
                """)
            if expire_discovery:
                program += self.stress_function(shell, "collect_owned_tree").replace(
                    "collect_owned_tree()", "real_collect_owned_tree()", 1
                )
                program += 'collect_owned_tree() { real_collect_owned_tree "$1" "$2" "$SECONDS"; }\n'
            if capture:
                program += textwrap.dedent(f"""
                    run_bounded_capture {shlex.quote(str(root / 'output'))} 2 \
                      {shlex.quote(str(wrapper))}
                    rc=$?
                    printf 'rc=%s incomplete=%s evidence=%s timeout=%s jobs=%s\\n' \
                      "$rc" "$CLEANUP_INCOMPLETE" "$EVIDENCE_FAILED" \
                      "$BOUNDED_CAPTURE_TIMED_OUT" "$(jobs -p | wc -l | tr -d ' ')"
                    """)
            else:
                program += textwrap.dedent(f"""
                    {shlex.quote(sys.executable)} {shlex.quote(str(tree))} &
                    TRAFFIC_PIDS=("$!")
                    for _ in $(seq 1 200); do
                      [[ -e {shlex.quote(str(ready_file))} ]] && break
                      sleep 0.01
                    done
                    [[ -e {shlex.quote(str(ready_file))} ]] || exit 9
                    leaf_pid="$(cat {shlex.quote(str(leaf_file))})"
                    """)
                if deny_kill:
                    # Model a failed descendant signal (e.g. lost permission).
                    # The direct job still exits, which cannot prove cleanup.
                    program += self.stress_function(
                        shell, "signal_owned_identity"
                    ).replace("signal_owned_identity()", "real_signal_owned_identity()", 1)
                    program += textwrap.dedent("""
                        signal_owned_identity() {
                          [[ "$1" != "$leaf_pid" || "$3" != KILL ]] || return 1
                          real_signal_owned_identity "$@"
                        }
                        trap 'kill -KILL "$leaf_pid" 2>/dev/null || true' EXIT
                        """)
                program += textwrap.dedent("""
                    cleanup_owned_jobs
                    printf 'incomplete=%s jobs=%s\\n' "$CLEANUP_INCOMPLETE" \
                      "$(jobs -p | wc -l | tr -d ' ')"
                    """)
            started = time.monotonic()
            process = subprocess.Popen(
                ["bash", "-c", program],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                start_new_session=True,
            )
            try:
                output, _ = process.communicate(timeout=12)
            finally:
                # This session was created solely for this fixture. Also clean
                # failed implementations so a regression cannot leak pipe owners.
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=2)
            self.assertLess(time.monotonic() - started, 12)
            self.assertEqual(process.returncode, 0, output)
            self.assertTrue(
                ready_file.exists(),
                output + ((root / "output").read_text() if capture else ""),
            )
            self.assertEqual(len(pids.read_text().splitlines()), 3, output)
            if capture:
                expected = f"rc={125 if expire_discovery else 124} incomplete={int(expire_discovery)} evidence=1 timeout=1 jobs=0"
            else:
                expected = f"incomplete={int(deny_kill)} jobs=0"
            self.assertEqual(output.splitlines()[-1], expected, output)

    def test_cleanup_reaps_stopped_orphaned_grandchild_holding_output_pipe(self):
        self.run_stopped_grandchild_cleanup_fixture()

    def test_capture_keeps_exec_ownership_and_reaps_stopped_orphaned_grandchild(self):
        self.run_stopped_grandchild_cleanup_fixture(capture=True)

    def test_capture_rejects_early_success_with_orphaned_pipe_holding_grandchild(self):
        self.run_stopped_grandchild_cleanup_fixture(capture=True, early_orphan=True)

    def test_cleanup_rejects_live_descendant_after_direct_job_has_exited(self):
        self.run_stopped_grandchild_cleanup_fixture(deny_kill=True)

    def test_discovery_visits_each_owned_generation_once(self):
        from test_modern_udp_evidence import exercise_owned_chain_discovery
        shell = STRESS_SCRIPT.read_text()
        helpers = "".join(self.stress_function(shell, name) for name in (
            "pid_identity", "owned_identity_has_exited", "collect_owned_tree", "signal_owned_identity",
        ))
        exercise_owned_chain_discovery(self, helpers, "")

    def test_expired_discovery_retains_root_cleanup_authority(self):
        from test_modern_udp_evidence import exercise_owned_chain_discovery
        shell = STRESS_SCRIPT.read_text()
        helpers = "".join(self.stress_function(shell, name) for name in (
            "pid_identity", "owned_identity_has_exited", "collect_owned_tree", "signal_owned_identity",
        ))
        exercise_owned_chain_discovery(self, helpers, "", expired=True)

    def test_capture_expired_discovery_reaps_group_and_blocks_evidence(self):
        self.run_stopped_grandchild_cleanup_fixture(capture=True, early_orphan=True, expire_discovery=True)

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
                      [[ "$argument" == --head ]] && downloaded=0
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
                    printf '200\t%s\t%s\t%s\t0.050' "$downloaded" "$uploaded" "$version"
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
                    # Only the provider is synthetic; cleanup must observe the
                    # real state, parent, group, and generation of its own jobs.
                    [[ "$pid" == "$FAKE_PROVIDER_PID" ]] || exec /bin/ps "$@"
                    kill -0 "$pid" 2>/dev/null || exit 1
                    if [[ " $* " == *" comm= "* ]]; then
                      printf '/bin/sleep\\n'
                    elif [[ " $* " == *" -ww "* ]]; then
                      printf '%s Wed Jan  1 00:00:00 2025 fake-provider\\n' "$pid"
                    elif [[ " $* " == *" pid=,rss=,vsz=,%cpu=,state= "* ]]; then
                      printf '%s 1 1 0.0 S\\n' "$pid"
                    else
                      printf 'PID RSS VSZ %%CPU STAT\\n%s 1 1 0.0 S\\n' "$pid"
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
                    STRESS_CURL_TOOL=str(fake_curl),
                    STRESS_ALLOW_TEST_TOOLS="1",
                    STRESS_DURATION="3",
                    STRESS_CONCURRENCY="1",
                    STRESS_LARGE_BYTES="1024",
                    STRESS_POST_BYTES="1024",
                    STRESS_SKIP_LIVENESS="1",
                    STRESS_MONITOR_PID=str(provider.pid),
                    FAKE_PROVIDER_PID=str(provider.pid),
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

    def test_monitor_uses_the_documented_five_second_bounded_resource_cadence(self):
        shell = STRESS_SCRIPT.read_text()
        start = shell.index("monitor_pid() {")
        end = shell.index("# ── Plan + launch", start)
        monitor = shell[start:end]
        self.assertIn("sleep 5", monitor)
        self.assertNotIn("sleep 1\n", monitor)
        self.assertIn("capture_resource_sample", monitor)
        self.assertNotIn("vmmap", monitor)
        self.assertNotIn("leaks", monitor)

    def test_candidate_marker_and_log_capture_are_exact_and_privacy_bounded(self):
        shell = STRESS_SCRIPT.read_text()
        curl = self.stress_function(shell, "do_one_curl")
        self.assertIn('[[ "$TRAFFIC_ROLE" == proxy-candidate ]]', curl)
        self.assertIn(
            'curl_args+=(--header "X-Rama-Tproxy-Stress-Run: $RUN_UUID:$request_id")',
            curl,
        )
        self.assertIn('2>/dev/null', curl)
        self.assertIn('metrics=$(run_hermetic_curl', curl)
        self.assertIn('--url "$target"', curl)
        self.assertNotIn('2>>"$LOG_DIR/${label}.log"', curl)
        self.assertIn(
            'LOG_PREDICATE="$LOG_PREDICATE AND eventMessage BEGINSWITH '
            '\'$EXPECTED_STRESS_EVENT_PREFIX\'"',
            shell,
        )
        self.assertIn('[[ "$LOG_TOOL" == /usr/bin/log && "$CURL_TOOL" == /usr/bin/curl ]]', shell)
        self.assertIn("capture-provider-generation", shell)
        self.assertIn('provider-generation-samples.tsv', shell)

    def test_hermetic_curl_disables_config_and_clears_network_override_environment(self):
        shell = STRESS_SCRIPT.read_text()
        start = shell.index("run_hermetic_curl() (")
        end = shell.index("\n)\n", start) + 3
        function = shell[start:end]
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            fake_curl = root / "curl"
            fake_curl.write_text(textwrap.dedent("""\
                #!/usr/bin/env bash
                index=0
                for argument in "$@"; do
                  printf 'arg_%s=<%s>\n' "$index" "$argument"
                  index=$((index + 1))
                done
                printf 'env=<%s%s%s%s%s%s%s%s%s%s>\n' \
                  "${HTTP_PROXY:-}" "${HTTPS_PROXY:-}" "${ALL_PROXY:-}" \
                  "${http_proxy:-}" "${https_proxy:-}" "${all_proxy:-}" \
                  "${CURL_HOME:-}" "${CURL_CA_BUNDLE:-}" \
                  "${SSL_CERT_FILE:-}" "${SSL_CERT_DIR:-}"
                """))
            fake_curl.chmod(0o755)
            curl_home = root / "home"
            curl_home.mkdir()
            (curl_home / ".curlrc").write_text(
                "--request DELETE\n--proxy http://127.0.0.1:1\n"
            )
            environment = os.environ.copy()
            environment.update({
                "HTTP_PROXY": "http://127.0.0.1:1",
                "HTTPS_PROXY": "http://127.0.0.1:1",
                "ALL_PROXY": "http://127.0.0.1:1",
                "http_proxy": "http://127.0.0.1:1",
                "https_proxy": "http://127.0.0.1:1",
                "all_proxy": "http://127.0.0.1:1",
                "CURL_HOME": str(curl_home),
                "CURL_CA_BUNDLE": "/private/tmp/untrusted-ca",
                "SSL_CERT_FILE": "/private/tmp/untrusted-cert",
                "SSL_CERT_DIR": "/private/tmp/untrusted-dir",
            })
            result = subprocess.run(
                ["bash", "-c", function + "\nCURL_TOOL=$1; run_hermetic_curl --url https://example.invalid/", "bash", str(fake_curl)],
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=5,
            )
            self.assertEqual(result.returncode, 0, result.stdout)
            self.assertEqual(result.stdout.splitlines()[:5], [
                "arg_0=<--disable>", "arg_1=<--noproxy>", "arg_2=<*>",
                "arg_3=<--proxy>", "arg_4=<>",
            ])
            self.assertEqual(result.stdout.splitlines()[-1], "env=<>")

    def test_target_option_injection_is_rejected_before_curl_execution(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            fake_curl = root / "curl"
            called = root / "called"
            fake_curl.write_text(
                "#!/usr/bin/env bash\n"
                f"touch {shlex.quote(str(called))}\n"
                "exit 99\n"
            )
            fake_curl.chmod(0o755)
            result = self.run_stress(
                root / "logs",
                STRESS_CURL_TOOL=str(fake_curl),
                STRESS_ALLOW_TEST_TOOLS="1",
                STRESS_DURATION="1",
                STRESS_CONCURRENCY="1",
                STRESS_HTTP_TARGET="--config=/private/tmp/secret",
            )
            self.assertEqual(result.returncode, 2, result.stdout)
            self.assertFalse(called.exists())

    def test_release_roles_reject_injected_curl_or_log_tools(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            fake_tool = root / "tool"
            fake_tool.write_text("#!/usr/bin/env bash\nexit 0\n")
            fake_tool.chmod(0o755)
            direct = self.run_stress(
                root / "direct",
                STRESS_TRAFFIC_ROLE="direct-baseline",
                STRESS_CURL_TOOL=str(fake_tool),
                STRESS_ALLOW_TEST_TOOLS="1",
            )
            self.assertEqual(direct.returncode, 2, direct.stdout)
            self.assertIn("requires SIP-protected /usr/bin/curl", direct.stdout)
            candidate = self.run_stress(
                root / "candidate",
                STRESS_TRAFFIC_ROLE="proxy-candidate",
                STRESS_MONITOR_PID="1",
                STRESS_BUILT_PROVIDER="/fixture/built.systemextension",
                STRESS_INSTALLED_PROVIDER="/fixture/installed.systemextension",
                STRESS_LOG_TOOL=str(fake_tool),
                STRESS_ALLOW_TEST_TOOLS="1",
            )
            self.assertEqual(candidate.returncode, 2, candidate.stdout)
            self.assertIn("requires SIP-protected /usr/bin/log", candidate.stdout)

    def test_release_producer_rejects_weakened_workload_or_resource_policy(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            for index, override in enumerate((
                {"STRESS_DURATION": "1"},
                {"STRESS_CONCURRENCY": "1"},
                {"STRESS_LARGE_BYTES": "1024"},
                {"STRESS_POST_BYTES": "1024"},
                {"STRESS_MAX_RSS_GROWTH_BYTES": "10737418240"},
                {"STRESS_MAX_CPU_PERCENT": "10000"},
            )):
                result = self.run_stress(
                    root / str(index),
                    STRESS_TRAFFIC_ROLE="direct-baseline",
                    **override,
                )
                self.assertEqual(result.returncode, 2, result.stdout)
                self.assertIn("canonical workload", result.stdout)

    def test_common_envelope_rejects_mutated_crash_or_generation_proof_before_reseal(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            for artifact_name in (
                "crashes/crash-snapshot.tsv",
                signed_run_evidence.GENERATION_SAMPLES_NAME,
            ):
                run = root / artifact_name.replace("/", "-")
                write_self_attested_traffic_run(
                    run, monitored=True, role="proxy-candidate"
                )
                add_common_stress_envelope(run)
                artifact = run / artifact_name
                artifact.write_text(artifact.read_text().replace(
                    dict(
                        row.split("\t", 1)
                        for row in (run / "evidence-status.tsv").read_text().splitlines()
                    )["provider_generation_identity"],
                    "f" * 64,
                    1,
                ))
                with self.subTest(artifact=artifact_name), self.assertRaisesRegex(
                    signed_run_evidence.EvidenceError,
                    "crash snapshot|generation samples",
                ):
                    signed_run_evidence.seal(run, actual_exit_code=0)

    def test_proxy_candidate_sealed_evidence_requires_usr_bin_log(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            run = Path(temp_dir) / "candidate"
            write_self_attested_traffic_run(
                run, monitored=True, role="proxy-candidate"
            )
            tool = run / "system-log-tool.tsv"
            tool.write_text(tool.read_text().replace("/usr/bin/log", "/fixture/log"))
            reseal_self_attested_traffic_run(run)
            with self.assertRaisesRegex(ValueError, "system log tool identity"):
                verify_stress_evidence(run)

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
            identity="$(pid_identity "$child" generation)" || exit 3
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


    def test_holder_cleanup_is_pid_scoped_and_joins_the_batch(self):
        shell = SOAK_SCRIPT.read_text()
        cleanup = self.soak_function(shell, "kill_holders")
        start = shell.index("# Every owned background function")
        end = shell.index("\nsoak_verdict_exit_code() {", start)
        helpers = shell[start:end]
        self.assertNotIn("pkill -f", cleanup)
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            pidfile = root / "holders.tsv"
            program = (
                helpers + cleanup
                + f"\nOUT={shlex.quote(str(root))}\n"
                + f"HOLDER_PIDFILE={shlex.quote(str(pidfile))}\n"
                + "FLOW_POOL_LABEL=test\nHOLDER_CLEANUP_OK=1\n"
                + 'sleep 30 & first=$!\nremember_owned_child "$first"\n'
                + 'sleep 30 & second=$!\nremember_owned_child "$second"\n'
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

    @staticmethod
    def status_lines(verdict=(1, 1, 0), attempts=9, passes=9, diagnostics=()):
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
            ("run_start_epoch_ms", 1000),
            ("run_end_epoch_ms", 2000),
            ("evidence_kind", "modern_udp"),
            ("provider_generation_identity", "b" * 64),
            ("producer_sources_sha256", "f" * 64),
            ("engine_generations_sha256", "c" * 64),
            ("provider_pid", 123),
            ("provider_identity", "b" * 64),
            ("provider_identity_stable", 1),
            ("http3_source_pid", 456),
            ("http3_flow_id", 88),
            ("http3_remote_endpoint", "1.1.1.1:443"),
            ("http3_request_count", 6),
            ("http3_pass_count", 6),
            ("http3_flow_count", 6),
            ("http3_duration_ms", 2000),
            ("http3_min_concurrent", 2),
            ("http3_intercept_passed", 1),
            ("http3_intercept_source_pid", 459),
            ("http3_intercept_flow_id", 89),
            ("http3_intercept_provider_generation", 2),
            ("http3_intercept_local_endpoint", "192.0.2.1:54000"),
            ("http3_intercept_remote_endpoint", "1.1.1.1:443"),
            ("echo_socket_count", 128),
            ("echo_datagrams_per_socket", 1),
            ("echo_payload_bytes", 1200),
            ("echo_expected_count", 128),
            ("echo_exact_echo_count", 128),
            ("echo_flow_count", 128),
            ("echo_payload_set_sha256", "d" * 64),
            ("echo_endpoint", "127.0.0.1:32000"),
            ("echo_source_pid", 458),
            ("pressure_datagram_count", 512),
            ("pressure_payload_bytes", 4096),
            ("pressure_expected_bytes", 2097152),
            ("concurrent_load_deadline_seconds", 180),
            ("concurrent_load_timed_out", 0),
            ("active_workload_forced_termination_count", 0),
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
            ("recovery_ntp_source_pid", 457),
            ("recovery_ntp_flow_id", 80),
            ("blocked_dns_source_pid", 455),
            ("blocked_dns_flow_id", 79),
            ("dial9_baseline_max_index", 8),
            ("dial9_required_flow_id", 77),
            ("dial9_current_segment_count", 1),
            ("dial9_required_pair_count", 132),
            ("dial9_required_close_reason", 1),
            ("dial9_required_close_reason_name", "shutdown"),
            ("dial9_required_close_age_ms", 2),
            ("dial9_close_age_bound_ms", 100),
            ("dial9_required_bytes_in", 48),
            ("dial9_required_bytes_out", 48),
            ("dial9_requirements_sha256", "e" * 64),
            ("dial9_requirement_count", 132),
            ("dial9_matched_requirement_count", 132),
            ("schema_version", 6),
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
        self.assertIn('--requirements "$DIAL9_REQUIREMENTS"', shell)
        self.assertIn("run_uuid=([0-9a-f]", shell)
        self.assertIn("provider_generation=([0-9]+)", shell)
        self.assertIn("modern_udp_evidence.py", shell)

    def test_pressure_window_waits_for_exact_flow_recovery_and_rejects_late_rows(self):
        run_uuid = "12345678-1234-4234-8234-123456789abc"
        provider_pid = 123
        decision = (
            f"udp_e2e_decision run_uuid={run_uuid} provider_pid={provider_pid} "
            "provider_generation=7 rama_decision=intercept flow_id=78 "
            "remote_endpoint=162.159.200.1:123 local_endpoint=127.0.0.1:45454 "
            "source_app=com.apple.python3 source_pid=454"
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
            ["before", decision], 1, *identity, run_uuid, provider_pid
        )
        self.assertFalse(decision_only["terminal"])
        dropped = pressure_window_observation(
            ["before", decision, drop], 1, *identity, run_uuid, provider_pid
        )
        self.assertFalse(dropped["terminal"])
        self.assertEqual(dropped["summary"]["unrecovered"], ["channel_count"])
        complete = pressure_window_observation(
            ["before", decision, drop, recovery], 1, *identity,
            run_uuid, provider_pid,
        )
        self.assertTrue(complete["terminal"])
        self.assertEqual(complete["flow_id"], 78)

        delayed_duplicate = pressure_window_observation(
            ["before", decision, drop, recovery, decision], 1, *identity,
            run_uuid, provider_pid,
        )
        self.assertFalse(delayed_duplicate["terminal"])
        self.assertEqual(delayed_duplicate["matching_decisions"], 2)
        foreign_recovery = pressure_window_observation(
            ["before", decision, drop, recovery.replace("flow_id=78", "flow_id=79")],
            1,
            *identity,
            run_uuid,
            provider_pid,
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
            "http3_intercept_passed": "0", "http3_intercept_source_pid": "none",
            "http3_intercept_flow_id": "none", "http3_intercept_provider_generation": "none",
            "http3_intercept_local_endpoint": "none", "http3_intercept_remote_endpoint": "none",
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
        unsupported_schema = replace(self.status_lines(), "schema_version", "3")
        self.assertIsNone(parse_signed_udp_status_lines(unsupported_schema))

        for key, value in (
            ("provider_identity_stable", "0"),
            ("http3_source_pid", "none"),
            ("run_uuid", "not-a-uuid"),
            ("http3_remote_endpoint", "cloudflare.com:443"),
            ("http3_intercept_passed", "0"),
            ("http3_intercept_source_pid", "none"),
            ("http3_intercept_flow_id", "88"),
            ("http3_intercept_provider_generation", "0"),
            ("http3_intercept_local_endpoint", "unavailable"),
            ("http3_intercept_remote_endpoint", "1.1.1.1:53"),
            ("pressure_resume_transitions", "0"),
            ("pressure_recovered_reasons", "flow_bytes"),
            ("ntp_flow_id", "78"),
            ("dial9_required_close_reason", "15"),
            ("dial9_required_close_reason_name", "idle_timeout"),
            ("dial9_required_close_age_ms", "101"),
            ("dial9_matched_requirement_count", "66"),
        ):
            with self.subTest(key=key):
                self.assertIsNone(parse_signed_udp_status_lines(
                    replace(self.status_lines(), key, value)
                ))

    def test_blocked_dns_requires_timeout_or_a_valid_matching_response(self):
        transaction_id = 0x1234
        valid = struct.pack(
            "!HHHHHH", transaction_id, 0x8180, 1, 1, 0, 0
        ) + b"\x07example\x03com\x00\x00\x01\x00\x01"
        valid += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + bytes((93, 184, 216, 34))

        class FakeSocket:
            def __init__(self, outcome):
                self.outcome = outcome

            def bind(self, _):
                pass

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

            def bind(self, _):
                pass

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

            def bind(self, _):
                pass

            def settimeout(self, timeout):
                self.timeout = timeout

            def sendto(self, packet, peer):
                self.packets.append((bytes(packet), peer))
                return len(packet)

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
        self.assertEqual(
            sleep.call_args_list,
            [mock.call(0.02)] * 65 + [mock.call(2.5)]
            + [mock.call(0.02)] * 445 + [mock.call(0.25)],
        )
        for arguments in ((63, 64, 0), (64, 63, 0), (64, 64, -1)):
            with self.assertRaises(ValueError):
                pressure_burst("162.159.200.1", *arguments)
        with self.assertRaisesRegex(ValueError, "IPv4 literal"):
            pressure_burst("2001:db8::1", 64, 64, 0)


if __name__ == "__main__":
    unittest.main()
