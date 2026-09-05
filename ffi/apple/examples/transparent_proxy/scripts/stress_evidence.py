#!/usr/bin/env python3
"""Measure, seal, and re-verify one self-attested local stress run."""

from datetime import datetime
from decimal import Decimal, InvalidOperation, ROUND_CEILING
import hashlib
import os
from pathlib import Path
import re
import sys
from urllib.parse import urlsplit
import uuid

import signed_run_evidence


SCHEMA_VERSION = 3
WORKERS = (
    "small_https", "small_http1", "plain_http", "large_get", "post_large",
    "head_only", "churn_close", "parallel_pool",
)
COMMON_ARTIFACTS = tuple(
    f"{worker}{suffix}" for worker in WORKERS for suffix in (".log", ".summary")
) + (
    "stress-metrics.tsv", "stress-workload.tsv", "stress-window.tsv",
    "source-stress_traffic.sh",
    "source-stress_evidence.py", "git-head.txt", "git-status.txt",
)
MONITORED_ARTIFACTS = (
    "monitor.identity.sha256", "preflight.txt", "postflight.txt",
    "provider-codesign.txt", "provider-identity.tsv", "system.ndjson",
    "system-log-capture.err",
    "system-log-tool.tsv",
)
SOURCE_MODES = ("traffic-only", "provider-monitored-traffic-only")
EVIDENCE_CLAIM = "self-attested-local-integrity-not-authenticity"
SHA256_RE = re.compile(r"[0-9a-f]{64}")
GIT_HEAD_RE = re.compile(r"[0-9a-f]{40,64}")
STRESS_MARKER_PREFIX = (
    "[rama_tproxy_example::stress_attribution] "
    "rama stress request attributed: run_uuid="
)
STRESS_MARKER_RE = re.compile(
    re.escape(STRESS_MARKER_PREFIX)
    + r"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"
    + r" request_id=([0-9a-f]{64})"
)
TRANSFER_RE = re.compile(
    r"request_id=([0-9a-f]{64}) status=(2\d\d) curl_exit=0 "
    r"downloaded=(\d+) uploaded=(\d+) http_version=(\S+) "
    r"duration_seconds=([0-9]+(?:\.[0-9]+)?)$"
)
SUMMARY_RE = re.compile(r"(\S+) done: iters=(\d+) ok=(\d+) fail=(\d+)$")
RESOURCE_SAMPLE_RE = re.compile(
    r"^resource_sample\t(\d+)\t([0-9a-f]{64})\t(\d+)\t(\d+)\t(\d+)\t"
    r"([0-9]+(?:\.[0-9]+)?)\t([^\t\s]+)$"
)
RESOURCE_SAMPLE_MAX_GAP_MS = 7_000
WINDOW_CLOCK_DRIFT_TOLERANCE_NS = 5_000_000_000
WORKLOAD_FIELDS = (
    "schema_version", "duration_seconds", "concurrency", "large_bytes",
    "post_bytes", "http_target_sha256", "https_target_sha256",
    "large_target_sha256", "post_target_sha256", "schema_complete",
)
WINDOW_FIELDS = (
    "traffic_start_epoch_ms", "traffic_end_epoch_ms",
    "traffic_start_monotonic_ns", "traffic_end_monotonic_ns",
    "schema_complete",
)
WORKER_HTTP_VERSION = {
    "small_https": "2", "small_http1": "1.1", "plain_http": "1.1",
    "large_get": "2", "post_large": "2", "head_only": "2",
    "churn_close": "1.1", "parallel_pool": "2",
}
WORKER_CLASS_ID = {
    worker: f"{index:02x}" for index, worker in enumerate(WORKERS, start=1)
}
RELEASE_WORKLOAD_NUMERIC = {
    "duration_seconds": 60,
    "concurrency": 16,
    "large_bytes": 16_777_216,
    "post_bytes": 8_388_608,
}
RELEASE_TARGETS = {
    "http_target_sha256": "http://http-test.ramaproxy.org/method",
    "https_target_sha256": "https://http-test.ramaproxy.org/method",
    "large_target_sha256": "https://http-test.ramaproxy.org/bytes?size=16777216",
    "post_target_sha256": "https://http-test.ramaproxy.org/octet-stream",
}
RELEASE_THRESHOLDS = {
    "max_p95_ms": "10000",
    "min_throughput_milli_rps": "100",
    "max_rss_growth_bytes": "67108864",
    "max_cpu_percent": "400",
}

CLAIM_FIELDS = {
    "evidence_kind", "run_uuid", "evidence_mode", "proxy_attributed",
    "evidence_claim", "traffic_start_epoch_ms", "traffic_end_epoch_ms",
    "artifact_manifest_sha256", "max_p95_ms",
    "min_throughput_milli_rps", "max_rss_growth_bytes", "max_cpu_percent",
    "observed_p95_ms", "observed_throughput_milli_rps",
    "observed_rss_growth_bytes", "observed_max_cpu_percent", "git_head",
    "git_dirty", "stress_script_sha256", "evidence_helper_sha256",
    "provider_pid", "provider_identity", "provider_executable_sha256",
    "provider_signing_identifier", "provider_signing_team",
    "provider_signing_cdhash", "ndjson_included", "schema_complete",
    "traffic_role", "workload_identity",
    "system_log_started", "system_log_alive_end", "system_log_joined",
    "system_log_child_rc",
    "system_log_tool_sha256",
    "attributed_request_count",
    "signed_evidence_helper_sha256", "provider_absent",
}
LEGACY_STATUS_FIELDS = (CLAIM_FIELDS - {
    "evidence_kind", "traffic_start_epoch_ms", "traffic_end_epoch_ms", "run_uuid",
    "signed_evidence_helper_sha256", "provider_absent",
}) | {
    "complete", "passed", "exit_code", "run_uuid", "run_start_epoch",
    "run_end_epoch", "issue",
}


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_uint(value, maximum=2**64 - 1):
    if re.fullmatch(r"0|[1-9]\d*", value or "") is None or len(value) > 20:
        raise ValueError("invalid integer")
    number = int(value)
    if number > maximum:
        raise ValueError("integer overflow")
    return number


def canonical_uuid(value):
    if str(uuid.UUID(value)) != value:
        raise ValueError("non-canonical UUID")
    return value


def _validated_target(value, scheme):
    if not isinstance(value, str) or any(ord(character) < 32 for character in value):
        raise ValueError("stress target contains control characters")
    parsed = urlsplit(value)
    try:
        port = parsed.port
    except ValueError as error:
        raise ValueError("stress target has an invalid port") from error
    if (
        parsed.scheme != scheme or not parsed.hostname or parsed.username is not None
        or parsed.password is not None or parsed.fragment or port == 0
        or value.startswith("-")
    ):
        raise ValueError(f"stress target must be an absolute privacy-safe {scheme} URL")
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def write_workload(
    directory, duration_text, concurrency_text, large_bytes_text, post_bytes_text,
    http_target, https_target, large_target, post_target,
):
    duration = canonical_uint(duration_text, 86_400)
    concurrency = canonical_uint(concurrency_text, 512)
    large_bytes = canonical_uint(large_bytes_text, 1_073_741_824)
    post_bytes = canonical_uint(post_bytes_text, 1_073_741_824)
    if any(value == 0 for value in (duration, concurrency, large_bytes, post_bytes)):
        raise ValueError("invalid stress workload bounds")
    values = (
        ("schema_version", str(SCHEMA_VERSION)),
        ("duration_seconds", str(duration)),
        ("concurrency", str(concurrency)),
        ("large_bytes", str(large_bytes)),
        ("post_bytes", str(post_bytes)),
        ("http_target_sha256", _validated_target(http_target, "http")),
        ("https_target_sha256", _validated_target(https_target, "https")),
        ("large_target_sha256", _validated_target(large_target, "https")),
        ("post_target_sha256", _validated_target(post_target, "https")),
        ("schema_complete", "1"),
    )
    destination = directory / "stress-workload.tsv"
    temporary = destination.with_name(destination.name + f".tmp.{os.getpid()}")
    temporary.write_text(
        "".join(f"{key}\t{value}\n" for key, value in values), encoding="utf-8"
    )
    os.replace(temporary, destination)
    return sha256_file(destination)


def read_workload(directory):
    values, rows = read_unique_tsv(
        artifact_path(directory, "stress-workload.tsv"),
        set(WORKLOAD_FIELDS), set(WORKLOAD_FIELDS),
    )
    if [row.split("\t", 1)[0] for row in rows] != list(WORKLOAD_FIELDS):
        raise ValueError("stress workload field order is invalid")
    if values["schema_version"] != str(SCHEMA_VERSION) or values["schema_complete"] != "1":
        raise ValueError("stress workload schema is invalid")
    workload = {
        "duration_seconds": canonical_uint(values["duration_seconds"], 86_400),
        "concurrency": canonical_uint(values["concurrency"], 512),
        "large_bytes": canonical_uint(values["large_bytes"], 1_073_741_824),
        "post_bytes": canonical_uint(values["post_bytes"], 1_073_741_824),
    }
    workload.update({key: values[key] for key in RELEASE_TARGETS})
    if any(workload[key] == 0 for key in (
        "duration_seconds", "concurrency", "large_bytes", "post_bytes"
    )) or any(
        SHA256_RE.fullmatch(values[key]) is None
        for key in WORKLOAD_FIELDS if key.endswith("_sha256")
    ):
        raise ValueError("stress workload values are invalid")
    return workload


def verify_release_policy(directory, status):
    workload = read_workload(directory)
    expected_targets = {
        key: hashlib.sha256(value.encode("utf-8")).hexdigest()
        for key, value in RELEASE_TARGETS.items()
    }
    if any(workload[key] != value for key, value in RELEASE_WORKLOAD_NUMERIC.items()):
        raise ValueError("release stress workload does not use the canonical load profile")
    if any(workload[key] != value for key, value in expected_targets.items()):
        raise ValueError("release stress workload does not use canonical target identities")
    if any(status[key] != value for key, value in RELEASE_THRESHOLDS.items()):
        raise ValueError("release stress workload weakened the hard threshold policy")


def read_window(directory):
    values, rows = read_unique_tsv(
        artifact_path(directory, "stress-window.tsv"),
        set(WINDOW_FIELDS), set(WINDOW_FIELDS),
    )
    if [row.split("\t", 1)[0] for row in rows] != list(WINDOW_FIELDS):
        raise ValueError("stress window field order is invalid")
    start = canonical_uint(values["traffic_start_epoch_ms"])
    end = canonical_uint(values["traffic_end_epoch_ms"])
    monotonic_start = canonical_uint(values["traffic_start_monotonic_ns"])
    monotonic_end = canonical_uint(values["traffic_end_monotonic_ns"])
    elapsed_epoch_ns = (end - start) * 1_000_000
    elapsed_monotonic_ns = monotonic_end - monotonic_start
    if (
        values["schema_complete"] != "1" or start == 0 or end <= start
        or monotonic_start == 0 or monotonic_end <= monotonic_start
        or abs(elapsed_epoch_ns - elapsed_monotonic_ns)
        > WINDOW_CLOCK_DRIFT_TOLERANCE_NS
    ):
        raise ValueError("invalid sealed stress timing window")
    return start, end, monotonic_start, monotonic_end


def read_unique_tsv(path, allowed, required=None):
    values = {}
    rows = path.read_text(encoding="utf-8").splitlines()
    for row in rows:
        fields = row.split("\t")
        if len(fields) != 2 or not all(fields) or fields[0] not in allowed:
            raise ValueError(f"malformed {path.name}")
        key, value = fields
        if key in values:
            raise ValueError(f"duplicate {path.name} field")
        values[key] = value
    if required is not None and set(required) != set(values):
        raise ValueError(f"incorrect {path.name} field set")
    return values, rows


def read_status(path):
    directory = path.parent
    if not (directory / signed_run_evidence.STATUS_NAME).exists():
        values, rows = read_unique_tsv(path, LEGACY_STATUS_FIELDS)
        required = LEGACY_STATUS_FIELDS - {"issue"}
        if set(values) != required or not rows or rows[-1] != "schema_complete\t1":
            raise ValueError("incomplete or unsealed source status")
        status = values
        expected_kind = None
    else:
        status = signed_run_evidence.read_status(directory)
        values, rows = read_unique_tsv(
            artifact_path(directory, signed_run_evidence.CLAIMS_NAME), CLAIM_FIELDS,
            CLAIM_FIELDS,
        )
        if not rows or rows[-1] != "schema_complete\t1":
            raise ValueError("incomplete or unsealed stress workload claims")
        values.update(status)
        values["run_start_epoch"] = status["run_start_epoch_ms"]
        values["run_end_epoch"] = status["run_end_epoch_ms"]
        expected_kind = {
            "direct-baseline": "stress-direct",
            "proxy-candidate": "stress-candidate",
            "unpaired-diagnostic": "stress-diagnostic",
        }.get(values.get("traffic_role"))
    if (
        values["complete"] != "1" or values["passed"] != "1"
        or values["exit_code"] != "0"
        or values["evidence_mode"] not in SOURCE_MODES
        or values["evidence_claim"] != EVIDENCE_CLAIM
        or (expected_kind is not None and values["evidence_kind"] != expected_kind)
        or values["traffic_role"] not in {
            "unpaired-diagnostic", "direct-baseline", "proxy-candidate"
        }
        or SHA256_RE.fullmatch(values["workload_identity"]) is None
    ):
        raise ValueError("source run did not pass")
    expected_attribution = "1" if values["traffic_role"] == "proxy-candidate" else "0"
    if values["proxy_attributed"] != expected_attribution:
        raise ValueError("source run has an invalid proxy-attribution claim")
    canonical_uint(values["attributed_request_count"])
    return values


def artifact_path(directory, name, allow_empty=False):
    path = directory / name
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"artifact {name} is missing or not a regular file")
    if not allow_empty and path.stat().st_size == 0:
        raise ValueError(f"artifact {name} is empty")
    return path


def expected_artifacts(mode, provider_pid, traffic_role):
    names = list(COMMON_ARTIFACTS)
    if traffic_role in {"direct-baseline", "proxy-candidate"}:
        names.append("crashes/crash-snapshot.tsv")
    if traffic_role == "proxy-candidate":
        names.append("provider-generation-samples.tsv")
    if mode == "provider-monitored-traffic-only":
        canonical_uint(provider_pid, 2**31 - 1)
        if provider_pid == "0":
            raise ValueError("invalid provider pid")
        names.extend(MONITORED_ARTIFACTS)
        names.append(f"monitor.{provider_pid}.log")
    elif mode != "traffic-only":
        raise ValueError("invalid evidence mode")
    return tuple(sorted(names))


def parse_summary(directory, worker):
    path = artifact_path(directory, f"{worker}.summary")
    lines = path.read_text(encoding="utf-8").splitlines()
    if len(lines) != 1:
        raise ValueError(f"malformed {worker} summary")
    match = SUMMARY_RE.fullmatch(lines[0])
    if match is None or match.group(1) != worker:
        raise ValueError(f"malformed {worker} summary")
    iterations, passed, failed = (canonical_uint(value) for value in match.groups()[1:])
    if iterations == 0 or passed == 0 or failed != 0 or iterations != passed + failed:
        raise ValueError(f"unsuccessful {worker} summary")
    return passed


def parse_transfers(directory, run_uuid=None):
    workload = read_workload(directory)
    result = {}
    all_request_ids = set()
    for worker in WORKERS:
        expected = parse_summary(directory, worker)
        transfers = []
        lines = artifact_path(directory, f"{worker}.log").read_text(
            encoding="utf-8", errors="strict"
        ).splitlines()
        if len(lines) != expected:
            raise ValueError(f"{worker} raw transfer count does not match its summary")
        for line in lines:
            match = TRANSFER_RE.fullmatch(line)
            if match is None:
                raise ValueError(f"malformed {worker} raw transfer")
            request_id, _, downloaded_text, uploaded_text, http_version, duration_text = (
                match.groups()
            )
            if request_id in all_request_ids:
                raise ValueError("stress request IDs are not globally unique")
            all_request_ids.add(request_id)
            downloaded = canonical_uint(downloaded_text)
            uploaded = canonical_uint(uploaded_text)
            if http_version != WORKER_HTTP_VERSION[worker]:
                raise ValueError(f"{worker} used the wrong HTTP version")
            if worker == "large_get":
                valid_bytes = downloaded == workload["large_bytes"] and uploaded == 0
            elif worker == "post_large":
                valid_bytes = (
                    downloaded == workload["post_bytes"]
                    and uploaded == workload["post_bytes"]
                )
            elif worker == "head_only":
                valid_bytes = downloaded == 0 and uploaded == 0
            else:
                valid_bytes = downloaded > 0 and uploaded == 0
            if not valid_bytes:
                raise ValueError(f"{worker} violated its exact byte contract")
            if len(duration_text) > 24:
                raise ValueError(f"invalid {worker} duration")
            try:
                duration = Decimal(duration_text)
            except InvalidOperation as error:
                raise ValueError(f"invalid {worker} duration") from error
            if not duration.is_finite() or duration <= 0 or duration > 31:
                raise ValueError(f"invalid {worker} duration")
            transfers.append((request_id, downloaded, uploaded, duration))
        if run_uuid is not None:
            canonical_uuid(run_uuid)
            prefix = run_uuid.replace("-", "") + WORKER_CLASS_ID[worker]
            expected_ids = [f"{prefix}{ordinal:030x}" for ordinal in range(1, expected + 1)]
            actual_ids = [transfer[0] for transfer in transfers]
            valid_ids = (
                set(actual_ids) == set(expected_ids)
                if worker == "parallel_pool"
                else actual_ids == expected_ids
            )
            if not valid_ids:
                raise ValueError(f"{worker} request IDs do not match the canonical class/ordinal set")
        result[worker] = transfers
    return result


def parse_ps_rows(path, provider_pid, provider_generation_identity):
    rows = []
    for line in artifact_path(path.parent, path.name).read_text(
        encoding="utf-8", errors="strict"
    ).splitlines():
        match = RESOURCE_SAMPLE_RE.fullmatch(line)
        if match is None:
            if line.startswith("resource_sample"):
                raise ValueError(f"malformed provider resource sample in {path.name}")
            continue
        epoch_ms = canonical_uint(match.group(1))
        if match.group(2) != provider_generation_identity:
            raise ValueError(f"provider generation changed in {path.name}")
        if canonical_uint(match.group(3), 2**31 - 1) != provider_pid:
            raise ValueError(f"foreign pid in {path.name}")
        rss_kib = canonical_uint(match.group(4))
        canonical_uint(match.group(5))
        cpu = Decimal(match.group(6))
        if not cpu.is_finite() or cpu < 0:
            raise ValueError(f"invalid cpu in {path.name}")
        if rows and epoch_ms <= rows[-1][0]:
            raise ValueError(f"unordered provider resource samples in {path.name}")
        rows.append((epoch_ms, rss_kib * 1024, cpu))
    if not rows:
        raise ValueError(f"no provider resource sample in {path.name}")
    return rows


def derive_metrics(
    directory, max_p95_text, min_throughput_text, max_rss_text, max_cpu_text,
    mode, provider_pid_text, run_uuid=None, provider_generation_identity=None,
):
    start, end, monotonic_start, monotonic_end = read_window(directory)
    elapsed_ns = monotonic_end - monotonic_start
    max_p95 = canonical_uint(max_p95_text)
    minimum_throughput = canonical_uint(min_throughput_text)
    max_rss = canonical_uint(max_rss_text)
    max_cpu = canonical_uint(max_cpu_text)
    transfers = parse_transfers(directory, run_uuid)
    workload = read_workload(directory)
    requested_ns = workload["duration_seconds"] * 1_000_000_000
    if (
        elapsed_ns + 1_000_000_000 < requested_ns
        or elapsed_ns > requested_ns + 60_000_000_000
    ):
        raise ValueError("sealed monotonic window is inconsistent with the workload duration")
    if len(transfers["parallel_pool"]) % workload["concurrency"]:
        raise ValueError("parallel pool count is inconsistent with sealed concurrency")
    all_durations = []
    total = 0
    total_bytes = 0
    class_metrics = {}
    passed = True
    for worker in WORKERS:
        worker_transfers = transfers[worker]
        durations = sorted(transfer[3] for transfer in worker_transfers)
        rank = ((len(durations) * 95 + 99) // 100) - 1
        p95 = int(
            (durations[rank] * 1000).to_integral_value(rounding=ROUND_CEILING)
        )
        count = len(worker_transfers)
        byte_count = sum(transfer[1] + transfer[2] for transfer in worker_transfers)
        request_throughput = (count * 1_000_000_000_000) // elapsed_ns
        byte_throughput = (byte_count * 1_000_000_000) // elapsed_ns
        class_metrics[worker] = {
            "successful_requests": count,
            "p95_ms": p95,
            "request_throughput_milli_rps": request_throughput,
            "byte_throughput_bytes_per_second": byte_throughput,
        }
        passed = passed and p95 <= max_p95 and request_throughput >= minimum_throughput
        passed = passed and (
            byte_throughput == 0 if worker == "head_only" else byte_throughput > 0
        )
        all_durations.extend(durations)
        total += count
        total_bytes += byte_count
    all_durations.sort()
    rank = ((len(all_durations) * 95 + 99) // 100) - 1
    p95_ms = int(
        (all_durations[rank] * 1000).to_integral_value(rounding=ROUND_CEILING)
    )
    throughput = (total * 1_000_000_000_000) // elapsed_ns
    byte_throughput = (total_bytes * 1_000_000_000) // elapsed_ns
    observed_rss = "not_applicable"
    observed_cpu = "not_applicable"
    passed = passed and p95_ms <= max_p95 and throughput >= minimum_throughput
    if mode == "provider-monitored-traffic-only":
        provider_pid = canonical_uint(provider_pid_text, 2**31 - 1)
        if provider_pid == 0:
            raise ValueError("invalid provider pid")
        if SHA256_RE.fullmatch(provider_generation_identity or "") is None:
            raise ValueError("missing canonical provider generation for resource samples")
        preflight = parse_ps_rows(
            directory / "preflight.txt", provider_pid, provider_generation_identity
        )
        postflight = parse_ps_rows(
            directory / "postflight.txt", provider_pid, provider_generation_identity
        )
        monitor = parse_ps_rows(
            directory / f"monitor.{provider_pid}.log", provider_pid,
            provider_generation_identity,
        )
        if len(preflight) != 1 or len(postflight) != 1 or len(monitor) < 2:
            raise ValueError("provider resource evidence lacks pre/monitor/post cadence")
        if not (
            preflight[0][0] <= start
            and all(start <= row[0] <= end for row in monitor)
            and postflight[0][0] >= end
        ):
            raise ValueError("provider resource samples do not span the traffic window")
        sample_times = [row[0] for row in preflight + monitor + postflight]
        if any(
            later <= earlier or later - earlier > RESOURCE_SAMPLE_MAX_GAP_MS
            for earlier, later in zip(sample_times, sample_times[1:])
        ):
            raise ValueError("provider resource sample cadence is invalid")
        baseline_rss = preflight[0][1]
        all_rows = preflight + monitor + postflight
        observed_rss_number = max(0, max(row[1] for row in all_rows) - baseline_rss)
        observed_cpu_number = int(
            max(row[2] for row in all_rows).to_integral_value(rounding=ROUND_CEILING)
        )
        observed_rss = str(observed_rss_number)
        observed_cpu = str(observed_cpu_number)
        passed = passed and observed_rss_number <= max_rss and observed_cpu_number <= max_cpu
    elif mode != "traffic-only" or provider_pid_text != "none":
        raise ValueError("metric mode/provider mismatch")
    values = [
        ("metric_schema_version", str(SCHEMA_VERSION)),
        ("metric_status", "PASSED" if passed else "FAILED"),
        ("traffic_start_epoch_ms", str(start)),
        ("traffic_end_epoch_ms", str(end)),
        ("traffic_start_monotonic_ns", str(monotonic_start)),
        ("traffic_end_monotonic_ns", str(monotonic_end)),
        ("elapsed_monotonic_ns", str(elapsed_ns)),
        ("successful_requests", str(total)),
        ("observed_p95_ms", str(p95_ms)),
        ("max_p95_ms", str(max_p95)),
        ("observed_throughput_milli_rps", str(throughput)),
        ("min_throughput_milli_rps", str(minimum_throughput)),
        ("observed_byte_throughput_bytes_per_second", str(byte_throughput)),
    ]
    for worker in WORKERS:
        metrics = class_metrics[worker]
        prefix = f"class_{worker}"
        values.extend(
            (f"{prefix}_{key}", str(metrics[key]))
            for key in (
                "successful_requests", "p95_ms",
                "request_throughput_milli_rps", "byte_throughput_bytes_per_second",
            )
        )
    values.extend((
        ("observed_rss_growth_bytes", observed_rss),
        ("max_rss_growth_bytes", str(max_rss)),
        ("observed_max_cpu_percent", observed_cpu),
        ("max_cpu_percent", str(max_cpu)),
        ("schema_complete", "1"),
    ))
    return values, transfers


def write_metrics(
    directory, start_text, end_text, max_p95_text, min_throughput_text,
    max_rss_text, max_cpu_text, mode, provider_pid_text,
    provider_generation_identity=None,
):
    start = canonical_uint(start_text)
    end = canonical_uint(end_text)
    sealed_start, sealed_end, _, _ = read_window(directory)
    if (start, end) != (sealed_start, sealed_end):
        raise ValueError("metric interval does not match sealed monotonic window")
    values, _ = derive_metrics(
        directory, max_p95_text, min_throughput_text, max_rss_text, max_cpu_text,
        mode, provider_pid_text, provider_generation_identity=provider_generation_identity,
    )
    destination = directory / "stress-metrics.tsv"
    temporary = directory / f"stress-metrics.tsv.tmp.{os.getpid()}"
    temporary.write_text(
        "".join(f"{key}\t{value}\n" for key, value in values), encoding="utf-8"
    )
    os.replace(temporary, destination)
    output_keys = (
        "metric_status", "successful_requests", "observed_p95_ms", "max_p95_ms",
        "observed_throughput_milli_rps", "min_throughput_milli_rps",
        "observed_rss_growth_bytes", "max_rss_growth_bytes",
        "observed_max_cpu_percent", "max_cpu_percent",
    )
    result = dict(values)
    return tuple(result[key] for key in output_keys)


def seal(
    directory, run_uuid, start_text, end_text, mode, provider_pid,
    traffic_role, workload_identity,
):
    canonical_uuid(run_uuid)
    start = canonical_uint(start_text)
    end = canonical_uint(end_text)
    if start == 0 or end <= start:
        raise ValueError("invalid run interval")
    if traffic_role not in {
        "unpaired-diagnostic", "direct-baseline", "proxy-candidate"
    } or SHA256_RE.fullmatch(workload_identity) is None:
        raise ValueError("invalid workload role or identity")
    rows = [
        f"schema_version\t{SCHEMA_VERSION}", f"run_uuid\t{run_uuid}",
        f"run_start_epoch\t{start}", f"run_end_epoch\t{end}",
        f"evidence_mode\t{mode}", f"provider_pid\t{provider_pid}",
        f"evidence_claim\t{EVIDENCE_CLAIM}",
        f"traffic_role\t{traffic_role}",
        f"workload_identity\t{workload_identity}",
    ]
    for name in expected_artifacts(mode, provider_pid, traffic_role):
        path = artifact_path(
            directory, name,
            allow_empty=name in {"git-status.txt", "system-log-capture.err"},
        )
        rows.append(f"artifact\t{name}\t{path.stat().st_size}\t{sha256_file(path)}")
    rows.append("schema_complete\t1")
    destination = directory / "stress-manifest.tsv"
    temporary = directory / f"stress-manifest.tsv.tmp.{os.getpid()}"
    temporary.write_text("\n".join(rows) + "\n", encoding="utf-8")
    os.replace(temporary, destination)
    return sha256_file(destination)


def parse_identity(directory, status):
    identity_path = artifact_path(directory, "provider-identity.tsv")
    first_row = identity_path.read_text(encoding="utf-8").splitlines()[0]
    if first_row.startswith("pid\t"):
        required = {
            "pid", "identity", "executable", "executable_sha256",
            "signing_identifier", "signing_team", "signing_cdhash",
        }
        legacy, _ = read_unique_tsv(identity_path, required, required)
        if (
            legacy["pid"] != status["provider_pid"]
            or legacy["identity"] != status["provider_identity"]
            or legacy["executable_sha256"] != status["provider_executable_sha256"]
            or legacy["signing_identifier"] != status["provider_signing_identifier"]
            or legacy["signing_team"] != status["provider_signing_team"]
            or legacy["signing_cdhash"] != status["provider_signing_cdhash"]
        ):
            raise ValueError("provider identity/status mismatch")
        identity_pid = legacy["pid"]
        identity_generation = legacy["identity"]
    else:
        identity = signed_run_evidence.read_provider_identity(identity_path)
        if (
            identity["running_pid"] != status["provider_pid"]
            or identity["provider_generation_identity"] != status["provider_identity"]
            or identity["running_executable_sha256"] != status["provider_executable_sha256"]
            or identity["running_bundle_id"] != status["provider_signing_identifier"]
            or identity["running_team_id"] != status["provider_signing_team"]
            or identity["running_cdhash"] != status["provider_signing_cdhash"]
            or identity["provider_build_identity"] != status["provider_build_identity"]
            or identity["provider_generation_identity"]
            != status["provider_generation_identity"]
        ):
            raise ValueError("provider identity/status mismatch")
        identity_pid = identity["running_pid"]
        identity_generation = identity["provider_generation_identity"]
    if artifact_path(directory, "monitor.identity.sha256").read_text(
        encoding="utf-8"
    ).strip() != identity_generation:
        raise ValueError("monitor identity mismatch")
    codesign = artifact_path(directory, "provider-codesign.txt").read_text(
        encoding="utf-8", errors="strict"
    )
    expected_codesign = (
        f"Identifier={status['provider_signing_identifier']}\n"
        f"TeamIdentifier={status['provider_signing_team']}\n"
        f"CDHash={status['provider_signing_cdhash']}\n"
    )
    if codesign != expected_codesign:
        raise ValueError("provider codesign/status mismatch")
    log_tool_required = {"path", "sha256"}
    log_tool, _ = read_unique_tsv(
        artifact_path(directory, "system-log-tool.tsv"),
        log_tool_required, log_tool_required,
    )
    if (
        not log_tool["path"].startswith("/")
        or SHA256_RE.fullmatch(log_tool["sha256"]) is None
        or log_tool["sha256"] != status["system_log_tool_sha256"]
        or (
            status["traffic_role"] == "proxy-candidate"
            and log_tool["path"] != "/usr/bin/log"
        )
    ):
        raise ValueError("system log tool identity mismatch")
    return canonical_uint(identity_pid, 2**31 - 1)


def parse_ndjson_timestamp(value):
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return int(parsed.timestamp() * 1000)


def verify_ndjson_window(
    path, provider_pid, subsystem, run_uuid, start, end, traffic_start, traffic_end,
    *, require_attribution=True,
):
    provider_rows = 0
    marker_ids = set()
    for line in path.read_text(encoding="utf-8", errors="strict").splitlines():
        try:
            record = signed_run_evidence._json_object(
                line.encode("utf-8"), "system.ndjson record"
            )
        except ValueError as error:
            raise ValueError("malformed system.ndjson") from error
        timestamp = parse_ndjson_timestamp(record.get("timestamp"))
        if timestamp is None:
            raise ValueError("system.ndjson row has no valid timestamp")
        message = record.get("eventMessage")
        if not isinstance(message, str):
            raise ValueError("system.ndjson row has no event message")
        marker = STRESS_MARKER_RE.fullmatch(message)
        process_id = record.get("processID")
        if (
            isinstance(process_id, bool)
            or not isinstance(process_id, int)
            or process_id != provider_pid
        ):
            raise ValueError("stress marker came from the wrong provider pid")
        if record.get("subsystem") != subsystem:
            raise ValueError("stress marker came from the wrong provider subsystem")
        if not start <= timestamp <= end:
            raise ValueError("provider log row is outside the exact run window")
        if not require_attribution:
            if marker is not None or STRESS_MARKER_PREFIX in message:
                raise ValueError("diagnostic provider log contains an attribution marker")
            provider_rows += 1
            continue
        if marker is None:
            raise ValueError("malformed stress attribution marker")
        if marker.group(1) != run_uuid:
            raise ValueError("stress marker has the wrong run UUID")
        request_id = marker.group(2)
        if request_id in marker_ids:
            raise ValueError("duplicate stress request marker")
        if not traffic_start <= timestamp <= traffic_end:
            raise ValueError("stress marker is outside the traffic window")
        marker_ids.add(request_id)
        provider_rows += 1
    if provider_rows == 0:
        raise ValueError("system.ndjson has no provider row inside the run window")
    return marker_ids


def measure_attribution(
    directory, provider_pid_text, subsystem, run_uuid, start_text, end_text,
    traffic_start_text, traffic_end_text,
):
    provider_pid = canonical_uint(provider_pid_text, 2**31 - 1)
    if provider_pid == 0 or not subsystem:
        raise ValueError("invalid provider attribution identity")
    canonical_uuid(run_uuid)
    start = canonical_uint(start_text)
    end = canonical_uint(end_text)
    traffic_start = canonical_uint(traffic_start_text)
    traffic_end = canonical_uint(traffic_end_text)
    if not 0 < start <= traffic_start < traffic_end <= end:
        raise ValueError("invalid attribution window")
    marker_ids = verify_ndjson_window(
        artifact_path(directory, "system.ndjson"),
        provider_pid,
        subsystem,
        run_uuid,
        start,
        end,
        traffic_start,
        traffic_end,
    )
    successful_ids = {
        transfer[0]
        for transfers in parse_transfers(directory, run_uuid).values()
        for transfer in transfers
    }
    if marker_ids != successful_ids:
        raise ValueError("provider request marker set does not equal successful traffic")
    return len(marker_ids)


def verify(directory):
    common_envelope = (directory / signed_run_evidence.STATUS_NAME).exists()
    if common_envelope:
        signed_run_evidence.verify(directory)
    status = read_status(artifact_path(directory, "stress-status.tsv"))
    run_uuid = canonical_uuid(status["run_uuid"])
    start = canonical_uint(status["run_start_epoch"])
    end = canonical_uint(status["run_end_epoch"])
    if start == 0 or end <= start:
        raise ValueError("invalid status run interval")
    mode = status["evidence_mode"]
    provider_pid_text = status["provider_pid"]
    expected = expected_artifacts(mode, provider_pid_text, status["traffic_role"])
    manifest = artifact_path(directory, "stress-manifest.tsv")
    manifest_hash = sha256_file(manifest)
    if status["artifact_manifest_sha256"] != manifest_hash:
        raise ValueError("manifest digest does not match source status")
    rows = manifest.read_text(encoding="utf-8").splitlines()
    header = [
        f"schema_version\t{SCHEMA_VERSION}", f"run_uuid\t{run_uuid}",
        f"run_start_epoch\t{start}", f"run_end_epoch\t{end}",
        f"evidence_mode\t{mode}", f"provider_pid\t{provider_pid_text}",
        f"evidence_claim\t{EVIDENCE_CLAIM}",
        f"traffic_role\t{status['traffic_role']}",
        f"workload_identity\t{status['workload_identity']}",
    ]
    if rows[:9] != header or rows[-1:] != ["schema_complete\t1"]:
        raise ValueError("manifest identity or schema is invalid")
    artifact_rows = rows[9:-1]
    if len(artifact_rows) != len(expected):
        raise ValueError("manifest artifact set is incomplete")
    for row, expected_name in zip(artifact_rows, expected):
        fields = row.split("\t")
        if len(fields) != 4 or fields[:2] != ["artifact", expected_name]:
            raise ValueError("manifest artifact set/order is invalid")
        size = canonical_uint(fields[2])
        if SHA256_RE.fullmatch(fields[3]) is None:
            raise ValueError("manifest artifact digest is invalid")
        path = artifact_path(
            directory, expected_name,
            allow_empty=expected_name in {"git-status.txt", "system-log-capture.err"},
        )
        if path.stat().st_size != size or sha256_file(path) != fields[3]:
            raise ValueError(f"artifact {expected_name} changed after sealing")
    if sha256_file(directory / "source-stress_traffic.sh") != status["stress_script_sha256"]:
        raise ValueError("stress source hash mismatch")
    if sha256_file(directory / "source-stress_evidence.py") != status["evidence_helper_sha256"]:
        raise ValueError("evidence helper source hash mismatch")
    if common_envelope:
        if (
            sha256_file(directory / "source-signed_run_evidence.py")
            != status["signed_evidence_helper_sha256"]
        ):
            raise ValueError("signed evidence helper source hash mismatch")
    git_head = artifact_path(directory, "git-head.txt").read_text(encoding="utf-8").strip()
    if GIT_HEAD_RE.fullmatch(git_head) is None or git_head != status["git_head"]:
        raise ValueError("git identity mismatch")
    dirty = "1" if (directory / "git-status.txt").stat().st_size else "0"
    if status["git_dirty"] != dirty:
        raise ValueError("git dirty-state mismatch")
    if sha256_file(directory / "stress-workload.tsv") != status["workload_identity"]:
        raise ValueError("sealed workload identity mismatch")
    expected_metric_rows, transfers = derive_metrics(
        directory, status["max_p95_ms"], status["min_throughput_milli_rps"],
        status["max_rss_growth_bytes"], status["max_cpu_percent"], mode,
        provider_pid_text, run_uuid,
        status.get("provider_generation_identity", status["provider_identity"]),
    )
    expected_metric_lines = [f"{key}\t{value}" for key, value in expected_metric_rows]
    metric_lines = artifact_path(directory, "stress-metrics.tsv").read_text(
        encoding="utf-8", errors="strict"
    ).splitlines()
    if metric_lines != expected_metric_lines:
        raise ValueError("metrics TSV does not match sealed raw transfers")
    metrics = dict(expected_metric_rows)
    if metrics["metric_schema_version"] != str(SCHEMA_VERSION) or metrics["metric_status"] != "PASSED":
        raise ValueError("performance metrics did not pass")
    traffic_start = canonical_uint(metrics["traffic_start_epoch_ms"])
    traffic_end = canonical_uint(metrics["traffic_end_epoch_ms"])
    if common_envelope and (
        status["traffic_start_epoch_ms"] != str(traffic_start)
        or status["traffic_end_epoch_ms"] != str(traffic_end)
    ):
        raise ValueError("traffic interval claim/metric mismatch")
    if not start <= traffic_start < traffic_end <= end:
        raise ValueError("traffic metric interval is outside the source run window")
    for key in (
        "max_p95_ms", "min_throughput_milli_rps", "max_rss_growth_bytes",
        "max_cpu_percent", "observed_p95_ms", "observed_throughput_milli_rps",
        "observed_rss_growth_bytes", "observed_max_cpu_percent",
    ):
        if metrics[key] != status[key]:
            raise ValueError(f"metric/status mismatch for {key}")
    if mode == "provider-monitored-traffic-only":
        provider_pid = parse_identity(directory, status)
        if (
            status["ndjson_included"] != "1"
            or status["system_log_started"] != "1"
            or status["system_log_alive_end"] != "1"
            or status["system_log_joined"] != "1"
            or status["system_log_child_rc"] not in {"0", "143"}
        ):
            raise ValueError("monitored source omitted system log evidence")
        marker_ids = verify_ndjson_window(
            directory / "system.ndjson",
            provider_pid,
            status["provider_signing_identifier"],
            run_uuid,
            start,
            end,
            traffic_start,
            traffic_end,
            require_attribution=status["traffic_role"] == "proxy-candidate",
        )
        successful_ids = {
            transfer[0]
            for worker_transfers in transfers.values()
            for transfer in worker_transfers
        }
        claimed_markers = canonical_uint(status["attributed_request_count"])
        if status["traffic_role"] == "proxy-candidate":
            if marker_ids != successful_ids or claimed_markers != len(marker_ids):
                raise ValueError("stress request marker set does not match successful traffic")
        elif marker_ids or claimed_markers != 0:
            raise ValueError("non-candidate run contains proxy-attribution markers")
    elif (
        provider_pid_text != "none" or status["provider_identity"] != "none"
        or status["provider_executable_sha256"] != "none"
        or status["provider_signing_identifier"] != "none"
        or status["provider_signing_team"] != "none"
        or status["provider_signing_cdhash"] != "none"
        or status["ndjson_included"] != "0"
        or status["system_log_started"] != "0"
        or status["system_log_alive_end"] != "0"
        or status["system_log_joined"] != "0"
        or status["system_log_child_rc"] != "none"
        or status["system_log_tool_sha256"] != "none"
        or status["attributed_request_count"] != "0"
        or metrics["observed_rss_growth_bytes"] != "not_applicable"
        or metrics["observed_max_cpu_percent"] != "not_applicable"
    ):
        raise ValueError("traffic-only source claims unavailable provider evidence")
    if common_envelope and status["traffic_role"] == "direct-baseline":
        if (
            status["provider_absent"] != "1"
            or status["provider_build_identity"] != "absent"
            or status["provider_generation_identity"] != "absent"
        ):
            raise ValueError("direct baseline lacks provider-absence evidence")
    elif common_envelope and status["provider_absent"] != "0":
        raise ValueError("non-direct source has an invalid provider-absence claim")
    envelope_manifest_hash = manifest_hash
    if common_envelope:
        envelope_manifest_hash = sha256_file(
            directory / signed_run_evidence.MANIFEST_NAME
        )
    return run_uuid, start, end, envelope_manifest_hash


def main():
    try:
        command, directory_text, *args = sys.argv[1:]
        directory = Path(directory_text)
        if command == "workload" and len(args) == 8:
            print(write_workload(directory, *args))
        elif command == "metrics" and len(args) in {8, 9}:
            print(*write_metrics(directory, *args), sep="\t")
        elif command == "attribution" and len(args) == 7:
            print(measure_attribution(directory, *args))
        elif command == "seal" and len(args) == 7:
            print(seal(directory, *args))
        elif command == "verify" and not args:
            print(*verify(directory), sep="\t")
        else:
            raise ValueError(
                "usage: stress_evidence.py <workload|metrics|attribution|seal|verify> "
                "DIR [arguments]"
            )
    except (OSError, UnicodeError, ValueError) as error:
        print(f"stress evidence failed: {error}", file=sys.stderr)
        raise SystemExit(2)


if __name__ == "__main__":
    main()
