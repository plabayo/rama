#!/usr/bin/env python3
"""Measure, seal, and re-verify one self-attested local stress run."""

from datetime import datetime
from decimal import Decimal, InvalidOperation, ROUND_CEILING
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import uuid


SCHEMA_VERSION = 2
WORKERS = (
    "small_https", "small_http1", "plain_http", "large_get", "post_large",
    "head_only", "churn_close", "parallel_pool",
)
COMMON_ARTIFACTS = tuple(
    f"{worker}{suffix}" for worker in WORKERS for suffix in (".log", ".summary")
) + (
    "stress-metrics.tsv", "source-stress_traffic.sh",
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
TRANSFER_RE = re.compile(
    r"2\d\d curl_exit=0 downloaded=(\d+) uploaded=(\d+) "
    r"http_version=\S+ duration_seconds=([0-9]+(?:\.[0-9]+)?)$"
)
SUMMARY_RE = re.compile(r"(\S+) done: iters=(\d+) ok=(\d+) fail=(\d+)$")
PS_ROW_RE = re.compile(
    r"^\s*(\d+)\s+(\d+)\s+(\d+)\s+([0-9]+(?:\.[0-9]+)?)\s+\S+\s*$"
)

STATUS_FIELDS = {
    "complete", "passed", "exit_code", "evidence_mode", "proxy_attributed",
    "evidence_claim", "run_uuid", "run_start_epoch", "run_end_epoch",
    "artifact_manifest_sha256", "max_p95_ms",
    "min_throughput_milli_rps", "max_rss_growth_bytes", "max_cpu_percent",
    "observed_p95_ms", "observed_throughput_milli_rps",
    "observed_rss_growth_bytes", "observed_max_cpu_percent", "git_head",
    "git_dirty", "stress_script_sha256", "evidence_helper_sha256",
    "provider_pid", "provider_identity", "provider_executable_sha256",
    "provider_signing_identifier", "provider_signing_team",
    "provider_signing_cdhash", "ndjson_included", "schema_complete", "issue",
    "traffic_role", "workload_identity",
    "system_log_started", "system_log_alive_end", "system_log_joined",
    "system_log_child_rc",
    "system_log_tool_sha256",
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
    values, rows = read_unique_tsv(path, STATUS_FIELDS)
    required = STATUS_FIELDS - {"issue"}
    if set(values) != required or not rows or rows[-1] != "schema_complete\t1":
        raise ValueError("incomplete or unsealed source status")
    if (
        values["complete"] != "1" or values["passed"] != "1"
        or values["exit_code"] != "0" or values["proxy_attributed"] != "0"
        or values["evidence_mode"] not in SOURCE_MODES
        or values["evidence_claim"] != EVIDENCE_CLAIM
        or values["traffic_role"] not in {
            "unpaired-diagnostic", "direct-baseline", "proxy-candidate"
        }
        or SHA256_RE.fullmatch(values["workload_identity"]) is None
    ):
        raise ValueError("source run did not pass")
    return values


def artifact_path(directory, name, allow_empty=False):
    path = directory / name
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"artifact {name} is missing or not a regular file")
    if not allow_empty and path.stat().st_size == 0:
        raise ValueError(f"artifact {name} is empty")
    return path


def expected_artifacts(mode, provider_pid):
    names = list(COMMON_ARTIFACTS)
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


def parse_transfers(directory):
    durations = []
    total = 0
    for worker in WORKERS:
        expected = parse_summary(directory, worker)
        observed = 0
        for line in artifact_path(directory, f"{worker}.log").read_text(
            encoding="utf-8", errors="strict"
        ).splitlines():
            match = TRANSFER_RE.fullmatch(line)
            if match is None:
                continue
            try:
                duration = Decimal(match.group(3))
            except InvalidOperation as error:
                raise ValueError(f"invalid {worker} duration") from error
            if not duration.is_finite() or duration <= 0:
                raise ValueError(f"invalid {worker} duration")
            durations.append(duration)
            observed += 1
        if observed != expected:
            raise ValueError(f"{worker} log/summary success-count mismatch")
        total += observed
    return durations, total


def parse_ps_rows(path, provider_pid):
    rows = []
    for line in artifact_path(path.parent, path.name).read_text(
        encoding="utf-8", errors="strict"
    ).splitlines():
        match = PS_ROW_RE.fullmatch(line)
        if match is None:
            continue
        if canonical_uint(match.group(1), 2**31 - 1) != provider_pid:
            raise ValueError(f"foreign pid in {path.name}")
        rss_kib = canonical_uint(match.group(2))
        cpu = Decimal(match.group(4))
        if not cpu.is_finite():
            raise ValueError(f"invalid cpu in {path.name}")
        rows.append((rss_kib * 1024, cpu))
    if not rows:
        raise ValueError(f"no provider resource sample in {path.name}")
    return rows


def write_metrics(
    directory, start_text, end_text, max_p95_text, min_throughput_text,
    max_rss_text, max_cpu_text, mode, provider_pid_text,
):
    start = canonical_uint(start_text)
    end = canonical_uint(end_text)
    if start == 0 or end <= start:
        raise ValueError("invalid metric interval")
    max_p95 = canonical_uint(max_p95_text)
    minimum_throughput = canonical_uint(min_throughput_text)
    max_rss = canonical_uint(max_rss_text)
    max_cpu = canonical_uint(max_cpu_text)
    durations, total = parse_transfers(directory)
    durations.sort()
    rank = ((len(durations) * 95 + 99) // 100) - 1
    p95_ms = int((durations[rank] * 1000).to_integral_value(rounding=ROUND_CEILING))
    throughput = (total * 1_000_000) // (end - start)
    observed_rss = "not_applicable"
    observed_cpu = "not_applicable"
    passed = p95_ms <= max_p95 and throughput >= minimum_throughput
    if mode == "provider-monitored-traffic-only":
        provider_pid = canonical_uint(provider_pid_text, 2**31 - 1)
        if provider_pid == 0:
            raise ValueError("invalid provider pid")
        preflight = parse_ps_rows(directory / "preflight.txt", provider_pid)
        postflight = parse_ps_rows(directory / "postflight.txt", provider_pid)
        monitor = parse_ps_rows(directory / f"monitor.{provider_pid}.log", provider_pid)
        baseline_rss = preflight[0][0]
        all_rows = preflight + monitor + postflight
        observed_rss_number = max(0, max(row[0] for row in all_rows) - baseline_rss)
        observed_cpu_number = int(
            max(row[1] for row in all_rows).to_integral_value(rounding=ROUND_CEILING)
        )
        observed_rss = str(observed_rss_number)
        observed_cpu = str(observed_cpu_number)
        passed = passed and observed_rss_number <= max_rss and observed_cpu_number <= max_cpu
    elif mode != "traffic-only" or provider_pid_text != "none":
        raise ValueError("metric mode/provider mismatch")
    values = (
        ("metric_schema_version", str(SCHEMA_VERSION)),
        ("metric_status", "PASSED" if passed else "FAILED"),
        ("traffic_start_epoch_ms", str(start)),
        ("traffic_end_epoch_ms", str(end)),
        ("successful_requests", str(total)),
        ("observed_p95_ms", str(p95_ms)),
        ("max_p95_ms", str(max_p95)),
        ("observed_throughput_milli_rps", str(throughput)),
        ("min_throughput_milli_rps", str(minimum_throughput)),
        ("observed_rss_growth_bytes", observed_rss),
        ("max_rss_growth_bytes", str(max_rss)),
        ("observed_max_cpu_percent", observed_cpu),
        ("max_cpu_percent", str(max_cpu)),
        ("schema_complete", "1"),
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
    for name in expected_artifacts(mode, provider_pid):
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
    required = {
        "pid", "identity", "executable", "executable_sha256",
        "signing_identifier", "signing_team", "signing_cdhash",
    }
    identity, _ = read_unique_tsv(
        artifact_path(directory, "provider-identity.tsv"), required, required
    )
    if (
        identity["pid"] != status["provider_pid"]
        or identity["identity"] != status["provider_identity"]
        or identity["executable_sha256"] != status["provider_executable_sha256"]
        or identity["signing_identifier"] != status["provider_signing_identifier"]
        or identity["signing_team"] != status["provider_signing_team"]
        or identity["signing_cdhash"] != status["provider_signing_cdhash"]
        or SHA256_RE.fullmatch(identity["identity"]) is None
        or SHA256_RE.fullmatch(identity["executable_sha256"]) is None
        or re.fullmatch(r"[0-9a-fA-F]+", identity["signing_cdhash"]) is None
        or not identity["executable"].startswith("/")
    ):
        raise ValueError("provider identity/status mismatch")
    if artifact_path(directory, "monitor.identity.sha256").read_text(
        encoding="utf-8"
    ).strip() != identity["identity"]:
        raise ValueError("monitor identity mismatch")
    codesign = artifact_path(directory, "provider-codesign.txt").read_text(
        encoding="utf-8", errors="strict"
    )
    signed_fields = {}
    for key, pattern in (
        ("signing_identifier", r"^Identifier=(.+)$"),
        ("signing_team", r"^TeamIdentifier=(.+)$"),
        ("signing_cdhash", r"^CDHash=([0-9a-fA-F]+)$"),
    ):
        matches = re.findall(pattern, codesign, flags=re.MULTILINE)
        if len(matches) != 1:
            raise ValueError(f"provider codesign output has no unique {key}")
        signed_fields[key] = matches[0]
    if any(identity[key] != value for key, value in signed_fields.items()):
        raise ValueError("provider codesign/identity mismatch")
    log_tool_required = {"path", "sha256"}
    log_tool, _ = read_unique_tsv(
        artifact_path(directory, "system-log-tool.tsv"),
        log_tool_required, log_tool_required,
    )
    if (
        not log_tool["path"].startswith("/")
        or SHA256_RE.fullmatch(log_tool["sha256"]) is None
        or log_tool["sha256"] != status["system_log_tool_sha256"]
    ):
        raise ValueError("system log tool identity mismatch")
    return canonical_uint(identity["pid"], 2**31 - 1)


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


def verify_ndjson_window(path, provider_pid, start, end):
    matched = 0
    for line in path.read_text(encoding="utf-8", errors="strict").splitlines():
        try:
            record = json.loads(line)
        except json.JSONDecodeError as error:
            raise ValueError("malformed system.ndjson") from error
        if not isinstance(record, dict):
            raise ValueError("malformed system.ndjson row")
        if record.get("processID") != provider_pid:
            continue
        timestamp = parse_ndjson_timestamp(record.get("timestamp"))
        if timestamp is not None and start <= timestamp <= end:
            matched += 1
    if matched == 0:
        raise ValueError("system.ndjson has no provider row inside the run window")


def verify(directory):
    status = read_status(artifact_path(directory, "stress-status.tsv"))
    run_uuid = canonical_uuid(status["run_uuid"])
    start = canonical_uint(status["run_start_epoch"])
    end = canonical_uint(status["run_end_epoch"])
    if start == 0 or end <= start:
        raise ValueError("invalid status run interval")
    mode = status["evidence_mode"]
    provider_pid_text = status["provider_pid"]
    expected = expected_artifacts(mode, provider_pid_text)
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
    git_head = artifact_path(directory, "git-head.txt").read_text(encoding="utf-8").strip()
    if GIT_HEAD_RE.fullmatch(git_head) is None or git_head != status["git_head"]:
        raise ValueError("git identity mismatch")
    dirty = "1" if (directory / "git-status.txt").stat().st_size else "0"
    if status["git_dirty"] != dirty:
        raise ValueError("git dirty-state mismatch")
    metric_required = {
        "metric_schema_version", "metric_status", "successful_requests",
        "traffic_start_epoch_ms", "traffic_end_epoch_ms",
        "observed_p95_ms", "max_p95_ms", "observed_throughput_milli_rps",
        "min_throughput_milli_rps", "observed_rss_growth_bytes",
        "max_rss_growth_bytes", "observed_max_cpu_percent", "max_cpu_percent",
        "schema_complete",
    }
    metrics, metric_rows = read_unique_tsv(
        artifact_path(directory, "stress-metrics.tsv"), metric_required, metric_required
    )
    if not metric_rows or metric_rows[-1] != "schema_complete\t1":
        raise ValueError("unsealed metrics")
    if metrics["metric_schema_version"] != str(SCHEMA_VERSION) or metrics["metric_status"] != "PASSED":
        raise ValueError("performance metrics did not pass")
    traffic_start = canonical_uint(metrics["traffic_start_epoch_ms"])
    traffic_end = canonical_uint(metrics["traffic_end_epoch_ms"])
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
        verify_ndjson_window(directory / "system.ndjson", provider_pid, start, end)
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
        or metrics["observed_rss_growth_bytes"] != "not_applicable"
        or metrics["observed_max_cpu_percent"] != "not_applicable"
    ):
        raise ValueError("traffic-only source claims unavailable provider evidence")
    return run_uuid, start, end, manifest_hash


def main():
    try:
        command, directory_text, *args = sys.argv[1:]
        directory = Path(directory_text)
        if command == "metrics" and len(args) == 8:
            print(*write_metrics(directory, *args), sep="\t")
        elif command == "seal" and len(args) == 7:
            print(seal(directory, *args))
        elif command == "verify" and not args:
            print(*verify(directory), sep="\t")
        else:
            raise ValueError(
                "usage: stress_evidence.py <metrics|seal|verify> DIR [arguments]"
            )
    except (OSError, UnicodeError, ValueError) as error:
        print(f"stress evidence failed: {error}", file=sys.stderr)
        raise SystemExit(2)


if __name__ == "__main__":
    main()
