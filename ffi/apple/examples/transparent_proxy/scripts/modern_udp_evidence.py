#!/usr/bin/env python3
"""Strict parser and raw-bundle verifier for signed modern-UDP evidence."""

import csv
from datetime import datetime
import ipaddress
import hashlib
import io
import json
from pathlib import Path
import re
import sys
import uuid


SINGLETON_KEYS = {
    "complete", "passed", "exit_code", "udp_probe_attempt_count",
    "udp_probe_pass_count", "udp_pressure_log_checked",
    "rust_udp_drop_transitions", "rust_udp_resume_transitions",
    "swift_udp_staging_drop_samples",
    "log_stream_started", "log_stream_alive_end",
    "log_stream_joined", "profile_restored", "dial9_baseline_max_index",
    "callback_generation", "dial9_required_flow_id",
    "dial9_current_segment_count", "dial9_required_pair_count",
    "dial9_required_close_reason", "dial9_required_close_age_ms",
    "dial9_required_bytes_in", "dial9_required_bytes_out",
    "provider_pid", "provider_identity", "provider_identity_stable",
    "http3_source_pid", "http3_flow_id",
    "http3_remote_endpoint", "pressure_probe_attempted",
    "pressure_probe_passed", "pressure_drop_transitions",
    "pressure_resume_transitions", "pressure_drop_reasons",
    "pressure_recovered_reasons", "run_uuid",
    "run_start_epoch_ms", "run_end_epoch_ms", "evidence_kind",
    "provider_generation_identity", "producer_sources_sha256",
    "engine_generations_sha256",
    "http3_request_count", "http3_pass_count", "http3_flow_count",
    "http3_duration_ms", "http3_min_concurrent",
    "echo_socket_count", "echo_datagrams_per_socket", "echo_payload_bytes",
    "echo_expected_count", "echo_exact_echo_count", "echo_flow_count",
    "echo_payload_set_sha256", "echo_endpoint", "echo_source_pid",
    "pressure_datagram_count", "pressure_payload_bytes", "pressure_expected_bytes",
    "concurrent_load_deadline_seconds", "concurrent_load_timed_out",
    "active_workload_forced_termination_count",
    "passthrough_dns_source_pid", "passthrough_dns_flow_id",
    "control_dns_source_pid", "control_dns_flow_id", "ntp_source_pid", "ntp_flow_id",
    "pressure_source_pid", "pressure_flow_id", "blocked_dns_source_pid",
    "blocked_dns_flow_id", "dial9_required_close_reason_name",
    "dial9_close_age_bound_ms",
    "recovery_ntp_source_pid", "recovery_ntp_flow_id",
    "dial9_requirements_sha256", "dial9_requirement_count",
    "dial9_matched_requirement_count",
    "schema_version", "schema_complete",
}
DIAGNOSTIC_KEYS = {"issue", "failure", "observed_failure"}
OPTIONAL_UINT_KEYS = {
    "dial9_required_flow_id", "dial9_required_close_reason",
    "dial9_required_close_age_ms", "dial9_required_bytes_in",
    "dial9_required_bytes_out", "provider_pid", "http3_source_pid",
    "http3_flow_id", "passthrough_dns_source_pid", "passthrough_dns_flow_id",
    "control_dns_source_pid", "control_dns_flow_id", "ntp_source_pid", "ntp_flow_id",
    "pressure_source_pid", "pressure_flow_id", "blocked_dns_source_pid",
    "blocked_dns_flow_id",
    "recovery_ntp_source_pid", "recovery_ntp_flow_id", "echo_source_pid",
}


def parse_optional_uint(value, maximum=2**64 - 1):
    if value == "none":
        return None
    if re.fullmatch(r"0|[1-9]\d*", value) is None or len(value) > 20:
        raise ValueError("non-canonical integer")
    number = int(value)
    if number > maximum:
        raise ValueError("integer overflow")
    return number


def is_udp_endpoint(value, required_port=None):
    try:
        if value.startswith("["):
            address, port = value[1:].split("]:", 1)
        else:
            address, port = value.rsplit(":", 1)
        parsed_port = int(port)
        return (
            1 <= parsed_port <= 65535
            and (required_port is None or parsed_port == required_port)
            and str(ipaddress.ip_address(address)) == address
        )
    except (ValueError, TypeError):
        return False


def is_udp_443_endpoint(value):
    return is_udp_endpoint(value, 443)


def parse_pressure_reasons(value):
    if value == "none":
        return set()
    parts = value.split(",")
    allowed = {"channel_count", "flow_bytes", "global_bytes"}
    if parts != sorted(set(parts)) or not set(parts) <= allowed:
        raise ValueError("invalid pressure reasons")
    return set(parts)


CLOSE_REASON_NAMES = {
    1: "shutdown", 2: "idle_timeout", 3: "peer_eof_left",
    4: "peer_eof_right", 5: "read_error_left", 6: "read_error_right",
    7: "write_error_left", 8: "write_error_right", 9: "peek_timeout",
    10: "handler_deadline", 11: "paused_timeout", 12: "first_byte_timeout",
    13: "max_lifetime", 14: "service_panic",
}

UDP_E2E_DECISION_MARKER = "udp_e2e_decision "
UDP_E2E_DECISION_RE = re.compile(
    r"udp_e2e_decision run_uuid=([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
    r"[0-9a-f]{4}-[0-9a-f]{12}) provider_pid=([0-9]+) "
    r"provider_generation=([0-9]+) rama_decision=([^ ]+) flow_id=([0-9]+) "
    r"remote_endpoint=([^ ]+) local_endpoint=([^ ]+) source_app=([^ ]+) "
    r"source_pid=([0-9]+)$"
)
UDP_CALLBACK_ERROR_RE = re.compile(
    r"\bflow_callback_error operation=udp_flow\.(open|read|write)(?=\s|$)"
)


def validate_echo_decision_bijection(
    rows, client_endpoints, expected_count, source_pid, run_uuid,
    provider_pid, remote_endpoint,
):
    """Validate exact client-local-endpoint ↔ provider-flow correspondence."""
    if (
        not isinstance(rows, list) or not isinstance(client_endpoints, list)
        or len(client_endpoints) != expected_count
        or len(set(client_endpoints)) != expected_count
        or any(not is_udp_endpoint(endpoint) for endpoint in client_endpoints)
    ):
        raise ValueError("invalid controlled-echo client endpoint set")
    selected = [row for row in rows if len(row) == 9 and row[5] == str(source_pid)]
    if len(selected) != expected_count:
        raise ValueError("controlled-echo decision cardinality mismatch")
    if any(
        row[0] != "intercept" or row[2] != remote_endpoint
        or row[4] != "com.apple.python3" or row[6] != run_uuid
        or row[7] != str(provider_pid) or not is_udp_endpoint(row[3])
        for row in selected
    ):
        raise ValueError("controlled-echo decision identity mismatch")
    flow_ids = [row[1] for row in selected]
    local_endpoints = [row[3] for row in selected]
    if (
        any(not value.isdigit() or int(value) <= 0 for value in flow_ids)
        or len(set(flow_ids)) != expected_count
        or len(set(local_endpoints)) != expected_count
        or set(local_endpoints) != set(client_endpoints)
    ):
        raise ValueError("controlled-echo endpoint/flow mapping is not bijective")
    generations = {row[8] for row in selected}
    if len(generations) != 1 or any(
        not value.isdigit() or int(value) <= 0 for value in generations
    ):
        raise ValueError("controlled-echo provider generation mismatch")
    return sorted(
        ((row[8], row[1], row[3]) for row in selected),
        key=lambda value: int(value[1]),
    )


def pressure_window_observation(
    lines, starting_line, expected_pid, endpoint, source_app,
    expected_run_uuid=None, expected_provider_pid=None,
):
    """Return the exact-flow pressure terminal state for one live log prefix."""
    from soak_pressure_log import (
        SWIFT_UDP_STAGING_DROP_MARKER,
        UDP_PRESSURE_DROP_MARKER,
        UDP_PRESSURE_RESUME_MARKER,
        summarize_udp_pressure_rows,
    )

    if (
        isinstance(starting_line, bool) or not isinstance(starting_line, int)
        or not 0 <= starting_line <= len(lines)
        or isinstance(expected_pid, bool) or not isinstance(expected_pid, int)
        or expected_pid <= 0 or not isinstance(endpoint, str) or not endpoint
        or not isinstance(source_app, str) or not source_app
        or (expected_run_uuid is not None and not _valid_uuid(expected_run_uuid))
        or (
            expected_provider_pid is not None
            and (
                isinstance(expected_provider_pid, bool)
                or not isinstance(expected_provider_pid, int)
                or expected_provider_pid <= 0
            )
        )
    ):
        raise ValueError("invalid pressure-window identity")
    segment = lines[starting_line:]
    decisions = []
    malformed_decision = False
    relevant = []
    for line in segment:
        match = UDP_E2E_DECISION_RE.search(line)
        if UDP_E2E_DECISION_MARKER in line and match is None:
            malformed_decision = True
            relevant.append(line)
            continue
        if match is not None and int(match.group(9)) == expected_pid:
            decisions.append(match.groups())
            relevant.append(line)
        if any(marker in line for marker in (
            UDP_PRESSURE_DROP_MARKER,
            UDP_PRESSURE_RESUME_MARKER,
            SWIFT_UDP_STAGING_DROP_MARKER,
        )):
            relevant.append(line)
    exact = [
        decision for decision in decisions
        if decision[5] == endpoint and decision[7] == source_app
        and (expected_run_uuid is None or decision[0] == expected_run_uuid)
        and (
            expected_provider_pid is None
            or int(decision[1]) == expected_provider_pid
        )
    ]
    unexpected = len(decisions) - len(exact)
    flow_id = int(exact[0][4]) if len(exact) == 1 else None
    summary = summarize_udp_pressure_rows(
        list(enumerate(segment, start=starting_line + 1)),
        workload_exercised=True,
        mode="find-ceiling",
        required_flow_id=flow_id,
    ) if flow_id is not None else None
    terminal = (
        not malformed_decision
        and unexpected == 0
        and len(exact) == 1
        and summary is not None
        and summary["status"] == "GOOD"
        and summary["drop_reasons"]
        and summary["drop_reasons"] == summary["recovered_reasons"]
        and not summary["unrecovered"]
        and summary["swift_staging_drop_samples"] == 0
    )
    fingerprint = hashlib.sha256(
        "\n".join(relevant).encode("utf-8", errors="strict")
    ).hexdigest()
    return {
        "terminal": terminal,
        "flow_id": flow_id,
        "fingerprint": fingerprint,
        "matching_decisions": len(exact),
        "unexpected_decisions": unexpected,
        "summary": summary,
    }


def parse_signed_udp_status_lines(lines):
    """Return the declared exit code for one valid terminal status, else None."""
    pairs = []
    values = {}
    diagnostics = {key: [] for key in DIAGNOSTIC_KEYS}
    for raw in lines:
        fields = raw.rstrip("\n").split("\t")
        if len(fields) != 2 or not all(fields):
            return None
        key, value = fields
        if key in SINGLETON_KEYS:
            if key in values:
                return None
            values[key] = value
        elif key in DIAGNOSTIC_KEYS:
            diagnostics[key].append(value)
        else:
            return None
        pairs.append((key, value))
    if [key for key, _ in pairs[:3]] != ["complete", "passed", "exit_code"]:
        return None
    if not pairs or pairs[-1] != ("schema_complete", "1"):
        return None
    if SINGLETON_KEYS - values.keys():
        return None
    numeric_text = {
        key: values[key]
        for key in SINGLETON_KEYS
        if key not in {
            "dial9_baseline_max_index", "callback_generation",
            "provider_identity", "http3_remote_endpoint", "run_uuid",
            "evidence_kind", "provider_generation_identity",
            "producer_sources_sha256",
            "engine_generations_sha256",
            "echo_payload_set_sha256", "echo_endpoint",
            "dial9_requirements_sha256",
            "pressure_drop_reasons", "pressure_recovered_reasons",
            "dial9_required_close_reason_name",
            *OPTIONAL_UINT_KEYS,
        }
    }
    if any(re.fullmatch(r"0|[1-9]\d*", value) is None for value in numeric_text.values()):
        return None
    if any(len(value) > 20 or int(value) > 2**64 - 1 for value in numeric_text.values()):
        return None
    numeric = {key: int(value) for key, value in numeric_text.items()}
    baseline = values["dial9_baseline_max_index"]
    if baseline != "none" and (
        re.fullmatch(r"0|[1-9]\d*", baseline) is None
        or len(baseline) > 10
        or int(baseline) > 2**32 - 1
    ):
        return None
    if values["callback_generation"] not in ("unknown", "modern", "legacy"):
        return None
    try:
        optional_uints = {
            key: parse_optional_uint(values[key]) for key in OPTIONAL_UINT_KEYS
        }
        drop_reasons = parse_pressure_reasons(values["pressure_drop_reasons"])
        recovered_reasons = parse_pressure_reasons(
            values["pressure_recovered_reasons"]
        )
    except ValueError:
        return None
    if any(numeric[key] not in (0, 1) for key in (
        "complete", "passed", "log_stream_started", "log_stream_alive_end",
        "log_stream_joined", "profile_restored", "udp_pressure_log_checked",
        "schema_complete", "provider_identity_stable",
        "pressure_probe_attempted", "pressure_probe_passed",
        "concurrent_load_timed_out",
    )):
        return None
    if numeric["schema_version"] != 5:
        return None
    attempts = numeric["udp_probe_attempt_count"]
    passes = numeric["udp_probe_pass_count"]
    if not 0 <= passes <= attempts <= 8:
        return None
    verdict = (
        numeric["complete"], numeric["passed"], numeric["exit_code"])
    probe_flow_keys = (
        "passthrough_dns_flow_id", "control_dns_flow_id", "ntp_flow_id",
        "pressure_flow_id", "recovery_ntp_flow_id", "blocked_dns_flow_id",
        "http3_flow_id",
    )
    probe_pid_keys = (
        "passthrough_dns_source_pid", "control_dns_source_pid", "ntp_source_pid",
        "pressure_source_pid", "blocked_dns_source_pid", "http3_source_pid",
        "recovery_ntp_source_pid",
    )
    probe_flows = [optional_uints[key] for key in probe_flow_keys]
    prerequisites = (
        attempts == 8
        and values["evidence_kind"] == "modern_udp"
        and 0 < numeric["run_start_epoch_ms"] <= numeric["run_end_epoch_ms"]
        and values["callback_generation"] == "modern"
        and optional_uints["dial9_required_flow_id"] not in (None, 0)
        and numeric["udp_pressure_log_checked"] == 1
        and numeric["pressure_probe_attempted"] == 1
        and numeric["pressure_probe_passed"] == 1
        and numeric["log_stream_started"] == 1
        and numeric["log_stream_alive_end"] == 1
        and numeric["log_stream_joined"] == 1
        and numeric["profile_restored"] == 1
        and optional_uints["provider_pid"] not in (None, 0)
        and re.fullmatch(r"[0-9a-f]{64}", values["provider_identity"]) is not None
        and values["provider_identity"] == values["provider_generation_identity"]
        and numeric["provider_identity_stable"] == 1
        and re.fullmatch(r"[0-9a-f]{64}", values["provider_generation_identity"])
            is not None
        and re.fullmatch(r"[0-9a-f]{64}", values["producer_sources_sha256"])
            is not None
        and re.fullmatch(r"[0-9a-f]{64}", values["engine_generations_sha256"])
            is not None
        and optional_uints["http3_source_pid"] not in (None, 0)
        and optional_uints["http3_flow_id"] not in (None, 0)
        and is_udp_443_endpoint(values["http3_remote_endpoint"])
        and numeric["http3_min_concurrent"] >= 2
        and numeric["http3_request_count"] >= 6
        and numeric["http3_pass_count"] == numeric["http3_request_count"]
        and numeric["http3_flow_count"] == numeric["http3_request_count"]
        and numeric["http3_duration_ms"] >= 2_000
        and 128 <= numeric["echo_socket_count"] <= 512
        and 1 <= numeric["echo_datagrams_per_socket"] <= 64
        and 1_200 <= numeric["echo_payload_bytes"] <= 60_000
        and numeric["echo_expected_count"]
            == numeric["echo_socket_count"] * numeric["echo_datagrams_per_socket"]
        and numeric["echo_exact_echo_count"] == numeric["echo_expected_count"]
        and numeric["echo_flow_count"] == numeric["echo_socket_count"]
        and re.fullmatch(r"[0-9a-f]{64}", values["echo_payload_set_sha256"])
            is not None
        and is_udp_endpoint(values["echo_endpoint"])
        and optional_uints["echo_source_pid"] not in (None, 0)
        and 64 <= numeric["pressure_datagram_count"] <= 100_000
        and 64 <= numeric["pressure_payload_bytes"] <= 60_000
        and numeric["pressure_expected_bytes"]
            == numeric["pressure_datagram_count"] * numeric["pressure_payload_bytes"]
        and numeric["pressure_expected_bytes"] <= 256 * 1024 * 1024
        and 1 <= numeric["concurrent_load_deadline_seconds"] < 600
        and numeric["concurrent_load_timed_out"] == 0
        and numeric["active_workload_forced_termination_count"] == 0
        and _valid_uuid(values["run_uuid"])
        and all(optional_uints[key] not in (None, 0) for key in probe_pid_keys)
        and all(flow not in (None, 0) for flow in probe_flows)
        and len(set(probe_flows)) == len(probe_flows)
        and optional_uints["dial9_required_flow_id"] == optional_uints["ntp_flow_id"]
        and numeric["dial9_current_segment_count"] >= 1
        and re.fullmatch(r"[0-9a-f]{64}", values["dial9_requirements_sha256"])
            is not None
        and numeric["dial9_requirement_count"] == numeric["echo_flow_count"] + 3
        and numeric["dial9_matched_requirement_count"]
            == numeric["dial9_requirement_count"]
        and numeric["dial9_required_pair_count"]
            == numeric["dial9_requirement_count"]
        and optional_uints["dial9_required_close_reason"] in CLOSE_REASON_NAMES
        and values["dial9_required_close_reason_name"]
            == CLOSE_REASON_NAMES.get(optional_uints["dial9_required_close_reason"])
        and optional_uints["dial9_required_close_age_ms"] is not None
        and numeric["dial9_close_age_bound_ms"] > 0
        and optional_uints["dial9_required_close_age_ms"]
            <= numeric["dial9_close_age_bound_ms"]
        and optional_uints["dial9_required_bytes_in"] is not None
        and optional_uints["dial9_required_bytes_out"] is not None
    )
    passing_requirements = (
        numeric["pressure_drop_transitions"] >= 1
        and numeric["pressure_resume_transitions"] >= 1
        and bool(drop_reasons)
        and drop_reasons == recovered_reasons
        and optional_uints["dial9_required_close_reason"] == 1
        and values["dial9_required_close_reason_name"] == "shutdown"
    )
    if verdict == (1, 1, 0):
        valid = (
            prerequisites and passing_requirements and passes == 8
            and numeric["rust_udp_drop_transitions"] >= 1
            and numeric["pressure_drop_transitions"] >= len(drop_reasons)
            and numeric["pressure_resume_transitions"] >= len(recovered_reasons)
            and numeric["swift_udp_staging_drop_samples"] == 0
            and not any(diagnostics.values())
        )
    elif verdict == (1, 0, 1):
        valid = (
            prerequisites
            and not diagnostics["issue"]
            and bool(diagnostics["failure"])
            and not diagnostics["observed_failure"]
        )
    elif verdict in ((0, 0, 2), (0, 0, 130), (0, 0, 143)):
        valid = (
            bool(diagnostics["issue"])
            and not diagnostics["failure"]
        )
    else:
        valid = False
    return numeric["exit_code"] if valid else None


def _valid_uuid(value):
    try:
        return str(uuid.UUID(value)) == value
    except (ValueError, AttributeError):
        return False


class BundleVerificationError(ValueError):
    """A sealed modern bundle does not prove its declared raw semantics."""


def _bundle_uint(value, maximum=2**64 - 1):
    if (
        isinstance(value, bool)
        or (not isinstance(value, (str, int)))
        or re.fullmatch(r"0|[1-9]\d*", str(value)) is None
    ):
        raise BundleVerificationError("non-canonical bundle integer")
    number = int(value)
    if number > maximum:
        raise BundleVerificationError("bundle integer exceeds its bound")
    return number


def _read_bundle_bytes(root, name, maximum, allow_empty=False):
    path = root / name
    try:
        if path.is_symlink() or not path.is_file():
            raise BundleVerificationError(f"required raw artifact is not a regular file: {name}")
        size = path.stat().st_size
        if size > maximum or (size == 0 and not allow_empty):
            raise BundleVerificationError(f"raw artifact has invalid size: {name}")
        content = path.read_bytes()
    except OSError as error:
        raise BundleVerificationError(f"cannot read raw artifact: {name}") from error
    if len(content) != size:
        raise BundleVerificationError(f"raw artifact changed while being read: {name}")
    return content


def _read_bundle_text(root, name, maximum, allow_empty=False):
    content = _read_bundle_bytes(root, name, maximum, allow_empty=allow_empty)
    try:
        text = content.decode("utf-8", errors="strict")
    except UnicodeError as error:
        raise BundleVerificationError(f"raw artifact is not UTF-8: {name}") from error
    if "\r" in text or (text and not text.endswith("\n")):
        raise BundleVerificationError(f"raw artifact is not canonical text: {name}")
    return text


def _exact_key_tsv(root, name, order, maximum=256 * 1024):
    text = _read_bundle_text(root, name, maximum)
    rows = []
    values = {}
    for line in text.splitlines():
        fields = line.split("\t")
        if len(fields) != 2 or not all(fields) or fields[0] in values:
            raise BundleVerificationError(f"malformed or duplicate row in {name}")
        values[fields[0]] = fields[1]
        rows.append(fields[0])
    if rows != list(order):
        raise BundleVerificationError(f"incorrect field order or set in {name}")
    return values


PRODUCER_SOURCE_NAMES = (
    "source-test_modern_udp_flow.sh",
    "source-modern_udp_e2e_probe.py",
    "source-install_tproxy_app_bundle.sh",
    "source-modern_udp_evidence.py",
    "source-soak_pressure_log.py",
    "source-signed_run_evidence.py",
)

WORKLOAD_CLAIM_FIELDS = (
    "evidence_kind", "run_uuid", "dial9_diagnostic_only",
    "dial9_workload_coverage", "dial9_claim", "quic_shaped_not_valid_quic",
    "echo_socket_count", "echo_exact_echo_count", "http3_request_count",
    "http3_pass_count", "dial9_requirement_count",
    "dial9_matched_requirement_count", "producer_sources_sha256",
    "schema_complete",
)


def producer_sources_sha256(root):
    """Hash the exact sealed modern producer bytes with an unambiguous framing."""
    digest = hashlib.sha256()
    for name in sorted(PRODUCER_SOURCE_NAMES):
        content = _read_bundle_bytes(root, name, 4 * 1024 * 1024)
        digest.update(name.encode("utf-8") + b"\0")
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest()


def _validate_producer_sources(root, status):
    digest = producer_sources_sha256(root)
    if digest != status["producer_sources_sha256"]:
        raise BundleVerificationError("sealed modern producer-source identity mismatch")
    claims = _exact_key_tsv(root, "workload-claims.tsv", WORKLOAD_CLAIM_FIELDS)
    exact = {
        "evidence_kind": "modern_udp",
        "run_uuid": status["run_uuid"],
        "dial9_diagnostic_only": "0",
        "dial9_workload_coverage": "1",
        "dial9_claim": "exact-workload",
        "quic_shaped_not_valid_quic": "1",
        "echo_socket_count": status["echo_socket_count"],
        "echo_exact_echo_count": status["echo_exact_echo_count"],
        "http3_request_count": status["http3_request_count"],
        "http3_pass_count": status["http3_pass_count"],
        "dial9_requirement_count": status["dial9_requirement_count"],
        "dial9_matched_requirement_count": status["dial9_matched_requirement_count"],
        "producer_sources_sha256": digest,
        "schema_complete": "1",
    }
    if claims != exact:
        raise BundleVerificationError("modern workload claims are not bound to raw/status evidence")


CRASH_SNAPSHOT_FIELDS = (
    "schema_version", "run_uuid", "provider_generation_identity",
    "since_epoch_ms", "snapshot_epoch_ms", "process_names", "crash_count",
    "crash_names_sha256", "schema_complete",
)
MODERN_PROVIDER_PROCESS = "org.ramaproxy.example.tproxy.dev.provider"
GENERATION_FIXED_FIELDS = (
    "schema_version", "provider_generation_identity", "running_pid",
    "running_start_epoch_ms", "running_start_epoch_us", "running_dynamic_cdhash",
    "running_command_sha256",
    "running_executable_path_sha256", "cadence_ms", "max_gap_ms",
    "sample_count",
)


def _validate_provider_generation_samples(root, status, required_through_epoch_ms):
    text = _read_bundle_text(root, "provider-generation-samples.tsv", 4 * 1024 * 1024)
    rows = []
    values = {}
    for line in text.splitlines():
        fields = line.split("\t")
        if len(fields) != 2 or not all(fields) or fields[0] in values:
            raise BundleVerificationError("provider generation sample proof is malformed")
        rows.append((fields[0], fields[1]))
        values[fields[0]] = fields[1]
    if (
        len(rows) < len(GENERATION_FIXED_FIELDS) + 4
        or tuple(key for key, _ in rows[:len(GENERATION_FIXED_FIELDS)])
            != GENERATION_FIXED_FIELDS
        or rows[-1] != ("schema_complete", "1")
        or values["schema_version"] != "1"
        or values["provider_generation_identity"]
            != status["provider_generation_identity"]
        or _bundle_uint(values["running_pid"], 2**31 - 1)
            != _bundle_uint(status["provider_pid"], 2**31 - 1)
    ):
        raise BundleVerificationError("provider generation proof is not bound to terminal identity")
    running_start = _bundle_uint(values["running_start_epoch_ms"])
    running_start_us = _bundle_uint(values["running_start_epoch_us"])
    cadence = _bundle_uint(values["cadence_ms"], 5_000)
    max_gap = _bundle_uint(values["max_gap_ms"], 10_000)
    count = _bundle_uint(values["sample_count"], 9_999_999)
    if (
        running_start == 0
        or running_start_us // 1000 != running_start
        or re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", values["running_dynamic_cdhash"]) is None
        or running_start > _bundle_uint(status["run_start_epoch_ms"])
        or not 250 <= cadence <= 5_000
        or not cadence <= max_gap <= min(cadence * 3, 10_000)
        or count < 3
        or any(
            re.fullmatch(r"[0-9a-f]{64}", values[key]) is None
            for key in ("running_command_sha256", "running_executable_path_sha256")
        )
    ):
        raise BundleVerificationError("provider generation cadence metadata is invalid")
    samples = rows[len(GENERATION_FIXED_FIELDS):-1]
    tail = "|".join((
        values["running_pid"], values["running_start_epoch_ms"],
        values["running_start_epoch_us"], values["running_dynamic_cdhash"],
        values["running_command_sha256"], values["running_executable_path_sha256"],
    ))
    epochs = []
    for index, (key, value) in enumerate(samples, start=1):
        fields = value.split("|", 1)
        if (
            key != f"sample_{index:06d}" or len(fields) != 2
            or fields[1] != tail
        ):
            raise BundleVerificationError("provider generation sample was substituted")
        epochs.append(_bundle_uint(fields[0]))
    run_start = _bundle_uint(status["run_start_epoch_ms"])
    run_end = _bundle_uint(status["run_end_epoch_ms"])
    pre_boundary = [epoch for epoch in epochs if epoch <= run_end]
    if (
        len(epochs) != count or epochs != sorted(epochs)
        or epochs[0] > run_start or epochs[-1] < required_through_epoch_ms
        or run_start - epochs[0] > max_gap
        or not pre_boundary or run_end - pre_boundary[-1] > max_gap
        or epochs[-1] > required_through_epoch_ms + 16_000
        or any(right - left > max_gap for left, right in zip(epochs, epochs[1:]))
    ):
        raise BundleVerificationError("provider generation samples do not span the bounded run/finalization")


def _validate_crash_snapshot(root, status):
    crash_root = root / "crashes"
    try:
        if crash_root.is_symlink() or not crash_root.is_dir():
            raise BundleVerificationError("provider crash snapshot directory is missing or unsafe")
        names = sorted(path.name for path in crash_root.iterdir())
    except OSError as error:
        raise BundleVerificationError("cannot inspect provider crash snapshot") from error
    if names != ["crash-snapshot.tsv"]:
        raise BundleVerificationError("passing modern evidence contains crash reports or extra crash artifacts")
    snapshot = _exact_key_tsv(
        root, "crashes/crash-snapshot.tsv", CRASH_SNAPSHOT_FIELDS
    )
    run_start = _bundle_uint(status["run_start_epoch_ms"])
    run_end = _bundle_uint(status["run_end_epoch_ms"])
    snapshot_epoch = _bundle_uint(snapshot["snapshot_epoch_ms"])
    if (
        snapshot["schema_version"] != "2"
        or snapshot["schema_complete"] != "1"
        or snapshot["run_uuid"] != status["run_uuid"]
        or snapshot["provider_generation_identity"]
            != status["provider_generation_identity"]
        or _bundle_uint(snapshot["since_epoch_ms"]) != run_start
        or not run_end <= snapshot_epoch <= run_end + 35_000
        or snapshot["process_names"] != MODERN_PROVIDER_PROCESS
        or snapshot["crash_count"] != "0"
        or snapshot["crash_names_sha256"] != hashlib.sha256(b"").hexdigest()
    ):
        raise BundleVerificationError("provider crash snapshot does not cover the exact modern generation/run")
    return snapshot_epoch


def _strict_json(root, name, expected_keys, maximum=2 * 1024 * 1024):
    content = _read_bundle_bytes(root, name, maximum)

    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise BundleVerificationError(f"duplicate JSON key in {name}: {key}")
            result[key] = value
        return result

    try:
        value = json.loads(
            content.decode("utf-8", errors="strict"), object_pairs_hook=unique_object
        )
    except (UnicodeError, ValueError, RecursionError) as error:
        raise BundleVerificationError(f"malformed JSON artifact: {name}") from error
    if not isinstance(value, dict) or set(value) != set(expected_keys):
        raise BundleVerificationError(f"incorrect JSON field set: {name}")
    return value


def _status_values(root):
    text = _read_bundle_text(root, "udp-evidence-status.tsv", 256 * 1024)
    if parse_signed_udp_status_lines(text.splitlines(keepends=True)) != 0:
        raise BundleVerificationError("terminal modern UDP status is not a strict pass")
    values = {}
    for line in text.splitlines():
        key, value = line.split("\t")
        if key in SINGLETON_KEYS:
            values[key] = value
    return values


PHASE_FIELDS = (
    "schema_version", "unblocked_start_line", "udp_error_start_line",
    "passthrough_start_line", "passthrough_end_line", "ntp_start_line",
    "ntp_end_line", "control_start_line", "control_end_line",
    "pressure_start_line", "pressure_end_line", "echo_start_line",
    "echo_end_line", "recovery_start_line", "recovery_end_line",
    "http3_start_line", "http3_end_line", "blocked_profile_start_line",
    "blocked_start_line", "blocked_end_line", "provider_log_end_line",
    "schema_complete",
)


def _provider_phases(root, line_count):
    raw = _exact_key_tsv(root, "provider-log-phases.tsv", PHASE_FIELDS)
    if raw["schema_version"] != "1" or raw["schema_complete"] != "1":
        raise BundleVerificationError("provider-log phase schema is incomplete")
    phases = {
        key: _bundle_uint(value, line_count)
        for key, value in raw.items()
        if key not in ("schema_version", "schema_complete")
    }
    if phases["provider_log_end_line"] != line_count:
        raise BundleVerificationError("provider-log terminal boundary is stale")
    sequential = (
        phases["unblocked_start_line"],
        phases["passthrough_start_line"], phases["passthrough_end_line"],
        phases["ntp_start_line"], phases["ntp_end_line"],
        phases["control_start_line"], phases["control_end_line"],
        phases["pressure_start_line"],
    )
    if list(sequential) != sorted(sequential):
        raise BundleVerificationError("early provider-log phase boundaries are unordered")
    if phases["udp_error_start_line"] != phases["unblocked_start_line"]:
        raise BundleVerificationError("provider error boundary does not start at the run generation")
    if phases["echo_start_line"] != phases["pressure_start_line"]:
        raise BundleVerificationError("echo and pressure did not share one concurrent start boundary")
    concurrent_end = max(phases["pressure_end_line"], phases["echo_end_line"])
    later = (
        concurrent_end,
        phases["recovery_start_line"], phases["recovery_end_line"],
        phases["http3_start_line"], phases["http3_end_line"],
        phases["blocked_profile_start_line"], phases["blocked_start_line"],
        phases["blocked_end_line"], phases["provider_log_end_line"],
    )
    if list(later) != sorted(later):
        raise BundleVerificationError("late provider-log phase boundaries are unordered")
    for prefix in ("passthrough", "ntp", "control", "pressure", "echo", "recovery", "http3", "blocked"):
        if phases[f"{prefix}_start_line"] >= phases[f"{prefix}_end_line"]:
            raise BundleVerificationError(f"empty provider-log phase: {prefix}")
    return phases


def _decision_records(lines):
    records = []
    for line_number, line in enumerate(lines, start=1):
        marker_count = line.count(UDP_E2E_DECISION_MARKER)
        match = UDP_E2E_DECISION_RE.search(line)
        if marker_count == 0:
            continue
        if marker_count != 1 or match is None:
            raise BundleVerificationError("provider log contains a malformed decision marker")
        groups = match.groups()
        if not _valid_uuid(groups[0]):
            raise BundleVerificationError("provider decision has a non-canonical run UUID")
        provider_pid = _bundle_uint(groups[1], 2**31 - 1)
        generation = _bundle_uint(groups[2])
        flow_id = _bundle_uint(groups[4])
        source_pid = _bundle_uint(groups[8], 2**31 - 1)
        if 0 in (provider_pid, generation, flow_id, source_pid):
            raise BundleVerificationError("provider decision contains a zero identity")
        if groups[3] not in ("passthrough", "intercept", "blocked"):
            raise BundleVerificationError("provider decision has an unknown action")
        if not is_udp_endpoint(groups[5]) or not is_udp_endpoint(groups[6]):
            raise BundleVerificationError("provider decision has a non-canonical endpoint")
        records.append({
            "line": line_number,
            "run_uuid": groups[0],
            "provider_pid": provider_pid,
            "generation": generation,
            "action": groups[3],
            "flow_id": flow_id,
            "remote": groups[5],
            "local": groups[6],
            "source_app": groups[7],
            "source_pid": source_pid,
        })
    return records


def _validate_udp_callback_errors(lines, phases):
    # Match the live gate's public unexpected-error marker. The provider emits
    # no such marker for pressure, peer disconnects, or normal closed-flow
    # callbacks. Keep the startup exclusion, but replay through the complete
    # sealed log: asynchronous errors can arrive after workload decisions and
    # the shell's scan while Dial9 collection/finalization is still running.
    for line in lines[phases["udp_error_start_line"]:phases["provider_log_end_line"]]:
        if UDP_CALLBACK_ERROR_RE.search(line) is not None:
            raise BundleVerificationError("provider log contains an unexpected UDP flow callback error")


def _in_phase(record, phases, prefix):
    return (
        phases[f"{prefix}_start_line"] < record["line"]
        <= phases[f"{prefix}_end_line"]
    )


def _endpoint_port(endpoint):
    return int(endpoint[1:].split("]:", 1)[1] if endpoint.startswith("[") else endpoint.rsplit(":", 1)[1])


def _validate_representative_decisions(status, decisions, phases):
    specs = {
        "passthrough": ("passthrough_dns_source_pid", "passthrough_dns_flow_id", "passthrough", 53),
        "ntp": ("ntp_source_pid", "ntp_flow_id", "intercept", 123),
        "control": ("control_dns_source_pid", "control_dns_flow_id", "passthrough", 53),
        "pressure": ("pressure_source_pid", "pressure_flow_id", "intercept", 123),
        "recovery": ("recovery_ntp_source_pid", "recovery_ntp_flow_id", "intercept", 123),
        "blocked": ("blocked_dns_source_pid", "blocked_dns_flow_id", "blocked", 53),
    }
    provider_pid = _bundle_uint(status["provider_pid"], 2**31 - 1)
    run_uuid = status["run_uuid"]
    result = {}
    representative_pids = []
    for label, (pid_key, flow_key, action, port) in specs.items():
        source_pid = _bundle_uint(status[pid_key], 2**31 - 1)
        flow_id = _bundle_uint(status[flow_key])
        matches = [row for row in decisions if row["source_pid"] == source_pid]
        if len(matches) != 1:
            raise BundleVerificationError(f"{label} canary does not have one exact decision")
        row = matches[0]
        if (
            row["flow_id"] != flow_id
            or row["action"] != action
            or row["source_app"] != "com.apple.python3"
            or row["provider_pid"] != provider_pid
            or row["run_uuid"] != run_uuid
            or _endpoint_port(row["remote"]) != port
            or not _in_phase(row, phases, label)
        ):
            raise BundleVerificationError(f"{label} canary identity/action mismatch")
        representative_pids.append(source_pid)
        result[label] = row
    if len(set(representative_pids)) != len(representative_pids):
        raise BundleVerificationError("representative canary source PIDs are ambiguous")
    if result["control"]["remote"] != result["blocked"]["remote"]:
        raise BundleVerificationError("pre-block control and blocked canary endpoints differ")
    if result["passthrough"]["remote"] == result["blocked"]["remote"]:
        raise BundleVerificationError("independent DNS canary reused the blocked endpoint")
    if len({result[label]["remote"] for label in ("ntp", "pressure", "recovery")}) != 1:
        raise BundleVerificationError("NTP pressure/recovery canaries target different endpoints")
    unblocked_labels = ("passthrough", "ntp", "control", "pressure", "recovery")
    generations = {result[label]["generation"] for label in unblocked_labels}
    if len(generations) != 1 or result["blocked"]["generation"] in generations:
        raise BundleVerificationError("provider generation transition is not exact")
    unblocked_generation = next(iter(generations))
    expected_digest = hashlib.sha256(
        f"{provider_pid}:{unblocked_generation}:{result['blocked']['generation']}".encode()
    ).hexdigest()
    if status["engine_generations_sha256"] != expected_digest:
        raise BundleVerificationError("engine generation digest does not match raw decisions")
    return result, unblocked_generation, result["blocked"]["generation"]


def _validate_probe_receipts(root, status, representative):
    # Common release verification materializes this module from the exact
    # evidence-head blob, alongside this archived validator. Never execute a
    # producer file taken from an unverified bundle to interpret its receipts.
    from modern_udp_e2e_probe import PROBE_LABELS, read_probe_receipt, replay_probe_receipt

    rows = _tabular_rows(root, "udp-probe-results.tsv", ("label", "source_pid", "exit_code"), 4096)
    if [row[0] for row in rows] != list(PROBE_LABELS):
        raise BundleVerificationError("UDP probe result label/cardinality mismatch")
    previous_end = 0
    try:
        for label, pid, exit_code in rows:
            decision = representative[label]
            if (_bundle_uint(pid, 2**31 - 1) != decision["source_pid"] or exit_code != "0"):
                raise BundleVerificationError("UDP probe joined child did not pass with the exact source PID")
            receipt = read_probe_receipt(root / f"udp-probe-{label}.json")
            if replay_probe_receipt(receipt, status["run_uuid"], label,
                                    decision["source_pid"], decision["remote"]) != 0:
                raise BundleVerificationError("UDP probe raw protocol outcome did not pass")
            if (not _bundle_uint(status["run_start_epoch_ms"]) <= receipt["start_epoch_ms"]
                    <= receipt["end_epoch_ms"] <= _bundle_uint(status["run_end_epoch_ms"])
                    or receipt["start_monotonic_ns"] < previous_end):
                raise BundleVerificationError("UDP probe receipts are unordered or outside the run")
            previous_end = receipt["end_monotonic_ns"]
    except (OSError, ValueError) as error:
        raise BundleVerificationError(f"UDP probe receipt verification failed: {error}") from error


ECHO_CLIENT_KEYS = {
    "schema_version", "kind", "run_uuid", "endpoint", "socket_count",
    "datagrams_per_socket", "payload_bytes", "expected_count", "sent_count",
    "received_count", "exact_echo_count", "unique_echo_count",
    "independent_socket_count", "local_endpoints", "local_endpoint_set_sha256",
    "payload_set_sha256", "echo_set_sha256", "error_count", "passed",
    "schema_complete",
    "interval_ms", "start_epoch_ms", "end_epoch_ms", "start_monotonic_ns",
    "end_monotonic_ns", "packet_timings_ns",
}
ECHO_SERVER_KEYS = {
    "schema_version", "kind", "run_uuid", "endpoint", "expected_count",
    "received_count", "echo_count", "duplicate_count", "malformed_count",
    "payload_set_sha256", "passed", "schema_complete",
}
ECHO_READY_KEYS = {
    "schema_version", "run_uuid", "endpoint", "server_pid", "schema_complete",
}


def _validate_echo_timing(client, status, sockets, per_socket):
    names = ("interval_ms", "start_epoch_ms", "end_epoch_ms",
             "start_monotonic_ns", "end_monotonic_ns")
    if any(type(client[name]) is not int or not 0 <= client[name] < 2**63 for name in names):
        raise BundleVerificationError("controlled echo clock samples are not canonical integers")
    interval = client["interval_ms"]
    start, end = client["start_monotonic_ns"], client["end_monotonic_ns"]
    wall_start, wall_end = client["start_epoch_ms"], client["end_epoch_ms"]
    if (
        interval > 10_000 or start <= 0 or end < start
        or not _bundle_uint(status["run_start_epoch_ms"]) <= wall_start <= wall_end
            <= _bundle_uint(status["run_end_epoch_ms"])
        or abs((wall_end - wall_start) * 1_000_000 - (end - start)) > 2_000_000_000
        or end - start > _bundle_uint(status["concurrent_load_deadline_seconds"]) * 1_000_000_000
    ):
        raise BundleVerificationError("controlled echo clock window is inconsistent")
    timings = client["packet_timings_ns"]
    if not isinstance(timings, list) or len(timings) != sockets * per_socket:
        raise BundleVerificationError("controlled echo packet timing cardinality mismatch")
    previous = {}
    for ordinal, row in enumerate(timings):
        if (not isinstance(row, list) or len(row) != 4
                or any(type(value) is not int or not 0 <= value < 2**63 for value in row)):
            raise BundleVerificationError("controlled echo packet timing is malformed")
        socket_index, sequence, sent, received = row
        if ((socket_index, sequence) != divmod(ordinal, per_socket)
                or not start <= sent <= received <= end):
            raise BundleVerificationError("controlled echo packet timing identity/window mismatch")
        if socket_index in previous:
            previous_sent, previous_received = previous[socket_index]
            if sent < previous_sent + interval * 1_000_000 or sent < previous_received:
                raise BundleVerificationError("controlled echo per-flow pacing is not supported by raw samples")
        previous[socket_index] = sent, received


def _validate_echo_raw(root, status, decisions, phases, unblocked_generation):
    client = _strict_json(root, "controlled-echo-client.json", ECHO_CLIENT_KEYS, 4 * 1024 * 1024)
    server = _strict_json(root, "controlled-echo-server.json", ECHO_SERVER_KEYS)
    ready = _strict_json(root, "controlled-echo-ready.json", ECHO_READY_KEYS)
    sockets = _bundle_uint(status["echo_socket_count"], 512)
    per_socket = _bundle_uint(status["echo_datagrams_per_socket"], 64)
    payload_bytes = _bundle_uint(status["echo_payload_bytes"], 60_000)
    expected = sockets * per_socket
    endpoint = status["echo_endpoint"]
    digest = status["echo_payload_set_sha256"]
    run_uuid = status["run_uuid"]
    echo_pid = _bundle_uint(status["echo_source_pid"], 2**31 - 1)
    _validate_echo_timing(client, status, sockets, per_socket)
    if not endpoint.startswith("127.0.0.1:") or not is_udp_endpoint(endpoint):
        raise BundleVerificationError("controlled echo endpoint is not canonical loopback")
    common = {
        "schema_version": 1, "run_uuid": run_uuid, "endpoint": endpoint,
        "expected_count": expected, "passed": True, "schema_complete": True,
    }
    for value, kind in ((client, "controlled_echo_client"), (server, "controlled_echo_server")):
        if value.get("kind") != kind or any(value.get(key) != item for key, item in common.items()):
            raise BundleVerificationError(f"{kind} raw result identity mismatch")
    if (
        client["socket_count"] != sockets
        or client["datagrams_per_socket"] != per_socket
        or client["payload_bytes"] != payload_bytes
        or any(client[key] != expected for key in (
            "sent_count", "received_count", "exact_echo_count", "unique_echo_count"
        ))
        or client["independent_socket_count"] != sockets
        or client["error_count"] != 0
        or any(server[key] != expected for key in ("received_count", "echo_count"))
        or server["duplicate_count"] != 0
        or server["malformed_count"] != 0
        or any(value != digest for value in (
            client["payload_set_sha256"], client["echo_set_sha256"],
            server["payload_set_sha256"],
        ))
        or re.fullmatch(r"[0-9a-f]{64}", digest) is None
        or _bundle_uint(status["echo_expected_count"], 65_536) != expected
        or _bundle_uint(status["echo_exact_echo_count"], 65_536) != expected
        or _bundle_uint(status["echo_flow_count"], 512) != sockets
    ):
        raise BundleVerificationError("controlled echo raw result/cardinality mismatch")
    local_endpoints = client["local_endpoints"]
    if (
        not isinstance(local_endpoints, list)
        or local_endpoints != sorted(set(local_endpoints))
        or len(local_endpoints) != sockets
        or any(not isinstance(value, str) or not value.startswith("127.0.0.1:")
               or not is_udp_endpoint(value) for value in local_endpoints)
    ):
        raise BundleVerificationError("controlled echo local endpoint set is not exact")
    endpoint_digest = hashlib.sha256("\n".join(local_endpoints).encode()).hexdigest()
    if client["local_endpoint_set_sha256"] != endpoint_digest:
        raise BundleVerificationError("controlled echo endpoint-set digest mismatch")
    if (
        ready != {
            "schema_version": 1, "run_uuid": run_uuid, "endpoint": endpoint,
            "server_pid": ready["server_pid"], "schema_complete": True,
        }
        or _bundle_uint(ready["server_pid"], 2**31 - 1) == 0
    ):
        raise BundleVerificationError("controlled echo readiness identity mismatch")
    expected_client_log = (
        f"QUIC-shaped UDP controlled echo ok: sockets={sockets} "
        f"datagrams={expected} bytes={payload_bytes} sha256={digest}\n"
    )
    if _read_bundle_text(root, "controlled-echo-client.log", 64 * 1024) != expected_client_log:
        raise BundleVerificationError("controlled echo client log does not match its raw result")
    if _read_bundle_bytes(root, "controlled-echo-server.log", 64 * 1024, allow_empty=True):
        raise BundleVerificationError("controlled echo server emitted unexpected output")

    selected = [row for row in decisions if row["source_pid"] == echo_pid]
    shell_rows = [[
        row["action"], str(row["flow_id"]), row["remote"], row["local"],
        row["source_app"], str(row["source_pid"]), row["run_uuid"],
        str(row["provider_pid"]), str(row["generation"]),
    ] for row in selected]
    identities = validate_echo_decision_bijection(
        shell_rows, local_endpoints, sockets, echo_pid, run_uuid,
        _bundle_uint(status["provider_pid"], 2**31 - 1), endpoint,
    )
    if any(not _in_phase(row, phases, "echo") for row in selected):
        raise BundleVerificationError("controlled echo decision escaped its raw phase")
    if {row["generation"] for row in selected} != {unblocked_generation}:
        raise BundleVerificationError("controlled echo used the wrong provider generation")
    identity_text = _read_bundle_text(root, "echo-identities.tsv", 256 * 1024)
    expected_identity_text = "".join(
        f"{generation}\t{flow_id}\t{local}\n" for generation, flow_id, local in identities
    )
    if identity_text != expected_identity_text:
        raise BundleVerificationError("derived echo identity artifact does not match provider.log")
    return [(int(generation), int(flow_id), local) for generation, flow_id, local in identities]


def _tabular_rows(root, name, header, maximum=2 * 1024 * 1024):
    text = _read_bundle_text(root, name, maximum)
    lines = text.splitlines()
    if not lines or lines[0].split("\t") != list(header):
        raise BundleVerificationError(f"incorrect tabular header: {name}")
    rows = [line.split("\t") for line in lines[1:]]
    if any(len(row) != len(header) or not all(row) for row in rows):
        raise BundleVerificationError(f"malformed tabular row: {name}")
    return rows


def _validate_http3_raw(root, status, decisions, phases, unblocked_generation, reserved_pids):
    pid_text = _read_bundle_text(root, "http3-pids.tsv", 256 * 1024)
    pid_rows = [line.split("\t") for line in pid_text.splitlines()]
    if any(len(row) != 3 or not all(row) for row in pid_rows):
        raise BundleVerificationError("malformed HTTP/3 PID rows")
    triples = [
        (_bundle_uint(row[0], 16), _bundle_uint(row[1], 16), _bundle_uint(row[2], 2**31 - 1))
        for row in pid_rows
    ]
    if not triples or any(0 in row for row in triples):
        raise BundleVerificationError("HTTP/3 PID rows contain zero identities")
    rounds = max(row[0] for row in triples)
    concurrency = max(row[1] for row in triples)
    expected_triples = [
        (round_number, worker, triples[(round_number - 1) * concurrency + worker - 1][2])
        for round_number in range(1, rounds + 1)
        for worker in range(1, concurrency + 1)
    ]
    if triples != expected_triples or rounds < 2 or concurrency < 2:
        raise BundleVerificationError("HTTP/3 round/worker PID matrix is incomplete")
    pids = [row[2] for row in triples]
    expected_count = rounds * concurrency
    if (
        len(set(pids)) != expected_count
        or set(pids) & set(reserved_pids)
        or expected_count != _bundle_uint(status["http3_request_count"], 256)
        or _bundle_uint(status["http3_pass_count"], 256) != expected_count
        or _bundle_uint(status["http3_flow_count"], 256) != expected_count
        or _bundle_uint(status["http3_min_concurrent"], 16) != concurrency
    ):
        raise BundleVerificationError("HTTP/3 raw PID/cardinality proof mismatch")
    result_rows = _tabular_rows(
        root, "http3-results.tsv",
        ("round", "worker", "source_pid", "exit_code", "http3_marker", "sha256"),
    )
    if len(result_rows) != expected_count:
        raise BundleVerificationError("HTTP/3 result cardinality mismatch")
    for triple, row in zip(triples, result_rows):
        observed = tuple(_bundle_uint(value) for value in row[:5])
        if observed[:3] != triple or observed[3:] != (0, 1):
            raise BundleVerificationError("HTTP/3 raw result identity/verdict mismatch")
        digest = row[5]
        if re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            raise BundleVerificationError("HTTP/3 raw result digest is malformed")
        output = _read_bundle_bytes(root, f"http3-{triple[0]}-{triple[1]}.log", 2 * 1024 * 1024)
        if hashlib.sha256(output).hexdigest() != digest or b"http=http/3" not in output:
            raise BundleVerificationError("HTTP/3 output does not prove its declared protocol/result")
    round_rows = _tabular_rows(
        root, "http3-round-results.tsv",
        ("round", "expected_workers", "barrier_release_epoch_ms", "pre_release_alive"),
    )
    if len(round_rows) != rounds:
        raise BundleVerificationError("HTTP/3 barrier result cardinality mismatch")
    release_epochs = []
    for round_number, row in enumerate(round_rows, start=1):
        values = tuple(_bundle_uint(value) for value in row)
        if values[0] != round_number or values[1] != concurrency or values[3] != concurrency:
            raise BundleVerificationError("HTTP/3 barrier did not hold exact concurrency")
        release_epochs.append(values[2])
    run_start = _bundle_uint(status["run_start_epoch_ms"])
    run_end = _bundle_uint(status["run_end_epoch_ms"])
    if (
        release_epochs != sorted(set(release_epochs))
        or any(not run_start <= value <= run_end for value in release_epochs)
    ):
        raise BundleVerificationError("HTTP/3 barrier release timing is outside the run")
    timing = _exact_key_tsv(
        root, "http3-timing.tsv",
        ("schema_version", "start_monotonic_ms", "end_monotonic_ms", "duration_ms",
         "rounds", "concurrency", "schema_complete"),
    )
    start = _bundle_uint(timing["start_monotonic_ms"])
    end = _bundle_uint(timing["end_monotonic_ms"])
    duration = _bundle_uint(timing["duration_ms"])
    if (
        timing["schema_version"] != "1" or timing["schema_complete"] != "1"
        or start == 0 or end < start or duration != end - start or duration < 2_000
        or duration != _bundle_uint(status["http3_duration_ms"])
        or _bundle_uint(timing["rounds"], 16) != rounds
        or _bundle_uint(timing["concurrency"], 16) != concurrency
        or duration > run_end - run_start + 1_000
    ):
        raise BundleVerificationError("HTTP/3 sustained timing proof is inconsistent")
    endpoints_text = _read_bundle_text(root, "http3-endpoints.txt", 64 * 1024)
    endpoints = endpoints_text.splitlines()
    if not endpoints or endpoints != sorted(set(endpoints)) or any(
        not is_udp_443_endpoint(endpoint) for endpoint in endpoints
    ):
        raise BundleVerificationError("HTTP/3 endpoint allowlist is malformed")
    selected = [row for row in decisions if row["source_pid"] in set(pids)]
    if (
        len(selected) != expected_count
        or {row["source_pid"] for row in selected} != set(pids)
        or len({row["flow_id"] for row in selected}) != expected_count
        or any(
            row["action"] != "passthrough" or row["source_app"] != "com.apple.nscurl"
            or row["remote"] not in endpoints or row["run_uuid"] != status["run_uuid"]
            or row["provider_pid"] != _bundle_uint(status["provider_pid"], 2**31 - 1)
            or row["generation"] != unblocked_generation
            or not _in_phase(row, phases, "http3")
            for row in selected
        )
    ):
        raise BundleVerificationError("HTTP/3 provider decisions do not match the raw workload")
    first = min(selected, key=lambda row: row["flow_id"])
    if (
        first["source_pid"] != _bundle_uint(status["http3_source_pid"], 2**31 - 1)
        or first["flow_id"] != _bundle_uint(status["http3_flow_id"])
        or first["remote"] != status["http3_remote_endpoint"]
    ):
        raise BundleVerificationError("HTTP/3 representative identity is not reproducible")
    return selected, pids


def _validate_pressure_raw(status, lines, phases, representative):
    try:
        from soak_pressure_log import (
            SWIFT_UDP_STAGING_DROP_MARKER,
            UDP_PRESSURE_DROP_MARKER,
            UDP_PRESSURE_RESUME_MARKER,
            summarize_udp_pressure_rows,
        )
    except ImportError as error:
        raise BundleVerificationError("pinned pressure parser is unavailable") from error
    pressure_flow = representative["pressure"]["flow_id"]
    healthy_ranges = (
        (phases["unblocked_start_line"], phases["pressure_start_line"]),
        (phases["pressure_end_line"], phases["blocked_profile_start_line"]),
        (phases["blocked_profile_start_line"], phases["provider_log_end_line"]),
    )
    healthy = [
        summarize_udp_pressure_rows(
            list(enumerate(lines[start:end], start=start + 1)),
            workload_exercised=True, mode="stress-only",
        )
        for start, end in healthy_ranges
    ]
    pressure = summarize_udp_pressure_rows(
        list(enumerate(
            lines[phases["pressure_start_line"]:phases["pressure_end_line"]],
            start=phases["pressure_start_line"] + 1,
        )),
        workload_exercised=True, mode="find-ceiling", required_flow_id=pressure_flow,
    )
    all_summaries = [*healthy, pressure]
    expected_reasons = ",".join(pressure["drop_reasons"]) or "none"
    expected_recovered = ",".join(pressure["recovered_reasons"]) or "none"
    drop_transitions = sum(value["drop_transitions"] for value in all_summaries)
    resume_transitions = sum(value["resume_transitions"] for value in all_summaries)
    swift_drops = sum(value["swift_staging_drop_samples"] for value in all_summaries)
    if (
        any(value["issues"] for value in all_summaries)
        or any(value["failures"] for value in all_summaries)
        or sum(value["events"] for value in healthy) != 0
        or pressure["status"] != "GOOD" or not pressure["drop_reasons"]
        or pressure["drop_reasons"] != pressure["recovered_reasons"]
        or pressure["unrecovered"] or swift_drops != 0
        or drop_transitions != _bundle_uint(status["rust_udp_drop_transitions"])
        or resume_transitions != _bundle_uint(status["rust_udp_resume_transitions"])
        or pressure["drop_transitions"] != _bundle_uint(status["pressure_drop_transitions"])
        or pressure["resume_transitions"] != _bundle_uint(status["pressure_resume_transitions"])
        or expected_reasons != status["pressure_drop_reasons"]
        or expected_recovered != status["pressure_recovered_reasons"]
        or _bundle_uint(status["swift_udp_staging_drop_samples"]) != swift_drops
    ):
        raise BundleVerificationError("raw pressure transition/recovery proof mismatch")
    markers = (UDP_PRESSURE_DROP_MARKER, UDP_PRESSURE_RESUME_MARKER, SWIFT_UDP_STAGING_DROP_MARKER)
    positions = [
        index for index, line in enumerate(
            lines[phases["unblocked_start_line"]:],
            start=phases["unblocked_start_line"] + 1,
        )
        if any(marker in line for marker in markers)
    ]
    if not positions or any(
        not phases["pressure_start_line"] < index <= phases["pressure_end_line"]
        for index in positions
    ):
        raise BundleVerificationError("pressure telemetry escaped the deliberate pressure phase")
    count = _bundle_uint(status["pressure_datagram_count"], 100_000)
    payload = _bundle_uint(status["pressure_payload_bytes"], 60_000)
    expected_bytes = count * payload
    if (
        count < 64 or payload < 64 or expected_bytes > 256 * 1024 * 1024
        or _bundle_uint(status["pressure_expected_bytes"]) != expected_bytes
    ):
        raise BundleVerificationError("pressure raw load dimensions are outside the bounded contract")


REQUIREMENT_HEADER = (
    "label", "provider_pid", "provider_generation", "flow_id", "protocol",
    "source_pid", "close_reason", "min_bytes_in", "max_bytes_in",
    "min_bytes_out", "max_bytes_out",
)


def _validate_requirements(root, status, representative, echo_identities, unblocked_generation):
    content = _read_bundle_bytes(root, "dial9-requirements.tsv", 2 * 1024 * 1024)
    try:
        text = content.decode("utf-8", errors="strict")
        if "\r" in text or not text.endswith("\n"):
            raise ValueError
        reader = csv.DictReader(io.StringIO(text), delimiter="\t")
        if tuple(reader.fieldnames or ()) != REQUIREMENT_HEADER:
            raise ValueError
        rows = list(reader)
    except (UnicodeError, ValueError, csv.Error) as error:
        raise BundleVerificationError("Dial9 requirements are malformed") from error
    labels = ["ntp", "pressure", "recovery-ntp"] + [
        f"echo-{index}" for index in range(len(echo_identities))
    ]
    if len(rows) != len(labels) or [row.get("label") for row in rows] != labels:
        raise BundleVerificationError("Dial9 requirements do not cover the exact modern workload")
    parsed = []
    for row in rows:
        if None in row or any(value in (None, "") for value in row.values()):
            raise BundleVerificationError("Dial9 requirement row is incomplete")
        parsed.append({key: _bundle_uint(row[key]) for key in REQUIREMENT_HEADER[1:]})
    provider_pid = _bundle_uint(status["provider_pid"], 2**31 - 1)
    if any(
        row["provider_pid"] != provider_pid or row["provider_generation"] != unblocked_generation
        or row["protocol"] != 2 or row["close_reason"] != 1
        or row["flow_id"] == 0 or row["source_pid"] == 0
        or row["min_bytes_in"] > row["max_bytes_in"]
        or row["min_bytes_out"] > row["max_bytes_out"]
        for row in parsed
    ):
        raise BundleVerificationError("Dial9 requirement identity/range is invalid")
    fixed = (
        (representative["ntp"], 48, 65_535, 48, 65_535),
        # The pressure burst sends equal-sized datagrams once each. Its exact
        # flow must accept at least one and reject at least one; rejected bytes
        # never enter the Rust ingress counter recorded by Dial9 at close.
        (representative["pressure"], _bundle_uint(status["pressure_payload_bytes"]),
         _bundle_uint(status["pressure_expected_bytes"])
         - _bundle_uint(status["pressure_payload_bytes"]), 0, 0),
        (representative["recovery"], 48, 65_535, 48, 65_535),
    )
    for row, (decision, min_in, max_in, min_out, max_out) in zip(parsed[:3], fixed):
        if (
            row["flow_id"] != decision["flow_id"]
            or row["source_pid"] != decision["source_pid"]
            or (row["min_bytes_in"], row["max_bytes_in"], row["min_bytes_out"], row["max_bytes_out"])
                != (min_in, max_in, min_out, max_out)
        ):
            raise BundleVerificationError("representative Dial9 requirement mismatch")
    echo_bytes = _bundle_uint(status["echo_datagrams_per_socket"]) * _bundle_uint(
        status["echo_payload_bytes"]
    )
    for row, (generation, flow_id, _local) in zip(parsed[3:], echo_identities):
        if (
            row["provider_generation"] != generation or row["flow_id"] != flow_id
            or row["source_pid"] != _bundle_uint(status["echo_source_pid"], 2**31 - 1)
            or any(row[key] != echo_bytes for key in (
                "min_bytes_in", "max_bytes_in", "min_bytes_out", "max_bytes_out"
            ))
        ):
            raise BundleVerificationError("echo Dial9 requirement mismatch")
    flow_ids = [row["flow_id"] for row in parsed]
    if len(set(flow_ids)) != len(flow_ids):
        raise BundleVerificationError("Dial9 requirements duplicate a flow identity")
    count = len(rows)
    if (
        hashlib.sha256(content).hexdigest() != status["dial9_requirements_sha256"]
        or _bundle_uint(status["dial9_requirement_count"]) != count
        or _bundle_uint(status["dial9_matched_requirement_count"]) != count
        or _bundle_uint(status["dial9_required_pair_count"]) != count
        or _bundle_uint(status["dial9_required_flow_id"]) != representative["ntp"]["flow_id"]
    ):
        raise BundleVerificationError("Dial9 requirement digest/cardinality status mismatch")


RESTORE_FIELDS = (
    "schema_version", "run_uuid", "provider_pid", "replaced_provider_generation",
    "restore_started_epoch_ms", "restore_completed_epoch_ms", "container_start_line",
    "container_end_line", "slice_line_count", "slice_sha256", "profile",
    "evidence_identity", "fresh_connected", "schema_complete",
)


def _validate_restore(root, status, blocked_generation):
    receipt = _exact_key_tsv(root, "restore-receipt.tsv", RESTORE_FIELDS)
    restore_log = _read_bundle_text(root, "restore.log", 2 * 1024 * 1024)
    slice_text = _read_bundle_text(root, "restore-container.log", 256 * 1024)
    lines = slice_text.splitlines()
    start = _bundle_uint(receipt["restore_started_epoch_ms"])
    end = _bundle_uint(receipt["restore_completed_epoch_ms"])
    line_start = _bundle_uint(receipt["container_start_line"])
    line_end = _bundle_uint(receipt["container_end_line"])
    if (
        receipt["schema_version"] != "1" or receipt["schema_complete"] != "1"
        or receipt["run_uuid"] != status["run_uuid"]
        or _bundle_uint(receipt["provider_pid"], 2**31 - 1) != _bundle_uint(status["provider_pid"], 2**31 - 1)
        or _bundle_uint(receipt["replaced_provider_generation"]) != blocked_generation
        or receipt["profile"] != "persisted-default"
        or receipt["evidence_identity"] != "absent" or receipt["fresh_connected"] != "1"
        or not _bundle_uint(status["run_start_epoch_ms"]) <= start <= end <= _bundle_uint(status["run_end_epoch_ms"])
        or not 4 <= len(lines) <= 256
        or _bundle_uint(receipt["slice_line_count"], 256) != len(lines)
        or line_end - line_start != len(lines)
        or receipt["slice_sha256"] != hashlib.sha256(slice_text.encode()).hexdigest()
    ):
        raise BundleVerificationError("restoration receipt does not match the terminal run")
    forbidden = (
        status["run_uuid"], "--evidence-run-uuid", "--udp-e2e-diagnostic-endpoints",
        "temporary UDP E2E evidence run=", "udp_e2e_diagnostic_endpoints",
    )
    if any(value in slice_text or value in restore_log for value in forbidden):
        raise BundleVerificationError("restoration retained an E2E evidence identity")
    invocation = (
        "restore_invocation schema=1 mode=dev reset_profile=0 "
        "udp_passthrough_ports=empty udp_blocked_endpoints=empty evidence_identity=absent"
    )
    if not restore_log.splitlines() or restore_log.splitlines()[0] != invocation:
        raise BundleVerificationError("restoration invocation receipt is missing or non-default")
    parsed_messages = []
    observed_epochs = []
    pattern = re.compile(r"^\[([^\]]+)\] (INFO|ERROR): (.*)$")
    for line in lines:
        match = pattern.fullmatch(line)
        if match is None:
            raise BundleVerificationError("restoration container slice contains a malformed line")
        try:
            timestamp = datetime.fromisoformat(match.group(1).replace("Z", "+00:00"))
            if timestamp.tzinfo is None:
                raise ValueError
            epoch_ms = int(timestamp.timestamp() * 1_000)
        except (ValueError, OverflowError) as error:
            raise BundleVerificationError("restoration container timestamp is malformed") from error
        observed_epochs.append(epoch_ms)
        parsed_messages.append(match.group(3))
    if observed_epochs != sorted(observed_epochs) or any(
        value < start - 1_000 or value > end + 1_000 for value in observed_epochs
    ):
        raise BundleVerificationError("restoration container timestamps are out of order/range")
    exact_messages = (
        "container app launched",
        "temporary test UDP pass-through ports=",
        "temporary test UDP blocked endpoints=",
        "udp_e2e_restore_profile=persisted-default evidence_identity=absent",
        "udp_e2e_restart=begin launch-time UDP policy overrides requested",
        "proxy stopped after UDP policy update",
        "calling startVPNTunnel",
        "transparent proxy start requested",
    )
    positions = []
    for message in exact_messages:
        matches = [index for index, value in enumerate(parsed_messages) if value == message]
        if len(matches) != 1:
            raise BundleVerificationError(f"restoration container proof lacks exact marker: {message}")
        positions.append(matches[0])
    disconnected = [
        index for index, value in enumerate(parsed_messages)
        if re.fullmatch(r"status transition [a-z]+ -> disconnected", value)
    ]
    connected = [
        index for index, value in enumerate(parsed_messages)
        if re.fullmatch(r"status transition [a-z]+ -> connected", value)
    ]
    if (
        positions != sorted(positions)
        or len(disconnected) != 1 or len(connected) != 1
        or not positions[4] < disconnected[0] < positions[5] < positions[6]
        or not positions[7] < connected[0]
        or any("invalid temporary UDP policy" in value for value in parsed_messages)
    ):
        raise BundleVerificationError("restoration did not prove an ordered fresh default restart")


def _verify_bundle_semantics(directory):
    root = Path(directory)
    if root.is_symlink() or not root.is_dir():
        raise BundleVerificationError("modern evidence root is not a directory")
    status = _status_values(root)
    _validate_producer_sources(root, status)
    provider_text = _read_bundle_text(root, "provider.log", 64 * 1024 * 1024)
    provider_lines = provider_text.splitlines()
    phases = _provider_phases(root, len(provider_lines))
    decisions = _decision_records(provider_lines)
    if not decisions or any(
        row["run_uuid"] != status["run_uuid"]
        or row["provider_pid"] != _bundle_uint(status["provider_pid"], 2**31 - 1)
        for row in decisions
    ):
        raise BundleVerificationError("provider decisions are not bound to one run/provider")
    representative, unblocked_generation, blocked_generation = (
        _validate_representative_decisions(status, decisions, phases)
    )
    _validate_probe_receipts(root, status, representative)
    representative_pids = {row["source_pid"] for row in representative.values()}
    echo_pid = _bundle_uint(status["echo_source_pid"], 2**31 - 1)
    if echo_pid in representative_pids:
        raise BundleVerificationError("controlled echo source PID collides with a canary")
    echo_identities = _validate_echo_raw(
        root, status, decisions, phases, unblocked_generation
    )
    http3, http3_pids = _validate_http3_raw(
        root, status, decisions, phases, unblocked_generation,
        representative_pids | {echo_pid},
    )
    expected_decision_count = 6 + len(echo_identities) + len(http3)
    flow_ids = [row["flow_id"] for row in decisions]
    known_pids = representative_pids | {echo_pid} | set(http3_pids)
    if (
        len(decisions) != expected_decision_count
        or {row["source_pid"] for row in decisions} != known_pids
        or len(set(flow_ids)) != len(flow_ids)
    ):
        raise BundleVerificationError("provider decision set has omitted/extra/colliding flows")
    _validate_udp_callback_errors(provider_lines, phases)
    _validate_pressure_raw(status, provider_lines, phases, representative)
    _validate_requirements(
        root, status, representative, echo_identities, unblocked_generation
    )
    _validate_restore(root, status, blocked_generation)
    crash_snapshot_epoch = _validate_crash_snapshot(root, status)
    _validate_provider_generation_samples(root, status, crash_snapshot_epoch)
    return 0


def verify_bundle(directory):
    """Re-derive modern workload semantics from a materialized sealed bundle."""
    try:
        return _verify_bundle_semantics(directory)
    except BundleVerificationError:
        raise
    except (KeyError, IndexError, TypeError, OverflowError, UnicodeError) as error:
        raise BundleVerificationError("raw modern bundle has malformed semantics") from error


def main():
    if len(sys.argv) == 3 and sys.argv[1] == "verify-bundle":
        try:
            parsed = verify_bundle(sys.argv[2])
        except (BundleVerificationError, OSError) as error:
            print(f"modern UDP bundle verification failed: {error}", file=sys.stderr)
            raise SystemExit(2)
        print(parsed)
        return
    if len(sys.argv) != 2:
        raise SystemExit(
            "usage: modern_udp_evidence.py <udp-evidence-status.tsv> | verify-bundle <dir>"
        )
    try:
        with open(sys.argv[1], encoding="utf-8") as status_input:
            parsed = parse_signed_udp_status_lines(status_input)
    except OSError:
        parsed = None
    if parsed is None:
        raise SystemExit(2)
    print(parsed)


if __name__ == "__main__":
    main()
