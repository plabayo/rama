#!/usr/bin/env python3
"""Strict parser for the signed modern-UDP terminal evidence artifact."""

import ipaddress
import hashlib
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
    "passthrough_dns_source_pid", "passthrough_dns_flow_id",
    "control_dns_source_pid", "control_dns_flow_id", "ntp_source_pid", "ntp_flow_id",
    "pressure_source_pid", "pressure_flow_id", "blocked_dns_source_pid",
    "blocked_dns_flow_id", "dial9_required_close_reason_name",
    "dial9_close_age_bound_ms",
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


def is_udp_443_endpoint(value):
    try:
        if value.startswith("["):
            address, port = value[1:].split("]:", 1)
        else:
            address, port = value.rsplit(":", 1)
        return int(port) == 443 and str(ipaddress.ip_address(address)) == address
    except (ValueError, TypeError):
        return False


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
    r"udp_e2e_decision rama_decision=([^ ]+) flow_id=([0-9]+) "
    r"remote_endpoint=([^ ]+) source_app=([^ ]+) source_pid=([0-9]+)"
)


def pressure_window_observation(
    lines, starting_line, expected_pid, endpoint, source_app
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
        if match is not None and int(match.group(5)) == expected_pid:
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
        if decision[2] == endpoint and decision[3] == source_app
    ]
    unexpected = len(decisions) - len(exact)
    flow_id = int(exact[0][1]) if len(exact) == 1 else None
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
    )):
        return None
    if numeric["schema_version"] != 3:
        return None
    attempts = numeric["udp_probe_attempt_count"]
    passes = numeric["udp_probe_pass_count"]
    if not 0 <= passes <= attempts <= 5:
        return None
    verdict = (
        numeric["complete"], numeric["passed"], numeric["exit_code"])
    probe_flow_keys = (
        "passthrough_dns_flow_id", "control_dns_flow_id", "ntp_flow_id",
        "pressure_flow_id", "blocked_dns_flow_id", "http3_flow_id",
    )
    probe_pid_keys = (
        "passthrough_dns_source_pid", "control_dns_source_pid", "ntp_source_pid",
        "pressure_source_pid", "blocked_dns_source_pid", "http3_source_pid",
    )
    probe_flows = [optional_uints[key] for key in probe_flow_keys]
    prerequisites = (
        attempts == 5
        and values["callback_generation"] in ("modern", "legacy")
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
        and numeric["provider_identity_stable"] == 1
        and optional_uints["http3_source_pid"] not in (None, 0)
        and optional_uints["http3_flow_id"] not in (None, 0)
        and is_udp_443_endpoint(values["http3_remote_endpoint"])
        and _valid_uuid(values["run_uuid"])
        and all(optional_uints[key] not in (None, 0) for key in probe_pid_keys)
        and all(flow not in (None, 0) for flow in probe_flows)
        and len(set(probe_flows)) == len(probe_flows)
        and optional_uints["dial9_required_flow_id"] == optional_uints["ntp_flow_id"]
        and numeric["dial9_current_segment_count"] >= 1
        and numeric["dial9_required_pair_count"] == 1
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
        and optional_uints["dial9_required_bytes_in"] >= 48
        and optional_uints["dial9_required_bytes_out"] >= 48
    )
    if verdict == (1, 1, 0):
        valid = (
            prerequisites and passing_requirements and passes == 5
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
    elif verdict == (0, 0, 2):
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


def main():
    if len(sys.argv) != 2:
        raise SystemExit("usage: modern_udp_evidence.py <udp-evidence-status.tsv>")
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
