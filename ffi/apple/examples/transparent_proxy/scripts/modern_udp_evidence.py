#!/usr/bin/env python3
"""Strict parser for the signed modern-UDP terminal evidence artifact."""

import re
import sys


SINGLETON_KEYS = {
    "complete", "passed", "exit_code", "udp_probe_attempt_count",
    "udp_probe_pass_count", "udp_pressure_log_checked",
    "rust_udp_drop_transitions", "rust_udp_resume_transitions",
    "swift_udp_staging_drop_samples",
    "log_stream_started", "log_stream_alive_end",
    "log_stream_joined", "profile_restored", "dial9_baseline_max_index",
    "callback_generation", "dial9_required_flow_id",
    "dial9_current_segment_count", "dial9_required_pair_count",
    "schema_version", "schema_complete",
}
DIAGNOSTIC_KEYS = {"issue", "failure", "observed_failure"}


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
            "dial9_required_flow_id",
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
    required_flow_id = values["dial9_required_flow_id"]
    if required_flow_id != "none" and (
        re.fullmatch(r"0|[1-9]\d*", required_flow_id) is None
        or len(required_flow_id) > 20
        or int(required_flow_id) > 2**64 - 1
    ):
        return None
    if any(numeric[key] not in (0, 1) for key in (
        "complete", "passed", "log_stream_started", "log_stream_alive_end",
        "log_stream_joined", "profile_restored", "udp_pressure_log_checked",
        "schema_complete",
    )):
        return None
    if numeric["schema_version"] != 1:
        return None
    attempts = numeric["udp_probe_attempt_count"]
    passes = numeric["udp_probe_pass_count"]
    if not 0 <= passes <= attempts <= 5:
        return None
    verdict = (
        numeric["complete"], numeric["passed"], numeric["exit_code"])
    prerequisites = (
        attempts == 5
        and values["callback_generation"] in ("modern", "legacy")
        and required_flow_id != "none"
        and numeric["udp_pressure_log_checked"] == 1
        and numeric["log_stream_started"] == 1
        and numeric["log_stream_alive_end"] == 1
        and numeric["log_stream_joined"] == 1
        and numeric["profile_restored"] == 1
        and numeric["dial9_current_segment_count"] >= 1
        and numeric["dial9_required_pair_count"] == 1
    )
    if verdict == (1, 1, 0):
        valid = (
            prerequisites and passes == 5
            and numeric["rust_udp_drop_transitions"] == 0
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
