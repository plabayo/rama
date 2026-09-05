#!/usr/bin/env python3
"""Create or re-verify a paired direct-baseline/proxy stress verdict."""

import os
from pathlib import Path
import shutil
import sys

from stress_evidence import (
    EVIDENCE_CLAIM,
    canonical_uint,
    read_status,
    sha256_file,
    verify as verify_stress_run,
)


SCHEMA_VERSION = 1
SOURCE_COPY_SUFFIX = ".source-stress_compare.py"


def comparison_source_path(artifact):
    return artifact.with_name(artifact.name + SOURCE_COPY_SUFFIX)


def current_source_path():
    return Path(__file__).resolve()


def read_artifact(path, description):
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{description} is missing or not a regular file")
    rows = path.read_text(encoding="utf-8").splitlines()
    values = {}
    for row in rows:
        fields = row.split("\t")
        if len(fields) != 2 or not all(fields) or fields[0] in values:
            raise ValueError(f"{description} is malformed")
        values[fields[0]] = fields[1]
    return values, rows


def current_source_identity():
    source = current_source_path()
    if source.is_symlink() or not source.is_file() or source.stat().st_size == 0:
        raise ValueError("current stress_compare.py source is unavailable")
    return source, sha256_file(source)


def write_artifact_with_source(destination, rows):
    source, source_hash = current_source_identity()
    if f"comparison_helper_sha256\t{source_hash}" not in rows:
        raise ValueError("stress_compare.py source changed while forming verdict")
    source_destination = comparison_source_path(destination)
    source_temporary = source_destination.with_name(
        source_destination.name + f".tmp.{os.getpid()}"
    )
    shutil.copyfile(source, source_temporary)
    if sha256_file(source_temporary) != source_hash:
        source_temporary.unlink(missing_ok=True)
        raise ValueError("copied stress_compare.py source identity changed")
    os.replace(source_temporary, source_destination)
    temporary = destination.with_name(destination.name + f".tmp.{os.getpid()}")
    temporary.write_text("\n".join(rows) + "\n", encoding="utf-8")
    os.replace(temporary, destination)


def comparison_rows(
    baseline_directory, candidate_directory, max_p95_ratio_text="1500",
    min_throughput_ratio_text="667", max_gap_ms_text="600000",
    comparison_helper_sha256=None,
):
    baseline_identity = verify_stress_run(baseline_directory)
    candidate_identity = verify_stress_run(candidate_directory)
    baseline_status_path = baseline_directory / "stress-status.tsv"
    candidate_status_path = candidate_directory / "stress-status.tsv"
    baseline = read_status(baseline_status_path)
    candidate = read_status(candidate_status_path)
    max_p95_ratio = canonical_uint(max_p95_ratio_text, 100_000)
    min_throughput_ratio = canonical_uint(min_throughput_ratio_text, 100_000)
    max_gap_ms = canonical_uint(max_gap_ms_text, 86_400_000)
    if max_p95_ratio == 0 or min_throughput_ratio == 0 or max_gap_ms == 0:
        raise ValueError("paired thresholds must be positive")
    if comparison_helper_sha256 is None:
        comparison_helper_sha256 = sha256_file(current_source_path())
    if len(comparison_helper_sha256) != 64 or any(
        character not in "0123456789abcdef" for character in comparison_helper_sha256
    ):
        raise ValueError("invalid comparison helper identity")
    if (
        baseline["traffic_role"] != "direct-baseline"
        or baseline["evidence_mode"] != "traffic-only"
    ):
        raise ValueError("baseline is not an explicit traffic-only direct run")
    if (
        candidate["traffic_role"] != "proxy-candidate"
        or candidate["evidence_mode"] != "provider-monitored-traffic-only"
    ):
        raise ValueError("candidate is not a provider-monitored proxy run")
    if baseline["workload_identity"] != candidate["workload_identity"]:
        raise ValueError("paired runs used different workloads")
    if (
        baseline["stress_script_sha256"] != candidate["stress_script_sha256"]
        or baseline["evidence_helper_sha256"] != candidate["evidence_helper_sha256"]
    ):
        raise ValueError("paired runs used different harness sources")
    baseline_end = canonical_uint(baseline["run_end_epoch"])
    candidate_start = canonical_uint(candidate["run_start_epoch"])
    if candidate_start < baseline_end or candidate_start - baseline_end > max_gap_ms:
        raise ValueError("paired runs are out of order or not adjacent")
    baseline_p95 = canonical_uint(baseline["observed_p95_ms"])
    candidate_p95 = canonical_uint(candidate["observed_p95_ms"])
    baseline_throughput = canonical_uint(baseline["observed_throughput_milli_rps"])
    candidate_throughput = canonical_uint(candidate["observed_throughput_milli_rps"])
    if baseline_p95 == 0 or baseline_throughput == 0:
        raise ValueError("baseline metrics cannot form a ratio")
    p95_ratio = (candidate_p95 * 1000 + baseline_p95 - 1) // baseline_p95
    throughput_ratio = (candidate_throughput * 1000) // baseline_throughput
    passed = p95_ratio <= max_p95_ratio and throughput_ratio >= min_throughput_ratio
    values = (
        ("schema_version", str(SCHEMA_VERSION)),
        ("complete", "1"),
        ("passed", "1" if passed else "0"),
        ("exit_code", "0" if passed else "1"),
        ("evidence_claim", EVIDENCE_CLAIM),
        ("comparison_helper_sha256", comparison_helper_sha256),
        ("workload_identity", baseline["workload_identity"]),
        ("baseline_run_uuid", baseline_identity[0]),
        ("baseline_manifest_sha256", baseline_identity[3]),
        ("baseline_status_sha256", sha256_file(baseline_status_path)),
        ("candidate_run_uuid", candidate_identity[0]),
        ("candidate_manifest_sha256", candidate_identity[3]),
        ("candidate_status_sha256", sha256_file(candidate_status_path)),
        ("baseline_end_epoch_ms", str(baseline_end)),
        ("candidate_start_epoch_ms", str(candidate_start)),
        ("maximum_pair_gap_ms", str(max_gap_ms)),
        ("baseline_p95_ms", str(baseline_p95)),
        ("candidate_p95_ms", str(candidate_p95)),
        ("observed_p95_ratio_milli", str(p95_ratio)),
        ("maximum_p95_ratio_milli", str(max_p95_ratio)),
        ("baseline_throughput_milli_rps", str(baseline_throughput)),
        ("candidate_throughput_milli_rps", str(candidate_throughput)),
        ("observed_throughput_ratio_milli", str(throughput_ratio)),
        ("minimum_throughput_ratio_milli", str(min_throughput_ratio)),
        ("candidate_rss_growth_bytes", candidate["observed_rss_growth_bytes"]),
        ("candidate_max_cpu_percent", candidate["observed_max_cpu_percent"]),
        ("schema_complete", "1"),
    )
    return [f"{key}\t{value}" for key, value in values]


def create_comparison(baseline, candidate, destination, *thresholds):
    _, source_hash = current_source_identity()
    rows = comparison_rows(
        baseline, candidate, *thresholds,
        comparison_helper_sha256=source_hash,
    )
    write_artifact_with_source(destination, rows)
    return 0 if "passed\t1" in rows else 1


def verify_comparison(baseline, candidate, artifact):
    values, existing = read_artifact(artifact, "comparison artifact")
    sealed_source = comparison_source_path(artifact)
    if (
        sealed_source.is_symlink() or not sealed_source.is_file()
        or sealed_source.stat().st_size == 0
    ):
        raise ValueError("sealed stress_compare.py source is missing")
    sealed_source_hash = sha256_file(sealed_source)
    if values.get("comparison_helper_sha256") != sealed_source_hash:
        raise ValueError("sealed stress_compare.py source changed after comparison")
    if sha256_file(current_source_path()) != sealed_source_hash:
        raise ValueError("current stress_compare.py differs from sealed comparison source")
    thresholds = (
        values.get("maximum_p95_ratio_milli", ""),
        values.get("minimum_throughput_ratio_milli", ""),
        values.get("maximum_pair_gap_ms", ""),
    )
    expected = comparison_rows(
        baseline, candidate, *thresholds,
        comparison_helper_sha256=sealed_source_hash,
    )
    if existing != expected:
        raise ValueError("comparison artifact does not match the sealed source runs")
    return canonical_uint(values["exit_code"], 1)


def integer_median(values):
    ordered = sorted(values)
    middle = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[middle]
    return (ordered[middle - 1] + ordered[middle] + 1) // 2


def series_rows(
    pairs, max_interpair_gap_text="600000", comparison_helper_sha256=None
):
    if len(pairs) < 3:
        raise ValueError("release series requires at least three stress pairs")
    max_interpair_gap = canonical_uint(max_interpair_gap_text, 86_400_000)
    if max_interpair_gap == 0:
        raise ValueError("inter-pair gap must be positive")
    if comparison_helper_sha256 is None:
        comparison_helper_sha256 = sha256_file(current_source_path())

    observed = []
    expected_workload = None
    expected_harness = None
    previous_candidate_end = None
    for index, (baseline_directory, candidate_directory, comparison) in enumerate(
        pairs, start=1
    ):
        pair_exit = verify_comparison(
            baseline_directory, candidate_directory, comparison
        )
        comparison_values, _ = read_artifact(
            comparison, f"comparison artifact {index}"
        )
        baseline = read_status(baseline_directory / "stress-status.tsv")
        candidate = read_status(candidate_directory / "stress-status.tsv")
        workload = comparison_values["workload_identity"]
        if expected_workload is None:
            expected_workload = workload
        elif workload != expected_workload:
            raise ValueError("release series used different workloads")
        harness = (
            baseline["stress_script_sha256"],
            baseline["evidence_helper_sha256"],
        )
        if expected_harness is None:
            expected_harness = harness
        elif harness != expected_harness:
            raise ValueError("release series used different harness sources")
        if canonical_uint(comparison_values["maximum_p95_ratio_milli"]) > 1500:
            raise ValueError("release series weakened the p95 pair gate")
        if canonical_uint(comparison_values["minimum_throughput_ratio_milli"]) < 667:
            raise ValueError("release series weakened the throughput pair gate")
        baseline_start = canonical_uint(baseline["run_start_epoch"])
        candidate_end = canonical_uint(candidate["run_end_epoch"])
        if previous_candidate_end is not None and (
            baseline_start < previous_candidate_end
            or baseline_start - previous_candidate_end > max_interpair_gap
        ):
            raise ValueError("release series pairs are not interleaved and adjacent")
        previous_candidate_end = candidate_end
        observed.append({
            "index": index,
            "pair_exit": pair_exit,
            "comparison_sha256": sha256_file(comparison),
            "comparison_source_sha256": sha256_file(
                comparison_source_path(comparison)
            ),
            "baseline_run_uuid": comparison_values["baseline_run_uuid"],
            "candidate_run_uuid": comparison_values["candidate_run_uuid"],
            "p95_ratio": canonical_uint(
                comparison_values["observed_p95_ratio_milli"]
            ),
            "throughput_ratio": canonical_uint(
                comparison_values["observed_throughput_ratio_milli"]
            ),
            "candidate_p95": canonical_uint(comparison_values["candidate_p95_ms"]),
            "candidate_throughput": canonical_uint(
                comparison_values["candidate_throughput_milli_rps"]
            ),
            "candidate_rss": canonical_uint(candidate["observed_rss_growth_bytes"]),
            "candidate_cpu": canonical_uint(candidate["observed_max_cpu_percent"]),
        })

    p95_ratios = [pair["p95_ratio"] for pair in observed]
    throughput_ratios = [pair["throughput_ratio"] for pair in observed]
    passed = all(pair["pair_exit"] == 0 for pair in observed)
    values = [
        ("schema_version", str(SCHEMA_VERSION)),
        ("complete", "1"),
        ("passed", "1" if passed else "0"),
        ("exit_code", "0" if passed else "1"),
        ("evidence_claim", EVIDENCE_CLAIM),
        ("comparison_helper_sha256", comparison_helper_sha256),
        ("pair_count", str(len(observed))),
        ("workload_identity", expected_workload),
        ("stress_script_sha256", expected_harness[0]),
        ("evidence_helper_sha256", expected_harness[1]),
        ("maximum_interpair_gap_ms", str(max_interpair_gap)),
        ("median_p95_ratio_milli", str(integer_median(p95_ratios))),
        ("worst_p95_ratio_milli", str(max(p95_ratios))),
        ("median_throughput_ratio_milli", str(integer_median(throughput_ratios))),
        ("worst_throughput_ratio_milli", str(min(throughput_ratios))),
        ("worst_candidate_p95_ms", str(max(pair["candidate_p95"] for pair in observed))),
        ("worst_candidate_throughput_milli_rps", str(
            min(pair["candidate_throughput"] for pair in observed)
        )),
        ("worst_candidate_rss_growth_bytes", str(
            max(pair["candidate_rss"] for pair in observed)
        )),
        ("worst_candidate_cpu_percent", str(
            max(pair["candidate_cpu"] for pair in observed)
        )),
    ]
    for pair in observed:
        prefix = f"pair_{pair['index']}"
        values.extend((
            (f"{prefix}_exit_code", str(pair["pair_exit"])),
            (f"{prefix}_comparison_sha256", pair["comparison_sha256"]),
            (f"{prefix}_comparison_source_sha256", pair["comparison_source_sha256"]),
            (f"{prefix}_baseline_run_uuid", pair["baseline_run_uuid"]),
            (f"{prefix}_candidate_run_uuid", pair["candidate_run_uuid"]),
            (f"{prefix}_p95_ratio_milli", str(pair["p95_ratio"])),
            (f"{prefix}_throughput_ratio_milli", str(pair["throughput_ratio"])),
        ))
    values.append(("schema_complete", "1"))
    return [f"{key}\t{value}" for key, value in values]


def create_series(pairs, destination):
    _, source_hash = current_source_identity()
    rows = series_rows(pairs, comparison_helper_sha256=source_hash)
    write_artifact_with_source(destination, rows)
    return 0 if "passed\t1" in rows else 1


def verify_series(pairs, artifact):
    values, existing = read_artifact(artifact, "series artifact")
    sealed_source = comparison_source_path(artifact)
    if sealed_source.is_symlink() or not sealed_source.is_file():
        raise ValueError("sealed stress_compare.py series source is missing")
    source_hash = sha256_file(sealed_source)
    if values.get("comparison_helper_sha256") != source_hash:
        raise ValueError("sealed stress_compare.py series source changed")
    if sha256_file(current_source_path()) != source_hash:
        raise ValueError("current stress_compare.py differs from sealed series source")
    expected = series_rows(
        pairs,
        values.get("maximum_interpair_gap_ms", ""),
        comparison_helper_sha256=source_hash,
    )
    if existing != expected:
        raise ValueError("series artifact does not match its sealed stress pairs")
    return canonical_uint(values["exit_code"], 1)


def main():
    try:
        if len(sys.argv) >= 3 and sys.argv[1] in ("create-series", "verify-series"):
            command = sys.argv[1]
            artifact = Path(sys.argv[2])
            pair_args = sys.argv[3:]
            if len(pair_args) < 9 or len(pair_args) % 3:
                raise ValueError(
                    "series usage requires at least three BASELINE CANDIDATE COMPARISON triples"
                )
            pairs = [
                tuple(Path(value) for value in pair_args[index:index + 3])
                for index in range(0, len(pair_args), 3)
            ]
            exit_code = (
                create_series(pairs, artifact)
                if command == "create-series"
                else verify_series(pairs, artifact)
            )
            raise SystemExit(exit_code)
        command, baseline_text, candidate_text, artifact_text, *args = sys.argv[1:]
        baseline = Path(baseline_text)
        candidate = Path(candidate_text)
        artifact = Path(artifact_text)
        if command == "create" and len(args) in (0, 3):
            exit_code = create_comparison(baseline, candidate, artifact, *args)
        elif command == "verify" and not args:
            exit_code = verify_comparison(baseline, candidate, artifact)
        else:
            raise ValueError(
                "usage: stress_compare.py <create|verify> BASELINE CANDIDATE ARTIFACT "
                "[MAX_P95_RATIO_MILLI MIN_THROUGHPUT_RATIO_MILLI MAX_GAP_MS]"
            )
    except (OSError, UnicodeError, ValueError) as error:
        print(f"stress comparison failed: {error}", file=sys.stderr)
        raise SystemExit(2)
    raise SystemExit(exit_code)


if __name__ == "__main__":
    main()
