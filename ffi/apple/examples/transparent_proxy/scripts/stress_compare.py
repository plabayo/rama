#!/usr/bin/env python3
"""Create or re-verify paired and self-contained series stress verdicts."""

import hashlib
import os
from pathlib import Path
import shutil
import sys
import uuid

import signed_run_evidence

from stress_evidence import (
    EVIDENCE_CLAIM,
    WORKERS,
    canonical_uint,
    derive_metrics,
    read_status,
    sha256_file,
    verify_release_policy,
    verify as verify_stress_run,
)


SCHEMA_VERSION = 1
SOURCE_COPY_SUFFIX = ".source-stress_compare.py"
MAX_RELEASE_GAP_MS = 600_000
SERIES_ARTIFACT_NAME = "stress-series.tsv"
SERIES_MEMBERS_NAME = "members"
SERIES_COMPARISONS_NAME = "comparisons"


def rederived_metrics(directory, status):
    rows, _ = derive_metrics(
        directory,
        status["max_p95_ms"],
        status["min_throughput_milli_rps"],
        status["max_rss_growth_bytes"],
        status["max_cpu_percent"],
        status["evidence_mode"],
        status["provider_pid"],
        status["run_uuid"],
        status.get("provider_generation_identity", status["provider_identity"]),
    )
    return dict(rows)


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
    common_envelopes = all(
        (directory / signed_run_evidence.STATUS_NAME).is_file()
        for directory in (baseline_directory, candidate_directory)
    )
    baseline_identity = verify_stress_run(baseline_directory)
    candidate_identity = verify_stress_run(candidate_directory)
    baseline_status_path = (
        baseline_directory / "evidence-status.tsv"
        if (baseline_directory / "evidence-status.tsv").is_file()
        else baseline_directory / "stress-status.tsv"
    )
    candidate_status_path = (
        candidate_directory / "evidence-status.tsv"
        if (candidate_directory / "evidence-status.tsv").is_file()
        else candidate_directory / "stress-status.tsv"
    )
    baseline = read_status(baseline_status_path)
    candidate = read_status(candidate_status_path)
    max_p95_ratio = canonical_uint(max_p95_ratio_text, 100_000)
    min_throughput_ratio = canonical_uint(min_throughput_ratio_text, 100_000)
    max_gap_ms = canonical_uint(max_gap_ms_text, MAX_RELEASE_GAP_MS)
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
    verify_release_policy(baseline_directory, baseline)
    verify_release_policy(candidate_directory, candidate)
    if baseline_identity[0] == candidate_identity[0]:
        raise ValueError("paired runs reused a run UUID")
    if (
        baseline["git_dirty"] != "0" or candidate["git_dirty"] != "0"
        or baseline["git_head"] != candidate["git_head"]
    ):
        raise ValueError("paired runs did not use the same clean git head")
    if (
        baseline["stress_script_sha256"] != candidate["stress_script_sha256"]
        or baseline["evidence_helper_sha256"] != candidate["evidence_helper_sha256"]
        or baseline.get("signed_evidence_helper_sha256", "legacy")
        != candidate.get("signed_evidence_helper_sha256", "legacy")
    ):
        raise ValueError("paired runs used different harness sources")
    if candidate["proxy_attributed"] != "1":
        raise ValueError("candidate traffic is not proxy-attributed")
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
    baseline_metrics = rederived_metrics(baseline_directory, baseline)
    candidate_metrics = rederived_metrics(candidate_directory, candidate)
    class_rows = []
    class_passed = True
    for worker in WORKERS:
        prefix = f"class_{worker}"
        baseline_class_p95 = canonical_uint(baseline_metrics[f"{prefix}_p95_ms"])
        candidate_class_p95 = canonical_uint(candidate_metrics[f"{prefix}_p95_ms"])
        baseline_class_requests = canonical_uint(
            baseline_metrics[f"{prefix}_request_throughput_milli_rps"]
        )
        candidate_class_requests = canonical_uint(
            candidate_metrics[f"{prefix}_request_throughput_milli_rps"]
        )
        baseline_class_bytes = canonical_uint(
            baseline_metrics[f"{prefix}_byte_throughput_bytes_per_second"]
        )
        candidate_class_bytes = canonical_uint(
            candidate_metrics[f"{prefix}_byte_throughput_bytes_per_second"]
        )
        if baseline_class_p95 == 0 or baseline_class_requests == 0:
            raise ValueError(f"baseline {worker} metrics cannot form a ratio")
        class_p95_ratio = (
            candidate_class_p95 * 1000 + baseline_class_p95 - 1
        ) // baseline_class_p95
        class_request_ratio = (
            candidate_class_requests * 1000
        ) // baseline_class_requests
        if worker == "head_only":
            if baseline_class_bytes != 0 or candidate_class_bytes != 0:
                raise ValueError("HEAD byte throughput must remain zero")
            class_byte_ratio = 1000
        else:
            if baseline_class_bytes == 0:
                raise ValueError(f"baseline {worker} byte throughput cannot form a ratio")
            class_byte_ratio = candidate_class_bytes * 1000 // baseline_class_bytes
        class_passed = class_passed and (
            class_p95_ratio <= max_p95_ratio
            and class_request_ratio >= min_throughput_ratio
            and class_byte_ratio >= min_throughput_ratio
        )
        class_rows.extend((
            (f"baseline_{worker}_p95_ms", str(baseline_class_p95)),
            (f"candidate_{worker}_p95_ms", str(candidate_class_p95)),
            (f"observed_{worker}_p95_ratio_milli", str(class_p95_ratio)),
            (f"baseline_{worker}_request_throughput_milli_rps", str(baseline_class_requests)),
            (f"candidate_{worker}_request_throughput_milli_rps", str(candidate_class_requests)),
            (f"observed_{worker}_request_throughput_ratio_milli", str(class_request_ratio)),
            (f"baseline_{worker}_byte_throughput_bytes_per_second", str(baseline_class_bytes)),
            (f"candidate_{worker}_byte_throughput_bytes_per_second", str(candidate_class_bytes)),
            (f"observed_{worker}_byte_throughput_ratio_milli", str(class_byte_ratio)),
        ))
    if not common_envelopes:
        raise ValueError("paired release runs require common signed envelopes")
    passed = (
        p95_ratio <= max_p95_ratio
        and throughput_ratio >= min_throughput_ratio
        and class_passed
    )
    values = [
        ("schema_version", str(SCHEMA_VERSION)),
        ("complete", "1"),
        ("passed", "1" if passed else "0"),
        ("exit_code", "0" if passed else "1"),
        ("evidence_claim", EVIDENCE_CLAIM),
        ("comparison_helper_sha256", comparison_helper_sha256),
        ("workload_identity", baseline["workload_identity"]),
        ("git_head", baseline["git_head"]),
        ("stress_script_sha256", baseline["stress_script_sha256"]),
        ("evidence_helper_sha256", baseline["evidence_helper_sha256"]),
        ("signed_evidence_helper_sha256", baseline.get(
            "signed_evidence_helper_sha256", "legacy"
        )),
        ("baseline_run_uuid", baseline_identity[0]),
        ("baseline_manifest_sha256", baseline_identity[3]),
        ("baseline_status_sha256", sha256_file(baseline_status_path)),
        ("candidate_run_uuid", candidate_identity[0]),
        ("candidate_manifest_sha256", candidate_identity[3]),
        ("candidate_status_sha256", sha256_file(candidate_status_path)),
        ("candidate_provider_build_identity", candidate.get(
            "provider_build_identity", candidate["provider_executable_sha256"]
        )),
        ("candidate_provider_signing_identifier", candidate["provider_signing_identifier"]),
        ("candidate_provider_signing_team", candidate["provider_signing_team"]),
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
    ]
    values.extend(class_rows)
    values.append(("schema_complete", "1"))
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
    if len(pairs) != 3:
        raise ValueError("release series requires exactly three stress pairs")
    max_interpair_gap = canonical_uint(max_interpair_gap_text, MAX_RELEASE_GAP_MS)
    if max_interpair_gap == 0:
        raise ValueError("inter-pair gap must be positive")
    if comparison_helper_sha256 is None:
        comparison_helper_sha256 = sha256_file(current_source_path())

    observed = []
    expected_workload = None
    expected_harness = None
    expected_git_head = None
    expected_provider_build = None
    previous_candidate_end = None
    run_uuids = set()
    candidate_generations = set()
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
            baseline.get("signed_evidence_helper_sha256", "legacy"),
        )
        if expected_harness is None:
            expected_harness = harness
        elif harness != expected_harness:
            raise ValueError("release series used different harness sources")
        if baseline["git_dirty"] != "0" or candidate["git_dirty"] != "0":
            raise ValueError("release series contains a dirty source run")
        pair_heads = (baseline["git_head"], candidate["git_head"])
        if pair_heads[0] != pair_heads[1]:
            raise ValueError("release series pair used different git heads")
        if expected_git_head is None:
            expected_git_head = pair_heads[0]
        elif pair_heads[0] != expected_git_head:
            raise ValueError("release series used different git heads")
        provider_build = (
            candidate.get(
                "provider_build_identity", candidate["provider_executable_sha256"]
            ),
            candidate["provider_signing_identifier"],
            candidate["provider_signing_team"],
        )
        if expected_provider_build is None:
            expected_provider_build = provider_build
        elif provider_build != expected_provider_build:
            raise ValueError("release series used different provider builds or teams")
        candidate_generation = candidate.get("provider_generation_identity", "")
        if (
            len(candidate_generation) != 64
            or any(character not in "0123456789abcdef" for character in candidate_generation)
            or candidate_generation in candidate_generations
        ):
            raise ValueError("release series reused or omitted a candidate provider generation")
        candidate_generations.add(candidate_generation)
        pair_uuids = {
            comparison_values["baseline_run_uuid"],
            comparison_values["candidate_run_uuid"],
        }
        if len(pair_uuids) != 2 or run_uuids.intersection(pair_uuids):
            raise ValueError("release series reused a run UUID")
        run_uuids.update(pair_uuids)
        if canonical_uint(comparison_values["maximum_p95_ratio_milli"]) > 1500:
            raise ValueError("release series weakened the p95 pair gate")
        if canonical_uint(comparison_values["minimum_throughput_ratio_milli"]) < 667:
            raise ValueError("release series weakened the throughput pair gate")
        if canonical_uint(comparison_values["maximum_pair_gap_ms"]) > MAX_RELEASE_GAP_MS:
            raise ValueError("release series weakened the pair timing gate")
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
            "classes": {
                worker: {
                    "p95_ratio": canonical_uint(
                        comparison_values[f"observed_{worker}_p95_ratio_milli"]
                    ),
                    "request_ratio": canonical_uint(
                        comparison_values[
                            f"observed_{worker}_request_throughput_ratio_milli"
                        ]
                    ),
                    "byte_ratio": canonical_uint(
                        comparison_values[
                            f"observed_{worker}_byte_throughput_ratio_milli"
                        ]
                    ),
                }
                for worker in WORKERS
            },
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
        ("signed_evidence_helper_sha256", expected_harness[2]),
        ("git_head", expected_git_head),
        ("provider_build_identity", expected_provider_build[0]),
        ("provider_signing_identifier", expected_provider_build[1]),
        ("provider_signing_team", expected_provider_build[2]),
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
    for worker in WORKERS:
        values.extend((
            (f"worst_{worker}_p95_ratio_milli", str(max(
                pair["classes"][worker]["p95_ratio"] for pair in observed
            ))),
            (f"worst_{worker}_request_throughput_ratio_milli", str(min(
                pair["classes"][worker]["request_ratio"] for pair in observed
            ))),
            (f"worst_{worker}_byte_throughput_ratio_milli", str(min(
                pair["classes"][worker]["byte_ratio"] for pair in observed
            ))),
        ))
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
        for worker in WORKERS:
            values.extend((
                (f"{prefix}_{worker}_p95_ratio_milli", str(
                    pair["classes"][worker]["p95_ratio"]
                )),
                (f"{prefix}_{worker}_request_throughput_ratio_milli", str(
                    pair["classes"][worker]["request_ratio"]
                )),
                (f"{prefix}_{worker}_byte_throughput_ratio_milli", str(
                    pair["classes"][worker]["byte_ratio"]
                )),
            ))
    values.append(("schema_complete", "1"))
    return [f"{key}\t{value}" for key, value in values]


def _series_member_pairs(directory):
    members = directory / SERIES_MEMBERS_NAME
    if members.is_symlink() or not members.is_dir():
        raise ValueError("stress series members directory is missing")
    expected_pair_names = [f"pair-{index:03d}" for index in range(1, 4)]
    if sorted(path.name for path in members.iterdir()) != expected_pair_names:
        raise ValueError("stress series must contain exactly three ordered member pairs")
    pairs = []
    for name in expected_pair_names:
        pair = members / name
        if pair.is_symlink() or not pair.is_dir():
            raise ValueError("stress series member pair is unsafe")
        if sorted(path.name for path in pair.iterdir()) != ["baseline", "candidate"]:
            raise ValueError("stress series member pair is incomplete")
        baseline = pair / "baseline"
        candidate = pair / "candidate"
        signed_run_evidence.verify(baseline, actual_exit_code=0)
        signed_run_evidence.verify(candidate, actual_exit_code=0)
        pairs.append((baseline, candidate))
    return pairs


def _series_internal_pairs(directory):
    members = _series_member_pairs(directory)
    comparisons = directory / SERIES_COMPARISONS_NAME
    if comparisons.is_symlink() or not comparisons.is_dir():
        raise ValueError("stress series comparisons directory is missing")
    expected_names = sorted(
        name
        for index in range(1, 4)
        for name in (
            f"pair-{index:03d}.tsv",
            f"pair-{index:03d}.tsv{SOURCE_COPY_SUFFIX}",
        )
    )
    if sorted(path.name for path in comparisons.iterdir()) != expected_names:
        raise ValueError("stress series comparisons are incomplete")
    return [
        (baseline, candidate, comparisons / f"pair-{index:03d}.tsv")
        for index, (baseline, candidate) in enumerate(members, start=1)
    ]


def _copy_verified_envelope(source, destination):
    source = Path(source)
    if not (source / signed_run_evidence.STATUS_NAME).is_file():
        raise ValueError("stress series members require common signed envelopes")
    signed_run_evidence.verify(source, actual_exit_code=0)
    shutil.copytree(source, destination, symlinks=False)
    signed_run_evidence.verify(destination, actual_exit_code=0)


def _series_claim_rows(directory, rows, run_uuid):
    values = dict(row.split("\t", 1) for row in rows)
    internal_pairs = _series_internal_pairs(directory)
    generations = []
    claims = [
        ("evidence_kind", "stress-series"),
        ("run_uuid", run_uuid),
        ("pair_count", "3"),
    ]
    for index, (baseline, candidate, comparison) in enumerate(
        internal_pairs, start=1
    ):
        baseline_status = read_status(baseline / signed_run_evidence.STATUS_NAME)
        candidate_status = read_status(candidate / signed_run_evidence.STATUS_NAME)
        generations.append(candidate_status["provider_generation_identity"])
        for role, member, status in (
            ("baseline", baseline, baseline_status),
            ("candidate", candidate, candidate_status),
        ):
            manifest_sha = sha256_file(
                member / signed_run_evidence.MANIFEST_NAME
            )
            prefix = f"pair_{index:03d}_{role}"
            claims.extend((
                (f"{prefix}_run_uuid", status["run_uuid"]),
                (f"{prefix}_manifest_sha256", manifest_sha),
            ))
        claims.append((
            f"pair_{index:03d}_comparison_sha256", sha256_file(comparison)
        ))
    generation_hash = hashlib.sha256(
        "".join(f"{identity}\n" for identity in sorted(generations)).encode()
    ).hexdigest()
    claims.extend((
        ("candidate_generation_identities_sha256", generation_hash),
        ("series_artifact_sha256", sha256_file(directory / SERIES_ARTIFACT_NAME)),
        ("comparison_helper_sha256", values["comparison_helper_sha256"]),
        ("workload_identity", values["workload_identity"]),
        ("git_head", values["git_head"]),
        ("provider_build_identity", values["provider_build_identity"]),
        ("provider_signing_identifier", values["provider_signing_identifier"]),
        ("provider_signing_team", values["provider_signing_team"]),
        ("maximum_interpair_gap_ms", values["maximum_interpair_gap_ms"]),
        ("schema_complete", "1"),
    ))
    return claims


def create_series(pairs, destination):
    destination = Path(destination)
    if destination.exists() or destination.is_symlink():
        raise ValueError("stress series destination must not already exist")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination_resolved = destination.resolve()
    for baseline, candidate, _ in pairs:
        for member in (baseline, candidate):
            member_resolved = Path(member).resolve()
            if member_resolved == destination_resolved \
                    or member_resolved in destination_resolved.parents:
                raise ValueError("stress series destination cannot contain a source member")
    _, source_hash = current_source_identity()
    # Verify all mutable inputs before snapshotting them. They are verified
    # again from their copies before the root common manifest is sealed.
    rows = series_rows(pairs, comparison_helper_sha256=source_hash)
    temporary = destination.with_name(
        f".{destination.name}.tmp.{os.getpid()}.{uuid.uuid4().hex}"
    )
    temporary.mkdir()
    try:
        members = temporary / SERIES_MEMBERS_NAME
        comparisons = temporary / SERIES_COMPARISONS_NAME
        members.mkdir()
        comparisons.mkdir()
        for index, (baseline, candidate, comparison) in enumerate(pairs, start=1):
            pair_directory = members / f"pair-{index:03d}"
            pair_directory.mkdir()
            _copy_verified_envelope(baseline, pair_directory / "baseline")
            _copy_verified_envelope(candidate, pair_directory / "candidate")
            comparison_copy = comparisons / f"pair-{index:03d}.tsv"
            shutil.copyfile(comparison, comparison_copy)
            shutil.copyfile(
                comparison_source_path(comparison),
                comparison_source_path(comparison_copy),
            )
        internal_pairs = _series_internal_pairs(temporary)
        rows = series_rows(internal_pairs, comparison_helper_sha256=source_hash)
        series_artifact = temporary / SERIES_ARTIFACT_NAME
        write_artifact_with_source(series_artifact, rows)
        run_uuid = str(uuid.uuid4())
        claim_rows = _series_claim_rows(temporary, rows, run_uuid)
        claims_path = temporary / signed_run_evidence.CLAIMS_NAME
        claims_path.write_text(
            "".join(f"{key}\t{value}\n" for key, value in claim_rows),
            encoding="utf-8",
        )
        values = dict(row.split("\t", 1) for row in rows)
        first_baseline = read_status(
            internal_pairs[0][0] / signed_run_evidence.STATUS_NAME
        )
        last_candidate = read_status(
            internal_pairs[-1][1] / signed_run_evidence.STATUS_NAME
        )
        exit_code = canonical_uint(values["exit_code"], 1)
        status = {
            "complete": "1",
            "passed": values["passed"],
            "exit_code": str(exit_code),
            "evidence_kind": "stress-series",
            "run_uuid": run_uuid,
            "run_start_epoch_ms": first_baseline["run_start_epoch_ms"],
            "run_end_epoch_ms": last_candidate["run_end_epoch_ms"],
            "git_head": values["git_head"],
            "git_dirty": "0",
            "provider_build_identity": values["provider_build_identity"],
            "provider_generation_identity": "multiple",
            "workload_claims_sha256": sha256_file(claims_path),
            "schema_complete": "1",
        }
        (temporary / signed_run_evidence.STATUS_NAME).write_text(
            "".join(
                f"{key}\t{status[key]}\n"
                for key in signed_run_evidence.STATUS_ORDER
            ),
            encoding="utf-8",
        )
        signed_run_evidence.seal(temporary, actual_exit_code=exit_code)
        signed_run_evidence.verify(temporary, actual_exit_code=exit_code)
        verify_series(temporary)
        os.replace(temporary, destination)
        return exit_code
    except BaseException:
        shutil.rmtree(temporary, ignore_errors=True)
        raise


def verify_series(pairs_or_directory, directory=None):
    external_pairs = None if directory is None else pairs_or_directory
    directory = Path(pairs_or_directory if directory is None else directory)
    common_status = signed_run_evidence.verify(directory)
    if common_status["evidence_kind"] != "stress-series":
        raise ValueError("common envelope is not stress-series evidence")
    artifact = directory / SERIES_ARTIFACT_NAME
    values, existing = read_artifact(artifact, "series artifact")
    sealed_source = comparison_source_path(artifact)
    if sealed_source.is_symlink() or not sealed_source.is_file():
        raise ValueError("sealed stress_compare.py series source is missing")
    source_hash = sha256_file(sealed_source)
    if values.get("comparison_helper_sha256") != source_hash:
        raise ValueError("sealed stress_compare.py series source changed")
    if sha256_file(current_source_path()) != source_hash:
        raise ValueError("current stress_compare.py differs from sealed series source")
    internal_pairs = _series_internal_pairs(directory)
    expected = series_rows(
        internal_pairs,
        values.get("maximum_interpair_gap_ms", ""),
        comparison_helper_sha256=source_hash,
    )
    if existing != expected:
        raise ValueError("series artifact does not match its sealed stress pairs")
    claims, claim_rows = read_artifact(
        directory / signed_run_evidence.CLAIMS_NAME, "series workload claims"
    )
    expected_claim_rows = [
        f"{key}\t{value}"
        for key, value in _series_claim_rows(
            directory, expected, common_status["run_uuid"]
        )
    ]
    if claim_rows != expected_claim_rows:
        raise ValueError("series workload claims do not match sealed members")
    if claims["candidate_generation_identities_sha256"] == "":
        raise ValueError("series candidate generations are not bound")
    if external_pairs is not None:
        if len(external_pairs) != len(internal_pairs):
            raise ValueError("external stress pair count does not match the series")
        for external, internal in zip(external_pairs, internal_pairs):
            for external_member, internal_member in zip(external[:2], internal[:2]):
                external_identity = verify_stress_run(external_member)
                internal_identity = verify_stress_run(internal_member)
                if external_identity != internal_identity:
                    raise ValueError("external stress member differs from sealed series copy")
            if sha256_file(external[2]) != sha256_file(internal[2]):
                raise ValueError("external comparison differs from sealed series copy")
    exit_code = canonical_uint(values["exit_code"], 1)
    if common_status["exit_code"] != str(exit_code):
        raise ValueError("series status exit code does not match its verdict")
    return exit_code


def main():
    try:
        if len(sys.argv) >= 3 and sys.argv[1] in ("create-series", "verify-series"):
            command = sys.argv[1]
            series_directory = Path(sys.argv[2])
            pair_args = sys.argv[3:]
            if command == "create-series" and len(pair_args) != 9:
                raise ValueError(
                    "series usage requires exactly three BASELINE CANDIDATE COMPARISON triples"
                )
            if command == "verify-series" and pair_args and len(pair_args) != 9:
                raise ValueError(
                    "optional verification inputs require exactly three stress pair triples"
                )
            pairs = [
                tuple(Path(value) for value in pair_args[index:index + 3])
                for index in range(0, len(pair_args), 3)
            ]
            exit_code = (
                create_series(pairs, series_directory)
                if command == "create-series"
                else verify_series(pairs, series_directory) if pairs
                else verify_series(series_directory)
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
                "[MAX_P95_RATIO_MILLI MIN_THROUGHPUT_RATIO_MILLI MAX_GAP_MS]; "
                "or <create-series|verify-series> SERIES_DIRECTORY "
                "[BASELINE CANDIDATE COMPARISON ...]"
            )
    except (OSError, UnicodeError, ValueError) as error:
        print(f"stress comparison failed: {error}", file=sys.stderr)
        raise SystemExit(2)
    raise SystemExit(exit_code)


if __name__ == "__main__":
    main()
