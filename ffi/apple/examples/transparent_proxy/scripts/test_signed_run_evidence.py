#!/usr/bin/env python3

import hashlib
from datetime import datetime, timezone
import io
import json
import os
from pathlib import Path
import plistlib
import subprocess
import sys
import tarfile
import tempfile
import textwrap
import time
import unittest
import uuid
from unittest import mock

import signed_run_evidence as evidence


HEAD = "a" * 40
CDHASH = "b" * 40
EXECUTABLE_HASH = "c" * 64


def current_script_source(_head, repository_relative_path):
    return (Path(__file__).resolve().parent / Path(repository_relative_path).name).read_bytes()


def write_tsv(path: Path, rows):
    path.write_text(
        "".join(f"{key}\t{value}\n" for key, value in rows),
        encoding="utf-8",
    )


def write_empty_crash_snapshot(directory: Path, status, process_name="provider"):
    crashes = directory / "crashes"
    crashes.mkdir(exist_ok=True)
    rows = [
        ("schema_version", str(evidence.CRASH_SCHEMA_VERSION)),
        ("run_uuid", status["run_uuid"]),
        ("provider_generation_identity", status["provider_generation_identity"]),
        ("since_epoch_ms", status["run_start_epoch_ms"]),
        ("snapshot_epoch_ms", status["run_end_epoch_ms"]),
        ("process_names", process_name),
        ("crash_count", "0"),
        ("crash_names_sha256", hashlib.sha256(b"").hexdigest()),
        ("schema_complete", "1"),
    ]
    write_tsv(crashes / "crash-snapshot.tsv", rows)


def write_generation_samples(directory: Path, status):
    identity = evidence.read_provider_identity(directory / evidence.PROVIDER_IDENTITY_NAME)
    start = int(status["run_start_epoch_ms"])
    end = int(status["run_end_epoch_ms"])
    path_hash = hashlib.sha256(identity["running_executable_path"].encode()).hexdigest()
    tail = "|".join((
        identity["running_pid"], identity["running_start_epoch_ms"],
        identity["running_start_epoch_us"], identity["running_dynamic_cdhash"],
        identity["running_command_sha256"], path_hash,
    ))
    rows = [
        ("schema_version", "1"),
        ("provider_generation_identity", status["provider_generation_identity"]),
        ("running_pid", identity["running_pid"]),
        ("running_start_epoch_ms", identity["running_start_epoch_ms"]),
        ("running_start_epoch_us", identity["running_start_epoch_us"]),
        ("running_dynamic_cdhash", identity["running_dynamic_cdhash"]),
        ("running_command_sha256", identity["running_command_sha256"]),
        ("running_executable_path_sha256", path_hash),
        ("cadence_ms", "2000"),
        ("max_gap_ms", "5000"),
        ("sample_count", "3"),
        ("sample_000001", f"{start}|{tail}"),
        ("sample_000002", f"{start + (end - start) // 2}|{tail}"),
        ("sample_000003", f"{end}|{tail}"),
        ("schema_complete", "1"),
    ]
    write_tsv(directory / evidence.GENERATION_SAMPLES_NAME, rows)


def write_identity(
    directory: Path,
    *,
    head=HEAD,
    dirty="0",
    executable_hash=EXECUTABLE_HASH,
    cdhash=CDHASH,
    pid=42,
    start=1_700_000_000_000,
    command="/Library/SystemExtensions/provider",
):
    build = evidence.provider_build_identity(
        evidence.DEV_PROVIDER_BUNDLE_ID,
        head,
        evidence.DEV_TEAM_ID,
        cdhash,
        executable_hash,
    )
    command_hash = hashlib.sha256(command.encode()).hexdigest()
    generation = evidence.provider_generation_identity(pid, start, command_hash)
    values = {
        "schema_version": "1",
        "expected_bundle_id": evidence.DEV_PROVIDER_BUNDLE_ID,
        "expected_team_id": evidence.DEV_TEAM_ID,
        "source_git_head": head,
        "source_git_dirty": dirty,
        "running_pid": str(pid),
        "running_start_epoch_ms": str(start),
        "running_start_epoch_us": str(start * 1000),
        "running_dynamic_cdhash": cdhash,
        "running_command": command,
        "running_command_sha256": command_hash,
        "provider_build_identity": build,
        "provider_generation_identity": generation,
        "schema_complete": "1",
    }
    for role in ("built", "installed", "running"):
        values.update({
            f"{role}_bundle_id": evidence.DEV_PROVIDER_BUNDLE_ID,
            f"{role}_git_head": head,
            f"{role}_git_dirty": dirty,
            f"{role}_team_id": evidence.DEV_TEAM_ID,
            f"{role}_cdhash": cdhash,
            f"{role}_executable_sha256": executable_hash,
            f"{role}_bundle_version": "123",
            f"{role}_bundle_path": f"/fixture/{role}/provider.systemextension",
            f"{role}_executable_path": f"/fixture/{role}/provider",
            f"{role}_build_identity": build,
        })
    write_tsv(
        directory / evidence.PROVIDER_IDENTITY_NAME,
        ((key, values[key]) for key in evidence.PROVIDER_IDENTITY_ORDER),
    )
    return build, generation


def make_run(
    directory: Path,
    kind: str,
    *,
    claims=None,
    executable_hash=EXECUTABLE_HASH,
    cdhash=CDHASH,
    outcome=("1", "1", "0"),
    pid=42,
    process_start=1_700_000_000_000,
    command="/Library/SystemExtensions/provider",
    crash_snapshot=True,
):
    directory.mkdir()
    build, generation = write_identity(
        directory,
        executable_hash=executable_hash,
        cdhash=cdhash,
        pid=pid,
        start=process_start,
        command=command,
    )
    run_uuid = str(uuid.uuid4())
    if claims is None:
        claims = []
    claim_rows = [
        ("evidence_kind", kind),
        ("run_uuid", run_uuid),
        *claims,
        ("schema_complete", "1"),
    ]
    write_tsv(directory / evidence.CLAIMS_NAME, claim_rows)
    claims_hash = evidence.sha256_file(directory / evidence.CLAIMS_NAME)
    values = dict(zip(("complete", "passed", "exit_code"), outcome))
    values.update({
        "evidence_kind": kind,
        "run_uuid": run_uuid,
        "run_start_epoch_ms": "1700000001000",
        "run_end_epoch_ms": "1700000002000",
        "git_head": HEAD,
        "git_dirty": "0",
        "provider_build_identity": build,
        "provider_generation_identity": generation,
        "workload_claims_sha256": claims_hash,
        "schema_complete": "1",
    })
    write_tsv(
        directory / evidence.STATUS_NAME,
        ((key, values[key]) for key in evidence.STATUS_ORDER),
    )
    if crash_snapshot and kind in {"modern_udp", "soak", "stress-candidate"}:
        write_empty_crash_snapshot(directory, values)
    if kind in {"modern_udp", "soak", "stress-candidate"}:
        write_generation_samples(directory, values)
    nested = directory / "logs" / "nested"
    nested.mkdir(parents=True)
    (nested / "empty.log").write_bytes(b"")
    (nested / "run.log").write_text("terminal output\n", encoding="utf-8")
    return values


def make_sleep_soak_run(directory: Path, *, sleep_seconds=45, pre_gap_ms=0, post_gap_ms=0):
    status = make_run(directory, "soak")
    identity = evidence.read_provider_identity(directory / evidence.PROVIDER_IDENTITY_NAME)
    base = 1_700_000_000_000
    sleep = base + 15_000
    wake = sleep + sleep_seconds * 1000
    end = wake + post_gap_ms + 2000
    status["run_end_epoch_ms"] = str(end)
    write_tsv(directory / evidence.STATUS_NAME, ((key, status[key]) for key in evidence.STATUS_ORDER))
    write_empty_crash_snapshot(directory, status)
    samples, rows = evidence._parse_tsv_bytes((directory / evidence.GENERATION_SAMPLES_NAME).read_bytes())
    tail = rows[len(evidence.GENERATION_FIXED_ORDER)][1].split("|", 1)[1]
    epochs = [*range(base + 1000, sleep - pre_gap_ms, 2000), sleep - pre_gap_ms,
              wake + post_gap_ms, end]
    samples["sample_count"] = str(len(epochs))
    write_tsv(directory / evidence.GENERATION_SAMPLES_NAME, [
        *((key, samples[key]) for key in evidence.GENERATION_FIXED_ORDER),
        *((f"sample_{index:06d}", f"{epoch}|{tail}") for index, epoch in enumerate(epochs, 1)),
        ("schema_complete", "1"),
    ])
    def epoch_text(ms):
        return f"{ms // 1000}.{ms % 1000:03d}000"
    def iso(ms):
        return datetime.fromtimestamp(ms / 1000, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    meta = {
        "run_uuid": status["run_uuid"], "run_start_epoch_ms": status["run_start_epoch_ms"],
        "run_end_epoch_ms": str(end), "provider_start_pid": "42",
        "provider_bundle": evidence.DEV_PROVIDER_BUNDLE_ID,
        "provider_executable": identity["running_executable_path"],
        "provider_binary_sha256": identity["running_executable_sha256"],
        "provider_codesign_identifier": identity["running_bundle_id"],
        "provider_codesign_cdhash": identity["running_cdhash"],
        "provider_codesign_team": identity["running_team_id"],
        "provider_start_identity": identity["provider_generation_identity"],
        "provider_executable_name": Path(identity["running_executable_path"]).name,
        "crash_process_name": Path(identity["running_executable_path"]).name,
        "common_provider_generation_identity": status["provider_generation_identity"],
        "sleep_command_ok": "1", "post_wake_ok": "1",
        "sleep_command_start": epoch_text(base + 14000),
        # A successful pmset invocation may return before actual system sleep.
        "sleep_command_end": epoch_text(base + 14100),
        "wake_workload_started": epoch_text(base + 11000),
        "wake_workload_established": epoch_text(base + 12000),
        "wake_workload_http_code": "200", "wake_workload_alive_at_sleep_command": "1",
        "wake_workload_established_nonzero_bytes": "1", "wake_workload_established_bytes": "64",
        "wake_workload_joined": "1", "wake_workload_child_rc": "143",
    }
    write_tsv(directory / "run-meta.tsv", meta.items())
    (directory / "wake-download-headers.txt").write_bytes(b"HTTP/2 200\r\n\r\n")
    (directory / "wake-download.body").write_bytes(b"x" * 64)
    (directory / "wake-download.txt").write_bytes(b"")
    (directory / "phases.tsv").write_text(
        f"sleep-wake\tstart\t{epoch_text(base + 10000)}\t{iso(base + 10000)}\n"
        f"sleep-wake\tend\t{epoch_text(end)}\t{iso(end)}\n"
    )
    (directory / "system.ndjson").write_text("".join(json.dumps({
        "timestamp": datetime.fromtimestamp(epoch / 1000, timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f%z"),
        "processID": 42, "subsystem": evidence.DEV_PROVIDER_BUNDLE_ID,
        "category": "lifecycle", "eventMessage": message,
    }) + "\n" for epoch, message in ((sleep, "system sleep"), (wake, "system wake"))))
    (directory / "sleep-probes.tsv").write_text(
        f"{epoch_text(wake + 10)}\t{epoch_text(wake + 1000)}\t{iso(wake + 1000)}\t0\t200\n"
    )
    return status


def make_direct_run(directory: Path, *, start=1000, end=2000):
    directory.mkdir()
    run_uuid = str(uuid.uuid4())
    claims = [
        ("evidence_kind", "stress-direct"),
        ("run_uuid", run_uuid),
        ("provider_absent", "1"),
        ("schema_complete", "1"),
    ]
    write_tsv(directory / evidence.CLAIMS_NAME, claims)
    values = {
        "complete": "1", "passed": "1", "exit_code": "0",
        "evidence_kind": "stress-direct", "run_uuid": run_uuid,
        "run_start_epoch_ms": str(start), "run_end_epoch_ms": str(end),
        "git_head": HEAD, "git_dirty": "0",
        "provider_build_identity": "absent",
        "provider_generation_identity": "absent",
        "workload_claims_sha256": evidence.sha256_file(directory / evidence.CLAIMS_NAME),
        "schema_complete": "1",
    }
    write_tsv(
        directory / evidence.STATUS_NAME,
        ((key, values[key]) for key in evidence.STATUS_ORDER),
    )
    absence_rows = [
        ("schema_version", "1"),
        ("bundle_id", evidence.DEV_PROVIDER_BUNDLE_ID),
        ("cadence_ms", "1000"),
        ("max_gap_ms", "2500"),
        ("sample_count", "2"),
        ("sample_000001", f"{start}|0|none"),
        ("sample_000002", f"{end}|0|none"),
        ("schema_complete", "1"),
    ]
    write_tsv(directory / evidence.ABSENCE_NAME, absence_rows)
    write_empty_crash_snapshot(
        directory, values, evidence.DEV_PROVIDER_BUNDLE_ID
    )
    return values


def make_stress_series(directory: Path):
    candidate_statuses = []
    for pair in range(1, 4):
        pair_dir = directory / "members" / f"pair-{pair:03d}"
        baseline = pair_dir / "baseline"
        candidate = pair_dir / "candidate"
        baseline.parent.mkdir(parents=True, exist_ok=True)
        make_direct_run(baseline, start=1000, end=2000)
        candidate_statuses.append(make_run(
            candidate,
            "stress-candidate",
            pid=40 + pair,
            process_start=1_700_000_000_000 + pair * 100,
        ))
        evidence.seal(baseline)
        evidence.seal(candidate)
    generations = sorted(
        status["provider_generation_identity"]
        for status in candidate_statuses
    )
    generation_hash = hashlib.sha256(
        "".join(f"{generation}\n" for generation in generations).encode()
    ).hexdigest()
    run_uuid = str(uuid.uuid4())
    claims = [
        ("evidence_kind", "stress-series"),
        ("run_uuid", run_uuid),
        ("pair_count", "3"),
        ("candidate_generation_identities_sha256", generation_hash),
        ("schema_complete", "1"),
    ]
    write_tsv(directory / evidence.CLAIMS_NAME, claims)
    values = {
        "complete": "1", "passed": "1", "exit_code": "0",
        "evidence_kind": "stress-series", "run_uuid": run_uuid,
        "run_start_epoch_ms": "1000",
        "run_end_epoch_ms": "1700000002000",
        "git_head": HEAD, "git_dirty": "0",
        "provider_build_identity": candidate_statuses[0]["provider_build_identity"],
        "provider_generation_identity": "multiple",
        "workload_claims_sha256": evidence.sha256_file(
            directory / evidence.CLAIMS_NAME
        ),
        "schema_complete": "1",
    }
    write_tsv(
        directory / evidence.STATUS_NAME,
        ((key, values[key]) for key in evidence.STATUS_ORDER),
    )
    return values


def make_strict_modern_run(directory: Path):
    from modern_udp_evidence import PRODUCER_SOURCE_NAMES, producer_sources_sha256
    from test_modern_udp_evidence import passing_status

    common = make_run(directory, "modern_udp")
    udp_rows = [tuple(line.rstrip("\n").split("\t", 1)) for line in passing_status()]
    udp = dict(udp_rows)
    pressure_defaults = (
        ("echo_source_pid", "3000"),
        ("pressure_datagram_count", "64"),
        ("pressure_payload_bytes", "1200"),
        ("pressure_expected_bytes", "76800"),
    )
    if "pressure_datagram_count" not in udp:
        schema_index = next(
            index for index, (key, _) in enumerate(udp_rows)
            if key == "schema_version"
        )
        udp_rows[schema_index:schema_index] = list(pressure_defaults)
        udp.update(pressure_defaults)
    udp.update({
        "run_uuid": common["run_uuid"],
        "run_start_epoch_ms": common["run_start_epoch_ms"],
        "run_end_epoch_ms": common["run_end_epoch_ms"],
        "provider_pid": "42",
        "provider_identity": common["provider_generation_identity"],
        "provider_generation_identity": common["provider_generation_identity"],
        "schema_version": "5",
    })
    script_directory = Path(__file__).resolve().parent
    source_paths = {
        "source-test_modern_udp_flow.sh": "test_modern_udp_flow.sh",
        "source-modern_udp_e2e_probe.py": "modern_udp_e2e_probe.py",
        "source-install_tproxy_app_bundle.sh": "install_tproxy_app_bundle.sh",
        "source-modern_udp_evidence.py": "modern_udp_evidence.py",
        "source-soak_pressure_log.py": "soak_pressure_log.py",
        "source-signed_run_evidence.py": "signed_run_evidence.py",
    }
    assert set(source_paths) == set(PRODUCER_SOURCE_NAMES)
    for artifact_name, source_name in source_paths.items():
        (directory / artifact_name).write_bytes((script_directory / source_name).read_bytes())
    udp["producer_sources_sha256"] = producer_sources_sha256(directory)
    write_tsv(
        directory / "udp-evidence-status.tsv",
        ((key, udp[key]) for key, _ in udp_rows),
    )
    claims = [
        ("evidence_kind", "modern_udp"),
        ("run_uuid", common["run_uuid"]),
        ("dial9_diagnostic_only", "0"),
        ("dial9_workload_coverage", "1"),
        ("dial9_claim", "exact-workload"),
        ("quic_shaped_not_valid_quic", "1"),
        ("echo_socket_count", udp["echo_socket_count"]),
        ("echo_exact_echo_count", udp["echo_exact_echo_count"]),
        ("http3_request_count", udp["http3_request_count"]),
        ("http3_pass_count", udp["http3_pass_count"]),
        ("dial9_requirement_count", udp["dial9_requirement_count"]),
        ("dial9_matched_requirement_count", udp["dial9_matched_requirement_count"]),
        ("producer_sources_sha256", udp["producer_sources_sha256"]),
        ("schema_complete", "1"),
    ]
    write_tsv(directory / evidence.CLAIMS_NAME, claims)
    common["workload_claims_sha256"] = evidence.sha256_file(
        directory / evidence.CLAIMS_NAME
    )
    write_tsv(
        directory / evidence.STATUS_NAME,
        ((key, common[key]) for key in evidence.STATUS_ORDER),
    )

    expected = int(udp["echo_expected_count"])
    digest = udp["echo_payload_set_sha256"]
    echo_common = {
        "schema_version": 1,
        "run_uuid": common["run_uuid"],
        "endpoint": udp["echo_endpoint"],
        "expected_count": expected,
        "passed": True,
        "schema_complete": True,
    }
    client = dict(echo_common, **{
        "kind": "controlled_echo_client",
        "interval_ms": 0,
        "start_epoch_ms": int(common["run_start_epoch_ms"]),
        "end_epoch_ms": int(common["run_start_epoch_ms"]) + 1,
        "start_monotonic_ns": 1000000000,
        "end_monotonic_ns": 1001000000,
        "packet_timings_ns": [
            [index, sequence, 1000000000, 1000000000]
            for index in range(int(udp["echo_socket_count"]))
            for sequence in range(int(udp["echo_datagrams_per_socket"]))
        ],
        "socket_count": int(udp["echo_socket_count"]),
        "datagrams_per_socket": int(udp["echo_datagrams_per_socket"]),
        "payload_bytes": int(udp["echo_payload_bytes"]),
        "sent_count": expected,
        "received_count": expected,
        "exact_echo_count": expected,
        "unique_echo_count": expected,
        "independent_socket_count": int(udp["echo_socket_count"]),
        "local_endpoints": [
            f"127.0.0.1:{30000 + index}"
            for index in range(int(udp["echo_socket_count"]))
        ],
        "payload_set_sha256": digest,
        "echo_set_sha256": digest,
        "error_count": 0,
    })
    client["local_endpoint_set_sha256"] = hashlib.sha256(
        "\n".join(client["local_endpoints"]).encode()
    ).hexdigest()
    server = dict(echo_common, **{
        "kind": "controlled_echo_server",
        "received_count": expected,
        "echo_count": expected,
        "duplicate_count": 0,
        "malformed_count": 0,
        "payload_set_sha256": digest,
    })
    (directory / "controlled-echo-client.json").write_text(json.dumps(client))
    (directory / "controlled-echo-server.json").write_text(json.dumps(server))
    (directory / "echo-identities.tsv").write_text("".join(
        f"7\t{200 + index}\t{client['local_endpoints'][index]}\n"
        for index in range(int(udp["echo_flow_count"]))
    ))

    header = [
        "label", "provider_pid", "provider_generation", "flow_id", "protocol",
        "source_pid", "close_reason", "min_bytes_in", "max_bytes_in",
        "min_bytes_out", "max_bytes_out",
    ]
    requirement_rows = []
    specific = {
        "ntp": (udp["ntp_flow_id"], udp["ntp_source_pid"]),
        "pressure": (udp["pressure_flow_id"], udp["pressure_source_pid"]),
        "recovery-ntp": (
            udp["recovery_ntp_flow_id"], udp["recovery_ntp_source_pid"]
        ),
    }
    for label, (flow_id, source_pid) in specific.items():
        bounds = ["0", "65535", "0", "65535"]
        if label == "pressure":
            payload = int(udp["pressure_payload_bytes"])
            bounds = [str(payload), str(int(udp["pressure_expected_bytes"]) - payload), "0", "0"]
        requirement_rows.append([
            label, "42", "7", flow_id, "2", source_pid, "1",
            *bounds,
        ])
    echo_bytes = str(
        int(udp["echo_datagrams_per_socket"]) * int(udp["echo_payload_bytes"])
    )
    for index in range(int(udp["echo_flow_count"])):
        requirement_rows.append([
            f"echo-{index}", "42", "7", str(200 + index), "2",
            udp["echo_source_pid"], "1",
            echo_bytes, echo_bytes, echo_bytes, echo_bytes,
        ])
    requirements_content = (
        "\t".join(header) + "\n"
        + "".join("\t".join(row) + "\n" for row in requirement_rows)
    )
    (directory / "dial9-requirements.tsv").write_text(requirements_content)
    requirements_digest = hashlib.sha256(requirements_content.encode()).hexdigest()
    udp["dial9_requirements_sha256"] = requirements_digest
    write_tsv(
        directory / "udp-evidence-status.tsv",
        ((key, udp[key]) for key, _ in udp_rows),
    )
    self_rows = [dict(zip(header, row)) for row in requirement_rows]
    flows = []
    for row in self_rows:
        flows.append({
            **{
                key: int(row[key]) for key in (
                    "provider_pid", "provider_generation", "flow_id", "protocol",
                    "source_pid", "close_reason",
                )
            },
            "label": row["label"],
            # Model exactly one dropped pressure packet from the once-only burst.
            "bytes_in": int(row["max_bytes_in"] if row["label"] == "pressure" else row["min_bytes_in"]),
            "bytes_out": int(row["min_bytes_out"]),
            "close_reason_name": "shutdown",
            "close_age_ms": 0,
        })
    trace = b"strict-modern-dial9-trace"
    traces = directory / "dial9-traces"
    traces.mkdir()
    (traces / "trace.8.bin").write_bytes(trace)
    (directory / "dial9-baseline.json").write_text(json.dumps({"max_index": 7}))
    (directory / "dial9-evidence.json").write_text(json.dumps({
        "schema_version": 1,
        "schema_complete": True,
        "baseline_max_index": 7,
        "requirements_sha256": requirements_digest,
        "requirement_count": len(requirement_rows),
        "matched_requirement_count": len(requirement_rows),
        "required_pair_count": len(requirement_rows),
        "required_flows": flows,
        "current_segment_count": 1,
        "current_indices": [8],
        "artifacts": [{
            "name": "trace.8.bin", "index": 8, "state": "sealed",
            "encoding": "raw", "size": len(trace),
            "sha256": hashlib.sha256(trace).hexdigest(),
        }],
    }))
    return common


class ManifestTests(unittest.TestCase):
    def test_seal_publication_stays_on_pinned_root_after_path_swap(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = base / "run"
            other = base / "other"
            detached = base / "detached"
            make_run(root, "candidate")
            other.mkdir()
            marker = other / evidence.MANIFEST_NAME
            marker.write_bytes(b"unrelated manifest\n")
            original_publish = evidence._write_atomic_at

            def swap_before_publish(directory_fd, name, content):
                root.rename(detached)
                root.symlink_to(other, target_is_directory=True)
                original_publish(directory_fd, name, content)

            with mock.patch.object(evidence, "_write_atomic_at", swap_before_publish):
                with self.assertRaisesRegex(evidence.EvidenceError, "root changed"):
                    evidence.seal(root)
            self.assertEqual(marker.read_bytes(), b"unrelated manifest\n")
            self.assertTrue((detached / evidence.MANIFEST_NAME).is_file())
            self.assertFalse(list(detached.glob("*.tmp.*")))

    def test_pinned_decoder_build_protects_source_but_keeps_sibling_target_writable(self):
        archive = io.BytesIO()
        source_name = "ffi/apple/examples/transparent_proxy/tproxy_rs/Cargo.toml"
        source_bytes = b"pinned decoder source\n"
        with tarfile.open(fileobj=archive, mode="w") as output:
            member = tarfile.TarInfo(source_name)
            member.size = len(source_bytes)
            member.mode = 0o644
            output.addfile(member, io.BytesIO(source_bytes))
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            cargo_called = False

            def fake_run(command, **kwargs):
                nonlocal cargo_called
                if command[0] == "git":
                    self.assertIn("archive", command)
                    self.assertEqual(command[-1], HEAD)
                    return subprocess.CompletedProcess(command, 0, archive.getvalue(), b"")
                cargo_called = True
                self.assertEqual(command[1:5], ["build", "--locked", "--offline", "--manifest-path"])
                manifest = Path(command[5])
                self.assertEqual(manifest.read_bytes(), source_bytes)
                target = Path(kwargs["env"]["CARGO_TARGET_DIR"])
                self.assertEqual(target, work / "cargo-target")
                replacement = target / "replacement"
                replacement.write_bytes(b"different source\n")
                with self.assertRaises(PermissionError):
                    manifest.write_bytes(b"different source\n")
                with self.assertRaises(PermissionError):
                    replacement.replace(manifest)
                with self.assertRaises(PermissionError):
                    manifest.parent.rename(manifest.parent.with_name("changed-crate"))
                with self.assertRaises(PermissionError):
                    (work / "source").rename(work / "changed-source")
                binary = target / "debug/dial9_evidence"
                binary.parent.mkdir()
                binary.write_text("#!/bin/sh\nexit 0\n")
                binary.chmod(0o755)
                return subprocess.CompletedProcess(command, 0, "", "")

            git_results = [
                subprocess.CompletedProcess([], 0, str(work), ""),
                subprocess.CompletedProcess([], 0, HEAD, ""),
                subprocess.CompletedProcess([], 0, "", ""),
            ]
            with mock.patch.object(evidence, "_run", side_effect=git_results), \
                mock.patch.object(evidence.subprocess, "run", side_effect=fake_run), \
                mock.patch.object(evidence.shutil, "which", return_value="/fixture/cargo"):
                binary = evidence._build_pinned_dial9_binary(HEAD, work)
            self.assertTrue(cargo_called)
            self.assertTrue(os.access(binary, os.X_OK))
            self.assertEqual((work / "source" / source_name).read_bytes(), source_bytes)
            (work / "post-build-output").write_text("parent mode restored\n")

    def test_direct_read_rejects_replaced_and_restored_path(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifact = root / "artifact"
            replacement = root / "replacement"
            detached = root / "detached"
            artifact.write_bytes(b"original")
            replacement.write_bytes(b"substituted")
            original_open = os.open

            def swapped_open(path, flags, *args, **kwargs):
                if Path(path) != artifact:
                    return original_open(path, flags, *args, **kwargs)
                artifact.rename(detached)
                replacement.rename(artifact)
                descriptor = original_open(path, flags, *args, **kwargs)
                artifact.rename(replacement)
                detached.rename(artifact)
                return descriptor

            with mock.patch.object(evidence.os, "open", side_effect=swapped_open):
                with self.assertRaisesRegex(evidence.EvidenceError, "changed while reading"):
                    evidence._read_regular_bytes(artifact)
            self.assertEqual(artifact.read_bytes(), b"original")

    def test_root_or_parent_swap_before_open_cannot_select_another_envelope(self):
        for swap_parent in (False, True):
            with self.subTest(swap_parent=swap_parent), tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary)
                parent = base / "requested-parent"
                other_parent = base / "other-parent"
                parent.mkdir()
                other_parent.mkdir()
                root = parent / "run"
                other = other_parent / "run"
                make_run(root, "candidate", outcome=("1", "0", "1"))
                make_run(other, "candidate")
                evidence.seal(root)
                evidence.seal(other)
                original_lstat = Path.lstat
                swapped = False

                def swap_after_root_stat(path, *args, **kwargs):
                    nonlocal swapped
                    result = original_lstat(path, *args, **kwargs)
                    if path == root and not swapped:
                        swapped = True
                        source = parent if swap_parent else root
                        target = other_parent if swap_parent else other
                        source.rename(base / "detached")
                        source.symlink_to(target, target_is_directory=True)
                    return result

                with mock.patch.object(Path, "lstat", swap_after_root_stat):
                    with self.assertRaises(evidence.EvidenceError):
                        evidence.verify(root)
                self.assertTrue(swapped)

    def test_signed_builds_reject_tracked_source_mutation_during_build(self):
        source_scripts = Path(__file__).resolve().parent
        for wrapper_name, spec_name in (
            ("build_tproxy_app_with_signing.sh", "Project.yml"),
            ("build_tproxy_app_with_developer_id_signing.sh", "Project.dist.yml"),
        ):
            with self.subTest(wrapper=wrapper_name), tempfile.TemporaryDirectory() as temporary:
                fixture = Path(temporary)
                script_dir = fixture / "ffi/apple/examples/transparent_proxy/scripts"
                app_dir = fixture / "ffi/apple/examples/transparent_proxy/tproxy_app"
                rust_dir = fixture / "ffi/apple/examples/transparent_proxy/tproxy_rs"
                tools = fixture / "tools"
                script_dir.mkdir(parents=True)
                app_dir.mkdir()
                rust_dir.mkdir()
                tools.mkdir()
                wrapper = script_dir / wrapper_name
                wrapper.write_bytes((source_scripts / wrapper_name).read_bytes())
                wrapper.chmod(0o755)
                (app_dir / spec_name).write_text("name: fixture\n")
                (rust_dir / "sentinel.txt").write_text("authenticated source\n")
                (fixture / "Cargo.toml").write_text(
                    '[workspace]\nmembers = []\n[workspace.package]\nversion = "1.0.0"\n'
                )
                mutation_result = fixture / "mutation-result"
                cargo = tools / "cargo"
                cargo.write_text(
                    "#!/bin/sh\n"
                    "if printf 'mutated source\\n' > \"$PWD/sentinel.txt\" 2>/dev/null; then\n"
                    "  printf bad > \"$MUTATION_RESULT\"\n"
                    "else\n"
                    "  printf blocked > \"$MUTATION_RESULT\"\n"
                    "fi\n"
                    "exit 77\n"
                )
                cargo.chmod(0o755)
                xcodegen = tools / "xcodegen"
                xcodegen.write_text(
                    '#!/bin/sh\nmkdir -p "$(dirname "$3")/RamaTransparentProxyExample.xcodeproj"\n'
                )
                xcodegen.chmod(0o755)
                subprocess.run(
                    ["git", "init", "-q", str(fixture)], check=True,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                )
                subprocess.run(
                    ["git", "-C", str(fixture), "config", "user.email", "fixture@example.invalid"],
                    check=True,
                )
                subprocess.run(
                    ["git", "-C", str(fixture), "config", "user.name", "Fixture"],
                    check=True,
                )
                subprocess.run(
                    ["git", "-C", str(fixture), "config", "commit.gpgSign", "false"],
                    check=True,
                )
                subprocess.run(
                    ["git", "-C", str(fixture), "add", "."], check=True,
                )
                subprocess.run(
                    ["git", "-C", str(fixture), "commit", "-qm", "fixture"], check=True,
                )
                self.assertEqual(
                    subprocess.run(
                        ["git", "-C", str(fixture), "status", "--porcelain=v1", "--untracked-files=normal"],
                        check=True, stdout=subprocess.PIPE, text=True,
                    ).stdout,
                    "",
                )
                result = subprocess.run(
                    [str(wrapper)],
                    check=False,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    env={
                        **os.environ,
                        "PATH": str(tools) + os.pathsep + os.environ["PATH"],
                        "MUTATION_RESULT": str(mutation_result),
                    },
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(mutation_result.read_text(), "blocked")

    def test_signed_build_composition_protects_source_and_exports_pinned_decoder(self):
        source_scripts = Path(__file__).resolve().parent
        for wrapper_name, spec_name, configuration in (
            ("build_tproxy_app_with_signing.sh", "Project.yml", "Debug"),
            ("build_tproxy_app_with_developer_id_signing.sh", "Project.dist.yml", "Release"),
        ):
            with self.subTest(wrapper=wrapper_name), tempfile.TemporaryDirectory() as temporary:
                fixture = Path(temporary)
                example = fixture / "ffi/apple/examples/transparent_proxy"
                scripts = example / "scripts"
                app = example / "tproxy_app"
                rust = example / "tproxy_rs"
                tools = fixture / "tools"
                output = fixture / "fixture-output"
                for path in (scripts, app, rust, tools, output):
                    path.mkdir(parents=True)
                wrapper = scripts / wrapper_name
                # Keep the production lipo path fixed; replace only that native
                # binary in this copied wrapper so the test performs no build.
                wrapper.write_text((source_scripts / wrapper_name).read_text().replace(
                    "/usr/bin/lipo", str(tools / "lipo")
                ))
                wrapper.chmod(0o755)
                (fixture / ".gitignore").write_text("fixture-output/\ntarget/\n.xcode-derived/\n")
                (fixture / "Cargo.toml").write_text(
                    '[workspace]\nmembers = []\n[workspace.package]\nversion = "1.0.0"\n'
                )
                (app / spec_name).write_text("name: RamaTransparentProxyExample\n")
                (rust / "sentinel.txt").write_text("pinned source\n")
                tool_program = textwrap.dedent('''\
                    import json, os, sys
                    from pathlib import Path
                    name = Path(sys.argv[0]).name
                    args = sys.argv[1:]
                    cwd = Path.cwd()
                    with Path(os.environ["BUILD_TRACE"]).open("a") as trace:
                        trace.write(json.dumps([name, str(cwd), args]) + "\\n")
                    if name == "xcodegen":
                        project = Path(args[2]).parent / "RamaTransparentProxyExample.xcodeproj"
                        project.mkdir()
                        (project / "project.pbxproj").write_text("generated project\\n")
                    elif name == "cargo":
                        assert args[:3] == ["build", "--locked", "--target"], args
                        target = Path(os.environ["CARGO_TARGET_DIR"]) / args[3] / "debug"
                        target.mkdir(parents=True)
                        (target / "librama_tproxy_example.a").write_text(args[3])
                        binary = target / "dial9_evidence"
                        binary.write_text("#!/bin/sh\\nexit 0\\n")
                        binary.chmod(0o755)
                        replacement = target / "replacement"
                        replacement.write_text("substituted source\\n")
                        source = cwd.parents[4]
                        attempts = [
                            lambda: (cwd / "sentinel.txt").write_text("mutated\\n"),
                            lambda: replacement.replace(cwd / "sentinel.txt"),
                            lambda: cwd.rename(cwd.with_name("replaced-rust")),
                            lambda: source.rename(source.with_name("replaced-source")),
                        ]
                        for mutate in attempts:
                            try:
                                mutate()
                            except PermissionError:
                                pass
                            else:
                                raise AssertionError("archived source mutation was allowed")
                        assert (cwd / "sentinel.txt").read_text() == "pinned source\\n"
                    elif name == "lipo":
                        if args[:2] == ["-create", "-output"]:
                            inputs = [Path(value) for value in args[3:]]
                            assert len(inputs) == 2 and all(path.is_file() for path in inputs)
                            names = {"aarch64-apple-darwin": "arm64", "x86_64-apple-darwin": "x86_64"}
                            slices = [names[path.read_text()] for path in inputs]
                            fault = os.environ.get("LIPO_FIXTURE_ARCHES")
                            if fault == "missing":
                                slices.pop()
                            elif fault == "wrong":
                                slices[-1] = "armv7"
                            Path(args[2]).write_text("\\n".join(slices))
                        else:
                            assert args[1:] == ["-verify_arch", "arm64", "x86_64"], args
                            if not set(args[2:]) <= set(Path(args[0]).read_text().splitlines()):
                                raise SystemExit(37)
                    elif name == "xcodebuild":
                        project = cwd / "RamaTransparentProxyExample.xcodeproj"
                        assert (project / "project.pbxproj").read_text() == "generated project\\n"
                        (project / "build-state").write_text("writable generated project\\n")
                        assert (cwd.parent / "tproxy_rs/target/universal/librama_tproxy_example.a").is_file()
                        derived = Path(args[args.index("-derivedDataPath") + 1])
                        (derived / "built-product").write_text("mock product\\n")
                    else:
                        raise AssertionError(name)
                    ''')
                for name in ("cargo", "lipo", "xcodegen", "xcodebuild"):
                    path = tools / name
                    path.write_text(f"#!{__import__('sys').executable}\n" + tool_program)
                    path.chmod(0o755)
                for args in (
                    ["init", "-q"], ["config", "user.email", "fixture@example.invalid"],
                    ["config", "user.name", "Fixture"], ["config", "commit.gpgSign", "false"],
                    ["add", "."], ["commit", "-qm", "fixture"],
                ):
                    subprocess.run(["git", "-C", str(fixture), *args], check=True,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                trace_path = output / "trace.jsonl"
                result = subprocess.run(
                    [str(wrapper)], capture_output=True, text=True,
                    env={**os.environ, "PATH": str(tools) + os.pathsep + os.environ["PATH"],
                         "BUILD_TRACE": str(trace_path),
                         "RAMA_TPROXY_DERIVED_DATA_PATH": str(output / "derived")},
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                trace = [json.loads(line) for line in trace_path.read_text().splitlines()]
                self.assertEqual([row[0] for row in trace],
                                 ["xcodegen", "cargo", "cargo", "lipo", "lipo", "xcodebuild"])
                self.assertEqual([row[2][-1] for row in trace if row[0] == "cargo"],
                                 ["aarch64-apple-darwin", "x86_64-apple-darwin"])
                self.assertEqual(trace[4][2],
                                 [trace[3][2][2], "-verify_arch", "arm64", "x86_64"])
                xcode_args = trace[-1][2]
                self.assertEqual(xcode_args[xcode_args.index("-configuration") + 1], configuration)
                self.assertEqual(xcode_args[-2:], ["clean", "build"])
                archive = Path(trace[1][1]).parents[4]
                self.assertFalse(archive.parent.exists(), "isolated build tree leaked")
                host_target = (
                    "aarch64-apple-darwin" if os.uname().machine in ("arm64", "aarch64")
                    else "x86_64-apple-darwin"
                )
                decoder = rust / "target" / host_target / "debug/dial9_evidence"
                self.assertEqual(decoder.read_text(), "#!/bin/sh\nexit 0\n")
                self.assertTrue(os.access(decoder, os.X_OK))
                self.assertFalse(list(decoder.parent.glob("*.tmp.*")))
                self.assertTrue((output / "derived/built-product").is_file())
                self.assertEqual((rust / "sentinel.txt").read_text(), "pinned source\n")
                for fault in ("missing", "wrong"):
                    with self.subTest(architecture_fault=fault):
                        trace_path.write_text("")
                        decoder.write_text("previous decoder\n")
                        rejected = subprocess.run(
                            [str(wrapper)], capture_output=True, text=True,
                            env={**os.environ,
                                 "PATH": str(tools) + os.pathsep + os.environ["PATH"],
                                 "BUILD_TRACE": str(trace_path), "LIPO_FIXTURE_ARCHES": fault,
                                 "RAMA_TPROXY_DERIVED_DATA_PATH": str(output / "derived")},
                        )
                        self.assertEqual(rejected.returncode, 37, rejected.stdout + rejected.stderr)
                        rejected_trace = [json.loads(line) for line in trace_path.read_text().splitlines()]
                        self.assertEqual([row[0] for row in rejected_trace],
                                         ["xcodegen", "cargo", "cargo", "lipo", "lipo"])
                        self.assertEqual(decoder.read_text(), "previous decoder\n")
                        failed_archive = Path(rejected_trace[1][1]).parents[4]
                        self.assertFalse(failed_archive.parent.exists(), "failed build tree leaked")

    def test_parent_directory_swap_to_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = base / "run"
            make_run(root, "candidate")
            outside = base / "outside"
            outside.mkdir()
            (outside / "run.log").write_text("outside bytes\n")
            original = evidence._read_regular_at
            swapped = False

            def swap_parent(directory_fd, name, display):
                nonlocal swapped
                if display == "logs/nested/run.log" and not swapped:
                    nested = root / "logs" / "nested"
                    nested.rename(root / "logs" / "detached")
                    nested.symlink_to(outside, target_is_directory=True)
                    swapped = True
                return original(directory_fd, name, display)

            with mock.patch.object(
                evidence, "_read_regular_at", side_effect=swap_parent
            ), self.assertRaisesRegex(evidence.EvidenceError, "directory changed"):
                evidence.seal(root)
            self.assertTrue(swapped)

    def test_seal_and_verify_recursive_artifacts_without_circular_hash(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "run"
            make_run(root, "modern_udp", claims=[
                ("dial9_workload_coverage", "1"),
                ("dial9_claim", "exact-workload"),
            ])
            manifest_hash = evidence.seal(root, actual_exit_code=0)
            self.assertRegex(manifest_hash, r"^[0-9a-f]{64}$")
            manifest = (root / evidence.MANIFEST_NAME).read_text()
            self.assertIn("logs/nested/empty.log", manifest)
            self.assertIn(evidence.STATUS_NAME, manifest)
            self.assertNotIn(evidence.MANIFEST_NAME, manifest)
            status = (root / evidence.STATUS_NAME).read_text()
            self.assertNotIn("manifest", status)
            self.assertEqual(evidence.verify(root, actual_exit_code=0)["passed"], "1")

    def test_tamper_extra_symlink_temp_and_truncation_fail_closed(self):
        mutations = {
            "tamper": lambda root: (root / "logs/nested/run.log").write_text("changed\n"),
            "extra": lambda root: (root / "extra.txt").write_text("extra\n"),
            "symlink": lambda root: (root / "link").symlink_to("logs/nested/run.log"),
            "temp": lambda root: (root / "orphan.tmp.123").write_text("partial\n"),
            "truncate": lambda root: (root / evidence.MANIFEST_NAME).write_bytes(
                (root / evidence.MANIFEST_NAME).read_bytes()[:-1]
            ),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "run"
                make_run(root, "modern_udp")
                evidence.seal(root)
                mutate(root)
                with self.assertRaises(evidence.EvidenceError):
                    evidence.verify(root)

    def test_seal_replaces_an_old_manifest_after_truthful_status_rewrite(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "run"
            values = make_run(root, "modern_udp")
            old_hash = evidence.seal(root)
            values.update({"complete": "1", "passed": "0", "exit_code": "1"})
            write_tsv(
                root / evidence.STATUS_NAME,
                ((key, values[key]) for key in evidence.STATUS_ORDER),
            )
            new_hash = evidence.seal(root, actual_exit_code=1)
            self.assertNotEqual(old_hash, new_hash)
            self.assertEqual(evidence.verify(root, actual_exit_code=1)["passed"], "0")

    def test_verify_semantics_use_bytes_retained_by_manifest_scan(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "run"
            status = make_run(root, "modern_udp")
            evidence.seal(root)
            status_path = root / evidence.STATUS_NAME
            valid_status = status_path.read_bytes()
            invalid_status = valid_status.replace(b"git_dirty\t0\n", b"git_dirty\t1\n")
            status_path.write_bytes(invalid_status)
            original_scan = evidence._manifest_artifacts
            artifacts, _ = original_scan(root)
            (root / evidence.MANIFEST_NAME).write_text("".join(
                f"{digest}\t{size}\t{name}\n"
                for name, (size, digest) in sorted(artifacts.items())
            ))
            swapped = False

            def scan_then_swap(directory):
                nonlocal swapped
                result = original_scan(directory)
                if not swapped:
                    swapped = True
                    status_path.write_bytes(valid_status)
                return result

            with mock.patch.object(evidence, "_manifest_artifacts", scan_then_swap):
                with self.assertRaisesRegex(evidence.EvidenceError, "clean exact source"):
                    evidence.verify(root)


class StatusAndIdentityTests(unittest.TestCase):
    def test_capture_provider_cli_uses_stable_provider_option_names(self):
        parsed = evidence._parser().parse_args([
            "capture-provider",
            "--built-provider", "/tmp/built",
            "--installed-provider", "/tmp/installed",
            "--pid", "42",
            "--output", "/tmp/identity.tsv",
            "--source-root", "/tmp/source",
        ])
        self.assertEqual(parsed.built_provider, Path("/tmp/built"))
        self.assertEqual(parsed.installed_provider, Path("/tmp/installed"))

    def test_provider_generation_cli_uses_stable_identity_and_destination_options(self):
        parsed = evidence._parser().parse_args([
            "capture-provider-generation",
            "--identity", "/tmp/provider-identity.tsv",
            "--append", "/tmp/provider-generation-samples.tsv",
        ])
        self.assertEqual(parsed.identity, Path("/tmp/provider-identity.tsv"))
        self.assertEqual(parsed.append, Path("/tmp/provider-generation-samples.tsv"))

    def test_provider_generation_samples_are_required_exact_and_bounded(self):
        mutations = {
            "missing": lambda root: (root / evidence.GENERATION_SAMPLES_NAME).unlink(),
            "substituted": lambda root: (root / evidence.GENERATION_SAMPLES_NAME).write_text(
                (root / evidence.GENERATION_SAMPLES_NAME).read_text().replace(
                    "|42|1700000000000|", "|43|1700000000000|"
                )
            ),
            "gap": lambda root: (root / evidence.GENERATION_SAMPLES_NAME).write_text(
                (root / evidence.GENERATION_SAMPLES_NAME).read_text().replace(
                    "sample_000002\t1700000001500|", "sample_000002\t1700000010000|"
                )
            ),
            "missing precise birth": lambda root: (root / evidence.GENERATION_SAMPLES_NAME).write_text(
                (root / evidence.GENERATION_SAMPLES_NAME).read_text().replace(
                    "running_start_epoch_us\t1700000000000000\n", ""
                )
            ),
            "missing dynamic code": lambda root: (root / evidence.GENERATION_SAMPLES_NAME).write_text(
                (root / evidence.GENERATION_SAMPLES_NAME).read_text().replace(
                    f"running_dynamic_cdhash\t{CDHASH}\n", ""
                )
            ),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "modern"
                make_run(root, "modern_udp")
                mutate(root)
                with self.assertRaises(evidence.EvidenceError):
                    evidence.seal(root)

    def test_soak_generation_proof_composes_with_real_lifecycle_and_awake_cadence(self):
        for sleep_seconds, pre_gap_ms, post_gap_ms in ((45, 0, 0), (45, 2000, 3000), (120, 0, 0)):
            with self.subTest(sleep_seconds=sleep_seconds, pre_gap_ms=pre_gap_ms), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "soak"
                make_sleep_soak_run(root, sleep_seconds=sleep_seconds, pre_gap_ms=pre_gap_ms, post_gap_ms=post_gap_ms)
                evidence.seal(root)
                self.assertEqual(evidence.verify(root)["passed"], "1")
                self.assertIn("max_gap_ms\t5000\n", (root / evidence.GENERATION_SAMPLES_NAME).read_text())

    def test_soak_sleep_cannot_excuse_unproven_or_excessive_generation_gaps(self):
        def replace_file(root, name, before, after):
            path = root / name
            path.write_text(path.read_text().replace(before, after))
        def replace_last_sample_identity(root, field):
            path = root / evidence.GENERATION_SAMPLES_NAME
            _, rows = evidence._parse_tsv_bytes(path.read_bytes())
            key, sample = rows[-2]
            fields = sample.split("|")
            fields[field] = "0" * 64
            rows[-2] = (key, "|".join(fields))
            write_tsv(path, rows)
        mutations = {
            "missing wake body": (
                lambda root: (root / "wake-download.body").unlink(), "lacks raw soak sleep"),
            "short wake body": (
                lambda root: (root / "wake-download.body").write_bytes(b"x" * 63),
                "retained body does not contain"),
            "failed wake headers": (
                lambda root: (root / "wake-download-headers.txt").write_bytes(b"HTTP/2 503\r\n\r\n"),
                "retained headers do not match"),
            "contradictory wake writeout": (
                lambda root: (root / "wake-download.txt").write_bytes(
                    b"wake-download: code=200 size=1 time=1.000000s\n"),
                "writeout does not match"),
            "incomplete natural wake completion": (
                lambda root: replace_file(root, "run-meta.tsv", "wake_workload_child_rc\t143", "wake_workload_child_rc\t0"),
                "canonical 32 MiB"),
            "missing raw log": (
                lambda root: (root / "system.ndjson").unlink(), "lacks raw soak sleep"),
            "claimed summary": (
                lambda root: (root / "system.ndjson").write_text('{"sleep_seconds":45}\n'),
                "malformed or unattributed"),
            "wrong PID": (
                lambda root: replace_file(root, "system.ndjson", '"processID": 42', '"processID": 43'),
                "malformed or unattributed"),
            "wrong subsystem": (
                lambda root: replace_file(root, "system.ndjson", evidence.DEV_PROVIDER_BUNDLE_ID, "other.provider"),
                "malformed or unattributed"),
            "wrong category": (
                lambda root: replace_file(root, "system.ndjson", '"lifecycle"', '"tproxy"'),
                "exact category/phase"),
            "missing wake": (
                lambda root: replace_file(root, "system.ndjson", '"system wake"', '"ordinary output"'),
                "exactly one ordered"),
            "duplicate field": (
                lambda root: replace_file(root, "system.ndjson", '"processID": 42', '"processID": 42, "processID": 42'),
                "malformed or unattributed"),
            "duplicate cycle": (
                lambda root: (root / "system.ndjson").write_text((root / "system.ndjson").read_text() * 2),
                "exactly one ordered"),
            "failed command": (
                lambda root: replace_file(root, "run-meta.tsv", "sleep_command_ok\t1", "sleep_command_ok\t0"),
                "this successful run"),
            "failed recovery": (
                lambda root: replace_file(root, "sleep-probes.tsv", "\t0\t200", "\t28\t000"),
                "successful paired probe"),
            "wrong generation": (
                lambda root: replace_file(root, "run-meta.tsv", "common_provider_generation_identity\t", "unrelated_generation\t"),
                "common provider identity"),
            "wrong executable": (
                lambda root: replace_file(root, "run-meta.tsv", "provider_executable\t", "unrelated_executable\t"),
                "this successful run"),
            "replaced process": (
                lambda root: replace_file(root, evidence.GENERATION_SAMPLES_NAME, "|42|1700000000000|", "|43|1700000000000|"),
                "malformed or substituted"),
            "replaced process start": (
                lambda root: replace_file(root, evidence.GENERATION_SAMPLES_NAME, "|42|1700000000000|", "|42|1700000000001|"),
                "malformed or substituted"),
            "postwake command identity": (
                lambda root: replace_last_sample_identity(root, 5), "malformed or substituted"),
            "postwake executable path": (
                lambda root: replace_last_sample_identity(root, 6), "malformed or substituted"),
            "postwake precise birth": (
                lambda root: replace_last_sample_identity(root, 3), "malformed or substituted"),
            "postwake dynamic code": (
                lambda root: replace_last_sample_identity(root, 4), "malformed or substituted"),
            "invalid timezone": (
                lambda root: replace_file(root, "system.ndjson", "+0000", "+unknown"),
                "invalid timestamp"),
            "out of phase": (
                lambda root: replace_file(root, "phases.tsv", "sleep-wake\t", "idle-tail\t"),
                "phase is missing"),
            "probe before wake": (
                lambda root: (root / "sleep-probes.tsv").write_text(
                    "1700000014.200000\t1700000014.400000\t2023-11-14T22:13:34Z\t0\t200\n"),
                "no probe attempted after the wake marker"),
        }
        for name, (mutate, reason) in mutations.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "soak"
                make_sleep_soak_run(root)
                mutate(root)
                with self.assertRaisesRegex(evidence.EvidenceError, reason):
                    evidence.seal(root)
        for arguments, reason in (
            ({"sleep_seconds": 121}, "120-second bound"),
            ({"pre_gap_ms": 2000, "post_gap_ms": 4000}, "bracketing its awake edges"),
        ):
            with self.subTest(arguments=arguments), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "soak"
                make_sleep_soak_run(root, **arguments)
                with self.assertRaisesRegex(evidence.EvidenceError, reason):
                    evidence.seal(root)

    def test_soak_lifecycle_does_not_excuse_an_independent_awake_gap(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "soak"
            make_sleep_soak_run(root)
            path = root / evidence.GENERATION_SAMPLES_NAME
            values, rows = evidence._parse_tsv_bytes(path.read_bytes())
            # Remove three ordinary awake samples without breaking chronology,
            # numbering, count, run coverage, or the valid sleep bracket.
            samples = [value for key, value in rows if key.startswith("sample_0")
                       and value.split("|", 1)[0] not in {
                           "1700000003000", "1700000005000", "1700000007000"}]
            values["sample_count"] = str(len(samples))
            write_tsv(path, [
                *((key, values[key]) for key in evidence.GENERATION_FIXED_ORDER),
                *((f"sample_{index:06d}", value) for index, value in enumerate(samples, 1)),
                ("schema_complete", "1"),
            ])
            with self.assertRaisesRegex(evidence.EvidenceError, "awake sampling gap"):
                evidence.seal(root)

    def test_soak_sleep_rounding_never_expands_the_exempt_interval(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "soak"
            make_sleep_soak_run(root, pre_gap_ms=2000, post_gap_ms=3000)
            path = root / "system.ndjson"
            # One microsecond less asleep leaves more than five seconds awake;
            # integer sample timestamps must not round that excess away.
            path.write_text(path.read_text().replace(
                "22:13:35.000000+0000", "22:13:35.000001+0000"))
            with self.assertRaisesRegex(evidence.EvidenceError, "bracketing its awake edges"):
                evidence.seal(root)

    def test_soak_samples_can_continue_between_the_lifecycle_edges(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "soak"
            make_sleep_soak_run(root)
            path = root / evidence.GENERATION_SAMPLES_NAME
            values, rows = evidence._parse_tsv_bytes(path.read_bytes())
            samples = [value for key, value in rows if key.startswith("sample_0")]
            tail = samples[0].split("|", 1)[1]
            # Callbacks and physical suspension need not coincide with sampler
            # scheduling. Interior samples do not change the two awake edges.
            samples.extend(f"{epoch}|{tail}" for epoch in (1700000016000, 1700000059000))
            samples.sort(key=lambda value: int(value.split("|", 1)[0]))
            values["sample_count"] = str(len(samples))
            write_tsv(path, [
                *((key, values[key]) for key in evidence.GENERATION_FIXED_ORDER),
                *((f"sample_{index:06d}", value) for index, value in enumerate(samples, 1)),
                ("schema_complete", "1"),
            ])
            evidence.seal(root)
            self.assertEqual(evidence.verify(root)["passed"], "1")

    def test_soak_bracket_samples_must_be_outside_the_precise_lifecycle_edges(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "soak"
            make_sleep_soak_run(root)
            log = root / "system.ndjson"
            log.write_text(log.read_text().replace(
                "22:13:35.000000+0000", "22:13:34.999999+0000"
            ).replace("22:14:20.000000+0000", "22:14:20.000001+0000"))
            path = root / evidence.GENERATION_SAMPLES_NAME
            values, rows = evidence._parse_tsv_bytes(path.read_bytes())
            tail = rows[len(evidence.GENERATION_FIXED_ORDER)][1].split("|", 1)[1]
            epochs = [1700000001000, 1700000003000, 1700000005000,
                      1700000007000, 1700000010000, 1700000015000,
                      1700000060000, 1700000062000]
            values["sample_count"] = str(len(epochs))
            write_tsv(path, [
                *((key, values[key]) for key in evidence.GENERATION_FIXED_ORDER),
                *((f"sample_{index:06d}", f"{epoch}|{tail}") for index, epoch in enumerate(epochs, 1)),
                ("schema_complete", "1"),
            ])
            # The apparent 15s/60s edge samples are both inside raw sleep.
            # The genuine outside samples leave ~7s awake in combination.
            with self.assertRaisesRegex(evidence.EvidenceError, "bracketing its awake edges"):
                evidence.seal(root)

    def test_modern_and_stress_receive_no_sleep_sampling_exception(self):
        for kind in ("modern_udp", "stress-candidate"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / kind
                status = make_sleep_soak_run(root)
                status["evidence_kind"] = kind
                claims_path = root / evidence.CLAIMS_NAME
                claims_path.write_text(claims_path.read_text().replace("evidence_kind\tsoak\n", f"evidence_kind\t{kind}\n"))
                status["workload_claims_sha256"] = evidence.sha256_file(claims_path)
                write_tsv(root / evidence.STATUS_NAME, ((key, status[key]) for key in evidence.STATUS_ORDER))
                with self.assertRaisesRegex(evidence.EvidenceError, "gap exceeds its encoded tolerance"):
                    evidence.seal(root)

    def test_provider_generation_cannot_start_after_run_end(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "run"
            make_run(
                root, "candidate", process_start=1_700_000_003_000
            )
            with self.assertRaisesRegex(evidence.EvidenceError, "starts after"):
                evidence.seal(root)

    def test_provider_generation_samples_cannot_predate_process_start(self):
        for kind in ("modern_udp", "soak", "stress-candidate"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "run"
                # The fixture consistently derives the replacement generation
                # and its samples, so this is a temporal invariant check rather
                # than a hash/identity mismatch.
                make_run(root, kind, process_start=1_700_000_001_500)
                with self.assertRaisesRegex(evidence.EvidenceError, "predates"):
                    evidence.seal(root)

    def test_provider_start_at_first_sample_and_incomplete_preflight_are_valid(self):
        for outcome, process_start in (
            (("1", "1", "0"), 1_700_000_001_000),
            (("0", "0", "2"), 1_700_000_001_500),
        ):
            with self.subTest(outcome=outcome), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "run"
                make_run(root, "modern_udp", outcome=outcome, process_start=process_start)
                evidence.seal(root)
                self.assertEqual(evidence.verify(root)["exit_code"], outcome[2])

    def test_status_semantics_and_actual_exit_must_match(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "run"
            values = make_run(root, "modern_udp")
            values.update({"complete": "0", "passed": "1", "exit_code": "2"})
            write_tsv(
                root / evidence.STATUS_NAME,
                ((key, values[key]) for key in evidence.STATUS_ORDER),
            )
            with self.assertRaisesRegex(evidence.EvidenceError, "status semantics"):
                evidence.seal(root)
            values.update({"complete": "1", "passed": "1", "exit_code": "0"})
            write_tsv(
                root / evidence.STATUS_NAME,
                ((key, values[key]) for key in evidence.STATUS_ORDER),
            )
            with self.assertRaisesRegex(evidence.EvidenceError, "actual shell exit"):
                evidence.seal(root, actual_exit_code=1)

    def test_incomplete_status_may_truthfully_mark_unavailable_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "run"
            root.mkdir()
            values = {
                "complete": "0", "passed": "0", "exit_code": "143",
                "evidence_kind": "soak", "run_uuid": str(uuid.uuid4()),
                "run_start_epoch_ms": "1700000001000",
                "run_end_epoch_ms": "1700000001000",
                "git_head": "unavailable", "git_dirty": "unavailable",
                "provider_build_identity": "unavailable",
                "provider_generation_identity": "unavailable",
                "workload_claims_sha256": "unavailable",
                "schema_complete": "1",
            }
            write_tsv(
                root / evidence.STATUS_NAME,
                ((key, values[key]) for key in evidence.STATUS_ORDER),
            )
            evidence.seal(root, actual_exit_code=143)
            self.assertEqual(evidence.verify(root, actual_exit_code=143)["complete"], "0")

    def test_workload_claims_must_include_the_exact_run_uuid(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "run"
            values = make_run(root, "modern_udp")
            write_tsv(root / evidence.CLAIMS_NAME, [
                ("evidence_kind", "modern_udp"),
                ("schema_complete", "1"),
            ])
            values["workload_claims_sha256"] = evidence.sha256_file(
                root / evidence.CLAIMS_NAME
            )
            write_tsv(
                root / evidence.STATUS_NAME,
                ((key, values[key]) for key in evidence.STATUS_ORDER),
            )
            with self.assertRaisesRegex(evidence.EvidenceError, "run UUID mismatch"):
                evidence.seal(root)

    def test_identity_head_dirty_and_derived_hash_tampering_is_rejected(self):
        mutations = {
            "head": ("source_git_head", "d" * 40),
            "dirty": ("running_git_dirty", "1"),
            "identity": ("provider_build_identity", "e" * 64),
            "command": ("running_command", "/different/provider"),
        }
        for name, (field, replacement) in mutations.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                write_identity(root)
                path = root / evidence.PROVIDER_IDENTITY_NAME
                rows = [line.split("\t") for line in path.read_text().splitlines()]
                for row in rows:
                    if row[0] == field:
                        row[1] = replacement
                write_tsv(path, rows)
                with self.assertRaises(evidence.EvidenceError):
                    evidence.read_provider_identity(path)

    def test_bundle_snapshot_requires_embedded_clean_full_head(self):
        with tempfile.TemporaryDirectory() as temporary:
            bundle = Path(temporary) / "provider.systemextension"
            executable = bundle / "Contents/MacOS/provider"
            executable.parent.mkdir(parents=True)
            executable.write_bytes(b"binary")
            info = {
                "CFBundleIdentifier": evidence.DEV_PROVIDER_BUNDLE_ID,
                "CFBundleExecutable": "provider",
                "CFBundleVersion": "1",
                "RamaGitHead": HEAD,
                "RamaGitDirty": "0",
            }
            with (bundle / "Contents/Info.plist").open("wb") as destination:
                plistlib.dump(info, destination)
            signing = (evidence.DEV_PROVIDER_BUNDLE_ID, evidence.DEV_TEAM_ID, CDHASH)
            with mock.patch.object(evidence, "_codesign_identity", return_value=signing):
                snapshot = evidence._bundle_snapshot(
                    bundle, evidence.DEV_PROVIDER_BUNDLE_ID, evidence.DEV_TEAM_ID
                )
                self.assertEqual(snapshot.git_head, HEAD)
                info["RamaGitDirty"] = "1"
                with (bundle / "Contents/Info.plist").open("wb") as destination:
                    plistlib.dump(info, destination)
                with self.assertRaisesRegex(evidence.EvidenceError, "built from a dirty"):
                    evidence._bundle_snapshot(
                        bundle, evidence.DEV_PROVIDER_BUNDLE_ID, evidence.DEV_TEAM_ID
                    )

    def test_capture_rejects_source_and_process_generation_changes(self):
        bundle = evidence.BundleSnapshot(
            evidence.DEV_PROVIDER_BUNDLE_ID, HEAD, "0", evidence.DEV_TEAM_ID,
            CDHASH, EXECUTABLE_HASH, "1", "/bundle", "/bundle/provider",
            evidence.provider_build_identity(
                evidence.DEV_PROVIDER_BUNDLE_ID, HEAD, evidence.DEV_TEAM_ID,
                CDHASH, EXECUTABLE_HASH,
            ),
        )
        process_a = evidence.ProcessSnapshot(42, 1000, "/provider", Path("/provider"))
        process_b = evidence.ProcessSnapshot(42, 2000, "/provider", Path("/provider"))
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
            evidence, "_git_snapshot", side_effect=[(HEAD, "0"), (HEAD, "0")]
        ), mock.patch.object(
            evidence, "_bundle_snapshot", return_value=bundle
        ), mock.patch.object(
            evidence, "_process_snapshot", side_effect=[process_a, process_b]
        ), mock.patch.object(
            evidence, "_dynamic_code_snapshot", return_value=evidence.DynamicCodeSnapshot(
                1_000_000, evidence.DEV_PROVIDER_BUNDLE_ID, evidence.DEV_TEAM_ID, CDHASH
            )
        ):
            with self.assertRaisesRegex(evidence.EvidenceError, "generation changed"):
                evidence.capture_provider(
                    Path("built"), Path("installed"), 42,
                    Path(temporary) / evidence.PROVIDER_IDENTITY_NAME, Path("source"),
                )

    def test_runtime_generation_cli_preserves_submillisecond_birth_and_soak_wiring(self):
        start_us = 1_700_000_000_123_456
        process = evidence.ProcessSnapshot(42, start_us // 1000, "/provider", Path("/provider"))
        expected = evidence.provider_generation_identity(
            42, start_us // 1000, hashlib.sha256(b"/provider").hexdigest(),
            start_epoch_us=start_us,
        )
        with mock.patch.object(evidence, "_process_start_epoch_us", return_value=start_us), \
             mock.patch.object(evidence, "_process_snapshot", return_value=process), \
             mock.patch("sys.stdout", new_callable=io.StringIO) as output:
            self.assertEqual(evidence.main(["process-generation-identity", "--pid", "42"]), 0)
            self.assertEqual(output.getvalue(), expected + "\n")
        shell = Path(__file__).with_name("soak_test.sh").read_text()
        body = shell.split("process_identity() {", 1)[1].split("\n}\n", 1)[0]
        result = subprocess.run(
            ["bash", "-c", 'evidence_tool() { printf "%s\\n" "$@"; }; '
             + "process_identity() {" + body + "\n}\nprocess_identity 42"],
            capture_output=True, text=True, timeout=3,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "process-generation-identity\n--pid\n42\n")

    def test_runtime_generation_rejects_a_birth_change_within_one_millisecond(self):
        start_us = 1_700_000_000_123_456
        process = evidence.ProcessSnapshot(42, start_us // 1000, "/provider", Path("/provider"))
        with mock.patch.object(
            evidence, "_process_start_epoch_us", side_effect=[start_us, start_us + 1]
        ), mock.patch.object(evidence, "_process_snapshot", return_value=process):
            with self.assertRaisesRegex(evidence.EvidenceError, "birth changed"):
                evidence.process_generation_identity(42)

    def test_process_snapshot_uses_kernel_executable_not_argv_or_mapped_images(self):
        with tempfile.TemporaryDirectory() as temporary:
            executable = Path(temporary) / "provider"
            executable.write_bytes(b"executable")
            proc = mock.Mock()
            def pidpath(pid, buffer, size):
                self.assertEqual(pid, 42)
                content = os.fsencode(executable)
                buffer.value = content
                return len(content)
            proc.proc_pidpath.side_effect = pidpath
            with mock.patch.object(evidence.ctypes, "CDLL", return_value=proc), \
                mock.patch.object(evidence, "_process_start_epoch_us", return_value=1_000_123), \
                mock.patch.object(evidence, "_run", side_effect=[
                    subprocess.CompletedProcess([], 0, "/argv/decoy\n", ""),
                ]) as commands:
                snapshot = evidence._process_snapshot(42)
            self.assertEqual(snapshot.executable_path, executable.resolve())
            self.assertEqual(snapshot.command, "/argv/decoy")
            self.assertEqual(snapshot.start_epoch_ms, 1000)
            self.assertEqual([call.args[0][0] for call in commands.call_args_list],
                             ["/bin/ps"])

    def test_kernel_executable_lookup_rejects_missing_truncated_or_malformed_path(self):
        cases = ((0, b""), (4096, b""), (4, b"abcdx"),
                 (7, b"decoy/x"), (5, b"/a\0bc"), (4, b"/a\nb"))
        for length, content in cases:
            with self.subTest(length=length, content=content):
                proc = mock.Mock()
                def pidpath(_pid, buffer, _size):
                    buffer.raw = content + bytes(len(buffer) - len(content))
                    return length
                proc.proc_pidpath.side_effect = pidpath
                with mock.patch.object(evidence.ctypes, "CDLL", return_value=proc):
                    with self.assertRaises(evidence.EvidenceError):
                        evidence._process_executable_path(42)
        with mock.patch.object(evidence.ctypes, "CDLL", side_effect=OSError("unavailable")):
            with self.assertRaisesRegex(evidence.EvidenceError, "unavailable"):
                evidence._process_executable_path(42)

    @unittest.skipUnless(sys.platform == "darwin", "Darwin kernel process API")
    def test_kernel_executable_lookup_handles_live_process_with_multiple_txt_mappings(self):
        executable = evidence._process_executable_path(os.getpid())
        self.assertTrue(executable.is_file())
        mappings = subprocess.run(
            ["/usr/sbin/lsof", "-a", "-p", str(os.getpid()), "-d", "txt", "-Fn"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        if mappings.returncode != 0:
            self.skipTest("host cannot inspect its own mapped images")
        paths = [Path(line[1:]).resolve() for line in mappings.stdout.splitlines()
                 if line.startswith("n/")]
        self.assertIn(executable, paths)
        self.assertIn(Path("/usr/lib/dyld"), paths)
        self.assertGreaterEqual(len(paths), 2)

    def test_capture_rejects_sibling_executable_decoy(self):
        declared = Path("/bundle/Contents/MacOS/provider")
        decoy = Path("/bundle/Contents/MacOS/provider-helper")
        bundle = evidence.BundleSnapshot(
            evidence.DEV_PROVIDER_BUNDLE_ID, HEAD, "0", evidence.DEV_TEAM_ID,
            CDHASH, EXECUTABLE_HASH, "1", "/bundle", str(declared),
            evidence.provider_build_identity(
                evidence.DEV_PROVIDER_BUNDLE_ID, HEAD, evidence.DEV_TEAM_ID,
                CDHASH, EXECUTABLE_HASH,
            ),
        )
        process = evidence.ProcessSnapshot(42, 1000, "/provider-helper", decoy)
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
            evidence, "_git_snapshot", side_effect=[(HEAD, "0"), (HEAD, "0")]
        ), mock.patch.object(
            evidence, "_bundle_snapshot", return_value=bundle
        ), mock.patch.object(
            evidence, "_process_snapshot", side_effect=[process, process]
        ), mock.patch.object(
            evidence, "_dynamic_code_snapshot", return_value=evidence.DynamicCodeSnapshot(
                1_000_000, evidence.DEV_PROVIDER_BUNDLE_ID, evidence.DEV_TEAM_ID, CDHASH
            )
        ):
            with self.assertRaisesRegex(evidence.EvidenceError, "declared executable"):
                evidence.capture_provider(
                    Path("built"), Path("installed"), 42,
                    Path(temporary) / evidence.PROVIDER_IDENTITY_NAME, Path("source"),
                )


class DynamicCodeIdentityTests(unittest.TestCase):
    @staticmethod
    def framework_fixture():
        cf, security = mock.Mock(), mock.Mock()
        constants = {
            "kSecGuestAttributePid": 1, "kSecCodeInfoIdentifier": 2,
            "kSecCodeInfoTeamIdentifier": 3, "kSecCodeInfoUnique": 4,
        }
        cf.CFNumberCreate.return_value = 11
        cf.CFDictionaryCreate.return_value = 21
        def copy_guest(host, attributes, flags, output):
            assert host is None and attributes == 21 and flags == 0
            output._obj.value = 31
            return 0
        def copy_information(guest, flags, output):
            assert guest.value == 31 and flags == 1 << 1
            output._obj.value = 41
            return 0
        security.SecCodeCopyGuestWithAttributes.side_effect = copy_guest
        security.SecCodeCopySigningInformation.side_effect = copy_information
        security.SecCodeCheckValidity.return_value = 0
        cf.CFDictionaryGetValue.side_effect = lambda _dictionary, key: {2: 51, 3: 52, 4: 53}[key]
        cf.CFGetTypeID.side_effect = lambda value: 2 if value == 53 else 1
        cf.CFStringGetTypeID.return_value = 1
        cf.CFDataGetTypeID.return_value = 2
        def get_string(value, buffer, _length, encoding):
            assert encoding == 0x08000100
            buffer.value = {
                51: evidence.DEV_PROVIDER_BUNDLE_ID.encode(),
                52: evidence.DEV_TEAM_ID.encode(),
            }[value]
            return True
        cf.CFStringGetCString.side_effect = get_string
        cf.CFDataGetLength.return_value = 20
        # Retain the storage for the borrowed CFData bytes throughout the test.
        cf.hash_buffer = evidence.ctypes.create_string_buffer(bytes.fromhex(CDHASH))
        cf.CFDataGetBytePtr.return_value = evidence.ctypes.addressof(cf.hash_buffer)
        return cf, security, constants

    def read_dynamic(self, cf, security, constants, births=(1_000_123, 1_000_123)):
        with mock.patch.object(evidence.ctypes, "CDLL", side_effect=[cf, security]), \
                mock.patch.object(evidence, "_framework_constant", side_effect=lambda _library, name: constants[name]), \
                mock.patch.object(evidence, "_process_start_epoch_us", side_effect=births):
            return evidence._dynamic_code_snapshot(42)

    def test_dynamic_guest_is_validated_and_owned_references_are_released(self):
        cf, security, constants = self.framework_fixture()
        self.assertEqual(self.read_dynamic(cf, security, constants), evidence.DynamicCodeSnapshot(
            1_000_123, evidence.DEV_PROVIDER_BUNDLE_ID, evidence.DEV_TEAM_ID, CDHASH
        ))
        self.assertEqual(security.SecCodeCheckValidity.call_count, 2)
        for call in security.SecCodeCheckValidity.call_args_list:
            self.assertEqual(call.args[0].value, 31)
            self.assertEqual(call.args[1:], (1 << 4, None))
        self.assertEqual([call.args[0] for call in cf.CFRelease.call_args_list], [41, 31, 21, 11])
        self.assertEqual(cf.CFNumberCreate.call_args.args[2]._obj.value, 42)

    def test_dynamic_api_errors_and_malformed_information_fail_closed(self):
        for failure in (
            "guest", "validity", "final validity", "information", "missing field",
            "wrong type", "unreadable string", "hash length", "hash address", "birth changed",
        ):
            with self.subTest(failure=failure):
                cf, security, constants = self.framework_fixture()
                births = (1_000_123, 1_000_123)
                if failure == "guest":
                    security.SecCodeCopyGuestWithAttributes.side_effect = None
                    security.SecCodeCopyGuestWithAttributes.return_value = -67062
                elif failure == "validity":
                    security.SecCodeCheckValidity.return_value = -67050
                elif failure == "final validity":
                    security.SecCodeCheckValidity.side_effect = [0, -67050]
                elif failure == "information":
                    security.SecCodeCopySigningInformation.side_effect = None
                    security.SecCodeCopySigningInformation.return_value = -67062
                elif failure == "missing field":
                    cf.CFDictionaryGetValue.side_effect = None
                    cf.CFDictionaryGetValue.return_value = None
                elif failure == "wrong type":
                    cf.CFGetTypeID.side_effect = None
                    cf.CFGetTypeID.return_value = 99
                elif failure == "unreadable string":
                    cf.CFStringGetCString.side_effect = None
                    cf.CFStringGetCString.return_value = False
                elif failure == "hash length":
                    cf.CFDataGetLength.return_value = 4096
                elif failure == "hash address":
                    cf.CFDataGetBytePtr.return_value = None
                else:
                    births = (1_000_123, 1_000_124)
                with self.assertRaises(evidence.EvidenceError):
                    self.read_dynamic(cf, security, constants, births)
                self.assertEqual(cf.CFRelease.call_args_list[-2:], [mock.call(21), mock.call(11)])
        with mock.patch.object(evidence, "_process_start_epoch_us", return_value=1_000_123), \
                mock.patch.object(evidence.ctypes, "CDLL", side_effect=OSError("unavailable")):
            with self.assertRaisesRegex(evidence.EvidenceError, "unavailable or unreadable"):
                evidence._dynamic_code_snapshot(42)

    def test_kernel_birth_uses_exact_public_structure_and_rejects_partial_or_wrong_pid(self):
        for failure in (None, "syscall", "length", "pid", "microseconds", "negative", "zero"):
            with self.subTest(failure=failure):
                system = mock.Mock()
                def lookup(mib, count, output, length, new_value, new_length):
                    self.assertEqual(list(mib), [1, 14, 1, 42])
                    self.assertEqual((count, len(output), length._obj.value, new_value, new_length),
                                     (4, 648, 648, None, 0))
                    evidence.ctypes.c_int64.from_buffer(output, 0).value = 0 if failure == "zero" else 1
                    evidence.ctypes.c_int32.from_buffer(output, 8).value = (
                        1_000_000 if failure == "microseconds" else -1 if failure == "negative" else 123
                    )
                    evidence.ctypes.c_int32.from_buffer(output, 40).value = 43 if failure == "pid" else 42
                    if failure == "length":
                        length._obj.value -= 1
                    return -1 if failure == "syscall" else 0
                system.sysctl.side_effect = lookup
                with mock.patch.object(evidence.ctypes, "CDLL", return_value=system):
                    if failure is None:
                        self.assertEqual(evidence._process_start_epoch_us(42), 1_000_123)
                    else:
                        with self.assertRaisesRegex(evidence.EvidenceError, "process birth"):
                            evidence._process_start_epoch_us(42)

    def test_capture_binds_live_signature_and_precise_birth_without_writing_on_failure(self):
        build = evidence.provider_build_identity(
            evidence.DEV_PROVIDER_BUNDLE_ID, HEAD, evidence.DEV_TEAM_ID, CDHASH, EXECUTABLE_HASH
        )
        bundle = evidence.BundleSnapshot(
            evidence.DEV_PROVIDER_BUNDLE_ID, HEAD, "0", evidence.DEV_TEAM_ID,
            CDHASH, EXECUTABLE_HASH, "1", "/bundle", "/bundle/provider", build
        )
        process = evidence.ProcessSnapshot(42, 1000, "/bundle/provider", Path("/bundle/provider"))
        valid = evidence.DynamicCodeSnapshot(
            1_000_123, evidence.DEV_PROVIDER_BUNDLE_ID, evidence.DEV_TEAM_ID, CDHASH
        )
        for failure in (None, "hash", "identifier", "team", "birth", "changed", "unavailable"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                dynamic = valid
                if failure == "hash":
                    dynamic = evidence.DynamicCodeSnapshot(valid.start_epoch_us, valid.signing_id, valid.team_id, "d" * 40)
                elif failure == "identifier":
                    dynamic = evidence.DynamicCodeSnapshot(valid.start_epoch_us, "other.provider", valid.team_id, valid.cdhash)
                elif failure == "team":
                    dynamic = evidence.DynamicCodeSnapshot(valid.start_epoch_us, valid.signing_id, "OTHERTEAM", valid.cdhash)
                elif failure == "birth":
                    dynamic = evidence.DynamicCodeSnapshot(2_000_123, valid.signing_id, valid.team_id, valid.cdhash)
                snapshots = [dynamic, dynamic]
                if failure == "changed":
                    snapshots[1] = evidence.DynamicCodeSnapshot(1_000_124, valid.signing_id, valid.team_id, valid.cdhash)
                output = Path(temporary) / "identity.tsv"
                with mock.patch.object(evidence, "_git_snapshot", return_value=(HEAD, "0")), \
                        mock.patch.object(evidence, "_bundle_snapshot", return_value=bundle), \
                        mock.patch.object(evidence, "_process_snapshot", return_value=process), \
                        mock.patch.object(evidence, "_dynamic_code_snapshot", side_effect=(
                            evidence.EvidenceError("unavailable") if failure == "unavailable" else snapshots
                        )):
                    if failure is not None:
                        with self.assertRaises(evidence.EvidenceError):
                            evidence.capture_provider(Path("built"), Path("installed"), 42, output, Path("source"))
                        self.assertFalse(output.exists())
                    else:
                        values = evidence.capture_provider(Path("built"), Path("installed"), 42, output, Path("source"))
                        self.assertEqual(values["running_start_epoch_us"], "1000123")
                        self.assertEqual(values["running_dynamic_cdhash"], CDHASH)
                        self.assertEqual(evidence.read_provider_identity(output), values)
                        self.assertNotEqual(values["provider_generation_identity"], evidence.provider_generation_identity(
                            42, 1000, values["running_command_sha256"], start_epoch_us=1_000_124
                        ))

    def test_each_sample_rechecks_live_code_and_birth_without_replacing_good_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            executable = root / "provider"
            executable.write_bytes(b"fixture")
            write_identity(root, command=str(executable))
            identity_path = root / evidence.PROVIDER_IDENTITY_NAME
            identity = evidence.read_provider_identity(identity_path)
            identity["running_executable_path"] = str(executable)
            write_tsv(identity_path, identity.items())
            process = evidence.ProcessSnapshot(42, 1_700_000_000_000, str(executable), executable)
            valid = evidence.DynamicCodeSnapshot(
                1_700_000_000_000_000, evidence.DEV_PROVIDER_BUNDLE_ID, evidence.DEV_TEAM_ID, CDHASH
            )
            output = root / evidence.GENERATION_SAMPLES_NAME
            with mock.patch.object(evidence, "_process_snapshot", return_value=process), \
                    mock.patch.object(evidence, "_dynamic_code_snapshot", return_value=valid) as capture:
                evidence.capture_provider_generation(identity_path, output)
                capture.assert_called_once_with(42)
            original = output.read_bytes()
            for failure in ("hash", "birth", "unavailable", "process changed"):
                with self.subTest(failure=failure):
                    dynamic = evidence.DynamicCodeSnapshot(
                        valid.start_epoch_us + (1 if failure == "birth" else 0), valid.signing_id,
                        valid.team_id, "d" * 40 if failure == "hash" else valid.cdhash,
                    )
                    after = process if failure != "process changed" else evidence.ProcessSnapshot(
                        42, process.start_epoch_ms, "other-command", executable
                    )
                    with mock.patch.object(evidence, "_process_snapshot", side_effect=[process, after]), \
                            mock.patch.object(evidence, "_dynamic_code_snapshot", side_effect=(
                                evidence.EvidenceError("unavailable") if failure == "unavailable" else [dynamic]
                            )):
                        with self.assertRaises(evidence.EvidenceError):
                            evidence.capture_provider_generation(identity_path, output, append=True)
                    self.assertEqual(output.read_bytes(), original)


class CrashAndReleaseSetTests(unittest.TestCase):
    def make_release_set_with_soak_child(self, base):
        modern = base / "modern"
        soak = base / "soak"
        series = base / "series"
        modern_status = make_run(modern, "modern_udp", claims=[
            ("dial9_diagnostic_only", "0"),
            ("dial9_workload_coverage", "1"),
            ("dial9_claim", "exact-workload"),
        ])
        soak_status = make_run(soak, "soak", claims=[
            ("dial9_diagnostic_only", "1"),
            ("dial9_workload_coverage", "0"),
            ("dial9_claim", "unattributed-diagnostic"),
        ])
        series_status = make_stress_series(series)
        child = soak / "stress/stress-status.tsv"
        child.parent.mkdir()
        write_tsv(child, [("run_uuid", str(uuid.uuid4())), ("schema_complete", "1")])
        roots = [modern, soak, series]
        for root in roots:
            evidence.seal(root)
        return roots, [modern_status, soak_status, series_status], child

    def test_release_set_uuid_uniqueness_includes_soak_stress_child(self):
        with tempfile.TemporaryDirectory() as temporary:
            roots, statuses, child = self.make_release_set_with_soak_child(Path(temporary))
            series = evidence._verify_and_capture(roots[2])
            for status in [*statuses, *series.nested_statuses]:
                with self.subTest(collision_kind=status["evidence_kind"], uuid=status["run_uuid"]):
                    write_tsv(child, [("run_uuid", status["run_uuid"]), ("schema_complete", "1")])
                    evidence.seal(roots[1])
                    # Diagnostic envelopes remain inspectable; the release set
                    # alone imposes uniqueness across independently sealed runs.
                    evidence.verify(roots[1])
                    with mock.patch.object(evidence, "_validate_release_kind"):
                        with self.assertRaisesRegex(
                            evidence.EvidenceError, "duplicate top-level or nested"
                        ):
                            evidence.verify_release_set(roots)

    def test_release_set_accepts_unique_soak_stress_child_uuid(self):
        with tempfile.TemporaryDirectory() as temporary:
            roots, statuses, _ = self.make_release_set_with_soak_child(Path(temporary))
            with mock.patch.object(evidence, "_validate_release_kind"):
                self.assertEqual(evidence.verify_release_set(roots), statuses)

    def test_release_set_requires_canonical_soak_stress_child_uuid(self):
        canonical = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
        malformed = (
            f"run_uuid\t{canonical.upper()}\nschema_complete\t1\n",
            f"run_uuid\t{{{canonical}}}\nschema_complete\t1\n",
            "run_uuid\tinvalid\nschema_complete\t1\n",
            "schema_complete\t1\n",
            f"run_uuid\t{canonical}\nrun_uuid\t{canonical}\nschema_complete\t1\n",
            f"run_uuid\t{canonical}\nschema_complete\t1",
        )
        with tempfile.TemporaryDirectory() as temporary:
            roots, _, child = self.make_release_set_with_soak_child(Path(temporary))
            for content in malformed:
                with self.subTest(content=content):
                    child.write_text(content)
                    evidence.seal(roots[1])
                    evidence.verify(roots[1])
                    with mock.patch.object(evidence, "_validate_release_kind"):
                        with self.assertRaises(evidence.EvidenceError):
                            evidence.verify_release_set(roots)

    def test_release_set_soak_child_uuid_uses_manifest_retained_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            roots, statuses, child = self.make_release_set_with_soak_child(Path(temporary))
            write_tsv(child, [("run_uuid", statuses[0]["run_uuid"]), ("schema_complete", "1")])
            evidence.seal(roots[1])
            original_scan = evidence._manifest_artifacts

            def scan_then_replace_child(directory):
                result = original_scan(directory)
                if directory == roots[1]:
                    write_tsv(child, [("run_uuid", str(uuid.uuid4())), ("schema_complete", "1")])
                return result

            with mock.patch.object(
                evidence, "_manifest_artifacts", side_effect=scan_then_replace_child
            ), mock.patch.object(evidence, "_validate_release_kind"), mock.patch.object(
                evidence, "_read_regular_bytes", side_effect=AssertionError("filesystem reread")
            ):
                with self.assertRaisesRegex(
                    evidence.EvidenceError, "duplicate top-level or nested"
                ):
                    evidence.verify_release_set(roots)

    def test_release_set_uuid_uniqueness_includes_nested_series_members(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            series = base / "series"
            series_status = make_stress_series(series)
            evidence.seal(series)
            duplicate_uuid = evidence.read_status(
                series / "members/pair-001/candidate"
            )["run_uuid"]
            modern = base / "modern"
            status = make_run(modern, "modern_udp")
            claims = [
                ("evidence_kind", "modern_udp"),
                ("run_uuid", duplicate_uuid),
                ("dial9_diagnostic_only", "0"),
                ("dial9_workload_coverage", "1"),
                ("dial9_claim", "exact-workload"),
                ("schema_complete", "1"),
            ]
            write_tsv(modern / evidence.CLAIMS_NAME, claims)
            status["run_uuid"] = duplicate_uuid
            status["workload_claims_sha256"] = evidence.sha256_file(
                modern / evidence.CLAIMS_NAME
            )
            write_tsv(
                modern / evidence.STATUS_NAME,
                ((key, status[key]) for key in evidence.STATUS_ORDER),
            )
            crash, rows = evidence._parse_tsv_bytes(
                (modern / "crashes/crash-snapshot.tsv").read_bytes()
            )
            crash["run_uuid"] = duplicate_uuid
            write_tsv(
                modern / "crashes/crash-snapshot.tsv",
                ((key, crash[key]) for key, _ in rows),
            )
            evidence.seal(modern)
            with mock.patch.object(evidence, "_validate_release_kind"):
                with self.assertRaisesRegex(
                    evidence.EvidenceError, "duplicate top-level or nested"
                ):
                    evidence.verify_release_set([series, modern])

    def test_direct_baseline_requires_zero_match_samples_spanning_run(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "direct"
            make_direct_run(root)
            absence = root / evidence.ABSENCE_NAME
            absence.unlink()
            with mock.patch.object(
                evidence,
                "_provider_absence_sample",
                side_effect=[(900, []), (2100, [])],
            ):
                evidence.capture_provider_absence(absence)
                evidence.capture_provider_absence(absence, append=True)
            evidence.seal(root)
            self.assertEqual(evidence.verify(root)["provider_build_identity"], "absent")

            rows = [line.split("\t") for line in absence.read_text().splitlines()]
            for row in rows:
                if row[0] == "sample_000002":
                    row[1] = f"2100|1|42@{'f' * 64}"
            write_tsv(absence, rows)
            with self.assertRaisesRegex(evidence.EvidenceError, "provider was present"):
                evidence.seal(root)

    def test_direct_baseline_rejects_samples_that_do_not_span_run(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / evidence.ABSENCE_NAME
            with mock.patch.object(
                evidence,
                "_provider_absence_sample",
                side_effect=[(1001, []), (1999, [])],
            ):
                evidence.capture_provider_absence(path)
                evidence.capture_provider_absence(path, append=True)
            with self.assertRaisesRegex(evidence.EvidenceError, "do not span"):
                evidence.verify_provider_absence(
                    path, run_start_epoch_ms=1000, run_end_epoch_ms=2000
                )

    def test_direct_baseline_rejects_sampling_gap_over_encoded_tolerance(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / evidence.ABSENCE_NAME
            with mock.patch.object(
                evidence,
                "_provider_absence_sample",
                side_effect=[(900, []), (4000, [])],
            ):
                evidence.capture_provider_absence(path)
                evidence.capture_provider_absence(path, append=True)
            with self.assertRaisesRegex(evidence.EvidenceError, "sampling gap"):
                evidence.verify_provider_absence(
                    path, run_start_epoch_ms=1000, run_end_epoch_ms=4000
                )

    def test_pass_cannot_hide_a_captured_crash(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = base / "run"
            status = make_run(root, "modern_udp", crash_snapshot=False)
            reports = base / "reports"
            reports.mkdir()
            crash = reports / "provider_2026-01-01.crash"
            crash.write_text("crash report\n")
            now = time.time_ns()
            crash.touch()
            evidence.snapshot_crashes(
                int(status["run_start_epoch_ms"]),
                root / "crashes",
                ["provider"],
                run_uuid=status["run_uuid"],
                provider_generation_identity=status["provider_generation_identity"],
                report_dirs=[reports],
            )
            with self.assertRaisesRegex(evidence.EvidenceError, "contradicts captured"):
                evidence.seal(root)

    def test_modern_run_cannot_hide_crash_under_members_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = base / "run"
            status = make_run(root, "modern_udp")
            reports = base / "reports"
            reports.mkdir()
            report = reports / "provider-2026-09-05-120000.ips"
            report.write_text(
                '{"app_name":"provider","bundleID":"org.example.provider"}\n'
            )
            since = (time.time_ns() // 1_000_000) - 1000
            evidence.snapshot_crashes(
                int(status["run_start_epoch_ms"]),
                root / "members" / "crashes",
                ["provider"],
                run_uuid=status["run_uuid"],
                provider_generation_identity=status["provider_generation_identity"],
                report_dirs=[reports],
            )
            with self.assertRaisesRegex(evidence.EvidenceError, "multiple crash snapshots"):
                evidence.seal(root)

    def test_crash_snapshot_recognizes_current_hyphenated_ips_name(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            reports = base / "reports"
            reports.mkdir()
            report = reports / "provider-2026-09-05-120000.ips"
            report.write_text(
                '{"app_name":"provider","bundleID":"org.example.provider"}\n'
                '{"procName":"provider","procPath":"/Library/SystemExtensions/provider"}\n'
            )
            metadata_report = reports / "Incident-2026-09-05-120001.ips"
            metadata_report.write_text(
                '{"bug_type":"309"}\n'
                '{"procName":"provider","procPath":"/Library/SystemExtensions/provider"}\n'
            )
            since = (time.time_ns() // 1_000_000) - 1000
            result = evidence.snapshot_crashes(
                since, base / "snapshot", ["provider"],
                run_uuid=str(uuid.uuid4()),
                provider_generation_identity="a" * 64,
                report_dirs=[reports],
            )
            self.assertEqual(result["crash_count"], "2")
            self.assertTrue((base / "snapshot" / report.name).is_file())
            self.assertTrue((base / "snapshot" / metadata_report.name).is_file())

    def test_crash_snapshot_rejects_ambiguous_ips_without_sealing_zero_crashes(self):
        for key in ("app_name", "bundleID", "procName", "procPath"):
            for replacement in ("unrelated", 999, True, None, [], {}):
                provider_value = json.dumps("/Library/provider" if key == "procPath" else "provider")
                fields = [json.dumps(key) + ":" + provider_value,
                          json.dumps(key) + ":" + json.dumps(replacement)]
                for ordered in (fields, list(reversed(fields))):
                    ambiguous = "{" + ",".join(ordered) + "}"
                    pretty_ambiguous = "{\n  " + ",\n  ".join(ordered) + "\n}"
                    for content in (ambiguous, '{"bug_type":"309"}\n' + ambiguous,
                                    '{"metadata":[' + ambiguous + "]}",
                                    '{"bug_type":"309"}\n\n' + pretty_ambiguous):
                        with self.subTest(key=key, replacement=replacement, content=content), \
                             tempfile.TemporaryDirectory() as temporary:
                            base = Path(temporary)
                            reports = base / "reports"
                            reports.mkdir()
                            (reports / "Incident.ips").write_text(content + "\n")
                            snapshot = base / "snapshot"
                            with self.assertRaisesRegex(evidence.EvidenceError, "duplicate JSON key"):
                                evidence.snapshot_crashes(
                                    1, snapshot, ["provider"],
                                    run_uuid=str(uuid.uuid4()),
                                    provider_generation_identity="a" * 64,
                                    report_dirs=[reports],
                                )
                            self.assertFalse((snapshot / "crash-snapshot.tsv").exists())

    def test_crash_snapshot_reads_complete_ips_object_streams(self):
        metadata = {"bug_type": "309", "future_field": [1, True, None]}
        report = {"metadata": {"format": "IPS"},
                  "procName": "provider", "procPath": "/Library/SystemExtensions/provider"}
        compact = json.dumps(report)
        pretty = json.dumps(report, indent=2)
        for content in (
            compact,
            pretty,
            json.dumps(metadata) + "\n" + compact,
            json.dumps(metadata) + "\n" + pretty,
            json.dumps(metadata, indent=2) + "\n" + pretty,
            " \t\r\n" + json.dumps(metadata) + "\n\n\n\n\n\t " + pretty + "\r\n ",
            json.dumps(metadata) * 6 + pretty,
        ):
            with self.subTest(content=content), tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary)
                root = base / "run"
                status = make_run(root, "modern_udp", crash_snapshot=False)
                reports = base / "reports"
                reports.mkdir()
                (reports / "Incident.ips").write_text(content)
                result = evidence.snapshot_crashes(
                    int(status["run_start_epoch_ms"]), root / "crashes", ["provider"],
                    run_uuid=status["run_uuid"],
                    provider_generation_identity=status["provider_generation_identity"],
                    report_dirs=[reports],
                )
                self.assertEqual(result["crash_count"], "1")
                self.assertEqual((root / "crashes" / "Incident.ips").read_bytes(), content.encode())
                with self.assertRaisesRegex(evidence.EvidenceError, "contradicts captured"):
                    evidence.seal(root)

    def test_crash_snapshot_rejects_unreadable_ips_stream_without_zero_crash_snapshot(self):
        for content in (
            b'{"bug_type":"309"}\n{"procName":"provider"',
            b'{"procName":"provider"}\ntrailing non-JSON data',
            b'{"procName":"unrelated"}\n\xff',
            b" \t\r\n",
            b'{"metadata":' + b"[" * 2000 + b'"provider"' + b"]" * 2000 + b"}",
        ):
            with self.subTest(content=content[:100]), tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary)
                reports = base / "reports"
                reports.mkdir()
                (reports / "Incident.ips").write_bytes(content)
                snapshot = base / "snapshot"
                with self.assertRaisesRegex(evidence.EvidenceError, "invalid IPS"):
                    evidence.snapshot_crashes(
                        1, snapshot, ["provider"], run_uuid=str(uuid.uuid4()),
                        provider_generation_identity="a" * 64, report_dirs=[reports],
                    )
                self.assertFalse((snapshot / "crash-snapshot.tsv").exists())

    def test_crash_snapshot_bounds_report_bytes_before_parsing(self):
        for size in (256, 257):
            with self.subTest(size=size), tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary)
                reports = base / "reports"
                reports.mkdir()
                # A legacy crash text report must retain its filename identity.
                content = b"crash text\n".ljust(size, b" ")
                (reports / "provider-incident.crash").write_bytes(content)
                snapshot = base / "snapshot"
                with mock.patch.object(evidence, "MAX_CRASH_REPORT_BYTES", 256):
                    if size == 256:
                        result = evidence.snapshot_crashes(
                            1, snapshot, ["provider"], run_uuid=str(uuid.uuid4()),
                            provider_generation_identity="a" * 64, report_dirs=[reports],
                        )
                        self.assertEqual(result["crash_count"], "1")
                        self.assertEqual((snapshot / "provider-incident.crash").read_bytes(), content)
                    else:
                        with self.assertRaisesRegex(evidence.EvidenceError, "byte limit"):
                            evidence.snapshot_crashes(
                                1, snapshot, ["provider"], run_uuid=str(uuid.uuid4()),
                                provider_generation_identity="a" * 64, report_dirs=[reports],
                            )
                        self.assertFalse((snapshot / "crash-snapshot.tsv").exists())

    def test_crash_snapshot_bounds_report_that_grows_during_read(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            reports = base / "reports"
            reports.mkdir()
            report = reports / "provider-incident.crash"
            report.write_bytes(b"crash\n")
            snapshot = base / "snapshot"
            original_read = os.read
            extended = False

            def read_then_extend(descriptor, size):
                nonlocal extended
                result = original_read(descriptor, size)
                if not extended:
                    extended = True
                    with report.open("ab") as output:
                        output.write(b"x" * 32)
                return result

            with mock.patch.object(evidence, "MAX_CRASH_REPORT_BYTES", 16), \
                 mock.patch.object(evidence.os, "read", side_effect=read_then_extend):
                with self.assertRaisesRegex(evidence.EvidenceError, "byte limit"):
                    evidence.snapshot_crashes(
                        1, snapshot, ["provider"], run_uuid=str(uuid.uuid4()),
                        provider_generation_identity="a" * 64, report_dirs=[reports],
                    )
            self.assertFalse((snapshot / "crash-snapshot.tsv").exists())

    def test_crash_snapshot_ignores_valid_unrelated_ips_object_stream(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            reports = base / "reports"
            reports.mkdir()
            (reports / "Incident.ips").write_text(
                json.dumps({"bug_type": "309"}, indent=2) + "\n"
                + json.dumps({"procName": "unrelated", "future_field": []}, indent=2)
            )
            result = evidence.snapshot_crashes(
                1, base / "snapshot", ["provider"], run_uuid=str(uuid.uuid4()),
                provider_generation_identity="a" * 64, report_dirs=[reports],
            )
            self.assertEqual(result["crash_count"], "0")
            self.assertFalse((base / "snapshot" / "Incident.ips").exists())

    def test_crash_snapshot_preserves_unique_unknown_ips_fields_and_nested_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            reports = base / "reports"
            reports.mkdir()
            (reports / "Incident.ips").write_text(
                '{"bug_type":"309","future_field":[1,true,null]}\n'
                '{"future_nested":{"procPath":"/Library/provider","other":{}}}\n'
            )
            result = evidence.snapshot_crashes(
                1, base / "snapshot", ["provider"],
                run_uuid=str(uuid.uuid4()),
                provider_generation_identity="a" * 64,
                report_dirs=[reports],
            )
            self.assertEqual(result["crash_count"], "1")
            self.assertTrue((base / "snapshot" / "Incident.ips").is_file())

    def test_release_set_cross_checks_identity_and_dial9_ownership(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            modern = base / "modern"
            soak = base / "soak"
            make_run(modern, "modern_udp", claims=[
                ("dial9_diagnostic_only", "0"),
                ("dial9_workload_coverage", "1"),
                ("dial9_claim", "exact-workload"),
            ])
            make_run(soak, "soak", claims=[
                ("dial9_diagnostic_only", "1"),
                ("dial9_workload_coverage", "0"),
                ("tcp_workload_exercised", "1"),
                ("udp_workload_exercised", "0"),
                ("dial9_claim", "unattributed-diagnostic"),
            ])
            evidence.seal(modern)
            evidence.seal(soak)
            with mock.patch.object(evidence, "_validate_release_kind"):
                statuses = evidence.verify_release_set(
                    [modern, soak], {"modern_udp", "soak"}
                )
            self.assertEqual(len(statuses), 2)

            mismatched = base / "mismatched"
            make_run(mismatched, "stress", executable_hash="d" * 64)
            evidence.seal(mismatched)
            with mock.patch.object(evidence, "_validate_release_kind"):
                with self.assertRaisesRegex(evidence.EvidenceError, "build_identity mismatch"):
                    evidence.verify_release_set([modern, mismatched])

    def test_release_set_rejects_claim_only_fake_modern_envelope(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            modern = base / "modern"
            soak = base / "soak"
            make_run(modern, "modern_udp", claims=[
                ("dial9_diagnostic_only", "0"),
                ("dial9_workload_coverage", "1"),
                ("dial9_claim", "exact-workload"),
            ])
            make_run(soak, "soak", claims=[
                ("dial9_diagnostic_only", "1"),
                ("dial9_workload_coverage", "0"),
                ("dial9_claim", "unattributed-diagnostic"),
            ])
            evidence.seal(modern)
            evidence.seal(soak)
            with self.assertRaisesRegex(evidence.EvidenceError, "modern UDP evidence is missing"):
                evidence.verify_release_set([modern, soak])

    def test_modern_semantics_recompute_echo_dial9_and_cross_bindings(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "modern"
            make_strict_modern_run(root)
            evidence.seal(root)
            envelope = evidence._verify_and_capture(root)
            with mock.patch.object(
                evidence, "_source_blob_at_head", side_effect=current_script_source
            ), mock.patch.object(
                evidence, "_verify_pinned_dial9_replay"
            ), mock.patch.object(evidence, "_validate_modern_domain_semantics"):
                evidence._validate_modern_semantics(envelope)

            client_path = root / "controlled-echo-client.json"
            client = json.loads(client_path.read_text())
            client["exact_echo_count"] -= 1
            client_path.write_text(json.dumps(client))
            evidence.seal(root)
            changed = evidence._verify_and_capture(root)
            with mock.patch.object(
                evidence, "_source_blob_at_head", side_effect=current_script_source
            ), mock.patch.object(
                evidence, "_verify_pinned_dial9_replay"
            ), mock.patch.object(
                evidence, "_validate_modern_domain_semantics"
            ), self.assertRaisesRegex(evidence.EvidenceError, "echo result cardinality"):
                evidence._validate_modern_semantics(changed)

    def test_modern_semantics_rejects_missing_or_substituted_echo_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "modern"
            make_strict_modern_run(root)
            identities = root / "echo-identities.tsv"
            identities.unlink()
            evidence.seal(root)
            missing = evidence._verify_and_capture(root)
            with mock.patch.object(
                evidence, "_source_blob_at_head", side_effect=current_script_source
            ), mock.patch.object(
                evidence, "_verify_pinned_dial9_replay"
            ), mock.patch.object(
                evidence, "_validate_modern_domain_semantics"
            ), self.assertRaisesRegex(evidence.EvidenceError, "missing required"):
                evidence._validate_modern_semantics(missing)

            make_strict_modern_run(Path(temporary) / "substituted")
            root = Path(temporary) / "substituted"
            identities = root / "echo-identities.tsv"
            rows = identities.read_text().splitlines()
            fields = rows[0].split("\t")
            fields[2] = "127.0.0.1:45000"
            rows[0] = "\t".join(fields)
            identities.write_text("\n".join(rows) + "\n")
            evidence.seal(root)
            substituted = evidence._verify_and_capture(root)
            with mock.patch.object(
                evidence, "_source_blob_at_head", side_effect=current_script_source
            ), mock.patch.object(
                evidence, "_verify_pinned_dial9_replay"
            ), mock.patch.object(
                evidence, "_validate_modern_domain_semantics"
            ), self.assertRaisesRegex(evidence.EvidenceError, "identity row is not exact"):
                evidence._validate_modern_semantics(substituted)

    def test_modern_common_dispatch_rejects_missing_raw_bundle_after_reseal(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "modern"
            make_strict_modern_run(root)
            evidence.seal(root)
            envelope = evidence._verify_and_capture(root)
            scripts = Path(__file__).resolve().parent

            def current_source(_head, repository_relative_path):
                return (scripts / Path(repository_relative_path).name).read_bytes()

            with mock.patch.object(
                evidence, "_source_blob_at_head", side_effect=current_source
            ), mock.patch.object(evidence, "_verify_pinned_dial9_replay"):
                with self.assertRaisesRegex(
                    evidence.EvidenceError, "raw-bundle validator rejected"
                ):
                    evidence._validate_modern_semantics(envelope)

    def test_modern_rejects_altered_producer_even_with_recomputed_aggregate(self):
        from modern_udp_evidence import producer_sources_sha256

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "modern"
            make_strict_modern_run(root)
            altered = root / "source-modern_udp_e2e_probe.py"
            altered.write_bytes(altered.read_bytes() + b"\n# substituted producer\n")
            digest = producer_sources_sha256(root)
            for name in ("udp-evidence-status.tsv", evidence.CLAIMS_NAME):
                path = root / name
                rows = [line.split("\t", 1) for line in path.read_text().splitlines()]
                write_tsv(
                    path,
                    ((key, digest if key == "producer_sources_sha256" else value)
                     for key, value in rows),
                )
            common, _ = evidence._parse_tsv_bytes(
                (root / evidence.STATUS_NAME).read_bytes()
            )
            common["workload_claims_sha256"] = evidence.sha256_file(
                root / evidence.CLAIMS_NAME
            )
            write_tsv(
                root / evidence.STATUS_NAME,
                ((key, common[key]) for key in evidence.STATUS_ORDER),
            )
            evidence.seal(root)
            envelope = evidence._verify_and_capture(root)
            with mock.patch.object(
                evidence, "_source_blob_at_head", side_effect=current_script_source
            ), self.assertRaisesRegex(evidence.EvidenceError, "exact evidence-head blob"):
                evidence._validate_modern_semantics(envelope)

    def test_modern_release_rejects_legacy_callback_after_reseal(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "modern"
            make_strict_modern_run(root)
            status_path = root / "udp-evidence-status.tsv"
            rows = [line.split("\t", 1) for line in status_path.read_text().splitlines()]
            write_tsv(
                status_path,
                ((key, "legacy" if key == "callback_generation" else value)
                 for key, value in rows),
            )
            evidence.seal(root)
            envelope = evidence._verify_and_capture(root)
            successful_parser = subprocess.CompletedProcess([], 0, "0\n", "")
            with mock.patch.object(
                evidence, "_source_blob_at_head", side_effect=current_script_source
            ), mock.patch.object(
                evidence, "_run_python_validator", return_value=successful_parser
            ), self.assertRaisesRegex(evidence.EvidenceError, "legacy callback"):
                evidence._validate_modern_semantics(envelope)

    def test_modern_dial9_replay_rejects_fabricated_summary_and_random_trace(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "modern"
            make_strict_modern_run(root)
            trace = root / "dial9-traces" / "trace.8.bin"
            trace.write_bytes(b"self-consistent but not a Dial9 event stream")
            summary = json.loads((root / "dial9-evidence.json").read_text())
            summary["artifacts"][0]["size"] = trace.stat().st_size
            summary["artifacts"][0]["sha256"] = hashlib.sha256(trace.read_bytes()).hexdigest()
            (root / "dial9-evidence.json").write_text(json.dumps(summary))
            decoder = Path(temporary) / "dial9_evidence"
            decoder.write_text("#!/bin/sh\necho 'invalid trace stream' >&2\nexit 2\n")
            decoder.chmod(0o700)
            with mock.patch.object(
                evidence, "_build_pinned_dial9_binary", return_value=decoder
            ), self.assertRaisesRegex(
                evidence.EvidenceError, "decoder rejected sealed traces"
            ):
                evidence._verify_pinned_dial9_replay(root, HEAD)

    def test_modern_pressure_summary_requires_whole_accepted_datagrams(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "modern"
            make_strict_modern_run(root)
            udp, _ = evidence._parse_tsv_bytes((root / "udp-evidence-status.tsv").read_bytes())
            echo_identities = [
                (int(generation), int(flow_id), endpoint)
                for generation, flow_id, endpoint in (
                    line.split("\t") for line in (root / "echo-identities.tsv").read_text().splitlines()
                )
            ]
            summary_path = root / "dial9-evidence.json"
            summary = json.loads(summary_path.read_text())
            pressure = next(flow for flow in summary["required_flows"] if flow["label"] == "pressure")
            payload, sent = int(udp["pressure_payload_bytes"]), int(udp["pressure_expected_bytes"])
            with mock.patch.object(evidence, "_verify_pinned_dial9_replay"):
                for accepted in (payload, 2 * payload, sent - payload):
                    with self.subTest(accepted=accepted):
                        pressure["bytes_in"] = accepted
                        summary_path.write_text(json.dumps(summary))
                        evidence._validate_modern_dial9(root, udp, echo_identities, HEAD)
                for rejected in (0, 1, payload - 1, payload + 1, sent, sent + payload):
                    with self.subTest(rejected=rejected):
                        pressure["bytes_in"] = rejected
                        summary_path.write_text(json.dumps(summary))
                        with self.assertRaisesRegex(
                            evidence.EvidenceError, "pressure|result mismatch"
                        ):
                            evidence._validate_modern_dial9(root, udp, echo_identities, HEAD)

    def test_modern_pressure_summary_rejects_weakened_requirements(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "modern"
            make_strict_modern_run(root)
            udp, _ = evidence._parse_tsv_bytes((root / "udp-evidence-status.tsv").read_bytes())
            requirements = root / "dial9-requirements.tsv"
            original = requirements.read_text()
            payload, sent = int(udp["pressure_payload_bytes"]), int(udp["pressure_expected_bytes"])
            for bounds in ((0, sent - payload), (payload, sent), (sent, sent)):
                with self.subTest(bounds=bounds):
                    rows = original.splitlines()
                    fields = rows[2].split("\t")
                    self.assertEqual(fields[0], "pressure")
                    fields[7:9] = map(str, bounds)
                    rows[2] = "\t".join(fields)
                    requirements.write_text("\n".join(rows) + "\n")
                    udp["dial9_requirements_sha256"] = evidence.sha256_file(requirements)
                    with mock.patch.object(
                        evidence, "_verify_pinned_dial9_replay"
                    ), self.assertRaisesRegex(evidence.EvidenceError, "pressure accepted-byte requirements"):
                        evidence._validate_modern_dial9(root, udp, [], HEAD)

    def test_release_set_rejects_claim_only_fake_soak_envelope(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            soak = base / "soak"
            modern = base / "modern"
            make_run(soak, "soak", claims=[
                ("dial9_diagnostic_only", "1"),
                ("dial9_workload_coverage", "0"),
                ("dial9_claim", "unattributed-diagnostic"),
            ])
            make_run(modern, "modern_udp", claims=[
                ("dial9_diagnostic_only", "0"),
                ("dial9_workload_coverage", "1"),
                ("dial9_claim", "exact-workload"),
            ])
            evidence.seal(soak)
            evidence.seal(modern)
            with self.assertRaisesRegex(evidence.EvidenceError, "soak evidence is missing"):
                evidence.verify_release_set([soak, modern])

    def test_release_set_rejects_ineligible_or_skipped_soak_after_common_reseal(self):
        for mutation, message in (
            ({"release_profile_eligible": "0"}, "not eligible"),
            ({"stress_ok": "skipped"}, "required workload"),
            ({"post_wake_ok": "skipped", "sleep_command_ok": "skipped"}, "required workload"),
        ):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                soak, modern = root / "soak", root / "modern"
                make_run(soak, "soak")
                make_run(modern, "modern_udp")
                meta = {"release_profile_eligible": "1", **{
                    key: "1" for key in (
                        "stress_ok", "fanout_established_target_sustained",
                        "idle_holders_established_target_sustained", "real_download_ok",
                        "post_wake_ok", "sleep_command_ok",
                    )
                }}
                meta.update(mutation)
                write_tsv(soak / "run-meta.tsv", meta.items())
                for name in (
                    "soak-verdict.tsv", "phases.tsv", "system.ndjson",
                    "probe-timeline.txt", "provider-timeline.tsv", "idle-cpu-baseline.tsv",
                    "idle-cpu-post.tsv", "baseline-mem.txt", "final-mem.txt", "leaks.txt",
                    "crashes-before.tsv", "real-download.metrics", "real-download.curl.log",
                    "real-download.txt", "stress/stress-manifest.tsv",
                    "fanout.txt", "sleep-probes.tsv", "wake-download.body",
                    "wake-download-headers.txt", "wake-download.txt",
                ):
                    (soak / name).parent.mkdir(parents=True, exist_ok=True)
                    (soak / name).write_text("unused\n")
                write_tsv(soak / "stress/stress-status.tsv", [
                    ("run_uuid", str(uuid.uuid4())), ("schema_complete", "1"),
                ])
                for artifact, source in evidence.SOAK_PRODUCER_SOURCES:
                    (soak / artifact).write_bytes(Path(__file__).with_name(source).read_bytes())
                evidence.seal(soak)
                evidence.seal(modern)
                # Ordinary envelope inspection remains available for diagnostics.
                self.assertEqual(evidence.verify(soak)["passed"], "1")
                with mock.patch.object(evidence, "_source_blob_at_head", side_effect=current_script_source):
                    with self.assertRaisesRegex(evidence.EvidenceError, message):
                        evidence.verify_release_set([soak, modern])

    def test_soak_download_rederives_exact_raw_transfer_after_reseal(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            metrics = "200\t33554432\t12345\t2.500000"
            report = ("real-download: code=200 curl_exit=0 size=33554432 "
                      "expected=33554432 avg=12345B/s time=2.500000s\n")
            (root / "real-download.metrics").write_text(metrics)
            (root / "real-download.txt").write_text(report)
            (root / "real-download.curl.log").write_text("")
            evidence._validate_soak_download_artifacts(root)
            for filename, changed in (
                ("real-download.metrics", metrics.replace("33554432", "1")),
                ("real-download.metrics", metrics.replace("12345", "0")),
                ("real-download.metrics", metrics.replace("2.500000", "NaN")),
                ("real-download.txt", report.replace("curl_exit=0", "curl_exit=18")),
                ("real-download.curl.log", "curl: (18) partial transfer\n"),
            ):
                with self.subTest(filename=filename, changed=changed):
                    path = root / filename
                    original = path.read_text()
                    path.write_text(changed)
                    with self.assertRaises(evidence.EvidenceError):
                        evidence._validate_soak_download_artifacts(root)
                    path.write_text(original)
            (root / "real-download.metrics").unlink()
            with self.assertRaises(evidence.EvidenceError):
                evidence._validate_soak_download_artifacts(root)

    @staticmethod
    def canonical_soak_workload():
        from test_soak_pressure_log import SoakPressureLogTests
        meta = SoakPressureLogTests.valid_release_profile_meta()
        meta.update({
            "fanout_target": "40", "fanout_hold_seconds": "90",
            "idle_holders_target": "40", "idle_holders_hold_seconds": "150",
            "idle_cpu_post_quiescence_seconds": "60", "hardcap": "100",
        })
        phases = (
            "fanout\tstart\t100.000000\t1970-01-01T00:01:40Z\n"
            "fanout\tend\t200.000000\t1970-01-01T00:03:20Z\n"
            "idle-holders\tstart\t201.000000\t1970-01-01T00:03:21Z\n"
            "idle-holders\tend\t361.000000\t1970-01-01T00:06:01Z\n"
            "idle-tail\tstart\t400.000000\t1970-01-01T00:06:40Z\n"
            "idle-tail\tend\t535.000000\t1970-01-01T00:08:55Z\n"
            "no-spin\tstart\t600.000000\t1970-01-01T00:10:00Z\n"
            "no-spin\tend\t660.000000\t1970-01-01T00:11:00Z\n"
        )
        return meta, phases

    @staticmethod
    def replay_soak_raw_pool(meta, label):
        from soak_pressure_log import flow_pool_status
        prefix = "fanout" if label == "fanout" else "idle_holders"
        target = int(meta[f"{prefix}_target"])
        hold = int(meta[f"{prefix}_hold_seconds"])
        start = 100 if label == "fanout" else 201
        end = 200 if label == "fanout" else 361
        return flow_pool_status(
            "1", meta[f"{prefix}_target"], [(start + 3, target)],
            [(start + 1, 0, 0), (start + 3, target, target), (end - 1, 0, 0)],
            40, int(meta["hardcap"]), [(start + 2, start + 2 + hold)],
            (label, start, end),
            (start + 1, 0, 0, start + 3, target, target, end - 1, 0, 0, target),
            meta[f"{prefix}_hold_seconds"],
        )

    def test_canonical_soak_actual_workload_matches_raw_replay(self):
        from soak_pressure_log import canonical_release_soak_profile_lines, release_soak_profile_issues
        meta, phases = self.canonical_soak_workload()
        self.assertEqual(release_soak_profile_issues(canonical_release_soak_profile_lines(), meta), [])
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "phases.tsv").write_text(phases)
            evidence._validate_soak_release_workload(root, meta)
            for label in ("fanout", "idle-holders"):
                self.assertEqual(self.replay_soak_raw_pool(meta, label), "1")

    def test_release_set_rejects_soak_workload_substitution_after_common_reseal(self):
        from soak_pressure_log import canonical_release_soak_profile_lines, release_soak_profile_issues
        for changes, phase_change, message in (
            ({"fanout_hold_seconds": "5"}, None, "actual workload 'fanout_hold_seconds'"),
            ({"idle_holders_hold_seconds": "5"}, None, "actual workload 'idle_holders_hold_seconds'"),
            ({"fanout_target": "1"}, None, "actual workload 'fanout_target'"),
            ({"idle_holders_target": "1"}, None, "actual workload 'idle_holders_target'"),
            ({"idle_cpu_post_quiescence_seconds": "0"}, None, "actual workload 'idle_cpu_post_quiescence_seconds'"),
            ({"hardcap": "0"}, None, "live hard cap"),
            ({}, ("200.000000\t1970-01-01T00:03:20Z", "189.999999\t1970-01-01T00:03:09Z"), "phase 'fanout' is shorter"),
            ({}, ("361.000000\t1970-01-01T00:06:01Z", "350.999999\t1970-01-01T00:05:50Z"), "phase 'idle-holders' is shorter"),
            ({}, ("535.000000\t1970-01-01T00:08:55Z", "534.999999\t1970-01-01T00:08:54Z"), "phase 'idle-tail' is shorter"),
            ({}, ("660.000000\t1970-01-01T00:11:00Z", "659.999999\t1970-01-01T00:10:59Z"), "phase 'no-spin' is shorter"),
        ):
            with self.subTest(changes=changes, phase_change=phase_change), tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary)
                soak, modern = base / "soak", base / "modern"
                make_run(soak, "soak")
                make_run(modern, "modern_udp")
                meta, phases = self.canonical_soak_workload()
                meta.update(changes)
                meta.update({key: "1" for key in (
                    "stress_ok", "fanout_established_target_sustained",
                    "idle_holders_established_target_sustained", "real_download_ok",
                    "post_wake_ok", "sleep_command_ok",
                )})
                # The configured canonical profile still passes. Actual raw
                # holder replay also accepts the shortened/weakened workload;
                # release verification must bind these two independent checks.
                self.assertEqual(release_soak_profile_issues(canonical_release_soak_profile_lines(), meta), [])
                for label in ("fanout", "idle-holders"):
                    self.assertEqual(self.replay_soak_raw_pool(meta, label), "1")
                write_tsv(soak / "run-meta.tsv", meta.items())
                for name in (
                    "soak-verdict.tsv", "system.ndjson", "probe-timeline.txt",
                    "provider-timeline.tsv", "idle-cpu-baseline.tsv", "idle-cpu-post.tsv",
                    "baseline-mem.txt", "final-mem.txt", "leaks.txt", "crashes-before.tsv",
                    "real-download.metrics", "real-download.curl.log", "real-download.txt",
                    "fanout.txt", "sleep-probes.tsv", "wake-download-headers.txt",
                    "wake-download.body", "wake-download.txt",
                    "stress/stress-manifest.tsv",
                ):
                    (soak / name).parent.mkdir(parents=True, exist_ok=True)
                    (soak / name).write_text("unused by workload configuration validation\n")
                (soak / "phases.tsv").write_text(
                    phases.replace(*phase_change) if phase_change else phases
                )
                write_tsv(soak / "stress/stress-status.tsv", [
                    ("run_uuid", str(uuid.uuid4())), ("schema_complete", "1"),
                ])
                for artifact, source in evidence.SOAK_PRODUCER_SOURCES:
                    (soak / artifact).write_bytes(Path(__file__).with_name(source).read_bytes())
                evidence.seal(soak)
                evidence.seal(modern)
                # Common diagnostic inspection remains permitted. This fixture
                # exercises the release rejection boundary, not a complete
                # signed-soak positive or unrelated forensic validators.
                self.assertEqual(evidence.verify(soak)["passed"], "1")
                with mock.patch.object(evidence, "_source_blob_at_head", side_effect=current_script_source):
                    with self.assertRaisesRegex(evidence.EvidenceError, message):
                        evidence.verify_release_set([soak, modern])

    def test_soak_release_workload_rejects_missing_ambiguous_and_weakened_requirements(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            meta, phases = self.canonical_soak_workload()
            for changed_phases in (
                phases.replace("idle-tail\tend\t535.000000\t1970-01-01T00:08:55Z\n", ""),
                phases + "idle-tail\tend\t535.000000\t1970-01-01T00:08:55Z\n",
                phases.replace("535.000000", "535.0"),
            ):
                (root / "phases.tsv").write_text(changed_phases)
                with self.assertRaisesRegex(evidence.EvidenceError, "phase.*timing boundaries"):
                    evidence._validate_soak_release_workload(root, meta)
            (root / "phases.tsv").write_text(phases)
            for changes in (
                {"fanout_hold_seconds": "5", "configured_fanout_hold_seconds": "5"},
                {"configured_idle_tail_seconds": "1"},
                {"fanout_target": None},
            ):
                with self.subTest(changes=changes), self.assertRaises(evidence.EvidenceError):
                    evidence._validate_soak_release_workload(root, dict(meta, **changes))

    def test_soak_stress_replays_raw_child_and_binds_profile_phase_and_generation(self):
        import test_stress_traffic as stress_fixtures
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            child = root / "stress"
            scripts = root / "scripts"
            scripts.mkdir()
            stress_fixtures.write_self_attested_traffic_run(
                child, monitored=True, role="unpaired-diagnostic", start=100000, end=280000,
                workload_duration=180, workload_concurrency=24,
            )
            for name in ("stress-status.tsv", "provider-identity.tsv", "provider-codesign.txt"):
                path = child / name
                path.write_text(path.read_text().replace("TEAM123", evidence.DEV_TEAM_ID))
            stress_fixtures.reseal_self_attested_traffic_run(child)
            (child / "source-signed_run_evidence.py").write_bytes(
                Path(__file__).with_name("signed_run_evidence.py").read_bytes()
            )
            write_identity(root, executable_hash="d" * 64, cdhash="e" * 40,
                           pid=42, start=90000)
            parent = dict(git_head=HEAD, git_dirty="0", run_uuid=str(uuid.uuid4()),
                          run_start_epoch_ms="99000", run_end_epoch_ms="281000")
            meta = {"stress_child_rc": "0", "configured_stress_seconds": "180",
                    "configured_stress_concurrency": "24"}
            phases = ("stress\tstart\t99.000000\t1970-01-01T00:01:39Z\n"
                      "stress\tend\t281.000000\t1970-01-01T00:04:41Z\n")
            (root / "phases.tsv").write_text(phases)
            with mock.patch.object(evidence, "_source_blob_at_head", side_effect=current_script_source):
                evidence._validate_soak_stress_artifacts(root, scripts, parent, meta)
                for changed_meta, changed_parent, message in (
                    (dict(meta, stress_child_rc="1"), parent, "exit successfully"),
                    (dict(meta, configured_stress_seconds="181"), parent, "configured release load"),
                    (meta, dict(parent, git_head="f" * 40), "generation"),
                ):
                    with self.subTest(message=message), self.assertRaisesRegex(evidence.EvidenceError, message):
                        evidence._validate_soak_stress_artifacts(root, scripts, changed_parent, changed_meta)
                (root / "phases.tsv").write_text(phases.replace("99.000000", "101.000000"))
                with self.assertRaisesRegex(evidence.EvidenceError, "declared workload phase"):
                    evidence._validate_soak_stress_artifacts(root, scripts, parent, meta)
                (root / "phases.tsv").write_text(phases)
                (child / "large_get.log").unlink()
                with self.assertRaisesRegex(evidence.EvidenceError, "raw workload"):
                    evidence._validate_soak_stress_artifacts(root, scripts, parent, meta)

    def test_soak_memory_artifacts_cannot_be_removed_failed_and_resealed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "soak"
            make_run(root, "soak")
            meta = {
                f"{prefix}_mem_{key}": value
                for prefix in ("baseline", "final")
                for key, value in (
                    ("child_rc", "0"),
                    ("joined", "1"),
                    ("forced", "0"),
                    ("privilege", "sudo"),
                )
            }
            meta.update({
                "provider_start_pid": "4242",
                "baseline_mem_sudo_rc": "0",
                "baseline_mem_ps_rc": "0",
                "baseline_mem_vmmap_rc": "0",
                "final_mem_sudo_rc": "0",
                "final_mem_ps_rc": "0",
                "final_mem_vmmap_rc": "0",
                "final_mem_heap_rc": "0",
                "final_mem_heap_filter_rc": "0",
            })
            write_tsv(root / "run-meta.tsv", meta.items())
            baseline = (
                "=== baseline provider pid=4242 @ 2026-09-05T00:00:00Z ===\n"
                "  PID    RSS      VSZ  %CPU STAT\n"
                "  4242  12000  900000   0.0 S\n"
                "\n--- vmmap --summary ---\n"
                "Process: provider [4242]\n"
                "Physical footprint: 12.0M\n"
            )
            final = (
                "=== final snapshot provider pid=4242 @ 2026-09-05T01:00:00Z ===\n"
                "  PID    RSS      VSZ  %CPU STAT\n"
                "  4242  12500  900000   0.0 S\n"
                "\n--- vmmap --summary ---\n"
                "Process: provider [4242]\n"
                "Physical footprint: 12.5M\n"
                "\n--- heap totals ---\n"
                "Process 4242: 12500 nodes malloced\n"
            )
            (root / "baseline-mem.txt").write_text(baseline)
            (root / "final-mem.txt").write_text(final)
            (root / "leaks.txt").write_text("Process 4242: 0 leaks for 0 total leaked bytes.\n")
            evidence.seal(root)
            envelope = evidence._verify_and_capture(root)
            evidence._validate_soak_memory_artifacts(envelope, root, meta)

            (root / "final-mem.txt").unlink()
            evidence.seal(root)
            stripped = evidence._verify_and_capture(root)
            with self.assertRaisesRegex(evidence.EvidenceError, "missing required"):
                evidence._validate_soak_memory_artifacts(stripped, root, meta)

            (root / "final-mem.txt").write_text(
                final.replace("Process 4242: 12500 nodes malloced", "heap unavailable")
            )
            evidence.seal(root)
            failed = evidence._verify_and_capture(root)
            with self.assertRaisesRegex(evidence.EvidenceError, "heap output"):
                evidence._validate_soak_memory_artifacts(failed, root, meta)

            (root / "final-mem.txt").write_text(
                final.replace(
                    "Process: provider [4242]\nPhysical footprint: 12.5M\n", ""
                )
            )
            evidence.seal(root)
            empty_vmmap = evidence._verify_and_capture(root)
            with self.assertRaisesRegex(evidence.EvidenceError, "vmmap|successful"):
                evidence._validate_soak_memory_artifacts(empty_vmmap, root, meta)

    def test_soak_post_boundary_forensics_bind_order_and_generation(self):
        identity = "a" * 64
        status = {"run_start_epoch_ms": "100000", "run_end_epoch_ms": "200000"}
        meta = {
            "provider_start_pid": "42",
            "provider_start_identity": identity,
            "baseline_mem_start_epoch_ms": "100100",
            "baseline_mem_end_epoch_ms": "100200",
            "baseline_mem_provider_pid": "42",
            "baseline_mem_identity_before": identity,
            "baseline_mem_identity_after": identity,
            "final_mem_start_epoch_ms": "200100",
            "final_mem_end_epoch_ms": "200200",
            "final_mem_provider_pid": "42",
            "final_mem_identity_before": identity,
            "final_mem_identity_after": identity,
            "leaks_start_epoch_ms": "200200",
            "leaks_end_epoch_ms": "200300",
            "leaks_provider_pid": "42",
            "leaks_identity_before": identity,
            "leaks_identity_after": identity,
        }
        evidence._validate_soak_post_boundary_forensics(status, meta)
        with self.assertRaisesRegex(evidence.EvidenceError, "ordering"):
            evidence._validate_soak_post_boundary_forensics(
                status, dict(meta, leaks_start_epoch_ms="200199")
            )
        with self.assertRaisesRegex(evidence.EvidenceError, "exact provider generation"):
            evidence._validate_soak_post_boundary_forensics(
                status, dict(meta, final_mem_identity_after="b" * 64)
            )

    def test_soak_generation_cannot_be_coherently_substituted_from_common_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "soak"
            make_run(root, "soak")
            identity = evidence.read_provider_identity(
                root / evidence.PROVIDER_IDENTITY_NAME
            )
            executable_name = Path(identity["running_executable_path"]).name
            meta = {
                "provider_start_pid": identity["running_pid"],
                "provider_bundle": identity["running_bundle_id"],
                "provider_binary_sha256": identity["running_executable_sha256"],
                "provider_codesign_identifier": identity["running_bundle_id"],
                "provider_codesign_cdhash": identity["running_cdhash"],
                "provider_codesign_team": identity["running_team_id"],
                "provider_start_identity": identity["provider_generation_identity"],
                "common_provider_generation_identity": identity["provider_generation_identity"],
                "provider_executable_name": executable_name,
                "crash_process_name": executable_name,
            }
            evidence._validate_soak_identity_metadata(meta, identity)
            substituted = "d" * 64
            changed = dict(
                meta,
                provider_start_identity=substituted,
                common_provider_generation_identity=substituted,
            )
            with self.assertRaisesRegex(evidence.EvidenceError, "common provider identity"):
                evidence._validate_soak_identity_metadata(changed, identity)

    def test_soak_rejects_resealed_alternate_producer_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "soak"
            root.mkdir()
            scripts = Path(__file__).resolve().parent
            for artifact, source in evidence.SOAK_PRODUCER_SOURCES:
                (root / artifact).write_bytes((scripts / source).read_bytes())
            (root / "source-signed_run_evidence.py").write_bytes(
                b"#!/usr/bin/env python3\n# alternate common helper\n"
            )
            with mock.patch.object(
                evidence, "_source_blob_at_head", side_effect=current_script_source
            ), self.assertRaisesRegex(evidence.EvidenceError, "exact evidence-head blob"):
                evidence._validate_pinned_producer_sources(
                    root, HEAD, evidence.SOAK_PRODUCER_SOURCES, "soak"
                )

    def test_release_set_rejects_claim_only_fake_stress_series(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            series = base / "series"
            modern = base / "modern"
            make_stress_series(series)
            make_run(modern, "modern_udp", claims=[
                ("dial9_diagnostic_only", "0"),
                ("dial9_workload_coverage", "1"),
                ("dial9_claim", "exact-workload"),
            ])
            evidence.seal(series)
            evidence.seal(modern)
            with self.assertRaisesRegex(evidence.EvidenceError, "stress-series evidence is missing"):
                evidence.verify_release_set([series, modern])

    def test_release_set_runs_strict_stress_comparator_after_common_reseal(self):
        import stress_compare
        import test_stress_traffic as stress_fixtures

        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            pairs = []
            for index, duration in enumerate(("0.060", "0.075", "0.050"), start=1):
                baseline = base / f"baseline-{index}"
                candidate = base / f"candidate-{index}"
                comparison = base / f"comparison-{index}.tsv"
                start = 100000 + (index - 1) * 200000
                stress_fixtures.write_self_attested_traffic_run(
                    baseline, start=start, end=start + 60000
                )
                stress_fixtures.write_self_attested_traffic_run(
                    candidate,
                    monitored=True,
                    role="proxy-candidate",
                    start=start + 100000,
                    end=start + 160000,
                    duration=duration,
                )
                stress_fixtures.add_common_stress_envelope(baseline)
                stress_fixtures.add_common_stress_envelope(candidate)
                self.assertEqual(
                    stress_compare.create_comparison(baseline, candidate, comparison), 0
                )
                pairs.append((baseline, candidate, comparison))
            series = base / "series"
            self.assertEqual(stress_compare.create_series(pairs, series), 0)
            series_status = evidence.verify(series)
            modern = base / "modern"
            make_run(
                modern,
                "modern_udp",
                executable_hash="d" * 64,
                cdhash="e" * 40,
                claims=[
                    ("dial9_diagnostic_only", "0"),
                    ("dial9_workload_coverage", "1"),
                    ("dial9_claim", "exact-workload"),
                ],
            )
            self.assertEqual(
                series_status["provider_build_identity"],
                evidence.read_status(modern)["provider_build_identity"],
            )
            evidence.seal(modern)

            comparison = series / "comparisons" / "pair-001.tsv"
            comparison.write_text(
                comparison.read_text().replace(
                    "observed_p95_ratio_milli\t1200",
                    "observed_p95_ratio_milli\t1",
                )
            )
            evidence.seal(series)

            scripts = Path(__file__).resolve().parent
            def current_source(_head, repository_relative_path):
                return (scripts / Path(repository_relative_path).name).read_bytes()

            with mock.patch.object(
                evidence, "_source_blob_at_head", side_effect=current_source
            ), mock.patch.object(evidence, "_validate_modern_semantics"):
                with self.assertRaisesRegex(
                    evidence.EvidenceError, "pinned stress-series comparator rejected"
                ):
                    evidence.verify_release_set([series, modern])

    def test_stress_series_rejects_coherently_resealed_alternate_producer(self):
        import stress_compare
        import test_stress_traffic as stress_fixtures

        def replace_value(path, key, value):
            rows = [line.split("\t", 1) for line in path.read_text().splitlines()]
            write_tsv(
                path,
                ((row_key, value if row_key == key else row_value)
                 for row_key, row_value in rows),
            )

        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            pairs = []
            members = []
            for index in range(1, 4):
                start = 100000 + (index - 1) * 200000
                baseline = base / f"baseline-{index}"
                candidate = base / f"candidate-{index}"
                comparison = base / f"comparison-{index}.tsv"
                stress_fixtures.write_self_attested_traffic_run(
                    baseline, start=start, end=start + 60000
                )
                stress_fixtures.write_self_attested_traffic_run(
                    candidate, monitored=True, role="proxy-candidate",
                    start=start + 100000, end=start + 160000,
                )
                for member in (baseline, candidate):
                    stress_fixtures.add_common_stress_envelope(member)
                    members.append(member)
                pairs.append((baseline, candidate, comparison))

            substituted = b"#!/bin/sh\nexit 0\n"
            substituted_hash = hashlib.sha256(substituted).hexdigest()
            for member in members:
                (member / "source-stress_traffic.sh").write_bytes(substituted)
                replace_value(
                    member / "stress-status.tsv", "stress_script_sha256", substituted_hash
                )
                stress_fixtures.reseal_self_attested_traffic_run(member)
                legacy = dict(
                    line.split("\t", 1)
                    for line in (member / "stress-status.tsv").read_text().splitlines()
                )
                claims = member / evidence.CLAIMS_NAME
                replace_value(claims, "stress_script_sha256", substituted_hash)
                replace_value(
                    claims, "artifact_manifest_sha256", legacy["artifact_manifest_sha256"]
                )
                common = dict(
                    line.split("\t", 1)
                    for line in (member / evidence.STATUS_NAME).read_text().splitlines()
                )
                common["workload_claims_sha256"] = evidence.sha256_file(claims)
                write_tsv(
                    member / evidence.STATUS_NAME,
                    ((key, common[key]) for key in evidence.STATUS_ORDER),
                )
                evidence.seal(member)

            for baseline, candidate, comparison in pairs:
                self.assertEqual(
                    stress_compare.create_comparison(baseline, candidate, comparison), 0
                )
            series = base / "series"
            self.assertEqual(stress_compare.create_series(pairs, series), 0)
            envelope = evidence._verify_and_capture(series)
            with mock.patch.object(
                evidence, "_source_blob_at_head", side_effect=current_script_source
            ), self.assertRaisesRegex(evidence.EvidenceError, "evidence-head"):
                evidence._validate_stress_series_semantics(envelope)

    def test_stress_series_is_self_contained_and_binds_three_generations(self):
        with tempfile.TemporaryDirectory() as temporary:
            series = Path(temporary) / "series"
            series_status = make_stress_series(series)
            evidence.seal(series)
            self.assertEqual(evidence.verify(series)["evidence_kind"], "stress-series")

    def test_stress_series_rejects_artifact_outside_six_member_prefixes(self):
        with tempfile.TemporaryDirectory() as temporary:
            series = Path(temporary) / "series"
            make_stress_series(series)
            rogue = series / "members" / "rogue.txt"
            rogue.write_text("not part of any member envelope\n")
            with self.assertRaisesRegex(
                evidence.EvidenceError, "outside its six member envelopes"
            ):
                evidence.seal(series)

    def test_stress_series_rejects_series_level_captured_crash(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            series = base / "series"
            series_status = make_stress_series(series)
            reports = base / "reports"
            reports.mkdir()
            report = reports / "provider-2026-09-05-120000.ips"
            report.write_text(
                '{"procName":"provider","procPath":"/Library/provider"}\n'
            )
            evidence.snapshot_crashes(
                int(series_status["run_start_epoch_ms"]),
                series / "crashes",
                ["provider"],
                run_uuid=series_status["run_uuid"],
                provider_generation_identity="multiple",
                report_dirs=[reports],
            )
            with self.assertRaisesRegex(evidence.EvidenceError, "contradicts captured"):
                evidence.seal(series)

    def test_soak_diagnostic_cannot_be_promoted_to_release_dial9_coverage(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            soak = base / "soak"
            stress = base / "stress"
            make_run(soak, "soak", claims=[
                ("dial9_diagnostic_only", "1"),
                ("dial9_workload_coverage", "0"),
                ("dial9_claim", "unattributed-diagnostic"),
            ])
            make_run(stress, "stress")
            evidence.seal(soak)
            evidence.seal(stress)
            with mock.patch.object(evidence, "_validate_release_kind"):
                with self.assertRaisesRegex(evidence.EvidenceError, "modern exact-workload"):
                    evidence.verify_release_set([soak, stress])


if __name__ == "__main__":
    unittest.main()
