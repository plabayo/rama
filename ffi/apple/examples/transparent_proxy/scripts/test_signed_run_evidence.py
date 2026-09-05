#!/usr/bin/env python3

import hashlib
import io
import json
import os
from pathlib import Path
import plistlib
import subprocess
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
        identity["running_command_sha256"], path_hash,
    ))
    rows = [
        ("schema_version", "1"),
        ("provider_generation_identity", status["provider_generation_identity"]),
        ("running_pid", identity["running_pid"]),
        ("running_start_epoch_ms", identity["running_start_epoch_ms"]),
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
        requirement_rows.append([
            label, "42", "7", flow_id, "2", source_pid, "1",
            "0", "65535", "0", "65535",
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
            "bytes_in": int(row["min_bytes_in"]),
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
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "modern"
                make_run(root, "modern_udp")
                mutate(root)
                with self.assertRaises(evidence.EvidenceError):
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
        ):
            with self.assertRaisesRegex(evidence.EvidenceError, "generation changed"):
                evidence.capture_provider(
                    Path("built"), Path("installed"), 42,
                    Path(temporary) / evidence.PROVIDER_IDENTITY_NAME, Path("source"),
                )

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
        ):
            with self.assertRaisesRegex(evidence.EvidenceError, "declared executable"):
                evidence.capture_provider(
                    Path("built"), Path("installed"), 42,
                    Path(temporary) / evidence.PROVIDER_IDENTITY_NAME, Path("source"),
                )


class CrashAndReleaseSetTests(unittest.TestCase):
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
