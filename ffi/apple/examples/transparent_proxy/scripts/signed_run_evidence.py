#!/usr/bin/env python3
"""Shared, fail-closed evidence envelope for signed transparent-proxy runs.

This helper proves local integrity and exact source/provider identity.  It does
not turn local files into a remotely authenticated attestation.  See ``help``
or the module-level CLI parser for the contract consumed by the live gates.
"""

from __future__ import annotations

import argparse
import csv
import ctypes
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal, InvalidOperation
import fcntl
import hashlib
import ipaddress
import io
import json
import os
from pathlib import Path, PurePosixPath
import plistlib
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import uuid


MANIFEST_NAME = "evidence-manifest.tsv"
STATUS_NAME = "evidence-status.tsv"
CLAIMS_NAME = "workload-claims.tsv"
PROVIDER_IDENTITY_NAME = "provider-identity.tsv"
SCHEMA_VERSION = 1
DEV_PROVIDER_BUNDLE_ID = "org.ramaproxy.example.tproxy.dev.provider"
DEV_TEAM_ID = "ADPG6C355H"
SHA256_RE = re.compile(r"[0-9a-f]{64}")
CDHASH_RE = re.compile(r"[0-9a-f]{40,64}")
GIT_HEAD_RE = re.compile(r"[0-9a-f]{40,64}")
KEY_RE = re.compile(r"[a-z][a-z0-9_]*")
EVIDENCE_KIND_RE = re.compile(r"[a-z][a-z0-9_-]*")
ABSENCE_NAME = "provider-absence.tsv"
ABSENCE_FIXED_ORDER = (
    "schema_version",
    "bundle_id",
    "cadence_ms",
    "max_gap_ms",
    "sample_count",
)
DEFAULT_ABSENCE_CADENCE_MS = 1000
DEFAULT_ABSENCE_MAX_GAP_MS = 2500
STATUS_ORDER = (
    "complete",
    "passed",
    "exit_code",
    "evidence_kind",
    "run_uuid",
    "run_start_epoch_ms",
    "run_end_epoch_ms",
    "git_head",
    "git_dirty",
    "provider_build_identity",
    "provider_generation_identity",
    "workload_claims_sha256",
    "schema_complete",
)
STATUS_SEMANTICS = {
    ("1", "1", "0"),       # complete product pass
    ("1", "0", "1"),       # complete product failure
    ("0", "0", "2"),       # incomplete harness/evidence failure
    ("0", "0", "130"),     # interrupted by SIGINT
    ("0", "0", "143"),     # interrupted by SIGTERM
}
SNAPSHOT_FIELDS = (
    "bundle_id",
    "git_head",
    "git_dirty",
    "team_id",
    "cdhash",
    "executable_sha256",
    "bundle_version",
    "bundle_path",
    "executable_path",
    "build_identity",
)
PROVIDER_IDENTITY_ORDER = (
    "schema_version",
    "expected_bundle_id",
    "expected_team_id",
    "source_git_head",
    "source_git_dirty",
    *(f"built_{field}" for field in SNAPSHOT_FIELDS),
    *(f"installed_{field}" for field in SNAPSHOT_FIELDS),
    *(f"running_{field}" for field in SNAPSHOT_FIELDS),
    "running_pid",
    "running_start_epoch_ms",
    "running_command",
    "running_command_sha256",
    "provider_build_identity",
    "provider_generation_identity",
    "schema_complete",
)
CRASH_SNAPSHOT_ORDER = (
    "schema_version",
    "run_uuid",
    "provider_generation_identity",
    "since_epoch_ms",
    "snapshot_epoch_ms",
    "process_names",
    "crash_count",
    "crash_names_sha256",
    "schema_complete",
)
CRASH_SCHEMA_VERSION = 2
GENERATION_SAMPLES_NAME = "provider-generation-samples.tsv"
GENERATION_FIXED_ORDER = (
    "schema_version",
    "provider_generation_identity",
    "running_pid",
    "running_start_epoch_ms",
    "running_command_sha256",
    "running_executable_path_sha256",
    "cadence_ms",
    "max_gap_ms",
    "sample_count",
)
DEFAULT_GENERATION_CADENCE_MS = 2000
DEFAULT_GENERATION_MAX_GAP_MS = 5000
MODERN_PRODUCER_SOURCES = (
    ("source-test_modern_udp_flow.sh", "test_modern_udp_flow.sh"),
    ("source-modern_udp_e2e_probe.py", "modern_udp_e2e_probe.py"),
    ("source-install_tproxy_app_bundle.sh", "install_tproxy_app_bundle.sh"),
    ("source-modern_udp_evidence.py", "modern_udp_evidence.py"),
    ("source-soak_pressure_log.py", "soak_pressure_log.py"),
    ("source-signed_run_evidence.py", "signed_run_evidence.py"),
)
SOAK_PRODUCER_SOURCES = (
    ("source-soak_test.sh", "soak_test.sh"),
    ("source-stress_traffic.sh", "stress_traffic.sh"),
    ("source-soak_pressure_log.py", "soak_pressure_log.py"),
    ("source-signed_run_evidence.py", "signed_run_evidence.py"),
)
STRESS_MEMBER_PRODUCER_SOURCES = (
    ("source-stress_traffic.sh", "stress_traffic.sh"),
    ("source-stress_evidence.py", "stress_evidence.py"),
    ("source-signed_run_evidence.py", "signed_run_evidence.py"),
)


class EvidenceError(ValueError):
    """The evidence is malformed, incomplete, inconsistent, or tampered."""


@dataclass(frozen=True)
class BundleSnapshot:
    bundle_id: str
    git_head: str
    git_dirty: str
    team_id: str
    cdhash: str
    executable_sha256: str
    bundle_version: str
    bundle_path: str
    executable_path: str
    build_identity: str


@dataclass(frozen=True)
class ProcessSnapshot:
    pid: int
    start_epoch_ms: int
    command: str
    executable_path: Path


@dataclass(frozen=True)
class VerifiedEnvelope:
    root: Path
    status: dict[str, str]
    claims: dict[str, str]
    artifacts: dict[str, tuple[int, str]]
    retained: dict[str, bytes]
    nested_statuses: tuple[dict[str, str], ...] = ()


def _canonical_uint(text: str, maximum: int = 2**64 - 1) -> int:
    if not isinstance(text, str) or re.fullmatch(r"0|[1-9][0-9]*", text) is None:
        raise EvidenceError("non-canonical integer")
    if len(text) > 20 or int(text) > maximum:
        raise EvidenceError("integer overflow")
    return int(text)


def _canonical_uuid(text: str) -> str:
    try:
        parsed = uuid.UUID(text)
    except (ValueError, AttributeError) as error:
        raise EvidenceError("invalid run UUID") from error
    if str(parsed) != text:
        raise EvidenceError("non-canonical run UUID")
    return text


def _identity_hash(domain: str, values: tuple[str, ...]) -> str:
    """Hash an unambiguous, domain-separated tuple."""
    digest = hashlib.sha256()
    digest.update(domain.encode("ascii") + b"\0")
    for value in values:
        encoded = value.encode("utf-8", errors="strict")
        digest.update(str(len(encoded)).encode("ascii") + b":" + encoded)
    return digest.hexdigest()


def provider_build_identity(
    bundle_id: str,
    git_head: str,
    team_id: str,
    cdhash: str,
    executable_sha256: str,
) -> str:
    """Return the specified exact provider-build identity."""
    return _identity_hash(
        "rama-signed-provider-build-v1",
        (bundle_id, git_head, team_id, cdhash, executable_sha256),
    )


def provider_generation_identity(
    pid: int, start_epoch_ms: int, command_sha256: str
) -> str:
    """Return the identity of one running process generation."""
    return _identity_hash(
        "rama-signed-provider-generation-v1",
        (str(pid), str(start_epoch_ms), command_sha256),
    )


def _reject_unsafe_name(name: str) -> None:
    if not name or "\t" in name or "\n" in name or "\r" in name:
        raise EvidenceError("artifact name contains unsafe characters")
    path = PurePosixPath(name)
    if path.is_absolute() or str(path) != name or any(part in ("", ".", "..") for part in path.parts):
        raise EvidenceError(f"non-canonical artifact path: {name!r}")
    if "\\" in name:
        raise EvidenceError(f"non-portable artifact path: {name!r}")


def _is_temp_name(name: str) -> bool:
    return any(".tmp." in part for part in PurePosixPath(name).parts)


def _read_regular_bytes(path: Path) -> bytes:
    """Read one stable regular file without following a final symlink."""
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        before_path = path.lstat()
        if stat.S_ISLNK(before_path.st_mode) or not stat.S_ISREG(before_path.st_mode):
            raise EvidenceError(f"not a regular file: {path}")
        descriptor = os.open(path, flags)
    except (OSError, FileNotFoundError) as error:
        raise EvidenceError(f"cannot safely open artifact: {path}") from error
    try:
        before_fd = os.fstat(descriptor)
        if not stat.S_ISREG(before_fd.st_mode):
            raise EvidenceError(f"not a regular file: {path}")
        chunks = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        after_fd = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    try:
        after_path = path.lstat()
    except OSError as error:
        raise EvidenceError(f"artifact changed while reading: {path}") from error
    identity = lambda value: (
        value.st_dev, value.st_ino, value.st_mode, value.st_size,
        value.st_mtime_ns, value.st_ctime_ns,
    )
    if identity(before_path) != identity(before_fd) \
        or identity(before_fd) != identity(after_fd) \
        or identity(after_fd) != identity(after_path):
        raise EvidenceError(f"artifact changed while reading: {path}")
    return b"".join(chunks)


def _read_regular_at(directory_fd: int, name: str, display: str) -> bytes:
    """Read a stable regular child without resolving any parent pathname."""
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if not stat.S_ISREG(before.st_mode):
            raise EvidenceError(f"not a regular file: {display}")
        descriptor = os.open(name, flags, dir_fd=directory_fd)
    except OSError as error:
        raise EvidenceError(f"cannot safely open artifact: {display}") from error
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise EvidenceError(f"not a regular file: {display}")
        chunks = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        after_opened = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    try:
        after = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except OSError as error:
        raise EvidenceError(f"artifact changed while reading: {display}") from error
    identity = lambda value: (
        value.st_dev, value.st_ino, value.st_mode, value.st_size,
        value.st_mtime_ns, value.st_ctime_ns,
    )
    if identity(before) != identity(opened) or identity(opened) != identity(after_opened) \
        or identity(after_opened) != identity(after):
        raise EvidenceError(f"artifact changed while reading: {display}")
    return b"".join(chunks)


def sha256_file(path: Path) -> str:
    return hashlib.sha256(_read_regular_bytes(Path(path))).hexdigest()


def _write_atomic(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f"{path.name}.tmp.{os.getpid()}")
    if temporary.exists() or temporary.is_symlink():
        raise EvidenceError(f"temporary output already exists: {temporary}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(temporary, flags, 0o600)
    try:
        view = memoryview(content)
        while view:
            written = os.write(descriptor, view)
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)


def _write_atomic_at(directory_fd: int, name: str, content: bytes) -> None:
    """Publish one child of a pinned directory without resolving its pathname."""
    _reject_unsafe_name(name)
    if PurePosixPath(name).name != name:
        raise EvidenceError("atomic directory output must be a direct child")
    temporary = f"{name}.tmp.{os.getpid()}"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    descriptor = os.open(temporary, flags, 0o600, dir_fd=directory_fd)
    try:
        view = memoryview(content)
        while view:
            written = os.write(descriptor, view)
            view = view[written:]
        os.fsync(descriptor)
        os.replace(temporary, name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
    finally:
        os.close(descriptor)
        try:
            os.unlink(temporary, dir_fd=directory_fd)
        except FileNotFoundError:
            pass


def _parse_tsv_bytes(
    content: bytes, *, expected_order: tuple[str, ...] | None = None
) -> tuple[dict[str, str], list[tuple[str, str]]]:
    try:
        text = content.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise EvidenceError("TSV is not UTF-8") from error
    if not text.endswith("\n") or "\r" in text:
        raise EvidenceError("TSV is truncated or has non-canonical line endings")
    rows: list[tuple[str, str]] = []
    values: dict[str, str] = {}
    for line in text.splitlines():
        fields = line.split("\t")
        if len(fields) != 2 or not all(fields) or KEY_RE.fullmatch(fields[0]) is None:
            raise EvidenceError("malformed TSV row")
        key, value = fields
        if key in values:
            raise EvidenceError(f"duplicate TSV field: {key}")
        values[key] = value
        rows.append((key, value))
    if expected_order is not None and tuple(key for key, _ in rows) != expected_order:
        raise EvidenceError("incorrect TSV field order or set")
    return values, rows


def read_status(
    directory: Path,
    actual_exit_code: int | None = None,
    *,
    artifact_bytes: dict[str, bytes] | None = None,
    artifact_index: dict[str, tuple[int, str]] | None = None,
    nested_statuses: list[dict[str, str]] | None = None,
) -> dict[str, str]:
    root = Path(directory)
    def content(name: str) -> bytes:
        if artifact_bytes is not None:
            try:
                return artifact_bytes[name]
            except KeyError as error:
                raise EvidenceError(f"required semantic artifact is missing: {name}") from error
        return _read_regular_bytes(root / name)

    def exists(name: str) -> bool:
        if artifact_index is not None:
            return name in artifact_index
        path = root / name
        return path.exists() or path.is_symlink()

    values, _ = _parse_tsv_bytes(
        content(STATUS_NAME), expected_order=STATUS_ORDER
    )
    if tuple(values[key] for key in ("complete", "passed", "exit_code")) not in STATUS_SEMANTICS:
        raise EvidenceError("untruthful status semantics")
    if actual_exit_code is not None and _canonical_uint(values["exit_code"], 255) != actual_exit_code:
        raise EvidenceError("status exit_code does not equal actual shell exit")
    complete = values["complete"] == "1"
    if EVIDENCE_KIND_RE.fullmatch(values["evidence_kind"]) is None:
        raise EvidenceError("invalid evidence kind")
    _canonical_uuid(values["run_uuid"])
    start = _canonical_uint(values["run_start_epoch_ms"])
    end = _canonical_uint(values["run_end_epoch_ms"])
    if start == 0 or end < start:
        raise EvidenceError("invalid run interval")
    if values["git_head"] != "unavailable" and GIT_HEAD_RE.fullmatch(values["git_head"]) is None:
        raise EvidenceError("git_head is not a full hexadecimal object id")
    if values["git_dirty"] not in ("0", "1", "unavailable"):
        raise EvidenceError("invalid git_dirty value")
    if complete and (
        GIT_HEAD_RE.fullmatch(values["git_head"]) is None
        or values["git_dirty"] != "0"
    ):
        raise EvidenceError("complete signed evidence requires a clean exact source tree")
    direct = values["evidence_kind"] == "stress-direct"
    series = values["evidence_kind"] == "stress-series"
    identity_values = (
        values["provider_build_identity"], values["provider_generation_identity"]
    )
    if values["workload_claims_sha256"] not in ("unavailable", "absent") \
        and SHA256_RE.fullmatch(values["workload_claims_sha256"]) is None:
        raise EvidenceError("invalid workload_claims_sha256")
    if complete and values["workload_claims_sha256"] == "unavailable":
        raise EvidenceError("complete evidence lacks workload_claims_sha256")
    identity = None
    if series:
        exact_series_identity = (
            SHA256_RE.fullmatch(values["provider_build_identity"]) is not None
            and values["provider_generation_identity"] == "multiple"
        )
        unavailable_series_identity = identity_values == ("unavailable", "unavailable")
        if not exact_series_identity and not (
            not complete and unavailable_series_identity
        ):
            raise EvidenceError("stress-series must declare one build and multiple generations")
    else:
        for key in ("provider_build_identity", "provider_generation_identity"):
            if values[key] not in ("unavailable", "absent") \
                and SHA256_RE.fullmatch(values[key]) is None:
                raise EvidenceError(f"invalid {key}")
            if complete and values[key] == "unavailable":
                raise EvidenceError(f"complete evidence lacks {key}")
    if complete and direct and identity_values != ("absent", "absent"):
        raise EvidenceError("stress-direct must declare the provider absent")
    if complete and not direct and not series and "absent" in identity_values:
        raise EvidenceError("provider-attributed evidence cannot declare provider absent")
    if values["workload_claims_sha256"] == "absent":
        raise EvidenceError("workload claims cannot be absent")
    if values["schema_complete"] != "1":
        raise EvidenceError("status is not complete")
    claims_path = root / CLAIMS_NAME
    if values["workload_claims_sha256"] == "unavailable":
        if exists(CLAIMS_NAME):
            raise EvidenceError("unavailable workload claims unexpectedly exist")
    else:
        claims_bytes = content(CLAIMS_NAME)
        claims, rows = _parse_tsv_bytes(claims_bytes)
        if not rows or rows[0] != ("evidence_kind", values["evidence_kind"]):
            raise EvidenceError("workload claims are not bound to evidence kind")
        if rows[-1] != ("schema_complete", "1"):
            raise EvidenceError("workload claims are truncated")
        if hashlib.sha256(claims_bytes).hexdigest() != values["workload_claims_sha256"]:
            raise EvidenceError("workload claims hash mismatch")
        if claims.get("run_uuid") != values["run_uuid"]:
            raise EvidenceError("workload claims run UUID mismatch")
    identity_path = root / PROVIDER_IDENTITY_NAME
    identities_available = all(
        value not in ("unavailable", "absent", "multiple") for value in identity_values
    )
    if series:
        if exists(PROVIDER_IDENTITY_NAME):
            raise EvidenceError("stress-series cannot claim one root provider identity")
    elif (
        values["provider_build_identity"] in ("unavailable", "absent")
    ) != (
        values["provider_generation_identity"] in ("unavailable", "absent")
    ):
        raise EvidenceError("provider identities are only partially available")
    elif not identities_available:
        if exists(PROVIDER_IDENTITY_NAME):
            raise EvidenceError("unavailable provider identity unexpectedly exists")
    else:
        identity = read_provider_identity_bytes(content(PROVIDER_IDENTITY_NAME))
        if identity["source_git_head"] != values["git_head"]:
            raise EvidenceError("status/provider git head mismatch")
        if identity["source_git_dirty"] != values["git_dirty"]:
            raise EvidenceError("status/provider git dirty mismatch")
        if identity["provider_build_identity"] != values["provider_build_identity"]:
            raise EvidenceError("status/provider build identity mismatch")
        if identity["provider_generation_identity"] != values["provider_generation_identity"]:
            raise EvidenceError("status/provider generation identity mismatch")
        if _canonical_uint(identity["running_start_epoch_ms"]) > end:
            raise EvidenceError("provider generation starts after the evidence run ended")
    absence_path = root / ABSENCE_NAME
    if direct:
        if complete:
            if claims.get("provider_absent") != "1":
                raise EvidenceError("stress-direct claims do not assert provider absence")
            verify_provider_absence(
                absence_path,
                run_start_epoch_ms=start,
                run_end_epoch_ms=end,
                content=content(ABSENCE_NAME),
            )
    elif not series and exists(ABSENCE_NAME):
        raise EvidenceError("provider-attributed evidence contains absence proof")
    if complete and series:
        if artifact_bytes is None or artifact_index is None:
            raise EvidenceError("stress-series requires one captured recursive artifact snapshot")
        members = _verify_stress_series_members(
            values,
            claims,
            artifact_bytes,
            artifact_index,
        )
        if nested_statuses is not None:
            nested_statuses.extend(members)
    crash_snapshot_epoch = _verify_crash_snapshots(
        root,
        values,
        artifact_bytes=artifact_bytes,
        artifact_index=artifact_index,
        ignore_member_snapshots=series,
        required=complete and values["evidence_kind"] in {
            "modern_udp", "soak", "stress-direct", "stress-candidate",
        },
    )
    if complete and values["evidence_kind"] in {
        "modern_udp", "soak", "stress-candidate",
    }:
        if identity is None:
            raise EvidenceError("provider generation samples lack a provider identity")
        verify_provider_generation_samples(
            content(GENERATION_SAMPLES_NAME),
            identity,
            run_start_epoch_ms=start,
            run_end_epoch_ms=end,
            required_through_epoch_ms=crash_snapshot_epoch,
        )
    return values


def _retain_semantic_artifact(name: str) -> bool:
    return PurePosixPath(name).name in {
        STATUS_NAME,
        CLAIMS_NAME,
        PROVIDER_IDENTITY_NAME,
        ABSENCE_NAME,
        MANIFEST_NAME,
        "crash-snapshot.tsv",
        GENERATION_SAMPLES_NAME,
    }


@contextmanager
def _directory_fd(directory: Path):
    """Pin the root and its parent entries while allowing existing OS aliases."""
    supplied = Path(directory).absolute()
    descriptors = []
    entries = []
    identity = lambda value: (value.st_dev, value.st_ino, value.st_mode)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    try:
        before = supplied.lstat()
        if not stat.S_ISDIR(before.st_mode):
            raise EvidenceError("evidence root is not a real directory")
        # Resolve pre-existing parent aliases such as macOS /var -> /private/var,
        # but never resolve the checked root itself. Pin every resulting path
        # component with openat and cross-check the originally observed root.
        canonical = supplied.parent.resolve(strict=True) / supplied.name
        descriptor = os.open(canonical.anchor, flags)
        descriptors.append(descriptor)
        for component in canonical.parts[1:]:
            observed = os.stat(component, dir_fd=descriptor, follow_symlinks=False)
            child = os.open(component, flags, dir_fd=descriptor)
            descriptors.append(child)
            opened = os.fstat(child)
            if identity(observed) != identity(opened):
                raise EvidenceError("evidence parent changed while opening root")
            entries.append((descriptor, component, opened))
            descriptor = child
        opened_root = os.fstat(descriptor)
        if identity(before) != identity(opened_root):
            raise EvidenceError("evidence root changed before traversal")
        yield descriptor
        if identity(supplied.lstat()) != identity(opened_root):
            raise EvidenceError("evidence root changed during traversal")
        for parent_fd, component, opened in reversed(entries):
            after = os.stat(component, dir_fd=parent_fd, follow_symlinks=False)
            if identity(after) != identity(opened):
                raise EvidenceError("evidence parent changed during traversal")
    except OSError as error:
        raise EvidenceError("cannot safely open or recheck evidence root") from error
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _manifest_artifacts(
    directory: Path,
    *,
    directory_fd: int | None = None,
) -> tuple[dict[str, tuple[int, str]], dict[str, bytes]]:
    artifacts: dict[str, tuple[int, str]] = {}
    retained: dict[str, bytes] = {}
    directory_flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        directory_flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        directory_flags |= os.O_NOFOLLOW

    def walk(directory_fd: int, prefix: str) -> None:
        try:
            initial_names = sorted(os.listdir(directory_fd))
        except OSError as error:
            raise EvidenceError(f"cannot enumerate evidence directory: {prefix or '.'}") from error
        for name in initial_names:
            relative = f"{prefix}/{name}" if prefix else name
            _reject_unsafe_name(relative)
            if _is_temp_name(relative):
                raise EvidenceError(f"temporary artifact present: {relative}")
            try:
                before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            except OSError as error:
                raise EvidenceError(f"artifact changed during traversal: {relative}") from error
            if stat.S_ISDIR(before.st_mode):
                try:
                    child_fd = os.open(name, directory_flags, dir_fd=directory_fd)
                except OSError as error:
                    raise EvidenceError(f"cannot safely open directory: {relative}") from error
                try:
                    opened = os.fstat(child_fd)
                    if (before.st_dev, before.st_ino, before.st_mode) != (
                        opened.st_dev, opened.st_ino, opened.st_mode
                    ):
                        raise EvidenceError(f"directory changed during traversal: {relative}")
                    walk(child_fd, relative)
                finally:
                    os.close(child_fd)
                try:
                    after = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                except OSError as error:
                    raise EvidenceError(f"directory changed during traversal: {relative}") from error
                if (opened.st_dev, opened.st_ino, opened.st_mode) != (
                    after.st_dev, after.st_ino, after.st_mode
                ):
                    raise EvidenceError(f"directory changed during traversal: {relative}")
            elif stat.S_ISREG(before.st_mode):
                content = _read_regular_at(directory_fd, name, relative)
                if relative == MANIFEST_NAME:
                    retained[MANIFEST_NAME] = content
                    continue
                artifacts[relative] = (
                    len(content), hashlib.sha256(content).hexdigest()
                )
                if _retain_semantic_artifact(relative):
                    retained[relative] = content
            elif stat.S_ISLNK(before.st_mode):
                raise EvidenceError(f"symlink artifact present: {relative}")
            else:
                raise EvidenceError(f"non-regular artifact present: {relative}")
        try:
            if sorted(os.listdir(directory_fd)) != initial_names:
                raise EvidenceError(f"evidence directory changed during traversal: {prefix or '.'}")
        except OSError as error:
            raise EvidenceError(f"cannot recheck evidence directory: {prefix or '.'}") from error

    if directory_fd is None:
        with _directory_fd(Path(directory)) as root_fd:
            walk(root_fd, "")
    else:
        walk(directory_fd, "")
    return artifacts, retained


def seal(directory: Path, actual_exit_code: int | None = None) -> str:
    """Write a deterministic recursive manifest and return its SHA-256."""
    root = Path(directory)
    with _directory_fd(root) as root_fd:
        artifacts, retained = _manifest_artifacts(root, directory_fd=root_fd)
        read_status(
            root,
            actual_exit_code=actual_exit_code,
            artifact_bytes=retained,
            artifact_index=artifacts,
        )
        if MANIFEST_NAME in artifacts:
            raise EvidenceError("manifest cannot contain itself")
        content = "".join(
            f"{digest}\t{size}\t{name}\n"
            for name, (size, digest) in sorted(artifacts.items())
        ).encode("utf-8")
        _write_atomic_at(root_fd, MANIFEST_NAME, content)
    return hashlib.sha256(content).hexdigest()


def _read_manifest(path: Path) -> dict[str, tuple[int, str]]:
    return _read_manifest_bytes(_read_regular_bytes(path))


def _read_manifest_bytes(content: bytes) -> dict[str, tuple[int, str]]:
    try:
        text = content.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise EvidenceError("manifest is not UTF-8") from error
    if not text or not text.endswith("\n") or "\r" in text:
        raise EvidenceError("manifest is empty or truncated")
    artifacts: dict[str, tuple[int, str]] = {}
    previous = None
    for line in text.splitlines():
        fields = line.split("\t")
        if len(fields) != 3:
            raise EvidenceError("malformed manifest row")
        digest, size_text, name = fields
        _reject_unsafe_name(name)
        if name == MANIFEST_NAME or _is_temp_name(name):
            raise EvidenceError("manifest names a forbidden artifact")
        if SHA256_RE.fullmatch(digest) is None:
            raise EvidenceError("malformed manifest digest")
        size = _canonical_uint(size_text)
        if name in artifacts or (previous is not None and name <= previous):
            raise EvidenceError("manifest is duplicated or unsorted")
        artifacts[name] = (size, digest)
        previous = name
    return artifacts


def _verify_captured_envelope(
    prefix: str,
    artifact_index: dict[str, tuple[int, str]],
    artifact_bytes: dict[str, bytes],
) -> dict[str, str]:
    """Verify a nested envelope solely from the parent scan's captured bytes."""
    prefix = prefix.rstrip("/") + "/"
    manifest_key = prefix + MANIFEST_NAME
    try:
        expected = _read_manifest_bytes(artifact_bytes[manifest_key])
    except KeyError as error:
        raise EvidenceError(f"nested envelope lacks retained manifest: {prefix}") from error
    actual = {
        name[len(prefix):]: metadata
        for name, metadata in artifact_index.items()
        if name.startswith(prefix) and name != manifest_key
    }
    # Do not let a sibling directory masquerade as part of this child.  Every
    # captured path below the child prefix must be named by the child manifest.
    if set(actual) != set(expected):
        raise EvidenceError(f"nested envelope artifact set mismatch: {prefix}")
    for name in expected:
        if actual[name] != expected[name]:
            raise EvidenceError(f"nested envelope artifact mismatch: {prefix}{name}")
    retained = {
        name[len(prefix):]: content
        for name, content in artifact_bytes.items()
        if name.startswith(prefix) and name != manifest_key
    }
    return read_status(
        Path(prefix), artifact_bytes=retained, artifact_index=actual
    )


def _verify_stress_series_members(
    series_status: dict[str, str],
    series_claims: dict[str, str],
    artifact_bytes: dict[str, bytes],
    artifact_index: dict[str, tuple[int, str]],
) -> list[dict[str, str]]:
    if series_claims.get("pair_count") != "3":
        raise EvidenceError("stress-series must claim exactly three pairs")
    manifest_pattern = re.compile(
        r"members/pair-([0-9]{3})/(baseline|candidate)/"
        + re.escape(MANIFEST_NAME)
        + r"\Z"
    )
    member_keys = []
    for name in artifact_index:
        match = manifest_pattern.fullmatch(name)
        if match is not None:
            member_keys.append((int(match.group(1)), match.group(2), name))
    expected_roles = [
        (pair, role)
        for pair in range(1, 4)
        for role in ("baseline", "candidate")
    ]
    allowed_prefixes = tuple(
        f"members/pair-{pair:03d}/{role}/"
        for pair, role in expected_roles
    )
    unexpected_member_artifacts = sorted(
        name for name in artifact_index
        if name.startswith("members/")
        and not name.startswith(allowed_prefixes)
    )
    if unexpected_member_artifacts:
        raise EvidenceError(
            "stress-series contains artifacts outside its six member envelopes: "
            + ", ".join(unexpected_member_artifacts)
        )
    observed_roles = sorted((pair, role) for pair, role, _ in member_keys)
    if observed_roles != expected_roles:
        raise EvidenceError("stress-series members are not exactly three ordered pairs")
    statuses = []
    for pair, role, _ in sorted(member_keys):
        prefix = f"members/pair-{pair:03d}/{role}"
        status = _verify_captured_envelope(prefix, artifact_index, artifact_bytes)
        expected_kind = "stress-direct" if role == "baseline" else "stress-candidate"
        if status["evidence_kind"] != expected_kind:
            raise EvidenceError(f"stress-series {prefix} has the wrong evidence kind")
        if (status["complete"], status["passed"], status["exit_code"]) != ("1", "1", "0"):
            raise EvidenceError(f"stress-series {prefix} is not a passing member")
        statuses.append(status)
    if len({status["run_uuid"] for status in statuses}) != 6:
        raise EvidenceError("stress-series member UUIDs are not unique")
    if any(status["git_head"] != series_status["git_head"] for status in statuses):
        raise EvidenceError("stress-series member git head mismatch")
    baselines = statuses[0::2]
    candidates = statuses[1::2]
    if any(
        status["provider_build_identity"] != "absent"
        or status["provider_generation_identity"] != "absent"
        for status in baselines
    ):
        raise EvidenceError("stress-series baseline did not prove provider absence")
    if any(
        status["provider_build_identity"] != series_status["provider_build_identity"]
        for status in candidates
    ):
        raise EvidenceError("stress-series candidate build mismatch")
    generations = sorted(status["provider_generation_identity"] for status in candidates)
    if len(set(generations)) != 3:
        raise EvidenceError("stress-series requires three distinct candidate generations")
    generation_hash = hashlib.sha256(
        "".join(f"{generation}\n" for generation in generations).encode("ascii")
    ).hexdigest()
    if series_claims.get("candidate_generation_identities_sha256") != generation_hash:
        raise EvidenceError("stress-series candidate generation-set hash mismatch")
    member_start = min(_canonical_uint(status["run_start_epoch_ms"]) for status in statuses)
    member_end = max(_canonical_uint(status["run_end_epoch_ms"]) for status in statuses)
    if (
        _canonical_uint(series_status["run_start_epoch_ms"]) > member_start
        or _canonical_uint(series_status["run_end_epoch_ms"]) < member_end
    ):
        raise EvidenceError("stress-series interval does not contain its members")
    return statuses


def verify(directory: Path, actual_exit_code: int | None = None) -> dict[str, str]:
    """Verify the sealed directory exactly, including extra-file rejection."""
    status, _ = _verify_and_read(directory, actual_exit_code)
    return status


def _verify_and_read(
    directory: Path, actual_exit_code: int | None = None
) -> tuple[dict[str, str], dict[str, str]]:
    """Verify once and return status/claims from that same artifact scan."""
    verified = _verify_and_capture(directory, actual_exit_code)
    return verified.status, verified.claims


def _verify_and_capture(
    directory: Path, actual_exit_code: int | None = None
) -> VerifiedEnvelope:
    """Verify once and retain the exact scan used by semantic validators."""
    root = Path(directory)
    actual, retained = _manifest_artifacts(root)
    try:
        expected = _read_manifest_bytes(retained[MANIFEST_NAME])
    except KeyError as error:
        raise EvidenceError("evidence manifest is missing") from error
    if set(expected) != set(actual):
        missing = sorted(set(expected) - set(actual))
        extra = sorted(set(actual) - set(expected))
        raise EvidenceError(f"manifest artifact set mismatch: missing={missing} extra={extra}")
    for name in sorted(expected):
        if actual[name] != expected[name]:
            raise EvidenceError(f"artifact size/hash mismatch: {name}")
    nested_statuses: list[dict[str, str]] = []
    status = read_status(
        root,
        actual_exit_code=actual_exit_code,
        artifact_bytes=retained,
        artifact_index=actual,
        nested_statuses=nested_statuses,
    )
    if status["workload_claims_sha256"] == "unavailable":
        claims = {}
    else:
        claims, _ = _parse_tsv_bytes(retained[CLAIMS_NAME])
    return VerifiedEnvelope(
        root, status, claims, actual, retained, tuple(nested_statuses)
    )


def verify_release_set(
    directories: list[Path], required_kinds: set[str] | None = None
) -> list[dict[str, str]]:
    """Verify passing runs came from one clean source and provider generation."""
    if len(directories) < 2:
        raise EvidenceError("release set requires at least two evidence directories")
    verified = [_verify_and_capture(Path(directory)) for directory in directories]
    statuses = [envelope.status for envelope in verified]
    if any((row["complete"], row["passed"], row["exit_code"]) != ("1", "1", "0") for row in statuses):
        raise EvidenceError("release set contains a non-passing run")
    for field in ("git_head", "git_dirty"):
        if len({row[field] for row in statuses}) != 1:
            raise EvidenceError(f"release set {field} mismatch")
    provider_build_statuses = [
        row for row in statuses if row["evidence_kind"] != "stress-direct"
    ]
    if not provider_build_statuses:
        raise EvidenceError("release set has no provider-attributed run")
    if len({row["provider_build_identity"] for row in provider_build_statuses}) != 1:
        raise EvidenceError("release set provider_build_identity mismatch")
    provider_generation_statuses = [
        row for row in provider_build_statuses
        if row["evidence_kind"] != "stress-series"
    ]
    if not provider_generation_statuses:
        raise EvidenceError("release set has no single provider generation evidence")
    if len({row["provider_generation_identity"] for row in provider_generation_statuses}) != 1:
        raise EvidenceError("release set provider_generation_identity mismatch")
    kinds = [row["evidence_kind"] for row in statuses]
    run_uuids = [
        row["run_uuid"]
        for envelope in verified
        for row in (envelope.status, *envelope.nested_statuses)
    ]
    if len(set(kinds)) != len(kinds):
        raise EvidenceError("release set contains duplicate evidence kinds")
    if len(set(run_uuids)) != len(run_uuids):
        raise EvidenceError("release set contains a duplicate top-level or nested run UUID")
    if required_kinds is not None and set(kinds) != required_kinds:
        raise EvidenceError(
            f"release set kind mismatch: expected={sorted(required_kinds)} actual={sorted(kinds)}"
        )
    for envelope in verified:
        _validate_release_kind(envelope)
    claims_by_kind = {
        envelope.status["evidence_kind"]: envelope.claims
        for envelope in verified
    }
    dial9_owners = []
    for kind, claims in claims_by_kind.items():
        diagnostic = claims.get("dial9_diagnostic_only")
        coverage = claims.get("dial9_workload_coverage")
        claim = claims.get("dial9_claim")
        if diagnostic == "1" and (coverage != "0" or claim != "unattributed-diagnostic"):
            raise EvidenceError(f"{kind} has contradictory diagnostic-only Dial9 claims")
        if coverage == "1" and claim == "exact-workload":
            dial9_owners.append(kind)
    if len(dial9_owners) != 1 or "modern" not in dial9_owners[0]:
        raise EvidenceError("release set lacks one modern exact-workload Dial9 proof")
    return statuses


def _required_artifacts(
    envelope: VerifiedEnvelope, names: tuple[str, ...], label: str
) -> None:
    missing = [name for name in names if name not in envelope.artifacts]
    if missing:
        raise EvidenceError(f"{label} evidence is missing required artifacts: {missing}")


def _manifest_content(artifacts: dict[str, tuple[int, str]]) -> bytes:
    return "".join(
        f"{digest}\t{size}\t{name}\n"
        for name, (size, digest) in sorted(artifacts.items())
    ).encode("utf-8")


def _materialize_verified_envelope(
    envelope: VerifiedEnvelope, destination: Path
) -> None:
    """Copy only bytes matching the already-verified artifact snapshot."""
    destination.mkdir()
    for name, (expected_size, expected_digest) in sorted(envelope.artifacts.items()):
        content = envelope.retained.get(name)
        if content is None:
            content = _read_regular_bytes(envelope.root / name)
        if (
            len(content) != expected_size
            or hashlib.sha256(content).hexdigest() != expected_digest
        ):
            raise EvidenceError(
                f"artifact changed while preparing semantic validation: {name}"
            )
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        _write_atomic(target, content)
    _write_atomic(destination / MANIFEST_NAME, _manifest_content(envelope.artifacts))


def _source_blob_at_head(git_head: str, repository_relative_path: str) -> bytes:
    if GIT_HEAD_RE.fullmatch(git_head) is None:
        raise EvidenceError("cannot load a validator for an invalid git head")
    _reject_unsafe_name(repository_relative_path)
    try:
        repository = _run(
            ["git", "-C", str(Path(__file__).resolve().parent), "rev-parse", "--show-toplevel"]
        ).stdout.strip()
        result = subprocess.run(
            ["git", "-C", repository, "show", f"{git_head}:{repository_relative_path}"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={**os.environ, "LC_ALL": "C"},
        )
    except (OSError, subprocess.CalledProcessError) as error:
        raise EvidenceError(
            f"cannot load {repository_relative_path} from evidence git head"
        ) from error
    if not result.stdout:
        raise EvidenceError(f"empty validator source at evidence git head: {repository_relative_path}")
    current_path = Path(repository) / repository_relative_path
    current_source = _read_regular_bytes(current_path)
    if current_source != result.stdout:
        raise EvidenceError(
            f"current semantic validator is not the exact evidence-head source: "
            f"{repository_relative_path}"
        )
    return current_source


def _validate_pinned_producer_sources(
    root: Path,
    git_head: str,
    sources: tuple[tuple[str, str], ...],
    label: str,
) -> dict[str, bytes]:
    """Require every sealed producer copy to equal the exact evidence-head blob."""
    validated: dict[str, bytes] = {}
    for artifact_name, source_name in sources:
        repository_path = (
            "ffi/apple/examples/transparent_proxy/scripts/" + source_name
        )
        expected = _source_blob_at_head(git_head, repository_path)
        actual = _read_regular_bytes(root / artifact_name)
        if actual != expected:
            raise EvidenceError(
                f"sealed {label} producer source is not the exact evidence-head "
                f"blob: {artifact_name}"
            )
        validated[artifact_name] = actual
    return validated


def _producer_sources_sha256(sources: dict[str, bytes]) -> str:
    digest = hashlib.sha256()
    for name in sorted(sources):
        content = sources[name]
        digest.update(name.encode("utf-8") + b"\0")
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest()


def _run_python_validator(
    arguments: list[str], *, timeout: int = 120
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            [sys.executable, *arguments],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="strict",
            timeout=timeout,
            env={**os.environ, "LC_ALL": "C", "PYTHONDONTWRITEBYTECODE": "1"},
        )
    except (OSError, subprocess.TimeoutExpired, UnicodeError) as error:
        raise EvidenceError("workload-specific semantic validator could not run") from error


def _validate_modern_domain_semantics(parser_path: Path, root: Path) -> None:
    result = _run_python_validator(
        [str(parser_path), "verify-bundle", str(root)], timeout=180
    )
    if result.returncode != 0 or result.stdout != "0\n":
        detail = (result.stderr or result.stdout).strip()
        raise EvidenceError(
            f"pinned modern raw-bundle validator rejected sealed semantics: {detail}"
        )


def _json_object(content: bytes, label: str) -> dict:
    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise EvidenceError(f"{label} contains duplicate JSON key {key!r}")
            result[key] = value
        return result

    try:
        value = json.loads(
            content.decode("utf-8", errors="strict"), object_pairs_hook=unique_object
        )
    except (UnicodeError, ValueError, RecursionError) as error:
        raise EvidenceError(f"{label} is malformed JSON") from error
    if not isinstance(value, dict):
        raise EvidenceError(f"{label} is not a JSON object")
    return value


def _strict_tsv_values(content: bytes, label: str) -> tuple[dict[str, str], list[tuple[str, str]]]:
    try:
        return _parse_tsv_bytes(content)
    except EvidenceError as error:
        raise EvidenceError(f"{label} is malformed: {error}") from error


def _validate_modern_echo(
    root: Path, udp: dict[str, str], run_uuid: str
) -> list[tuple[int, int, str]]:
    client = _json_object(
        _read_regular_bytes(root / "controlled-echo-client.json"),
        "modern echo client",
    )
    server = _json_object(
        _read_regular_bytes(root / "controlled-echo-server.json"),
        "modern echo server",
    )
    expected = _canonical_uint(udp["echo_expected_count"], 65_536)
    sockets = _canonical_uint(udp["echo_socket_count"], 512)
    per_socket = _canonical_uint(udp["echo_datagrams_per_socket"], 64)
    payload_bytes = _canonical_uint(udp["echo_payload_bytes"], 65_535)
    digest = udp["echo_payload_set_sha256"]
    endpoint = udp["echo_endpoint"]
    flow_count = _canonical_uint(udp["echo_flow_count"], 512)
    if expected != sockets * per_socket or flow_count != sockets:
        raise EvidenceError("modern echo cardinality arithmetic mismatch")
    for value, kind in (
        (client, "controlled_echo_client"),
        (server, "controlled_echo_server"),
    ):
        if (
            value.get("schema_version") != 1
            or value.get("schema_complete") is not True
            or value.get("kind") != kind
            or value.get("run_uuid") != run_uuid
            or value.get("endpoint") != endpoint
            or value.get("expected_count") != expected
            or value.get("passed") is not True
        ):
            raise EvidenceError(f"modern {kind} identity/result mismatch")
    if any(
        client.get(key) != expected
        for key in ("sent_count", "received_count", "exact_echo_count", "unique_echo_count")
    ) or any(
        server.get(key) != expected for key in ("received_count", "echo_count")
    ):
        raise EvidenceError("modern echo result cardinality mismatch")
    local_endpoints = client.get("local_endpoints")
    if (
        client.get("socket_count") != sockets
        or client.get("independent_socket_count") != sockets
        or client.get("datagrams_per_socket") != per_socket
        or client.get("payload_bytes") != payload_bytes
        or client.get("error_count") != 0
        or server.get("duplicate_count") != 0
        or server.get("malformed_count") != 0
        or client.get("payload_set_sha256") != digest
        or client.get("echo_set_sha256") != digest
        or server.get("payload_set_sha256") != digest
    ):
        raise EvidenceError("modern echo payload/independent-socket proof mismatch")
    if (
        not isinstance(local_endpoints, list)
        or len(local_endpoints) != sockets
        or any(not isinstance(value, str) for value in local_endpoints)
        or local_endpoints != sorted(set(local_endpoints))
    ):
        raise EvidenceError("modern echo client local endpoints are not canonical/distinct")
    for value in local_endpoints:
        try:
            host, port = (
                value[1:].split("]:", 1)
                if value.startswith("[")
                else value.rsplit(":", 1)
            )
            if str(ipaddress.ip_address(host)) != host or not 1 <= int(port) <= 65535:
                raise ValueError
        except (TypeError, ValueError) as error:
            raise EvidenceError("modern echo client local endpoint is malformed") from error
    endpoint_digest = hashlib.sha256(
        "\n".join(local_endpoints).encode("utf-8")
    ).hexdigest()
    if client.get("local_endpoint_set_sha256") != endpoint_digest:
        raise EvidenceError("modern echo client local endpoint digest mismatch")

    try:
        identity_text = _read_regular_bytes(root / "echo-identities.tsv").decode(
            "utf-8", errors="strict"
        )
    except UnicodeError as error:
        raise EvidenceError("modern echo identities are not UTF-8 text") from error
    if not identity_text.endswith("\n"):
        raise EvidenceError("modern echo identities are truncated")
    rows = identity_text.splitlines()
    if len(rows) != sockets:
        raise EvidenceError("modern echo identity cardinality mismatch")
    identities: list[tuple[int, int, str]] = []
    for row in rows:
        fields = row.split("\t")
        if len(fields) != 3:
            raise EvidenceError("modern echo identity row is malformed")
        generation = _canonical_uint(fields[0])
        flow_id = _canonical_uint(fields[1])
        if generation == 0 or flow_id == 0 or fields[2] not in local_endpoints:
            raise EvidenceError("modern echo identity row is not exact")
        identities.append((generation, flow_id, fields[2]))
    if (
        identities != sorted(identities, key=lambda value: value[1])
        or len({generation for generation, _, _ in identities}) != 1
        or len({flow_id for _, flow_id, _ in identities}) != sockets
        or {local for _, _, local in identities} != set(local_endpoints)
    ):
        raise EvidenceError("modern echo endpoint/flow identity mapping is not bijective")
    return identities


@contextmanager
def _protected_build_source(source: Path):
    """Protect source contents and directory entries while the compiler runs.

    The sibling target must already exist. Permissions provide local mutation
    protection; they do not authenticate an owner who can reset mode bits.
    """
    paths = [source, *source.rglob("*"), source.parent]
    modes = [(path, stat.S_IMODE(path.stat().st_mode)) for path in paths]
    try:
        for path, mode in modes:
            path.chmod(mode & ~0o222)
        yield
    finally:
        for path, mode in reversed(modes):
            path.chmod(mode)


def _build_pinned_dial9_binary(git_head: str, build_root: Path) -> Path:
    """Build the decoder in an isolated target from an exact clean checkout."""
    script_directory = Path(__file__).resolve().parent
    repository = Path(
        _run(["git", "-C", str(script_directory), "rev-parse", "--show-toplevel"])
        .stdout.strip()
    )
    current_head = _run(["git", "-C", str(repository), "rev-parse", "HEAD"]).stdout.strip()
    dirty = _run(
        ["git", "-C", str(repository), "status", "--porcelain", "--untracked-files=all"]
    ).stdout
    if current_head != git_head or dirty:
        raise EvidenceError(
            "Dial9 replay requires a clean verifier checkout at the evidence git head"
        )
    try:
        archived = subprocess.run(
            ["git", "-C", str(repository), "archive", "--format=tar", git_head],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ).stdout
    except (OSError, subprocess.CalledProcessError) as error:
        raise EvidenceError("cannot archive the pinned Dial9 verifier source") from error
    source = build_root / "source"
    source.mkdir()
    seen = set()
    try:
        with tarfile.open(fileobj=io.BytesIO(archived), mode="r:") as archive:
            for member in archive:
                name = member.name.rstrip("/")
                _reject_unsafe_name(name)
                if name in seen or not (member.isfile() or member.isdir()):
                    raise EvidenceError("unsafe entry in pinned verifier source archive")
                seen.add(name)
                target_path = source / name
                if member.isdir():
                    if target_path.exists() and not target_path.is_dir():
                        raise EvidenceError("file/directory collision in verifier source archive")
                    target_path.mkdir(parents=True, exist_ok=True)
                    continue
                target_path.parent.mkdir(parents=True, exist_ok=True)
                extracted = archive.extractfile(member)
                if extracted is None:
                    raise EvidenceError("missing file body in pinned verifier source archive")
                _write_atomic(target_path, extracted.read())
                target_path.chmod(member.mode & 0o777)
    except (tarfile.TarError, OSError) as error:
        raise EvidenceError("cannot materialize pinned Dial9 verifier source") from error
    del archived
    cargo = shutil.which("cargo")
    if cargo is None:
        raise EvidenceError("cargo is unavailable for pinned Dial9 replay")
    manifest = source / "ffi/apple/examples/transparent_proxy/tproxy_rs/Cargo.toml"
    target = build_root / "cargo-target"
    target.mkdir()
    try:
        with _protected_build_source(source):
            result = subprocess.run(
                [
                    cargo, "build", "--locked", "--offline", "--manifest-path",
                    str(manifest), "--bin", "dial9_evidence",
                ],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="strict",
                timeout=900,
                env={
                    **os.environ,
                    "CARGO_NET_OFFLINE": "true",
                    "CARGO_TARGET_DIR": str(target),
                    "LC_ALL": "C",
                },
            )
    except (OSError, subprocess.TimeoutExpired, UnicodeError) as error:
        raise EvidenceError("could not build the pinned Dial9 decoder") from error
    if result.returncode != 0:
        raise EvidenceError(
            f"could not build the pinned Dial9 decoder: {result.stderr.strip()}"
        )
    binary = target / "debug" / "dial9_evidence"
    if not binary.is_file() or binary.is_symlink():
        raise EvidenceError("pinned Dial9 decoder build produced no regular executable")
    return binary


def _verify_pinned_dial9_replay(root: Path, git_head: str) -> None:
    """Decode the sealed trace set afresh and match its derived summary."""
    with tempfile.TemporaryDirectory(prefix="rama-dial9-replay.") as temporary:
        work = Path(temporary)
        binary = _build_pinned_dial9_binary(git_head, work)
        destination = work / "decoded-traces"
        try:
            result = subprocess.run(
                [
                    str(binary), "collect", str(root / "dial9-traces"),
                    str(root / "dial9-baseline.json"), str(destination),
                    "--wait-seconds", "0", "--requirements",
                    str(root / "dial9-requirements.tsv"),
                ],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="strict",
                timeout=120,
                env={**os.environ, "LC_ALL": "C"},
            )
        except (OSError, subprocess.TimeoutExpired, UnicodeError) as error:
            raise EvidenceError("pinned Dial9 decoder could not replay sealed traces") from error
        if result.returncode != 0:
            raise EvidenceError(
                f"pinned Dial9 decoder rejected sealed traces: {result.stderr.strip()}"
            )
        derived = _json_object(result.stdout.encode("utf-8"), "replayed Dial9 summary")
        sealed = _json_object(
            _read_regular_bytes(root / "dial9-evidence.json"), "modern Dial9 summary"
        )
        if derived != sealed:
            raise EvidenceError("sealed Dial9 summary does not match decoded trace semantics")


def _validate_modern_dial9(
    root: Path,
    udp: dict[str, str],
    echo_identities: list[tuple[int, int, str]],
    git_head: str,
) -> None:
    _verify_pinned_dial9_replay(root, git_head)
    requirements_content = _read_regular_bytes(root / "dial9-requirements.tsv")
    expected_digest = hashlib.sha256(requirements_content).hexdigest()
    if udp["dial9_requirements_sha256"] != expected_digest:
        raise EvidenceError("modern Dial9 requirements hash mismatch")
    try:
        text = requirements_content.decode("utf-8", errors="strict")
        reader = csv.DictReader(io.StringIO(text), delimiter="\t")
        expected_header = [
            "label", "provider_pid", "provider_generation", "flow_id", "protocol",
            "source_pid", "close_reason", "min_bytes_in", "max_bytes_in",
            "min_bytes_out", "max_bytes_out",
        ]
        if reader.fieldnames != expected_header:
            raise EvidenceError("modern Dial9 requirements header mismatch")
        requirements = list(reader)
    except (UnicodeError, csv.Error) as error:
        raise EvidenceError("modern Dial9 requirements are malformed") from error
    count = _canonical_uint(udp["dial9_requirement_count"], 100_000)
    if len(requirements) != count or count != _canonical_uint(
        udp["dial9_matched_requirement_count"], 100_000
    ):
        raise EvidenceError("modern Dial9 requirement cardinality mismatch")
    if any(None in row or any(value is None or value == "" for value in row.values()) for row in requirements):
        raise EvidenceError("modern Dial9 requirement row is incomplete")
    labels = [row["label"] for row in requirements]
    if len(set(labels)) != count:
        raise EvidenceError("modern Dial9 requirement labels are duplicated")
    provider_pid = _canonical_uint(udp["provider_pid"], 2**31 - 1)
    numeric_keys = expected_header[1:]
    parsed_rows = []
    for row in requirements:
        try:
            parsed = {key: _canonical_uint(row[key]) for key in numeric_keys}
        except EvidenceError as error:
            raise EvidenceError("modern Dial9 requirement contains a bad integer") from error
        if (
            parsed["provider_pid"] != provider_pid
            or parsed["protocol"] != 2
            or parsed["close_reason"] != 1
            or parsed["flow_id"] == 0
            or parsed["source_pid"] == 0
            or parsed["provider_generation"] == 0
            or parsed["min_bytes_in"] > parsed["max_bytes_in"]
            or parsed["min_bytes_out"] > parsed["max_bytes_out"]
        ):
            raise EvidenceError("modern Dial9 requirement identity/range mismatch")
        parsed_rows.append(parsed)
    expected_specific = {
        "ntp": (udp["ntp_flow_id"], udp["ntp_source_pid"]),
        "pressure": (udp["pressure_flow_id"], udp["pressure_source_pid"]),
        "recovery-ntp": (udp["recovery_ntp_flow_id"], udp["recovery_ntp_source_pid"]),
    }
    by_label = dict(zip(labels, parsed_rows))
    if set(expected_specific) - set(by_label):
        raise EvidenceError("modern Dial9 representative requirements are missing")
    for label, (flow_id, source_pid) in expected_specific.items():
        if (
            by_label[label]["flow_id"] != _canonical_uint(flow_id)
            or by_label[label]["source_pid"] != _canonical_uint(source_pid)
        ):
            raise EvidenceError(f"modern Dial9 {label} identity mismatch")
    echo_labels = {f"echo-{index}" for index in range(_canonical_uint(udp["echo_flow_count"], 512))}
    if set(labels) != echo_labels | set(expected_specific):
        raise EvidenceError("modern Dial9 exact workload label set mismatch")
    echo_rows = [by_label[label] for label in sorted(echo_labels)]
    echo_bytes = _canonical_uint(udp["echo_datagrams_per_socket"]) * _canonical_uint(
        udp["echo_payload_bytes"]
    )
    if echo_rows and (
        len({row["source_pid"] for row in echo_rows}) != 1
        or echo_rows[0]["source_pid"] != _canonical_uint(udp["echo_source_pid"])
        or any(
            row[key] != echo_bytes
            for row in echo_rows
            for key in ("min_bytes_in", "max_bytes_in", "min_bytes_out", "max_bytes_out")
        )
    ):
        raise EvidenceError("modern Dial9 echo flow cardinality/byte proof mismatch")
    ordered_echo_rows = [by_label[f"echo-{index}"] for index in range(len(echo_identities))]
    if len(ordered_echo_rows) != len(echo_identities) or any(
        row["provider_generation"] != identity[0]
        or row["flow_id"] != identity[1]
        for row, identity in zip(ordered_echo_rows, echo_identities)
    ):
        raise EvidenceError("modern echo identities do not match Dial9 requirements")
    flow_ids = [row["flow_id"] for row in parsed_rows]
    if len(set(flow_ids)) != len(flow_ids):
        raise EvidenceError("modern Dial9 flow identities are duplicated")

    summary = _json_object(
        _read_regular_bytes(root / "dial9-evidence.json"), "modern Dial9 summary"
    )
    baseline = _json_object(
        _read_regular_bytes(root / "dial9-baseline.json"), "modern Dial9 baseline"
    )
    baseline_value = baseline.get("max_index")
    if baseline_value is not None and (
        type(baseline_value) is not int or not 0 <= baseline_value < 2**32
    ):
        raise EvidenceError("modern Dial9 baseline index is malformed")
    baseline_text = "none" if baseline_value is None else str(baseline_value)
    if baseline_text != udp["dial9_baseline_max_index"]:
        raise EvidenceError("modern Dial9 baseline identity mismatch")
    flows = summary.get("required_flows")
    artifacts = summary.get("artifacts")
    if (
        summary.get("schema_version") != 1
        or summary.get("schema_complete") is not True
        or summary.get("requirements_sha256") != expected_digest
        or summary.get("requirement_count") != count
        or summary.get("matched_requirement_count") != count
        or summary.get("required_pair_count") != count
        or summary.get("baseline_max_index") != baseline_value
        or not isinstance(flows, list)
        or len(flows) != count
        or not isinstance(artifacts, list)
        or len(artifacts) != _canonical_uint(udp["dial9_current_segment_count"])
        or summary.get("current_segment_count") != len(artifacts)
    ):
        raise EvidenceError("modern Dial9 summary/cardinality mismatch")
    observed = {}
    for flow in flows:
        if not isinstance(flow, dict) or not isinstance(flow.get("label"), str):
            raise EvidenceError("modern Dial9 required flow is malformed")
        if flow["label"] in observed:
            raise EvidenceError("modern Dial9 required flow labels are duplicated")
        observed[flow["label"]] = flow
    if observed.keys() != by_label.keys():
        raise EvidenceError("modern Dial9 required flow label set mismatch")
    age_bound = _canonical_uint(udp["dial9_close_age_bound_ms"])
    for label, required in zip(labels, parsed_rows):
        flow = observed[label]
        for key in (
            "provider_pid", "provider_generation", "flow_id", "protocol",
            "source_pid", "close_reason",
        ):
            if flow.get(key) != required[key]:
                raise EvidenceError(f"modern Dial9 required flow identity mismatch: {label}")
        if (
            type(flow.get("bytes_in")) is not int
            or not required["min_bytes_in"] <= flow["bytes_in"] <= required["max_bytes_in"]
            or type(flow.get("bytes_out")) is not int
            or not required["min_bytes_out"] <= flow["bytes_out"] <= required["max_bytes_out"]
            or flow.get("close_reason_name") != "shutdown"
            or type(flow.get("close_age_ms")) is not int
            or not 0 <= flow["close_age_ms"] <= age_bound
        ):
            raise EvidenceError(f"modern Dial9 required flow result mismatch: {label}")
    trace_names = []
    trace_indices = []
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            raise EvidenceError("modern Dial9 trace manifest is malformed")
        name = artifact.get("name")
        match = re.fullmatch(r"trace\.([0-9]+)\.bin(?:\.gz)?", str(name))
        if match is None or str(int(match.group(1))) != match.group(1):
            raise EvidenceError("modern Dial9 trace name/index is non-canonical")
        index = int(match.group(1))
        path = root / "dial9-traces" / str(name)
        content = _read_regular_bytes(path)
        expected_encoding = "gzip" if str(name).endswith(".gz") else "raw"
        if (
            artifact.get("state") != "sealed"
            or artifact.get("encoding") != expected_encoding
            or artifact.get("index") != index
            or artifact.get("size") != len(content)
            or artifact.get("sha256") != hashlib.sha256(content).hexdigest()
        ):
            raise EvidenceError("modern Dial9 trace hash/identity mismatch")
        trace_names.append(str(name))
        trace_indices.append(index)
    actual_trace_names = sorted(
        path.name for path in (root / "dial9-traces").iterdir() if path.is_file()
    )
    if (
        sorted(trace_names) != actual_trace_names
        or len(set(trace_indices)) != len(trace_indices)
        or summary.get("current_indices") != sorted(trace_indices)
    ):
        raise EvidenceError("modern Dial9 copied trace set mismatch")


def _validate_modern_semantics(envelope: VerifiedEnvelope) -> None:
    required = (
        "udp-evidence-status.tsv",
        "controlled-echo-client.json",
        "controlled-echo-server.json",
        "echo-identities.tsv",
        "dial9-requirements.tsv",
        "dial9-baseline.json",
        "dial9-evidence.json",
        *(artifact for artifact, _ in MODERN_PRODUCER_SOURCES),
    )
    _required_artifacts(envelope, required, "modern UDP")
    status = envelope.status
    expected_claim_order = (
        "evidence_kind", "run_uuid", "dial9_diagnostic_only",
        "dial9_workload_coverage", "dial9_claim", "quic_shaped_not_valid_quic",
        "echo_socket_count", "echo_exact_echo_count", "http3_request_count",
        "http3_pass_count", "dial9_requirement_count",
        "dial9_matched_requirement_count", "producer_sources_sha256",
        "schema_complete",
    )
    claims, claim_rows = _strict_tsv_values(
        envelope.retained[CLAIMS_NAME], "modern workload claims"
    )
    if tuple(key for key, _ in claim_rows) != expected_claim_order or any(
        claims.get(key) != value for key, value in {
            "evidence_kind": "modern_udp",
            "run_uuid": status["run_uuid"],
            "dial9_diagnostic_only": "0",
            "dial9_workload_coverage": "1",
            "dial9_claim": "exact-workload",
            "quic_shaped_not_valid_quic": "1",
            "schema_complete": "1",
        }.items()
    ):
        raise EvidenceError("modern workload claims do not match the exact release contract")
    with tempfile.TemporaryDirectory(prefix="rama-modern-verify.") as temporary:
        temporary_root = Path(temporary)
        root = temporary_root / "evidence"
        _materialize_verified_envelope(envelope, root)
        source_copies = _validate_pinned_producer_sources(
            root, status["git_head"], MODERN_PRODUCER_SOURCES, "modern UDP"
        )
        parser_path = temporary_root / "modern_udp_evidence.py"
        _write_atomic(
            parser_path,
            source_copies["source-modern_udp_evidence.py"],
        )
        _write_atomic(
            temporary_root / "soak_pressure_log.py",
            source_copies["source-soak_pressure_log.py"],
        )
        result = _run_python_validator(
            [str(parser_path), str(root / "udp-evidence-status.tsv")]
        )
        if result.returncode != 0 or result.stdout != "0\n":
            raise EvidenceError("modern terminal evidence parser did not return exit 0")
        udp, _ = _strict_tsv_values(
            _read_regular_bytes(root / "udp-evidence-status.tsv"),
            "modern terminal status",
        )
        if udp.get("producer_sources_sha256") != _producer_sources_sha256(source_copies):
            raise EvidenceError("modern producer-source aggregate does not match sealed bytes")
        if udp.get("callback_generation") != "modern":
            raise EvidenceError("modern release evidence used a legacy callback generation")
        for common_key, udp_key in (
            ("complete", "complete"), ("passed", "passed"),
            ("exit_code", "exit_code"), ("evidence_kind", "evidence_kind"),
            ("run_uuid", "run_uuid"),
            ("run_start_epoch_ms", "run_start_epoch_ms"),
            ("run_end_epoch_ms", "run_end_epoch_ms"),
            ("provider_generation_identity", "provider_generation_identity"),
        ):
            if status[common_key] != udp[udp_key]:
                raise EvidenceError(f"modern common/terminal {common_key} mismatch")
        identity = read_provider_identity_bytes(envelope.retained[PROVIDER_IDENTITY_NAME])
        if identity["running_pid"] != udp["provider_pid"]:
            raise EvidenceError("modern terminal/common provider PID mismatch")
        claim_bindings = {
            "echo_socket_count": "echo_socket_count",
            "echo_exact_echo_count": "echo_exact_echo_count",
            "http3_request_count": "http3_request_count",
            "http3_pass_count": "http3_pass_count",
            "dial9_requirement_count": "dial9_requirement_count",
            "dial9_matched_requirement_count": "dial9_matched_requirement_count",
            "producer_sources_sha256": "producer_sources_sha256",
        }
        if any(claims[key] != udp[value] for key, value in claim_bindings.items()):
            raise EvidenceError("modern workload claims do not match terminal cardinalities")
        echo_identities = _validate_modern_echo(root, udp, status["run_uuid"])
        _validate_modern_dial9(root, udp, echo_identities, status["git_head"])
        _validate_modern_domain_semantics(parser_path, root)


def _extract_soak_validator(shell_source: bytes) -> str:
    try:
        text = shell_source.decode("utf-8", errors="strict")
        marker = "<<'PYEOF'\n"
        return text.split(marker, 1)[1].split("\nPYEOF", 1)[0]
    except (UnicodeError, IndexError) as error:
        raise EvidenceError("cannot extract the pinned soak semantic validator") from error


def _validate_soak_memory_artifacts(
    envelope: VerifiedEnvelope, root: Path, meta: dict[str, str]
) -> None:
    """Require successful, useful privileged memory snapshots at both boundaries.

    A zero shell status is insufficient because the producer deliberately turns
    failed ``ps``, ``vmmap``, and ``heap`` invocations into diagnostic text.  Bind
    the bounded-child metadata and also inspect the sealed command output so a
    missing process or failed attach cannot be presented as memory evidence.
    """
    names = ("baseline-mem.txt", "final-mem.txt")
    _required_artifacts(envelope, names, "soak memory")
    for name in names:
        if envelope.artifacts[name][0] == 0:
            raise EvidenceError(f"soak memory artifact is empty: {name}")

    for prefix in ("baseline", "final"):
        expected = {
            f"{prefix}_mem_child_rc": "0",
            f"{prefix}_mem_joined": "1",
            f"{prefix}_mem_forced": "0",
            f"{prefix}_mem_privilege": "sudo",
            f"{prefix}_mem_sudo_rc": "0",
            f"{prefix}_mem_ps_rc": "0",
            f"{prefix}_mem_vmmap_rc": "0",
        }
        if prefix == "final":
            expected.update({
                "final_mem_heap_rc": "0",
                "final_mem_heap_filter_rc": "0",
            })
        if any(meta.get(key) != value for key, value in expected.items()):
            raise EvidenceError(
                f"soak {prefix} memory diagnostic metadata is not a successful "
                "bounded sudo collection"
            )

    try:
        baseline = _read_regular_bytes(root / names[0]).decode("utf-8", errors="strict")
        final = _read_regular_bytes(root / names[1]).decode("utf-8", errors="strict")
    except UnicodeError as error:
        raise EvidenceError("soak memory artifacts are not UTF-8 text") from error

    try:
        provider_pid = _canonical_uint(meta["provider_start_pid"], 2**31 - 1)
    except (KeyError, EvidenceError) as error:
        raise EvidenceError("soak memory artifacts lack an exact provider PID") from error
    for label, content in (("baseline", baseline), ("final", final)):
        header_label = "baseline provider" if label == "baseline" else "final snapshot provider"
        ps_row = re.compile(
            rf"(?m)^\s*{provider_pid}\s+[0-9]+\s+[0-9]+\s+"
        )
        if (
            re.search(
                rf"(?m)^=== {re.escape(header_label)} pid={provider_pid} @ .+ ===$",
                content,
            ) is None
            or "--- vmmap --summary ---" not in content
            or ps_row.search(content) is None
            or re.search(
                rf"(?m)^Process:\s+.+\s+\[{provider_pid}\]\s*$", content
            ) is None
            or "vmmap unavailable" in content.lower()
        ):
            raise EvidenceError(
                f"soak {label} memory artifact lacks successful ps/vmmap output"
            )
        vmmap = content.split("--- vmmap --summary ---", 1)[1]
        if label == "final":
            vmmap = vmmap.split("--- heap totals ---", 1)[0]
        if not vmmap.strip():
            raise EvidenceError(f"soak {label} vmmap output is empty")

    if "--- heap totals ---" not in final or "heap unavailable" in final.lower():
        raise EvidenceError("soak final memory artifact lacks successful heap output")
    heap = final.split("--- heap totals ---", 1)[1]
    if not heap.strip() or re.search(
        rf"(?m)^\s*Process {provider_pid}:", heap
    ) is None:
        raise EvidenceError("soak final heap output is empty or unrecognized")

    try:
        leaks = _read_regular_bytes(root / "leaks.txt").decode("utf-8", errors="strict")
    except UnicodeError as error:
        raise EvidenceError("soak leaks artifact is not UTF-8 text") from error
    if not leaks.strip() or re.search(
        rf"(?m)^\s*Process {provider_pid}:.*(?:leaks|bytes)", leaks
    ) is None:
        raise EvidenceError("soak leaks artifact is not bound to the provider PID")


def _validate_soak_post_boundary_forensics(
    status: dict[str, str], meta: dict[str, str]
) -> None:
    """Bind post-run memory/leak attaches to one exact provider generation."""
    try:
        run_start = _canonical_uint(status["run_start_epoch_ms"])
        run_end = _canonical_uint(status["run_end_epoch_ms"])
        baseline_start = _canonical_uint(meta["baseline_mem_start_epoch_ms"])
        baseline_end = _canonical_uint(meta["baseline_mem_end_epoch_ms"])
        final_start = _canonical_uint(meta["final_mem_start_epoch_ms"])
        final_end = _canonical_uint(meta["final_mem_end_epoch_ms"])
        leaks_start = _canonical_uint(meta["leaks_start_epoch_ms"])
        leaks_end = _canonical_uint(meta["leaks_end_epoch_ms"])
        provider_pid = _canonical_uint(meta["provider_start_pid"], 2**31 - 1)
    except (KeyError, EvidenceError) as error:
        raise EvidenceError("soak post-boundary forensic timing is missing or malformed") from error
    if not (
        run_start <= baseline_start <= baseline_end <= run_end
        <= final_start <= final_end <= leaks_start <= leaks_end
    ):
        raise EvidenceError("soak post-boundary forensic ordering is invalid")
    identity = meta.get("provider_start_identity")
    if (
        provider_pid == 0
        or SHA256_RE.fullmatch(str(identity)) is None
        or meta.get("final_mem_provider_pid") != str(provider_pid)
        or meta.get("leaks_provider_pid") != str(provider_pid)
        or meta.get("baseline_mem_provider_pid") != str(provider_pid)
        or any(
            meta.get(key) != identity
            for key in (
                "baseline_mem_identity_before", "baseline_mem_identity_after",
                "final_mem_identity_before", "final_mem_identity_after",
                "leaks_identity_before", "leaks_identity_after",
            )
        )
    ):
        raise EvidenceError(
            "soak post-boundary forensics are not bound to the exact provider generation"
        )


def _validate_soak_identity_metadata(
    meta: dict[str, str], identity: dict[str, str]
) -> None:
    executable_name = Path(identity["running_executable_path"]).name
    expected = {
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
    if any(meta.get(key) != value for key, value in expected.items()):
        raise EvidenceError("soak metadata is not bound to common provider identity")


def _validate_soak_download_artifacts(root: Path) -> None:
    """Re-derive the steady download result from curl's sealed raw fields."""
    try:
        raw = _read_regular_bytes(root / "real-download.metrics").decode("utf-8")
        code, size, speed, duration = raw.split("\t")
        if (
            re.fullmatch(r"2[0-9]{2}", code) is None
            or _canonical_uint(size) != 32 * 1024 * 1024
            or any(re.fullmatch(r"(?:0|[1-9][0-9]*)(?:\.[0-9]+)?", value) is None
                   for value in (speed, duration))
            or Decimal(speed) <= 0 or Decimal(duration) <= 0
        ):
            raise ValueError("unsuccessful steady download")
    except (UnicodeError, ValueError, InvalidOperation) as error:
        raise EvidenceError("soak raw download did not prove the exact successful 32 MiB transfer") from error
    stderr = _read_regular_bytes(root / "real-download.curl.log")
    expected = stderr + (
        f"real-download: code={code} curl_exit=0 size={size} expected=33554432 "
        f"avg={speed}B/s time={duration}s\n"
    ).encode("utf-8")
    if stderr or _read_regular_bytes(root / "real-download.txt") != expected:
        raise EvidenceError("soak download outcome contradicts its raw curl fields")


def _validate_soak_stress_artifacts(
    root: Path, scripts: Path, status: dict[str, str], meta: dict[str, str]
) -> None:
    """Replay the nested stress run and bind its actual workload to this soak."""
    if meta.get("stress_child_rc") != "0":
        raise EvidenceError("release soak stress child did not exit successfully")
    child, _ = _strict_tsv_values(
        _read_regular_bytes(root / "stress/stress-status.tsv"), "soak nested stress status"
    )
    identity = read_provider_identity(root / PROVIDER_IDENTITY_NAME)
    if (
        tuple(child.get(key) for key in ("complete", "passed", "exit_code")) != ("1", "1", "0")
        or child.get("traffic_role") != "unpaired-diagnostic"
        or child.get("evidence_mode") != "provider-monitored-traffic-only"
        or child.get("run_uuid") == status["run_uuid"]
        or any(child.get(key) != status[key] for key in ("git_head", "git_dirty"))
        or any(child.get(child_key) != identity[identity_key] for child_key, identity_key in (
            ("provider_pid", "running_pid"),
            ("provider_executable_sha256", "running_executable_sha256"),
            ("provider_signing_identifier", "running_bundle_id"),
            ("provider_signing_team", "running_team_id"),
            ("provider_signing_cdhash", "running_cdhash"),
        ))
    ):
        raise EvidenceError("soak nested stress run does not match its source/provider generation")
    # The diagnostic child's legacy ps fingerprint differs from the common
    # identity hash. Exact PID/binary/signing plus the parent's continuous
    # generation samples spanning this complete interval bind the same process.
    child_start = _canonical_uint(child.get("run_start_epoch"))
    child_end = _canonical_uint(child.get("run_end_epoch"))
    if not _canonical_uint(status["run_start_epoch_ms"]) <= child_start < child_end \
        <= _canonical_uint(status["run_end_epoch_ms"]):
        raise EvidenceError("soak nested stress interval escapes the parent run")
    phase_rows = _read_regular_bytes(root / "phases.tsv").decode("utf-8").splitlines()
    boundaries = {}
    for line in phase_rows:
        fields = line.split("\t")
        if fields[0] != "stress":
            continue
        if len(fields) != 4 or fields[1] not in ("start", "end") or fields[1] in boundaries \
            or re.fullmatch(r"(?:0|[1-9][0-9]*)\.[0-9]{6}", fields[2]) is None:
            raise EvidenceError("soak stress phase has ambiguous timing boundaries")
        boundaries[fields[1]] = int(Decimal(fields[2]) * 1000)
    if set(boundaries) != {"start", "end"} or not \
        boundaries["start"] <= child_start < child_end <= boundaries["end"]:
        raise EvidenceError("soak nested stress run is outside its declared workload phase")
    workload, _ = _strict_tsv_values(
        _read_regular_bytes(root / "stress/stress-workload.tsv"), "soak nested stress workload"
    )
    if any(workload.get(key) != meta.get(meta_key) for key, meta_key in (
        ("duration_seconds", "configured_stress_seconds"),
        ("concurrency", "configured_stress_concurrency"),
    )):
        raise EvidenceError("soak nested stress workload differs from the configured release load")
    if any(workload.get(key) != value for key, value in {
        "large_bytes": "16777216", "post_bytes": "8388608",
        **{key: hashlib.sha256(value.encode()).hexdigest() for key, value in {
            "http_target_sha256": "http://http-test.ramaproxy.org/method",
            "https_target_sha256": "https://http-test.ramaproxy.org/method",
            "large_target_sha256": "https://http-test.ramaproxy.org/bytes?size=16777216",
            "post_target_sha256": "https://http-test.ramaproxy.org/octet-stream",
        }.items()},
    }.items()) or any(child.get(key) != value for key, value in {
        "max_p95_ms": "10000", "min_throughput_milli_rps": "100",
        "max_rss_growth_bytes": "67108864", "max_cpu_percent": "400",
    }.items()):
        raise EvidenceError("soak nested stress weakened the canonical transfers or thresholds")
    log_tool, _ = _strict_tsv_values(
        _read_regular_bytes(root / "stress/system-log-tool.tsv"), "soak stress log tool"
    )
    if log_tool.get("path") != "/usr/bin/log":
        raise EvidenceError("soak nested stress did not use the system log tool")
    sources = _validate_pinned_producer_sources(
        root / "stress", status["git_head"], STRESS_MEMBER_PRODUCER_SOURCES,
        "soak nested stress",
    )
    for artifact_name, source_name in STRESS_MEMBER_PRODUCER_SOURCES:
        _write_atomic(scripts / source_name, sources[artifact_name])
    result = _run_python_validator(
        [str(scripts / "stress_evidence.py"), "verify", str(root / "stress")], timeout=180
    )
    if result.returncode != 0:
        raise EvidenceError(
            "pinned soak stress validator rejected its raw workload: "
            + (result.stderr or result.stdout).strip()
        )


def _validate_soak_semantics(envelope: VerifiedEnvelope) -> None:
    required = (
        "run-meta.tsv", "soak-verdict.tsv", "phases.tsv", "system.ndjson",
        "probe-timeline.txt", "provider-timeline.tsv", "idle-cpu-baseline.tsv",
        "idle-cpu-post.tsv", "baseline-mem.txt", "final-mem.txt", "leaks.txt",
        "crashes-before.tsv",
        "crashes/crash-snapshot.tsv", "workload-claims.tsv",
        "real-download.metrics", "real-download.curl.log", "real-download.txt",
        "stress/stress-manifest.tsv", "stress/stress-status.tsv",
        *(artifact for artifact, _ in SOAK_PRODUCER_SOURCES),
    )
    _required_artifacts(envelope, required, "soak")
    status = envelope.status
    with tempfile.TemporaryDirectory(prefix="rama-soak-verify.") as temporary:
        temporary_root = Path(temporary)
        root = temporary_root / "evidence"
        scripts = temporary_root / "scripts"
        _materialize_verified_envelope(envelope, root)
        source_copies = _validate_pinned_producer_sources(
            root, status["git_head"], SOAK_PRODUCER_SOURCES, "soak"
        )
        shell_source = source_copies["source-soak_test.sh"]
        stress_source = source_copies["source-stress_traffic.sh"]
        parser_source = source_copies["source-soak_pressure_log.py"]
        signed_source = source_copies["source-signed_run_evidence.py"]
        scripts.mkdir()
        _write_atomic(scripts / "soak_pressure_log.py", parser_source)
        meta, _ = _strict_tsv_values(
            _read_regular_bytes(root / "run-meta.tsv"), "soak run metadata"
        )
        if meta.get("release_profile_eligible") != "1":
            raise EvidenceError("soak run is not eligible for the canonical release profile")
        if any(meta.get(key) != "1" for key in (
            "stress_ok", "fanout_established_target_sustained",
            "idle_holders_established_target_sustained", "real_download_ok",
            "post_wake_ok", "sleep_command_ok",
        )):
            raise EvidenceError("release soak omitted or failed a required workload phase")
        expected_meta = {
            "repo_head": status["git_head"],
            "repo_dirty": status["git_dirty"],
            "run_uuid": status["run_uuid"],
            "run_start_epoch_ms": status["run_start_epoch_ms"],
            "run_end_epoch_ms": status["run_end_epoch_ms"],
            "soak_script_sha256": hashlib.sha256(shell_source).hexdigest(),
            "stress_script_sha256": hashlib.sha256(stress_source).hexdigest(),
            "pressure_parser_sha256": hashlib.sha256(parser_source).hexdigest(),
            "signed_evidence_helper_sha256": hashlib.sha256(signed_source).hexdigest(),
        }
        if any(meta.get(key) != value for key, value in expected_meta.items()):
            raise EvidenceError("soak metadata is not bound to common status/pinned sources")
        identity = read_provider_identity_bytes(envelope.retained[PROVIDER_IDENTITY_NAME])
        _validate_soak_identity_metadata(meta, identity)
        _validate_soak_post_boundary_forensics(status, meta)
        _validate_soak_memory_artifacts(envelope, root, meta)
        _validate_soak_download_artifacts(root)
        _validate_soak_stress_artifacts(root, scripts, status, meta)
        sealed_verdict = _read_regular_bytes(root / "soak-verdict.tsv")
        validator = _extract_soak_validator(shell_source)
        result = _run_python_validator(
            ["-c", validator, str(root), str(scripts)], timeout=180
        )
        if result.returncode != 0:
            raise EvidenceError("pinned soak semantic extractor failed")
        recomputed = _read_regular_bytes(root / "soak-verdict.tsv")
        if recomputed != sealed_verdict:
            raise EvidenceError("sealed soak verdict does not match recomputed semantics")
        verdict, rows = _strict_tsv_values(recomputed, "recomputed soak verdict")
        if (
            rows[:3] != [("complete", "1"), ("passed", "1"), ("exit_code", "0")]
            or rows[-1] != ("schema_complete", "1")
            or len(rows) != 4
            or any(status[key] != verdict[key] for key in ("complete", "passed", "exit_code"))
        ):
            raise EvidenceError("recomputed soak semantics are not a complete pass")


def _validate_stress_series_semantics(envelope: VerifiedEnvelope) -> None:
    required = (
        "stress-series.tsv", "stress-series.tsv.source-stress_compare.py",
        "comparisons/pair-001.tsv", "comparisons/pair-002.tsv",
        "comparisons/pair-003.tsv",
    )
    _required_artifacts(envelope, required, "stress-series")
    head = envelope.status["git_head"]
    sources = {
        "stress_compare.py": _source_blob_at_head(
            head, "ffi/apple/examples/transparent_proxy/scripts/stress_compare.py"
        ),
        "stress_traffic.sh": _source_blob_at_head(
            head, "ffi/apple/examples/transparent_proxy/scripts/stress_traffic.sh"
        ),
        "stress_evidence.py": _source_blob_at_head(
            head, "ffi/apple/examples/transparent_proxy/scripts/stress_evidence.py"
        ),
        "signed_run_evidence.py": _source_blob_at_head(
            head, "ffi/apple/examples/transparent_proxy/scripts/signed_run_evidence.py"
        ),
    }
    with tempfile.TemporaryDirectory(prefix="rama-stress-series-verify.") as temporary:
        temporary_root = Path(temporary)
        root = temporary_root / "evidence"
        scripts = temporary_root / "scripts"
        _materialize_verified_envelope(envelope, root)
        scripts.mkdir()
        for name, content in sources.items():
            _write_atomic(scripts / name, content)
        series_values, _ = _strict_tsv_values(
            _read_regular_bytes(root / "stress-series.tsv"), "stress series artifact"
        )
        expected_hashes = {
            "comparison_helper_sha256": hashlib.sha256(sources["stress_compare.py"]).hexdigest(),
            "stress_script_sha256": hashlib.sha256(sources["stress_traffic.sh"]).hexdigest(),
            "evidence_helper_sha256": hashlib.sha256(sources["stress_evidence.py"]).hexdigest(),
            "signed_evidence_helper_sha256": hashlib.sha256(
                sources["signed_run_evidence.py"]
            ).hexdigest(),
        }
        if any(series_values.get(key) != value for key, value in expected_hashes.items()):
            raise EvidenceError("stress-series helper identities are not evidence-head pinned")
        if _read_regular_bytes(
            root / "stress-series.tsv.source-stress_compare.py"
        ) != sources["stress_compare.py"]:
            raise EvidenceError("sealed stress comparator is not the evidence-head source")
        for pair in range(1, 4):
            for role in ("baseline", "candidate"):
                member = root / "members" / f"pair-{pair:03d}" / role
                for artifact_name, source_name in STRESS_MEMBER_PRODUCER_SOURCES:
                    if _read_regular_bytes(member / artifact_name) != sources[source_name]:
                        raise EvidenceError(
                            "sealed stress member producer is not the evidence-head source: "
                            f"pair-{pair:03d}/{role}/{artifact_name}"
                        )
        result = _run_python_validator(
            [str(scripts / "stress_compare.py"), "verify-series", str(root)]
        )
        if result.returncode != 0:
            detail = (result.stderr or result.stdout).strip()
            raise EvidenceError(
                f"pinned stress-series comparator rejected sealed performance semantics: {detail}"
            )


def _validate_release_kind(envelope: VerifiedEnvelope) -> None:
    kind = envelope.status["evidence_kind"]
    if kind == "modern_udp":
        _validate_modern_semantics(envelope)
    elif kind == "soak":
        _validate_soak_semantics(envelope)
    elif kind == "stress-series":
        _validate_stress_series_semantics(envelope)
    else:
        raise EvidenceError(f"unsupported release evidence kind: {kind}")


def _run(command: list[str]) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            command,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="strict",
            env={**os.environ, "LC_ALL": "C"},
        )
    except (OSError, subprocess.CalledProcessError) as error:
        detail = ""
        if isinstance(error, subprocess.CalledProcessError):
            detail = (error.stderr or error.stdout or "").strip()
        raise EvidenceError(f"command failed: {shlex.join(command)}: {detail}") from error


def _git_snapshot(source_root: Path) -> tuple[str, str]:
    root = str(Path(source_root).resolve(strict=True))
    head = _run(["git", "-C", root, "rev-parse", "HEAD"]).stdout.strip()
    dirty_output = _run(
        ["git", "-C", root, "status", "--porcelain=v1", "--untracked-files=normal"]
    ).stdout
    if GIT_HEAD_RE.fullmatch(head) is None:
        raise EvidenceError("source repository did not return a full git head")
    return head, "1" if dirty_output else "0"


def _codesign_identity(bundle: Path) -> tuple[str, str, str]:
    _run(["/usr/bin/codesign", "--verify", "--strict", "--verbose=4", str(bundle)])
    result = _run(["/usr/bin/codesign", "-d", "--verbose=4", str(bundle)])
    text = result.stdout + "\n" + result.stderr
    fields: dict[str, str] = {}
    for line in text.splitlines():
        for key in ("Identifier", "TeamIdentifier", "CDHash"):
            prefix = key + "="
            if line.startswith(prefix):
                if key in fields:
                    raise EvidenceError(f"duplicate codesign {key}")
                fields[key] = line[len(prefix):]
    if set(fields) != {"Identifier", "TeamIdentifier", "CDHash"}:
        raise EvidenceError("codesign identity output is incomplete")
    cdhash = fields["CDHash"].lower()
    if CDHASH_RE.fullmatch(cdhash) is None:
        raise EvidenceError("invalid provider CDHash")
    return fields["Identifier"], fields["TeamIdentifier"], cdhash


def _locate_provider_bundle(path: Path, expected_bundle_id: str) -> Path:
    original = Path(path)
    resolved = original.resolve(strict=True)
    candidates: list[Path] = []
    if resolved.is_dir() and (resolved / "Contents/Info.plist").is_file():
        candidates.append(resolved)
    if resolved.is_dir() and resolved.suffix == ".app":
        base = resolved / "Contents/Library/SystemExtensions"
        if base.is_dir():
            candidates.extend(sorted(base.glob("*.systemextension")))
    if resolved.is_file():
        candidates.extend(parent for parent in resolved.parents if parent.suffix == ".systemextension")
    matches = []
    for candidate in candidates:
        try:
            with (candidate / "Contents/Info.plist").open("rb") as source:
                info = plistlib.load(source)
        except (OSError, plistlib.InvalidFileException):
            continue
        if info.get("CFBundleIdentifier") == expected_bundle_id:
            matches.append(candidate.resolve(strict=True))
    unique = sorted(set(matches))
    if len(unique) != 1:
        raise EvidenceError(
            f"expected exactly one {expected_bundle_id} provider below {path}, found {len(unique)}"
        )
    return unique[0]


def _bundle_snapshot(
    path: Path, expected_bundle_id: str, expected_team_id: str
) -> BundleSnapshot:
    bundle = _locate_provider_bundle(path, expected_bundle_id)
    info_path = bundle / "Contents/Info.plist"
    if info_path.is_symlink():
        raise EvidenceError("provider Info.plist is a symlink")
    try:
        with info_path.open("rb") as source:
            info = plistlib.load(source)
    except (OSError, plistlib.InvalidFileException) as error:
        raise EvidenceError("cannot read provider Info.plist") from error
    bundle_id = info.get("CFBundleIdentifier")
    git_head = info.get("RamaGitHead")
    git_dirty = str(info.get("RamaGitDirty"))
    executable_name = info.get("CFBundleExecutable")
    bundle_version = str(info.get("CFBundleVersion", ""))
    if bundle_id != expected_bundle_id:
        raise EvidenceError("provider bundle identifier mismatch")
    if not isinstance(git_head, str) or GIT_HEAD_RE.fullmatch(git_head) is None:
        raise EvidenceError("provider lacks an embedded full git head")
    if git_dirty != "0":
        raise EvidenceError("provider was built from a dirty source tree")
    if not isinstance(executable_name, str) or not executable_name or Path(executable_name).name != executable_name:
        raise EvidenceError("invalid provider executable name")
    if not bundle_version or any(character in bundle_version for character in "\t\r\n"):
        raise EvidenceError("invalid provider bundle version")
    executable = bundle / "Contents/MacOS" / executable_name
    if executable.is_symlink():
        raise EvidenceError("provider executable is a symlink")
    executable_digest = sha256_file(executable)
    signing_id, team_id, cdhash = _codesign_identity(bundle)
    if signing_id != expected_bundle_id or team_id != expected_team_id:
        raise EvidenceError("provider signing identifier/team mismatch")
    build_id = provider_build_identity(
        bundle_id, git_head, team_id, cdhash, executable_digest
    )
    return BundleSnapshot(
        bundle_id=bundle_id,
        git_head=git_head,
        git_dirty=git_dirty,
        team_id=team_id,
        cdhash=cdhash,
        executable_sha256=executable_digest,
        bundle_version=bundle_version,
        bundle_path=str(bundle),
        executable_path=str(executable.resolve(strict=True)),
        build_identity=build_id,
    )


def _process_executable_path(pid: int) -> Path:
    """Read the main executable from Darwin's process table, never argv/lsof.

    lsof's `txt` rows also include dyld and other mapped images. proc_pidpath
    identifies the process's executable without selecting one of those mappings
    or trusting an editable command line, and does not require a sudo helper.
    """
    if isinstance(pid, bool) or not 0 < pid <= 2**31 - 1:
        raise EvidenceError("invalid provider pid")
    try:
        proc = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
        pidpath = proc.proc_pidpath
        pidpath.argtypes = (ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32)
        pidpath.restype = ctypes.c_int
        # PROC_PIDPATHINFO_MAXSIZE is 4 * MAXPATHLEN on Darwin.
        buffer = ctypes.create_string_buffer(4096)
        length = pidpath(pid, buffer, len(buffer))
    except (OSError, AttributeError) as error:
        raise EvidenceError("kernel process executable lookup is unavailable") from error
    if not 0 < length < len(buffer) or buffer.raw[length] != 0:
        raise EvidenceError("kernel could not identify the running provider executable")
    try:
        text = buffer.raw[:length].decode("utf-8", errors="strict")
        if not text.startswith("/") or any(character in text for character in "\0\t\r\n"):
            raise ValueError("invalid kernel executable pathname")
        return Path(text).resolve(strict=True)
    except (OSError, ValueError) as error:
        raise EvidenceError("kernel provider executable pathname is invalid") from error


def _process_snapshot(pid: int) -> ProcessSnapshot:
    if isinstance(pid, bool) or not 0 < pid <= 2**31 - 1:
        raise EvidenceError("invalid provider pid")
    start_text = _run(["/bin/ps", "-p", str(pid), "-o", "lstart="]).stdout.strip()
    command = _run(["/bin/ps", "-ww", "-p", str(pid), "-o", "command="]).stdout.rstrip("\n")
    if not start_text or not command or "\n" in command or any(character in command for character in "\t\r"):
        raise EvidenceError("provider process metadata is incomplete")
    try:
        start = datetime.strptime(start_text, "%a %b %d %H:%M:%S %Y").astimezone()
    except ValueError as error:
        raise EvidenceError("cannot parse provider process start time") from error
    start_epoch_ms = int(start.timestamp()) * 1000
    executable = _process_executable_path(pid)
    return ProcessSnapshot(pid, start_epoch_ms, command, executable)


def _snapshot_rows(prefix: str, snapshot: BundleSnapshot) -> list[tuple[str, str]]:
    return [(f"{prefix}_{field}", str(getattr(snapshot, field))) for field in SNAPSHOT_FIELDS]


def capture_provider(
    built_provider: Path,
    installed_provider: Path,
    pid: int,
    output: Path,
    source_root: Path,
    expected_bundle_id: str = DEV_PROVIDER_BUNDLE_ID,
    expected_team_id: str = DEV_TEAM_ID,
) -> dict[str, str]:
    """Capture and atomically write exact built/installed/running identity."""
    source_before = _git_snapshot(source_root)
    process_before = _process_snapshot(pid)
    built = _bundle_snapshot(built_provider, expected_bundle_id, expected_team_id)
    installed = _bundle_snapshot(installed_provider, expected_bundle_id, expected_team_id)
    running = _bundle_snapshot(
        process_before.executable_path, expected_bundle_id, expected_team_id
    )
    process_after = _process_snapshot(pid)
    source_after = _git_snapshot(source_root)
    if process_before != process_after:
        raise EvidenceError("provider process generation changed during capture")
    declared_running_executable = Path(running.executable_path)
    if (
        process_before.executable_path != declared_running_executable
        or process_after.executable_path != declared_running_executable
    ):
        raise EvidenceError(
            "running process executable is not the provider bundle's declared executable"
        )
    if source_before != source_after:
        raise EvidenceError("source repository changed during capture")
    source_head, source_dirty = source_before
    if source_dirty != "0":
        raise EvidenceError("signed evidence requires a clean source tree")
    snapshots = (built, installed, running)
    if any(snapshot.git_head != source_head for snapshot in snapshots):
        raise EvidenceError("built/installed/running provider source head mismatch")
    if len({snapshot.build_identity for snapshot in snapshots}) != 1:
        raise EvidenceError("built/installed/running provider build identity mismatch")
    command_sha = hashlib.sha256(process_before.command.encode("utf-8")).hexdigest()
    generation_id = provider_generation_identity(
        pid, process_before.start_epoch_ms, command_sha
    )
    rows = [
        ("schema_version", str(SCHEMA_VERSION)),
        ("expected_bundle_id", expected_bundle_id),
        ("expected_team_id", expected_team_id),
        ("source_git_head", source_head),
        ("source_git_dirty", source_dirty),
        *_snapshot_rows("built", built),
        *_snapshot_rows("installed", installed),
        *_snapshot_rows("running", running),
        ("running_pid", str(pid)),
        ("running_start_epoch_ms", str(process_before.start_epoch_ms)),
        ("running_command", process_before.command),
        ("running_command_sha256", command_sha),
        ("provider_build_identity", built.build_identity),
        ("provider_generation_identity", generation_id),
        ("schema_complete", "1"),
    ]
    content = "".join(f"{key}\t{value}\n" for key, value in rows).encode("utf-8")
    _write_atomic(Path(output), content)
    return dict(rows)


def read_provider_identity(path: Path) -> dict[str, str]:
    return read_provider_identity_bytes(_read_regular_bytes(Path(path)))


def read_provider_identity_bytes(content: bytes) -> dict[str, str]:
    values, _ = _parse_tsv_bytes(
        content, expected_order=PROVIDER_IDENTITY_ORDER
    )
    if values["schema_version"] != str(SCHEMA_VERSION) or values["schema_complete"] != "1":
        raise EvidenceError("unsupported or incomplete provider identity")
    if values["expected_bundle_id"] != DEV_PROVIDER_BUNDLE_ID:
        raise EvidenceError("provider identity is not for the exact development provider")
    if values["expected_team_id"] != DEV_TEAM_ID:
        raise EvidenceError("provider identity is not for the exact development team")
    if GIT_HEAD_RE.fullmatch(values["source_git_head"]) is None or values["source_git_dirty"] != "0":
        raise EvidenceError("provider identity source is not exact and clean")
    expected_build_ids = set()
    for prefix in ("built", "installed", "running"):
        if values[f"{prefix}_bundle_id"] != DEV_PROVIDER_BUNDLE_ID:
            raise EvidenceError(f"{prefix} provider bundle id mismatch")
        if values[f"{prefix}_git_head"] != values["source_git_head"]:
            raise EvidenceError(f"{prefix} provider git head mismatch")
        if values[f"{prefix}_git_dirty"] != "0":
            raise EvidenceError(f"{prefix} provider was built dirty")
        if values[f"{prefix}_team_id"] != DEV_TEAM_ID:
            raise EvidenceError(f"{prefix} provider team mismatch")
        if CDHASH_RE.fullmatch(values[f"{prefix}_cdhash"]) is None:
            raise EvidenceError(f"{prefix} provider CDHash is invalid")
        if SHA256_RE.fullmatch(values[f"{prefix}_executable_sha256"]) is None:
            raise EvidenceError(f"{prefix} provider executable hash is invalid")
        recomputed = provider_build_identity(
            values[f"{prefix}_bundle_id"],
            values[f"{prefix}_git_head"],
            values[f"{prefix}_team_id"],
            values[f"{prefix}_cdhash"],
            values[f"{prefix}_executable_sha256"],
        )
        if recomputed != values[f"{prefix}_build_identity"]:
            raise EvidenceError(f"{prefix} provider build identity is invalid")
        expected_build_ids.add(recomputed)
        for suffix in ("bundle_path", "executable_path", "bundle_version"):
            if not values[f"{prefix}_{suffix}"] or any(
                character in values[f"{prefix}_{suffix}"] for character in "\t\r\n"
            ):
                raise EvidenceError(f"invalid {prefix} provider {suffix}")
    if len(expected_build_ids) != 1 or values["provider_build_identity"] not in expected_build_ids:
        raise EvidenceError("provider build identities do not match")
    pid = _canonical_uint(values["running_pid"], 2**31 - 1)
    start = _canonical_uint(values["running_start_epoch_ms"])
    if pid == 0 or start == 0:
        raise EvidenceError("invalid provider generation process metadata")
    command = values["running_command"]
    command_sha = hashlib.sha256(command.encode("utf-8")).hexdigest()
    if command_sha != values["running_command_sha256"]:
        raise EvidenceError("provider command fingerprint mismatch")
    generation_id = provider_generation_identity(pid, start, command_sha)
    if generation_id != values["provider_generation_identity"]:
        raise EvidenceError("provider generation identity mismatch")
    return values


def _validated_generation_cadence(cadence_ms: int, max_gap_ms: int) -> None:
    if (
        isinstance(cadence_ms, bool)
        or isinstance(max_gap_ms, bool)
        or not 250 <= cadence_ms <= 5000
        or not cadence_ms <= max_gap_ms <= min(cadence_ms * 3, 10_000)
    ):
        raise EvidenceError(
            "provider generation cadence must be 250..5000ms with a small 1x..3x gap tolerance"
        )


def _generation_lock_path(destination: Path) -> Path:
    digest = hashlib.sha256(
        str(destination.absolute()).encode("utf-8", errors="strict")
    ).hexdigest()
    return Path(tempfile.gettempdir()) / f"rama-provider-generation-{digest}.lock"


def capture_provider_generation(
    identity_path: Path,
    destination: Path,
    *,
    append: bool = False,
    cadence_ms: int | None = None,
    max_gap_ms: int | None = None,
) -> dict[str, str]:
    """Atomically add one live sample for the captured provider generation."""
    identity = read_provider_identity(Path(identity_path))
    output = Path(destination)
    lock_path = _generation_lock_path(output)
    lock_fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        if append:
            values, rows = _parse_tsv_bytes(_read_regular_bytes(output))
            if (
                len(rows) < len(GENERATION_FIXED_ORDER) + 2
                or tuple(key for key, _ in rows[:len(GENERATION_FIXED_ORDER)])
                    != GENERATION_FIXED_ORDER
                or rows[-1] != ("schema_complete", "1")
                or values["schema_version"] != str(SCHEMA_VERSION)
            ):
                raise EvidenceError("malformed provider generation samples")
            count = _canonical_uint(values["sample_count"], 9_999_999)
            previous = rows[len(GENERATION_FIXED_ORDER):-1]
            if [key for key, _ in previous] != [
                f"sample_{index:06d}" for index in range(1, count + 1)
            ]:
                raise EvidenceError("provider generation samples are incomplete or unordered")
            encoded_cadence = _canonical_uint(values["cadence_ms"], 5000)
            encoded_max_gap = _canonical_uint(values["max_gap_ms"], 10_000)
            _validated_generation_cadence(encoded_cadence, encoded_max_gap)
            if cadence_ms is not None and cadence_ms != encoded_cadence:
                raise EvidenceError("appended provider generation cadence changed")
            if max_gap_ms is not None and max_gap_ms != encoded_max_gap:
                raise EvidenceError("appended provider generation gap tolerance changed")
            cadence_ms, max_gap_ms = encoded_cadence, encoded_max_gap
        else:
            if output.exists() or output.is_symlink():
                raise EvidenceError("provider generation output already exists; use --append")
            count = 0
            previous = []
            cadence_ms = DEFAULT_GENERATION_CADENCE_MS if cadence_ms is None else cadence_ms
            max_gap_ms = DEFAULT_GENERATION_MAX_GAP_MS if max_gap_ms is None else max_gap_ms
            _validated_generation_cadence(cadence_ms, max_gap_ms)

        expected = {
            "provider_generation_identity": identity["provider_generation_identity"],
            "running_pid": identity["running_pid"],
            "running_start_epoch_ms": identity["running_start_epoch_ms"],
            "running_command_sha256": identity["running_command_sha256"],
            "running_executable_path_sha256": hashlib.sha256(
                identity["running_executable_path"].encode("utf-8")
            ).hexdigest(),
        }
        if append and any(values.get(key) != value for key, value in expected.items()):
            raise EvidenceError("provider generation sample identity changed")
        process = _process_snapshot(_canonical_uint(identity["running_pid"], 2**31 - 1))
        actual = {
            "running_pid": str(process.pid),
            "running_start_epoch_ms": str(process.start_epoch_ms),
            "running_command_sha256": hashlib.sha256(
                process.command.encode("utf-8")
            ).hexdigest(),
            "running_executable_path_sha256": hashlib.sha256(
                str(process.executable_path).encode("utf-8")
            ).hexdigest(),
        }
        if any(actual[key] != expected[key] for key in actual):
            raise EvidenceError("running provider no longer matches the captured generation")
        if process.executable_path != Path(identity["running_executable_path"]).resolve(strict=True):
            raise EvidenceError("running provider executable path changed")
        epoch_ms = time.time_ns() // 1_000_000
        count += 1
        sample = "|".join((
            str(epoch_ms), actual["running_pid"], actual["running_start_epoch_ms"],
            actual["running_command_sha256"], actual["running_executable_path_sha256"],
        ))
        output_rows = [
            ("schema_version", str(SCHEMA_VERSION)),
            *expected.items(),
            ("cadence_ms", str(cadence_ms)),
            ("max_gap_ms", str(max_gap_ms)),
            ("sample_count", str(count)),
            *previous,
            (f"sample_{count:06d}", sample),
            ("schema_complete", "1"),
        ]
        _write_atomic(
            output,
            "".join(f"{key}\t{value}\n" for key, value in output_rows).encode("utf-8"),
        )
        return {"epoch_ms": str(epoch_ms), **actual}
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)


def verify_provider_generation_samples(
    content: bytes,
    identity: dict[str, str],
    *,
    run_start_epoch_ms: int,
    run_end_epoch_ms: int,
    required_through_epoch_ms: int | None = None,
) -> list[int]:
    values, rows = _parse_tsv_bytes(content)
    if (
        len(rows) < len(GENERATION_FIXED_ORDER) + 4
        or tuple(key for key, _ in rows[:len(GENERATION_FIXED_ORDER)])
            != GENERATION_FIXED_ORDER
        or rows[-1] != ("schema_complete", "1")
        or values["schema_version"] != str(SCHEMA_VERSION)
    ):
        raise EvidenceError("malformed provider generation samples")
    expected = {
        "provider_generation_identity": identity["provider_generation_identity"],
        "running_pid": identity["running_pid"],
        "running_start_epoch_ms": identity["running_start_epoch_ms"],
        "running_command_sha256": identity["running_command_sha256"],
        "running_executable_path_sha256": hashlib.sha256(
            identity["running_executable_path"].encode("utf-8")
        ).hexdigest(),
    }
    if any(values.get(key) != value for key, value in expected.items()):
        raise EvidenceError("provider generation samples do not match provider identity")
    cadence_ms = _canonical_uint(values["cadence_ms"], 5000)
    max_gap_ms = _canonical_uint(values["max_gap_ms"], 10_000)
    _validated_generation_cadence(cadence_ms, max_gap_ms)
    count = _canonical_uint(values["sample_count"], 9_999_999)
    samples = rows[len(GENERATION_FIXED_ORDER):-1]
    if count < 3 or len(samples) != count:
        raise EvidenceError("provider generation proof requires at least three samples")
    epochs: list[int] = []
    process_start = _canonical_uint(expected["running_start_epoch_ms"])
    expected_tail = "|".join((
        expected["running_pid"], expected["running_start_epoch_ms"],
        expected["running_command_sha256"], expected["running_executable_path_sha256"],
    ))
    for index, (key, value) in enumerate(samples, start=1):
        fields = value.split("|", 1)
        if key != f"sample_{index:06d}" or len(fields) != 2 or fields[1] != expected_tail:
            raise EvidenceError("provider generation sample is malformed or substituted")
        epoch = _canonical_uint(fields[0])
        if epoch < process_start:
            raise EvidenceError("provider generation sample predates the process start")
        if epochs and epoch < epochs[-1]:
            raise EvidenceError("provider generation samples are not chronological")
        epochs.append(epoch)
    through = run_end_epoch_ms if required_through_epoch_ms is None else required_through_epoch_ms
    if epochs[0] > run_start_epoch_ms or epochs[-1] < through:
        raise EvidenceError("provider generation samples do not span the required run interval")
    if any(right - left > max_gap_ms for left, right in zip(epochs, epochs[1:])):
        raise EvidenceError("provider generation sampling gap exceeds its encoded tolerance")
    return epochs


def _provider_absence_sample() -> tuple[int, list[tuple[int, str]]]:
    """Resolve only exact installed development-provider executable paths."""
    executable_name = DEV_PROVIDER_BUNDLE_ID
    pattern = re.compile(
        r"/Library/SystemExtensions/[^/\s]+/"
        + re.escape(DEV_PROVIDER_BUNDLE_ID)
        + r"\.systemextension/Contents/MacOS/"
        + re.escape(executable_name)
        + r"\Z"
    )
    output = _run(["/bin/ps", "-axo", "pid=,command="]).stdout
    matches: list[tuple[int, str]] = []
    for line in output.splitlines():
        match = re.match(r"^\s*([0-9]+)\s+(.+)$", line)
        if match is None:
            continue
        pid = _canonical_uint(match.group(1), 2**31 - 1)
        try:
            arguments = shlex.split(match.group(2), posix=True)
        except ValueError as error:
            raise EvidenceError("cannot parse process command during provider absence capture") from error
        if not arguments or pattern.fullmatch(arguments[0]) is None:
            continue
        # `ps` is only a candidate finder. Kernel-backed process capture binds
        # the PID to the actual executable and rejects PID reuse/disappearance.
        process = _process_snapshot(pid)
        actual_path = str(process.executable_path)
        if pattern.fullmatch(actual_path) is None:
            raise EvidenceError("provider candidate command/executable path mismatch")
        matches.append((pid, hashlib.sha256(actual_path.encode("utf-8")).hexdigest()))
    return time.time_ns() // 1_000_000, sorted(set(matches))


def _validated_absence_cadence(cadence_ms: int, max_gap_ms: int) -> None:
    if (
        isinstance(cadence_ms, bool)
        or isinstance(max_gap_ms, bool)
        or not 100 <= cadence_ms <= 5000
        or not cadence_ms <= max_gap_ms <= min(cadence_ms * 3, 10_000)
    ):
        raise EvidenceError(
            "provider absence cadence must be 100..5000ms with a small 1x..3x gap tolerance"
        )


def capture_provider_absence(
    path: Path,
    *,
    append: bool = False,
    cadence_ms: int | None = None,
    max_gap_ms: int | None = None,
) -> dict[str, str]:
    """Write/append one exact-provider absence sample, returning its fields."""
    destination = Path(path)
    if append:
        values, rows = _parse_tsv_bytes(_read_regular_bytes(destination))
        if (
            len(rows) < len(ABSENCE_FIXED_ORDER) + 2
            or tuple(key for key, _ in rows[:len(ABSENCE_FIXED_ORDER)])
                != ABSENCE_FIXED_ORDER
            or rows[-1] != ("schema_complete", "1")
            or values["schema_version"] != str(SCHEMA_VERSION)
            or values["bundle_id"] != DEV_PROVIDER_BUNDLE_ID
        ):
            raise EvidenceError("malformed provider absence proof")
        encoded_cadence = _canonical_uint(values["cadence_ms"], 5000)
        encoded_max_gap = _canonical_uint(values["max_gap_ms"], 10_000)
        _validated_absence_cadence(encoded_cadence, encoded_max_gap)
        if cadence_ms is not None and cadence_ms != encoded_cadence:
            raise EvidenceError("appended provider absence cadence changed")
        if max_gap_ms is not None and max_gap_ms != encoded_max_gap:
            raise EvidenceError("appended provider absence gap tolerance changed")
        cadence_ms = encoded_cadence
        max_gap_ms = encoded_max_gap
        count = _canonical_uint(values["sample_count"], 999_999)
        expected_keys = [f"sample_{index:06d}" for index in range(1, count + 1)]
        if [key for key, _ in rows[len(ABSENCE_FIXED_ORDER):-1]] != expected_keys:
            raise EvidenceError("provider absence samples are incomplete or unordered")
        previous_samples = rows[len(ABSENCE_FIXED_ORDER):-1]
    else:
        if destination.exists() or destination.is_symlink():
            raise EvidenceError("provider absence output already exists; use --append")
        count = 0
        previous_samples = []
        cadence_ms = (
            DEFAULT_ABSENCE_CADENCE_MS if cadence_ms is None else cadence_ms
        )
        max_gap_ms = (
            DEFAULT_ABSENCE_MAX_GAP_MS if max_gap_ms is None else max_gap_ms
        )
        _validated_absence_cadence(cadence_ms, max_gap_ms)
    epoch_ms, matches = _provider_absence_sample()
    fingerprints = ",".join(f"{pid}@{digest}" for pid, digest in matches) or "none"
    sample_value = f"{epoch_ms}|{len(matches)}|{fingerprints}"
    count += 1
    rows = [
        ("schema_version", str(SCHEMA_VERSION)),
        ("bundle_id", DEV_PROVIDER_BUNDLE_ID),
        ("cadence_ms", str(cadence_ms)),
        ("max_gap_ms", str(max_gap_ms)),
        ("sample_count", str(count)),
        *previous_samples,
        (f"sample_{count:06d}", sample_value),
        ("schema_complete", "1"),
    ]
    _write_atomic(
        destination,
        "".join(f"{key}\t{value}\n" for key, value in rows).encode("utf-8"),
    )
    return {
        "epoch_ms": str(epoch_ms),
        "match_count": str(len(matches)),
        "matching_pid_path_fingerprints": fingerprints,
    }


def verify_provider_absence(
    path: Path,
    *,
    run_start_epoch_ms: int,
    run_end_epoch_ms: int,
    content: bytes | None = None,
) -> list[tuple[int, int, str]]:
    if content is None:
        content = _read_regular_bytes(Path(path))
    values, rows = _parse_tsv_bytes(content)
    if (
        len(rows) < len(ABSENCE_FIXED_ORDER) + 3
        or tuple(key for key, _ in rows[:len(ABSENCE_FIXED_ORDER)])
            != ABSENCE_FIXED_ORDER
        or rows[-1] != ("schema_complete", "1")
        or values["schema_version"] != str(SCHEMA_VERSION)
        or values["bundle_id"] != DEV_PROVIDER_BUNDLE_ID
    ):
        raise EvidenceError("malformed provider absence proof")
    cadence_ms = _canonical_uint(values["cadence_ms"], 5000)
    max_gap_ms = _canonical_uint(values["max_gap_ms"], 10_000)
    _validated_absence_cadence(cadence_ms, max_gap_ms)
    count = _canonical_uint(values["sample_count"], 999_999)
    sample_rows = rows[len(ABSENCE_FIXED_ORDER):-1]
    if count < 2 or len(sample_rows) != count:
        raise EvidenceError("provider absence requires at least two samples")
    samples = []
    previous_epoch = None
    for index, (key, value) in enumerate(sample_rows, start=1):
        if key != f"sample_{index:06d}":
            raise EvidenceError("provider absence samples are incomplete or unordered")
        fields = value.split("|")
        if len(fields) != 3:
            raise EvidenceError("malformed provider absence sample")
        epoch = _canonical_uint(fields[0])
        match_count = _canonical_uint(fields[1], 2**31 - 1)
        fingerprints = fields[2]
        if previous_epoch is not None and epoch < previous_epoch:
            raise EvidenceError("provider absence samples are not chronological")
        previous_epoch = epoch
        if match_count == 0:
            if fingerprints != "none":
                raise EvidenceError("zero provider matches have non-empty fingerprints")
        else:
            entries = fingerprints.split(",")
            if len(entries) != match_count or entries != sorted(set(entries)):
                raise EvidenceError("provider match fingerprint count/order mismatch")
            for entry in entries:
                parts = entry.split("@")
                if (
                    len(parts) != 2
                    or _canonical_uint(parts[0], 2**31 - 1) == 0
                    or SHA256_RE.fullmatch(parts[1]) is None
                ):
                    raise EvidenceError("invalid provider match fingerprint")
        samples.append((epoch, match_count, fingerprints))
    if samples[0][0] > run_start_epoch_ms or samples[-1][0] < run_end_epoch_ms:
        raise EvidenceError("provider absence samples do not span the run")
    if any(match_count != 0 for _, match_count, _ in samples):
        raise EvidenceError("development provider was present during direct baseline")
    gaps = [right[0] - left[0] for left, right in zip(samples, samples[1:])]
    if any(gap > max_gap_ms for gap in gaps):
        raise EvidenceError(
            f"provider absence sampling gap exceeded encoded {max_gap_ms}ms tolerance"
        )
    return samples


def snapshot_crashes(
    since_epoch_ms: int,
    output_dir: Path,
    process_names: list[str],
    *,
    run_uuid: str,
    provider_generation_identity: str,
    report_dirs: list[Path] | None = None,
) -> dict[str, str]:
    """Copy stable crash reports for named processes since the run began."""
    if isinstance(since_epoch_ms, bool) or since_epoch_ms <= 0:
        raise EvidenceError("invalid crash snapshot start")
    _canonical_uuid(run_uuid)
    if (
        provider_generation_identity not in ("absent", "multiple")
        and SHA256_RE.fullmatch(provider_generation_identity) is None
    ):
        raise EvidenceError("invalid crash snapshot provider generation")
    if not process_names or any(
        not name or Path(name).name != name or any(character in name for character in "\t,\r\n")
        for name in process_names
    ):
        raise EvidenceError("invalid crash process name")
    names = sorted(set(process_names))
    if report_dirs is None:
        report_dirs = [
            Path.home() / "Library/Logs/DiagnosticReports",
            Path("/Library/Logs/DiagnosticReports"),
        ]
    destination = Path(output_dir)
    if destination.exists():
        if destination.is_symlink() or not destination.is_dir() or any(destination.iterdir()):
            raise EvidenceError("crash output directory must be absent or empty")
    else:
        destination.mkdir(parents=True)
    copied: list[str] = []
    for report_dir in report_dirs:
        source_dir = Path(report_dir)
        if not source_dir.exists():
            continue
        if source_dir.is_symlink() or not source_dir.is_dir():
            raise EvidenceError(f"unsafe crash report directory: {source_dir}")
        for source in sorted(source_dir.iterdir()):
            if source.is_symlink() or not source.is_file():
                continue
            if source.suffix.lower() not in (".crash", ".ips"):
                continue
            if source.stat().st_mtime_ns // 1_000_000 < since_epoch_ms:
                continue
            content = _read_regular_bytes(source)
            if not _crash_report_matches(source.name, content, names):
                continue
            unique_name = source.name
            index = 1
            while (destination / unique_name).exists():
                unique_name = f"{source.stem}.{index}{source.suffix}"
                index += 1
            _write_atomic(destination / unique_name, content)
            copied.append(unique_name)
    copied.sort()
    names_digest = hashlib.sha256("\n".join(copied).encode("utf-8")).hexdigest()
    rows = [
        ("schema_version", str(CRASH_SCHEMA_VERSION)),
        ("run_uuid", run_uuid),
        ("provider_generation_identity", provider_generation_identity),
        ("since_epoch_ms", str(since_epoch_ms)),
        ("snapshot_epoch_ms", str(time.time_ns() // 1_000_000)),
        ("process_names", ",".join(names)),
        ("crash_count", str(len(copied))),
        ("crash_names_sha256", names_digest),
        ("schema_complete", "1"),
    ]
    _write_atomic(
        destination / "crash-snapshot.tsv",
        "".join(f"{key}\t{value}\n" for key, value in rows).encode("utf-8"),
    )
    return dict(rows)


def _crash_report_matches(
    filename: str, content: bytes, process_names: list[str]
) -> bool:
    if any(
        filename.startswith(name + "_") or filename.startswith(name + "-")
        for name in process_names
    ):
        return True
    if not filename.lower().endswith(".ips"):
        return False
    candidates = set()
    try:
        text = content.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return False
    # Current .ips files commonly contain a metadata JSON object on the first
    # line and a report object after it.  Inspect both without depending on one
    # OS-version-specific layout.
    objects = []
    lines = text.splitlines()
    for candidate_text in lines[:4] + [text]:
        try:
            objects.append(json.loads(candidate_text))
        except (ValueError, RecursionError):
            continue

    interesting = {
        "app_name", "bundleid", "bundleidentifier",
        "process", "processname", "procname", "procpath",
    }

    def visit(value, key=""):
        if isinstance(value, dict):
            for child_key, child in value.items():
                visit(child, str(child_key).lower())
        elif isinstance(value, list):
            for child in value:
                visit(child, key)
        elif isinstance(value, str) and key in interesting:
            candidates.add(value)
            candidates.add(Path(value).name)

    for parsed in objects:
        visit(parsed)
    return any(name in candidates for name in process_names)


def _verify_crash_snapshots(
    root: Path,
    status: dict[str, str],
    *,
    artifact_bytes: dict[str, bytes] | None = None,
    artifact_index: dict[str, tuple[int, str]] | None = None,
    ignore_member_snapshots: bool = False,
    required: bool = False,
) -> int | None:
    if artifact_index is None:
        snapshot_paths = sorted(root.rglob("crash-snapshot.tsv"))
        snapshot_names = [
            path.relative_to(root).as_posix() for path in snapshot_paths
            if not (
                ignore_member_snapshots
                and path.relative_to(root).parts[0] == "members"
            )
        ]
        snapshot_paths = [root / name for name in snapshot_names]
    else:
        snapshot_names = sorted(
            name for name in artifact_index
            if PurePosixPath(name).name == "crash-snapshot.tsv"
            and not (
                ignore_member_snapshots
                and PurePosixPath(name).parts[0] == "members"
            )
        )
        snapshot_paths = [root / name for name in snapshot_names]
    if len(snapshot_names) > 1:
        raise EvidenceError("multiple crash snapshots present")
    if not snapshot_names:
        if required:
            raise EvidenceError("complete evidence lacks a required crash snapshot")
        return None
    if required and snapshot_names != ["crashes/crash-snapshot.tsv"]:
        raise EvidenceError("required crash snapshot is not at its canonical root path")
    name = snapshot_names[0]
    path = snapshot_paths[0]
    if artifact_bytes is None:
        snapshot_content = _read_regular_bytes(path)
    else:
        try:
            snapshot_content = artifact_bytes[name]
        except KeyError as error:
            raise EvidenceError("crash snapshot bytes were not retained") from error
    values, _ = _parse_tsv_bytes(
        snapshot_content, expected_order=CRASH_SNAPSHOT_ORDER
    )
    if (
        values["schema_version"] != str(CRASH_SCHEMA_VERSION)
        or values["schema_complete"] != "1"
    ):
        raise EvidenceError("unsupported or incomplete crash snapshot")
    if (
        values["run_uuid"] != status["run_uuid"]
        or values["provider_generation_identity"]
            != status["provider_generation_identity"]
    ):
        raise EvidenceError("crash snapshot run/provider generation mismatch")
    since = _canonical_uint(values["since_epoch_ms"])
    captured = _canonical_uint(values["snapshot_epoch_ms"])
    count = _canonical_uint(values["crash_count"])
    run_start = _canonical_uint(status["run_start_epoch_ms"])
    run_end = _canonical_uint(status["run_end_epoch_ms"])
    if since == 0 or captured < since or since > run_start or captured < run_end:
        raise EvidenceError("invalid crash snapshot interval")
    process_names = values["process_names"].split(",")
    if (
        not process_names
        or process_names != sorted(set(process_names))
        or any(not name or Path(name).name != name for name in process_names)
    ):
        raise EvidenceError("invalid crash snapshot process-name set")
    if status["evidence_kind"] != "stress-series":
        expected_process = DEV_PROVIDER_BUNDLE_ID
        if status["provider_generation_identity"] not in ("absent", "unavailable"):
            try:
                identity_content = (
                    artifact_bytes[PROVIDER_IDENTITY_NAME]
                    if artifact_bytes is not None
                    else _read_regular_bytes(root / PROVIDER_IDENTITY_NAME)
                )
                expected_process = Path(
                    read_provider_identity_bytes(identity_content)["running_executable_path"]
                ).name
            except KeyError as error:
                raise EvidenceError("crash snapshot cannot bind provider executable") from error
        if expected_process not in process_names:
            raise EvidenceError("crash snapshot omits the exact provider executable")
    if artifact_index is None:
        report_names = sorted(
            candidate.name for candidate in path.parent.iterdir()
            if candidate.name != path.name
        )
        if any(
            (path.parent / report_name).is_symlink()
            or not (path.parent / report_name).is_file()
            for report_name in report_names
        ):
            raise EvidenceError("unsafe crash snapshot artifact")
    else:
        parent = PurePosixPath(name).parent
        report_names = sorted(
            PurePosixPath(candidate).name
            for candidate in artifact_index
            if PurePosixPath(candidate).parent == parent and candidate != name
        )
    expected_digest = hashlib.sha256("\n".join(report_names).encode("utf-8")).hexdigest()
    if count != len(report_names) or values["crash_names_sha256"] != expected_digest:
        raise EvidenceError("crash snapshot count/fingerprint mismatch")
    if status["passed"] == "1" and count != 0:
        raise EvidenceError("passing status contradicts captured provider crash")
    return captured


CONTRACT = """\
Shared signed-run evidence contract (schema 1)

Status: root evidence-status.tsv has exactly these rows, in order:
  complete, passed, exit_code, evidence_kind, run_uuid,
  run_start_epoch_ms, run_end_epoch_ms, git_head, git_dirty,
  provider_build_identity, provider_generation_identity,
  workload_claims_sha256, schema_complete.
Allowed outcomes are (complete,passed,exit): (1,1,0), (1,0,1),
(0,0,2), (0,0,130), or (0,0,143).  The outer script MUST exit with
that same code and SHOULD pass it to seal/verify with --actual-exit-code.

Claims: root workload-claims.tsv starts with evidence_kind matching status,
contains a mandatory run_uuid exactly matching status, contains unique non-empty
key/value TSV rows owned by that workload, and ends with schema_complete=1.
Status hashes its exact bytes.

Provider: capture-provider writes root provider-identity.tsv after matching the
built, installed, and current running provider to the exact development bundle
ID/team, embedded full clean git head, CDHash, executable hash, PID, process
start, and command fingerprint.  Capture fails on source/process races.
Attributed runs also use capture-provider-generation --identity FILE --output
provider-generation-samples.tsv for the first observation and --append for all
later observations. Its canonical PID/start/command/executable fingerprints,
cadence, and gap tolerance require at least three samples spanning the run
through the post-crash observation. Concurrent appenders are serialized.
The only exception is evidence_kind=stress-direct: both provider identities are
the literal `absent`, claims contain provider_absent=1, and root
provider-absence.tsv has at least two zero-match samples spanning the run.
Create its first sample with capture-provider-absence --output FILE and later
samples with capture-provider-absence --append FILE.  The proof encodes a
sampling cadence and a bounded gap tolerance; verification rejects gaps, so it
proves periodic observations rather than claiming impossible continuous
observation.  Matching uses only the exact /Library/SystemExtensions generation
path for the development provider.

Stress series: evidence_kind=stress-series declares one exact provider build
and provider_generation_identity=multiple.  Its claims require pair_count=3 and
candidate_generation_identities_sha256, computed over the sorted three member
generation IDs with one trailing newline per ID.  It embeds and verifies exactly
members/pair-001..003/{baseline,candidate}/ as six complete sealed envelopes.

Seal: evidence-manifest.tsv covers every recursive regular file, including
status, claims, identity, logs, Dial9, crashes, source, and git artifacts.  The
manifest excludes only itself.  Symlinks, temporary (*.tmp.*) artifacts,
missing, extra, changed, or truncated artifacts are rejected.  The manifest's
hash is deliberately absent from status, avoiding a circular hash.

Release set: verify-release-set requires all runs to pass and to have unique
kinds/UUIDs plus identical clean git head/provider build. Single-generation
runs must share one generation; a verified stress-series binds its three
self-contained member generations instead of falsely claiming one of them.
Release verification reruns each kind's evidence-head semantic validator over
a hash-checked materialization. Modern evidence also rebuilds the Dial9 decoder
from an archived clean checkout at that head, decodes the sealed trace set, and
requires the recomputed summary to equal the sealed JSON.
"""


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("help", help="print the shared evidence contract")

    capture = subparsers.add_parser("capture-provider")
    capture.add_argument("--built-provider", required=True, type=Path)
    capture.add_argument("--installed-provider", required=True, type=Path)
    capture.add_argument("--pid", required=True, type=int)
    capture.add_argument("--output", required=True, type=Path)
    capture.add_argument("--source-root", required=True, type=Path)

    executable = subparsers.add_parser("process-executable")
    executable.add_argument("--pid", required=True, type=int)

    absence = subparsers.add_parser("capture-provider-absence")
    absence_destination = absence.add_mutually_exclusive_group(required=True)
    absence_destination.add_argument("--output", type=Path)
    absence_destination.add_argument("--append", type=Path)
    absence.add_argument("--cadence-ms", type=int)
    absence.add_argument("--max-gap-ms", type=int)

    generation = subparsers.add_parser("capture-provider-generation")
    generation.add_argument("--identity", required=True, type=Path)
    generation_destination = generation.add_mutually_exclusive_group(required=True)
    generation_destination.add_argument("--output", type=Path)
    generation_destination.add_argument("--append", type=Path)
    generation.add_argument("--cadence-ms", type=int)
    generation.add_argument("--max-gap-ms", type=int)

    crashes = subparsers.add_parser("snapshot-crashes")
    crashes.add_argument("--since-epoch-ms", required=True, type=int)
    crashes.add_argument("--output-dir", required=True, type=Path)
    crashes.add_argument("--process", action="append", required=True)
    crashes.add_argument("--run-uuid", required=True)
    crashes.add_argument("--provider-generation-identity", required=True)
    crashes.add_argument("--report-dir", action="append", type=Path)

    seal_parser = subparsers.add_parser("seal")
    seal_parser.add_argument("directory", type=Path)
    seal_parser.add_argument("--actual-exit-code", type=int)
    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("directory", type=Path)
    verify_parser.add_argument("--actual-exit-code", type=int)
    release = subparsers.add_parser("verify-release-set")
    release.add_argument("directories", nargs="+", type=Path)
    release.add_argument("--require-kind", action="append")
    return parser


def main(arguments: list[str] | None = None) -> int:
    args = _parser().parse_args(arguments)
    try:
        if args.command == "help":
            print(CONTRACT, end="")
        elif args.command == "process-executable":
            print(_process_executable_path(args.pid))
        elif args.command == "capture-provider":
            values = capture_provider(
                args.built_provider,
                args.installed_provider,
                args.pid,
                args.output,
                args.source_root,
            )
            print(f"provider_build_identity\t{values['provider_build_identity']}")
            print(f"provider_generation_identity\t{values['provider_generation_identity']}")
        elif args.command == "snapshot-crashes":
            values = snapshot_crashes(
                args.since_epoch_ms,
                args.output_dir,
                args.process,
                run_uuid=args.run_uuid,
                provider_generation_identity=args.provider_generation_identity,
                report_dirs=args.report_dir,
            )
            print(f"crash_count\t{values['crash_count']}")
        elif args.command == "capture-provider-absence":
            path = args.append if args.append is not None else args.output
            values = capture_provider_absence(
                path,
                append=args.append is not None,
                cadence_ms=args.cadence_ms,
                max_gap_ms=args.max_gap_ms,
            )
            print(f"epoch_ms\t{values['epoch_ms']}")
            print(f"match_count\t{values['match_count']}")
            if values["match_count"] != "0":
                return 1
        elif args.command == "capture-provider-generation":
            path = args.append if args.append is not None else args.output
            values = capture_provider_generation(
                args.identity,
                path,
                append=args.append is not None,
                cadence_ms=args.cadence_ms,
                max_gap_ms=args.max_gap_ms,
            )
            print(f"epoch_ms\t{values['epoch_ms']}")
            print(f"running_pid\t{values['running_pid']}")
            print(f"running_start_epoch_ms\t{values['running_start_epoch_ms']}")
        elif args.command == "seal":
            print(seal(args.directory, args.actual_exit_code))
        elif args.command == "verify":
            values = verify(args.directory, args.actual_exit_code)
            print(f"verified\t{values['evidence_kind']}\t{values['run_uuid']}")
        elif args.command == "verify-release-set":
            values = verify_release_set(
                args.directories,
                set(args.require_kind) if args.require_kind else None,
            )
            print("verified_release_set\t" + ",".join(row["evidence_kind"] for row in values))
        else:  # pragma: no cover - argparse makes this unreachable
            raise EvidenceError("unknown command")
    except EvidenceError as error:
        print(f"signed evidence error: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
