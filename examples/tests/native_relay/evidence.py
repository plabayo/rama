"""Select decoded evidence for local inspection and CI artifact upload.

Raw packet captures, private keys and executables stay outside this directory.
The allowlist is shared by successful and failed runs.
"""

from pathlib import Path
import shutil

REPORTS = (
    "comparison.json",
    "cleanup.json",
    "dependency-graph.txt",
    "binaries.json",
    "client.jsonl",
    "client.log",
    "fixture-build.log",
    "ingress.pdml",
    "egress.pdml",
)
WEBSOCKET_REPORTS = ("*.json", "*.log", "*.pdml", "*.tls-stream.txt")


def export_evidence(output: Path) -> None:
    """Copy available reports into artifacts/, including incomplete failed runs."""
    artifacts = output / "artifacts"
    artifacts.mkdir()
    candidates = [output / name for name in REPORTS]
    websocket = output / "websocket"
    if not websocket.is_symlink():
        for pattern in WEBSOCKET_REPORTS:
            candidates.extend(websocket.glob(pattern))

    for source in candidates:
        # Never follow links into private files or outside this owned run.
        if source.is_symlink() or not source.is_file():
            continue
        destination = artifacts / source.relative_to(output)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
