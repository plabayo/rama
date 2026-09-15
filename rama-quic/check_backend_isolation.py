#!/usr/bin/env python3
"""Reject accidental native TLS/crypto dependencies in Boring-only consumers."""
from pathlib import Path
import subprocess
import re

ROOT = Path(__file__).resolve().parent.parent
FORBIDDEN = {"ring", "aws-lc-rs", "aws-lc-sys", "rustls", "rama-tls-rustls"}


def check(arguments, subtree=None, features="boring"):
    result = subprocess.check_output(
        ["cargo", "tree", *arguments, "--no-default-features", "--features", features,
         "--edges", "normal,build,dev", "--prefix", "depth", "--format", "{p}", "--locked", "--no-dedupe"],
        cwd=ROOT, text=True,
    )
    packages = set()
    selected_depth = None
    found = subtree is None
    for line in result.splitlines():
        depth, package = re.match(r"^(\d+)(\S+)", line).groups()
        depth = int(depth)
        if selected_depth is not None and depth <= selected_depth:
            selected_depth = None
        if package == subtree:
            selected_depth = depth
            found = True
        if subtree is None or selected_depth is not None:
            packages.add(package)
    if not found:
        raise RuntimeError(f"{arguments}: missing dependency subtree {subtree}")
    unexpected = sorted(packages & FORBIDDEN)
    if unexpected:
        raise RuntimeError(f"{arguments}: Boring-only build includes {unexpected}")
    print(f"Boring isolation verified: {' '.join(arguments)}")


if __name__ == "__main__":
    for package in ("rama-crypto", "rama-quic"):
        check(["--package", package])
    for package in ("rama", "rama-examples"):
        check(["--package", package], features="quic,boring")
    for project in ("interop-common", "interop-runner", "aioquic-interop", "quiche-interop"):
        check(["--manifest-path", f"rama-quic/e2e/{project}/Cargo.toml"])
    # Quinn's independent peer intentionally uses Rustls+ring. Inspect only Rama's subtree.
    check(["--manifest-path", "rama-quic/e2e/quinn-interop/Cargo.toml"], subtree="rama")
