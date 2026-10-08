#!/usr/bin/env python3
"""A/B compare a divan bench between a git ref and the working tree.

Both sides are built from the same directory (`target/divan-ab/src`, the base
exported with `git archive`, no worktree), one after the other: cargo derives
crate metadata, and so every `TypeId`, from the source path, and lookups that
hash type ids must see the same ids on both sides. The binaries then run
interleaved (ABBA rounds), so drift of the machine hits both sides alike. Per
case the median of the per-round medians is reported, with the ratio head/base
and the min-max of the per-round ratios: a range that spans 1.00 is noise.

    scripts/bench/divan_ab.py --bench extensions_lookup --features boring
    scripts/bench/divan_ab.py --base origin/main --bench pool_contention --features http-full -- multiplex
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import statistics
import subprocess
import sys
from pathlib import Path

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
# A row is either a group (name only) or a case (name, then the timing columns).
# Names can hold spaces (`Debug` of an argument), so a case name ends where the
# first timing column starts.
TIME = r"[\d.]+ [nµm]?s"
CASE_RE = re.compile(
    rf"^(?P<indent>[│ ]*)(?:├─|╰─) (?P<name>.+?)\s+(?P<fastest>{TIME})\s+│\s+(?P<slowest>{TIME})\s+│\s+(?P<median>{TIME})"
)
GROUP_RE = re.compile(r"^(?P<indent>[│ ]*)(?:├─|╰─) (?P<name>.+?)\s+│")
UNITS = {"ns": 1.0, "µs": 1e3, "us": 1e3, "ms": 1e6, "s": 1e9}


def to_ns(value: str) -> float:
    number, unit = value.split()
    return float(number) * UNITS[unit]


def parse(output: str) -> dict[str, float]:
    medians: dict[str, float] = {}
    stack: list[str] = []
    for line in output.splitlines():
        line = ANSI_RE.sub("", line)
        m = CASE_RE.match(line) or GROUP_RE.match(line)
        if not m:
            continue
        depth = len(m.group("indent")) // 3
        stack = stack[:depth] + [m.group("name").strip()]
        if "median" in m.groupdict() and m.group("median"):
            medians["/".join(stack)] = to_ns(m.group("median"))
    return medians


def run(cmd: list[str], cwd: Path) -> str:
    proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if proc.returncode != 0:
        sys.stderr.write(proc.stdout + proc.stderr)
        raise SystemExit(f"command failed ({proc.returncode}): {' '.join(cmd)}")
    return proc.stdout + proc.stderr


def build(src: Path, target_dir: Path, bench: str, features: str) -> Path:
    env = dict(os.environ, CARGO_TARGET_DIR=str(target_dir))
    cmd = ["cargo", "bench", "--bench", bench, "--no-run", "--message-format=json"]
    if features:
        cmd += ["--features", features]
    out = subprocess.run(cmd, cwd=src, env=env, capture_output=True, text=True)
    if out.returncode != 0:
        sys.stderr.write(out.stderr)
        raise SystemExit(f"build failed in {src}")
    for line in out.stdout.splitlines():
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        if msg.get("reason") == "compiler-artifact" and msg.get("executable"):
            if msg["target"]["name"] == bench:
                return Path(msg["executable"])
    raise SystemExit(f"no executable found for bench {bench}")


def sync(source: Path, files: list[str], dest: Path) -> None:
    """Mirror `files` of `source` into `dest`, and remove anything else there.

    Compares by content and gives changed files a fresh mtime (no `-t`), so
    cargo rebuilds exactly what differs from the previous side.
    """
    subprocess.run(
        ["rsync", "-rlp", "--checksum", "--from0", "--files-from=-", f"{source}/", f"{dest}/"],
        input="\0".join(files).encode(),
        check=True,
    )
    keep = set(files)
    for path in dest.rglob("*"):
        if path.is_file() and path.relative_to(dest).as_posix() not in keep:
            path.unlink()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--base", default="HEAD", help="git ref to compare against (default: HEAD)")
    parser.add_argument("--bench", required=True)
    parser.add_argument("--features", default="")
    parser.add_argument("--rounds", type=int, default=6, help="ABBA rounds, rounded up to even (default: 6)")
    parser.add_argument("--sample-count", type=int, default=200)
    parser.add_argument(
        "--base-bench-src",
        action="store_true",
        help="build the base with its own bench sources (default: the working tree's, so new cases compare too)",
    )
    parser.add_argument(
        "--overlay",
        action="append",
        default=[],
        help="copy this working tree path into the base too (repeatable), e.g. a Cargo.toml the new bench setup needs",
    )
    parser.add_argument("divan_args", nargs="*", help="extra divan args, e.g. a filter")
    args = parser.parse_args()

    repo = Path(run(["git", "rev-parse", "--show-toplevel"], Path.cwd()).strip())
    sha = run(["git", "rev-parse", "--short", args.base], repo).strip()
    work = repo / "target" / "divan-ab"
    src, bins, export = work / "src", work / "bin", work / "export"
    src.mkdir(parents=True, exist_ok=True)
    bins.mkdir(parents=True, exist_ok=True)

    print(f"building base {sha} ...", file=sys.stderr)
    if export.exists():
        shutil.rmtree(export)
    export.mkdir()
    archive = subprocess.Popen(["git", "archive", sha], cwd=repo, stdout=subprocess.PIPE)
    subprocess.run(["tar", "-x", "-C", str(export)], stdin=archive.stdout, check=True)
    archive.wait()
    overlays = args.overlay if args.base_bench_src else ["benches", *args.overlay]
    for overlay in overlays:
        source = repo / overlay
        if source.is_dir():
            shutil.copytree(source, export / overlay, dirs_exist_ok=True)
        else:
            shutil.copy2(source, export / overlay)
    sync(export, [p.relative_to(export).as_posix() for p in export.rglob("*") if p.is_file()], src)
    base_bin = bins / "base"
    shutil.copy2(build(src, work / "target", args.bench, args.features), base_bin)

    print("building head (working tree) ...", file=sys.stderr)
    listed = run(["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"], repo)
    sync(repo, [f for f in listed.split("\0") if f and (repo / f).is_file()], src)
    head_bin = bins / "head"
    shutil.copy2(build(src, work / "target", args.bench, args.features), head_bin)

    divan = ["--sample-count", str(args.sample_count), *args.divan_args]
    results: dict[str, dict[str, list[float]]] = {"base": {}, "head": {}}
    rounds = args.rounds + args.rounds % 2
    for i in range(rounds):
        order = [("base", base_bin), ("head", head_bin)]
        if i % 2:
            order.reverse()
        for side, binary in order:
            print(f"round {i + 1}/{rounds}: {side}", file=sys.stderr)
            for case, ns in parse(run([str(binary), "--bench", *divan], repo)).items():
                results[side].setdefault(case, []).append(ns)

    width = max([44, *(len(case) for case in results["base"])])
    print(f"{'case':{width}s} {'base':>11s} {'head':>11s}  ratio  (range)")
    for case, base in results["base"].items():
        head = results["head"].get(case)
        if not head:
            continue
        ratios = [h / b for b, h in zip(base, head)]
        b, h = statistics.median(base), statistics.median(head)
        lo, hi = min(ratios), max(ratios)
        verdict = "~" if lo <= 1.0 <= hi else ("faster" if hi < 1.0 else "SLOWER")
        print(f"{case:{width}s} {b:9.1f}ns {h:9.1f}ns  {h / b:5.2f}x ({lo:4.2f}-{hi:4.2f}) {verdict}")


if __name__ == "__main__":
    main()
