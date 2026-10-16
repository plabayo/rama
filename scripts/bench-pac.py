#!/usr/bin/env python3
"""Compare Winch/Pulley PAC startup and evaluation in fresh processes.

Run from anywhere: python3 scripts/bench-pac.py --runs 3 --output /tmp/pac.json
Only the Python standard library and Cargo are needed. Builds use bench profile.
"""

import argparse
import csv
import io
import json
import os
import platform
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def capture(*args):
    return subprocess.check_output(args, cwd=ROOT, text=True).strip()


def build(features):
    result = subprocess.run(
        ["cargo", "bench", "--locked", "-p", "rama-pac", "--bench", "pac",
         "--no-default-features", "--features", features, "--no-run",
         "--message-format=json"],
        cwd=ROOT, text=True, stdout=subprocess.PIPE,
    )
    executable = None
    for line in result.stdout.splitlines():
        artifact = json.loads(line)
        if artifact.get("reason") == "compiler-message":
            print(artifact["message"].get("rendered", ""), file=sys.stderr, end="")
        if (artifact.get("reason") == "compiler-artifact"
                and artifact["target"]["name"] == "pac"
                and artifact.get("executable")):
            executable = artifact["executable"]
    result.check_returncode()
    if executable:
        return executable
    raise RuntimeError("Cargo did not report the PAC benchmark executable")


def measure(binary, cache, mode, run):
    env = dict(os.environ)
    env.pop("RAMA_PAC_BENCH_CACHE", None)
    if cache is not None:
        env["RAMA_PAC_BENCH_CACHE"] = str(cache)
    result = subprocess.run([binary], cwd=ROOT, env=env, text=True,
                            stdout=subprocess.PIPE, check=True, timeout=300)
    row, = csv.DictReader(io.StringIO(result.stdout))
    return {"backend": row["backend"], "mode": mode, "run": run,
            **{key: float(value) for key, value in row.items() if key != "backend"}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.runs < 1:
        parser.error("--runs must be positive")
    metadata = {
        "os": platform.platform(), "architecture": platform.machine(),
        "rustc": capture("rustc", "--version"),
        "revision": capture("git", "rev-parse", "HEAD"),
        "dirty": bool(capture("git", "status", "--porcelain")),
    }
    if platform.system() == "Darwin":
        metadata["cpu"] = capture("sysctl", "-n", "machdep.cpu.brand_string")
    rows = []
    # Finish both builds before timing, then alternate backend order between
    # repetitions to reduce bias from machine load, temperature, and ordering.
    binaries = [build(features) for features in
                ["js-disk-cache", "js-disk-cache,js-interpreter"]]
    for run in range(1, args.runs + 1):
        order = binaries if run % 2 else reversed(binaries)
        for binary in order:
            with tempfile.TemporaryDirectory(prefix="rama-pac-bench-") as cache:
                for mode in ["disabled", "empty", "warm"]:
                    if mode == "warm" and not any(path.is_file() and path.stat().st_size
                                                  for path in Path(cache).rglob("*")):
                        raise RuntimeError("The empty-cache run did not populate its cache")
                    row = measure(binary, None if mode == "disabled" else cache, mode, run)
                    rows.append(row)
                    print(f"{row['backend']} {mode} run {run}: {row['mean_us']:.1f} us/request", file=sys.stderr)
                    # Preserve every completed measurement if a later run fails.
                    args.output.write_text(json.dumps({"metadata": metadata, "results": rows}, indent=2) + "\n")
    print(args.output)


if __name__ == "__main__":
    main()
