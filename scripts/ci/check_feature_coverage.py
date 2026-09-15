#!/usr/bin/env python3
"""Verify that the two cargo-hack partitions preserve the former jobs' union.

Records Cargo commands; it does not compile any targets. Keep the two original
selections here so future partition changes cannot drop coverage. cargo-hack
0.6.45's --print-command-list does not advance its partition counter, so use a
recording Cargo shim to exercise its real partition scheduler instead.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BASE = ["--each-feature", "--no-dev-deps", "--workspace"]


def commands(*extra):
    with tempfile.TemporaryDirectory(prefix="rama-feature-coverage-") as temp:
        shim = Path(temp) / "cargo-recorder"
        record = Path(temp) / "commands.jsonl"
        shim.write_text(f"#!{sys.executable}\n" + '''import json, os, sys
args = sys.argv[1:]
if args and args[0] == "check":
    with open(os.environ["RAMA_CARGO_RECORD"], "a") as out:
        out.write(json.dumps(args) + "\\n")
elif args and args[0] in ("metadata", "locate-project", "--version", "-V", "-vV"):
    os.execv(os.environ["RAMA_REAL_CARGO"], [os.environ["RAMA_REAL_CARGO"], *args])
else:
    sys.exit("Unexpected Cargo command in coverage recorder: " + repr(args))
''')
        shim.chmod(0o755)
        result = subprocess.run(
            ["cargo", "hack", "check", *BASE, *extra], cwd=ROOT, text=True,
            capture_output=True, env={
                **os.environ, "CARGO_HACK_CARGO_SRC": str(shim),
                "RAMA_REAL_CARGO": shutil.which("cargo"), "RAMA_CARGO_RECORD": str(record),
            },
        )
        if result.returncode:
            sys.exit(result.stdout + result.stderr)
        return {tuple(json.loads(line)) for line in record.read_text().splitlines()}


def main():
    original = commands() | commands("--exclude-features", "dial9", "--exclude-all-features")
    first = commands("--partition", "1/2")
    second = commands("--partition", "2/2")
    assert first.isdisjoint(second), "Feature partitions overlap"
    assert first | second == original, {
        "missing": sorted(original - (first | second)),
        "unexpected": sorted((first | second) - original),
    }
    print(f"All {len(original)} original feature checks preserved: {len(first)} + {len(second)}")


if __name__ == "__main__":
    main()
