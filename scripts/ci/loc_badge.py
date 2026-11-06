#!/usr/bin/env python3
"""Count tracked source lines, optionally writing a shields.io endpoint badge.

Every line counts, blank and comment lines included.
"""

from collections import Counter
import json
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[2]
LANGUAGES = {".rs": "Rust", ".swift": "Swift", ".c": "C", ".h": "C", ".py": "Python"}


def short(n):
    if n >= 1_000_000:
        return f"{n / 1_000_000:.2f}M"
    if n >= 1_000:
        return f"{n / 1_000:.1f}k"
    return str(n)


def main(output=None):
    files = subprocess.run(
        ["git", "ls-files", "-z", "--", *(f"*{ext}" for ext in LANGUAGES)],
        cwd=ROOT, check=True, capture_output=True,
    ).stdout.decode().split("\0")
    lines = Counter()
    for name in filter(None, files):
        data = (ROOT / name).read_bytes()
        # A final line without a trailing newline still counts.
        lines[LANGUAGES[Path(name).suffix]] += data.count(b"\n") + (data[-1:] not in (b"", b"\n"))
    total = sum(lines.values())
    for language, count in lines.most_common():
        print(f"{language:<8}{count:>12,}")
    print(f"{'Total':<8}{total:>12,}")
    if output:
        badge = {"schemaVersion": 1, "label": "LoC", "message": short(total), "color": "blue"}
        Path(output).parent.mkdir(parents=True, exist_ok=True)
        Path(output).write_text(json.dumps(badge) + "\n")


if __name__ == "__main__":
    main(*sys.argv[1:2])
