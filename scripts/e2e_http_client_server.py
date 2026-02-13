#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

DEFAULT_CMD = (
    "cargo bench --bench e2e_http_client_server --features http-full,rustls,boring"
)

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
UNITS_TIME = {"ns": 1e-9, "µs": 1e-6, "us": 1e-6, "ms": 1e-3, "s": 1.0}
UNITS_BYTES = {
    "B": 1.0,
    "KB": 1024.0,
    "MB": 1024.0**2,
    "GB": 1024.0**3,
    "TB": 1024.0**4,
}


def strip_ansi(s: str) -> str:
    return ANSI_RE.sub("", s)


def now_iso_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def parse_number(s: str) -> Optional[float]:
    try:
        return float(s)
    except Exception:
        return None


def parse_time_to_seconds(token: str) -> Optional[float]:
    m = re.match(r"^\s*([0-9]+(?:\.[0-9]+)?)\s*([a-zA-Zµ]+)\s*$", token)
    if not m:
        return None
    val = parse_number(m.group(1))
    unit = m.group(2)
    if val is None:
        return None
    mul = UNITS_TIME.get(unit)
    if mul is None:
        return None
    return val * mul


def parse_bytes(token: str) -> Optional[float]:
    m = re.match(r"^\s*([0-9]+(?:\.[0-9]+)?)\s*([KMGTP]?B)\s*$", token)
    if not m:
        return None
    val = parse_number(m.group(1))
    unit = m.group(2)
    if val is None:
        return None
    mul = UNITS_BYTES.get(unit)
    if mul is None:
        return None
    return val * mul


def parse_throughput(token: str) -> Optional[float]:
    m = re.match(r"^\s*([0-9]+(?:\.[0-9]+)?)\s*([KMGTP]?B)/s\s*$", token)
    if not m:
        return None
    val = parse_number(m.group(1))
    unit = m.group(2)
    if val is None:
        return None
    mul = UNITS_BYTES.get(unit)
    if mul is None:
        return None
    return val * mul


def human_bar(value: float, max_value: float, width: int = 28) -> str:
    if max_value <= 0:
        return " " * width
    ratio = value / max_value
    ratio = 0.0 if ratio < 0 else 1.0 if ratio > 1 else ratio
    filled = int(round(ratio * width))
    if filled <= 0:
        return " " * width
    if filled >= width:
        return "█" * width
    return "█" * filled + " " * (width - filled)


def fmt_seconds(s: float) -> str:
    if s < 1e-6:
        return f"{s * 1e9:.3g} ns"
    if s < 1e-3:
        return f"{s * 1e6:.3g} µs"
    if s < 1.0:
        return f"{s * 1e3:.3g} ms"
    return f"{s:.3g} s"


def fmt_bytes(b: float) -> str:
    if b < 1024:
        return f"{b:.3g} B"
    kb = b / 1024.0
    if kb < 1024:
        return f"{kb:.3g} KB"
    mb = kb / 1024.0
    if mb < 1024:
        return f"{mb:.3g} MB"
    gb = mb / 1024.0
    if gb < 1024:
        return f"{gb:.3g} GB"
    tb = gb / 1024.0
    return f"{tb:.3g} TB"


@dataclass
class StatRow:
    fastest: Optional[float] = None
    slowest: Optional[float] = None
    median: Optional[float] = None
    mean: Optional[float] = None
    samples: Optional[int] = None
    iters: Optional[int] = None


@dataclass
class BenchCase:
    name: str
    group: Optional[str]
    time_s: StatRow
    throughput_bps: StatRow
    metrics: Dict[str, StatRow]


@dataclass
class BenchRun:
    cmd: str
    started_at_utc: str
    cwd: str
    raw_head: List[str]
    cases: List[BenchCase]


def run_command(cmd: str) -> Tuple[int, str]:
    proc = subprocess.run(
        cmd,
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        env=os.environ.copy(),
    )
    return proc.returncode, proc.stdout


def find_header_starts(line: str) -> Optional[Dict[str, int]]:
    lowered = line.lower()
    needed = ["fastest", "slowest", "median", "mean", "samples", "iters"]
    if not all(k in lowered for k in needed):
        return None

    starts: Dict[str, int] = {}
    for k in needed:
        idx = lowered.find(k)
        if idx < 0:
            return None
        starts[k] = idx

    # ensure order makes sense
    order = [starts[k] for k in needed]
    if order != sorted(order):
        # if something odd happened, still reject
        return None

    return starts


def slice_row(line: str, starts: Dict[str, int]) -> Tuple[str, Dict[str, str]]:
    # Create ordered boundaries
    keys = ["fastest", "slowest", "median", "mean", "samples", "iters"]
    bounds = [starts[k] for k in keys]
    label = line[: bounds[0]].strip()

    fields: Dict[str, str] = {}
    for i, k in enumerate(keys):
        start = bounds[i]
        end = bounds[i + 1] if i + 1 < len(bounds) else len(line)
        fields[k] = line[start:end].strip(" │|").strip()
    return label, fields


def parse_stat_from_fields(fields: Dict[str, str], parse_value_fn) -> StatRow:
    fastest = parse_value_fn(fields.get("fastest", ""))
    slowest = parse_value_fn(fields.get("slowest", ""))
    median = parse_value_fn(fields.get("median", ""))
    mean = parse_value_fn(fields.get("mean", ""))

    samples_s = fields.get("samples", "")
    iters_s = fields.get("iters", "")
    samples = int(samples_s) if samples_s.isdigit() else None
    iters = int(iters_s) if iters_s.isdigit() else None

    return StatRow(
        fastest=fastest,
        slowest=slowest,
        median=median,
        mean=mean,
        samples=samples,
        iters=iters,
    )


def normalize_metric_key(section: str, kind: str) -> str:
    return f"{section}.{kind}"


def parse_bench_output(text: str, cmd: str, cwd: str, debug: bool) -> BenchRun:
    lines = [strip_ansi(l.rstrip("\n")) for l in text.splitlines()]
    raw_head = lines[:80]

    starts: Optional[Dict[str, int]] = None
    group_name: Optional[str] = None
    cases: List[BenchCase] = []

    current_case: Optional[BenchCase] = None
    current_metric_section: Optional[str] = None
    expecting_metric_rows: int = 0

    for line in lines:
        if starts is None:
            maybe = find_header_starts(line)
            if maybe:
                starts = maybe
                if debug:
                    sys.stderr.write(f"Detected header starts: {starts}\n")
                    sys.stderr.write(f"Header line: {line}\n")
            continue

        # group line, eg "╰─ bench_http_transport"
        if line.strip().startswith(("╰─", "├─")) and "bench_" in line:
            group_name = line.strip().lstrip("╰─").lstrip("├─").strip()
            continue

        # case line
        if "TestParameters" in line and line.strip().startswith(("├─", "╰─")):
            label, fields = slice_row(line, starts)
            if parse_time_to_seconds(fields.get("fastest", "")) is not None:
                current_case = BenchCase(
                    name=label.lstrip("├─").lstrip("╰─").strip(),
                    group=group_name,
                    time_s=parse_stat_from_fields(fields, parse_time_to_seconds),
                    throughput_bps=StatRow(),
                    metrics={},
                )
                cases.append(current_case)
                current_metric_section = None
                expecting_metric_rows = 0
            continue

        # throughput line
        if current_case and re.search(r"[KMGTP]?B/s", line):
            _, fields = slice_row(line, starts)
            tp = parse_stat_from_fields(fields, parse_throughput)
            if tp.fastest is not None or tp.mean is not None:
                current_case.throughput_bps = tp
                current_metric_section = None
                expecting_metric_rows = 0
            continue

        # metric section label
        if current_case:
            m = re.match(r"^\s*[│| ]*\s*([a-zA-Z ]+):\s*$", line)
            if m:
                current_metric_section = m.group(1).strip().lower()
                expecting_metric_rows = 2
                continue

        # metric rows (count then bytes usually)
        if current_case and current_metric_section and expecting_metric_rows > 0:
            _, fields = slice_row(line, starts)
            fastest_cell = fields.get("fastest", "").strip()

            is_count = bool(re.fullmatch(r"\d+(\.\d+)?", fastest_cell))
            kind = "count" if is_count else "bytes"

            def parse_metric_value(x: str):
                if is_count:
                    return parse_number(x.strip())
                return parse_bytes(x.strip())

            row = parse_stat_from_fields(fields, parse_metric_value)
            current_case.metrics[normalize_metric_key(current_metric_section, kind)] = (
                row
            )

            expecting_metric_rows -= 1
            if expecting_metric_rows == 0:
                current_metric_section = None

    if debug:
        sys.stderr.write(f"Parsed cases: {len(cases)}\n")

    return BenchRun(
        cmd=cmd,
        started_at_utc=now_iso_utc(),
        cwd=cwd,
        raw_head=raw_head,
        cases=cases,
    )


def payload_bucket(case_name: str) -> str:
    # Expected substring inside case_name:
    # "server: Large, client: Small" etc
    m_server = re.search(r"\bserver:\s*(Small|Large)\b", case_name)
    m_client = re.search(r"\bclient:\s*(Small|Large)\b", case_name)
    if not m_server or not m_client:
        return "unknown"

    server = m_server.group(1)
    client = m_client.group(1)

    if server == "Small" and client == "Small":
        return "small/small"
    if server == "Large" and client == "Large":
        return "big/big"
    return "mixed"


def print_group_charts(title: str, cases: List["BenchCase"]) -> None:
    if not cases:
        return

    # Mean time
    time_means = [(c, c.time_s.mean) for c in cases if c.time_s.mean is not None]
    if time_means:
        max_time = max(v for _, v in time_means if v is not None)
        print(f"\n{title}\n")
        print("Mean time (lower is better)\n")
        for c, v in sorted(time_means, key=lambda x: x[1]):
            bar = human_bar(v, max_time, width=32)
            print(f"{fmt_seconds(v):>10}  {bar}  {c.name}")

    # Mean throughput
    tp_means = [
        (c, c.throughput_bps.mean) for c in cases if c.throughput_bps.mean is not None
    ]
    if tp_means:
        max_tp = max(v for _, v in tp_means if v is not None)
        print("\nMean throughput (higher is better)\n")
        for c, v in sorted(tp_means, key=lambda x: x[1], reverse=True):
            bar = human_bar(v, max_tp, width=32)
            print(f"{fmt_bytes(v):>10}/s  {bar}  {c.name}")


def print_ascii_charts(run: BenchRun) -> None:
    if not run.cases:
        print("No benchmark cases parsed.")
        return

    buckets: Dict[str, List[BenchCase]] = {
        "small/small": [],
        "mixed": [],
        "big/big": [],
        "unknown": [],
    }

    for c in run.cases:
        buckets[payload_bucket(c.name)].append(c)

    # Print in your requested order
    print_group_charts("Payload group: small / small", buckets["small/small"])
    print_group_charts("Payload group: small / big or big / small", buckets["mixed"])
    print_group_charts("Payload group: big / big", buckets["big/big"])

    # If anything did not match expected patterns, still show it
    if buckets["unknown"]:
        print_group_charts("Payload group: unknown", buckets["unknown"])


def run_to_jsonable(run: BenchRun) -> Dict[str, Any]:
    def row(r: StatRow) -> Dict[str, Any]:
        return {
            "fastest": r.fastest,
            "slowest": r.slowest,
            "median": r.median,
            "mean": r.mean,
            "samples": r.samples,
            "iters": r.iters,
        }

    return {
        "cmd": run.cmd,
        "started_at_utc": run.started_at_utc,
        "cwd": run.cwd,
        "raw_head": run.raw_head,
        "cases": [
            {
                "name": c.name,
                "group": c.group,
                "time_s": row(c.time_s),
                "throughput_bps": row(c.throughput_bps),
                "metrics": {k: row(v) for k, v in c.metrics.items()},
            }
            for c in run.cases
        ],
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cmd", default=DEFAULT_CMD)
    ap.add_argument("--json-out", default=None)
    ap.add_argument("--allow-nonzero", action="store_true")
    ap.add_argument("--debug", action="store_true")
    args = ap.parse_args()

    rc, out = run_command(args.cmd)
    if rc != 0 and not args.allow_nonzero:
        sys.stderr.write(out)
        sys.stderr.write(f"\nCommand failed with exit code {rc}\n")
        sys.stderr.write("Use --allow-nonzero to still attempt parsing.\n")
        return rc

    run = parse_bench_output(out, cmd=args.cmd, cwd=os.getcwd(), debug=args.debug)

    if args.json_out:
        payload = run_to_jsonable(run)
        os.makedirs(os.path.dirname(os.path.abspath(args.json_out)), exist_ok=True)
        with open(args.json_out, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, sort_keys=True)
        print(args.json_out)
        return 0

    print_ascii_charts(run)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
