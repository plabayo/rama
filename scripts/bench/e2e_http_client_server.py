#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import queue
import re
import shlex
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

DEFAULT_CMD = "cargo bench --bench e2e_http_client_server --features http-full,rustls,aws-lc,boring,socks5"

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
UNITS_TIME = {"ns": 1e-9, "µs": 1e-6, "us": 1e-6, "ms": 1e-3, "s": 1.0}
UNITS_BYTES = {
    "B": 1.0,
    "KB": 1024.0,
    "MB": 1024.0**2,
    "GB": 1024.0**3,
    "TB": 1024.0**4,
}

HEADER_KEYS = ["fastest", "slowest", "median", "mean", "samples", "iters"]


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


def pct_change(new: float, old: float) -> Optional[float]:
    if old == 0:
        return None
    return ((new - old) / old) * 100.0


def status_line(msg: str) -> None:
    # stderr so it does not mix with streamed stdout output
    sys.stderr.write("\r" + msg[:120].ljust(120))
    sys.stderr.flush()


def status_done() -> None:
    sys.stderr.write("\r" + (" " * 120) + "\r")
    sys.stderr.flush()


def shorten_status_label(label: str, max_len: int = 72) -> str:
    label = re.sub(r"\s+", " ", label).strip()
    if len(label) <= max_len:
        return label
    return label[: max_len - 3] + "..."


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


def run_command_streaming(
    cmd: str, debug: bool, show_progress: bool
) -> Tuple[int, str]:
    if show_progress:
        status_line("Phase: starting command")

    proc = subprocess.Popen(
        cmd,
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        universal_newlines=True,
        env=os.environ.copy(),
    )

    assert proc.stdout is not None
    collected: List[str] = []
    line_queue: "queue.Queue[Optional[str]]" = queue.Queue()

    phase = "starting"
    running = False
    bench_rows_seen = 0
    last_case_label: Optional[str] = None
    started_at = time.monotonic()
    last_status_update = started_at

    def enqueue_stdout() -> None:
        assert proc.stdout is not None
        for line in proc.stdout:
            line_queue.put(line)
        line_queue.put(None)

    reader = threading.Thread(target=enqueue_stdout, daemon=True)
    reader.start()

    while True:
        try:
            line = line_queue.get(timeout=0.5)
        except queue.Empty:
            if show_progress and running:
                now = time.monotonic()
                if now - last_status_update >= 1.0:
                    elapsed = now - started_at
                    if last_case_label:
                        status_line(
                            f"Phase: running benches [{bench_rows_seen} cases completed, {elapsed:.0f}s elapsed] "
                            f"last completed: {shorten_status_label(last_case_label)}"
                        )
                    else:
                        status_line(
                            f"Phase: running benches [{elapsed:.0f}s elapsed, waiting for first completed case]"
                        )
                    last_status_update = now
            if proc.poll() is not None:
                break
            continue

        if line is None:
            break

        if debug:
            sys.stdout.write(line)
            sys.stdout.flush()
        collected.append(line)

        if not show_progress:
            continue

        s = strip_ansi(line).strip()

        # Very light heuristics, safe and useful
        if s.startswith("Compiling ") or s.startswith("Building "):
            if phase != "compiling":
                phase = "compiling"
                status_line("Phase: compiling")
        elif "Finished `bench` profile" in s or s.startswith("Finished `bench`"):
            phase = "compiled"
            status_line("Phase: compile finished, preparing to run benches")
        elif s.startswith("Running benches/") or s.startswith("Running "):
            running = True
            phase = "running"
            status_line("Phase: running benches")
            last_status_update = time.monotonic()
        elif running and "TestParameters" in s and s.startswith(("├─", "╰─")):
            bench_rows_seen += 1
            last_case_label = s
            status_line(
                f"Phase: running benches [{bench_rows_seen} cases completed] {shorten_status_label(s)}"
            )
            last_status_update = time.monotonic()
        elif any(k in s.lower() for k in ["timer precision", "tracing will be piped"]):
            if running:
                status_line("Phase: running benches, collecting results")
                last_status_update = time.monotonic()
        elif all(
            k in s.lower()
            for k in ["fastest", "slowest", "median", "mean", "samples", "iters"]
        ):
            status_line("Phase: benchmark table detected")
            last_status_update = time.monotonic()

    proc.wait()

    if show_progress:
        if proc.returncode == 0:
            status_line("Phase: command finished, parsing output")
        else:
            status_line(
                f"Phase: command finished with exit code {proc.returncode}, parsing output"
            )

    return proc.returncode, "".join(collected)


def find_header_starts(line: str) -> Optional[Dict[str, int]]:
    lowered = line.lower()
    if not all(k in lowered for k in HEADER_KEYS):
        return None

    starts: Dict[str, int] = {}
    for k in HEADER_KEYS:
        idx = lowered.find(k)
        if idx < 0:
            return None
        starts[k] = idx

    order = [starts[k] for k in HEADER_KEYS]
    if order != sorted(order):
        return None
    return starts


def slice_row(line: str, starts: Dict[str, int]) -> Tuple[str, Dict[str, str]]:
    bounds = [starts[k] for k in HEADER_KEYS]
    label = line[: bounds[0]].strip()

    fields: Dict[str, str] = {}
    for i, k in enumerate(HEADER_KEYS):
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
                    sys.stderr.write(f"\nDetected header starts: {starts}\n")
                    sys.stderr.write(f"Header line: {line}\n")
            continue

        if line.strip().startswith(("╰─", "├─")) and "bench_" in line:
            group_name = line.strip().lstrip("╰─").lstrip("├─").strip()
            continue

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

        if current_case and re.search(r"[KMGTP]?B/s", line):
            _, fields = slice_row(line, starts)
            tp = parse_stat_from_fields(fields, parse_throughput)
            if tp.fastest is not None or tp.mean is not None:
                current_case.throughput_bps = tp
                current_metric_section = None
                expecting_metric_rows = 0
            continue

        if current_case:
            m = re.match(r"^\s*[│| ]*\s*([a-zA-Z ]+):\s*$", line)
            if m:
                current_metric_section = m.group(1).strip().lower()
                expecting_metric_rows = 2
                continue

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
        sys.stderr.write(f"\nParsed cases: {len(cases)}\n")

    return BenchRun(
        cmd=cmd,
        started_at_utc=now_iso_utc(),
        cwd=cwd,
        raw_head=raw_head,
        cases=cases,
    )


def payload_bucket(case_name: str) -> str:
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


def extract_case_field(case_name: str, field: str) -> Optional[str]:
    pattern = rf"\b{re.escape(field)}:\s*([A-Za-z0-9_]+)\b"
    m = re.search(pattern, case_name)
    if not m:
        return None
    return m.group(1)


def proxy_bucket(case_name: str) -> str:
    proxy = extract_case_field(case_name, "proxy")
    if proxy is None:
        return "unknown"
    return proxy.lower()


def short_case_label(case_name: str) -> str:
    version = extract_case_field(case_name, "version") or "?"
    tls = extract_case_field(case_name, "tls") or "?"
    server = extract_case_field(case_name, "server") or "?"
    client = extract_case_field(case_name, "client") or "?"
    return f"{version} {tls} s:{server} c:{client}"


def case_key(case_name: str) -> str:
    return re.sub(r"\s+", " ", case_name).strip()


def load_baseline(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def baseline_index(baseline_json: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    cases = baseline_json.get("cases", [])
    out: Dict[str, Dict[str, Any]] = {}
    for c in cases:
        name = case_key(str(c.get("name", "")))
        if name:
            out[name] = c
    return out


def pct_fmt(delta: Optional[float]) -> str:
    if delta is None:
        return "n/a"
    return f"{delta:+.2f}%"


def print_group_charts(
    title: str,
    cases: List[BenchCase],
    baseline_map: Optional[Dict[str, Dict[str, Any]]],
) -> None:
    if not cases:
        return

    print(f"\n{title}\n")

    time_rows: List[Tuple[BenchCase, float, Optional[float]]] = []
    for c in cases:
        if c.time_s.mean is None:
            continue
        old = None
        if baseline_map:
            bc = baseline_map.get(case_key(c.name))
            if bc:
                old = bc.get("time_s", {}).get("mean", None)
        time_rows.append((c, c.time_s.mean, old))

    if time_rows:
        max_time = max(v for _, v, _ in time_rows)
        print("Mean time (lower is better)\n")
        for c, new_v, old_v in sorted(time_rows, key=lambda x: x[1]):
            bar = human_bar(new_v, max_time, width=28)
            label = short_case_label(c.name)
            if old_v is not None:
                delta = pct_change(new_v, old_v)
                print(f"{fmt_seconds(new_v):>10}  {bar}  {pct_fmt(delta):>9}  {label}")
            else:
                print(f"{fmt_seconds(new_v):>10}  {bar}  {'':>9}  {label}")

    tp_rows: List[Tuple[BenchCase, float, Optional[float]]] = []
    for c in cases:
        if c.throughput_bps.mean is None:
            continue
        old = None
        if baseline_map:
            bc = baseline_map.get(case_key(c.name))
            if bc:
                old = bc.get("throughput_bps", {}).get("mean", None)
        tp_rows.append((c, c.throughput_bps.mean, old))

    if tp_rows:
        max_tp = max(v for _, v, _ in tp_rows)
        print("\nMean throughput (higher is better)\n")
        for c, new_v, old_v in sorted(tp_rows, key=lambda x: x[1], reverse=True):
            bar = human_bar(new_v, max_tp, width=28)
            label = short_case_label(c.name)
            if old_v is not None:
                delta = pct_change(new_v, old_v)
                print(f"{fmt_bytes(new_v):>10}/s  {bar}  {pct_fmt(delta):>9}  {label}")
            else:
                print(f"{fmt_bytes(new_v):>10}/s  {bar}  {'':>9}  {label}")


def print_ascii_charts(run: BenchRun, baseline_json_path: Optional[str]) -> None:
    baseline_map: Optional[Dict[str, Dict[str, Any]]] = None
    if baseline_json_path:
        baseline_map = baseline_index(load_baseline(baseline_json_path))

    buckets: Dict[Tuple[str, str], List[BenchCase]] = {}
    for c in run.cases:
        key = (payload_bucket(c.name), proxy_bucket(c.name))
        buckets.setdefault(key, []).append(c)

    payload_titles = {
        "small/small": "Payload group: small / small",
        "mixed": "Payload group: small / big or big / small",
        "big/big": "Payload group: big / big",
        "unknown": "Payload group: unknown",
    }
    proxy_titles = {
        "none": "proxy: none",
        "http": "proxy: http",
        "socks5": "proxy: socks5",
        "unknown": "proxy: unknown",
    }

    ordered_keys = [
        ("small/small", "none"),
        ("small/small", "http"),
        ("small/small", "socks5"),
        ("mixed", "none"),
        ("mixed", "http"),
        ("mixed", "socks5"),
        ("big/big", "none"),
        ("big/big", "http"),
        ("big/big", "socks5"),
        ("unknown", "unknown"),
    ]

    for payload_key, proxy_key in ordered_keys:
        cases = buckets.get((payload_key, proxy_key))
        if not cases:
            continue
        print_group_charts(
            f"{payload_titles.get(payload_key, payload_key)} | {proxy_titles.get(proxy_key, proxy_key)}",
            cases,
            baseline_map,
        )


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
    ap.add_argument(
        "--sample-count",
        type=int,
        default=None,
        help="Override Divan sample count for faster exploratory runs",
    )
    ap.add_argument(
        "--max-time",
        default=None,
        help="Pass through Divan --max-time (for example 2s or 500ms)",
    )
    ap.add_argument(
        "--min-time",
        default=None,
        help="Pass through Divan --min-time",
    )
    ap.add_argument(
        "--filter",
        action="append",
        default=[],
        help="Pass through Divan --filter; may be repeated",
    )
    ap.add_argument(
        "--json-out",
        default=None,
        help="Write parsed JSON to this path instead of printing charts",
    )
    ap.add_argument(
        "--compare-to",
        default=None,
        help="Path to baseline JSON file to compare against",
    )
    ap.add_argument("--allow-nonzero", action="store_true")
    ap.add_argument("--debug", action="store_true")
    ap.add_argument(
        "--no-progress", action="store_true", help="Disable progress status line"
    )
    args = ap.parse_args()

    cmd = args.cmd
    bench_args: List[str] = []
    if args.sample_count is not None:
        bench_args.extend(["--sample-count", str(args.sample_count)])
    if args.max_time:
        bench_args.extend(["--max-time", args.max_time])
    if args.min_time:
        bench_args.extend(["--min-time", args.min_time])
    positional_filters = list(args.filter)
    if bench_args:
        cmd += " -- " + " ".join(shlex.quote(arg) for arg in bench_args)
        if positional_filters:
            cmd += " " + " ".join(shlex.quote(arg) for arg in positional_filters)
    elif positional_filters:
        cmd += " -- " + " ".join(shlex.quote(arg) for arg in positional_filters)

    show_progress = not args.no_progress
    rc, out = run_command_streaming(cmd, debug=args.debug, show_progress=show_progress)

    if rc != 0 and not args.allow_nonzero:
        if show_progress:
            status_done()
        sys.stderr.write(out)
        sys.stderr.write(f"\nCommand failed with exit code {rc}\n")
        sys.stderr.write("Use --allow-nonzero to still attempt parsing.\n")
        return rc

    if show_progress:
        status_line("Phase: parsing output")
    run = parse_bench_output(out, cmd=cmd, cwd=os.getcwd(), debug=args.debug)

    if args.json_out:
        if show_progress:
            status_line("Phase: writing JSON snapshot")
        payload = run_to_jsonable(run)
        os.makedirs(os.path.dirname(os.path.abspath(args.json_out)), exist_ok=True)
        with open(args.json_out, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, sort_keys=True)
        if show_progress:
            status_done()
        print(args.json_out)
        return 0

    if show_progress:
        status_line("Phase: printing charts")
        status_done()

    if not run.cases:
        print("No benchmark cases parsed.")
        return 0

    print_ascii_charts(run, baseline_json_path=args.compare_to)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
