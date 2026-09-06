#!/usr/bin/env python3
"""Generate bounded HTTP traffic through an already running transparent proxy."""

import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import math
from pathlib import Path
import subprocess
import tempfile
import threading
import time
from urllib.parse import urlsplit


def bounded_integer(minimum, maximum):
    def parse(value):
        try:
            number = int(value)
        except ValueError as error:
            raise argparse.ArgumentTypeError("expected an integer") from error
        if not minimum <= number <= maximum:
            raise argparse.ArgumentTypeError(f"expected {minimum}..{maximum}")
        return number
    return parse


def target_url(value):
    parsed = urlsplit(value)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise argparse.ArgumentTypeError("expected an HTTP(S) URL")
    if parsed.username or parsed.password or parsed.fragment:
        raise argparse.ArgumentTypeError("credentials and fragments are unsupported")
    return value.rstrip("/")


class Results:
    def __init__(self):
        self.lock = threading.Lock()
        self.classes = {}

    def record(self, name, elapsed, downloaded, error):
        with self.lock:
            row = self.classes.setdefault(name, {
                "requests": 0, "failures": 0, "downloaded_bytes": 0,
                "latency_buckets_ms": {}, "first_error": None,
            })
            row["requests"] += 1
            row["failures"] += bool(error)
            row["downloaded_bytes"] += downloaded
            bucket = 1 << max(0, math.ceil(elapsed * 1000) - 1).bit_length()
            buckets = row["latency_buckets_ms"]
            buckets[bucket] = buckets.get(bucket, 0) + 1
            if error and row["first_error"] is None:
                row["first_error"] = error[:512]

    def summary(self, elapsed):
        result = {}
        for name, row in self.classes.items():
            count = 0
            p95 = 0
            for ceiling, samples in sorted(row["latency_buckets_ms"].items()):
                count += samples
                if count >= math.ceil(row["requests"] * 0.95):
                    p95 = ceiling
                    break
            result[name] = {key: value for key, value in row.items() if key != "latency_buckets_ms"}
            result[name]["p95_latency_upper_bound_ms"] = p95
            result[name]["requests_per_second"] = row["requests"] / max(elapsed, 0.001)
        return result


def transfer(curl, url, options, timeout):
    command = [
        curl, "--disable", "--silent", "--show-error", "--fail", "--location",
        "--proto", "=http,https", "--proto-redir", "=http,https",
        "--max-time", str(timeout), "--output", "/dev/null",
        "--write-out", "%{size_download}", *options, "--url", url,
    ]
    started = time.monotonic()
    try:
        process = subprocess.run(command, capture_output=True, text=True, timeout=timeout + 1)
        error = None
        if process.returncode:
            error = process.stderr.strip() or f"curl exited {process.returncode}"
        downloaded = int(process.stdout.strip() or "0")
    except (OSError, subprocess.TimeoutExpired, ValueError) as exception:
        error, downloaded = str(exception), 0
    return time.monotonic() - started, downloaded, error


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--http-url", type=target_url, default="http://http-test.ramaproxy.org")
    parser.add_argument("--https-url", type=target_url, default="https://http-test.ramaproxy.org")
    parser.add_argument("--duration", type=bounded_integer(1, 86400), default=60)
    parser.add_argument("--concurrency", type=bounded_integer(1, 512), default=16)
    parser.add_argument("--body-bytes", type=bounded_integer(1, 1024 ** 3), default=8 * 1024 ** 2)
    parser.add_argument("--curl", default="curl")
    args = parser.parse_args(argv)
    results = Results()
    stop = threading.Event()
    with tempfile.TemporaryDirectory(prefix="rama-http-stress-") as directory:
        body = Path(directory) / "body.bin"
        with body.open("wb") as output:
            remaining = args.body_bytes
            chunk = b"x" * min(remaining, 1024 ** 2)
            while remaining:
                count = min(remaining, len(chunk))
                output.write(chunk[:count])
                remaining -= count
        workloads = [
            ("http_get", args.http_url + "/method", ["--http1.1"]),
            ("https_h1_get", args.https_url + "/method", ["--http1.1"]),
            ("https_h2_get", args.https_url + "/method", ["--http2"]),
            ("https_large_get", args.https_url + f"/bytes?size={args.body_bytes}", []),
            ("https_post", args.https_url + "/octet-stream", ["--data-binary", "@" + str(body)]),
        ]
        started = time.monotonic()
        deadline = started + args.duration

        def worker(index):
            while not stop.is_set():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return
                name, url, options = workloads[index % len(workloads)]
                elapsed, downloaded, error = transfer(args.curl, url, options, 20)
                results.record(name, elapsed, downloaded, error)
                index += 1

        interrupted = False
        with ThreadPoolExecutor(max_workers=args.concurrency) as executor:
            futures = [executor.submit(worker, index) for index in range(args.concurrency)]
            try:
                for future in futures:
                    future.result()
            except KeyboardInterrupt:
                interrupted = True
                stop.set()
        summary = results.summary(time.monotonic() - started)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 130 if interrupted else int(not summary or any(row["failures"] for row in summary.values()))


if __name__ == "__main__":
    raise SystemExit(main())
