#!/usr/bin/env python3
"""Byte-exact slow-reader soak client; emits JSONL progress and provider RSS."""
import argparse
import hashlib
import json
import subprocess
import threading
import time
import urllib.request


def positive(value):
    value = int(value)
    if value <= 0:
        raise argparse.ArgumentTypeError("must be positive")
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("url", help="HTTPS URL configured to use promoted passthrough")
    parser.add_argument("--expect-bytes", type=positive, required=True)
    parser.add_argument("--sha256", required=True, help="independently computed source digest")
    parser.add_argument("--rate", type=positive, default=1024 * 1024, help="read bytes/second")
    parser.add_argument("--pause-every", type=positive, default=64 * 1024 * 1024)
    parser.add_argument("--pause-seconds", type=positive, default=300)
    parser.add_argument("--provider-pid", type=positive)
    args = parser.parse_args()
    if len(args.sha256) != 64 or any(c not in "0123456789abcdef" for c in args.sha256.lower()):
        parser.error("--sha256 must contain 64 hexadecimal characters")
    start = time.monotonic()
    output_lock = threading.Lock()
    stopped = threading.Event()
    monitor_failed = threading.Event()

    def emit(event, **fields):
        with output_lock:
            print(json.dumps(dict(event=event, elapsed_s=round(time.monotonic() - start, 3),
                                  **fields)), flush=True)

    def sample_rss():
        try:
            while not stopped.is_set():
                result = subprocess.run(["ps", "-o", "rss=", "-p", str(args.provider_pid)],
                                        capture_output=True, text=True, timeout=5, check=False)
                rss = result.stdout.strip()
                if result.returncode != 0 or not rss:
                    raise RuntimeError("provider PID exited or RSS is unavailable")
                emit("provider_rss", pid=args.provider_pid, rss_bytes=int(rss) * 1024)
                stopped.wait(1)
        except Exception as error:
            monitor_failed.set()
            emit("rss_sampling_failed", error=str(error))

    monitor = None
    if args.provider_pid:
        monitor = threading.Thread(target=sample_rss, daemon=True)
        monitor.start()
    count = 0
    digest = hashlib.sha256()
    next_pause = args.pause_every
    next_report = 1024 * 1024
    try:
        request = urllib.request.Request(args.url, headers={"Accept-Encoding": "identity"})
        with urllib.request.urlopen(request, timeout=max(420, args.pause_seconds + 60)) as response:
            if response.status != 200:
                raise RuntimeError(f"expected HTTP 200, got {response.status}")
            if response.headers.get("Content-Encoding", "identity") != "identity":
                raise RuntimeError("server ignored identity encoding request")
            length = response.headers.get("Content-Length")
            if length is not None and int(length) != args.expect_bytes:
                raise RuntimeError(f"unexpected Content-Length: {length}")
            while True:
                read_start = time.monotonic()
                data = response.read(min(64 * 1024, args.rate))
                if not data:
                    break
                digest.update(data)
                count += len(data)
                if count > args.expect_bytes:
                    raise RuntimeError("received more bytes than expected")
                if count >= next_report:
                    emit("progress", bytes=count)
                    next_report = count + 1024 * 1024
                time.sleep(max(0, len(data) / args.rate - (time.monotonic() - read_start)))
                if count >= next_pause and count < args.expect_bytes:
                    emit("pause", bytes=count, seconds=args.pause_seconds)
                    time.sleep(args.pause_seconds)
                    emit("resume", bytes=count)
                    next_pause = count + args.pause_every
        actual = digest.hexdigest()
        if count != args.expect_bytes or actual != args.sha256.lower():
            raise RuntimeError(f"stream mismatch: bytes={count}, sha256={actual}")
        if monitor_failed.is_set():
            raise RuntimeError("provider RSS monitoring failed; see rss_sampling_failed event")
        emit("passed", bytes=count, sha256=actual)
        return 0
    except Exception as error:
        emit("failed", bytes=count, error=str(error))
        return 1
    finally:
        stopped.set()
        if monitor:
            monitor.join(timeout=6)


if __name__ == "__main__":
    raise SystemExit(main())
