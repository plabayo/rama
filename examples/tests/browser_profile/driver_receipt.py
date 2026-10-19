"""Persist bounded private driver observations before export or replay begins."""

from dataclasses import asdict
import json
import os

MAX_DRIVER_BYTES = 3 * 1024 * 1024


def write_driver_result(path, result):
    """Keep the actual final URL, page responses and driver-known WS input."""
    payload = (json.dumps(asdict(result), ensure_ascii=False, indent=2) + "\n").encode()
    if len(payload) > MAX_DRIVER_BYTES:
        raise ValueError("driver result budget exceeded")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(payload)
