"""Own a fixture process, its log, readiness deadline and orderly shutdown.

These local packet tests currently run on Linux/macOS. Browser discovery itself
is cross-platform; Windows process/capture integration needs its own validation.
"""

from contextlib import contextmanager
import os
import signal
import subprocess
import time


def stop(process):
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGINT)
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=30)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=5)
        raise RuntimeError("fixture failed to shut down cleanly")


@contextmanager
def running(command, log, environment=None):
    """Always stop our process group, including when readiness or a check fails."""
    with log.open("w") as output:
        process = subprocess.Popen(
            command,
            stdout=output,
            stderr=subprocess.STDOUT,
            env=environment,
            start_new_session=True,
        )
        try:
            yield process
        finally:
            stop(process)


def wait_ready(process, log, predicate, timeout=30):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("fixture exited before readiness; see " + str(log))
        if predicate(log.read_text()):
            return
        time.sleep(0.05)
    raise TimeoutError("fixture readiness; see " + str(log))
