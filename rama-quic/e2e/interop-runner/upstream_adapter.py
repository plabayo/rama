#!/usr/bin/env python3
"""Small runtime adapter; leave upstream protocol checks and result schema intact."""
import logging
import json
import os
from pathlib import Path
import subprocess
import sys
import time

checkout = Path(sys.argv.pop(1)).resolve()
os.chdir(checkout)
sys.path.insert(0, str(checkout))
import interop  # noqa: E402
import pyshark.capture.capture  # noqa: E402
import run  # noqa: E402
import testcase  # noqa: E402
from adapter_support import copy_logs, run_with_completion  # noqa: E402


def run_test_with_evidence(self, server, client, prefix, fn):
    """Keep endpoint exit provenance, including cases upstream calls unsupported."""
    self._rama_evidence = {"server": server, "client": client, "case": fn.name()}
    self._rama_evidence_dir = Path(self._log_dir) / "exit-evidence" / f"{server}_{client}"
    self._rama_evidence_dir.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    try:
        return _run_test(self, server, client, prefix, fn)
    finally:
        self._rama_evidence["duration_seconds"] = time.monotonic() - started
        (self._rama_evidence_dir / f"{fn.name()}.json").write_text(
            json.dumps(self._rama_evidence, indent=2) + "\n")



def cleanup_dir(directory):
    # The pinned upstream creates this path itself. Cleanup only that volume,
    # with a pinned image and a label identifying our run (never docker prune).
    subprocess.run(
        ["docker", "run", "--rm", "--label",
         "rama.quic-interop.project=" + os.environ["COMPOSE_PROJECT_NAME"],
         "--volume", f"{directory}:/cleanup", os.environ["RAMA_CLEANUP_IMAGE"],
         "sh", "-c", "rm -rf /cleanup/*"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30, check=True,
    )


def close_ignoring_tshark_exit(self):
    # Upstream tolerates pyshark dying mid-iteration on a pcap cut short
    # (`trace.py::_get_packets`, pyshark#390), but the `cap.close()` right
    # after it sits outside that guard: the same truncated capture makes
    # tshark exit non-zero, which pyshark only reports at close, discarding
    # packets it had already parsed and failing the whole role. Lossy cases
    # (transferloss, longrtt) produce cut-short captures routinely.
    try:
        _pyshark_close(self)
    except pyshark.capture.capture.TSharkCrashException as err:
        logging.debug("ignoring tshark exit status at capture close: %s", err)


interop.InteropRunner._copy_logs = copy_logs
_run_test = interop.InteropRunner._run_test
interop.InteropRunner._run_test = run_test_with_evidence
testcase.docker_cleanup_dir = cleanup_dir
_pyshark_close = pyshark.capture.capture.Capture.close
pyshark.capture.capture.Capture.close = close_ignoring_tshark_exit
sys.exit(run_with_completion(run.main, os.environ["RAMA_RUNNER_COMPLETION"]))
