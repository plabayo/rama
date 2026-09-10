"""Deterministic late-sample regressions: python3 -m unittest discover -s Tools."""
import contextlib
import hashlib
import io
import json
import sys
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import slow_download


class Response(io.BytesIO):
    status = 200
    headers = {"Content-Length": "1"}


class SlowDownloadTests(unittest.TestCase):
    def run_with_late_sample(self, *, succeeds):
        started = threading.Event()
        joining = threading.Event()
        original_thread = threading.Thread

        class JoinControlledThread(original_thread):
            def join(self, timeout=None):
                joining.set()
                super().join(timeout)

        def sample(*args, **kwargs):
            started.set()
            if not joining.wait(timeout=5):
                raise RuntimeError("test did not join sampling thread")
            return SimpleNamespace(returncode=0 if succeeds else 1,
                                   stdout="123" if succeeds else "")

        def response(*args, **kwargs):
            self.assertTrue(started.wait(timeout=5), "sample must already be in flight")
            return Response(b"x")

        arguments = ["slow_download.py", "https://example.invalid/file", "--expect-bytes", "1",
                     "--sha256", hashlib.sha256(b"x").hexdigest(), "--provider-pid", "999999"]
        output = io.StringIO()
        with patch.object(sys, "argv", arguments), \
                patch.object(slow_download.threading, "Thread", JoinControlledThread), \
                patch.object(slow_download.urllib.request, "urlopen", side_effect=response), \
                patch.object(slow_download.subprocess, "run", side_effect=sample), \
                contextlib.redirect_stdout(output):
            result = slow_download.main()
        return result, [json.loads(line)["event"] for line in output.getvalue().splitlines()]

    def test_late_sampling_failure_cannot_report_success(self):
        result, events = self.run_with_late_sample(succeeds=False)
        self.assertEqual(result, 1)
        self.assertIn("rss_sampling_failed", events)
        self.assertNotIn("passed", events)
        self.assertEqual(events[-1], "failed")

    def test_success_waits_for_final_sample(self):
        result, events = self.run_with_late_sample(succeeds=True)
        self.assertEqual(result, 0)
        self.assertIn("provider_rss", events)
        self.assertEqual(events[-1], "passed")


if __name__ == "__main__":
    unittest.main()
