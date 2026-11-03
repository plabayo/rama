"""Collector failures must reach CI without exposing credentials."""

from contextlib import nullcontext, redirect_stdout
import io
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import quote

import main


class NightlyTests(unittest.TestCase):
    storage_cookie = "private/storage-cookie&value"
    completed = SimpleNamespace(protocols=dict.fromkeys(
        ("navigate", "fetch", "xhr", "ws", "form", "form_get"), "h3"
    ))

    def collect(self, journey, *, entrypoints=None, profile=None):
        """Supply browser outcomes; exercise real exit handling and receipt writing."""
        report = {"tls": {"ja4": {"hash": "observed", "profile": profile}}}
        browser = SimpleNamespace(
            capabilities={},
            set_page_load_timeout=lambda _timeout: None,
            set_script_timeout=lambda _timeout: None,
            get=lambda _url: None,
            execute_script=lambda _script: "h2",
            execute_async_script=lambda *_args: report,
        )
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            main.os.environ, {"RAMA_FP_STORAGE_COOKIE": self.storage_cookie}
        ), patch.object(
            main, "ENTRYPOINTS", entrypoints or [("https://h3.invalid/", "h3")]
        ), patch.object(
            main, "device_session", side_effect=lambda *_args: nullcontext(browser)
        ), patch.object(
            main, "run_capture_flow", side_effect=journey
        ), redirect_stdout(io.StringIO()) as stdout:
            output = Path(directory) / "receipts"
            code = main.main(["--output", str(output), "--device", "safari"])
            raw = "\n".join(path.read_text() for path in sorted(output.glob("*.json")))
            receipts = {
                path.stem: json.loads(path.read_text()) for path in output.glob("*.json")
            }
        return code, receipts, raw + stdout.getvalue()

    def test_failed_journey_keeps_failure_exit_and_other_results(self):
        def journey(_driver, origin, **_kwargs):
            if origin == "https://broken.invalid/":
                raise RuntimeError("journey failed")
            return self.completed

        code, receipts, _ = self.collect(journey, entrypoints=[
            ("https://broken.invalid/", "h3"), ("https://working.invalid/", "h3")
        ])
        self.assertEqual(code, 1)
        self.assertEqual(receipts["000-0"]["status"], "failed")
        self.assertEqual(receipts["000-1"]["status"], "passed")

    def test_failed_revisit_cannot_be_hidden_by_a_successful_first_visit(self):
        def journey(_driver, _origin, *, cookies, **_kwargs):
            if cookies is None:
                raise RuntimeError("second connection broke")
            return self.completed

        code, receipts, _ = self.collect(
            journey, entrypoints=[("https://h3.fp.ramaproxy.org/", "h3")]
        )
        self.assertEqual(code, 1)
        self.assertEqual(receipts["000-0"]["status"], "failed")
        self.assertEqual(receipts["000-0"]["failure_stage"], "revisit")

    def test_all_h3_cells_staying_on_tcp_fails_but_known_ws_limits_do_not(self):
        for reason, expected in (
            ("h3: browser stayed on TCP: did not switch to HTTP/3", 1),
            ("ws: WebSocket over HTTP/3 is not supported by this browser", 0),
        ):
            with self.subTest(reason=reason):
                code, _, _ = self.collect(main.UnsupportedFlow(reason))
                self.assertEqual(code, expected)

    def test_fingerprint_mismatch_fails_but_matching_or_absent_profiles_do_not(self):
        for profile, expected in (
            ({"hash": "reference", "matched": False}, 1),
            ({"hash": "observed", "matched": True}, 0),
            (None, 0),
        ):
            with self.subTest(profile=profile):
                code, receipts, _ = self.collect(
                    lambda *_args, **_kwargs: self.completed, profile=profile
                )
                self.assertEqual(code, expected)
                self.assertEqual(receipts["echo"]["status"], "failed" if expected else "passed")

    def test_failure_receipts_and_logs_redact_credentials(self):
        secret = self.storage_cookie
        validation = ValueError("incomplete coverage " + secret)
        validation.add_note("POST=h1, GET=" + quote(secret, safe="") + " " * 400)
        driver = main.WebDriverException("Could not create a session: " + secret)
        for error in (validation, driver):
            with self.subTest(error=type(error).__name__):
                code, receipts, public = self.collect(error)
                self.assertEqual(code, 1)
                self.assertIn("<redacted>", receipts["000-0"]["failure_reason"])
                self.assertNotIn(secret, public)
                self.assertNotIn(quote(secret, safe=""), public)

    def test_provider_error_details_are_not_reported(self):
        error = main.WebDriverException("provider session private-access-key")
        self.assertEqual(main.failure_reason(error, secrets=()), "WebDriverException")


if __name__ == "__main__":
    unittest.main()
