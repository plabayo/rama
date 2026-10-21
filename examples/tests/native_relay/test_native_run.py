"""Aggregation must not turn a failed HTTP or WebSocket verdict into a pass."""

from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from run import combined_report, report_failure, main


class NativeRunnerTests(unittest.TestCase):
    def test_combined_verdict(self):
        # HTTP match, WS match, HTTP credit, WS credit, allow differences, failure.
        cases = [
            (True, True, True, True, False, None),
            (False, True, True, True, False, "native fingerprint"),
            (True, False, True, True, False, "native fingerprint"),
            (False, True, True, True, True, None),
            (True, False, True, True, True, None),
            (True, True, False, True, True, "initial credit"),
            (True, True, True, False, True, "initial credit"),
        ]
        for http, ws, hc, wc, allow, failure in cases:
            with self.subTest(case=(http, ws, hc, wc, allow)):
                report = combined_report(
                    dict(fingerprint_match=http, h2_initial_credit_match=hc),
                    dict(fingerprint_match=ws, h2_initial_credit_match=wc), protocol="h2")
                self.assertEqual(report["fingerprint_match"], http and ws)
                error = report_failure(report, protocol="h2", allow_differences=allow)
                if failure:
                    self.assertIn(failure, error)
                else:
                    self.assertIsNone(error)

    def test_missing_websocket_evidence_cannot_pass(self):
        for ws, reason in [({}, "connection-fingerprint"),
                           ({"fingerprint_match": True}, "initial-credit")]:
            with self.subTest(websocket=ws), self.assertRaisesRegex(ValueError, reason):
                combined_report({"fingerprint_match": True}, ws, protocol="h2")


class DecoderAdmissionTests(unittest.TestCase):
    def test_unsafe_capture_fails_before_building_and_keeps_cleanup_report(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "evidence"
            args = SimpleNamespace(protocol="h3", output=output, interface="lo")
            with patch("run.parse_args", return_value=args), patch("run.require_h3_tshark"), patch(
                "run.require_capture_environment", side_effect=RuntimeError("unsafe capture")
            ), patch("run.build_binaries") as build, patch("run.execute") as execute:
                with self.assertRaisesRegex(RuntimeError, "unsafe capture"):
                    main()
            build.assert_not_called()
            execute.assert_not_called()
            self.assertTrue((output / "artifacts" / "cleanup.json").is_file())

    def test_missing_h3_decoder_fails_before_allocating_resources(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "unused"
            args = SimpleNamespace(
                protocol="h3",
                output=output,
                inside_disposable_database=False,
                postgres_image="unused",
            )
            with patch("run.parse_args", return_value=args), patch(
                "run.require_h3_tshark", side_effect=RuntimeError("missing H3 decoder")
            ), patch("run.build_binaries", return_value=0) as allocate, patch(
                "run.execute", return_value=0
            ):
                with self.assertRaisesRegex(RuntimeError, "missing H3 decoder"):
                    main()
            allocate.assert_not_called()
            self.assertFalse(output.exists())
