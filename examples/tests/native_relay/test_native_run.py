"""Aggregation must not turn a failed HTTP or WebSocket verdict into a pass."""

from pathlib import Path
import tempfile
import unittest

from run import combined_report, report_failure, validate_client_capture


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


class ClientFailurePrecedenceTests(unittest.TestCase):
    def test_client_failure_retains_both_decoder_reports(self):
        broken = b'<pdml><packet><proto name="quic"><field name="quic.decryption_failed"/></proto></packet></pdml>'
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaisesRegex(RuntimeError, 'external client failed') as caught:
                validate_client_capture(1, dict(ingress=broken, egress=broken), root)
            self.assertIsInstance(caught.exception.__cause__, ValueError)
            for side in ('ingress', 'egress'):
                self.assertTrue((root / (side + '.diagnostics.json')).exists())
            with self.assertRaisesRegex(ValueError, 'undecodable QUIC'):
                validate_client_capture(0, dict(ingress=broken, egress=broken), root)
