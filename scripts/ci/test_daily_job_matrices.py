import json
import unittest

from daily_job_matrices import select


class DailyJobMatricesTest(unittest.TestCase):
    def test_default_and_family_dispatch(self):
        default = select("")
        self.assertEqual(default["only"], "")
        self.assertEqual(len(json.loads(default["test-browser-profiles"])), 16)
        self.assertEqual(len(json.loads(default["test-safari-desktop"])), 2)
        self.assertEqual(len(json.loads(default["test-quic-interop-qa"])), 4)
        safari = select("test-safari-desktop")
        self.assertEqual(safari["test-safari-desktop"], default["test-safari-desktop"])
        self.assertEqual(json.loads(safari["test-browser-profiles"]), [])

    def test_exact_names_select_only_the_requested_entries(self):
        browser = "browser-firefox-h1-tls-debug"
        quic = "test-quic-interop-qa-all-1.96.0-windows-latest"
        outputs = select(f"{browser} {quic} test-rust-base")
        self.assertEqual([r["name"] for r in json.loads(outputs["test-browser-profiles"])], [browser])
        self.assertEqual([r["name"] for r in json.loads(outputs["test-quic-interop-qa"])], [quic])
        self.assertEqual(json.loads(outputs["test-safari-desktop"]), [])
        self.assertEqual(outputs["only"], "test-browser-profiles test-quic-interop-qa test-rust-base")

    def test_unknown_names_reach_the_result_gate(self):
        result = select("browser-firefox-typo")
        self.assertEqual(result["only"], "browser-firefox-typo")
        self.assertEqual(json.loads(result["test-browser-profiles"]), [])
