import json
import unittest

from daily_job_matrices import select


class DailyJobMatricesTest(unittest.TestCase):
    def test_default_and_family_dispatch(self):
        default = select("")
        self.assertEqual(default["only"], "")
        self.assertEqual(len(json.loads(default["test-browser-profiles"])), 16)
        self.assertEqual(len(json.loads(default["test-safari-desktop"])), 2)
        self.assertEqual(len(json.loads(default["test-rust-base"])), 16)
        self.assertEqual(len(json.loads(default["test-quic-interop-qa"])), 12)
        self.assertEqual(len(json.loads(default["test-native-relay-contract"])), 8)
        self.assertEqual(len(json.loads(default["test-android-on-device"])), 2)
        safari = select("test-safari-desktop")
        self.assertEqual(safari["test-safari-desktop"], default["test-safari-desktop"])
        self.assertEqual(json.loads(safari["test-browser-profiles"]), [])

    def test_exact_names_select_only_the_requested_entries(self):
        browser = "browser-firefox-h1-tls-debug"
        quic = "test-quic-interop-qa-rustls-ring-1.96.0-windows-latest"
        base = "test-rust-base-minimal-stable-macos-15"
        relay = "native-relay-h3-v2-release"
        android = "android-on-device-api-34"
        outputs = select(f"{browser} {quic} {base} {relay} {android} check-rust")
        self.assertEqual([r["name"] for r in json.loads(outputs["test-native-relay-contract"])], [relay])
        self.assertEqual([r["api"] for r in json.loads(outputs["test-android-on-device"])], [34])
        self.assertEqual([r["name"] for r in json.loads(outputs["test-browser-profiles"])], [browser])
        self.assertEqual([r["name"] for r in json.loads(outputs["test-quic-interop-qa"])], [quic])
        self.assertEqual([r["name"] for r in json.loads(outputs["test-rust-base"])], [base])
        self.assertEqual(json.loads(outputs["test-safari-desktop"]), [])
        self.assertEqual(outputs["only"],
                         "check-rust test-android-on-device test-browser-profiles "
                         "test-native-relay-contract test-quic-interop-qa test-rust-base")

    def test_scarce_rows_queue_on_a_slot_and_linux_rows_do_not(self):
        rows = [row for job in ("test-rust-base", "test-quic-interop-qa")
                for row in json.loads(select("")[job])]
        self.assertEqual(len({row["name"] for row in rows}), len(rows))
        for row in rows:
            family = row["os"].split("-")[0]
            expected = "" if family == "ubuntu" else f"rama-{family}-slot-"
            self.assertTrue(row["slot"].startswith(expected) and bool(row["slot"]) == bool(expected), row)

    def test_unknown_names_reach_the_result_gate(self):
        result = select("browser-firefox-typo")
        self.assertEqual(result["only"], "browser-firefox-typo")
        self.assertEqual(json.loads(result["test-browser-profiles"]), [])
