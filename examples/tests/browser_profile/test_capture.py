from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from capture import capture, drain_capture


class TlsCaptureTests(unittest.TestCase):
    def test_drain_waits_for_complete_body_coverage_not_only_headers(self):
        process = Mock()
        process.poll.return_value = None
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)

            def decode(*args):
                (root / "headers.pdml").write_bytes(b"<pdml/>")
                return ["headers"]

            with patch("capture.read_header_blocks", side_effect=decode) as read, patch(
                "capture.parse_pdml", return_value=["frames"]
            ), patch(
                "capture.check_original_bodies",
                side_effect=[ValueError("incomplete"), {"complete": True}],
            ), patch(
                "capture.time.sleep"
            ):
                self.assertEqual(
                    drain_capture(process, root, "h3", 443),
                    (["headers"], {"complete": True}),
                )
                self.assertEqual(read.call_count, 2)

    def test_drain_rejects_capture_exit_with_incomplete_flows(self):
        process = Mock()
        process.poll.return_value = 1
        with tempfile.TemporaryDirectory() as temporary, patch(
            "capture.read_header_blocks", side_effect=ValueError("incomplete")
        ):
            with self.assertRaisesRegex(RuntimeError, "incomplete independently"):
                drain_capture(process, Path(temporary), "h3", 443)

    def test_early_setup_failure_removes_ephemeral_keys_and_profile(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in ("key.pem", "server.keys", "browser.keys"):
                (root / name).write_text("fixture")
            (root / "browser-profile").mkdir()
            with patch("capture.capture_tls", side_effect=RuntimeError("setup")):
                with self.assertRaisesRegex(RuntimeError, "setup"):
                    capture(SimpleNamespace(output=root, protocol="h2"))
            self.assertEqual(list(root.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
