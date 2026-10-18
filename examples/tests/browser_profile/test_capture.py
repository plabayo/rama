from dataclasses import replace
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from capture import capture
from wire import HeaderBlock, drain_capture
from test_flow_bodies import fixture


class TlsCaptureTests(unittest.TestCase):
    def test_drain_waits_for_complete_body_coverage_not_only_headers(self):
        process = Mock()
        process.poll.return_value = None
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)

            def decode(*args, **kwargs):
                (root / "headers.pdml").write_bytes(b"<pdml/>")
                return [HeaderBlock("h3", 1, 1, 0, False, ((":method", "GET"),))]

            with patch("wire.read_header_blocks", side_effect=decode) as read, patch(
                "wire.check_flow_bodies",
                side_effect=[ValueError("incomplete"), {"complete": True}],
            ), patch("wire.time.sleep"):
                traffic = drain_capture(
                    process,
                    capture=root / "reference.pcapng",
                    keylog=root / "browser.keys",
                    protocol="h3",
                    server_port=443,
                    output=root / "headers.pdml",
                )
                self.assertEqual(traffic.bodies, {"complete": True})
                self.assertEqual(len(traffic.headers), 1)
                self.assertEqual(read.call_count, 2)

    def test_drain_waits_for_all_pinned_variants_even_after_six_flows_are_visible(self):
        process = Mock()
        process.poll.return_value = None
        first = fixture("h2")
        all_variants = first + [replace(frame, connection=1) for frame in first]
        with tempfile.TemporaryDirectory() as temporary, patch(
            "wire.read_header_blocks", side_effect=[first, all_variants]
        ) as read, patch(
            "wire.check_flow_bodies", return_value={"complete": True}
        ), patch(
            "wire.time.sleep"
        ):
            root = Path(temporary)
            traffic = drain_capture(
                process,
                capture=root / "wire.pcapng",
                keylog=root / "fixture.keys",
                protocol="h2",
                server_port=443,
                output=root / "headers.pdml",
                expected_per_flow=2,
            )
            self.assertEqual(read.call_count, 2)
            self.assertEqual(len(traffic.headers), 24)

    def test_drain_allows_only_the_exact_declared_root_warmups(self):
        warmup = HeaderBlock(
            "h3", 1, 7, 0, False,
            ((":method", "GET"), (":path", "/"), ("user-agent", "fixture")),
        )
        cases = [
            ([warmup], 1, True),
            ([warmup], 0, False),
            ([warmup, warmup], 1, False),
            ([replace(warmup, headers=((":method", "GET"), (":path", "/other")))], 1, False),
        ]
        for extra, expected, accepted in cases:
            with self.subTest(expected=expected, extra=extra), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                process = Mock()
                process.poll.return_value = 0
                with patch("wire.read_header_blocks", return_value=fixture("h3") + extra):
                    arguments = dict(
                        capture=root / "wire.pcapng", keylog=root / "fixture.keys",
                        protocol="h3", server_port=443, output=root / "headers.pdml",
                        expected_per_flow=1, expected_warmups=expected,
                    )
                    if accepted:
                        traffic = drain_capture(process, **arguments)
                        self.assertEqual(len(traffic.headers), 13)
                    else:
                        with self.assertRaisesRegex(RuntimeError, "incomplete independently"):
                            drain_capture(process, **arguments)

    def test_drain_rejects_capture_exit_with_incomplete_flows(self):
        process = Mock()
        process.poll.return_value = 1
        with tempfile.TemporaryDirectory() as temporary, patch(
            "wire.read_header_blocks", side_effect=ValueError("incomplete")
        ):
            with self.assertRaisesRegex(RuntimeError, "incomplete independently"):
                root = Path(temporary)
                drain_capture(
                    process,
                    capture=root / "reference.pcapng",
                    keylog=root / "browser.keys",
                    protocol="h3",
                    server_port=443,
                    output=root / "headers.pdml",
                )

    def test_early_setup_failure_removes_ephemeral_keys_and_profile(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in ("key.pem", "server.keys", "browser.keys", "replay.keys"):
                (root / name).write_text("fixture")
            (root / "browser-profile").mkdir()
            with patch("capture.capture_tls", side_effect=RuntimeError("setup")):
                with self.assertRaisesRegex(RuntimeError, "setup"):
                    capture(SimpleNamespace(output=root, protocol="h2"))
            self.assertEqual(list(root.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
