import json
from dataclasses import replace
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from capture import capture, tls_browser_options
from browser_automation.workflow import FlowResult
from flow_bodies import WEBSOCKET_PROBE
from driver_receipt import MAX_DRIVER_BYTES, write_driver_result
from test_flow_bodies import fixture
from wire import HeaderBlock, drain_capture


class PageProbeCaptureTests(unittest.TestCase):
    def test_drain_passes_the_page_probe_to_decoding_and_body_validation(self):
        probe = WEBSOCKET_PROBE + " #" + "12" * 16
        rows = fixture("h3")
        rows[6] = replace(rows[6], websocket_text=(probe,))
        rows[7] = replace(rows[7], websocket_text=(rows[7].websocket_text[0], probe))
        process = SimpleNamespace(poll=lambda: 0)
        with (
            tempfile.TemporaryDirectory() as directory,
            patch("wire.read_header_blocks", return_value=rows) as decoded,
        ):
            args = dict(
                capture=Path(directory) / "capture",
                keylog=Path(directory) / "keys",
                protocol="mixed",
                server_port=443,
                output=Path(directory) / "wire.pdml",
            )
            self.assertEqual(
                len(
                    drain_capture(process, **args, websocket_probe=probe).bodies[
                        "flows"
                    ]
                ),
                6,
            )
            self.assertEqual(decoded.call_args.kwargs.get("websocket_probe"), probe)
            with self.assertRaisesRegex(
                RuntimeError, "incomplete independently decoded"
            ):
                drain_capture(process, **args, websocket_probe=probe + "wrong")


class TlsCaptureTests(unittest.TestCase):
    def test_firefox_tls_uses_private_nss_and_explicit_h3_routing(self):
        for protocol in ("h2", "h3"):
            with (
                self.subTest(protocol=protocol),
                tempfile.TemporaryDirectory() as temporary,
            ):
                root = Path(temporary)
                args = SimpleNamespace(
                    browser="firefox", protocol=protocol, output=root
                )
                certificate = root / "fixture.pem"
                with patch("capture.prepare_nss_trust") as trust:
                    options, prepare = tls_browser_options(
                        args, 24443, certificate, "owned-spki"
                    )
                    prepare(root / "browser-profile")
                trust.assert_called_once_with(
                    root / "browser-profile",
                    certificate=certificate,
                    log=root / "nss-setup.log",
                )
                self.assertEqual(options.preferences["network.proxy.type"], 0)
                self.assertNotIn("network.http.http3.enable", options.preferences)
                self.assertFalse(
                    any("force-quic" in option for option in options.arguments)
                )
                mapping = "network.http.http3.alt-svc-mapping-for-testing"
                if protocol == "h3":
                    self.assertEqual(
                        options.preferences[mapping], "localhost;h3=:24443"
                    )
                    self.assertIs(
                        options.preferences[
                            "network.http.http3.force-use-alt-svc-mapping-for-testing"
                        ],
                        True,
                    )
                    self.assertIs(
                        options.preferences[
                            "network.http.http3.disable_when_third_party_roots_found"
                        ],
                        False,
                    )
                else:
                    self.assertNotIn(mapping, options.preferences)
                    self.assertNotIn(
                        "network.http.http3.force-use-alt-svc-mapping-for-testing",
                        options.preferences,
                    )

    def test_chromium_tls_keeps_the_certificate_bound_exception_and_h3_route(self):
        for browser in ("chrome", "edge"):
            for protocol in ("h2", "h3"):
                with self.subTest(browser=browser, protocol=protocol):
                    args = SimpleNamespace(
                        browser=browser, protocol=protocol, output=Path("/owned")
                    )
                    options, prepare = tls_browser_options(
                        args, 24443, Path("fixture.pem"), "owned-spki"
                    )
                    self.assertIsNone(prepare)
                    self.assertIn(
                        "--ignore-certificate-errors-spki-list=owned-spki",
                        options.arguments,
                    )
                    self.assertNotIn("--ignore-certificate-errors", options.arguments)
                    self.assertEqual(
                        "--origin-to-force-quic-on=localhost:24443"
                        in options.arguments,
                        protocol == "h3",
                    )

    def test_drain_waits_for_complete_body_coverage_not_only_headers(self):
        process = Mock()
        process.poll.return_value = None
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)

            def decode(*args, **kwargs):
                (root / "headers.pdml").write_bytes(b"<pdml/>")
                return [HeaderBlock("h3", 1, 1, 0, False, ((":method", "GET"),))]

            with (
                patch("wire.read_header_blocks", side_effect=decode) as read,
                patch(
                    "wire.check_flow_bodies",
                    side_effect=[ValueError("incomplete"), {"complete": True}],
                ),
                patch("wire.time.sleep"),
            ):
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
        with (
            tempfile.TemporaryDirectory() as temporary,
            patch("wire.read_header_blocks", side_effect=[first, all_variants]) as read,
            patch("wire.check_flow_bodies", return_value={"complete": True}),
            patch("wire.time.sleep"),
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
            "h3",
            1,
            7,
            0,
            False,
            ((":method", "GET"), (":path", "/"), ("user-agent", "fixture")),
        )
        cases = [
            ([warmup], 1, True),
            ([warmup], 0, False),
            ([warmup, warmup], 1, False),
            (
                [replace(warmup, headers=((":method", "GET"), (":path", "/other")))],
                1,
                False,
            ),
        ]
        for extra, expected, accepted in cases:
            with (
                self.subTest(expected=expected, extra=extra),
                tempfile.TemporaryDirectory() as temporary,
            ):
                root = Path(temporary)
                process = Mock()
                process.poll.return_value = 0
                with patch(
                    "wire.read_header_blocks", return_value=fixture("h3") + extra
                ):
                    arguments = dict(
                        capture=root / "wire.pcapng",
                        keylog=root / "fixture.keys",
                        protocol="h3",
                        server_port=443,
                        output=root / "headers.pdml",
                        expected_per_flow=1,
                        expected_warmups=expected,
                    )
                    if accepted:
                        traffic = drain_capture(process, **arguments)
                        self.assertEqual(len(traffic.headers), 13)
                    else:
                        with self.assertRaisesRegex(
                            RuntimeError, "incomplete independently"
                        ):
                            drain_capture(process, **arguments)

    def test_drain_rejects_capture_exit_with_incomplete_flows(self):
        process = Mock()
        process.poll.return_value = 1
        with (
            tempfile.TemporaryDirectory() as temporary,
            patch("wire.read_header_blocks", side_effect=ValueError("incomplete")),
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


class DriverReceiptTests(unittest.TestCase):
    def result(self):
        return FlowResult(
            "fixture",
            "chrome",
            "155",
            {"navigate": "h2"},
            "driver report",
            None,
            report_url="https://owned.test/report?h3_probe=1",
        )

    def test_private_receipt_keeps_actual_url_and_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "page-result.json"
            write_driver_result(path, self.result())
            original = path.read_bytes()
            self.assertEqual(
                json.loads(original)["report_url"], self.result().report_url
            )
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                write_driver_result(
                    path, replace(self.result(), report_url="different")
                )
            self.assertEqual(path.read_bytes(), original)

    def test_oversized_receipt_is_rejected_before_creating_a_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "page-result.json"
            with self.assertRaisesRegex(ValueError, "budget"):
                write_driver_result(
                    path, replace(self.result(), report_html="x" * MAX_DRIVER_BYTES)
                )
            self.assertFalse(path.exists())


if __name__ == "__main__":
    unittest.main()
