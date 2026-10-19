import ast
import hashlib
import inspect
import json
from contextlib import contextmanager
from dataclasses import replace
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import capture as capture_module
from capture import capture, capture_tls, tls_browser_options
from browser_automation.workflow import FlowResult
from flow_bodies import WEBSOCKET_PROBE
from driver_receipt import MAX_DRIVER_BYTES, write_driver_result
from test_flow_bodies import fixture
from wire import HeaderBlock, drain_capture


class PageProbeCaptureTests(unittest.TestCase):
    def test_h1_serialized_summary_retains_driver_probe_digest_only_for_all_flows(self):
        # Exercise the runner's real report statements without starting browsers.
        tree = ast.parse(inspect.getsource(capture_module.capture_http1))
        result_assignment = next(
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Name) and target.id == "result"
                for target in node.targets
            )
        )
        probe_assignment = next(
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.If)
            and isinstance(node.test, ast.Name)
            and node.test.id == "all_flows"
            and any(
                isinstance(child, ast.Constant)
                and child.value == "websocket_probe_sha256"
                for child in ast.walk(node)
            )
        )
        summary_write = next(
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Expr)
            and isinstance(node.value, ast.Call)
            and isinstance(node.value.func, ast.Attribute)
            and node.value.func.attr == "write_text"
            and any(
                isinstance(child, ast.Constant) and child.value == "summary.json"
                for child in ast.walk(node.value.func)
            )
        )
        report = compile(
            ast.Module(
                body=[result_assignment, probe_assignment, summary_write],
                type_ignores=[],
            ),
            capture_module.__file__,
            "exec",
        )
        probe = "driver-known echo 🐬 #" + "87" * 16
        for all_flows in (False, True):
            with (
                self.subTest(all_flows=all_flows),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory)
                namespace = dict(
                    root=root,
                    capture_result=SimpleNamespace(
                        browser_name="firefox",
                        browser_version="158.0",
                        protocols={"navigate": "h1"},
                        websocket_probe=probe,
                    ),
                    all_flows=all_flows,
                    browser_kind="firefox",
                    flow_mode="all" if all_flows else "navigate",
                    archive={"profiles": [{}]},
                    hashlib=hashlib,
                    json=json,
                )
                exec(report, namespace)
                serialized = (root / "summary.json").read_text()
                summary = json.loads(serialized)
                self.assertEqual(summary["browser"], "firefox")
                self.assertEqual(summary["version"], "158.0")
                self.assertEqual(summary["protocols"], {"navigate": "h1"})
                if all_flows:
                    self.assertEqual(
                        summary.get("websocket_probe_sha256"),
                        hashlib.sha256(probe.encode()).hexdigest(),
                    )
                else:
                    self.assertNotIn("websocket_probe_sha256", summary)
                self.assertNotIn(probe, serialized)
                self.assertNotIn("page_results", summary)

    def test_tls_capture_supplies_its_completed_page_probe_to_the_decoder(self):
        class DecoderReached(Exception):
            pass

        @contextmanager
        def owned(*_args, **_kwargs):
            yield SimpleNamespace(returncode=0)

        for protocol in ("h2", "h3"):
            with (
                self.subTest(protocol=protocol),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory)
                key, certificate = root / "key.pem", root / "cert.pem"
                key.write_bytes(b"owned fixture key placeholder")
                certificate.write_bytes(b"owned fixture certificate placeholder")
                args = SimpleNamespace(
                    output=root,
                    rama=Path("rama"),
                    browser="chrome",
                    protocol=protocol,
                    interface="lo",
                    browser_binary=None,
                )
                environment = dict.fromkeys(
                    (
                        "RAMA_BROWSER_CAPTURE_DATABASE_URL",
                        "DATABASE_URL",
                        "RAMA_FP_DATABASE_URL",
                    ),
                    "host=127.0.0.1 dbname=rama_fp_capture",
                )
                page = FlowResult(
                    user_agent="fixture",
                    browser_name="chrome",
                    browser_version="155",
                    protocols=dict.fromkeys(
                        ("navigate", "fetch", "xhr", "ws", "form", "form_get"), protocol
                    ),
                    report_html="driver report",
                    form_html="driver form",
                    get_form_html="driver GET form",
                    page_results={"websocket": {"probe": "page-known echo 🐢"}},
                    report_url="https://localhost:24443/report?h3_probe=1",
                )
                with (
                    patch.dict(os.environ, environment),
                    patch(
                        "capture.fixture_certificate",
                        return_value=(key, certificate, "spki"),
                    ),
                    patch("capture.socket.socket") as socket,
                    patch("capture.tls_browser_options", return_value=(None, None)),
                    patch("capture.running", owned),
                    patch("capture.wait_ready"),
                    patch("capture.local_session", owned),
                    patch("capture.run_capture_flow", return_value=page) as journey,
                    patch(
                        "capture.wire.drain_capture", side_effect=DecoderReached
                    ) as decoder,
                ):
                    socket.return_value.__enter__.return_value.getsockname.return_value = (
                        "127.0.0.1",
                        24443,
                    )
                    with self.assertRaises(DecoderReached):
                        capture_tls(args)
                receipt = json.loads((root / "page-result.json").read_text())
                self.assertEqual(receipt["report_url"], page.report_url)
                self.assertEqual(
                    receipt["page_results"]["websocket"]["probe"], page.websocket_probe
                )
                self.assertEqual(
                    (root / "page-result.json").stat().st_mode & 0o777, 0o600
                )
                self.assertEqual(journey.call_count, 1)
                self.assertEqual(
                    decoder.call_args.kwargs.get("websocket_probe"),
                    page.websocket_probe,
                )

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
