"""The common entry point must preserve protocol, browser and failure results."""

from types import SimpleNamespace
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import run


class RunnerTests(unittest.TestCase):
    def arguments(self, root, protocol="h1", browser="chrome"):
        binary = root / "rama"
        binary.touch(exist_ok=True)
        return [
            "--rama",
            str(binary),
            "--output",
            str(root / "evidence"),
            "--protocol",
            protocol,
            "--browser",
            browser,
        ]

    def test_every_protocol_uses_same_database_boundary(self):
        for protocol in ("h1", "h2", "h3"):
            with self.subTest(
                protocol=protocol
            ), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                argv = self.arguments(root, protocol)
                with patch("run.shutil.which", return_value="/tool"), patch(
                    "run.require_h3_tshark"
                ), patch("run.run_isolated", return_value=7) as isolated:
                    self.assertEqual(run.main(argv), 7)
                command = isolated.call_args.args[0]
                self.assertEqual(command[2:], argv + ["--inside-disposable-database"])
                self.assertEqual((root / "evidence").stat().st_mode & 0o777, 0o700)
                with patch("run.shutil.which", return_value="/tool"), patch(
                    "run.require_h3_tshark"
                ), patch("run.run_isolated") as isolated:
                    with self.assertRaises(FileExistsError):
                        run.main(argv)
                    isolated.assert_not_called()

    def test_capture_failure_propagates_for_every_protocol(self):
        for protocol in ("h1", "h2", "h3"):
            with tempfile.TemporaryDirectory() as directory, patch(
                "run.shutil.which", return_value="/tool"
            ):
                args = run.parse_args(self.arguments(Path(directory), protocol))
                with patch(
                    "capture.capture", side_effect=RuntimeError("fixture failed")
                ):
                    with self.assertRaisesRegex(RuntimeError, "fixture failed"):
                        run.execute(args)


    def test_firefox_tls_needs_nss_before_allocating_a_database(self):
        for protocol in ("h2", "h3"):
            with tempfile.TemporaryDirectory() as directory:
                self.check_firefox_nss_preflight(Path(directory), protocol)

    def check_firefox_nss_preflight(self, root, protocol):
        argv = self.arguments(root, protocol, "firefox")
        with patch(
            "run.shutil.which",
            side_effect=lambda name: None if name == "certutil" else "/tool",
        ), patch("run.run_isolated") as isolated:
            with self.assertRaises(SystemExit):
                run.main(argv)
            isolated.assert_not_called()
        with patch("run.shutil.which", return_value="/tool"):
            self.assertEqual(run.parse_args(argv).browser, "firefox")

    def test_all_supported_browsers_reach_each_protocol_fixture(self):
        for browser in ("chrome", "firefox", "edge"):
            for protocol in ("h1", "h2", "h3"):
                with self.subTest(browser=browser, protocol=protocol):
                    with tempfile.TemporaryDirectory() as directory, patch(
                        "run.shutil.which", return_value="/tool"
                    ), patch("capture.capture") as capture:
                        args = run.parse_args(
                            self.arguments(Path(directory), protocol, browser)
                        )
                        self.assertEqual(run.execute(args), 0)
                        self.assertIs(capture.call_args.args[0], args)
                        self.assertEqual(
                            (args.browser, args.protocol), (browser, protocol)
                        )

    def test_h1_tls_preflights_trust_tools_and_requires_all_operations(self):
        with tempfile.TemporaryDirectory() as directory:
            argv = self.arguments(Path(directory), "h1", "firefox") + ["--tls"]
            with patch("run.shutil.which", return_value="/tool"):
                self.assertTrue(run.parse_args(argv).tls)
                with self.assertRaises(SystemExit):
                    run.parse_args(argv + ["--flows", "navigate"])
            for missing in ("openssl", "certutil"):
                with self.subTest(missing=missing), patch(
                    "run.shutil.which",
                    side_effect=lambda name: None if name == missing else "/tool",
                ), patch("run.run_isolated") as isolated:
                    with self.assertRaises(SystemExit):
                        run.main(argv)
                    isolated.assert_not_called()

    def test_partial_tls_journeys_fail_before_starting(self):
        with tempfile.TemporaryDirectory() as directory, patch(
            "run.shutil.which", return_value="/tool"
        ):
            for protocol in ("h2", "h3"):
                for extra, browser in [
                    (["--flows", "navigate"], "chrome"),
                ]:
                    with self.assertRaises(SystemExit):
                        run.parse_args(
                            self.arguments(Path(directory), protocol, browser) + extra
                        )


class DecoderAdmissionTests(unittest.TestCase):
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
            ), patch("run.run_isolated", return_value=0) as allocate, patch(
                "run.execute", return_value=0
            ):
                with self.assertRaisesRegex(RuntimeError, "missing H3 decoder"):
                    run.main([])
            allocate.assert_not_called()
            self.assertFalse(output.exists())
