"""The common entry point must preserve protocol, browser and failure results."""

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
                    "run.run_isolated", return_value=7
                ) as isolated:
                    self.assertEqual(run.main(argv), 7)
                command = isolated.call_args.args[0]
                self.assertEqual(command[2:], argv + ["--inside-disposable-database"])
                self.assertEqual((root / "evidence").stat().st_mode & 0o777, 0o700)
                with patch("run.shutil.which", return_value="/tool"), patch(
                    "run.run_isolated"
                ) as isolated:
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

    def test_every_protocol_reaches_capture_unchanged(self):
        for protocol in ("h1", "h2", "h3"):
            with tempfile.TemporaryDirectory() as directory, patch(
                "run.shutil.which", return_value="/tool"
            ):
                args = run.parse_args(self.arguments(Path(directory), protocol))
                with patch("capture.capture") as capture:
                    self.assertEqual(run.execute(args), 0)
                self.assertIs(capture.call_args.args[0], args)
                self.assertEqual(args.protocol, protocol)

    def test_unimplemented_combinations_fail_before_starting(self):
        with tempfile.TemporaryDirectory() as directory, patch(
            "run.shutil.which", return_value="/tool"
        ):
            with self.assertRaises(SystemExit):
                run.parse_args(self.arguments(Path(directory), "h1", "edge"))
            for protocol in ("h2", "h3"):
                for extra, browser in [
                    ([], "firefox"),
                    (["--flows", "navigate"], "chrome"),
                ]:
                    with self.assertRaises(SystemExit):
                        run.parse_args(
                            self.arguments(Path(directory), protocol, browser) + extra
                        )


if __name__ == "__main__":
    unittest.main()
