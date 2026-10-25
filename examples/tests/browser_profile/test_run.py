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
                    "run.require_h3_tshark"
                ), patch("run.require_capture_environment"), patch("run.run_isolated", return_value=7):
                    self.assertEqual(run.main(argv), 7)
                self.assertEqual((root / "evidence").stat().st_mode & 0o777, 0o700)
                with patch("run.shutil.which", return_value="/tool"), patch(
                    "run.require_h3_tshark"
                ), patch("run.require_capture_environment"), patch("run.run_isolated") as isolated:
                    with self.assertRaises(FileExistsError):
                        run.main(argv)
                    isolated.assert_not_called()

    def test_unsafe_capture_fails_before_database_allocation(self):
        with tempfile.TemporaryDirectory() as directory, patch(
            "run.shutil.which", return_value="/tool"
        ), patch("run.require_h3_tshark"), patch(
            "run.require_capture_environment", side_effect=RuntimeError("unsafe offload")
        ) as preflight, patch("run.run_isolated") as database:
            root = Path(directory)
            argv = self.arguments(root, "h3")
            with self.assertRaisesRegex(RuntimeError, "unsafe offload"):
                run.main(argv)
            preflight.assert_called_once()
            database.assert_not_called()
