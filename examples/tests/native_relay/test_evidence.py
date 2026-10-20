"""Check the upload boundary with real files and runner failure paths."""

import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from evidence import export_evidence
from run import main


class EvidenceTests(unittest.TestCase):
    def test_exports_decoded_reports_without_raw_captures_keys_or_binaries(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "websocket").mkdir()
            reports = (
                "comparison.json",
                "ingress.pdml",
                "websocket/comparison.json",
                "websocket/egress.tls-stream.txt",
            )
            private = (
                "wire.pcapng",
                "client.keys",
                "ca.key",
                "peer",
                "websocket/wire.pcapng",
                "websocket/client.keys",
            )
            for name in (*reports, *private):
                (root / name).write_text(name)

            export_evidence(root)

            artifacts = root / "artifacts"
            self.assertEqual(
                {
                    str(path.relative_to(artifacts))
                    for path in artifacts.rglob("*")
                    if path.is_file()
                },
                set(reports),
            )
            for name in reports:
                self.assertEqual((artifacts / name).read_text(), name)

    def test_does_not_follow_report_or_websocket_directory_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "run"
            root.mkdir()
            private = Path(directory) / "private"
            private.mkdir()
            (private / "comparison.json").write_text("private material")
            (root / "comparison.json").symlink_to(private / "comparison.json")
            (root / "websocket").symlink_to(private, target_is_directory=True)

            export_evidence(root)

            self.assertEqual(list((root / "artifacts").iterdir()), [])

    def test_runner_exports_available_evidence_after_success_and_failure(self):
        for fail in (False, True):
            with self.subTest(fail=fail), tempfile.TemporaryDirectory() as directory:
                root = Path(directory) / "run"
                args = SimpleNamespace(output=root, protocol="h1")

                def build(_args):
                    (root / "fixture-build.log").write_text("build diagnostic")
                    (root / "client.keys").write_text("temporary secret")
                    if fail:
                        raise RuntimeError("build failed")

                with patch("run.parse_args", return_value=args), patch(
                    "run.build_binaries", side_effect=build
                ), patch("run.execute", return_value=0):
                    if fail:
                        with self.assertRaisesRegex(RuntimeError, "build failed"):
                            main()
                    else:
                        self.assertEqual(main(), 0)

                artifacts = root / "artifacts"
                self.assertEqual(
                    (artifacts / "fixture-build.log").read_text(), "build diagnostic"
                )
                self.assertEqual(
                    json.loads((artifacts / "cleanup.json").read_text()),
                    {"private_files_remaining": []},
                )
                self.assertFalse((root / "client.keys").exists())
                self.assertFalse((artifacts / "client.keys").exists())

    def test_failed_comparison_is_exported_without_turning_failure_into_success(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "run"
            args = SimpleNamespace(output=root, protocol="h1")

            def compare(_args):
                (root / "comparison.json").write_text('{"fingerprint_match": false}')
                raise ValueError("native fingerprint differs")

            with patch("run.parse_args", return_value=args), patch(
                "run.build_binaries"
            ), patch("run.execute", side_effect=compare):
                with self.assertRaisesRegex(ValueError, "native fingerprint differs"):
                    main()

            report = json.loads((root / "artifacts/comparison.json").read_text())
            self.assertIs(report["fingerprint_match"], False)
