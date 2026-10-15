import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import apple_preview_phase as phase


class PreviewPhaseTests(unittest.TestCase):
    def test_cleanup_preserves_result_and_unrelated_outputs(self):
        for status in (0, 17):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve()
                for path in phase.OUTPUTS["ffi"] + [phase.EXAMPLE / "tproxy_rs/target", Path("evidence")]:
                    (root / path).mkdir(parents=True)
                    (root / path / "keep-or-remove").write_text("data")
                with patch.object(phase, "ROOT", root), patch.dict(os.environ, {"GITHUB_ACTIONS": "true", "GITHUB_WORKSPACE": str(root)}), patch.object(phase.subprocess, "run", return_value=subprocess.CompletedProcess([], status)) as run:
                    self.assertEqual(phase.execute("ffi", ["just", "test-e2e-ffi-apple"]), status)
                run.assert_called_once_with(["just", "test-e2e-ffi-apple"], cwd=root)
                self.assertFalse((root / ".build").exists())
                self.assertFalse((root / phase.EXAMPLE / "tproxy_ffi_e2e/target").exists())
                self.assertTrue((root / phase.EXAMPLE / "tproxy_rs/target/keep-or-remove").exists())
                self.assertTrue((root / "evidence/keep-or-remove").exists())

    def test_sanitizer_cleanup_keeps_evidence_archives(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            temporary = root / "runner-temp"
            for mode in ("asan", "tsan"):
                (temporary / ("egress-policy-build-" + mode)).mkdir(parents=True)
            report = temporary / "rama-egress-policy-result/report.zip"
            report.parent.mkdir()
            report.write_bytes(b"evidence")
            env = {"GITHUB_ACTIONS": "true", "GITHUB_WORKSPACE": str(root), "RUNNER_TEMP": str(temporary)}
            with patch.object(phase, "ROOT", root), patch.dict(os.environ, env), patch.object(phase.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)):
                self.assertEqual(phase.execute("egress", ["just", "test"]), 0)
            self.assertEqual(list(temporary.iterdir()), [report.parent])
            self.assertEqual(report.read_bytes(), b"evidence")

    def test_local_invocation_cannot_delete_builds(self):
        with patch.dict(os.environ, {"GITHUB_ACTIONS": "false"}), patch.object(phase.subprocess, "run") as run:
            with self.assertRaisesRegex(RuntimeError, "restricted"):
                phase.execute("ffi", ["just", "test-e2e-ffi-apple"])
            run.assert_not_called()

    def test_cleanup_rejects_symlink_to_unrelated_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / "keep").mkdir()
            (root / "target").symlink_to(root / "keep", target_is_directory=True)
            with patch.object(phase, "ROOT", root), patch.dict(os.environ, {"GITHUB_ACTIONS": "true", "GITHUB_WORKSPACE": str(root)}), patch.object(phase.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)):
                with self.assertRaisesRegex(RuntimeError, "symlink"):
                    phase.execute("crates", ["just", "test"])
            self.assertTrue((root / "keep").is_dir())
