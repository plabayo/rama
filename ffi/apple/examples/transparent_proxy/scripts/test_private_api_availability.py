import json
from pathlib import Path
import plistlib
import tempfile
import unittest
from unittest.mock import patch

from private_api_availability import Probe, SYMBOL, newest_runtime, newest_xcode, probe_result


class AvailabilityTests(unittest.TestCase):
    def test_xcode_selection_includes_beta_and_deduplicates_aliases(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            for name, short, build in (("Xcode.app", "27.1", "24000"),
                                       ("Xcode_beta.app", "27.2", "25000"),
                                       ("Xcode_old.app", "9.4", "90000")):
                contents = root / name / "Contents"
                contents.mkdir(parents=True)
                (contents / "version.plist").write_bytes(plistlib.dumps({
                    "CFBundleShortVersionString": short, "CFBundleVersion": build}))
            (root / "Xcode_27.2.app").symlink_to(root / "Xcode_beta.app")
            self.assertEqual(newest_xcode(root), root / "Xcode_beta.app/Contents/Developer")

    def test_no_xcode_is_a_failure(self):
        with tempfile.TemporaryDirectory() as directory, self.assertRaises(ValueError):
            newest_xcode(Path(directory))

    def test_unavailable_newest_runtime_does_not_fall_back(self):
        runtimes = [{"identifier": f"com.apple.CoreSimulator.SimRuntime.iOS-{v}",
                     "version": v, "buildversion": "A1", "isAvailable": available}
                    for v, available in (("26.0", True), ("27.2", False))]
        with self.assertRaisesRegex(ValueError, "unavailable"):
            newest_runtime(runtimes)
        runtimes[1]["isAvailable"] = True
        self.assertEqual(newest_runtime(runtimes)["version"], "27.2")
        with self.assertRaisesRegex(ValueError, "No iOS"):
            newest_runtime([])

    def test_incomplete_or_wrong_platform_result_fails(self):
        valid = {"symbol": SYMBOL, "platform": "ios-simulator", "os": "27.2", "called_true_and_false": True}
        self.assertEqual(probe_result(json.dumps(valid), "ios-simulator"), valid)
        for change in ({"symbol": "other"}, {"platform": "macos"}, {"called_true_and_false": False}, {"os": ""}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                probe_result(json.dumps({**valid, **change}), "ios-simulator")

    def test_download_cannot_silently_use_an_older_runtime(self):
        runtime = {"identifier": "com.apple.CoreSimulator.SimRuntime.iOS-26", "version": "26.0",
                   "buildversion": "A1", "isAvailable": True}
        with tempfile.TemporaryDirectory() as directory:
            probe = Probe(Path(directory), Path("/Xcode"))
            with patch.object(probe, "run", side_effect=["27.2", json.dumps({"runtimes": [runtime]}), "", json.dumps({"runtimes": [runtime]})]) as run:
                with self.assertRaisesRegex(ValueError, "older than SDK"):
                    probe.simulator(True)
                self.assertIn(unittest.mock.call("xcodebuild", "-downloadPlatform", "iOS", "-buildVersion", "27.2",
                                                 "-architectureVariant", "arm64", timeout=1800), run.call_args_list)

    def test_stable_uses_system_selection_and_accepts_release_build_letters(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            for name, short, build in (("Xcode_16.2.app", "16.2", "16C5032a"),
                                       ("Xcode_27_beta.app", "27.2", "27B5028f")):
                contents = root / name / "Contents"
                contents.mkdir(parents=True)
                (contents / "version.plist").write_bytes(plistlib.dumps({
                    "CFBundleShortVersionString": short, "CFBundleVersion": short,
                    "ProductBuildVersion": build}))
            selected = root / "Xcode_16.2.app/Contents/Developer"
            with patch("private_api_availability.subprocess.check_output", return_value=str(selected)) as command, \
                    patch.dict("os.environ", {"DEVELOPER_DIR": "/overridden/beta"}):
                self.assertEqual(newest_xcode(root, stable=True), selected)
            self.assertNotIn("DEVELOPER_DIR", command.call_args.kwargs["env"])
            self.assertEqual(newest_xcode(root), root / "Xcode_27_beta.app/Contents/Developer")

    def test_stable_rejects_selected_preview_and_command_line_tools(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            for name in ("Xcode_26.1_rc.app", "Xcode_beta.app", "Xcode_preview.app", "CommandLineTools"):
                selected = root / name / "Contents/Developer"
                if name != "CommandLineTools":
                    selected.parent.mkdir(parents=True)
                    (selected.parent / "version.plist").write_bytes(plistlib.dumps({}))
                with self.subTest(name=name), patch("private_api_availability.subprocess.check_output", return_value=str(selected)), self.assertRaises(ValueError):
                    newest_xcode(root, stable=True)
