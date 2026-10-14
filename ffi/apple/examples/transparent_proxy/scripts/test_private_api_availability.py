import json
from pathlib import Path
import plistlib
import subprocess
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

    def test_command_failure_and_timeout_are_saved(self):
        with tempfile.TemporaryDirectory() as directory:
            probe = Probe(Path(directory), Path("/Xcode"))
            for error in (RuntimeError("Missing private symbol"), subprocess.TimeoutExpired("simctl", 1)):
                with patch.object(probe, "macos", side_effect=error):
                    probe.check("macos-runtime", probe.macos)
                report = json.loads((Path(directory) / "report.json").read_text())
                self.assertEqual(report["checks"]["macos-runtime"]["status"], "failed")

    def test_failed_runtime_probe_still_removes_owned_device(self):
        runtime = {"identifier": "com.apple.CoreSimulator.SimRuntime.iOS-27-2", "version": "27.2",
                   "buildversion": "B1", "isAvailable": True,
                   "supportedDeviceTypes": [{"identifier": "iphone", "productFamily": "iPhone"}]}
        calls = []

        def run(*args, **kwargs):
            calls.append(args)
            if "--show-sdk-version" in args:
                return "27.2"
            if "runtimes" in args:
                return json.dumps({"runtimes": [runtime]})
            if "create" in args:
                return "owned-device"
            if "spawn" in args:
                raise RuntimeError("Missing private symbol")
            return ""

        with tempfile.TemporaryDirectory() as directory:
            probe = Probe(Path(directory), Path("/Xcode"))
            with patch.object(probe, "run", side_effect=run), patch.object(probe, "compile", return_value="probe"):
                with self.assertRaisesRegex(RuntimeError, "Missing private symbol"):
                    probe.simulator(False)
            self.assertIn(("xcrun", "simctl", "shutdown", "owned-device"), calls)
            self.assertIn(("xcrun", "simctl", "delete", "owned-device"), calls)

            def failed_shutdown(*args, **kwargs):
                if "shutdown" in args:
                    raise RuntimeError("Shutdown failed")
                return run(*args, **kwargs)

            calls.clear()
            with patch.object(probe, "run", side_effect=failed_shutdown), patch.object(probe, "compile", return_value="probe"):
                with self.assertRaisesRegex(RuntimeError, "Missing private symbol"):
                    probe.simulator(False)
            self.assertIn(("xcrun", "simctl", "delete", "owned-device"), calls)
            self.assertEqual(probe.report["checks"]["simulator-shutdown"]["status"], "failed")

    def test_download_cannot_silently_use_an_older_runtime(self):
        runtime = {"identifier": "com.apple.CoreSimulator.SimRuntime.iOS-26", "version": "26.0",
                   "buildversion": "A1", "isAvailable": True}
        with tempfile.TemporaryDirectory() as directory:
            probe = Probe(Path(directory), Path("/Xcode"))
            with patch.object(probe, "run", side_effect=["27.2", "", json.dumps({"runtimes": [runtime]})]) as run:
                with self.assertRaisesRegex(ValueError, "older than SDK"):
                    probe.simulator(True)
                self.assertIn(unittest.mock.call("xcodebuild", "-downloadPlatform", "iOS", "-buildVersion", "27.2",
                                                 "-architectureVariant", "arm64", timeout=1800), run.call_args_list)
