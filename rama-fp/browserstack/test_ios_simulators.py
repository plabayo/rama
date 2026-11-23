"""Simulator startup regressions without booting a host device."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch, call

import ios_simulators


class SimulatorStartupTests(unittest.TestCase):
    def run_device(self, state="Booted", boot_error=None, child_error=None, udid="target"):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            listing = json.dumps({"devices": {"runtime": [{"udid": udid, "state": state}]}})
            with patch.object(ios_simulators, "transition") as transition, patch.object(
                ios_simulators, "simctl", side_effect=[boot_error, listing, None]
            ), patch.object(ios_simulators, "run_bounded") as child:
                child.side_effect = child_error
                error = None
                try:
                    ios_simulators.run_device("26.0.1", "target", output)
                except (subprocess.TimeoutExpired, subprocess.CalledProcessError) as caught:
                    error = caught
                receipt = json.loads((output / "ios-26.0.1-simulator.json").read_text())
                self.assertEqual(transition.call_args_list, [
                    call("boot", "target", "Booted"), call("shutdown", "target", "Shutdown")
                ] * receipt["startup_attempts"])
                return error, receipt, child.call_args_list

    def test_status_timeout_requires_safari_probe_before_journeys(self):
        error, receipt, calls = self.run_device(
            boot_error=subprocess.TimeoutExpired("bootstatus", 300)
        )
        self.assertIsNone(error)
        self.assertTrue(receipt["bootstatus_timed_out"])
        self.assertEqual(receipt["status"], "passed")
        self.assertEqual(len(calls), 2)
        self.assertIn("--probe-safari", calls[0].args[0])
        self.assertEqual(calls[0].kwargs["env"]["RAMA_FP_IOS_SIMULATOR_UDID"], "target")
        self.assertEqual(calls[1].kwargs["env"], calls[0].kwargs["env"])
        self.assertIn("--device", calls[1].args[0])

    def test_status_timeout_does_not_accept_unbooted_or_other_device(self):
        for state, udid in [("Shutdown", "target"), ("Booted", "other")]:
            with self.subTest(state=state, udid=udid):
                timeout = subprocess.TimeoutExpired("bootstatus", 300)
                error, receipt, calls = self.run_device(state, timeout, udid=udid)
                self.assertIs(error, timeout)
                self.assertEqual(receipt["failure_stage"], "bootstatus")
                self.assertEqual(receipt["status"], "failed")
                self.assertEqual(calls, [])

    def test_failed_probe_after_status_timeout_prevents_journeys(self):
        failure = subprocess.TimeoutExpired("probe", 300)
        error, receipt, calls = self.run_device(
            boot_error=subprocess.TimeoutExpired("bootstatus", 300), child_error=failure
        )
        self.assertIs(error, failure)
        self.assertEqual(receipt["failure_stage"], "safari_ready")
        self.assertEqual(receipt["status"], "failed")
        self.assertEqual(len(calls), 2)
        self.assertTrue(all("--probe-safari" in call.args[0] for call in calls))

    def test_reboot_recovers_before_single_journey(self):
        error, receipt, calls = self.run_device(
            child_error=[subprocess.TimeoutExpired("probe", 300), None, None]
        )
        self.assertIsNone(error)
        self.assertEqual(receipt["startup_attempts"], 2)
        self.assertEqual(receipt["status"], "passed")
        self.assertEqual(len(calls), 3)
        self.assertIn("--device", calls[-1].args[0])

    def test_status_command_failure_is_not_a_timeout(self):
        failure = subprocess.CalledProcessError(1, "bootstatus")
        error, receipt, calls = self.run_device(boot_error=failure)
        self.assertIs(error, failure)
        self.assertFalse(receipt["bootstatus_timed_out"])
        self.assertEqual(receipt["failure_stage"], "bootstatus")
        self.assertEqual(calls, [])

    def test_journey_failure_is_not_retried_after_status_timeout(self):
        failure = subprocess.CalledProcessError(1, "journeys")
        error, receipt, calls = self.run_device(
            boot_error=subprocess.TimeoutExpired("bootstatus", 300),
            child_error=[None, failure],
        )
        self.assertIs(error, failure)
        self.assertEqual(receipt["failure_stage"], "journeys")
        self.assertEqual(receipt["status"], "failed")
        self.assertEqual(len(calls), 2)

    def test_normal_startup_does_not_mark_timeout(self):
        error, receipt, calls = self.run_device()
        self.assertIsNone(error)
        self.assertFalse(receipt["bootstatus_timed_out"])
        self.assertEqual(receipt["status"], "passed")
        self.assertEqual(len(calls), 2)


if __name__ == "__main__":
    unittest.main()
