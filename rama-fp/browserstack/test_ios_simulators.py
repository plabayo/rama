import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

import ios_simulators as ios


class SimulatorTests(unittest.TestCase):
    def test_selects_one_available_iphone_per_available_ios_runtime(self):
        runtimes = [dict(identifier="com.apple.iOS-18", version="18.0", isAvailable=True),
                    dict(identifier="com.apple.iOS-26", version="26.0", isAvailable=False)]
        devices = {"com.apple.iOS-18": [dict(name="iPad", udid="tablet", isAvailable=True),
                    dict(name="iPhone 16", udid="phone", isAvailable=True),
                    dict(name="iPhone 16 Pro", udid="other", isAvailable=True)]}
        self.assertEqual(ios.devices_by_runtime(devices, runtimes), [("18.0", "phone")])
        with self.assertRaisesRegex(RuntimeError, "no available"):
            ios.devices_by_runtime({}, runtimes)

    def test_shutdown_timeout_is_accepted_only_after_state_confirmation(self):
        for state, calls in (("Shutdown", 2), ("Booted", 4)):
            devices = json.dumps({"devices": {"runtime": [dict(udid="phone", state=state)]}})
            with self.subTest(state=state), patch.object(ios, "simctl", side_effect=[
                subprocess.TimeoutExpired("shutdown", 120), devices,
                subprocess.TimeoutExpired("shutdown", 120), devices,
            ]) as run:
                if state == "Shutdown":
                    ios.transition("shutdown", "phone", "Shutdown")
                else:
                    with self.assertRaises(subprocess.TimeoutExpired):
                        ios.transition("shutdown", "phone", "Shutdown")
                self.assertEqual(run.call_count, calls)

    def test_boot_failure_still_shuts_down_its_device(self):
        with patch.object(ios, "transition") as transition, patch.object(
            ios, "simctl", side_effect=subprocess.TimeoutExpired("bootstatus", 900)
        ):
            with self.assertRaises(subprocess.TimeoutExpired):
                ios.run_device("18.0", "phone", Path("evidence"))
        self.assertEqual([call.args for call in transition.call_args_list],
                         [("boot", "phone", "Booted"), ("shutdown", "phone", "Shutdown")])
