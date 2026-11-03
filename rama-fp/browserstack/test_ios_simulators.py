"""Simulator startup readiness must not consume or conceal journey failures."""

import io
import json
from pathlib import Path
import signal
import subprocess
import tempfile
import unittest
from unittest.mock import MagicMock, call, patch

from selenium.common.exceptions import SessionNotCreatedException, WebDriverException

import ios_simulators as ios


class SimulatorTests(unittest.TestCase):
    def test_readiness_waits_for_a_working_session_and_quit(self):
        driver = MagicMock()
        driver.execute_script.return_value = "complete"
        slow = SessionNotCreatedException("private startup details")
        with patch("browser_automation.drivers.webdriver.Safari",
                   side_effect=[slow] * 6 + [driver]) as start, patch(
            "browser_automation.drivers.time.sleep"
        ), patch("sys.stdout", new_callable=io.StringIO) as stdout:
            ios.probe_safari("26.2")
        self.assertEqual(start.call_count, 7)
        driver.get.assert_called_once_with("about:blank")
        driver.execute_script.assert_called_once_with("return document.readyState")
        driver.quit.assert_called_once_with()
        self.assertNotIn("private startup details", stdout.getvalue())

    def test_readiness_retries_unusable_documents_and_failed_quit(self):
        incomplete, bad_quit, ready = MagicMock(), MagicMock(), MagicMock()
        incomplete.execute_script.return_value = "loading"
        bad_quit.execute_script.return_value = ready.execute_script.return_value = "complete"
        bad_quit.quit.side_effect = WebDriverException("quit failed")
        with patch("browser_automation.drivers.webdriver.Safari",
                   side_effect=[incomplete, bad_quit, ready]), patch.object(ios.time, "sleep"):
            ios.probe_safari("26.2")
        for driver in (incomplete, bad_quit, ready):
            driver.quit.assert_called_once_with()

    def test_readiness_has_a_deadline(self):
        with patch("browser_automation.drivers.device_session",
                   side_effect=SessionNotCreatedException("still starting")), patch.object(
            ios.time, "monotonic", side_effect=[0, 601]
        ), patch.object(ios.time, "sleep") as sleep:
            with self.assertRaisesRegex(TimeoutError, "did not become ready"):
                ios.probe_safari("26.2")
        sleep.assert_not_called()

    def test_probe_precedes_journeys_without_precreating_cell_directory(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(
            ios, "transition"
        ) as transition, patch.object(ios, "simctl") as simctl, patch.object(
            ios, "run_bounded"
        ) as run:
            output = Path(directory)

            def child(arguments, timeout):
                if "--output" in arguments:
                    # The collector exclusively creates this directory itself.
                    Path(arguments[arguments.index("--output") + 1]).mkdir(exist_ok=False)

            run.side_effect = child
            ios.run_device("26.2", "phone", output)
            receipt = json.loads((output / "ios-26.2-simulator.json").read_text())
        transition.assert_has_calls([
            call("boot", "phone", "Booted"), call("shutdown", "phone", "Shutdown")
        ])
        simctl.assert_called_once_with("bootstatus", "phone", "-b", timeout=900)
        self.assertEqual(run.call_args_list[0].args[0][-2:], ["--probe-safari", "26.2"])
        self.assertEqual(run.call_args_list[1].args[0][-2:], ["--device", "ios-simulator:26.2"])
        self.assertEqual(receipt["status"], "passed")

    def test_startup_and_journey_failures_are_recorded_and_never_retried(self):
        for stage in ("safari_ready", "journeys"):
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as directory, patch.object(
                ios, "transition"
            ) as transition, patch.object(ios, "simctl"), patch.object(ios, "run_bounded") as run:
                failure = subprocess.CalledProcessError(1, ["child"])
                run.side_effect = [failure] if stage == "safari_ready" else [None, failure]
                with self.assertRaises(subprocess.CalledProcessError) as raised:
                    ios.run_device("26.2", "phone", Path(directory))
                self.assertIs(raised.exception, failure)
                self.assertEqual(run.call_count, 1 if stage == "safari_ready" else 2)
                transition.assert_called_with("shutdown", "phone", "Shutdown")
                receipt = json.loads((Path(directory) / "ios-26.2-simulator.json").read_text())
                self.assertEqual(receipt["status"], "failed")
                self.assertEqual(receipt["failure_stage"], stage)

    def test_shutdown_failure_does_not_replace_original_error(self):
        for journey_failed in (False, True):
            with self.subTest(journey_failed=journey_failed), tempfile.TemporaryDirectory() as directory:
                failure = subprocess.CalledProcessError(1, ["journeys"])
                shutdown = subprocess.TimeoutExpired(["shutdown"], 120)
                with patch.object(ios, "transition", side_effect=[None, shutdown]), patch.object(
                    ios, "simctl"
                ), patch.object(ios, "run_bounded", side_effect=[None, failure] if journey_failed else None):
                    with self.assertRaises(Exception) as raised:
                        ios.run_device("26.2", "phone", Path(directory))
                self.assertIs(raised.exception, failure if journey_failed else shutdown)
                receipt = json.loads((Path(directory) / "ios-26.2-simulator.json").read_text())
                self.assertEqual(receipt["status"], "failed")
                self.assertEqual(receipt["shutdown_error"], "TimeoutExpired")
                self.assertEqual(receipt["failure_stage"], "journeys" if journey_failed else "shutdown")

    def test_timeout_reaps_child_driver_processes(self):
        process = MagicMock(pid=1234)
        process.wait.side_effect = [subprocess.TimeoutExpired(["probe"], 660), -9]
        with patch.object(ios.subprocess, "Popen") as popen, patch.object(ios.os, "killpg") as kill:
            popen.return_value.__enter__.return_value = process
            with self.assertRaises(subprocess.TimeoutExpired):
                ios.run_bounded(["probe"], timeout=660)
        popen.assert_called_once_with(["probe"], start_new_session=True)
        kill.assert_called_once_with(1234, signal.SIGKILL)
        self.assertEqual(process.wait.call_args_list, [call(timeout=660), call()])

    def test_failed_transition_accepts_only_the_requested_device_state(self):
        failed = subprocess.TimeoutExpired(["boot"], 120)
        for udid, state, accepted in [("phone", "Booted", True),
                                      ("other", "Booted", False), ("phone", "Shutdown", False)]:
            with self.subTest(udid=udid, state=state):
                devices = json.dumps({"devices": {"runtime": [{"udid": udid, "state": state}]}})
                with patch.object(ios, "simctl", side_effect=[failed, devices] * 2) as simctl:
                    if accepted:
                        ios.transition("boot", "phone", "Booted")
                    else:
                        with self.assertRaises(subprocess.TimeoutExpired):
                            ios.transition("boot", "phone", "Booted")
                self.assertEqual(simctl.call_count, 2 if accepted else 4)


if __name__ == "__main__":
    unittest.main()
