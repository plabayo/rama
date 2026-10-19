"""Nightly scheduling must not hide failed browser journeys."""

from contextlib import contextmanager
import io
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import MagicMock, patch
from urllib.parse import quote

import main


class NightlyTests(unittest.TestCase):
    def test_import_does_not_require_credentials_or_start_jobs(self):
        # Import above succeeds in local/CI unit runs with no BrowserStack secrets.
        self.assertTrue(callable(main.main))

    def test_every_origin_uses_the_shared_workflow_and_failure_is_returned(self):
        drivers = []
        browser_arguments = []

        @contextmanager
        def session(endpoint, options):
            browser_arguments.append(options.arguments)
            driver = MagicMock()
            drivers.append(driver)
            yield driver

        result = MagicMock(
            protocols=dict.fromkeys(
                ("navigate", "fetch", "xhr", "ws", "form", "form_get"), "h1"
            )
        )
        capability = dict(
            browserName="Chrome",
            browserVersion="latest",
            os="Windows",
            osVersion="11",
            buildName="test",
            sessionName="fixture",
        )
        with tempfile.TemporaryDirectory() as directory, patch.object(
            main, "remote_session", session
        ), patch.object(
            main,
            "ENTRYPOINTS",
            [("https://h1.invalid/", "h1"), ("https://h3.invalid/", "h3")],
        ), patch.object(
            main, "run_capture_flow", side_effect=[result, RuntimeError("failed")]
        ) as capture:
            failures = main.run_session(
                capability,
                output=Path(directory),
                capability_index=0,
                endpoint="https://grid.invalid/",
                username="private-login",
                access_key="private-access-key",
                storage_cookie="private-storage-cookie",
            )
        self.assertEqual(failures, ["https://h3.invalid/"])
        self.assertFalse(
            any(
                "EnableWebsocketsOverHttp3" in argument
                for arguments in browser_arguments
                for argument in arguments
            )
        )
        self.assertEqual(capture.call_count, 2)
        self.assertEqual(
            [call.kwargs["expected_protocol"] for call in capture.call_args_list],
            ["h1", "h3"],
        )
        self.assertEqual(
            capture.call_args.kwargs["cookies"]["source-browser-name"], "Chrome"
        )
        self.assertIn("passed", drivers[0].execute_script.call_args.args[0])
        self.assertIn("failed", drivers[1].execute_script.call_args.args[0])

    def test_real_session_owner_records_success_and_failures_without_private_data(self):
        capability = dict(
            browserName="Chrome",
            browserVersion="latest",
            deviceName="Requested device",
            osVersion="17",
            buildName="not-public",
            sessionName="fixture",
        )
        secrets = ("private-login", "private-access-key", "private-storage-cookie")
        cases = (
            ("success", None, False, "passed", None, "succeeded"),
            ("incomplete_metadata", None, False, "failed", "journey", "succeeded"),
            (
                "workflow_failed",
                RuntimeError("unsupported " + " ".join(secrets)),
                False,
                "failed",
                "journey",
                "succeeded",
            ),
            ("quit_failed", None, True, "failed", "session_quit", "failed"),
            (
                "both_failed",
                RuntimeError("private failure"),
                True,
                "failed",
                "journey",
                "failed",
            ),
        )
        for (
            name,
            journey_error,
            quit_failed,
            status,
            failure_stage,
            quit_outcome,
        ) in cases:
            with self.subTest(case=name), tempfile.TemporaryDirectory() as directory:
                driver = MagicMock()
                driver.capabilities = {
                    "browserName": "chrome",
                    "browserVersion": "155.0.8059.40",
                    "deviceName": "Actual device",
                    "platformName": "android",
                    "sessionId": "must-not-retain",
                    "accessKey": secrets[1],
                }
                if quit_failed:
                    driver.quit.side_effect = RuntimeError(
                        "provider secret " + secrets[1]
                    )
                result = SimpleNamespace(
                    protocols={
                        **dict.fromkeys(
                            ("navigate", "fetch", "xhr", "form", "form_get"), "h3"
                        ),
                        "ws": "h1",
                    }
                )
                if name == "incomplete_metadata":
                    result.protocols = {"navigate": "h3"}
                with patch(
                    "browser_automation.drivers.webdriver.Remote", return_value=driver
                ), patch.object(
                    main, "ENTRYPOINTS", [("https://h3.invalid/", "h3")]
                ), patch.object(
                    main,
                    "run_capture_flow",
                    side_effect=journey_error,
                    return_value=result,
                ):
                    failures = main.run_session(
                        capability,
                        output=Path(directory),
                        capability_index=7,
                        endpoint="https://provider.invalid/",
                        username=secrets[0],
                        access_key=secrets[1],
                        storage_cookie=secrets[2],
                    )
                receipt_path = Path(directory) / "007-0.json"
                raw = receipt_path.read_text()
                receipt = json.loads(raw)
                self.assertEqual(receipt["status"], status)
                self.assertEqual(receipt["failure_stage"], failure_stage)
                self.assertEqual(receipt["quit_outcome"], quit_outcome)
                self.assertEqual(
                    receipt["failure_reason"],
                    {
                        "success": None,
                        "incomplete_metadata": "ValueError: invalid cell protocol receipt",
                    }.get(name, "RuntimeError"),
                )
                self.assertTrue(receipt["session_started"])
                self.assertEqual(receipt["actual"]["browserVersion"], "155.0.8059.40")
                self.assertEqual(receipt["actual"]["deviceName"], "Actual device")
                self.assertEqual(receipt["requested"]["deviceName"], "Requested device")
                self.assertEqual(
                    receipt["protocols"],
                    (
                        result.protocols
                        if journey_error is None and name != "incomplete_metadata"
                        else None
                    ),
                )
                self.assertGreaterEqual(receipt["elapsed_seconds"], 0)
                self.assertEqual(receipt_path.stat().st_mode & 0o777, 0o600)
                self.assertEqual(
                    failures, [] if status == "passed" else ["https://h3.invalid/"]
                )
                driver.quit.assert_called_once_with()
                for private in (
                    *secrets,
                    "must-not-retain",
                    "private failure",
                    "unsupported",
                ):
                    self.assertNotIn(private, raw)

    def test_journey_validation_reason_is_recorded_without_secrets(self):
        secrets = ("private-login", "private-access-key", "private-storage-cookie")
        error = ValueError("incomplete coverage " + secrets[2])
        error.add_note("POST=h1,\nGET=" + quote(secrets[1], safe="") + " " * 400)
        with tempfile.TemporaryDirectory() as directory, patch(
            "browser_automation.drivers.webdriver.Remote", return_value=MagicMock()
        ), patch.object(
            main, "ENTRYPOINTS", [("https://h1.invalid/", "h1")]
        ), patch.object(
            main, "run_capture_flow", side_effect=error
        ), patch(
            "sys.stdout", new_callable=io.StringIO
        ) as stdout:
            main.run_session(
                dict(browserName="Chrome", sessionName="fixture"),
                output=Path(directory),
                capability_index=2,
                endpoint="https://provider.invalid/",
                username=secrets[0],
                access_key=secrets[1],
                storage_cookie=secrets[2],
            )
            raw = (Path(directory) / "002-0.json").read_text()
        reason = "ValueError: incomplete coverage <redacted> POST=h1, GET=<redacted>"
        self.assertEqual(json.loads(raw)["failure_reason"], reason)
        self.assertEqual(
            stdout.getvalue(),
            "FAILED 002-0 https://h1.invalid/ journey " + reason + "\n",
        )
        for private in secrets:
            self.assertNotIn(private, raw + stdout.getvalue())

    def test_failed_start_never_claims_session_or_quit(self):
        capability = dict(
            browserName="Safari",
            browserVersion="latest",
            os="OS X",
            osVersion="Tahoe",
            buildName="private-build",
            sessionName="fixture",
        )
        with tempfile.TemporaryDirectory() as directory, patch(
            "browser_automation.drivers.webdriver.Remote",
            side_effect=RuntimeError("unsupported provider secret"),
        ), patch.object(
            main, "ENTRYPOINTS", [("https://h3.invalid/", "h3")]
        ), patch.object(
            main, "run_capture_flow"
        ) as journey:
            failures = main.run_session(
                capability,
                output=Path(directory),
                capability_index=1,
                endpoint="https://provider.invalid/",
                username="private-login",
                access_key="private-access-key",
                storage_cookie="private-storage-cookie",
            )
            receipt = json.loads((Path(directory) / "001-0.json").read_text())
        self.assertEqual(failures, ["https://h3.invalid/"])
        self.assertEqual(receipt["status"], "failed")
        self.assertEqual(receipt["failure_stage"], "session_start")
        self.assertFalse(receipt["session_started"])
        self.assertEqual(receipt["quit_outcome"], "not_started")
        self.assertEqual(receipt["actual"], {})
        self.assertIsNone(receipt["protocols"])
        journey.assert_not_called()

    def test_receipt_command_runs_all_cells_and_keeps_failure_exit(self):
        caps = [
            dict(
                browserName="Chrome",
                browserVersion=version,
                os="Windows",
                osVersion="11",
                buildName="build",
                sessionName="fixture",
            )
            for version in ("latest", "latest-1")
        ]
        drivers = []

        def remote(**_kwargs):
            driver = MagicMock(
                capabilities={"browserName": "chrome", "browserVersion": "155.0"}
            )
            drivers.append(driver)
            return driver

        def journey(_driver, _origin, *, cookies, **_kwargs):
            if cookies["source-browser-version"] == "latest-1":
                raise RuntimeError("unsupported but not verified")
            return SimpleNamespace(
                protocols=dict.fromkeys(
                    ("navigate", "fetch", "xhr", "ws", "form", "form_get"), "h2"
                )
            )

        with tempfile.TemporaryDirectory() as directory, patch.dict(
            main.os.environ,
            {
                "BROWSERSTACK_USERNAME": "private-login",
                "BROWSERSTACK_ACCESS_KEY": "private-access-key",
                "RAMA_FP_STORAGE_COOKIE": "private-storage-cookie",
            },
        ), patch.object(main, "capabilities", return_value=caps), patch.object(
            main, "ENTRYPOINTS", [("https://h2.invalid/", "h2")]
        ), patch(
            "browser_automation.drivers.webdriver.Remote", side_effect=remote
        ), patch.object(
            main, "run_capture_flow", side_effect=journey
        ):
            output = Path(directory) / "receipts"
            self.assertEqual(main.main(["--output", str(output)]), 1)
            receipts = [
                json.loads(path.read_text()) for path in sorted(output.glob("*.json"))
            ]
            self.assertEqual([row["cell"] for row in receipts], ["000-0", "001-0"])
            self.assertEqual([row["status"] for row in receipts], ["passed", "failed"])
            self.assertEqual(output.stat().st_mode & 0o777, 0o700)
            with self.assertRaises(FileExistsError):
                main.main(["--output", str(output)])
        self.assertEqual(len(drivers), 2)
        for driver in drivers:
            driver.quit.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
