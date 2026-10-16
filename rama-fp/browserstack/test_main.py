"""Nightly scheduling must not hide failed browser journeys."""

from contextlib import contextmanager
import unittest
from unittest.mock import MagicMock, patch

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

        result = MagicMock(protocols={"navigate": "h1"})
        capability = dict(
            browserName="Chrome",
            browserVersion="latest",
            os="Windows",
            osVersion="11",
            buildName="test",
            sessionName="fixture",
        )
        with patch.object(main, "remote_session", session), patch.object(
            main,
            "ENTRYPOINTS",
            [("https://h1.invalid/", "h1"), ("https://h3.invalid/", "h3")],
        ), patch.object(
            main, "run_capture_flow", side_effect=[result, RuntimeError("failed")]
        ) as capture:
            failures = main.run_session(
                capability,
                endpoint="https://grid.invalid/",
                username="test",
                access_key="fixture",
                storage_cookie="fixture",
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


if __name__ == "__main__":
    unittest.main()
