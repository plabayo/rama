"""Nightly scheduling must not hide failed browser journeys."""

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

    def test_every_h3_cell_on_the_bootstrap_door_fails_the_run(self):
        door = {
            "expected_http_protocol": "h3",
            "status": "unsupported",
            "unsupported_reason": "h3: browser did not leave the HTTP/3 bootstrap",
        }
        websocket = dict(door, unsupported_reason="ws: WebSocket over HTTP/3")
        h2 = {"expected_http_protocol": "h2", "status": "passed"}
        self.assertTrue(main.h3_never_reached([door, door, h2]))
        self.assertFalse(main.h3_never_reached([door, websocket, h2]))
        self.assertFalse(main.h3_never_reached([door, dict(door, status="failed")]))
        self.assertFalse(main.h3_never_reached([h2]))

    def test_receipt_command_fails_when_no_h3_cell_switched(self):
        caps = [
            dict(
                browserName="Safari",
                browserVersion="latest",
                os="OS X",
                osVersion="Sequoia",
                buildName="build",
                sessionName="fixture",
            )
        ]

        def journey(_driver, _origin, **_kwargs):
            raise main.UnsupportedFlow("h3: browser stayed on TCP: did not switch to HTTP/3")

        with tempfile.TemporaryDirectory() as directory, patch.dict(
            main.os.environ,
            {
                "BROWSERSTACK_USERNAME": "private-login",
                "BROWSERSTACK_ACCESS_KEY": "private-access-key",
                "RAMA_FP_STORAGE_COOKIE": "private-storage-cookie",
            },
        ), patch.object(main, "capabilities", return_value=caps), patch.object(
            main, "ENTRYPOINTS", [("https://h3.invalid/", "h3")]
        ), patch(
            "browser_automation.drivers.webdriver.Remote",
            side_effect=lambda **_kwargs: MagicMock(
                capabilities={"browserName": "safari", "browserVersion": "26.0"}
            ),
        ), patch.object(
            main, "run_capture_flow", side_effect=journey
        ):
            output = Path(directory) / "receipts"
            self.assertEqual(main.main(["--output", str(output)]), 1)

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
            self.assertEqual([row["attempts"] for row in receipts], [1, 2])
            self.assertEqual(output.stat().st_mode & 0o777, 0o700)
            with self.assertRaises(FileExistsError):
                main.main(["--output", str(output)])
        # One session for the passing cell, two for the retried failing cell.
        self.assertEqual(len(drivers), 3)
        for driver in drivers:
            driver.quit.assert_called_once_with()

    def unsupported_receipt(self, error, *, driver=None):
        driver = driver or MagicMock()
        with tempfile.TemporaryDirectory() as directory, patch(
            "browser_automation.drivers.webdriver.Remote", return_value=driver
        ), patch.object(
            main, "ENTRYPOINTS", [("https://h3.invalid/", "h3")]
        ), patch.object(
            main, "run_capture_flow", side_effect=error
        ), patch(
            "sys.stdout", new_callable=io.StringIO
        ):
            failures = main.run_session(
                dict(browserName="Firefox", sessionName="fixture"),
                output=Path(directory),
                capability_index=0,
                endpoint="https://provider.invalid/",
                username="private-login",
                access_key="private-access-key",
                storage_cookie="private-storage-cookie",
            )
            self.assertEqual(failures, [])
            return json.loads((Path(directory) / "000-0.json").read_text())

    def test_unsupported_websocket_keeps_the_completed_http3_flows(self):
        completed = dict.fromkeys(("navigate", "fetch", "xhr", "form", "form_get"), "h3")
        receipt = self.unsupported_receipt(
            main.UnsupportedFlow("ws: WebSocket over HTTP/3", protocols=completed)
        )
        self.assertEqual(receipt["status"], "unsupported")
        self.assertEqual(receipt["completed_protocols"], completed)
        self.assertNotIn("h3_control", receipt)

    def test_bootstrap_door_records_the_public_http3_control(self):
        driver = MagicMock()
        transports = iter(["h2", "h3"])
        driver.execute_script.side_effect = lambda script: (
            next(transports) if "nextHopProtocol" in script else None
        )
        receipt = self.unsupported_receipt(
            main.UnsupportedFlow("h3: browser stayed on TCP"), driver=driver
        )
        self.assertEqual(receipt["status"], "unsupported")
        self.assertEqual(receipt["h3_control"], "h3")
        self.assertNotIn("completed_protocols", receipt)
        driver.get.assert_called_with(main.H3_CONTROL_ORIGIN)

    def test_control_probe_failure_never_fails_the_cell(self):
        driver = MagicMock()
        driver.get.side_effect = RuntimeError("provider network")
        receipt = self.unsupported_receipt(
            main.UnsupportedFlow("h3: browser stayed on TCP"), driver=driver
        )
        self.assertEqual(receipt["status"], "unsupported")
        self.assertEqual(receipt["h3_control"], "unavailable")

    def test_partial_protocol_receipts_reject_websocket_and_unknown_values(self):
        with self.assertRaises(ValueError):
            main.checked_partial_protocols({"ws": "h3"})
        with self.assertRaises(ValueError):
            main.checked_partial_protocols({"navigate": "quic"})
        with self.assertRaises(ValueError):
            main.checked_partial_protocols({})


if __name__ == "__main__":
    unittest.main()
