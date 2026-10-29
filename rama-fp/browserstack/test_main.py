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

    def revisited_receipt(self, journey, *, driver=None):
        driver = driver or MagicMock()
        origin = "https://h3.invalid/"
        with tempfile.TemporaryDirectory() as directory, patch(
            "browser_automation.drivers.webdriver.Remote", return_value=driver
        ) as remote, patch.object(
            main, "ENTRYPOINTS", [(origin, "h3")]
        ), patch.object(
            main, "REVISITED", frozenset((origin,))
        ), patch.object(
            main, "run_capture_flow", side_effect=journey
        ) as flow, patch(
            "sys.stdout", new_callable=io.StringIO
        ):
            main.run_session(
                dict(browserName="Safari", sessionName="fixture"),
                output=Path(directory),
                capability_index=0,
                endpoint="https://provider.invalid/",
                username="private-login",
                access_key="private-access-key",
                storage_cookie="private-storage-cookie",
            )
            receipt = json.loads((Path(directory) / "000-0.json").read_text())
        return receipt, remote, flow

    def test_a_revisit_in_the_same_session_can_still_switch_to_http3(self):
        completed = dict.fromkeys(
            ("navigate", "fetch", "xhr", "ws", "form", "form_get"), "h3"
        )
        outcomes = iter(
            [
                main.UnsupportedFlow("h3: browser stayed on TCP"),
                SimpleNamespace(protocols=completed),
            ]
        )

        def journey(_driver, _origin, **_kwargs):
            outcome = next(outcomes)
            if isinstance(outcome, Exception):
                raise outcome
            return outcome

        receipt, remote, flow = self.revisited_receipt(journey)
        self.assertEqual(receipt["status"], "passed")
        self.assertEqual(receipt["protocols"], completed)
        self.assertEqual(
            receipt["visits"],
            [
                {
                    "status": "unsupported",
                    "unsupported_reason": "h3: browser stayed on TCP",
                },
                {"status": "passed", "protocols": completed},
            ],
        )
        self.assertIsNone(receipt["unsupported_reason"])
        self.assertNotIn("h3_control", receipt)
        self.assertEqual(remote.call_count, 1)
        # Only the first visit installs the collection cookies.
        cookies = [call.kwargs["cookies"] for call in flow.call_args_list]
        self.assertIsNotNone(cookies[0])
        self.assertIsNone(cookies[1])

    def test_two_visits_on_tcp_stay_unsupported_with_the_control(self):
        driver = MagicMock()
        driver.execute_script.side_effect = lambda script: (
            "h3" if "nextHopProtocol" in script else None
        )
        receipt, remote, flow = self.revisited_receipt(
            main.UnsupportedFlow("h3: browser stayed on TCP"), driver=driver
        )
        self.assertEqual(receipt["status"], "unsupported")
        self.assertEqual(receipt["h3_control"], "h3")
        self.assertEqual(
            [visit["status"] for visit in receipt["visits"]], ["unsupported"] * 2
        )
        self.assertEqual((remote.call_count, flow.call_count), (1, 2))

    def test_device_h3_cell_that_stayed_on_tcp_gets_a_fresh_session(self):
        completed = dict.fromkeys(
            ("navigate", "fetch", "xhr", "ws", "form", "form_get"), "h3"
        )
        outcomes = iter([main.UnsupportedFlow("h3: browser stayed on TCP"), completed])

        def journey(_driver, _origin, **_kwargs):
            outcome = next(outcomes)
            if isinstance(outcome, Exception):
                raise outcome
            return SimpleNamespace(protocols=outcome)

        driver = MagicMock(capabilities={"browserName": "Safari"})
        with tempfile.TemporaryDirectory() as directory, patch(
            "browser_automation.drivers.webdriver.Safari", return_value=driver
        ) as safari, patch.object(
            main, "ENTRYPOINTS", [("https://h3.invalid/", "h3")]
        ), patch.object(
            main, "run_capture_flow", side_effect=journey
        ), patch(
            "sys.stdout", new_callable=io.StringIO
        ):
            failures = main.run_session(
                dict(browserName="Safari", sessionName="fixture"),
                output=Path(directory),
                capability_index=0,
                endpoint=None,
                username=None,
                access_key=None,
                storage_cookie="private-storage-cookie",
                device=("safari", None),
            )
            receipt = json.loads((Path(directory) / "000-0.json").read_text())
        self.assertEqual(failures, [])
        self.assertEqual((receipt["status"], receipt["attempts"]), ("passed", 2))
        self.assertEqual(receipt["first_failure_reason"], "h3: browser stayed on TCP")
        self.assertEqual(safari.call_count, 2)

    def test_a_failed_revisit_fails_the_attempt(self):
        completed = dict.fromkeys(
            ("navigate", "fetch", "xhr", "ws", "form", "form_get"), "h3"
        )
        outcomes = iter([completed, None, completed, None])

        def journey(_driver, _origin, **_kwargs):
            protocols = next(outcomes)
            if protocols is None:
                raise RuntimeError("second connection broke")
            return SimpleNamespace(protocols=protocols)

        receipt, remote, flow = self.revisited_receipt(journey)
        self.assertEqual(receipt["status"], "failed")
        self.assertEqual(receipt["failure_stage"], "revisit")
        self.assertEqual(receipt["attempts"], 2)
        self.assertEqual((remote.call_count, flow.call_count), (2, 4))

    def test_chromium_switches_follow_the_device_and_origin(self):
        arguments = {}

        def remote(**kwargs):
            options = kwargs["options"]
            name = options.to_capabilities()["bstack:options"]["sessionName"]
            arguments.setdefault(name, []).append(list(options.arguments))
            return MagicMock()

        completed = dict.fromkeys(
            ("navigate", "fetch", "xhr", "ws", "form", "form_get"), "h1"
        )
        plain = "--disable-features=HttpsUpgrades,UseDnsHttpsSvcb"
        with tempfile.TemporaryDirectory() as directory, patch(
            "browser_automation.drivers.webdriver.Remote", side_effect=remote
        ), patch.object(
            main,
            "ENTRYPOINTS",
            [("http://h1.invalid/", "h1"), ("https://h1.invalid/", "h1")],
        ), patch.object(
            main, "run_capture_flow", return_value=SimpleNamespace(protocols=completed)
        ), patch(
            "sys.stdout", new_callable=io.StringIO
        ):
            for index, capability in enumerate(
                (
                    dict(browserName="chrome", deviceName="Pixel", sessionName="android"),
                    dict(browserName="Edge", os="Windows", sessionName="desktop"),
                    dict(browserName="firefox", deviceName="Pixel", sessionName="fx"),
                )
            ):
                main.run_session(
                    capability,
                    output=Path(directory),
                    capability_index=index,
                    endpoint="https://provider.invalid/",
                    username="private-login",
                    access_key="private-access-key",
                    storage_cookie="private-storage-cookie",
                )
        self.assertEqual(
            arguments,
            {
                "android h1": [["--no-proxy-server", plain], ["--no-proxy-server"]],
                "desktop h1": [[plain], []],
                "fx h1": [[], []],
            },
        )

    @staticmethod
    def echo_report(*, matched=True, profile=True):
        reference = {"hash": "t13d2013h2_ref", "matched": matched} if profile else None
        return {
            "http": {"version": "HTTP/2.0", "ja4h": {"hash": "ge20cn09enus_x"}},
            "tls": {"ja4": {"hash": "t13d2013h2_obs", "profile": reference}},
        }

    def device_run(self, device, environment, echo=None):
        completed = dict.fromkeys(
            ("navigate", "fetch", "xhr", "ws", "form", "form_get"), "h2"
        )
        driver = MagicMock(capabilities={"browserName": "Safari"})
        driver.execute_async_script.return_value = echo or self.echo_report()
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            main.os.environ, environment, clear=True
        ), patch.object(
            main, "ENTRYPOINTS", [("https://h2.invalid/", "h2")]
        ), patch(
            "browser_automation.drivers.webdriver.Safari", return_value=driver
        ) as safari, patch(
            "browser_automation.drivers.webdriver.Firefox", return_value=driver
        ) as firefox, patch(
            "browser_automation.drivers.webdriver.Remote"
        ) as remote, patch.object(
            main, "run_capture_flow", return_value=SimpleNamespace(protocols=completed)
        ) as flow, patch(
            "sys.stdout", new_callable=io.StringIO
        ):
            output = Path(directory) / "receipts"
            code = main.main(["--output", str(output), "--device", device])
            receipt = json.loads((output / "000-0.json").read_text())
            self.echo = json.loads((output / "echo.json").read_text())
        launched = safari if safari.called else firefox
        return code, receipt, launched, remote, flow, driver

    def test_device_runs_fail_on_a_tls_fingerprint_that_differs_from_the_profile(self):
        environment = {"RAMA_FP_STORAGE_COOKIE": "private-storage-cookie"}
        code, *_ = self.device_run("ios-simulator", environment)
        self.assertEqual(code, 0)
        self.assertEqual(
            self.echo["ja4"],
            {"observed": "t13d2013h2_obs", "reference": "t13d2013h2_ref", "matched": True},
        )
        # JA4H is recorded, never judged: its Accept-Language follows the device locale.
        self.assertEqual(self.echo["ja4h"]["observed"], "ge20cn09enus_x")
        code, *_ = self.device_run(
            "ios-simulator", environment, echo=self.echo_report(matched=False)
        )
        self.assertEqual((code, self.echo["status"]), (1, "failed"))
        # A User-Agent without an embedded profile has nothing to match yet.
        code, *_ = self.device_run(
            "ios-simulator", environment, echo=self.echo_report(profile=False)
        )
        self.assertEqual((code, self.echo["status"]), (0, "passed"))
        self.assertIsNone(self.echo["ja4"]["matched"])

    def test_simulator_captures_are_stored_like_any_other(self):
        code, receipt, safari, remote, flow, driver = self.device_run(
            "ios-simulator:26.0", {"RAMA_FP_STORAGE_COOKIE": "private-storage-cookie"}
        )
        self.assertEqual(code, 0)
        self.assertEqual(receipt["status"], "passed")
        self.assertEqual(receipt["requested"]["deviceName"], "iOS Simulator")
        self.assertEqual(receipt["requested"]["osVersion"], "26.0")
        remote.assert_not_called()
        options = safari.call_args.kwargs["options"].to_capabilities()
        self.assertEqual(options["platformName"], "iOS")
        self.assertEqual(options["safari:platformVersion"], "26.0")
        self.assertEqual(
            flow.call_args.kwargs["cookies"]["rama-storage-auth"],
            "private-storage-cookie",
        )
        # No BrowserStack status call reaches a local browser.
        driver.execute_script.assert_not_called()

    def test_emulator_version_names_the_firefox_release(self):
        code, receipt, firefox, remote, _flow, _driver = self.device_run(
            "firefox-android:151.0", {"RAMA_FP_STORAGE_COOKIE": "private-storage-cookie"}
        )
        self.assertEqual(code, 0)
        self.assertEqual(receipt["requested"]["browserVersion"], "151.0")
        self.assertIsNone(receipt["requested"]["osVersion"])
        remote.assert_not_called()
        options = firefox.call_args.kwargs["options"].to_capabilities()
        self.assertEqual(
            options["moz:firefoxOptions"]["androidPackage"], "org.mozilla.firefox"
        )
        self.assertFalse(options["acceptInsecureCerts"])

    def test_every_device_requires_and_sends_the_storage_cookie(self):
        for device in main.DEVICES:
            with self.subTest(device=device):
                with patch("sys.stderr", new_callable=io.StringIO), self.assertRaises(
                    ValueError
                ):
                    self.device_run(device, {})
                code, _receipt, _launched, _remote, flow, _driver = self.device_run(
                    device, {"RAMA_FP_STORAGE_COOKIE": "private-storage-cookie"}
                )
                self.assertEqual(code, 0)
                self.assertEqual(
                    flow.call_args.kwargs["cookies"]["rama-storage-auth"],
                    "private-storage-cookie",
                )

    def test_device_runs_record_the_driver_message_without_secrets(self):
        error = main.WebDriverException("Could not create a session: private-storage-cookie")
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            main.os.environ, {"RAMA_FP_STORAGE_COOKIE": "private-storage-cookie"}, clear=True
        ), patch.object(main, "ENTRYPOINTS", [("https://h2.invalid/", "h2")]), patch(
            "browser_automation.drivers.webdriver.Safari", side_effect=error
        ), patch("sys.stdout", new_callable=io.StringIO):
            output = Path(directory) / "receipts"
            self.assertEqual(main.main(["--output", str(output), "--device", "safari"]), 1)
            receipt = json.loads((output / "000-0.json").read_text())
            echo = json.loads((output / "echo.json").read_text())
        reason = "WebDriverException: Could not create a session: <redacted>"
        self.assertEqual(
            (receipt["failure_stage"], receipt["failure_reason"]), ("session_start", reason)
        )
        self.assertEqual(echo["failure_reason"], reason)
        # A provider's driver messages can echo its session, so only their type is kept.
        self.assertEqual(main.failure_reason(error, secrets=()), "WebDriverException")

    def test_unknown_device_is_rejected(self):
        with patch("sys.stderr", new_callable=io.StringIO), self.assertRaises(
            SystemExit
        ):
            main.main(["--output", "/nonexistent", "--device", "netscape"])

    def test_other_origins_are_visited_once(self):
        receipt = self.unsupported_receipt(
            main.UnsupportedFlow("h3: browser stayed on TCP")
        )
        self.assertNotIn("visits", receipt)

    def test_partial_protocol_receipts_reject_websocket_and_unknown_values(self):
        with self.assertRaises(ValueError):
            main.checked_partial_protocols({"ws": "h3"})
        with self.assertRaises(ValueError):
            main.checked_partial_protocols({"navigate": "quic"})
        with self.assertRaises(ValueError):
            main.checked_partial_protocols({})


if __name__ == "__main__":
    unittest.main()
