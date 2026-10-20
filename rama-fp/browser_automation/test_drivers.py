"""Session isolation and cleanup regressions without launching browsers."""

import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch, MagicMock

from browser_automation.drivers import browser_options, local_session, remote_session


class SessionTests(unittest.TestCase):
    def setUp(self):
        # Service construction reserves a port even with a mocked driver. No
        # process is started here, so avoid touching host network interfaces.
        port = patch("selenium.webdriver.common.utils.free_port", return_value=4444)
        port.start()
        self.addCleanup(port.stop)

    def test_protocol_expectations_do_not_enable_experimental_browser_features(self):
        for protocol in (None, "h1", "h2", "h3"):
            for browser in ("chrome", "edge"):
                with self.subTest(browser=browser, protocol=protocol):
                    self.assertFalse(
                        any(
                            "EnableWebsocketsOverHttp3" in argument
                            for argument in browser_options(
                                browser, protocol=protocol
                            ).arguments
                        )
                    )
            with self.subTest(browser="firefox", protocol=protocol):
                self.assertNotIn(
                    "network.http.http3.enable",
                    browser_options("firefox", protocol=protocol).preferences,
                )
        with self.assertRaises(ValueError):
            browser_options("chrome", protocol="h4")

    def test_remote_options_preserve_default_protocol_preferences(self):
        options = browser_options("firefox", protocol="h3")
        with patch("browser_automation.drivers.webdriver.Remote") as start:
            with remote_session("https://grid.invalid/", options):
                pass
        applied = start.call_args.kwargs["options"]
        self.assertIs(applied, options)
        self.assertNotIn("network.http.http3.enable", applied.preferences)
        self.assertNotIn(
            "network.http.http3.alt-svc-mapping-for-testing", applied.preferences
        )
        start.return_value.quit.assert_called_once_with()

    def test_remote_session_quits_after_flow_failure(self):
        driver = MagicMock()
        with patch("browser_automation.drivers.webdriver.Remote", return_value=driver):
            with self.assertRaisesRegex(RuntimeError, "flow failed"):
                with remote_session("https://grid.invalid/", MagicMock()):
                    raise RuntimeError("flow failed")
        driver.quit.assert_called_once_with()

    def test_optional_transport_timeout_reaches_remote_constructor_and_quit(self):
        options = browser_options("firefox")
        for timeout in (None, 30):
            driver = MagicMock()
            with self.subTest(timeout=timeout), patch(
                "browser_automation.drivers.webdriver.Remote", return_value=driver
            ) as start:
                with remote_session(
                    "https://grid.invalid/", options, transport_timeout=timeout
                ):
                    pass
                arguments = start.call_args.kwargs
                self.assertIs(arguments["options"], options)
                self.assertEqual(arguments["command_executor"], "https://grid.invalid/")
                if timeout is None:
                    self.assertNotIn("client_config", arguments)
                else:
                    self.assertEqual(arguments["client_config"].timeout, timeout)
                    self.assertEqual(
                        arguments["client_config"].remote_server_addr,
                        "https://grid.invalid/",
                    )
                driver.quit.assert_called_once_with()
        driver = MagicMock()
        driver.quit.side_effect = TimeoutError("remote quit unconfirmed")
        with patch("browser_automation.drivers.webdriver.Remote", return_value=driver):
            with self.assertRaisesRegex(TimeoutError, "quit unconfirmed"):
                with remote_session(
                    "https://grid.invalid/", options, transport_timeout=30
                ):
                    pass
        driver.quit.assert_called_once_with()

    def test_invalid_transport_timeouts_fail_before_creating_a_session(self):
        for timeout in (True, 0, 61, 1.5, "30"):
            with self.subTest(timeout=timeout), patch(
                "browser_automation.drivers.webdriver.Remote"
            ) as start:
                with self.assertRaises(ValueError):
                    with remote_session(
                        "https://grid.invalid/", MagicMock(), transport_timeout=timeout
                    ):
                        pass
                start.assert_not_called()

    def test_each_local_driver_quits_and_cannot_inherit_keylog(self):
        for browser, constructor in [
            ("chrome", "Chrome"),
            ("edge", "Edge"),
            ("firefox", "Firefox"),
            ("safari", "Safari"),
        ]:
            with self.subTest(
                browser=browser
            ), tempfile.TemporaryDirectory() as directory:
                driver = MagicMock()
                with patch.dict(
                    os.environ, {"SSLKEYLOGFILE": "/unowned/keylog"}
                ), patch(
                    "browser_automation.drivers.webdriver." + constructor,
                    return_value=driver,
                ) as start:
                    with self.assertRaisesRegex(RuntimeError, "flow failed"):
                        with local_session(
                            browser, profile=Path(directory) / "profile"
                        ):
                            raise RuntimeError("flow failed")
                driver.quit.assert_called_once_with()
                arguments = start.call_args.kwargs
                self.assertNotIn("SSLKEYLOGFILE", arguments["service"].env)
                self.assertFalse(arguments["options"].accept_insecure_certs)

    def test_profile_preparation_precedes_browser_start(self):
        with tempfile.TemporaryDirectory() as directory:
            profile = Path(directory) / "profile"

            def prepare(path):
                (path / "fixture-ca-installed").touch()

            def start(**kwargs):
                self.assertTrue((profile / "fixture-ca-installed").exists())
                return MagicMock()

            with patch(
                "browser_automation.drivers.webdriver.Firefox", side_effect=start
            ):
                with local_session("firefox", profile=profile, prepare_profile=prepare):
                    pass

    def test_existing_profile_is_never_reused(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch("browser_automation.drivers.webdriver.Chrome") as start:
                with self.assertRaises(FileExistsError):
                    with local_session("chrome", profile=directory):
                        pass
                start.assert_not_called()

    def test_explicit_keylog_is_private_and_passed_to_browser(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            keylog = (root / "tls.keys").resolve()
            with patch("browser_automation.drivers.webdriver.Chrome") as start:
                with local_session("chrome", profile=root / "profile", keylog=keylog):
                    self.assertEqual(
                        start.call_args.kwargs["service"].env["SSLKEYLOGFILE"],
                        str(keylog),
                    )
                    self.assertIn(
                        "--ssl-key-log-file=" + str(keylog),
                        start.call_args.kwargs["options"].arguments,
                    )
                    if os.name != "nt":
                        self.assertEqual(keylog.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
