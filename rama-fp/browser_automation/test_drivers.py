"""Session isolation and cleanup regressions without launching browsers."""

import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch, MagicMock

from selenium.common.exceptions import SessionNotCreatedException, WebDriverException

from browser_automation.drivers import device_session, local_session


class SessionTests(unittest.TestCase):
    def setUp(self):
        # Service construction reserves a port even with a mocked driver. No
        # process is started here, so avoid touching host network interfaces.
        port = patch("selenium.webdriver.common.utils.free_port", return_value=4444)
        port.start()
        self.addCleanup(port.stop)


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

    def test_android_firefox_never_gets_a_desktop_binary(self):
        paths = {"driver_path": "/drivers/geckodriver", "browser_path": "/usr/bin/firefox"}
        with patch(
            "browser_automation.drivers.SeleniumManager.binary_paths", return_value=paths
        ) as manager, patch("browser_automation.drivers.webdriver.Firefox") as start:
            with device_session("firefox-android"):
                pass
        self.assertEqual(manager.call_args.args[0], ["--driver", "geckodriver"])
        # A preset driver path keeps Selenium from adding the browser it finds.
        self.assertEqual(start.call_args.kwargs["service"].path, "/drivers/geckodriver")
        firefox = start.call_args.kwargs["options"].to_capabilities()["moz:firefoxOptions"]
        self.assertEqual(firefox["androidPackage"], "org.mozilla.firefox")
        self.assertNotIn("binary", firefox)
        self.assertEqual(
            firefox["androidIntentArguments"][-3:], ["--ez", "performancetest", "true"]
        )
        start.return_value.quit.assert_called_once()

    def test_simulator_safari_gets_time_to_launch(self):
        slow = SessionNotCreatedException("timed out while connecting to a Safari instance")
        exited = WebDriverException("Service /usr/bin/safaridriver unexpectedly exited")
        driver = MagicMock()
        with patch("browser_automation.drivers.time.sleep") as sleep, patch(
            "browser_automation.drivers.webdriver.Safari", side_effect=[slow, exited, driver]
        ) as start:
            with device_session("ios-simulator", "26.5") as session:
                self.assertIs(session, driver)
        self.assertEqual(start.call_count, 3)
        self.assertEqual(sleep.call_count, 2)
        driver.quit.assert_called_once()
        # Only the simulator showed slow Safari launches; desktop errors stay failures.
        with patch(
            "browser_automation.drivers.webdriver.Safari", side_effect=slow
        ) as start, self.assertRaises(SessionNotCreatedException):
            with device_session("safari"):
                pass
        self.assertEqual(start.call_count, 1)


if __name__ == "__main__":
    unittest.main()
