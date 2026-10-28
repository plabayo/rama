"""Selenium session ownership for local tests and remote capture jobs.

Executable discovery is delegated to Selenium Manager. Explicit browser paths
remain available for pinned CI installations; no operating-system app path is
baked into the workflow. Local TLS secrets stay in the caller's private evidence
staging directory and must be deleted/sanitized after packet decoding.
"""

from contextlib import contextmanager
from pathlib import Path
import os
import time

from selenium import webdriver
from selenium.common.exceptions import NoSuchDriverException, WebDriverException
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.common.selenium_manager import SeleniumManager
from selenium.webdriver.edge.service import Service as EdgeService
from selenium.webdriver.firefox.service import Service as FirefoxService
from selenium.webdriver.safari.service import Service as SafariService

OPTION_TYPES = {
    "chrome": webdriver.ChromeOptions,
    "edge": webdriver.EdgeOptions,
    "firefox": webdriver.FirefoxOptions,
    "safari": webdriver.SafariOptions,
}


def launch(factory, attempts=3, delay=2.0, transient=(NoSuchDriverException,)):
    """Start a driver; Selenium Manager fetches it over the network and
    occasionally fails transiently (seen in CI)."""
    for attempt in range(attempts):
        try:
            return factory()
        except transient:
            if attempt + 1 == attempts:
                raise
            time.sleep(delay)


def browser_options(browser):
    """Use the installed browser's default protocol capabilities.

    The requested protocol is verified against observed traffic. It does not
    enable experimental WebSockets or alter Firefox's HTTP/3 preferences.
    """
    browser = browser.lower()
    try:
        options = OPTION_TYPES[browser]()
    except KeyError as error:
        raise ValueError("unsupported browser: " + browser) from error
    return options


@contextmanager
def remote_session(endpoint, options):
    """BrowserStack/Grid owns the remote process; always release the session."""
    driver = webdriver.Remote(command_executor=endpoint, options=options)
    try:
        yield driver
    finally:
        driver.quit()


def device_options(kind, platform_version=None):
    """Default options for a browser this host drives without a host profile.

    `safari` is desktop Safari, `ios-simulator` Safari on a booted iOS Simulator
    (Apple's safaridriver, optionally pinned to an iOS version) and
    `firefox-android` Firefox for Android on the one connected adb device.
    """
    if kind == "safari":
        return webdriver.SafariOptions()
    if kind == "ios-simulator":
        options = webdriver.SafariOptions()
        options.set_capability("platformName", "iOS")
        options.set_capability("safari:useSimulator", True)
        options.set_capability("safari:deviceType", "iPhone")
        if platform_version:
            options.set_capability("safari:platformVersion", platform_version)
        return options
    if kind == "firefox-android":
        options = webdriver.FirefoxOptions()
        options.enable_mobile(android_package="org.mozilla.firefox")
        # Firefox 157+ opens on a first-run Terms of Use screen that hides the page (a 0x0
        # viewport); Mozilla's performance harness skips onboarding with this extra. The
        # arguments replace geckodriver's default intent, so that is repeated first.
        options.mobile_options["androidIntentArguments"] = [
            *("-a", "android.intent.action.VIEW", "-d", "about:blank"),
            *("--ez", "performancetest", "true"),
        ]
        options.accept_insecure_certs = False
        return options
    raise ValueError("unsupported device browser: " + kind)


def android_firefox(options):
    """geckodriver rejects a desktop `binary` next to `androidPackage`, which Selenium
    Manager adds when the host also has desktop Firefox, so resolve only the driver."""
    try:
        path = SeleniumManager().binary_paths(["--driver", "geckodriver"])["driver_path"]
    except WebDriverException as error:
        raise NoSuchDriverException("Unable to obtain geckodriver") from error
    return webdriver.Firefox(options=options, service=FirefoxService(executable_path=path))


@contextmanager
def device_session(kind, platform_version=None):
    """Start a `device_options` browser and always release it."""
    options = device_options(kind, platform_version)
    if kind == "ios-simulator":
        # On a slow runner safaridriver can exit at startup or outlast its wait for the
        # simulator's Safari to launch.
        driver = launch(
            lambda: webdriver.Safari(options=options),
            delay=10.0,
            transient=(WebDriverException,),
        )
    elif isinstance(options, webdriver.SafariOptions):
        driver = webdriver.Safari(options=options)
    else:
        driver = launch(lambda: android_firefox(options))
    try:
        yield driver
    finally:
        driver.quit()


@contextmanager
def local_session(
    browser, *, profile, binary=None, keylog=None, options=None, prepare_profile=None,
    safari_accept_insecure_certs=False
):
    """Start a local browser using a fresh, caller-owned profile.

    The caller can add protocol preferences through options and install a fixture
    CA with prepare_profile(path), called before the browser starts.
    Certificate checks stay enabled by default. Chrome/Edge can receive the
    fixture certificate's explicit SPKI exception through their options. Safari
    fixtures can explicitly opt into session-scoped insecure certificate acceptance.
    """
    browser = browser.lower()
    if browser not in OPTION_TYPES:
        raise ValueError("unsupported browser: " + browser)
    if browser == "safari" and (binary or keylog or prepare_profile):
        raise ValueError(
            "Safari uses isolated Automation windows; use server TLS key logging"
        )

    # Give each run fresh storage and apply any fixture CA before launch.
    options = options if options is not None else browser_options(browser)
    if safari_accept_insecure_certs and browser != "safari":
        raise ValueError("the fixture certificate exception is Safari-only")
    options.accept_insecure_certs = safari_accept_insecure_certs
    profile = Path(profile).resolve()
    profile.mkdir(parents=True, exist_ok=False)
    if prepare_profile is not None:
        prepare_profile(profile)

    # Never inherit another run's TLS secret log.
    environment = dict(os.environ)
    environment.pop("SSLKEYLOGFILE", None)
    if keylog is not None:
        keylog = Path(keylog).resolve()
        keylog.touch(mode=0o600, exist_ok=False)
        environment["SSLKEYLOGFILE"] = str(keylog)
    if binary is not None:
        options.binary_location = str(Path(binary).resolve(strict=True))

    # Driver-specific launch options; the caller still uses one shared journey.
    if browser in ("chrome", "edge"):
        options.add_argument("--headless=new")
        options.add_argument("--user-data-dir=" + str(profile))
        options.add_argument("--disable-background-networking")
        options.add_argument("--disable-component-update")
        options.add_argument("--no-first-run")
        if keylog is not None:
            options.add_argument("--ssl-key-log-file=" + str(keylog))
        constructor = webdriver.Chrome if browser == "chrome" else webdriver.Edge
        service_type = ChromeService if browser == "chrome" else EdgeService
        driver = launch(
            lambda: constructor(options=options, service=service_type(env=environment))
        )
    elif browser == "firefox":
        options.add_argument("--headless")
        options.add_argument("-profile")
        options.add_argument(str(profile))
        options.set_preference("remote.prefs.recommended", False)
        options.set_preference("browser.aboutwelcome.enabled", False)
        driver = launch(
            lambda: webdriver.Firefox(
                options=options, service=FirefoxService(env=environment)
            )
        )
    else:
        # SafariDriver isolates Automation windows and storage itself. TLS secrets
        # come from the local fp server, since Safari exposes no key-log option.
        driver = webdriver.Safari(
            options=options, service=SafariService(env=environment)
        )
    try:
        yield driver
    finally:
        driver.quit()
