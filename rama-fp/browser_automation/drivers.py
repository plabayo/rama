"""Selenium session ownership for local tests and remote capture jobs.

Executable discovery is delegated to Selenium Manager. Explicit browser paths
remain available for pinned CI installations; no operating-system app path is
baked into the workflow. Local TLS secrets stay in the caller's private evidence
staging directory and must be deleted/sanitized after packet decoding.
"""

from contextlib import contextmanager
from pathlib import Path
import os

from selenium import webdriver
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.edge.service import Service as EdgeService
from selenium.webdriver.firefox.service import Service as FirefoxService
from selenium.webdriver.safari.service import Service as SafariService

OPTION_TYPES = {
    "chrome": webdriver.ChromeOptions,
    "edge": webdriver.EdgeOptions,
    "firefox": webdriver.FirefoxOptions,
    "safari": webdriver.SafariOptions,
}


def browser_options(browser, *, protocol=None):
    """Common local/remote options, including explicit H3 WebSocket coverage.

    Chromium gates RFC 9220 behind this feature. Record configured H3 runs as
    such; this is not evidence for an unchanged default browser installation.
    """
    if protocol not in (None, "h1", "h2", "h3"):
        raise ValueError("unsupported protocol: " + str(protocol))
    browser = browser.lower()
    try:
        options = OPTION_TYPES[browser]()
    except KeyError as error:
        raise ValueError("unsupported browser: " + browser) from error
    if browser == "firefox" and protocol in ("h2", "h3"):
        options.set_preference("network.http.http3.enable", protocol == "h3")
    if protocol == "h3" and browser in ("chrome", "edge"):
        options.add_argument("--enable-features=EnableWebsocketsOverHttp3")
    return options


@contextmanager
def remote_session(endpoint, options):
    """BrowserStack/Grid owns the remote process; always release the session."""
    driver = webdriver.Remote(command_executor=endpoint, options=options)
    try:
        yield driver
    finally:
        driver.quit()


@contextmanager
def local_session(
    browser, *, profile, binary=None, keylog=None, options=None, prepare_profile=None
):
    """Start a local browser using a fresh, caller-owned profile.

    The caller can add protocol preferences through options and install a fixture
    CA with prepare_profile(path), called before the browser starts.
    Certificate checks stay enabled. Chrome/Edge can additionally receive the
    fixture certificate's explicit SPKI exception through their options.
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
    options.accept_insecure_certs = False
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
        driver = constructor(options=options, service=service_type(env=environment))
    elif browser == "firefox":
        options.add_argument("--headless")
        options.add_argument("-profile")
        options.add_argument(str(profile))
        options.set_preference("remote.prefs.recommended", False)
        options.set_preference("browser.aboutwelcome.enabled", False)
        driver = webdriver.Firefox(
            options=options, service=FirefoxService(env=environment)
        )
    elif browser == "safari":
        # SafariDriver isolates Automation windows and storage itself. TLS secrets
        # come from the local fp server, since Safari exposes no key-log option.
        driver = webdriver.Safari(
            options=options, service=SafariService(env=environment)
        )
    else:
        raise ValueError("unsupported browser: " + browser)
    try:
        yield driver
    finally:
        driver.quit()
