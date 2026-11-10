"""Drive the existing fp page and require each requested flow to finish.

No HTTP requests are synthesized here: navigation, fetch, XHR, WebSocket and form
submission are performed by the browser and fp's own page script. The same code
accepts a local Selenium driver or BrowserStack's Remote WebDriver.
"""

import json
import math
import re
import time

from dataclasses import dataclass
from functools import partial
from typing import Mapping, Optional
from urllib.parse import parse_qs, urlencode, urljoin, urlsplit

from selenium.common.exceptions import (
    NoSuchWindowException,
    StaleElementReferenceException,
    TimeoutException,
    WebDriverException,
)
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support import expected_conditions as conditions
from selenium.webdriver.support.ui import WebDriverWait


def submit_form(driver, form_selector, timeout=30):
    """Wait for a fresh submit button while the page replaces its form DOM.

    Safari can report a detached element or window for the keypress that navigated; an
    unmarked document then means the form was submitted, not that its button is missing.
    """
    try:
        activate_by_keyboard(
            driver, form_selector + ' button[type="submit"]', timeout=timeout
        )
    except TimeoutException as error:
        # Keep our own bounded diagnostic; provider messages may contain secrets.
        raise ValueError("form submit button unavailable: " + form_selector) from error


def follow_link(driver, link_selector, timeout=30):
    """Follow a link by keyboard, so its navigation carries user activation."""
    try:
        activate_by_keyboard(driver, link_selector, timeout=timeout)
    except TimeoutException as error:
        raise ValueError("link unavailable: " + link_selector) from error


def activate_by_keyboard(driver, selector, timeout=30):
    """Press Enter on an element until its document is replaced by a navigation."""
    marked = False

    def activate(browser):
        nonlocal marked
        if not marked:
            browser.execute_script("window.ramaFpFormPage = true")
            marked = True
        elif browser.execute_script("return window.ramaFpFormPage !== true") is True:
            return True
        browser.find_element(By.CSS_SELECTOR, selector).send_keys(Keys.ENTER)
        return True

    WebDriverWait(
        driver, timeout,
        ignored_exceptions=(StaleElementReferenceException, NoSuchWindowException),
    ).until(activate)


def navigated_to(accept):
    """A wait condition for a loaded document at a URL that `accept` admits.

    Safari reports a navigation's URL before its document replaces the current one,
    so the loaded document must itself be at that URL.
    """

    def complete(browser):
        url = browser.current_url
        return accept(urlsplit(url)) and browser.execute_script(
            "return document.readyState === 'complete' && document.URL === arguments[0]",
            url,
        ) is True

    return complete


class JourneyTimeout(TimeoutException):
    """A journey wait that ran out, with a message built here rather than by a driver."""


def activated_again(condition, activate, after):
    """`condition`, activating the shown document once more if it outlives `after` seconds.

    A navigation whose request stalled leaves the document that started it in place.
    """
    deadline = time.monotonic() + after
    pending = True

    def check(browser):
        nonlocal pending
        if condition(browser):
            return True
        if pending and time.monotonic() >= deadline and browser.execute_script(
            "return window.ramaFpFormPage === true"
        ) is True:
            pending = False
            print("RETRY navigation: its document was not replaced", flush=True)
            activate()
        return False

    return check


def await_navigation(driver, wait, condition, message):
    """`wait.until(condition)`; a timeout names the document the browser shows instead."""
    try:
        wait.until(condition, message)
    except TimeoutException as error:
        try:
            url = urlsplit(driver.current_url)
            shown, state = driver.execute_script(
                "return [document.URL, document.readyState]"
            )
            shown = urlsplit(shown)
            # Host and path only: a query can carry a site token.
            where = f"{url.hostname}{url.path} ({state})"
            if shown[:3] != url[:3]:
                # The reported URL is then a navigation that never replaced the document.
                where = (
                    f"{shown.scheme}://{shown.hostname}{shown.path} ({state}), "
                    f"bound for {url.scheme}://{url.hostname}{url.path}"
                )
        except (WebDriverException, TypeError, ValueError):
            where = "an unreadable document"
        raise JourneyTimeout(f"{message}; at {where}") from error


get_form_navigation_complete = navigated_to(
    lambda url: url.path == "/form"
    and parse_qs(url.query) == {"source": ["web"], "turtles": ["yes"]}
)


@dataclass(frozen=True)
class FlowResult:
    """Browser identity and flow evidence; packet verification remains independent."""

    user_agent: str
    browser_name: str
    browser_version: str
    protocols: Mapping[str, str]
    report_html: str
    form_html: Optional[str]
    get_form_html: Optional[str] = None
    page_results: Optional[Mapping] = None
    report_url: Optional[str] = None
    # Per site kind, the transport of each flow sent to that host of the service.
    site_protocols: Optional[Mapping[str, Mapping[str, str]]] = None

    @property
    def websocket_probe(self):
        if self.page_results is None:
            raise ValueError("page results unavailable for navigation-only capture")
        return self.page_results["websocket"]["probe"]


PROTOCOLS = {
    "http/1.1": "h1",
    "HTTP/1.1": "h1",
    "h2": "h2",
    "HTTP/2": "h2",
    "HTTP/2.0": "h2",
    "h3": "h3",
    "HTTP/3": "h3",
    "HTTP/3.0": "h3",
}
PAGE_FLOW_NAMES = {
    "Navigation": "navigate",
    "Fetch": "fetch",
    "XMLHttpRequest": "xhr",
    "WebSocket": "ws",
}


class UnsupportedFlow(ValueError):
    """A flow the browser cannot perform on this origin; every other flow passed.

    ``protocols`` holds the transports of the flows that did complete, if any.
    """

    def __init__(self, reason, protocols=None):
        super().__init__(reason)
        self.protocols = protocols
        self.site_protocols = None


_SAFARI_VERSION = re.compile(r"Version/(\d+)(?:\.(\d+))?")
_CHROME_VERSION = re.compile(r"Chrome/(\d+)")
_NON_SAFARI_WEBKIT = re.compile(r"Chrome|CriOS|FxiOS|EdgiOS|Edg")


def _safari_version(user_agent):
    """Safari's (major, minor) version from the UA (iOS has no browserVersion), else None."""
    if not isinstance(user_agent, str):
        return None
    if "Safari/" not in user_agent or _NON_SAFARI_WEBKIT.search(user_agent):
        return None
    version = _SAFARI_VERSION.search(user_agent)
    return None if version is None else (int(version.group(1)), int(version.group(2) or 0))


_RELEASE = re.compile(r"(\d+)(?:\.(\d+))?")


def _safari_network_version(user_agent, platform_version):
    """Safari's WebSocket transports come from the OS network stack: the session's OS
    release where known (desktop Safari's UA freezes macOS at 10_15_7), else Safari's."""
    safari = _safari_version(user_agent)
    if safari is None or not isinstance(platform_version, str):
        return safari
    release = _RELEASE.match(platform_version)
    return safari if release is None else (int(release.group(1)), int(release.group(2) or 0))


def _chrome_major(user_agent):
    """Chrome's (or a Chromium-based browser's) major version from the UA, else None."""
    if not isinstance(user_agent, str):
        return None
    version = _CHROME_VERSION.search(user_agent)
    return None if version is None else int(version.group(1))


def websocket_over_h2_unsupported(user_agent, expected_protocol, platform_version=None):
    """Safari before OS 26, or Chrome 114 and older, on an H2-only origin."""
    if expected_protocol != "h2":
        return False
    safari = _safari_network_version(user_agent, platform_version)
    # The OS 26 network stack added WebSocket over HTTP/2 (RFC 8441); Safari 26 on
    # macOS 15 opens WebSockets with an HTTP/1 Upgrade.
    if safari is not None:
        return safari < (26, 0)
    chrome = _chrome_major(user_agent)
    # Observed: Chrome 114 opens WebSockets with an HTTP/1 Upgrade; current Chrome uses h2.
    return chrome is not None and chrome <= 114


def websocket_over_h3_unsupported(user_agent, expected_protocol, platform_version=None):
    """Any browser but Safari on OS 26.0 on an H3-only origin."""
    if expected_protocol != "h3":
        return False
    # Only the OS 26.0 network stack gives Safari WebSocket over HTTP/3 (RFC 9220);
    # 26.1 opens WebSockets over TCP again (WebKit bug 298616).
    return _safari_network_version(user_agent, platform_version) != (26, 0)


_IOS = re.compile(r"iPhone|iPad|iPod")


def h3_switch_optional(user_agent):
    """Browsers seen staying on TCP at an H3-only origin: Safari, iOS, Android."""
    if not isinstance(user_agent, str):
        return False
    if _safari_version(user_agent) is not None or _IOS.search(user_agent):
        return True
    # Firefox for Android reports a Linux platform, so only its User-Agent marks it mobile.
    return "Android" in user_agent


_H3_BOOTSTRAP_TITLE = "ラマ | HTTP/3"
_H3_BOOTSTRAP_PAGES = (
    (
        "ラマ | This browser did not switch to HTTP/3",
        "stayed on TCP: did not switch to HTTP/3",
    ),
    ("ラマ | Switching to HTTP/3", "did not leave the HTTP/3 bootstrap"),
)


def _user_agent(driver, attempts=1):
    # The bootstrap door reloads every second; a read can land mid-navigation.
    for attempt in range(attempts):
        try:
            agent = driver.execute_script("return navigator.userAgent")
        except Exception:
            agent = None
        if isinstance(agent, str) and agent:
            return agent
        if attempt + 1 < attempts:
            time.sleep(0.5)
    return None


def _mobile_platform(driver):
    """Whether the session itself runs on Android or iOS, independent of the page."""
    capabilities = getattr(driver, "capabilities", None) or {}
    platform = str(capabilities.get("platformName") or capabilities.get("platform") or "")
    return platform.lower() in ("android", "ios")


def report_state(driver):
    """Where a report page that never showed its form stopped, for the failure reason."""
    try:
        state = driver.execute_script("""
            const form = document.querySelector('form[action="/form"]');
            return {
                path: location.pathname,
                title: document.title,
                ready: document.readyState,
                flows: Array.from(document.querySelectorAll("#flow-protocols li"), li => li.innerText),
                form: form === null ? "absent" : form.getClientRects().length ? "laid out" : "not laid out",
                viewport: [innerWidth, innerHeight],
            };
        """)
    except Exception as error:
        return "page state unavailable: " + type(error).__name__
    return json.dumps(state, ensure_ascii=False) if isinstance(state, dict) else "no page state"


def h3_bootstrap_reason(driver):
    """Why the browser still shows the H3-only origin's TCP door, else None."""
    try:
        page = driver.execute_script(
            'return [document.title, document.querySelector("h1")?.textContent ?? ""]'
        )
    except Exception:
        return None
    if not isinstance(page, list) or len(page) != 2:
        return None
    title, heading = page
    heading = " ".join(heading.split()) if isinstance(heading, str) else ""
    for prefix, reason in _H3_BOOTSTRAP_PAGES:
        if heading.startswith(prefix):
            return "browser " + reason
    if title == _H3_BOOTSTRAP_TITLE:
        return "browser " + _H3_BOOTSTRAP_PAGES[1][1]
    return None


def parse_protocol_report(lines, *, optional=()):
    """Reject missing/ambiguous page observations instead of treating load as success.

    A flow in ``optional`` may report "unavailable"; it is then omitted from the result.
    """
    protocols, unavailable = {}, set()
    for line in lines:
        # WebDriver separates flex/grid children with newlines in visible text.
        line = " ".join(line.split())
        label, separator, value = line.partition(": ")
        if label not in PAGE_FLOW_NAMES:
            continue
        flow = PAGE_FLOW_NAMES[label]
        if not separator or flow in protocols or flow in unavailable:
            raise ValueError("ambiguous protocol observation for " + flow)
        protocol = value.split(" ", 1)[0]
        if flow in optional and protocol == "unavailable":
            unavailable.add(flow)
            continue
        if protocol not in PROTOCOLS:
            raise ValueError("flow failed or protocol unavailable: " + flow)
        protocols[flow] = PROTOCOLS[protocol]
    if set(protocols) | unavailable != set(PAGE_FLOW_NAMES.values()):
        raise ValueError("incomplete navigation/fetch/XHR/WebSocket coverage")
    return protocols


def verify_protocols(protocols, expected):
    """Require the requested HTTP version and retain the actual WebSocket version.

    Browsers choose WebSocket transport independently of page HTTP. A successful
    H1 WebSocket on an H3 page is valid evidence, never an H3 WebSocket claim.
    """
    if any(actual not in ("h1", "h2", "h3") for actual in protocols.values()):
        raise ValueError("unknown observed flow protocol")
    if expected is not None:
        if expected not in ("h1", "h2", "h3"):
            raise ValueError("unknown expected protocol: " + expected)
        mismatches = {
            flow: actual
            for flow, actual in protocols.items()
            if flow != "ws" and actual != expected
        }
        if mismatches:
            raise ValueError(
                f"expected {expected}; observed protocol fallback: {mismatches}"
            )


# Bound each original Fetch/XHR response before decoding it, independently of its shape.
MAX_PAGE_RESPONSE_BYTES = 4 * 1024 * 1024


def _unique_json_object(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("duplicate JSON object member")
        result[name] = value
    return result


def _finite_json_float(token):
    value = float(token)
    if not math.isfinite(value):
        raise ValueError("non-finite JSON number")
    return value


def _invalid_json_constant(_token):
    raise ValueError("non-finite JSON constant")


def _page_response_json(raw, flow):
    if not isinstance(raw, str):
        raise ValueError("page response unavailable for " + flow)
    try:
        if (
            len(raw) > MAX_PAGE_RESPONSE_BYTES
            or len(raw.encode("utf-8")) > MAX_PAGE_RESPONSE_BYTES
        ):
            raise ValueError("page response exceeds JSON byte budget for " + flow)
        response = json.loads(
            raw,
            object_pairs_hook=_unique_json_object,
            parse_constant=_invalid_json_constant,
            parse_float=_finite_json_float,
        )
    except (ValueError, RecursionError) as error:
        raise ValueError("invalid page response JSON for " + flow) from error
    if not isinstance(response, dict):
        raise ValueError("page response is not a JSON object for " + flow)
    return response


def checked_page_results(value, protocols, *, websocket=True):
    """Decode original response text without JavaScript's integer rounding.

    Display parsing belongs to the page; these bounded, unambiguous objects are
    the evidence retained by both local and BrowserStack journeys. ``websocket``
    is False only for an unsupported WebSocket, whose result is not evidence.
    """
    if not isinstance(value, dict):
        raise ValueError("page function results unavailable")
    responses = {}
    for flow in ("fetch", "xhr"):
        response = _page_response_json(value.get(flow), flow)
        responses[flow] = response
        fingerprint = response.get("fp")
        info = (
            fingerprint.get("request_info") if isinstance(fingerprint, dict) else None
        )
        if not isinstance(info, dict):
            raise ValueError("page response unavailable for " + flow)
        version = info.get("version")
        if not isinstance(version, str) or PROTOCOLS.get(version) != protocols[flow]:
            raise ValueError("page response protocol differs for " + flow)
    if not websocket:
        return dict(value, **responses)
    websocket = value.get("websocket")
    if not isinstance(websocket, dict):
        raise ValueError("completed WebSocket result unavailable")
    greeting, probe = websocket.get("greeting"), websocket.get("probe")
    if (
        not isinstance(greeting, dict)
        or greeting.get("initiator") != "ws"
        or not isinstance(greeting.get("version"), str)
        or PROTOCOLS.get(greeting["version"]) != protocols["ws"]
    ):
        raise ValueError("WebSocket result protocol differs")
    if (
        not isinstance(probe, str)
        or not probe
        or len(probe) > 1024
        or len(probe.encode("utf-8")) > 1024
        or any(character in probe for character in ("\0", "\r", "\n"))
    ):
        raise ValueError("invalid WebSocket probe")
    return dict(value, **responses)


def completed_protocols(
    user_agent,
    expected_protocol,
    page_protocols,
    post_protocol,
    get_protocol,
    link_protocol,
    page_results,
    platform_version=None,
):
    """Every flow's transport; a WebSocket the browser cannot use raises UnsupportedFlow
    carrying the protocols of the flows that did complete.

    A generic WebSocket error cannot distinguish unsupported negotiation from DNS,
    network, TLS or service failure, so only a known browser limitation is tolerated.
    """
    ws_unsupported = (
        "ws: WebSocket over HTTP/2 (RFC 8441) is not supported by this browser"
        if websocket_over_h2_unsupported(user_agent, expected_protocol, platform_version)
        else "ws: WebSocket over HTTP/3 (RFC 9220) is not supported by this browser"
        if websocket_over_h3_unsupported(user_agent, expected_protocol, platform_version)
        else None
    )
    try:
        protocols = parse_protocol_report(
            page_protocols, optional=("ws",) if ws_unsupported else ()
        )
        if post_protocol not in PROTOCOLS:
            raise ValueError("form navigation protocol unavailable")
        if get_protocol not in PROTOCOLS:
            raise ValueError("GET form navigation protocol unavailable")
        if link_protocol not in PROTOCOLS:
            raise ValueError("link navigation protocol unavailable")
        protocols["form"] = PROTOCOLS[post_protocol]
        protocols["form_get"] = PROTOCOLS[get_protocol]
        protocols["link"] = PROTOCOLS[link_protocol]
        verify_protocols(protocols, expected_protocol)
        page_results = checked_page_results(
            page_results, protocols, websocket="ws" in protocols
        )
    except ValueError as error:
        error.add_note(
            "Both form submissions and the link completed; protocols: POST="
            + PROTOCOLS.get(post_protocol, "unavailable")
            + ", GET="
            + PROTOCOLS.get(get_protocol, "unavailable")
            + ", link="
            + PROTOCOLS.get(link_protocol, "unavailable")
            + ". Partial collection is not successful coverage."
        )
        raise
    if "ws" not in protocols:
        raise UnsupportedFlow(ws_unsupported, protocols=dict(protocols))
    return protocols, page_results


SITE_KINDS = ("same-site", "cross-site")
# Subresources expose their protocol only through resource timing, which a browser
# may withhold: those report "unknown" rather than fail. The frame confirms its own.
SITE_TIMED_FLOWS = ("image", "style", "script")
SITE_PAGE_FLOWS = SITE_TIMED_FLOWS + ("frame", "fetch", "xhr", "ws")
SITE_FLOW_NAMES = SITE_PAGE_FLOWS + ("navigate", "form")
SITE_TOKEN_PARAM = "rama-fp-site"
# The page's own error text, which names no URL, tells a stall from a refusal.
MAX_SITE_ERROR_CHARS = 120
# Base64url of expiry, authorization, a page origin of at most 255 bytes and a MAC.
_SITE_TOKEN = re.compile(r"[A-Za-z0-9_-]{1,400}")


def parse_site_probes(content):
    """The other hosts the report page probes, one per site kind, all of them required."""
    if not isinstance(content, str):
        raise ValueError("report page advertises no same-site and cross-site hosts")
    try:
        probes = json.loads(content)
    except ValueError as error:
        raise ValueError("invalid site probe configuration") from error
    if not isinstance(probes, list):
        raise ValueError("invalid site probe configuration")
    sites = {}
    for probe in probes:
        if not isinstance(probe, dict) or set(probe) != {"site", "origin", "token"}:
            raise ValueError("invalid site probe")
        site, origin, token = probe["site"], probe["origin"], probe["token"]
        parsed = urlsplit(origin) if isinstance(origin, str) else None
        if (
            site not in SITE_KINDS
            or site in sites
            or parsed is None
            or parsed.scheme != "https"
            or not parsed.hostname
            or parsed.path not in ("", "/")
            or parsed.query
            or parsed.fragment
            or not isinstance(token, str)
            or not _SITE_TOKEN.fullmatch(token)
        ):
            raise ValueError("invalid site probe")
        sites[site] = {"origin": origin, "token": token}
    if set(sites) != set(SITE_KINDS):
        raise ValueError("report page must probe both a same-site and a cross-site host")
    return sites


def site_url(origin, path, token):
    return urljoin(origin, path) + "?" + urlencode({SITE_TOKEN_PARAM: token})


def checked_site_results(value, *, websocket=True):
    """Every flow the report page sent to each site host; only a WebSocket the
    browser cannot use on this origin may be missing."""
    if not isinstance(value, dict) or set(value) != set(SITE_KINDS):
        raise ValueError("site probe results unavailable")
    protocols = {}
    for site in SITE_KINDS:
        flows = value[site]
        if not isinstance(flows, dict) or set(flows) != set(SITE_PAGE_FLOWS):
            raise ValueError("incomplete site probe results for " + site)
        protocols[site] = {}
        for flow in SITE_PAGE_FLOWS:
            result = flows[flow]
            if not isinstance(result, dict):
                raise ValueError(f"invalid {flow} result for {site}")
            if "error" in result:
                if flow == "ws" and not websocket:
                    continue
                error = " ".join(str(result["error"]).split())[:MAX_SITE_ERROR_CHARS]
                raise ValueError(f"{flow} failed for {site}: {error}")
            protocol = PROTOCOLS.get(result.get("protocol"))
            if protocol is None and flow in SITE_TIMED_FLOWS and result.get("protocol") == "":
                protocol = "unknown"
            if protocol is None:
                raise ValueError(f"{flow} protocol unavailable for {site}")
            protocols[site][flow] = protocol
    return protocols


_INJECT_SITE_FORM = """
    const form = document.createElement("form");
    form.id = "rama-fp-site-form";
    form.method = "POST";
    form.action = arguments[0];
    form.innerHTML = '<input type="hidden" name="source" value="web">'
        + '<button type="submit">Submit</button>';
    document.body.append(form);
"""
_INJECT_LINK = """
    const link = document.createElement("a");
    link.id = arguments[1];
    link.href = arguments[0];
    link.textContent = "Visit";
    document.body.append(link);
"""


def visit_sites(driver, wait, origin, sites, timeout):
    """User-activated form submissions and link navigations to each site host.

    Each step starts from the page the previous one reached, so the chain stays inside
    what each page's form-action policy admits:
    primary -form-> same-site -form-> cross-site -link-> same-site -link-> primary.
    """
    same, cross = sites["same-site"], sites["cross-site"]
    steps = (
        ("same-site", "form", site_url(same["origin"], "/form", same["token"])),
        ("cross-site", "form", site_url(cross["origin"], "/form", cross["token"])),
        ("cross-site", "navigate", site_url(same["origin"], "/landing", same["token"])),
        ("same-site", "navigate", site_url(origin, "/landing", same["token"])),
    )
    protocols = {site: {} for site in SITE_KINDS}
    for site, flow, target in steps:
        if flow == "form":
            driver.execute_script(_INJECT_SITE_FORM, target)
            activate = partial(submit_form, driver, "#rama-fp-site-form", timeout=timeout)
        else:
            driver.execute_script(_INJECT_LINK, target, "rama-fp-site-link")
            activate = partial(follow_link, driver, "#rama-fp-site-link", timeout=timeout)
        activate()
        expected = urlsplit(target)
        await_navigation(
            driver, wait,
            activated_again(
                navigated_to(lambda url, expected=expected: url.hostname == expected.hostname
                             and url.path == expected.path),
                activate, timeout / 3,
            ),
            f"{site} {flow} did not navigate",
        )
        protocol = PROTOCOLS.get(driver.execute_script(
            'return performance.getEntriesByType("navigation")[0]?.nextHopProtocol'
        ))
        if protocol is None:
            raise ValueError(f"{flow} protocol unavailable for {site}")
        protocols[site][flow] = protocol
    return protocols


def drop_connections(driver, origins):
    """Have each origin drain the connection this browser reaches it on.

    The browser then opens a new connection for its next request to that host. A host
    that does not answer keeps its connection: the journey before it is already complete.
    """
    for origin in origins:
        try:
            driver.get(urljoin(origin, "/disconnect"))
        except WebDriverException as error:
            # Provider exception text can contain private data; log only its type.
            print(f"SKIP disconnect: {type(error).__name__}", flush=True)


def run_capture_flow(
    driver,
    origin,
    *,
    cookies=None,
    expected_protocol=None,
    all_flows=True,
    sites=False,
    new_connections_after=False,
    timeout=30,
):
    """Collect one real browser journey against a configurable fp origin.

    ``cookies`` is used by nightly storage authorization/metadata. Local isolated
    tests omit it to keep reference requests credential-free. The caller owns the
    driver and always quits it in a context manager/finally block.
    ``new_connections_after`` ends a completed journey by having every host it
    reached drain its connection, so a later journey in the session opens new ones.
    """
    parsed = urlsplit(origin)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("fp origin must be an HTTP(S) URL")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("fp origin must not contain credentials, query or fragment")

    # Safari can briefly detach the current document during form navigation.
    # Retry until the same completion condition holds; a closed window still times out.
    wait = WebDriverWait(driver, timeout, ignored_exceptions=(NoSuchWindowException,))
    driver.set_page_load_timeout(timeout)
    # ``sites`` requires the same-site and cross-site flows the report page advertises.
    # Until the report's form is visible, the H3-only origin may still show its
    # TCP bootstrap door: a browser that never switched is unsupported, not a failure.
    try:
        # Install collection cookies before visiting the page that runs the probes.
        if cookies:
            driver.get(urljoin(origin, "/"))
            for name, value in cookies.items():
                driver.add_cookie({"name": name, "value": value, "path": "/"})

        driver.get(urljoin(origin, "/report"))
        # A load that failed leaves the browser on the page it came from.
        if urlsplit(driver.current_url).path != "/report":
            print("RETRY report: the browser did not leave its previous page", flush=True)
            driver.get(urljoin(origin, "/report"))
        user_agent = driver.execute_script("return navigator.userAgent")
        if not all_flows:
            protocol = driver.execute_script(
                'return performance.getEntriesByType("navigation")[0]?.nextHopProtocol'
            )
            protocols = {"navigate": PROTOCOLS.get(protocol, "unavailable")}
            verify_protocols(protocols, expected_protocol)
            return FlowResult(
                user_agent,
                driver.capabilities.get("browserName", ""),
                driver.capabilities.get("browserVersion", ""),
                protocols,
                driver.page_source,
                None,
            )

        # The fp page inserts this form after fetch, XHR and the WebSocket probe.
        # A WebSocket failure can still expose the form; require its protocol
        # report too.
        wait.until(
            conditions.visibility_of_element_located(
                (By.CSS_SELECTOR, 'form[action="/form"]')
            ),
            "report page never showed its form",
        )
    except Exception as error:
        reason = h3_bootstrap_reason(driver) if expected_protocol == "h3" else None
        if reason is None:
            if isinstance(error, TimeoutException):
                raise TimeoutException(error.msg + ": " + report_state(driver)) from error
            raise
        # Desktop Chromium and Firefox switch; stuck there means a broken H3 origin.
        if not (h3_switch_optional(_user_agent(driver, attempts=6)) or _mobile_platform(driver)):
            raise RuntimeError("h3: " + reason + " (this browser must switch)") from error
        raise UnsupportedFlow("h3: " + reason) from error

    # Await the page's existing work; calling main/fetch/XHR again would duplicate it.
    driver.set_script_timeout(timeout)
    page_results = driver.execute_async_script("""
        const done = arguments[arguments.length - 1];
        const flow = window.ramaFpFlow;
        if (!flow || typeof flow.then !== "function") {
          done(null);
          return;
        }
        flow.then(done, () => done(null));
    """)

    # Preserve this page's observations before either form replaces its DOM.
    # Validate them after both forms, so an unavailable WebSocket does not hide
    # otherwise useful HTTP captures. All seven operations remain mandatory.
    # One script read: element handles can go stale if the page re-renders.
    page_protocols = driver.execute_script(
        'return Array.from(document.querySelectorAll("#flow-protocols li"), li => li.innerText)'
    ) or []
    report_html = driver.page_source
    report_url = driver.current_url
    site_probes = parse_site_probes(driver.execute_script(
        'return document.querySelector(\'meta[name="rama-fp-sites"]\')?.content ?? null'
    )) if sites else None

    # Native keyboard activation avoids SafariDriver's intermittent
    # click no-op on the long report page. The browser still submits the form.
    activate = partial(submit_form, driver, 'form[action="/form"]', timeout=timeout)
    activate()
    await_navigation(
        driver, wait,
        activated_again(navigated_to(lambda url: url.path == "/form"), activate, timeout / 3),
        "POST form submission did not navigate",
    )
    post_protocol = driver.execute_script(
        'return performance.getEntriesByType("navigation")[0]?.nextHopProtocol'
    )

    # Preserve the second form from the nightly journey: POST /form renders a
    # GET form. Its query string distinguishes it from the POST response.
    wait.until(
        conditions.visibility_of_element_located(
            (By.CSS_SELECTOR, 'form[method="GET"][action="/form"]')
        ),
        "POST form response never showed the GET form",
    )
    form_html = driver.page_source
    activate = partial(
        submit_form, driver, 'form[method="GET"][action="/form"]', timeout=timeout
    )
    activate()
    await_navigation(
        driver, wait,
        activated_again(get_form_navigation_complete, activate, timeout / 3),
        "GET form submission did not navigate",
    )
    get_protocol = driver.execute_script(
        'return performance.getEntriesByType("navigation")[0]?.nextHopProtocol'
    )
    get_form_html = driver.page_source

    # A same-origin link click, the navigation a page's own links make.
    driver.execute_script(_INJECT_LINK, urljoin(origin, "/landing"), "rama-fp-link")
    activate = partial(follow_link, driver, "#rama-fp-link", timeout=timeout)
    activate()
    await_navigation(
        driver, wait,
        activated_again(navigated_to(lambda url: url.path == "/landing"), activate, timeout / 3),
        "same-origin link did not navigate",
    )
    link_protocol = driver.execute_script(
        'return performance.getEntriesByType("navigation")[0]?.nextHopProtocol'
    )
    site_navigations = (
        visit_sites(driver, wait, origin, site_probes, timeout) if sites else None
    )
    if new_connections_after:
        hosts = [probe["origin"] for probe in site_probes.values()] if sites else []
        drop_connections(driver, [origin, *hosts])

    def site_protocols_of(results, *, websocket):
        checked = checked_site_results(
            results.get("sites") if isinstance(results, dict) else None,
            websocket=websocket,
        )
        for site, flows in site_navigations.items():
            checked[site].update(flows)
        return checked

    try:
        protocols, checked_results = completed_protocols(
            user_agent, expected_protocol, page_protocols, post_protocol, get_protocol,
            link_protocol, page_results, driver.capabilities.get("safari:platformVersion"),
        )
    except UnsupportedFlow as unsupported:
        # The browser limit that excused the WebSocket also excuses it on the site hosts.
        if sites:
            unsupported.site_protocols = site_protocols_of(page_results, websocket=False)
        raise
    site_protocols = site_protocols_of(page_results, websocket=True) if sites else None
    page_results = checked_results
    return FlowResult(
        user_agent,
        driver.capabilities.get("browserName", ""),
        driver.capabilities.get("browserVersion", ""),
        protocols,
        report_html,
        form_html,
        get_form_html,
        page_results,
        report_url,
        site_protocols,
    )
