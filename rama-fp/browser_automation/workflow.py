"""Drive the existing fp page and require each requested flow to finish.

No HTTP requests are synthesized here: navigation, fetch, XHR, WebSocket and form
submission are performed by the browser and fp's own page script. The same code
accepts a local Selenium driver or BrowserStack's Remote WebDriver.
"""

import json
import math
import re

from dataclasses import dataclass
from typing import Mapping, Optional
from urllib.parse import parse_qs, urljoin, urlsplit

from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as conditions
from selenium.webdriver.support.ui import WebDriverWait


def get_form_navigation_complete(browser):
    """Wait for the GET form's distinct URL, without probing a detached DOM node."""
    url = urlsplit(browser.current_url)
    return (
        url.path == "/form"
        and parse_qs(url.query) == {"source": ["web"], "turtles": ["yes"]}
        and browser.execute_script("return document.readyState") == "complete"
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
    """A flow the browser cannot perform on this origin; every other flow passed."""


_SAFARI_VERSION = re.compile(r"Version/(\d+)")
_NON_SAFARI_WEBKIT = re.compile(r"Chrome|CriOS|FxiOS|EdgiOS|Edg")


def _safari_major(user_agent):
    """Safari's major version from the UA (iOS has no browserVersion), else None."""
    if not isinstance(user_agent, str):
        return None
    if "Safari/" not in user_agent or _NON_SAFARI_WEBKIT.search(user_agent):
        return None
    version = _SAFARI_VERSION.search(user_agent)
    return None if version is None else int(version.group(1))


def websocket_over_h2_unsupported(user_agent, expected_protocol):
    """Safari before 26 on an H2-only origin."""
    if expected_protocol != "h2":
        return False
    version = _safari_major(user_agent)
    # Safari 26 added WebSocket over HTTP/2 (RFC 8441).
    return version is not None and version < 26


def websocket_over_h3_unsupported(user_agent, expected_protocol):
    """Any browser but Safari 26+ on an H3-only origin."""
    if expected_protocol != "h3":
        return False
    version = _safari_major(user_agent)
    # Safari 26 is the only shipped browser with WebSocket over HTTP/3 (RFC 9220).
    return version is None or version < 26


_H3_BOOTSTRAP_TITLE = "ラマ | HTTP/3"
_H3_BOOTSTRAP_PAGES = (
    (
        "ラマ | This browser did not switch to HTTP/3",
        "stayed on TCP: did not switch to HTTP/3",
    ),
    ("ラマ | Switching to HTTP/3", "did not leave the HTTP/3 bootstrap"),
)


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


def run_capture_flow(
    driver, origin, *, cookies=None, expected_protocol=None, all_flows=True, timeout=30
):
    """Collect one real browser journey against a configurable fp origin.

    ``cookies`` is used by nightly storage authorization/metadata. Local isolated
    tests omit it to keep reference requests credential-free. The caller owns the
    driver and always quits it in a context manager/finally block.
    """
    parsed = urlsplit(origin)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("fp origin must be an HTTP(S) URL")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("fp origin must not contain credentials, query or fragment")

    wait = WebDriverWait(driver, timeout)
    driver.set_page_load_timeout(timeout)
    # Until the report's form is visible, the H3-only origin may still show its
    # TCP bootstrap door: a browser that never switched is unsupported, not a failure.
    try:
        # Install collection cookies before visiting the page that runs the probes.
        if cookies:
            driver.get(urljoin(origin, "/"))
            for name, value in cookies.items():
                driver.add_cookie({"name": name, "value": value, "path": "/"})

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
        form = wait.until(
            conditions.visibility_of_element_located(
                (By.CSS_SELECTOR, 'form[action="/form"]')
            )
        )
    except Exception as error:
        reason = h3_bootstrap_reason(driver) if expected_protocol == "h3" else None
        if reason is None:
            raise
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
    # otherwise useful HTTP captures. All six operations remain mandatory.
    page_protocols = [
        element.text
        for element in driver.find_elements(By.CSS_SELECTOR, "#flow-protocols li")
    ]
    report_html = driver.page_source
    report_url = driver.current_url

    # Submit the native POST form after all page-driven probes have finished.
    form.find_element(By.CSS_SELECTOR, 'button[type="submit"]').click()
    wait.until(
        lambda browser: urlsplit(browser.current_url).path == "/form"
        and browser.execute_script("return document.readyState") == "complete"
    )
    post_protocol = driver.execute_script(
        'return performance.getEntriesByType("navigation")[0]?.nextHopProtocol'
    )
    form_html = driver.page_source

    # Preserve the second form from the nightly journey: POST /form renders a
    # GET form. Its query string distinguishes it from the POST response.
    get_form = wait.until(
        conditions.visibility_of_element_located(
            (By.CSS_SELECTOR, 'form[method="GET"][action="/form"]')
        )
    )
    get_form.find_element(By.CSS_SELECTOR, 'button[type="submit"]').click()
    wait.until(get_form_navigation_complete)
    get_protocol = driver.execute_script(
        'return performance.getEntriesByType("navigation")[0]?.nextHopProtocol'
    )

    # A generic WebSocket error cannot distinguish unsupported negotiation from
    # DNS, network, TLS or service failure. Keep it a strict failure, except for
    # a known browser limitation, while the completed form observations make
    # partial collection explicit.
    ws_unsupported = (
        "ws: WebSocket over HTTP/2 requires Safari 26+"
        if websocket_over_h2_unsupported(user_agent, expected_protocol)
        else "ws: WebSocket over HTTP/3 (RFC 9220) is not supported by this browser"
        if websocket_over_h3_unsupported(user_agent, expected_protocol)
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
        protocols["form"] = PROTOCOLS[post_protocol]
        protocols["form_get"] = PROTOCOLS[get_protocol]
        verify_protocols(protocols, expected_protocol)
        page_results = checked_page_results(
            page_results, protocols, websocket="ws" in protocols
        )
    except ValueError as error:
        error.add_note(
            "Both form submissions completed; protocols: POST="
            + PROTOCOLS.get(post_protocol, "unavailable")
            + ", GET="
            + PROTOCOLS.get(get_protocol, "unavailable")
            + ". Partial collection is not successful coverage."
        )
        raise
    if "ws" not in protocols:
        raise UnsupportedFlow(ws_unsupported)
    return FlowResult(
        user_agent,
        driver.capabilities.get("browserName", ""),
        driver.capabilities.get("browserVersion", ""),
        protocols,
        report_html,
        form_html,
        driver.page_source,
        page_results,
        report_url,
    )
