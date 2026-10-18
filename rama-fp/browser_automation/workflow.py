"""Drive the existing fp page and require each requested flow to finish.

No HTTP requests are synthesized here: navigation, fetch, XHR, WebSocket and form
submission are performed by the browser and fp's own page script. The same code
accepts a local Selenium driver or BrowserStack's Remote WebDriver.
"""

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


def parse_protocol_report(lines):
    """Reject missing/ambiguous page observations instead of treating load as success."""
    protocols = {}
    for line in lines:
        label, separator, value = line.partition(": ")
        if label not in PAGE_FLOW_NAMES:
            continue
        flow = PAGE_FLOW_NAMES[label]
        if not separator or flow in protocols:
            raise ValueError("ambiguous protocol observation for " + flow)
        protocol = value.split(" ", 1)[0]
        if protocol not in PROTOCOLS:
            raise ValueError("flow failed or protocol unavailable: " + flow)
        protocols[flow] = PROTOCOLS[protocol]
    if set(protocols) != set(PAGE_FLOW_NAMES.values()):
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

    # Install collection cookies before visiting the page that runs the probes.
    wait = WebDriverWait(driver, timeout)
    driver.set_page_load_timeout(timeout)
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
    # A WebSocket failure can still expose the form; require its protocol report too.
    form = wait.until(
        conditions.visibility_of_element_located(
            (By.CSS_SELECTOR, 'form[action="/form"]')
        )
    )
    protocols = parse_protocol_report(
        [
            element.text
            for element in driver.find_elements(By.CSS_SELECTOR, "#flow-protocols li")
        ]
    )
    report_html = driver.page_source

    # Submit the native POST form after all page-driven probes have finished.
    form.find_element(By.CSS_SELECTOR, 'button[type="submit"]').click()
    wait.until(
        lambda browser: urlsplit(browser.current_url).path == "/form"
        and browser.execute_script("return document.readyState") == "complete"
    )
    protocol = driver.execute_script(
        'return performance.getEntriesByType("navigation")[0]?.nextHopProtocol'
    )
    if protocol not in PROTOCOLS:
        raise ValueError("form navigation protocol unavailable")
    protocols["form"] = PROTOCOLS[protocol]
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
    protocol = driver.execute_script(
        'return performance.getEntriesByType("navigation")[0]?.nextHopProtocol'
    )
    if protocol not in PROTOCOLS:
        raise ValueError("GET form navigation protocol unavailable")
    protocols["form_get"] = PROTOCOLS[protocol]

    verify_protocols(protocols, expected_protocol)
    return FlowResult(
        user_agent,
        driver.capabilities.get("browserName", ""),
        driver.capabilities.get("browserVersion", ""),
        protocols,
        report_html,
        form_html,
        driver.page_source,
    )
