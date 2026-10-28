"""Nightly profile collection using the same browser journey as local/CI tests.

Only provisioning differs: BrowserStack supplies the browsers and the public fp
origins store observations. Local tests additionally capture and replay packets.
Missing flows or HTTP fallback fail the job. WebSocket transport is recorded
independently, following the installed browser's default behavior. Known
browser limitations (WebSocket over HTTP/2 before Safari 26, WebSocket over
HTTP/3 outside Safari 26+, a browser that never leaves the H3-only origin's TCP
bootstrap door) are recorded as "unsupported" and do not fail the job, unless
every H3 cell stayed on that door, which points at a broken H3 origin.
A failed cell is retried once in a fresh session; its receipt records
`attempts` and, after a retry, the first attempt's `first_failure_stage` and
`first_failure_reason`, and only a cell failing both attempts fails the job. A browser
this host drives also gets a second session when an H3 cell stayed on TCP.
Origins in `REVISITED` run the journey twice in one session, recorded per visit in
`visits`; the cell passes when either visit completes.
"""

import argparse
import concurrent.futures
from datetime import datetime, timezone
import itertools
import json
import os
from pathlib import Path
import platform
import sys
import time

from selenium.common.exceptions import WebDriverException

# Allow `python rama-fp/browserstack/main.py` from any working directory.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from browser_automation.drivers import browser_options, device_session, remote_session
from browser_automation.workflow import PROTOCOLS, UnsupportedFlow, run_capture_flow
from matrix import desktop_permutations, mobile_configs
from receipts import (
    checked_partial_protocols,
    checked_protocols,
    identity,
    secret_forms,
    write_receipt,
)

MAX_FAILURE_REASON_CHARS = 300

# Public HTTP/3 site: tells a session that cannot use HTTP/3 at all apart from a broken fp origin.
H3_CONTROL_ORIGIN = "https://cloudflare-quic.com/"

# Reports whether a request's fingerprints match the embedded profile for its User-Agent.
ECHO_ORIGIN = "https://echo.ramaproxy.org/"

FETCH_JSON = """
const done = arguments[arguments.length - 1];
fetch(arguments[0], {cache: "no-store"}).then((r) => r.json()).then(done, () => done(null));
"""

ENTRYPOINTS = (
    ("http://h1.fp.ramaproxy.org/", "h1"),
    ("https://h1.fp.ramaproxy.org/", "h1"),
    ("https://h2.fp.ramaproxy.org/", "h2"),
    ("https://h3.fp.ramaproxy.org/", "h3"),
    ("http://fp.ramaproxy.org/", None),
    ("https://fp.ramaproxy.org/", None),
)

# A second visit opens later connections (resumed handshakes) and gives browsers that
# learn HTTP/3 slowly another chance to switch.
REVISITED = frozenset(("https://h3.fp.ramaproxy.org/", "https://fp.ramaproxy.org/"))

# Browsers this host drives (`--device`), for what BrowserStack's proxied sessions cannot
# capture. Simulator and emulator run the device's own browser and network code, so their
# captures are stored like any other. The optional VERSION names the iOS release or the
# Firefox release.
DEVICES = {
    "safari": (dict(browserName="Safari", os="OS X"), "osVersion"),
    "ios-simulator": (dict(browserName="safari", deviceName="iOS Simulator"), "osVersion"),
    "firefox-android": (
        dict(browserName="firefox", deviceName="Android Emulator"),
        "browserVersion",
    ),
}


def browser_arguments(capability, origin):
    """Chromium switches that keep a cell measuring what its origin names."""
    if capability["browserName"].lower() not in ("chrome", "edge"):
        return []
    arguments = []
    if "deviceName" in capability:
        # The provider launches Android Chrome behind an HTTP proxy, which rules out QUIC.
        arguments.append("--no-proxy-server")
    if origin.startswith("http://"):
        # Either feature alone moves a plain-HTTP navigation to HTTPS before any request.
        arguments.append("--disable-features=HttpsUpgrades,UseDnsHttpsSvcb")
    return arguments


def required_env(name):
    value = os.environ.get(name)
    if not value:
        raise ValueError(name + " is not set")
    return value


def capabilities(build):
    """Preserve the nightly desktop/mobile matrix without starting any sessions."""
    for version, browser, (system, system_version) in itertools.product(
        *desktop_permutations
    ):
        if browser == "Safari" and (system != "OS X" or version != "latest"):
            continue
        if browser == "Edge" and system != "Windows":
            continue
        yield dict(
            browserName=browser,
            browserVersion=version,
            os=system,
            osVersion=system_version,
            buildName=build,
            sessionName=f"{browser} {version} on {system} {system_version}",
        )
    for device, version, browser in mobile_configs:
        yield dict(
            browserName=browser,
            deviceName=device,
            osVersion=version,
            buildName=build,
            sessionName=f"{device} {version} {browser}",
        )


def failure_reason(error, *, secrets, driver_message=False):
    """Name every failure; keep text only for the journey's own validation errors.

    Provider and driver messages can echo session data, so only their type is kept,
    unless the driver runs on this host (`driver_message`), where no provider session exists.
    """
    reason = type(error).__name__
    if type(error) is ValueError:
        text = " ".join([str(error), *getattr(error, "__notes__", ())])
    elif driver_message and isinstance(error, WebDriverException) and error.msg:
        text = error.msg
    else:
        return reason
    for secret in sorted(secret_forms(secrets), key=len, reverse=True):
        text = text.replace(secret, "<redacted>")
    text = " ".join(text.split())[:MAX_FAILURE_REASON_CHARS]
    return reason + ": " + "".join(c if c.isprintable() else "?" for c in text)


def fingerprint_match(value):
    """A JA4/JA4H report: the observed hash and, when a profile exists, its hash."""
    value = value if isinstance(value, dict) else {}
    profile = value.get("profile") if isinstance(value.get("profile"), dict) else None
    return {
        "observed": value.get("hash"),
        "reference": profile and profile.get("hash"),
        "matched": profile and profile.get("matched") is True,
    }


def check_echo(device, output, *, secrets):
    """Device sources must keep the embedded profile's TLS fingerprint where one exists.

    JA4H is recorded only: its Accept-Language part follows the device locale.
    """
    receipt = {"cell": "echo", "origin": ECHO_ORIGIN, "protocols": None}
    try:
        with device_session(*device) as driver:
            driver.set_page_load_timeout(30)
            driver.set_script_timeout(30)
            driver.get(ECHO_ORIGIN)
            # A same-origin fetch reuses the navigation's connection and reads raw JSON.
            report = driver.execute_async_script(FETCH_JSON, ECHO_ORIGIN)
        if not isinstance(report, dict):
            raise ValueError("echo returned no JSON report")
        receipt["http_version"] = (report.get("http") or {}).get("version")
        receipt["ja4"] = fingerprint_match((report.get("tls") or {}).get("ja4"))
        receipt["ja4h"] = fingerprint_match((report.get("http") or {}).get("ja4h"))
        receipt["status"] = "failed" if receipt["ja4"]["matched"] is False else "passed"
    except Exception as error:
        receipt["status"] = "failed"
        receipt["failure_reason"] = failure_reason(error, secrets=secrets, driver_message=True)
    write_receipt(output / "echo.json", receipt, secrets=secrets)
    print(receipt["status"].upper(), "echo", json.dumps(receipt.get("ja4")), flush=True)
    return receipt["status"] == "passed"


def h3_control_protocol(driver):
    """Transport of a public HTTP/3 site, visited twice so Alt-Svc can take effect."""
    protocol = None
    try:
        for _ in range(2):
            driver.get(H3_CONTROL_ORIGIN)
            protocol = driver.execute_script(
                'return performance.getEntriesByType("navigation")[0]?.nextHopProtocol'
            )
            if PROTOCOLS.get(protocol) == "h3":
                break
    except Exception:
        return "unavailable"
    return PROTOCOLS.get(protocol, "unavailable")


def mark_status(driver, status, reason):
    driver.execute_script(
        "browserstack_executor: "
        + json.dumps(
            {
                "action": "setSessionStatus",
                "arguments": {"status": status, "reason": reason},
            }
        )
    )


def run_session(
    capability,
    *,
    output,
    capability_index,
    endpoint,
    username,
    access_key,
    storage_cookie,
    device=None,
):
    """Collect every entry point once; `device` = (kind, version) drives a local browser."""
    provider = {
        key: capability[key]
        for key in ("os", "osVersion", "deviceName", "buildName", "sessionName")
        if key in capability
    }
    provider.update(userName=username, accessKey=access_key, source="python:rama-fp")
    cookies = {
        "rama-storage-auth": storage_cookie,
        "source-device-name": capability.get("deviceName", ""),
        "source-os-name": capability.get("os", ""),
        "source-os-version": capability.get("osVersion", ""),
        "source-browser-name": capability["browserName"],
        "source-browser-version": capability.get("browserVersion", ""),
    }
    failures = []
    secrets = (username, access_key, storage_cookie)
    # Only BrowserStack sessions have a provider status to report.
    report = mark_status if device is None else lambda *_args: None

    def attempt(cell, origin, protocol):
        started = time.monotonic()
        receipt = {
            "cell": cell,
            "requested": identity(capability, secrets=secrets),
            "origin": origin,
            "expected_http_protocol": protocol,
            "actual": {},
            "protocols": None,
            "session_started": False,
            "quit_outcome": "not_started",
            "journey_completed": False,
            "status": "failed",
            "failure_stage": None,
            "failure_reason": None,
            "unsupported_reason": None,
            "started_at": datetime.now(timezone.utc).isoformat(),
        }
        stage = "session_start"
        try:
            if device is None:
                # Default browser capabilities and the shared journey stay unchanged,
                # apart from the switches in `browser_arguments`.
                options = browser_options(capability["browserName"])
                if "browserVersion" in capability:
                    options.browser_version = capability["browserVersion"]
                for argument in browser_arguments(capability, origin):
                    options.add_argument(argument)
                options.set_capability(
                    "bstack:options",
                    dict(
                        provider,
                        sessionName=provider["sessionName"] + f' {protocol or "auto"}',
                    ),
                )
                session = remote_session(endpoint, options)
            else:
                session = device_session(*device)
            with session as driver:
                receipt["session_started"] = True
                try:
                    stage = "session_identity"
                    receipt["actual"] = identity(driver.capabilities, secrets=secrets)
                    visits = []
                    unsupported = None
                    for visit in range(2 if origin in REVISITED else 1):
                        stage = "revisit" if visit else "journey"
                        try:
                            # The session keeps the cookies the first visit installed.
                            result = run_capture_flow(
                                driver,
                                origin,
                                cookies=None if visit else cookies,
                                expected_protocol=protocol,
                            )
                        except UnsupportedFlow as error:
                            unsupported = error
                            visits.append(
                                {"status": "unsupported", "unsupported_reason": str(error)}
                            )
                        else:
                            protocols = checked_protocols(result.protocols)
                            visits.append({"status": "passed", "protocols": protocols})
                            if not receipt["journey_completed"]:
                                receipt["protocols"] = protocols
                                receipt["journey_completed"] = True
                    if origin in REVISITED:
                        receipt["visits"] = visits
                    if not receipt["journey_completed"]:
                        receipt["unsupported_reason"] = str(unsupported)
                        if unsupported.protocols is not None:
                            receipt["completed_protocols"] = checked_partial_protocols(
                                unsupported.protocols
                            )
                        if str(unsupported).startswith("h3:"):
                            stage = "h3_control"
                            receipt["h3_control"] = h3_control_protocol(driver)
                    stage = "provider_status"
                    report(
                        driver,
                        "passed",
                        (
                            f"unsupported at {origin}: {receipt['unsupported_reason']}"
                            if receipt["unsupported_reason"]
                            else f"all six flows completed at {origin}"
                        ),
                    )
                except Exception as error:
                    receipt["failure_stage"] = stage
                    receipt["failure_reason"] = failure_reason(
                        error, secrets=secrets, driver_message=device is not None
                    )
                    try:
                        report(driver, "failed", f"capture flow failed at {origin}")
                    except Exception:
                        pass
                # Let the existing owner quit normally even after journey failure.
                # A raised quit is then distinguishable from the original failure.
                stage = "session_quit"
            receipt["quit_outcome"] = "succeeded"
        except Exception as error:
            receipt["failure_stage"] = receipt["failure_stage"] or stage
            receipt["failure_reason"] = receipt["failure_reason"] or failure_reason(
                error, secrets=secrets, driver_message=device is not None
            )
            if receipt["session_started"]:
                receipt["quit_outcome"] = "failed"

        if receipt["failure_stage"] is None:
            receipt["status"] = (
                "unsupported" if receipt["unsupported_reason"] else "passed"
            )
        receipt["finished_at"] = datetime.now(timezone.utc).isoformat()
        receipt["elapsed_seconds"] = round(time.monotonic() - started, 3)
        return receipt

    for origin_index, (origin, protocol) in enumerate(ENTRYPOINTS):
        cell = f"{capability_index:03d}-{origin_index}"
        receipt = attempt(cell, origin, protocol)
        receipt["attempts"] = 1
        # Nothing on a host we drive keeps QUIC away, so staying on TCP there is the
        # browser's Alt-Svc timing and gets a fresh session too.
        stayed_on_tcp = device is not None and str(receipt["unsupported_reason"]).startswith(
            "h3:"
        )
        if receipt["status"] == "failed" or stayed_on_tcp:
            # Real-device sessions fail transiently; a genuine fault fails twice.
            first = receipt
            receipt = attempt(cell, origin, protocol)
            receipt["attempts"] = 2
            receipt["first_failure_stage"] = first["failure_stage"]
            receipt["first_failure_reason"] = (
                first["failure_reason"] or first["unsupported_reason"]
            )
        if receipt["status"] == "failed":
            failures.append(origin)
        write_receipt(output / (cell + ".json"), receipt, secrets=secrets)
        print(
            receipt["status"].upper(),
            cell,
            origin,
            *(
                [receipt["failure_stage"], receipt["failure_reason"]]
                if receipt["failure_stage"]
                else [receipt["unsupported_reason"]]
                if receipt["unsupported_reason"]
                else []
            ),
            flush=True,
        )
    return failures


def h3_never_reached(receipts):
    """Every H3 cell ran but stayed on the TCP bootstrap door."""
    h3 = [row for row in receipts if row.get("expected_http_protocol") == "h3"]
    return bool(h3) and all(
        row.get("status") == "unsupported"
        and str(row.get("unsupported_reason")).startswith("h3:")
        for row in h3
    )


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output", type=Path, required=True, help="new receipt directory"
    )
    parser.add_argument(
        "--device",
        metavar="KIND[:VERSION]",
        help="drive a browser on this host instead of BrowserStack: " + ", ".join(DEVICES),
    )
    args = parser.parse_args(argv)
    build = "rama-fp-{}-{}-{}".format(
        platform.system(),
        platform.node().replace("-", "_"),
        datetime.now(timezone.utc).strftime("%Y_%m_%d_%H_%M_%S"),
    )
    if args.device:
        kind, _, version = args.device.partition(":")
        if kind not in DEVICES:
            parser.error("unknown device browser: " + kind)
        capability, version_key = DEVICES[kind]
        version = version or (platform.mac_ver()[0] if kind == "safari" else "")
        sessions = [dict(capability, **{version_key: version}, sessionName=args.device)]
        settings = dict(
            endpoint=None,
            username=None,
            access_key=None,
            storage_cookie=required_env("RAMA_FP_STORAGE_COOKIE"),
            device=(kind, version if kind == "ios-simulator" and version else None),
        )
    else:
        sessions = list(capabilities(build))
        settings = dict(
            endpoint=os.environ.get("URL") or "https://hub.browserstack.com/wd/hub",
            username=required_env("BROWSERSTACK_USERNAME"),
            access_key=required_env("BROWSERSTACK_ACCESS_KEY"),
            storage_cookie=required_env("RAMA_FP_STORAGE_COOKIE"),
        )
    args.output.mkdir(parents=True, mode=0o700, exist_ok=False)
    failures = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = [
            executor.submit(
                run_session, cap, output=args.output, capability_index=index, **settings
            )
            for index, cap in enumerate(sessions)
        ]
        for future in concurrent.futures.as_completed(futures):
            failures += len(future.result())
    receipts = [json.loads(path.read_text()) for path in args.output.glob("*.json")]
    if h3_never_reached(receipts):
        print("FAILED no H3 cell left the HTTP/3 bootstrap door", flush=True)
        failures += 1
    if args.device:
        failures += not check_echo(
            settings["device"], args.output, secrets=(settings["storage_cookie"],)
        )
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
