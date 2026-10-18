"""Nightly profile collection using the same browser journey as local/CI tests.

Only provisioning differs: BrowserStack supplies the browsers and the public fp
origins store observations. Local tests additionally capture and replay packets.
Missing flows or HTTP fallback fail the job. WebSocket transport is recorded
independently, following the installed browser's default behavior.
"""

import concurrent.futures
from datetime import datetime, timezone
import itertools
import json
import os
from pathlib import Path
import platform
import sys

# Allow `python rama-fp/browserstack/main.py` from any working directory.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from browser_automation.drivers import browser_options, remote_session
from browser_automation.workflow import run_capture_flow
from matrix import desktop_permutations, mobile_configs

ENTRYPOINTS = (
    ("http://h1.fp.ramaproxy.org/", "h1"),
    ("https://h1.fp.ramaproxy.org/", "h1"),
    ("https://h2.fp.ramaproxy.org/", "h2"),
    ("https://h3.fp.ramaproxy.org/", "h3"),
    ("http://fp.ramaproxy.org/", None),
    ("https://fp.ramaproxy.org/", None),
)


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


def run_session(capability, *, endpoint, username, access_key, storage_cookie):
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
    for origin, protocol in ENTRYPOINTS:
        # Public archives retain default browser protocol capabilities.
        # The shared journey records each flow's actual transport.
        options = browser_options(capability["browserName"])
        if "browserVersion" in capability:
            options.browser_version = capability["browserVersion"]
        cell_provider = dict(
            provider, sessionName=provider["sessionName"] + f' {protocol or "auto"}'
        )
        options.set_capability("bstack:options", cell_provider)
        try:
            with remote_session(endpoint, options) as driver:
                try:
                    result = run_capture_flow(
                        driver, origin, cookies=cookies, expected_protocol=protocol
                    )
                    mark_status(
                        driver, "passed", f"all six flows completed at {origin}"
                    )
                    print(
                        capability["sessionName"],
                        origin,
                        dict(result.protocols),
                        flush=True,
                    )
                except Exception:
                    # Provider errors can include credentials/URLs. Keep public logs
                    # and session annotations limited to the failing test identity.
                    try:
                        mark_status(
                            driver, "failed", f"capture flow failed at {origin}"
                        )
                    except Exception:
                        pass
                    raise
        except Exception as error:
            failures.append(origin)
            print(
                "FAILED",
                capability["sessionName"],
                origin,
                type(error).__name__,
                flush=True,
            )
    return failures


def main():
    settings = dict(
        endpoint=os.environ.get("URL") or "https://hub.browserstack.com/wd/hub",
        username=required_env("BROWSERSTACK_USERNAME"),
        access_key=required_env("BROWSERSTACK_ACCESS_KEY"),
        storage_cookie=required_env("RAMA_FP_STORAGE_COOKIE"),
    )
    build = "rama-fp-{}-{}-{}".format(
        platform.system(),
        platform.node().replace("-", "_"),
        datetime.now(timezone.utc).strftime("%Y_%m_%d_%H_%M_%S"),
    )
    failures = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = [
            executor.submit(run_session, cap, **settings) for cap in capabilities(build)
        ]
        for future in concurrent.futures.as_completed(futures):
            failures += len(future.result())
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
