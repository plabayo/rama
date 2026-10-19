"""Nightly profile collection using the same browser journey as local/CI tests.

Only provisioning differs: BrowserStack supplies the browsers and the public fp
origins store observations. Local tests additionally capture and replay packets.
Missing flows or HTTP fallback fail the job. WebSocket transport is recorded
independently, following the installed browser's default behavior.
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

# Allow `python rama-fp/browserstack/main.py` from any working directory.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from browser_automation.drivers import browser_options, remote_session
from browser_automation.workflow import run_capture_flow
from matrix import desktop_permutations, mobile_configs
from receipts import checked_protocols, identity, secret_forms, write_receipt

MAX_FAILURE_REASON_CHARS = 300

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


def failure_reason(error, *, secrets):
    """Name every failure; keep text only for the journey's own validation errors.

    Provider and driver messages can echo session data, so only their type is kept.
    """
    reason = type(error).__name__
    if type(error) is ValueError:
        text = " ".join([str(error), *getattr(error, "__notes__", ())])
        for secret in sorted(secret_forms(secrets), key=len, reverse=True):
            text = text.replace(secret, "<redacted>")
        text = " ".join(text.split())[:MAX_FAILURE_REASON_CHARS]
        reason += ": " + "".join(c if c.isprintable() else "?" for c in text)
    return reason


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
):
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
    for origin_index, (origin, protocol) in enumerate(ENTRYPOINTS):
        cell = f"{capability_index:03d}-{origin_index}"
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
            "started_at": datetime.now(timezone.utc).isoformat(),
        }
        stage = "session_start"
        try:
            # Default browser capabilities and the shared journey stay unchanged.
            options = browser_options(capability["browserName"])
            if "browserVersion" in capability:
                options.browser_version = capability["browserVersion"]
            options.set_capability(
                "bstack:options",
                dict(
                    provider,
                    sessionName=provider["sessionName"] + f' {protocol or "auto"}',
                ),
            )
            with remote_session(endpoint, options) as driver:
                receipt["session_started"] = True
                try:
                    stage = "session_identity"
                    receipt["actual"] = identity(driver.capabilities, secrets=secrets)
                    stage = "journey"
                    result = run_capture_flow(
                        driver, origin, cookies=cookies, expected_protocol=protocol
                    )
                    receipt["protocols"] = checked_protocols(result.protocols)
                    receipt["journey_completed"] = True
                    stage = "provider_status"
                    mark_status(
                        driver, "passed", f"all six flows completed at {origin}"
                    )
                except Exception as error:
                    receipt["failure_stage"] = stage
                    receipt["failure_reason"] = failure_reason(error, secrets=secrets)
                    try:
                        mark_status(
                            driver, "failed", f"capture flow failed at {origin}"
                        )
                    except Exception:
                        pass
                # Let the existing owner quit normally even after journey failure.
                # A raised quit is then distinguishable from the original failure.
                stage = "session_quit"
            receipt["quit_outcome"] = "succeeded"
        except Exception as error:
            receipt["failure_stage"] = receipt["failure_stage"] or stage
            receipt["failure_reason"] = receipt["failure_reason"] or failure_reason(
                error, secrets=secrets
            )
            if receipt["session_started"]:
                receipt["quit_outcome"] = "failed"

        if receipt["failure_stage"] is None:
            receipt["status"] = "passed"
        else:
            failures.append(origin)
        receipt["finished_at"] = datetime.now(timezone.utc).isoformat()
        receipt["elapsed_seconds"] = round(time.monotonic() - started, 3)
        write_receipt(output / (cell + ".json"), receipt, secrets=secrets)
        print(
            receipt["status"].upper(),
            cell,
            origin,
            *(
                [receipt["failure_stage"], receipt["failure_reason"]]
                if receipt["failure_stage"]
                else []
            ),
            flush=True,
        )
    return failures


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output", type=Path, required=True, help="new receipt directory"
    )
    args = parser.parse_args(argv)
    settings = dict(
        endpoint=os.environ.get("URL") or "https://hub.browserstack.com/wd/hub",
        username=required_env("BROWSERSTACK_USERNAME"),
        access_key=required_env("BROWSERSTACK_ACCESS_KEY"),
        storage_cookie=required_env("RAMA_FP_STORAGE_COOKIE"),
    )
    args.output.mkdir(parents=True, mode=0o700, exist_ok=False)
    build = "rama-fp-{}-{}-{}".format(
        platform.system(),
        platform.node().replace("-", "_"),
        datetime.now(timezone.utc).strftime("%Y_%m_%d_%H_%M_%S"),
    )
    failures = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = [
            executor.submit(
                run_session, cap, output=args.output, capability_index=index, **settings
            )
            for index, cap in enumerate(capabilities(build))
        ]
        for future in concurrent.futures.as_completed(futures):
            failures += len(future.result())
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
