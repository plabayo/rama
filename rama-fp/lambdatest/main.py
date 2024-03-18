import os
import json
import subprocess
import itertools
import urllib
from concurrent.futures import ThreadPoolExecutor

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options as ChromeOptions


desktop_permutations = [
    [
        'Windows 10',
        'Windows 11',
        'MacOS Ventura',
        'MacOS Monterey',
    ]
]


def env(key):
    value = os.environ.get(key)
    if value is None:
        raise ValueError(f"{key} is not set")
    return value


LT_USERNAME = env("LT_USERNAME")
LT_ACCESS_KEY = env("LT_ACCESS_KEY")

desired_caps = [
    {
        "browser": comb[1],
        "browser_version": comb[0],
        "os": comb[2][0],
        "os_version": comb[2][1],
        "name": f"{comb[1]} {comb[0]} on {comb[2][0]} {comb[2][1]}",
        "browserstack.username": BROWSERSTACK_USERNAME,
        "browserstack.accessKey": BROWSERSTACK_ACCESS_KEY,
        "browserstack.consoleLogs": "errors",
    }
    for comb in itertools.product(*permutations)
]


entrypoints = [
    "http://fp.ramaproxy.org:80/",
    "https://fp.ramaproxy.org:443/",
    "http://h1.fp.ramaproxy.org:80/",
    "https://h1.fp.ramaproxy.org:443/",
]


def run_parallel_session(desired_cap):
    with sync_playwright() as playwright:
        clientPlaywrightVersion = (
            str(subprocess.getoutput("playwright --version"))
            .strip()
            .split(" ")[1]  # noqa: E501
        )
        desired_cap["client.playwrightVersion"] = clientPlaywrightVersion

        cdpUrl = "wss://cdp.browserstack.com/playwright?caps=" + urllib.parse.quote(
            json.dumps(desired_cap)
        )  # noqa: E501
        browser = playwright.chromium.connect(cdpUrl)

        for entrypoint in entrypoints:
            try:
                page = browser.new_page()
                page.on("console", lambda msg: print(msg.text))
                print(page.evaluate("() => navigator.userAgent"))

                page.goto(entrypoint)
                print(page.evaluate("() => document.location.href"))

                page.locator('a[href="/report"]').click()
                print(page.evaluate("() => document.location.href"))

                page.locator('button[type="submit"]').click()
                print(page.evaluate("() => document.location.href"))

                page.locator('button[type="submit"]').click()
                print(page.evaluate("() => document.location.href"))

                try:
                    page.close()
                except Exception:
                    pass

                mark_test_status("passed", "flow complete for ua", page)

            except Exception as err:
                mark_test_status("failed", str(err), page)

        try:
            browser.close()
        except Exception:
            pass


def mark_test_status(status, reason, page):
    page.evaluate(
        "_ => {}",
        'browserstack_executor: {"action": "setSessionStatus", "arguments": {"status":"'  # noqa: E501
        + status
        + '", "reason": "'
        + reason
        + '"}}',
    )


with ThreadPoolExecutor(max_workers=10) as executor:
    for cap in desired_caps:
        executor.submit(run_parallel_session, cap)
