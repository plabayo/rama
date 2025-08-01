import concurrent.futures
from datetime import datetime
import os
import platform
import itertools
from urllib.parse import urlparse
from selenium import webdriver
from selenium.webdriver.chrome.options import Options as ChromeOptions
from selenium.webdriver.firefox.options import Options as FirefoxOptions
from selenium.webdriver.safari.options import Options as SafariOptions
from selenium.webdriver.edge.options import Options as EdgeOptions
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.by import By
import json

# capability source:
# > <https://www.browserstack.com/docs/automate/capabilities>

# availability list:
# > <https://www.browserstack.com/list-of-browsers-and-platforms/automate>

desktop_permutations = [
    ["latest", "latest-1", "latest-2"],
    ["Chrome", "Edge", "Firefox", "Safari"],
    (
        [["Windows", v] for v in ["10", "11"]]
        + [["OS X", v] for v in ["Ventura", "Sonoma", "Sequoia", "Tahoe"]]
    ),
]

mobile_configs = [
    ("Samsung Galaxy S23 Ultra", "13.0", "chrome"),
    ("Samsung Galaxy S23", "13.0", "chrome"),
    ("Samsung Galaxy S22 Ultra", "12.0", "chrome"),
    ("Samsung Galaxy S22 Plus", "12.0", "chrome"),
    ("Samsung Galaxy S22", "12.0", "chrome"),
    ("Samsung Galaxy Tab S8", "12.0", "chrome"),
    ("Samsung Galaxy A52", "11.0", "chrome"),
    ("Samsung Galaxy M52", "11.0", "chrome"),
    ("Google Pixel 9 Pro XL", "15.0", "chrome"),
    ("Google Pixel 9 Pro", "15.0", "chrome"),
    ("Google Pixel 9", "15.0", "chrome"),
    ("Google Pixel 8 Pro", "14.0", "chrome"),
    ("Google Pixel 8", "14.0", "chrome"),
    ("Google Pixel 7 Pro", "13.0", "chrome"),
    ("Google Pixel 7", "13.0", "chrome"),
    ("Google Pixel 6 Pro", "13.0", "chrome"),
    ("Google Pixel 6 Pro", "12.0", "chrome"),
    ("Google Pixel 6", "12.0", "chrome"),
    ("Google Pixel 5", "12.0", "chrome"),
    ("OnePlus 11R", "13.0", "chrome"),
    ("OnePlus 12R", "14.0", "chrome"),
    ("Huawei P30", "9.0", "chrome"),
    ("iPhone 16e", "18", "safari"),
    ("iPhone 16 Pro Max", "18", "safari"),
    ("iPhone 16 Pro", "18", "safari"),
    ("iPhone 16 Plus", "18", "safari"),
    ("iPhone 16", "18", "safari"),
    ("iPhone 15 Pro Max", "17", "safari"),
    ("iPhone 15 Pro", "17", "safari"),
    ("iPhone 15 Plus", "17", "safari"),
    ("iPhone 15", "17", "safari"),
    ("iPhone 14 Pro Max", "16", "safari"),
    ("iPhone 14 Pro", "16", "safari"),
    ("iPhone 14 Plus", "16", "safari"),
    ("iPhone 14", "16", "safari"),
]


def env(key):
    value = os.environ.get(key)
    if value is None:
        raise ValueError(f"{key} is not set")
    return value


BROWSERSTACK_USERNAME = env("BROWSERSTACK_USERNAME")
BROWSERSTACK_ACCESS_KEY = env("BROWSERSTACK_ACCESS_KEY")
URL = os.environ.get("URL") or "https://hub.browserstack.com/wd/hub"

RAMA_FP_STORAGE_COOKIE = env("RAMA_FP_STORAGE_COOKIE")


def get_browser_option(browser):
    switcher = {
        "chrome": ChromeOptions(),
        "firefox": FirefoxOptions(),
        "edge": EdgeOptions(),
        "safari": SafariOptions(),
    }
    return switcher.get(browser, ChromeOptions())


build_name = "rama-fp-{system}-{node}-{date}".format(
    system=platform.system(),
    node=platform.node().replace("-", "_"),
    date=datetime.now().strftime("%Y_%m_%d_%H_%M_%S"),
)


desktop_desired_caps = [
    {
        "browserName": comb[1],
        "browserVersion": comb[0],
        "os": comb[2][0],
        "osVersion": comb[2][1],
        "buildName": build_name,
        "sessionName": f"{comb[1]} {comb[0]} on {comb[2][0]} {comb[2][1]}",
        "browserstack.networkLogs": True,
    }
    for comb in itertools.product(*desktop_permutations)
    if (comb[1] != "Safari" or (comb[2][0] == "OS X" and comb[0] == "latest"))
    and (comb[1] != "Edge" or comb[2][0] == "Windows")
]

mobile_desired_caps = [
    {
        "browserName": browser,
        "deviceName": device,
        "osVersion": os_version,
        "buildName": build_name,
        "sessionName": f"{device} {os_version} {browser}",
        "browserstack.networkLogs": True,
    }
    for (device, os_version, browser) in mobile_configs
]

desired_caps = desktop_desired_caps + mobile_desired_caps
# desired_caps = desktop_desired_caps
# desired_caps = mobile_desired_caps

# ensure auto comes last, so we get h2
# as tls profile... even though rama emulate
# should be able to adapt stuff like ALPN on the fly,
# doesn't hurt to make sure the default is also the UA
# default...
entrypoints = [
    "http://h1.fp.ramaproxy.org:80/",
    "https://h1.fp.ramaproxy.org:443/",
    "http://fp.ramaproxy.org:80/",
    "https://fp.ramaproxy.org:443/",
]


def run_session(cap):
    print("running parallel session", cap)
    bstack_options = {
        "osVersion": cap["osVersion"],
        "buildName": cap["buildName"],
        "sessionName": cap["sessionName"],
        "userName": BROWSERSTACK_USERNAME,
        "accessKey": BROWSERSTACK_ACCESS_KEY,
    }
    if "os" in cap:
        bstack_options["os"] = cap["os"]
    if "deviceName" in cap:
        bstack_options["deviceName"] = cap["deviceName"]
    bstack_options["source"] = "python:rama-fp"
    options = get_browser_option(cap["browserName"].lower())
    if "browserVersion" in cap:
        options.browser_version = cap["browserVersion"]
    options.set_capability("bstack:options", bstack_options)

    for entrypoint in entrypoints:
        print("for entrypoint", entrypoint)
        driver = None
        try:
            driver = webdriver.Remote(
                command_executor=URL,
                options=options,
            )

            driver.get(entrypoint)
            print("ua", driver.execute_script("return navigator.userAgent;"))
            print("loc", driver.execute_script("return document.location.href;"))

            domain = urlparse(entrypoint).netloc.split(":")[0]
            print("add cookies for domain", domain)
            cookies = {
                "rama-storage-auth": RAMA_FP_STORAGE_COOKIE,
                "source-device-name": cap.get("deviceName", ""),
                "source-os-name": cap.get("os", ""),
                "source-os-version": cap.get("osVersion", ""),
                "source-browser-name": cap.get("browserName", ""),
                "source-browser-version": cap.get("browserVersion", ""),
            }
            for name, value in cookies.items():
                print("add cookie to domain", domain, name)
                driver.add_cookie({
                    "name": name,
                    "value": value,
                    "domain": domain,
                    "path": "/",
                })

            WebDriverWait(driver, 10).until(
                EC.visibility_of_element_located(
                    (By.CSS_SELECTOR, 'a[href="/report"]')
                )  # noqa: E501
            ).click()
            print("loc", driver.execute_script("return document.location.href;"))

            for _ in range(2):
                WebDriverWait(driver, 10).until(
                    EC.visibility_of_element_located(
                        (By.CSS_SELECTOR, 'button[type="submit"]')
                    )
                ).click()
                print(driver.execute_script("return document.location.href;"))

            mark_test_status(
                "passed",
                f"flow complete for ua @ {entrypoint}",
                driver,
            )

        except Exception as err:
            if driver:
                try:
                    mark_test_status("failed", str(err), driver)
                except Exception as err:
                    print("error marking test status", str(err))
        finally:
            if driver:
                driver.quit()


def mark_test_status(status, reason, driver):
    payload = {
        'action': 'setSessionStatus',
        'arguments': {
            'status': status,    # 'passed' or 'failed'
            'reason': reason
        }
    }
    js = 'browserstack_executor: {}'.format(json.dumps(payload))
    driver.execute_script(js)


print("start script")

with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
    # Submit the tasks to the executor
    futures = [executor.submit(run_session, cap) for cap in desired_caps]

    # Wait for all tasks to complete
    concurrent.futures.wait(futures)
