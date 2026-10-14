#!/usr/bin/env python3
"""Resolve GitHub's newest advertised standard Xcode runner (no major pin)."""

import os
import re
import time
import urllib.error
import urllib.request

CATALOG = "https://raw.githubusercontent.com/actions/runner-images/main/README.md"


def select_runner(catalog):
    labels = set()
    for line in catalog.splitlines():
        cells = line.split("|")
        if len(cells) == 6 and cells[2].strip() == "arm64" and "deprecated" not in cells[1].lower():
            labels.update(re.findall(r"`(xcode-[0-9]+)`", cells[3]))
    if not labels:
        raise ValueError("No standard Xcode runner in GitHub's image catalog; review runner availability")
    return max(labels, key=lambda label: int(label.split("-")[1]))


def fetch_catalog():
    for attempt in range(3):
        try:
            with urllib.request.urlopen(CATALOG, timeout=30) as response:
                return response.read().decode("utf-8")
        except (urllib.error.URLError, TimeoutError) as error:
            if isinstance(error, urllib.error.HTTPError) and error.code not in (408, 429, 500, 502, 503, 504):
                raise
            if attempt == 2:
                raise
            time.sleep(2 ** attempt)


def main():
    runner = select_runner(fetch_catalog())
    print(f"Newest advertised Xcode runner: {runner} ({CATALOG})")
    with open(os.environ["GITHUB_OUTPUT"], "a") as output:
        output.write(f"runner={runner}\n")


if __name__ == "__main__":
    main()
