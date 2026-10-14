#!/usr/bin/env python3
"""Resolve GitHub's newest advertised standard Xcode runner (no major pin)."""

import os
import re
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


def main():
    with urllib.request.urlopen(CATALOG, timeout=30) as response:
        runner = select_runner(response.read().decode("utf-8"))
    print(f"Newest advertised Xcode runner: {runner} ({CATALOG})")
    with open(os.environ["GITHUB_OUTPUT"], "a") as output:
        output.write(f"runner={runner}\n")


if __name__ == "__main__":
    main()
