#!/usr/bin/env python3
"""Keep HTTP and native relays usable without user-agent profile support.

Inspect Cargo's resolved normal dependencies rather than manifest text. Explicit
UA selections also verify that embedded profiles remain a separate choice.
"""

from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[2]


def check(package, features, *, ua=False, embedded=False):
    command = [
        "cargo", "tree", "--locked", "--offline",
        "-p", package, "--no-default-features", "--features", features,
        "--edges", "normal", "--prefix", "none", "--format", "{p} features={f}",
    ]
    graph = subprocess.run(
        command, cwd=ROOT, check=True, text=True, capture_output=True,
    ).stdout
    profiles = [line for line in graph.splitlines() if line.startswith("rama-ua ")]

    if bool(profiles) != ua:
        raise RuntimeError(f"{package} [{features}]: unexpected rama-ua dependency")

    for profile in profiles:
        enabled = profile.split(" features=", 1)[1].removesuffix(" (*)").split(",")
        if ("embed-profiles" in enabled) != embedded:
            raise RuntimeError(f"{package} [{features}]: unexpected embedded profiles")

    print(f"PASS {package} [{features}]: ua={ua}, embedded={embedded}")


def main():
    # Both HTTP tiers and the actual relay example must remain UA-independent.
    for features in ("http", "http,boring", "http-full,boring"):
        check("rama", features)
    check("rama-examples", "http-full,boring")

    # Classification and embedded datasets are separate, explicit selections.
    check("rama", "http-full,boring,ua", ua=True)
    check("rama", "http-full,boring,ua-embed-profiles", ua=True, embedded=True)
    check("rama", "cli", ua=True)


if __name__ == "__main__":
    main()
