#!/usr/bin/env python3
"""Keep HTTP and native relays usable without user-agent profile support.

Inspect Cargo's resolved normal dependencies rather than manifest text. Explicit
UA selections also verify that embedded profiles remain a separate choice.
"""

from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[2]


def check(package, features=None, *, manifest=None, ua=False, embedded=False):
    command = [
        "cargo", "tree", "--locked",
        "--edges", "normal", "--prefix", "none", "--format", "{p} features={f}",
    ]
    command += ["--manifest-path", manifest] if manifest else ["-p", package]
    if features is not None:
        command += ["--no-default-features", "--features", features]
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

    # The excluded Apple engine and harness have their own lockfiles. Cargo can
    # inspect their native dependency graphs on any host, without building Swift.
    for project, package in (
        ("tproxy_rs", "rama_tproxy_example"),
        ("tproxy_ffi_e2e", "rama_tproxy_ffi_e2e"),
    ):
        check(
            package,
            manifest=f"ffi/apple/examples/transparent_proxy/{project}/Cargo.toml",
        )

    # Classification and embedded datasets are separate, explicit selections.
    check("rama", "http-full,boring,ua", ua=True)
    check("rama", "http-full,boring,ua-embed-profiles", ua=True, embedded=True)
    check("rama", "cli", ua=True)


if __name__ == "__main__":
    main()
