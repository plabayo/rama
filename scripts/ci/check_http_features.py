#!/usr/bin/env python3
"""Keep HTTP and native relays usable without user-agent profile support.

Inspect Cargo's resolved normal dependencies rather than manifest text. Explicit
UA selections also verify that embedded profiles remain a separate choice.
"""

from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[2]
# `rama::cli::service` over TCP and HTTP. Without `quic` it has no HTTP/3 service.
CLI_SERVICES = "cli,http-backend,ws,tcp,dns,net,haproxy"
TLS_FREE = "http-backend,tcp,dns,test-utils"


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


def cargo(*args):
    subprocess.run(
        ["cargo", args[0], "--locked", "--no-default-features", *args[1:]],
        cwd=ROOT, check=True,
    )
    print(f"PASS cargo {' '.join(args)}")


def check_quic(features, expected):
    graph = subprocess.run(
        [
            "cargo", "tree", "--locked", "-p", "rama",
            "--edges", "normal", "--prefix", "none",
            "--no-default-features", "--features", features,
        ],
        cwd=ROOT, check=True, text=True, capture_output=True,
    ).stdout
    found = any(line.startswith("rama-quic ") for line in graph.splitlines())

    if found != expected:
        raise RuntimeError(f"rama [{features}]: rama-quic present={found}, expected={expected}")

    print(f"PASS rama [{features}]: quic={expected}")


def main():
    check_quic("http-backend", False)
    check_quic("http-backend,boring", False)
    check_quic("http-backend,fuzz-utils", False)
    check_quic("http-backend,quic", True)
    check_quic("http-full", True)

    # Both sides of the `quic` feature must build and keep their behavior.
    for quic in ("", ",quic"):
        cargo("check", "-p", "rama", "--features", f"{CLI_SERVICES}{quic}")
        cargo(
            "test", "-p", "rama", "--lib",
            "--features", f"{CLI_SERVICES},test-utils{quic}", "cli::service",
        )
        cargo("check", "-p", "rama", "--lib", "--tests", "--features", f"{TLS_FREE}{quic}")
        cargo("check", "-p", "rama", "--tests", "--features", f"{TLS_FREE},boring{quic}")
        cargo("check", "-p", "rama-http-core", "--features", f"fuzz-utils{quic}")
    cargo("test", "-p", "rama-http-backend", "--lib", "mixed_transport")
    cargo("test", "-p", "rama-http-backend", "--lib", "--features", "quic", "mixed_transport")

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
