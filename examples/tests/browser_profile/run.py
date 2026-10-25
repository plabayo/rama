#!/usr/bin/env python3
"""Run the shared browser journey, capture profiles, and verify packet evidence.

All protocols replay admitted components through the same six operations.
Unsupported H3 startup patterns fail admission. Protocol-specific wire decoders
live behind this common local/CI entry point.
"""

import argparse
import os
from pathlib import Path
import shutil
import signal
import sys

from disposable_postgres import run as run_isolated
from native_postgres import run as run_native
from fixture_process import require_h3_tshark
from capture_environment import require_capture_environment

HERE = Path(__file__).resolve().parent


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rama", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--protocol", choices=("h1", "h2", "h3"), required=True)
    parser.add_argument(
        "--browser", choices=("chrome", "firefox", "edge", "safari"), default="chrome"
    )
    parser.add_argument("--browser-binary", type=Path)
    parser.add_argument("--postgres-backend", choices=("docker", "native"), default="docker")
    parser.add_argument("--safari-accept-insecure-certs", action="store_true",
                        help="Allow the ephemeral loopback certificate in this Safari automation session only")
    parser.add_argument("--flows", choices=("all", "navigate"), default="all")
    parser.add_argument(
        "--tls",
        action="store_true",
        help="Use HTTPS/WSS for H1; H2/H3 already require TLS",
    )
    parser.add_argument(
        "--interface", default="lo0" if sys.platform == "darwin" else "lo"
    )
    parser.add_argument(
        "--postgres-image",
        default="postgres:17-alpine",
        help="Locally cached image; no automatic image pulls",
    )
    parser.add_argument(
        "--inside-disposable-database", action="store_true", help=argparse.SUPPRESS
    )
    args = parser.parse_args(argv)
    if os.name != "posix":
        parser.error(
            "local packet/process integration currently requires Linux or macOS"
        )
    if args.protocol != "h1":
        if args.flows != "all":
            parser.error("H2/H3 verification requires all six operations")
    if args.tls and args.flows != "all":
        parser.error("TLS verification requires all six operations")
    args.rama = args.rama.resolve(strict=True)
    args.output = args.output.resolve()
    if args.browser_binary is not None:
        args.browser_binary = args.browser_binary.resolve(strict=True)
    if args.browser == "safari":
        if sys.platform != "darwin" or args.browser_binary is not None:
            parser.error("Safari requires macOS and its installed safaridriver")
        if (args.tls or args.protocol != "h1") and not args.safari_accept_insecure_certs:
            parser.error("Safari TLS fixtures require --safari-accept-insecure-certs (session-only)")
    elif args.safari_accept_insecure_certs:
        parser.error("--safari-accept-insecure-certs is Safari-only")
    programs = ["dumpcap", "tshark"]
    programs += ["docker"] if args.postgres_backend == "docker" else ["initdb", "pg_ctl", "psql"]
    if args.browser == "safari":
        programs.append("safaridriver")
    if args.tls or args.protocol != "h1":
        programs.append("openssl")
    if args.browser == "firefox" and (args.tls or args.protocol != "h1"):
        programs.append("certutil")
    for program in programs:
        if shutil.which(program) is None:
            parser.error("required executable not found: " + program)
    return args


def execute(args):
    """Run the selected protocol inside the common disposable database."""
    from capture import capture

    capture(args)
    return 0


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    args = parse_args(argv)
    if args.protocol == "h3":
        require_h3_tshark()
    if not args.inside_disposable_database:
        # Reject stale evidence before allocating a database or starting a browser.
        args.output.mkdir(parents=True, exist_ok=False, mode=0o700)
        if args.protocol == "h3":
            require_capture_environment(args.interface, args.output)
        database = run_native if args.postgres_backend == "native" else run_isolated
        database_options = {} if args.postgres_backend == "native" else {"image_name": args.postgres_image}
        return database(
            [
                sys.executable,
                str(Path(__file__).resolve()),
                *argv,
                "--inside-disposable-database",
            ],
            **database_options,
        )

    def interrupted(number, _frame):
        raise InterruptedError(number)

    for number in (signal.SIGINT, signal.SIGTERM):
        signal.signal(number, interrupted)
    return execute(args)


if __name__ == "__main__":
    raise SystemExit(main())
