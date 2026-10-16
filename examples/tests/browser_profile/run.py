#!/usr/bin/env python3
"""Run the shared browser journey, capture profiles, and verify packet evidence.

H1 and TLS H2 include strict replay. H3 currently verifies original capture;
native QUIC connection-profile replay remains unfinished. Protocol-specific verifiers live
behind this common local/CI entry point.
"""

import argparse
import os
from pathlib import Path
import shutil
import signal
import sys

from disposable_postgres import run as run_isolated

HERE = Path(__file__).resolve().parent


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rama", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--protocol", choices=("h1", "h2", "h3"), required=True)
    parser.add_argument(
        "--browser", choices=("chrome", "firefox", "edge"), default="chrome"
    )
    parser.add_argument("--browser-binary", type=Path)
    parser.add_argument("--flows", choices=("all", "navigate"), default="all")
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
    if args.protocol == "h1" and args.browser == "edge":
        parser.error("the H1 replay fixture currently supports Chrome and Firefox")
    if args.protocol != "h1":
        if args.browser == "firefox" and args.protocol == "h3":
            parser.error("the H3 TLS fixture currently supports Chrome and Edge")
        if args.flows != "all":
            parser.error("H2/H3 verification requires all six operations")
    args.rama = args.rama.resolve(strict=True)
    args.output = args.output.resolve()
    if args.browser_binary is not None:
        args.browser_binary = args.browser_binary.resolve(strict=True)
    programs = ["docker", "dumpcap", "tshark"]
    if args.protocol != "h1":
        programs.append("openssl")
    if args.browser == "firefox" and args.protocol == "h2":
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
    if not args.inside_disposable_database:
        # Reject stale evidence before allocating a database or starting a browser.
        args.output.mkdir(parents=True, exist_ok=False, mode=0o700)
        return run_isolated(
            [
                sys.executable,
                str(Path(__file__).resolve()),
                *argv,
                "--inside-disposable-database",
            ],
            image_name=args.postgres_image,
        )

    def interrupted(number, _frame):
        raise InterruptedError(number)

    for number in (signal.SIGINT, signal.SIGTERM):
        signal.signal(number, interrupted)
    return execute(args)


if __name__ == "__main__":
    raise SystemExit(main())
