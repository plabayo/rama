#!/usr/bin/env python3
"""Disposable real browser -> fp archive -> Rama H1 replay -> tshark proof.

This exercises plaintext navigation or five request flows, not the complete browser matrix.
No existing database, browser profile, or network proxy is used.
"""
import argparse
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys

from disposable_postgres import run


def main(browser="chrome"):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rama", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(f"--{browser}", dest="browser_binary", type=Path)
    parser.add_argument("--interface", default="lo0" if platform.system() == "Darwin" else "lo")
    parser.add_argument("--postgres-image", default="postgres:17-alpine",
                        help="Locally cached image; no automatic image pulls")
    parser.add_argument("--flows", choices=("navigate", "all"), default="navigate")
    args = parser.parse_args()
    args.rama = args.rama.resolve(strict=True)
    if not args.browser_binary:
        candidates = (["/Applications/Firefox.app/Contents/MacOS/firefox",
                       shutil.which("firefox")] if browser == "firefox" else
                      ["/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
                       shutil.which("google-chrome"), shutil.which("chromium"),
                       shutil.which("chromium-browser")])
        args.browser_binary = next((Path(p) for p in candidates if p and Path(p).is_file()), None)
    if args.browser_binary is None:
        parser.error(f"{browser} not found; provide --{browser}")
    args.browser_binary = args.browser_binary.resolve(strict=True)
    for program in ("docker", "node", "dumpcap", "tshark"):
        if shutil.which(program) is None:
            parser.error(f"required executable not found: {program}")
    subprocess.run(["node", "-e", "if(typeof WebSocket !== 'function')process.exit(1)"],
                   check=True, timeout=10)
    # Refuse reuse so old observations cannot turn an unsuccessful run into a pass.
    args.output = args.output.resolve()
    args.output.mkdir(parents=True, exist_ok=False)
    args.output.chmod(0o700)
    environment = dict(os.environ,
                       RAMA_ROUNDTRIP_BINARY=str(args.rama),
                       RAMA_ROUNDTRIP_BROWSER=browser,
                       RAMA_ROUNDTRIP_FLOWS=args.flows,
                       RAMA_ROUNDTRIP_BROWSER_BINARY=str(args.browser_binary),
                       RAMA_ROUNDTRIP_OUTPUT=str(args.output),
                       RAMA_ROUNDTRIP_INTERFACE=args.interface)
    return run([sys.executable, str(Path(__file__).with_name("capture_h1.py"))],
               image_name=args.postgres_image, environment=environment)


if __name__ == "__main__":
    raise SystemExit(main())
