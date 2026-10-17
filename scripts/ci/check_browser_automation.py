#!/usr/bin/env python3
"""Run the shared browser journey and local verifier regressions in both modes.

Use the same Python environment as the integration test (install
rama-fp/browser_automation/requirements.txt first). Separate processes avoid test
module-name collisions and ensure optimized Python cannot disable assertions.
"""

from pathlib import Path
import subprocess
import sys


def main():
    root = Path(__file__).resolve().parents[2]
    suites = (
        "rama-fp/browser_automation",
        "rama-fp/browserstack",
        "examples/tests/browser_profile",
    )
    for optimized in (False, True):
        for suite in suites:
            command = [sys.executable] + (["-O"] if optimized else [])
            command += [
                "-m",
                "unittest",
                "discover",
                "-s",
                str(root / suite),
                "-p",
                "test_*.py",
            ]
            subprocess.run(command, cwd=root / "rama-fp", check=True)
    # Test the actual page function driven by local and remote browser journeys.
    subprocess.run(
        ["node", "--test", "rama-fp/browser_automation/test_websocket.mjs"],
        cwd=root,
        check=True,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
