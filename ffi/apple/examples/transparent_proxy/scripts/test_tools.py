#!/usr/bin/env python3
"""Run the maintained script tests; skipped coverage is a failed gate."""

from pathlib import Path
import unittest


def main():
    directory = Path(__file__).resolve().parent
    suite = unittest.TestSuite(
        unittest.defaultTestLoader.discover(str(directory), pattern=pattern)
        for pattern in ("test_pressure_log.py", "test_udp_probe.py", "test_http_stress.py")
    )
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return int(not result.wasSuccessful() or bool(result.skipped) or result.testsRun == 0)


if __name__ == "__main__":
    raise SystemExit(main())
