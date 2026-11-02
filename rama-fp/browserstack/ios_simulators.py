"""Run every installed iOS runtime without leaving an unbounded simctl process."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import time


def simctl(*arguments, timeout=120, capture=False):
    print("simctl " + " ".join(arguments), flush=True)
    return subprocess.run(
        ["xcrun", "simctl", *arguments], check=True, timeout=timeout,
        capture_output=capture, text=True,
    ).stdout


def devices_by_runtime(devices, runtimes):
    versions = {runtime["identifier"]: runtime["version"] for runtime in runtimes
                if runtime.get("isAvailable") and ".iOS-" in runtime["identifier"]}
    selected = []
    for runtime, version in versions.items():
        iphones = [device for device in devices.get(runtime, [])
                   if device.get("isAvailable") and device["name"].startswith("iPhone")]
        if iphones:
            selected.append((version, iphones[0]["udid"]))
    if not selected:
        raise RuntimeError("no available iPhone simulator runtimes")
    return selected


def transition(command, udid, expected):
    for attempt in range(2):
        try:
            simctl(command, udid)
            return
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
            # simctl can hang after CoreSimulator has completed the transition.
            # Accept only the requested device's observed terminal state.
            devices = json.loads(simctl("list", "devices", "--json", capture=True))["devices"]
            if any(device["udid"] == udid and device["state"] == expected
                   for group in devices.values() for device in group):
                return
            if attempt:
                raise


def run_device(version, udid, output):
    try:
        transition("boot", udid, "Booted")
        simctl("bootstatus", udid, "-b", timeout=900)
        simctl("launch", udid, "com.apple.mobilesafari")
        # Safari's first launch can outlast safaridriver's connect timeout.
        time.sleep(15)
        simctl("terminate", udid, "com.apple.mobilesafari")
        subprocess.run(
            [sys.executable, str(Path(__file__).with_name("main.py")),
             "--output", str(output / ("ios-" + version)),
             "--device", "ios-simulator:" + version],
            check=True, timeout=1200,
        )
    finally:
        transition("shutdown", udid, "Shutdown")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    devices = json.loads(simctl("list", "devices", "available", "--json", capture=True))["devices"]
    runtimes = json.loads(simctl("list", "runtimes", "--json", capture=True))["runtimes"]
    failed = False
    for version, udid in devices_by_runtime(devices, runtimes):
        try:
            run_device(version, udid, args.output)
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError) as error:
            print(f"FAILED iOS {version}: {error}", file=sys.stderr, flush=True)
            failed = True
    return int(failed)


if __name__ == "__main__":
    sys.exit(main())
