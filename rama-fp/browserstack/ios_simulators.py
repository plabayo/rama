"""Run every installed iOS runtime without leaving an unbounded simctl process."""
import argparse
import json
import os
from pathlib import Path
import signal
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


def probe_safari(version, timeout=600):
    """Wait for an automation session, not just a booted OS or a launched app.

    Run in a child process: the parent also bounds blocked WebDriver commands.
    No capture origin is visited, so readiness retries cannot hide flow failures.
    """
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from selenium.common.exceptions import WebDriverException
    from browser_automation.drivers import device_session

    deadline = time.monotonic() + timeout
    attempt = 0
    while True:
        attempt += 1
        try:
            with device_session("ios-simulator", version) as driver:
                driver.set_page_load_timeout(30)
                driver.get("about:blank")
                if driver.execute_script("return document.readyState") != "complete":
                    raise WebDriverException("Safari document is not ready")
            print(f"READY iOS {version}: Safari probe {attempt}", flush=True)
            return
        except WebDriverException as error:
            # Provider exception text can contain private data; log only its type.
            print(f"WAIT iOS {version}: Safari probe {attempt}: {type(error).__name__}",
                  flush=True)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("Safari automation did not become ready") from None
            time.sleep(min(10, remaining))


def run_bounded(arguments, timeout):
    """Bound the child and its driver processes, including a blocked probe/quit."""
    with subprocess.Popen(arguments, start_new_session=True) as process:
        try:
            returncode = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
            raise
        if returncode:
            raise subprocess.CalledProcessError(returncode, arguments)


def run_device(version, udid, output):
    output.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    receipt = {"version": version, "udid": udid, "status": "failed",
               "failure_stage": None, "error_type": None, "shutdown_error": None}
    stage = "boot"
    try:
        transition("boot", udid, "Booted")
        stage = "bootstatus"
        simctl("bootstatus", udid, "-b", timeout=900)
        stage = "safari_ready"
        # Booted does not mean Safari's remote automation is ready. Let the same
        # session owner as the collector prove it can open, script and quit Safari.
        # Avoid simctl terminate: it can hang even after a successful warm launch.
        run_bounded(
            [sys.executable, str(Path(__file__).resolve()), "--probe-safari", version],
            timeout=660,
        )
        stage = "journeys"
        run_bounded(
            [sys.executable, str(Path(__file__).with_name("main.py")),
             "--output", str(output / ("ios-" + version)),
             "--device", "ios-simulator:" + version],
            timeout=1200,
        )
        receipt["status"] = "passed"
    except Exception as error:
        receipt.update(failure_stage=stage, error_type=type(error).__name__)
        raise
    finally:
        try:
            transition("shutdown", udid, "Shutdown")
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError) as error:
            receipt["shutdown_error"] = type(error).__name__
            # A cleanup fault must fail a successful run without replacing the
            # original startup/journey fault when both failed.
            if receipt["failure_stage"] is None:
                receipt.update(status="failed", failure_stage="shutdown",
                               error_type=type(error).__name__)
                raise
        finally:
            receipt["elapsed_seconds"] = round(time.monotonic() - started, 3)
            (output / ("ios-" + version + "-simulator.json")).write_text(
                json.dumps(receipt, indent=2) + "\n"
            )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, nargs="?")
    parser.add_argument("--probe-safari", metavar="VERSION", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.probe_safari:
        probe_safari(args.probe_safari)
        return 0
    if args.output is None:
        parser.error("output is required")
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
