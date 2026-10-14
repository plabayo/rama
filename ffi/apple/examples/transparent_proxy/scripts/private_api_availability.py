#!/usr/bin/env python3
"""Probe the newest installed Xcode's SDK exports and macOS/iOS simulator runtime.

Use --download-ios-runtime in disposable CI to require a runtime matching the SDK.
This never changes proxy settings or claims physical-device/attribution coverage.
"""

import argparse
import json
import os
from pathlib import Path
import platform
import plistlib
import re
import shlex
import subprocess
import tempfile

SYMBOL = "nw_parameters_set_no_proxy"
SOURCE = Path(__file__).with_name("private_api_probe.m")


def version(value):
    return tuple(int(part) for part in re.findall(r"\d+", value))


def newest_xcode(applications=Path("/Applications"), stable=False):
    candidates = []
    for app in sorted({p.resolve() for p in applications.glob("Xcode*.app")}):
        with (app / "Contents/version.plist").open("rb") as source:
            info = plistlib.load(source)
        build = info.get("ProductBuildVersion", "")
        if stable and (re.search(r"beta|preview|\brc\b", app.name, re.IGNORECASE)
                       or (build and not build[-1].isdigit())):
            continue
        candidates.append((version(info["CFBundleShortVersionString"]),
                           version(info["CFBundleVersion"]), app))
    if not candidates:
        raise ValueError("No Xcode installation found")
    return max(candidates)[2] / "Contents/Developer"


def newest_runtime(runtimes):
    ios = [r for r in runtimes if r["identifier"].startswith("com.apple.CoreSimulator.SimRuntime.iOS-")]
    if not ios:
        raise ValueError("No iOS simulator runtime installed")
    runtime = max(ios, key=lambda r: (version(r["version"]), r["buildversion"]))
    if not runtime.get("isAvailable"):
        raise ValueError(f"Newest iOS runtime is unavailable: {runtime}")
    return runtime


def probe_result(output, expected_platform):
    result = json.loads(output)
    if (result.get("symbol") != SYMBOL or result.get("platform") != expected_platform
            or result.get("called_true_and_false") is not True or not result.get("os")):
        raise ValueError(f"Incomplete probe result: {result}")
    return result


class Probe:
    def __init__(self, output, developer):
        self.output = output
        self.env = {**os.environ, "DEVELOPER_DIR": str(developer)}
        self.report = {"developer_dir": str(developer), "checks": {},
                       "runner_image": os.environ.get("ImageVersion"),
                       "scope": "SDK exports and runtime calls; no device, PAC or signed attribution check"}
        self.counter = 0

    def run(self, *args, timeout=120):
        command = [str(arg) for arg in args]
        print("+", shlex.join(command), flush=True)
        self.counter += 1
        log = self.output / f"{self.counter:02d}.log"
        with log.open("w") as stream:
            stream.write(shlex.join(command) + "\n")
            stream.flush()
            result = subprocess.run(command, env=self.env, stdout=stream,
                                    stderr=subprocess.STDOUT, timeout=timeout)
        text = log.read_text().split("\n", 1)[1]
        if result.returncode:
            raise RuntimeError(f"Exit {result.returncode}: {log}\n{text[-4000:]}")
        return text.strip()

    def check(self, name, function):
        try:
            self.report["checks"][name] = {"status": "passed", "detail": function()}
        except Exception as error:
            self.report["checks"][name] = {"status": "failed", "error": str(error)}
            print(f"{name}: {error}", flush=True)
        self.save()

    def save(self):
        (self.output / "report.json").write_text(json.dumps(self.report, indent=2) + "\n")

    def compile(self, sdk, target, name, link_only=False):
        sdk_path = self.run("xcrun", "--sdk", sdk, "--show-sdk-path")
        self.report.setdefault("sdks", {})[sdk] = {
            "version": self.run("xcrun", "--sdk", sdk, "--show-sdk-version"),
            "build": self.run("xcrun", "--sdk", sdk, "--show-sdk-build-version"),
        }
        binary = self.output / name
        self.run("xcrun", "--sdk", sdk, "clang", "-target", target, "-isysroot", sdk_path,
                 "-fobjc-arc", "-fblocks", "-Wall", "-Wextra", "-Werror",
                 *(["-DRAMA_PROBE_LINK_ONLY=1"] if link_only else []), SOURCE,
                 "-framework", "Foundation", "-framework", "Network", "-o", binary)
        return binary

    def macos(self):
        binary = self.compile("macosx", f"{platform.machine()}-apple-macos12.0", "macos-runtime")
        return probe_result(self.run(binary), "macos")

    def sdk_export(self, sdk, target):
        self.compile(sdk, target, f"{sdk}-link", link_only=True)
        return "Direct reference linked successfully (not executed)"

    def simulator(self, download, stable=False):
        sdk_version = self.run("xcrun", "--sdk", "iphonesimulator", "--show-sdk-version")
        def inventory():
            runtimes = json.loads(self.run("xcrun", "simctl", "list", "runtimes", "--json"))["runtimes"]
            return [r for r in runtimes if not stable or r["buildversion"][-1].isdigit()]

        def matches(runtime):
            return runtime.get("isAvailable") and version(runtime["version"])[:2] >= version(sdk_version)[:2]

        runtimes = inventory()
        ios = [r for r in runtimes if r["identifier"].startswith("com.apple.CoreSimulator.SimRuntime.iOS-")]
        if download and not any(matches(r) for r in ios):
            try:
                self.run("xcodebuild", "-downloadPlatform", "iOS", "-buildVersion", sdk_version,
                         "-architectureVariant", "arm64", timeout=1800)
            except RuntimeError as error:
                # Beta catalogs may require Xcode's default selection rather than
                # the bare SDK version. Other download failures remain failures.
                if not any(text in str(error) for text in ("not available for download", "No needed downloadables")):
                    raise
                self.report["versioned_download_error"] = str(error)
                self.run("xcodebuild", "-downloadPlatform", "iOS",
                         "-architectureVariant", "arm64", timeout=1800)
            runtimes = inventory()
        runtime = newest_runtime(runtimes)
        self.report["simulator_runtime"] = {key: runtime[key] for key in ("identifier", "version", "buildversion")}
        if download and not matches(runtime):
            raise ValueError(f"Newest runtime {runtime['version']} is older than SDK {sdk_version}")
        devices = runtime.get("supportedDeviceTypes", [])
        device = next((d for d in devices if d.get("productFamily") == "iPhone"), None)
        if device is None:
            raise ValueError("Runtime does not advertise a supported iPhone device type")
        binary = self.compile("iphonesimulator",
                              f"{platform.machine()}-apple-ios{runtime['version']}-simulator", "ios-runtime")
        # Only this temporary device is booted/removed; existing simulators are untouched.
        udid = self.run("xcrun", "simctl", "create", "Rama private API probe",
                        device["identifier"], runtime["identifier"])
        try:
            self.run("xcrun", "simctl", "boot", udid)
            # Fresh hosted-runner devices can spend over five minutes in
            # CoreLocation's first-boot data migration after a runtime download.
            self.run("xcrun", "simctl", "bootstatus", udid, "-b", timeout=900)
            return probe_result(self.run("xcrun", "simctl", "spawn", udid, binary), "ios-simulator")
        finally:
            # Keep cleanup failures separate, so they cannot hide the probe error.
            self.check("simulator-shutdown", lambda: self.run("xcrun", "simctl", "shutdown", udid))
            self.check("simulator-delete", lambda: self.run("xcrun", "simctl", "delete", udid))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--download-ios-runtime", action="store_true")
    parser.add_argument("--stable", action="store_true", help="exclude beta and release-candidate Xcodes")
    parser.add_argument("--select-xcode", action="store_true", help="print newest DEVELOPER_DIR and exit")
    args = parser.parse_args()
    developer = newest_xcode(stable=args.stable)
    if args.select_xcode:
        print(developer)
        return 0
    output = args.output or Path(tempfile.mkdtemp(prefix="rama-private-api-"))
    output.mkdir(parents=True, exist_ok=True)
    probe = Probe(output.resolve(), developer)
    probe.check("toolchain", lambda: probe.run("xcodebuild", "-version") + "\n" + probe.run("sw_vers"))
    probe.check("macos-runtime", probe.macos)
    probe.check("macos-sdk", lambda: probe.sdk_export("macosx", "arm64-apple-macos12.0"))
    probe.check("ios-device-sdk", lambda: probe.sdk_export("iphoneos", "arm64-apple-ios15.0"))
    probe.check("ios-simulator-runtime", lambda: probe.simulator(args.download_ios_runtime, stable=args.stable))
    report = output / "report.json"
    print(f"Report: {report}")
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as summary:
            summary.write("### Apple private API availability\n\n```json\n" + report.read_text() + "```\n")
    return int(any(check["status"] != "passed" for check in probe.report["checks"].values()))


if __name__ == "__main__":
    raise SystemExit(main())
