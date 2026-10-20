#!/usr/bin/env python3
"""Exercise the production native adapter. System PAC mutation is explicit opt-in.

Default: local-only XCTest matrix (no admin or system settings changes).
Optional: --system-pac-service 'Wi-Fi' --allow-system-settings
Run on an isolated development Mac. This tests Network.framework, not a signed NE
provider or downstream identity stamping. SIGINT/SIGTERM and ordinary failures
restore settings; SIGKILL/power loss require the printed recovery command.
"""
import argparse
from contextlib import contextmanager
import http.server
import json
import os
import platform
import re
from pathlib import Path
import shlex
import signal
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
import zipfile

ROOT = Path(__file__).resolve().parents[5]
HERE = Path(__file__).resolve().parent
LOG = None
LOCAL_TESTS = set(re.findall(
    r"^    func (test\w+)\(",
    (ROOT / "ffi/apple/RamaAppleNetworkExtension/Tests/RamaAppleNetworkExtensionTests/NativeTcpConnectionTests.swift").read_text(),
    re.MULTILINE,
)) - {"testDeveloperSystemProxyScenario"}


def check_test_log(path, expected):
    # SwiftPM's serial runner omits xUnit output; its parallel runner labels
    # XCTest skips as passes. Require each actual XCTest completion instead.
    content = path.read_text()
    prefix = r"^Test Case '-\[RamaAppleNetworkExtensionTests\.NativeTcpConnectionTests (\w+)\]' "
    started = re.findall(prefix + r"started\.$", content, re.MULTILINE)
    completed = re.findall(prefix + r"(passed|failed|skipped) \(", content, re.MULTILINE)
    names = [name for name, _ in completed]
    if (set(started) != expected or len(started) != len(expected)
            or set(names) != expected or len(names) != len(expected)):
        raise RuntimeError(f"incomplete/unexpected test inventory: {names}; expected {sorted(expected)}")
    for name, status in completed:
        if status != "passed":
            raise RuntimeError(f"required test {name}: {status}")
    return len(completed)


def run(command, log_path=None, **kwargs):
    if LOG is None:
        subprocess.run(command, check=True, **kwargs)
        return
    print("+", shlex.join(map(str, command)), flush=True)
    LOG.write("+ " + shlex.join(map(str, command)) + "\n")
    LOG.flush()
    destination = log_path or Path(LOG.name)
    try:
        if log_path:
            with log_path.open("w") as output:
                subprocess.run(command, check=True, stdout=output, stderr=subprocess.STDOUT, **kwargs)
        else:
            subprocess.run(command, check=True, stdout=LOG, stderr=subprocess.STDOUT, **kwargs)
    except subprocess.CalledProcessError:
        LOG.flush()
        with destination.open("rb") as stream:
            stream.seek(max(0, destination.stat().st_size - 12000))
            tail = stream.read().decode("utf-8", errors="replace")
        print(f"Failed command log: {destination}\n{tail}", file=sys.stderr, flush=True)
        raise


@contextmanager
def settings_transaction(helper, snapshot):
    try:
        run([*helper, "apply", str(snapshot)])
        yield
    finally:
        # Also needed when CommitChanges succeeds but ApplyChanges fails.
        # Do not let a second Ctrl-C interrupt the restoration subprocess.
        handlers = {sig: signal.signal(sig, signal.SIG_IGN) for sig in (signal.SIGINT, signal.SIGTERM)}
        try:
            run([*helper, "restore", str(snapshot)])
        finally:
            for sig, handler in handlers.items():
                signal.signal(sig, handler)


class Proxy(socketserver.BaseRequestHandler):
    def handle(self):
        with self.server.count_lock:
            self.server.contacts += 1
        self.request.settimeout(20)
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = self.request.recv(65536)
            if not chunk:
                return
            data += chunk
            if len(data) > 65536:
                raise RuntimeError("CONNECT header too large")
        header, data = data.split(b"\r\n\r\n", 1)
        if not header.startswith(b"CONNECT rama-egress-test.invalid:443 "):
            self.request.sendall(b"HTTP/1.1 403 Forbidden\r\n\r\n")
            return
        self.request.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        while chunk := self.request.recv(65536):
            data += chunk
            if len(data) > 1024 * 1024:
                raise RuntimeError("test payload too large")
        self.request.sendall(data)


class Server(socketserver.ThreadingTCPServer):
    daemon_threads = True


@contextmanager
def servers():
    with Server(("127.0.0.1", 0), Proxy) as proxy:
        proxy.contacts = 0
        proxy.count_lock = threading.Lock()
        proxy.pac_fetches = 0
        script = ('function FindProxyForURL(url, host) { '
                  'if (host === "rama-egress-test.invalid") return "PROXY 127.0.0.1:%d"; '
                  'return "DIRECT"; }' % proxy.server_address[1]).encode()

        class PAC(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                with proxy.count_lock:
                    proxy.pac_fetches += 1
                self.send_response(200)
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Type", "application/x-ns-proxy-autoconfig")
                self.send_header("Content-Length", str(len(script)))
                self.end_headers()
                self.wfile.write(script)

            def log_message(self, *_):
                pass

        with http.server.ThreadingHTTPServer(("127.0.0.1", 0), PAC) as pac:
            threads = [threading.Thread(target=s.serve_forever, daemon=True) for s in (proxy, pac)]
            for thread in threads:
                thread.start()
            try:
                yield proxy, "http://127.0.0.1:%d/rama-%d.pac" % (pac.server_address[1], time.time_ns())
            finally:
                pac.shutdown()
                proxy.shutdown()
                for thread in threads:
                    thread.join()


def swift_command(scratch):
    library = ROOT / "ffi/apple/examples/transparent_proxy/tproxy_rs/target/debug"
    return ["swift", "test", "--traits", "PrivateNetworkProxyControl", "--disable-sandbox", "--package-path", str(ROOT), "--scratch-path", str(scratch),
            "-Xlinker", "-L" + str(library), "-Xlinker", "-lrama_tproxy_example", "-Xlinker", "-lz",
            "-Xlinker", "-framework", "-Xlinker", "NetworkExtension",
            "-Xlinker", "-framework", "-Xlinker", "SystemConfiguration"]


def run_suite(directory, report, name, command, expected, proxy=None, proxy_baseline=None, **kwargs):
    check = {"name": name, "status": "failed"}
    report["checks"].append(check)
    if proxy:
        with proxy.count_lock:
            before, before_fetches = proxy_baseline or (proxy.contacts, proxy.pac_fetches)
    try:
        log = directory / (name + ".log")
        run(command, log_path=log, **kwargs)
        check["passed"] = check_test_log(log, expected)
        check["status"] = "passed"
    finally:
        if proxy:
            with proxy.count_lock:
                check.update(proxy_contacts=proxy.contacts - before, pac_fetches=proxy.pac_fetches - before_fetches)
    return check


def execute(args, directory, report):
    if args.system_pac_service:
        # Fail before expensive builds or mutations; the just target authenticates.
        try:
            run(["sudo", "-n", "true"])
        except subprocess.CalledProcessError as error:
            raise RuntimeError("sudo authentication required: run just test-egress-policy-deep in your terminal") from error
    command = swift_command(args.scratch_path)
    if args.skip_build:
        command.append("--skip-build")
    else:
        library = ROOT / "ffi/apple/examples/transparent_proxy/tproxy_rs"
        run(["cargo", "build", "--manifest-path", str(library / "Cargo.toml"),
             "--target-dir", str(library / "target")])

    def suite(name, cmd, expected, **kwargs):
        return run_suite(directory, report, name, cmd, expected, **kwargs)

    expected = set(LOCAL_TESTS)
    unavailable = set()
    if int(platform.mac_ver()[0].split(".")[0]) < 14:
        unavailable = {"testExplicitProxyOptInAndPreferenceOnlyFallback", "testIPv6ProxyEndpointFormatting",
                       "testNoProxyDoesNotFallBackAfterDnsFailure"}
        expected -= unavailable
        report["unsupported_tests"] = {name: "requires macOS 14 proxy configuration" for name in sorted(unavailable)}
    skipped = unavailable | {"testDeveloperSystemProxyScenario"}
    local = ["--filter", "NativeTcpConnectionTests/", "--skip",
             "NativeTcpConnectionTests/(" + "|".join(sorted(skipped)) + ")$"]
    modes = ["debug", "release", "asan", "tsan"] if args.deep else (args.configuration or ["debug"])
    if args.system_pac_service and "debug" not in modes:
        raise ValueError("system PAC validation requires a debug build")
    for name in modes:
        scratch = args.scratch_path if name == "debug" else args.scratch_path.with_name(args.scratch_path.name + "-" + name)
        flags = {"debug": [], "release": ["-c", "release", "-Xswiftc", "-DRAMA_TESTING"],
                 "asan": ["--sanitize", "address"], "tsan": ["--sanitize", "thread"]}[name]
        env = dict(os.environ)
        if name == "tsan":
            env["TSAN_OPTIONS"] = "halt_on_error=1:exitcode=66"
        elif name == "asan":
            env["ASAN_OPTIONS"] = "halt_on_error=1:abort_on_error=1"
        suite("local-" + name, [*swift_command(scratch), *flags,
                               *(["--skip-build"] if args.skip_build else []), *local], expected, env=env)
    if not args.system_pac_service:
        return
    helper = directory / "settings"
    run(["swiftc", str(HERE / "egress_proxy_settings.swift"), "-o", str(helper)])
    # Builds can outlast sudo's ticket. Prompt in the developer's terminal again.
    run(["sudo", "-v"])
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(SystemExit(143)))
    with servers() as (proxy, url):
        for name, allow, missing in (("allowed", True, False), ("denied", False, False),
                                    ("missing-symbol", False, True)):
            snapshot = directory / ("original-" + name + ".plist")
            # A fresh URL makes proxy-using cases prove their own PAC evaluation.
            run([str(helper), "capture", args.system_pac_service, str(snapshot), url + "?case=" + name])
            privileged = ["sudo", "-n", str(helper)]
            recovery = shlex.join([*privileged, "restore", str(snapshot)])
            print("Recovery command:", recovery, flush=True)
            report["recovery_command"] = recovery
            report["settings_restored"] = False
            # macOS can fetch the PAC as soon as settings are applied.
            with proxy.count_lock:
                baseline = (proxy.contacts, proxy.pac_fetches)
            try:
                with settings_transaction(privileged, snapshot):
                    time.sleep(2)
                    uses_proxy = allow or missing
                    env = dict(os.environ, RAMA_EGRESS_TEST_HOST="rama-egress-test.invalid",
                               RAMA_EGRESS_TEST_PORT="443", RAMA_EGRESS_TEST_ALLOW_PROXY=str(int(allow)),
                               RAMA_EGRESS_TEST_MISSING_SYMBOL=str(int(missing)),
                               RAMA_EGRESS_TEST_USED_PROXY=str(int(uses_proxy)),
                               RAMA_EGRESS_TEST_EXPECT_FAILURE=str(int(not uses_proxy)))
                    check = suite("system-pac-" + name,
                          [*command, "--skip-build", "--filter",
                           "NativeTcpConnectionTests/testDeveloperSystemProxyScenario$"],
                          {"testDeveloperSystemProxyScenario"}, proxy=proxy, proxy_baseline=baseline, env=env)
                    contacts = check["proxy_contacts"]
                    if (uses_proxy and contacts < 1) or (not uses_proxy and contacts != 0):
                        check["status"] = "failed"
                        raise RuntimeError(f"{name}: unexpected proxy contacts={contacts}")
                    if uses_proxy and check["pac_fetches"] < 1:
                        check["status"] = "failed"
                        raise RuntimeError(f"{name}: no fresh PAC fetch observed")
            finally:
                run([*privileged, "restore", str(snapshot)])
                report["settings_restored"] = True
        print("System proxy settings restored and verified.")


def main():
    global LOG
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--system-pac-service", help="exact macOS network service name")
    parser.add_argument("--allow-system-settings", action="store_true")
    parser.add_argument("--configuration", action="append", choices=["debug", "release", "asan", "tsan"],
                        help="run selected matrices; repeatable, default: debug")
    parser.add_argument("--deep", action="store_true", help="also run Release, ASan and TSan matrices")
    parser.add_argument("--scratch-path", type=Path, default=ROOT / ".build/egress-policy")
    parser.add_argument("--skip-build", action="store_true", help="reuse matching binaries (local checks only)")
    args = parser.parse_args()
    if bool(args.system_pac_service) != args.allow_system_settings:
        parser.error("system PAC testing requires both --system-pac-service and --allow-system-settings")
    if args.deep and args.configuration:
        parser.error("choose --deep or --configuration")
    if args.skip_build and (args.deep or args.system_pac_service):
        parser.error("deep/system validation requires a fresh build")
    directory = Path(tempfile.mkdtemp(prefix="rama-egress-policy-"))
    report = {"status": "running", "macos": platform.mac_ver()[0], "architecture": platform.machine(),
              "commit": subprocess.check_output(["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True).strip(),
              "dirty": bool(subprocess.check_output(["git", "-C", str(ROOT), "status", "--porcelain"])),
              "system_pac_service": args.system_pac_service, "deep": args.deep, "checks": [],
              "not_covered": ["signed NE interception and downstream identity stamping",
                              "other macOS versions", "Rust sanitizer instrumentation"]}
    if not args.system_pac_service:
        report["not_covered"].append("live system PAC")
    print("Evidence directory:", directory, flush=True)
    try:
        with (directory / "run.log").open("w") as log:
            LOG = log
            execute(args, directory, report)
        report["status"] = "passed"
    except BaseException as error:
        report["status"] = "failed"
        report["error"] = str(error) or type(error).__name__
        raise
    finally:
        LOG = None
        (directory / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        archive = directory / "report.zip"
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as bundle:
            for path in [directory / "report.json", *directory.glob("*.log")]:
                bundle.write(path, path.name)
        print(f"Result: {report['status']}. Share this report: {archive}", flush=True)
        print("Signed-extension attribution is a separate check; it is not covered by this harness.")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"Error: {error}", file=sys.stderr)
        sys.exit(1)
