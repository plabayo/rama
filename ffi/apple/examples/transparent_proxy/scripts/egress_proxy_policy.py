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
import os
from pathlib import Path
import shlex
import signal
import socketserver
import subprocess
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[5]
HERE = Path(__file__).resolve().parent


def run(command, **kwargs):
    subprocess.run(command, check=True, **kwargs)


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
        script = ('function FindProxyForURL(url, host) { return "PROXY 127.0.0.1:%d"; }' % proxy.server_address[1]).encode()

        class PAC(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
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
    return ["swift", "test", "--package-path", str(ROOT), "--scratch-path", str(scratch),
            "-Xlinker", "-L" + str(library), "-Xlinker", "-lrama_tproxy_example", "-Xlinker", "-lz",
            "-Xlinker", "-framework", "-Xlinker", "NetworkExtension",
            "-Xlinker", "-framework", "-Xlinker", "SystemConfiguration"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--system-pac-service", help="exact macOS network service name")
    parser.add_argument("--allow-system-settings", action="store_true")
    parser.add_argument("--scratch-path", type=Path, default=ROOT / ".build")
    parser.add_argument("--skip-build", action="store_true", help="reuse a test binary built with matching sources")
    args = parser.parse_args()
    if bool(args.system_pac_service) != args.allow_system_settings:
        parser.error("system PAC testing requires both --system-pac-service and --allow-system-settings")
    command = swift_command(args.scratch_path)
    if args.skip_build:
        command.append("--skip-build")
    else:
        run(["cargo", "build", "--manifest-path", str(ROOT / "ffi/apple/examples/transparent_proxy/tproxy_rs/Cargo.toml")])
    run([*command, "--filter", "NativeTcpConnectionTests", "--skip", "NativeTcpConnectionTests.testDeveloperSystemProxyScenario"])
    if not args.system_pac_service:
        return
    # Build and snapshot before any mutation; keep artifacts on restoration error.
    directory = Path(tempfile.mkdtemp(prefix="rama-egress-pac-"))
    helper = directory / "settings"
    snapshot = directory / "original.plist"
    run(["swiftc", str(HERE / "egress_proxy_settings.swift"), "-o", str(helper)])
    run(["sudo", "-v"])
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(SystemExit(143)))
    with servers() as (proxy, url):
        run([str(helper), "capture", args.system_pac_service, str(snapshot), url])
        privileged = ["sudo", "-n", str(helper)]
        print("Recovery command:", shlex.join([*privileged, "restore", str(snapshot)]), flush=True)
        with settings_transaction(privileged, snapshot):
            time.sleep(2)  # Let SystemConfiguration publish the change.
            for allow in (True, False):
                with proxy.count_lock:
                    before = proxy.contacts
                env = dict(os.environ, RAMA_EGRESS_TEST_HOST="rama-egress-test.invalid", RAMA_EGRESS_TEST_PORT="443",
                           RAMA_EGRESS_TEST_ALLOW_PROXY=str(int(allow)), RAMA_EGRESS_TEST_USED_PROXY=str(int(allow)),
                           RAMA_EGRESS_TEST_EXPECT_FAILURE=str(int(not allow)))
                run([*command, "--filter", "NativeTcpConnectionTests.testDeveloperSystemProxyScenario"], env=env)
                with proxy.count_lock:
                    contacts = proxy.contacts - before
                if (allow and contacts < 1) or (not allow and contacts != 0):
                    raise RuntimeError(f"allow_proxy={allow}: unexpected proxy contacts={contacts}")
        print("System proxy settings restored and verified. Snapshot retained:", snapshot)


if __name__ == "__main__":
    main()
