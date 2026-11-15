#!/usr/bin/env python3
"""Exercise real ECH and baseline Chrome connections to the fp and echo binaries.

Uses disposable browser profiles, a local HTTPS DNS resolver and scoped SPKI
trust. No system DNS, trust store or existing browser profile is changed.
"""

import argparse
import base64
import hashlib
import html
import http.server
import importlib.util
import json
import os
from pathlib import Path
import re
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import urllib.parse

from ech_reference import answer


def require(condition, details):
    if not condition:
        raise RuntimeError(f"ECH service validation failed: {details}")


def free_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--browser", required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--openssl", default="openssl")
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--services", nargs="+", default=["echo", "fp"])
    parser.add_argument("--protocols", nargs="+", default=["h1", "h2", "h3", "auto"])
    args = parser.parse_args()
    root = args.evidence.resolve()
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    summaries = []
    with tempfile.TemporaryDirectory(prefix="rama-ech-service-keys-") as private_dir:
        private = Path(private_dir)
        spec = importlib.util.spec_from_file_location("ech_keygen", Path(__file__).parents[1] / "infra/scripts/ech_keygen.py")
        keygen = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(keygen)
        keys, config = keygen.generate(args.openssl, "baseline.test")
        key_file = private / "ech.json"
        key_file.write_text(json.dumps(keys))
        key_file.chmod(0o600)
        cert, key = private / "cert.pem", private / "key.pem"
        subprocess.run([
            args.openssl, "req", "-x509", "-newkey", "rsa:2048", "-noenc", "-days", "1",
            "-subj", "/CN=origin.test", "-addext", "subjectAltName=DNS:origin.test,DNS:baseline.test,DNS:doh.test",
            "-keyout", str(key), "-out", str(cert),
        ], check=True, capture_output=True)
        public = subprocess.check_output([args.openssl, "x509", "-in", str(cert), "-pubkey", "-noout"])
        public = subprocess.run([args.openssl, "pkey", "-pubin", "-outform", "DER"], input=public, check=True, capture_output=True).stdout
        spki = base64.b64encode(hashlib.sha256(public).digest()).decode()
        env = dict(os.environ, RUST_LOG="info", RAMA_TLS_ECH_KEYS_FILE=str(key_file),
                   RAMA_TLS_CRT=base64.b64encode(cert.read_bytes()).decode(),
                   RAMA_TLS_KEY=base64.b64encode(key.read_bytes()).decode())
        for name in list(env):
            if name.startswith("RAMA_TLS_REMOTE"):
                del env[name]
        for service in args.services:
            for protocol in args.protocols:
                port = free_port()
                queries = []
                alpn = {"h1": b"\x08http/1.1", "h2": b"\x02h2", "h3": b"\x02h3", "auto": b"\x02h3\x02h2\x08http/1.1"}[protocol]

                class Handler(http.server.BaseHTTPRequestHandler):
                    def do_POST(self):
                        self.respond(self.rfile.read(min(int(self.headers["Content-Length"]), 4096)))

                    def do_GET(self):
                        encoded = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)["dns"][0]
                        self.respond(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))

                    def respond(self, query):
                        response, host, kind = answer(query, port, base64.b64decode(config), alpn)
                        queries.append({"name": host, "type": kind})
                        self.send_response(200)
                        self.send_header("Content-Type", "application/dns-message")
                        self.send_header("Content-Length", str(len(response)))
                        self.end_headers()
                        self.wfile.write(response)

                    def log_message(self, *_args):
                        pass

                doh = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.load_cert_chain(cert, key)
                doh.socket = context.wrap_socket(doh.socket, server_side=True)
                threading.Thread(target=doh.serve_forever, daemon=True).start()
                command = [str(args.binary.resolve()), "serve", service, "--bind", f"127.0.0.1:{port}", "--http-version", protocol]
                command += ["--mode", "https"] if service == "echo" else ["-s"]
                if protocol == "auto":
                    command += ["--h3-bind", f"127.0.0.1:{port}"]
                server = None
                label = f"{service}-{protocol}"
                try:
                    with (root / f"{label}-server.log").open("w") as log:
                        server = subprocess.Popen(command, env=env, stdout=log, stderr=subprocess.STDOUT)
                    deadline = time.monotonic() + 30
                    while True:
                        if server.poll() is not None:
                            raise RuntimeError(f"{label}: service exited")
                        if protocol == "h3":
                            if "service ready" in (root / f"{label}-server.log").read_text().lower():
                                break
                        else:
                            try:
                                with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                                    break
                            except OSError:
                                pass
                        if time.monotonic() > deadline:
                            raise RuntimeError(f"{label}: service did not start")
                        time.sleep(0.2)
                    for host in ("baseline.test", "origin.test"):
                        with tempfile.TemporaryDirectory(prefix="rama-ech-chrome-") as profile:
                            default = Path(profile) / "Default"
                            default.mkdir()
                            settings = json.dumps({"dns_over_https": {"mode": "secure", "templates": f"https://doh.test:{doh.server_port}/dns-query"}, "async_dns": {"enabled": True}, "ssl": {"ech_enabled": True}})
                            (default / "Preferences").write_text(settings)
                            (Path(profile) / "Local State").write_text(settings)
                            command = [args.browser, "--headless=new", "--no-first-run", "--no-default-browser-check", "--disable-background-networking", "--no-proxy-server", "--host-resolver-rules=MAP doh.test 127.0.0.1", f"--user-data-dir={profile}", f"--ignore-certificate-errors-spki-list={spki}", f"--log-net-log={root / (label + '-' + host + '-netlog.json')}"]
                            if protocol in ("h1", "h2"):
                                command += ["--disable-quic"]
                            elif protocol == "h3":
                                command += ["--enable-quic", f"--origin-to-force-quic-on={host}:{port}"]
                            # Observe this connection without the full journey's asynchronous
                            # H3 reload racing Chrome's one-shot DOM snapshot.
                            command += ["--dump-dom", f"https://{host}:{port}/" + ("report?connection_only=1" if service == "fp" else "")]
                            browser = subprocess.run(command, capture_output=True, text=True, timeout=45)
                            (root / f"{label}-{host}.html").write_text(browser.stdout)
                            (root / f"{label}-{host}.log").write_text(browser.stderr)
                            text = html.unescape(re.sub(r"<[^>]*>", "", browser.stdout))
                            accepted = host == "origin.test"
                            if service == "echo":
                                data = json.loads(text)
                                require(data["ech_accepted"] is accepted, label)
                                require((data["tls_inner"] is not None) is accepted, label)
                                version = data["http"]["version"]
                                (root / f"{label}-{host}.json").write_text(json.dumps(data, indent=2))
                            else:
                                require(re.search(r"Encrypted ClientHello.{0,100}?Accepted\s*" + str(accepted).lower(), text, re.S), label)
                                require(("ECH Inner" in text) is accepted, label)
                                version = re.search(r"HTTP/[123](?:\.[01])?", text).group()
                            if protocol != "auto":
                                require(version.startswith({"h1": "HTTP/1", "h2": "HTTP/2", "h3": "HTTP/3"}[protocol]), (label, version))
                            summaries.append({"service": service, "protocol": protocol, "host": host, "version": version, "accepted": accepted})
                            print(summaries[-1], flush=True)
                finally:
                    if server is not None and server.poll() is None:
                        server.terminate()
                        try:
                            server.wait(timeout=10)
                        except subprocess.TimeoutExpired:
                            server.kill()
                            server.wait()
                    doh.shutdown()
                    doh.server_close()
                    (root / f"{label}-dns.json").write_text(json.dumps(queries, indent=2))
                    (root / "results.json").write_text(json.dumps(summaries, indent=2))


if __name__ == "__main__":
    main()
