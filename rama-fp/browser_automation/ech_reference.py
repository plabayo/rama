"""Direct Chrome -> local ECH server reference, with scoped DoH and trust.

No relay, global DNS changes, system trust changes or existing browser profile.
Run from the repository root with --browser pointing to a Chrome executable.
"""

import argparse
import base64
import hashlib
import http.server
import json
import os
from pathlib import Path
import ssl
import struct
import subprocess
import tempfile
import threading
import time
import urllib.parse


def answer(query, port, ech, alpn=b"\x08http/1.1"):
    """Answer one uncompressed IN question for the two controlled test names."""
    if len(query) < 12 or struct.unpack("!H", query[4:6])[0] != 1:
        raise ValueError("expected one DNS question")
    offset, labels = 12, []
    while query[offset]:
        length = query[offset]
        if length > 63:
            raise ValueError("compressed question")
        offset += 1
        labels.append(query[offset:offset + length].decode("ascii"))
        offset += length
    offset += 1
    qtype, qclass = struct.unpack("!HH", query[offset:offset + 4])
    end = offset + 4
    name = ".".join(labels).lower()
    records = []
    origin = name.split("._https.", 1)[-1]
    controlled = origin in ("origin.test", "baseline.test")
    if controlled and qclass == 1:
        if qtype == 1:
            records.append(b"\x7f\x00\x00\x01")
        elif qtype == 65:
            params = [(1, alpn), (3, struct.pack("!H", port))]
            if origin == "origin.test":
                params.append((5, ech))
            target = b"".join(bytes([len(label)]) + label.encode("ascii") for label in origin.split(".")) + b"\x00"
            records.append(b"\x00\x01" + target + b"".join(
                struct.pack("!HH", key, len(value)) + value for key, value in params
            ))
    header = query[:2] + struct.pack("!HHHHH", 0x8180 if controlled else 0x8183,
                                    1, len(records), 0, 0)
    return header + query[12:end] + b"".join(
        b"\xc0\x0c" + struct.pack("!HHIH", qtype, 1, 30, len(data)) + data
        for data in records
    ), name, qtype


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--browser", required=True)
    parser.add_argument("--evidence", type=Path)
    args = parser.parse_args()
    root = args.evidence or Path(tempfile.mkdtemp(prefix="rama-ech-reference-"))
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    root.chmod(0o700)
    if (root / "ready.json").exists():
        raise RuntimeError("use a fresh evidence directory")
    env = dict(os.environ, RAMA_ECH_BROWSER_EVIDENCE=str(root.resolve()))
    server = None
    doh = None
    try:
        with (root / "server.log").open("w") as log:
            server = subprocess.Popen([
                "cargo", "test", "-p", "rama-tls-boring", "--all-features",
                "browser_ech_reference", "--lib", "--", "--ignored", "--nocapture",
            ], env=env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        deadline = time.monotonic() + 180
        while not (root / "ready.json").exists():
            if server.poll() is not None or time.monotonic() > deadline:
                raise RuntimeError(f"reference server failed; see {root / 'server.log'}")
            time.sleep(0.2)
        port = json.loads((root / "ready.json").read_text())["port"]
        ech = (root / "ech-config.bin").read_bytes()
        queries = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                self.respond(self.rfile.read(min(int(self.headers["Content-Length"]), 4096)))

            def do_GET(self):
                encoded = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)["dns"][0]
                self.respond(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))

            def respond(self, query):
                response, name, qtype = answer(query, port, ech)
                queries.append({"name": name, "type": qtype})
                self.send_response(200)
                self.send_header("Content-Type", "application/dns-message")
                self.send_header("Content-Length", str(len(response)))
                self.end_headers()
                self.wfile.write(response)

            def log_message(self, *_args):
                pass

        doh = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(root / "server.pem", root / "server-key.pem")
        doh.socket = context.wrap_socket(doh.socket, server_side=True)
        threading.Thread(target=doh.serve_forever, daemon=True).start()
        public = subprocess.check_output(["openssl", "x509", "-in", str(root / "server.pem"), "-pubkey", "-noout"])
        public = subprocess.run(["openssl", "pkey", "-pubin", "-outform", "DER"], input=public, check=True, capture_output=True).stdout
        spki = base64.b64encode(hashlib.sha256(public).digest()).decode()
        version = subprocess.check_output([args.browser, "--version"], text=True).strip()
        for host in ("baseline.test", "origin.test"):
            with tempfile.TemporaryDirectory(prefix="rama-ech-chrome-") as profile:
                default = Path(profile) / "Default"
                default.mkdir()
                preferences = json.dumps({
                    "dns_over_https": {"mode": "secure", "templates": f"https://doh.test:{doh.server_port}/dns-query"},
                    "async_dns": {"enabled": True},
                    "ssl": {"ech_enabled": True},
                })
                (default / "Preferences").write_text(preferences)
                (Path(profile) / "Local State").write_text(preferences)
                command = [
                    args.browser, "--headless=new", "--no-first-run", "--no-default-browser-check",
                    "--disable-background-networking", "--no-proxy-server", "--disable-quic",
                    "--host-resolver-rules=MAP doh.test 127.0.0.1",
                    f"--user-data-dir={profile}", f"--ignore-certificate-errors-spki-list={spki}",
                    f"--log-net-log={root / (host + '-netlog.json')}",
                    "--dump-dom", f"https://{host}:{port}/",
                ]
                result = subprocess.run(command, capture_output=True, text=True, timeout=45)
                (root / (host + ".html")).write_text(result.stdout)
                (root / (host + ".log")).write_text(result.stderr)
                expected = "true" if host == "origin.test" else "false"
                if f"ECH accepted: {expected}" not in result.stdout:
                    raise RuntimeError(f"{host}: acceptance not observed; inspect {root}")
        (root / "browser.json").write_text(json.dumps({"version": version, "queries": queries}, indent=2))
        print(f"Direct browser real-ECH and baseline accepted: {root}")
    finally:
        if doh is not None:
            doh.shutdown()
            doh.server_close()
        if server is not None and server.poll() is None:
            import signal
            os.killpg(server.pid, signal.SIGTERM)
            server.wait(timeout=10)
        if "queries" in locals():
            (root / "dns-queries.json").write_text(json.dumps(queries, indent=2))
        (root / "server-key.pem").unlink(missing_ok=True)


if __name__ == "__main__":
    main()
