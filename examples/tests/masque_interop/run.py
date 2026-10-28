#!/usr/bin/env python3
"""Independent CONNECT-UDP peers, HTTP/3 tunnel workloads, and datagram/policy checks.

Results go to OUTPUT/results.json with process logs alongside.
"""

import argparse
import json
import os
import re
from collections import Counter
from pathlib import Path
import socket
import subprocess
import sys
import time
import threading
import signal

ROOT = Path(__file__).resolve().parents[3]
RAMA_TEMPLATE = "/.well-known/masque/udp/{target_host}/{target_port}/"
PEER_TEMPLATE = "/masque?h={target_host}&p={target_port}"


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--rama", type=Path, required=True, help="Built rama binary")
    parser.add_argument("--peer", type=Path, required=True, help="Built masque-go peer")
    parser.add_argument("--runs", type=int, default=10)
    args = parser.parse_args(argv)
    if args.runs < 1:
        parser.error("--runs must be positive")
    return args


def free_port():
    """A port free on loopback for both TCP and UDP."""
    while True:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp:
            tcp.bind(("127.0.0.1", 0))
            port = tcp.getsockname()[1]
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
                try:
                    udp.bind(("127.0.0.1", port))
                except OSError:
                    continue
            return port


def wait_tcp(port, deadline=15.0):
    start = time.monotonic()
    while time.monotonic() - start < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.1)
    raise TimeoutError(f"nothing listens on 127.0.0.1:{port}")


# The shutdown gate reads Rama's info-level "gracefully shutdown" line, whatever the caller's level.
RAMA_LOG = "info"


def child_env(environ):
    """The environment of a started process: the caller's, with Rama's log level fixed."""
    env = dict(environ)
    env["RUST_LOG"] = RAMA_LOG
    for key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"):
        env.pop(key, None)
        env.pop(key.lower(), None)
    env["NO_PROXY"] = ""
    env["no_proxy"] = ""
    env["NO_COLOR"] = "1"
    return env


class Processes:
    """Started processes, each logging to OUTPUT/<name>.log, stopped on exit.

    `stopped` records how each one ended: its exit code after SIGTERM, and for Rama whether
    its graceful shutdown completed.
    """

    def __init__(self, output):
        self.output = output
        self.running = []
        self.stopped = {}

    def start(self, name, argv):
        log = open(self.output / f"{name}.log", "w")
        process = subprocess.Popen(
            argv, stdout=log, stderr=subprocess.STDOUT, text=True, env=child_env(os.environ)
        )
        self.running.append((name, process, log))
        return process

    def stop(self):
        for name, process, log in reversed(self.running):
            running = process.poll() is None
            if running:
                process.terminate()
            try:
                code = process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                code = process.wait(timeout=5)
            log.close()
            text = (self.output / f"{name}.log").read_text()
            self.stopped[name] = {
                "exit_code": code,
                "graceful": "gracefully shutdown" in text if name.startswith("rama") else None,
                "clean_exit": code == 0 if name.startswith("rama") else code == 0 or (running and code == -signal.SIGTERM),
            }
        self.running = []

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.stop()


def start_origin(processes, rama, name):
    port = free_port()
    processes.start(
        name,
        [str(rama), "serve", "echo", "--mode", "https", "--bind", f"127.0.0.1:{port}"],
    )
    wait_tcp(port)
    return port


def start_peer_proxy(processes, peer, output):
    port = free_port()
    template = f"https://127.0.0.1:{port}{PEER_TEMPLATE}"
    processes.start("masque-go-proxy", [str(peer), "proxy", "-t", template, "-b", f"127.0.0.1:{port}"])
    log = output / "masque-go-proxy.log"
    start = time.monotonic()
    while "ready" not in log.read_text():
        if time.monotonic() - start > 15:
            raise TimeoutError("masque-go proxy did not start")
        time.sleep(0.1)
    return template


def rama_client_cell(processes, args, output):
    origin = start_peer_origin(processes, args.peer, output)
    template = start_peer_proxy(processes, args.peer, output)
    proxy = template.replace("https://", "masque://", 1)
    runs = []
    for run in range(1, args.runs + 1):
        payload = (f"independent-tunnel-{run}-" * 5000).encode()
        payload_file = output / f"payload-{run}.bin"
        payload_file.write_bytes(payload)
        result = subprocess.run(
            [
                str(args.rama),
                "send",
                "--http3",
                "--show-headers",
                "--insecure",
                "--proxy-insecure",
                "--proxy",
                proxy,
                f"https://127.0.0.1:{origin}/echo",
                "--data", "@" + str(payload_file), "--binary",
            ],
            capture_output=True,
            text=True,
            timeout=30,
            env=child_env(os.environ),
        )
        (output / f"rama-client-run-{run}.log").write_text(result.stdout + result.stderr)
        observed = re.findall(r"request peer=(\S+) path=/echo", (output / "quic-go-origin.log").read_text())
        egress = re.findall(r"tunnel egress=(\S+) target=", (output / "masque-go-proxy.log").read_text())
        traversed = len(observed) == run and observed[-1] in egress
        runs.append({"run": run, "ok": result.returncode == 0 and "HTTP/3.0 200 OK" in result.stderr
                     and payload.decode() == result.stdout and traversed,
                     "tunnel_verified": traversed, "bytes": len(payload), "exit_code": result.returncode})
    return runs


def masque_go_client_cell(processes, args, output):
    origin = start_origin(processes, args.rama, "rama-origin")
    proxy = free_port()
    processes.start(
        "rama-proxy",
        [
            str(args.rama),
            "serve",
            "proxy",
            "--bind",
            f"127.0.0.1:{proxy}",
            "--protocol",
            "masque",
            "--masque-allow-private",
        ],
    )
    wait_tcp(proxy)
    result = subprocess.run(
        [
            str(args.peer),
            "client",
            "-t",
            f"https://127.0.0.1:{proxy}{RAMA_TEMPLATE}",
            "-n",
            str(args.runs),
            f"https://127.0.0.1:{origin}/",
        ],
        capture_output=True,
        text=True,
        timeout=30 * args.runs,
        env=child_env(os.environ),
    )
    (output / "masque-go-client.log").write_text(result.stdout + result.stderr)
    return client_runs(result.stdout, result.returncode, args.runs)


def client_runs(stdout, returncode, runs):
    """The runs the masque-go client reported, all failed unless it also exited cleanly."""
    succeeded = Counter(
        int(match.group(1))
        for line in stdout.splitlines()
        if (match := re.fullmatch(r'run ([1-9][0-9]*) ok: .+', line))
    )
    valid = all(1 <= run <= runs and count == 1 for run, count in succeeded.items())
    return [
        {"run": run, "ok": valid and returncode == 0 and succeeded[run] == 1, "exit_code": returncode}
        for run in range(1, runs + 1)
    ]


def start_peer_origin(processes, peer, output):
    port = free_port()
    processes.start("quic-go-origin", [str(peer), "coverage", "-mode", "server", "-address", f"127.0.0.1:{port}"])
    start = time.monotonic()
    while '"address"' not in (output / "quic-go-origin.log").read_text():
        if time.monotonic() - start > 15:
            raise TimeoutError("independent H3 origin did not start")
        time.sleep(0.1)
    return port


def start_rama_proxy(processes, rama, name, *, auth=None, allow_private=True, protocol="masque", extra=()):
    port = free_port()
    argv = [str(rama), "serve", "proxy", "--bind", f"127.0.0.1:{port}", "--protocol", protocol, *extra]
    if allow_private:
        argv.append("--masque-allow-private")
    if auth:
        argv.extend(["--proxy-auth", auth])
    processes.start(name, argv)
    wait_tcp(port)
    return port


def peer_coverage(args, output, name, *flags):
    result = subprocess.run([str(args.peer), "coverage", *flags], capture_output=True, text=True,
                            timeout=60, env=child_env(os.environ))
    (output / f"{name}.log").write_text(result.stdout + result.stderr)
    try:
        evidence = json.loads(result.stdout)
    except json.JSONDecodeError:
        evidence = {}
    return {"case": name, "ok": result.returncode == 0 and evidence.get("ok") is True,
            "exit_code": result.returncode, "evidence": evidence}


def tunnel_workload_cell(processes, args, output):
    origin = start_peer_origin(processes, args.peer, output)
    proxy = start_rama_proxy(processes, args.rama, "rama-proxy")
    return [peer_coverage(args, output, "streaming-multiplexing-cancellation", "-mode", "tunneled-client",
                          "-address", f"127.0.0.1:{proxy}", "-target", f"127.0.0.1:{origin}")]


def datagram_cell(processes, args, output, *, capsule=False):
    proxy = start_rama_proxy(processes, args.rama, "rama-proxy")
    authenticated = start_rama_proxy(processes, args.rama, "rama-auth-proxy", auth="interop:secret")
    restricted = start_rama_proxy(processes, args.rama, "rama-restricted-proxy", allow_private=False)
    results = []
    for family, host in ((socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")):
        with socket.socket(family, socket.SOCK_DGRAM) as echo:
            echo.bind((host, 0))
            echo.settimeout(0.2)
            stopped = threading.Event()
            received = []
            def respond():
                while not stopped.is_set():
                    try:
                        data, sender = echo.recvfrom(65535)
                        received.append(data)
                        echo.sendto(data, sender)
                    except socket.timeout:
                        continue
            thread = threading.Thread(target=respond)
            thread.start()
            target = f"{host}:{echo.getsockname()[1]}" if family == socket.AF_INET else f"[{host}]:{echo.getsockname()[1]}"
            try:
                for name, port, extra in (
                    ("datagrams", proxy, []),
                    ("authenticated", authenticated, ["-auth", "Basic aW50ZXJvcDpzZWNyZXQ="]),
                    ("missing-auth", authenticated, ["-expect-status", "407"]),
                    ("wrong-auth", authenticated, ["-auth", "Basic d3Jvbmc6d3Jvbmc=", "-expect-status", "407"]),
                    ("private-denied", restricted, ["-expect-status", "502"]),
                ):
                    for carrier in (("h1", "h2", "h3") if capsule else ("native",)):
                        before = len(received)
                        mode = ["-mode", "capsule-client", "-carrier", carrier] if capsule else ["-mode", "masque-client"]
                        result = peer_coverage(args, output, f"{name}-{family.name}-{carrier}", *mode,
                                               "-address", f"127.0.0.1:{port}", "-target", target, *extra)
                        packets = len(received) - before
                        result["target_datagrams"] = packets
                        result["ok"] &= packets == (32 if name in ("datagrams", "authenticated") else 0)
                        results.append(result)
            finally:
                stopped.set()
                thread.join(timeout=2)
    return results


def capsule_cell(processes, args, output):
    return datagram_cell(processes, args, output, capsule=True)


def interception_cell(processes, args, output):
    inner = start_rama_proxy(processes, args.rama, "rama-inner-proxy", auth="inner:secret",
                             extra=("--masque-template", "/custom{?target_host,target_port}"))
    front = start_rama_proxy(processes, args.rama, "rama-mitm-proxy", auth="outer:x", extra=("--mitm",))
    front_tcp = start_rama_proxy(processes, args.rama, "rama-mitm-tcp", auth="outer:x",
                                 protocol="http", extra=("--mitm",))
    results = []
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as echo:
        echo.bind(("127.0.0.1", 0))
        echo.settimeout(0.2)
        received = []
        stopped = threading.Event()
        def respond():
            while not stopped.is_set():
                try:
                    data, sender = echo.recvfrom(65535)
                    received.append(data)
                    echo.sendto(data, sender)
                except socket.timeout:
                    continue
        thread = threading.Thread(target=respond)
        thread.start()
        try:
            for carrier in ("h1", "h2", "h3", "native"):
                baseline = None
                for name, extra, expected in (
                    ("direct", [], 32),
                    ("intercepted", ["-via", f"127.0.0.1:{front if carrier in ('h3', 'native') else front_tcp}",
                                      "-via-auth", "Basic b3V0ZXI6eA=="], 32),
                    ("inner-auth-refused", ["-via", f"127.0.0.1:{front if carrier in ('h3', 'native') else front_tcp}",
                                            "-via-auth", "Basic b3V0ZXI6eA==",
                                            "-expect-status", "407"], 0),
                ):
                    before = len(received)
                    mode = ["-mode", "masque-client"] if carrier == "native" else ["-mode", "capsule-client", "-carrier", carrier]
                    if carrier == "native" and name == "intercepted":
                        expected = 24  # nested native path MTU; capsules also cover 1200-byte payloads
                    inner_auth = "Basic aW5uZXI6d3Jvbmc=" if name == "inner-auth-refused" else "Basic aW5uZXI6c2VjcmV0"
                    result = peer_coverage(args, output, f"{name}-{carrier}", *mode,
                                           "-address", f"127.0.0.1:{inner}",
                                           "-template", "/custom{?target_host,target_port}",
                                           "-target", f"127.0.0.1:{echo.getsockname()[1]}",
                                           "-auth", inner_auth, *extra)
                    result["target_datagrams"] = len(received) - before
                    result["ok"] &= result["target_datagrams"] == expected
                    certificate = result["evidence"].get("peer_certificate_sha256")
                    if name == "direct":
                        baseline = certificate
                    else:
                        result["interception_verified"] = bool(certificate and baseline and certificate != baseline)
                        result["ok"] &= result["interception_verified"]
                    results.append(result)
        finally:
            stopped.set()
            thread.join(timeout=2)
    return results


def main(argv=None):
    args = parse_args(argv)
    args.output.mkdir(parents=True, exist_ok=False)
    results = {}
    for name, cell in (
        ("rama-client", rama_client_cell),
        ("masque-go-client", masque_go_client_cell),
        ("tunneled-http3", tunnel_workload_cell),
        ("datagrams-and-policy", datagram_cell),
        ("capsules-and-policy", capsule_cell),
        ("transparent-interception", interception_cell),
    ):
        cell_output = args.output / name
        cell_output.mkdir()
        started = time.monotonic()
        with Processes(cell_output) as processes:
            try:
                runs = cell(processes, args, cell_output)
                result = {"runs": runs}
            except Exception as error:  # noqa: BLE001 - every cell reports its own failure
                result = {"error": repr(error), "runs": []}
            processes.stop()
            result["processes"] = processes.stopped
            # Every Rama process must shut down gracefully once its peers are done.
            clean = all(process["clean_exit"] and process["graceful"] is not False
                        for process in processes.stopped.values())
            result["passed"] = bool(result["runs"]) and all(run["ok"] for run in result["runs"]) and clean
            result["elapsed_seconds"] = time.monotonic() - started
            results[name] = result
    (args.output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    print(json.dumps({name: cell["passed"] for name, cell in results.items()}))
    for name, result in results.items():
        if not result["passed"]:
            print(f"FAILED {name}: {json.dumps(result)}", file=sys.stderr)
            for path in sorted((args.output / name).glob("*.log")):
                tail = path.read_text(errors="replace")[-8000:].splitlines()[-40:]
                print(f"{path.name}:\n" + "\n".join(line[:500] for line in tail), file=sys.stderr)
    return 0 if all(cell["passed"] for cell in results.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
