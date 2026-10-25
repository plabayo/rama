#!/usr/bin/env python3
"""CONNECT-UDP interop between Rama and masque-go on loopback.

Cells, each ten consecutive HTTP/3 exchanges through a CONNECT-UDP tunnel, every one on a
new tunnel and inner QUIC connection:

- rama-client: `rama send --http3` through the masque-go proxy to a Rama HTTP/3 origin.
- masque-go-client: the masque-go client through `rama serve proxy --protocol masque` to
  a Rama HTTP/3 origin.

Results go to OUTPUT/results.json, with every process's output next to it.
"""

import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[3]
RAMA_TEMPLATE = "/.well-known/masque/udp/{target_host}/{target_port}/"
PEER_TEMPLATE = "/masque?h={target_host}&p={target_port}"


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--rama", type=Path, required=True, help="Built rama binary")
    parser.add_argument("--peer", type=Path, required=True, help="Built masque-go peer")
    parser.add_argument("--runs", type=int, default=10)
    return parser.parse_args(argv)


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
        for name, process, log in self.running:
            process.terminate()
            try:
                code = process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                code = None
            log.close()
            text = (self.output / f"{name}.log").read_text()
            self.stopped[name] = {
                "exit_code": code,
                "graceful": "gracefully shutdown" in text if name.startswith("rama") or "origin" in name else None,
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
    origin = start_origin(processes, args.rama, "rama-client-origin")
    template = start_peer_proxy(processes, args.peer, output)
    proxy = template.replace("https://", "masque://", 1)
    runs = []
    for run in range(1, args.runs + 1):
        result = subprocess.run(
            [
                str(args.rama),
                "send",
                "--http3",
                "--insecure",
                "--proxy-insecure",
                "--proxy",
                proxy,
                f"https://localhost:{origin}/",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        (output / f"rama-client-run-{run}.log").write_text(result.stdout + result.stderr)
        runs.append({"run": run, "ok": result.returncode == 0 and "HTTP/3" in result.stdout})
    return runs


def masque_go_client_cell(processes, args, output):
    origin = start_origin(processes, args.rama, "masque-go-client-origin")
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
    )
    (output / "masque-go-client.log").write_text(result.stdout + result.stderr)
    return client_runs(result.stdout, result.returncode, args.runs)


def client_runs(stdout, returncode, runs):
    """The runs the masque-go client reported, all failed unless it also exited cleanly."""
    succeeded = {
        int(line.split()[1])
        for line in stdout.splitlines()
        if line.startswith("run ") and " ok: " in line
    }
    return [
        {"run": run, "ok": returncode == 0 and run in succeeded, "exit_code": returncode}
        for run in range(1, runs + 1)
    ]


def main(argv=None):
    args = parse_args(argv)
    args.output.mkdir(parents=True, exist_ok=False)
    results = {}
    for name, cell in (
        ("rama-client", rama_client_cell),
        ("masque-go-client", masque_go_client_cell),
    ):
        cell_output = args.output / name
        cell_output.mkdir()
        with Processes(cell_output) as processes:
            try:
                runs = cell(processes, args, cell_output)
                result = {"runs": runs}
            except Exception as error:  # noqa: BLE001 - every cell reports its own failure
                result = {"error": repr(error), "runs": []}
            processes.stop()
            result["processes"] = processes.stopped
            # Every Rama process must shut down gracefully once its peers are done.
            clean = all(
                process["exit_code"] == 0 and process["graceful"]
                for process in processes.stopped.values()
                if process["graceful"] is not None
            )
            result["passed"] = bool(result["runs"]) and all(run["ok"] for run in result["runs"]) and clean
            results[name] = result
    (args.output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    print(json.dumps({name: cell["passed"] for name, cell in results.items()}))
    return 0 if all(cell["passed"] for cell in results.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
