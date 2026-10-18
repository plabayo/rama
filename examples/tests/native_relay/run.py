#!/usr/bin/env python3
"""Exercise an umbrella Rama relay between independent Go TLS/HTTP endpoints.

Strict fingerprint comparison is the default. --allow-differences retains all
wire differences while checking bodies, trailers, field preservation and fresh
cryptographic values; it must not be reported as full fingerprint transparency.
"""

import argparse
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

from comparison import compare_legs
from identity import local_identities
from fixture_process import running, wait_ready

ROOT = Path(__file__).resolve().parents[3]
BODY = "external-relay-body"


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--protocol", choices=("h1", "h2"), required=True)
    parser.add_argument("--mode", choices=("debug", "release"), default="debug")
    parser.add_argument(
        "--fixture", type=Path, help="Prebuilt native-relay test executable"
    )
    parser.add_argument("--peer", type=Path, help="Prebuilt independent Go peer")
    parser.add_argument(
        "--offline", action="store_true", help="Use only cached Cargo/Go dependencies"
    )
    parser.add_argument(
        "--without-mirroring",
        action="store_true",
        help="Negative control: omit ingress ClientHello mirroring",
    )
    parser.add_argument(
        "--allow-differences",
        action="store_true",
        help="Report full fidelity separately; still require the native functional contract",
    )
    parser.add_argument(
        "--interface", default="lo0" if sys.platform == "darwin" else "lo"
    )
    args = parser.parse_args()
    if os.name != "posix":
        parser.error(
            "local packet/process integration currently requires Linux or macOS"
        )
    programs = ["openssl", "dumpcap", "tshark", "cargo"]
    if args.peer is None:
        programs.append("go")
    for program in programs:
        if shutil.which(program) is None:
            parser.error("required executable not found: " + program)
    args.output = args.output.resolve()
    for name in ("fixture", "peer"):
        path = getattr(args, name)
        if path is not None:
            setattr(args, name, path.resolve(strict=True))
    return args


def build_binaries(args):
    root = args.output
    cargo = ["cargo", "--locked"] + (["--offline"] if args.offline else [])
    features = ["-p", "rama", "--no-default-features", "--features", "http-full,boring"]
    # Include dev/build edges: the running integration fixture uses those too.
    graph_command = [
        cargo[0],
        "tree",
        *cargo[1:],
        *features,
        "--edges",
        "normal,build,dev",
    ]
    graph = subprocess.check_output(graph_command, cwd=ROOT, text=True, timeout=60)
    (root / "dependency-graph.txt").write_text(graph)
    if "rama-ua v" in graph:
        raise ValueError("native fixture dependency graph contains rama-ua")
    if args.fixture is None:
        command = [
            cargo[0],
            "test",
            *cargo[1:],
            *features,
            "--test",
            "native-relay",
            "--no-run",
            "--message-format=json",
        ]
        if args.mode == "release":
            command.append("--release")
        with (root / "fixture-build.jsonl").open("w") as output, (
            root / "fixture-build.log"
        ).open("w") as log:
            subprocess.run(
                command, cwd=ROOT, stdout=output, stderr=log, check=True, timeout=1200
            )
        executables = {
            record["executable"]
            for line in (root / "fixture-build.jsonl").read_text().splitlines()
            if (record := json.loads(line)).get("executable")
            and record.get("target", {}).get("name") == "native-relay"
        }
        if len(executables) != 1:
            raise ValueError("native fixture build did not identify one executable")
        args.fixture = Path(executables.pop())
    if args.peer is None:
        args.peer = root / "peer"
        environment = dict(os.environ)
        if args.offline:
            environment["GOPROXY"] = "off"
        with (root / "peer-build.log").open("w") as log:
            subprocess.run(
                ["go", "build", "-o", str(args.peer), "."],
                cwd=Path(__file__).parent / "peer",
                env=environment,
                stdout=log,
                stderr=subprocess.STDOUT,
                check=True,
                timeout=600,
            )
    (root / "binaries.json").write_text(
        json.dumps(
            {
                name: dict(
                    path=str(getattr(args, name)),
                    sha256=hashlib.sha256(getattr(args, name).read_bytes()).hexdigest(),
                )
                for name in ("fixture", "peer")
            },
            indent=2,
        )
        + "\n"
    )


def execute(args):
    root = args.output
    with ExitStack() as owned:
        authority, identity = local_identities(root)
        origin_log = root / "origin.log"
        origin = owned.enter_context(
            running(
                [
                    str(args.peer),
                    "--mode",
                    "origin",
                    "--protocol",
                    args.protocol,
                    "--cert",
                    str(identity.certificate),
                    "--key",
                    str(identity.key),
                    "--keylog",
                    str(root / "origin.keys"),
                ],
                origin_log,
            )
        )
        wait_ready(origin, origin_log, lambda text: text.startswith("{"))
        origin_address = json.loads(origin_log.read_text().splitlines()[0])["ready"]
        origin_port = int(origin_address.rsplit(":", 1)[1])

        config, ready = root / "relay-config.json", root / "relay-ready.json"
        config.write_text(
            json.dumps(
                dict(
                    origin=origin_address,
                    ca=str(authority.certificate),
                    key=str(authority.key),
                    ready=str(ready),
                    mirror=not args.without_mirroring,
                ),
                indent=2,
            )
            + "\n"
        )
        relay_log = root / "relay.log"
        relay = owned.enter_context(
            running(
                [
                    str(args.fixture),
                    "--ignored",
                    "--exact",
                    "tcp_relay_fixture",
                    "--nocapture",
                ],
                relay_log,
                dict(
                    os.environ,
                    RAMA_NATIVE_RELAY_FIXTURE_CONFIG=str(config),
                    SSLKEYLOGFILE=str(root / "relay.keys"),
                ),
            )
        )
        wait_ready(relay, relay_log, lambda _: ready.exists())
        readiness = json.loads(ready.read_text())
        if readiness.get("ua_enabled") is not False:
            raise ValueError("running native relay fixture must have UA disabled")
        address = readiness["listen"]
        port = int(address.rsplit(":", 1)[1])

        capture = root / "wire.pcapng"
        capture_log = root / "dumpcap.log"
        recorder = owned.enter_context(
            running(
                [
                    "dumpcap",
                    "-i",
                    args.interface,
                    "-a",
                    "duration:5",
                    "-f",
                    f"tcp port {port} or tcp port {origin_port}",
                    "-w",
                    str(capture),
                ],
                capture_log,
            )
        )
        wait_ready(recorder, capture_log, lambda text: "File:" in text)
        with (root / "client.log").open("w") as log:
            result = subprocess.run(
                [
                    str(args.peer),
                    "--mode",
                    "client",
                    "--protocol",
                    args.protocol,
                    "--ca",
                    str(authority.certificate),
                    "--url",
                    "https://" + address,
                    "--keylog",
                    str(root / "client.keys"),
                    "--body",
                    BODY,
                ],
                stdout=subprocess.PIPE,
                stderr=log,
                text=True,
                timeout=30,
            )
        (root / "client.jsonl").write_text(result.stdout)
        # Let macOS BPF flush its last buffered packets; early SIGINT can lose a
        # short successful exchange even after dumpcap printed its readiness.
        recorder.wait(timeout=10)
        if recorder.returncode:
            raise RuntimeError("capture failed; see dumpcap.log")
        if capture.stat().st_size > 40 * 1024 * 1024:
            raise ValueError("capture byte limit exceeded")

        legs = {}
        for side, destination, keylog in (
            ("ingress", port, "client.keys"),
            ("egress", origin_port, "origin.keys"),
        ):
            path = root / (side + ".pdml")
            with path.open("xb") as output:
                subprocess.run(
                    [
                        "tshark",
                        "-r",
                        str(capture),
                        "-d",
                        f"tcp.port=={destination},tls",
                        "-o",
                        "tls.keylog_file:" + str(root / keylog),
                        "-Y",
                        f"tcp.port=={destination}",
                        "-T",
                        "pdml",
                    ],
                    stdout=output,
                    check=True,
                    timeout=15,
                )
            legs[side] = path.read_bytes()
        if result.returncode:
            raise RuntimeError(
                "external client failed; both decoded legs retained, see client.log"
            )
        report = compare_legs(
            legs["ingress"],
            legs["egress"],
            args.protocol,
            port,
            origin_port,
            BODY.encode(),
        )
        report.update(
            ua_enabled=False,
            mirror_requested=not args.without_mirroring,
            ports=dict(ingress=port, egress=origin_port),
        )
        (root / "comparison.json").write_text(json.dumps(report, indent=2) + "\n")
        if not args.allow_differences and not report["fingerprint_match"]:
            raise ValueError("native fingerprint differs; see comparison.json")
        return 0


def main():
    args = parse_args()
    args.output.mkdir(exist_ok=False, mode=0o700)
    try:
        build_binaries(args)
        return execute(args)
    finally:
        # Process contexts unwind before cleanup, including every failure path.
        for path in args.output.iterdir():
            if path.suffix in (".key", ".keys"):
                path.unlink(missing_ok=True)
        remaining = [
            path.name
            for path in args.output.iterdir()
            if path.suffix in (".key", ".keys")
        ]
        (args.output / "cleanup.json").write_text(
            json.dumps(dict(private_files_remaining=remaining)) + "\n"
        )


if __name__ == "__main__":
    raise SystemExit(main())
