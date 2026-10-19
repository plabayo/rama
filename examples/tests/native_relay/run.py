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
from evidence import export_evidence
from identity import local_identities
from websocket_probe import peer_environment, run_probe
from fixture_process import require_h3_tshark, running, wait_ready

ROOT = Path(__file__).resolve().parents[3]
BODY = "external-relay-body"
# Deliberate loopback-fixture receive ceilings in bytes, not observed peer credit.
H2_FIXTURE_INGRESS_CREDIT_MAX = 64 * 1024 * 1024
H2_FIXTURE_EGRESS_CREDIT_MAX = 1536 * 1024 * 1024
H2_INITIAL_CREDIT_MIN = 65535
H2_INITIAL_CREDIT_MAX = (1 << 31) - 1


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--protocol", choices=("h1", "h2", "h3"), required=True)
    parser.add_argument("--quic-version", type=int, choices=(1, 2), default=1)
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
        help="Broad negative control: omit ingress-derived TLS and H2 credit mirroring",
    )
    parser.add_argument(
        "--allow-differences",
        action="store_true",
        help="Report full fidelity separately; still require the native functional contract",
    )
    parser.add_argument(
        "--interface", default="lo0" if sys.platform == "darwin" else "lo"
    )
    parser.add_argument(
        "--retry",
        choices=("ingress", "egress"),
        help="Negative control: force Retry on one H3 leg; this Initial-flight verifier rejects it",
    )
    parser.add_argument(
        "--h2-ingress-credit-max",
        type=int,
        help="H2 fixture ingress receive ceiling in bytes (default: 64 MiB); supply both ceilings",
    )
    parser.add_argument(
        "--h2-egress-credit-max",
        type=int,
        help="H2 fixture egress receive ceiling in bytes (default: 1536 MiB); supply both ceilings",
    )
    args = parser.parse_args(argv)
    credit_maxima = (args.h2_ingress_credit_max, args.h2_egress_credit_max)
    supplied = tuple(value is not None for value in credit_maxima)
    if any(supplied):
        if not all(supplied):
            parser.error("H2 receive ceilings must be supplied together")
        if args.protocol != "h2":
            parser.error("H2 receive ceilings require --protocol h2")
        if any(
            value < H2_INITIAL_CREDIT_MIN or value > H2_INITIAL_CREDIT_MAX
            for value in credit_maxima
        ):
            parser.error(
                "H2 receive ceilings must be between 65535 and 2147483647 bytes"
            )
    elif args.protocol == "h2":
        args.h2_ingress_credit_max = H2_FIXTURE_INGRESS_CREDIT_MAX
        args.h2_egress_credit_max = H2_FIXTURE_EGRESS_CREDIT_MAX
    if args.retry and args.protocol != "h3":
        parser.error("--retry requires H3")
    if args.protocol != "h3" and args.quic_version != 1:
        parser.error("--quic-version=2 requires H3")
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
                    "--version",
                    str(args.quic_version),
                    *(["--retry"] if args.retry == "egress" else []),
                    "--cert",
                    str(identity.certificate),
                    "--key",
                    str(identity.key),
                    "--keylog",
                    str(root / "origin.keys"),
                ],
                origin_log,
                peer_environment(),
            )
        )
        wait_ready(origin, origin_log, lambda text: text.startswith("{"))
        origin_address = json.loads(origin_log.read_text().splitlines()[0])["ready"]
        origin_port = int(origin_address.rsplit(":", 1)[1])

        config, ready = root / "relay-config.json", root / "relay-ready.json"
        config.write_text(
            json.dumps(
                dict(
                    protocol=args.protocol,
                    origin=origin_address,
                    ca=str(authority.certificate),
                    key=str(authority.key),
                    ready=str(ready),
                    mirror=not args.without_mirroring,
                    validate_address=args.retry == "ingress",
                    **(
                        dict(
                            h2_ingress_initial_credit_max=args.h2_ingress_credit_max,
                            h2_egress_initial_credit_max=args.h2_egress_credit_max,
                        )
                        if args.protocol == "h2"
                        else {}
                    ),
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
                    "relay_fixture",
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

        transport = "udp" if args.protocol == "h3" else "tcp"
        dissector = "quic" if args.protocol == "h3" else "tls"
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
                    f"{transport} port {port} or {transport} port {origin_port}",
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
                    "--version",
                    str(args.quic_version),
                    "--flow",
                    "http",
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
                env=peer_environment(),
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
                        f"{transport}.port=={destination},{dissector}",
                        "-o",
                        "tls.keylog_file:" + str(root / keylog),
                        "-Y",
                        f"{transport}.port=={destination}",
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
            quic_version=args.quic_version,
        )
        websocket = run_probe(args, authority, address, origin_port)
        report.update(
            websocket=websocket,
            ua_enabled=False,
            mirror_requested=not args.without_mirroring,
            ports=dict(ingress=port, egress=origin_port),
        )
        if args.protocol == "h2":
            if type(websocket.get("h2_initial_credit_match")) is not bool:
                raise ValueError("missing WebSocket H2 initial-credit result")
            report["http_fingerprint_match"] = report["fingerprint_match"]
            report["fingerprint_match"] = (
                report["fingerprint_match"] and websocket["h2_initial_credit_match"]
            )
        (root / "comparison.json").write_text(json.dumps(report, indent=2) + "\n")
        if (
            args.protocol == "h2"
            and not args.without_mirroring
            and getattr(args, "h2_ingress_credit_max", None) is not None
            and getattr(args, "h2_egress_credit_max", None) is not None
            and (
                not report["h2_initial_credit_match"]
                or not websocket["h2_initial_credit_match"]
            )
        ):
            raise ValueError("mirrored H2 initial credit differs; see comparison.json")
        if not args.allow_differences and not report["fingerprint_match"]:
            raise ValueError("native fingerprint differs; see comparison.json")
        return 0


def main():
    args = parse_args()
    if args.protocol == "h3":
        require_h3_tshark()
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
        export_evidence(args.output)


if __name__ == "__main__":
    raise SystemExit(main())
