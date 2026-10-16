"""Replay browser operations through the CLI and verify independent packet data.

The original browser journey stays in browser_automation. This module supplies
current request/TLS bindings, owns a second isolated fp database, and compares
replayed traffic against the original profile rather than trusting saved analysis.
"""

from collections import defaultdict
import json
import os
import secrets
import subprocess

from capture_fields import compare_capture_fields
from connection_fields import compare_connection_fields, h2_prefixes
from fixture_process import running, wait_ready
from flows import FLOWS, ReplayTarget, compare_requests, flow_name, replay_args, require
from tls_wire import TRUST_ANCHORS_EXTENSION, client_hellos, compare_tls_captures
from wire import Request, drain_capture


def requests_from_wire(frames):
    """Keep request bodies with their own connection/stream; skip WS framing."""
    streams = defaultdict(list)
    for frame in frames:
        streams[(frame.connection, frame.stream)].append(frame)
    requests = defaultdict(list)
    for frames in streams.values():
        heads = [frame for frame in frames if frame.headers and not frame.from_server]
        if not heads:
            continue
        require(len(heads) == 1, "one original request per stream")
        fields = dict(heads[0].headers)
        flow = flow_name(heads[0].headers)
        if flow is None:
            continue
        require(
            not any(
                name in fields
                for name in ("cookie", "authorization", "proxy-authorization")
            ),
            "local replay fixture must remain credential-free",
        )
        bindings = {}
        for name, value in heads[0].headers:
            if name in (
                "content-type",
                "content-length",
                "origin",
                "referer",
                "sec-websocket-protocol",
                "sec-websocket-extensions",
            ):
                require(name not in bindings, "ambiguous current request binding")
                bindings[name] = value
        # WebSocket DATA contains frames, not an HTTP request body. The shared
        # journey/decoder checks its greeting separately from HTTP body replay.
        body = (
            b""
            if flow == "ws"
            else b"".join(frame.data for frame in frames if not frame.from_server)
        )
        require(len(body) <= 65536, "fixture request body limit")
        requests[flow].append(
            Request(
                fields[":method"], fields[":path"], heads[0].headers, body, bindings
            )
        )
    require(set(requests) == set(FLOWS), "six-operation replay input coverage")
    return requests


def current_trust_ids(hellos):
    """Make new fixture IDs matching retained length, never recover discarded IDs.

    The CLI takes logical IDs. TLS adds one byte per ID and a two-byte outer
    vector length. Multiple advertised lengths need a separate fixture policy.
    """
    lengths = {
        extension["value"]["ConnectionLength"]
        for hello in hellos
        for extension in hello.capture["extensions"]
        if extension["id"] == TRUST_ANCHORS_EXTENSION
    }
    if not lengths:
        return None
    require(len(lengths) == 1, "fixture needs one current trust-advertisement shape")
    remaining = lengths.pop() - 2
    require(
        0 <= remaining <= 65533 and remaining != 1, "invalid trust-advertisement length"
    )
    ids = []
    while remaining:
        length = min(255, remaining - 1)
        if remaining - length - 1 == 1:
            length -= 1  # Leave room for another nonempty ID, never a lone prefix.
        require(length > 0, "nonempty current trust ID required")
        ids.append(secrets.token_bytes(length).hex())
        remaining -= length + 1
    return ",".join(ids)


def replay_environment(parent):
    """Create replay storage in this run's container, without altering the parent."""
    keys = ("DATABASE_URL", "RAMA_FP_DATABASE_URL", "RAMA_BROWSER_CAPTURE_DATABASE_URL")
    source = parent["RAMA_BROWSER_CAPTURE_DATABASE_URL"]
    require(
        all(parent[key] == source for key in keys),
        "isolated database identities differ",
    )
    require(
        "host=127.0.0.1 " in source and "dbname=rama_fp_capture" in source,
        "loopback capture database required",
    )
    subprocess.run(
        [
            "docker",
            "exec",
            parent["RAMA_BROWSER_TEST_PG_CONTAINER"],
            "createdb",
            "-U",
            "postgres",
            "rama_fp_replay",
        ],
        check=True,
        timeout=10,
    )
    replay = dict(parent)
    for key in keys:
        replay[key] = source.replace("dbname=rama_fp_capture", "dbname=rama_fp_replay")
    return replay


def connection_variants(inspected):
    """Enumerate actual retained joint IDs so fixed draws cannot miss a shape."""
    variants = sorted(
        {
            bytes(variant["id"]).hex()
            for profile in inspected["profiles"]
            for scope in profile["scopes"]
            for variant in scope["variants"]
            if variant["capture"].get("level") == "Connection"
        }
    )
    require(
        variants and all(len(value) == 64 for value in variants),
        "retained connection variants required",
    )
    return variants


def check_missing_tls_bindings(command, environment, root, *, trust_ids):
    """The positive replay must need its CA and any explicit current IDs."""
    probes = [("ca", "--cacert", "certificate")]
    if trust_ids is not None:
        probes.append(("trust-ids", "--tls-requested-trust-anchors", "trust-anchor"))
    for label, option, expected_error in probes:
        arguments = list(command)
        index = arguments.index(option)
        del arguments[index : index + 2]
        path = root / ("missing-" + label + ".log")
        with path.open("w") as log:
            result = subprocess.run(
                arguments,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=log,
                stderr=subprocess.STDOUT,
                timeout=30,
            )
        require(result.returncode != 0, "replay unexpectedly accepted missing " + label)
        require(
            expected_error in path.read_text().lower(),
            "unexpected missing-binding failure; see " + path.name,
        )


def verify_tls_replay(
    args, *, traffic, inspected, server_command, environment, certificate, port
):
    """Run all six operations against fresh storage and require independent matches."""
    root = args.output
    reference = requests_from_wire(traffic.frames)
    variants = connection_variants(inspected)
    transport = "Tcp" if args.protocol == "h2" else "Quic"
    hellos = client_hellos((root / "headers.pdml").read_bytes(), transport)
    target = ReplayTarget(
        args.protocol,
        f"https://localhost:{port}",
        certificate,
        current_trust_ids(hellos),
    )
    environment = replay_environment(environment)
    environment["SSLKEYLOGFILE"] = str(root / "replay.keys")
    capture_command = [
        "dumpcap",
        "-i",
        args.interface,
        "-a",
        "duration:90",
        "-f",
        f"tcp port {port} or udp port {port}",
        "-w",
        str(root / "replay.pcapng"),
    ]

    # Both endpoints log into one private file; it is never embedded into pcapng.
    # The surrounding capture owner deletes it, including on setup/replay failure.
    (root / "replay.keys").touch(mode=0o600, exist_ok=False)
    with running(server_command, root / "replay-server.log", environment) as server:
        wait_ready(
            server,
            root / "replay-server.log",
            lambda text: "listening" in text or "service ready" in text,
        )
        with running(capture_command, root / "replay-dumpcap.log") as packets:
            wait_ready(
                packets, root / "replay-dumpcap.log", lambda text: "File:" in text
            )
            probe = replay_args(
                args.rama,
                root / "profiles.json",
                root / "binding-probe.response",
                target,
                "navigate",
                reference["navigate"][0],
                connection_variant=variants[0],
            )
            check_missing_tls_bindings(
                probe, environment, root, trust_ids=target.trust_anchors
            )
            for variant_index, variant in enumerate(variants):
                for flow in FLOWS:
                    label = f"{variant_index}-{flow}"
                    command = replay_args(
                        args.rama,
                        root / "profiles.json",
                        root / (label + ".response"),
                        target,
                        flow,
                        reference[flow][0],
                        connection_variant=variant,
                    )
                    with (root / (label + "-replay.log")).open("w") as log:
                        subprocess.run(
                            command,
                            env=environment,
                            stdin=subprocess.DEVNULL,
                            stdout=log,
                            stderr=subprocess.STDOUT,
                            check=True,
                            timeout=30,
                        )
            replay = drain_capture(
                packets,
                capture=root / "replay.pcapng",
                keylog=root / "replay.keys",
                protocol=args.protocol,
                server_port=port,
                output=root / "replay.pdml",
                expected_per_flow=len(variants),
            )
    require(
        server.returncode == packets.returncode == 0, "replay fixture process failed"
    )

    # Use the original profile as oracle for both original capture and replay.
    # A separate replay archive must also pass Rama's literal comparison.
    comparisons = compare_requests(
        reference, requests_from_wire(replay.frames), expected_per_flow=len(variants)
    )
    wire_report = {
        "scope": f"{args.protocol} six-operation exact request method/path/ordered headers/body tuples",
        "comparisons": comparisons,
        "limits": "same-origin credential-free fixture; WebSocket DATA framing is checked separately",
    }
    (root / "wire-comparison.json").write_text(json.dumps(wire_report, indent=2) + "\n")
    require(
        all(item["match"] for item in comparisons),
        "exact request tuple mismatch; see wire-comparison.json",
    )
    fields = compare_capture_fields(inspected, replay.headers)
    tls = compare_tls_captures(
        inspected,
        client_hellos((root / "replay.pdml").read_bytes(), transport),
        replay.headers,
    )
    data = (root / "replay.pdml").read_bytes()
    connection_fields = compare_connection_fields(
        inspected,
        client_hellos(data, transport),
        h2_prefixes(data, port),
        replay.headers,
        expected_per_variant_flow=1,
    )
    with (root / "export-replay.log").open("w") as log:
        subprocess.run(
            [
                str(args.rama),
                "ua",
                "export",
                "--output",
                str(root / "replay-profiles.json"),
            ],
            env=environment,
            stdout=log,
            stderr=subprocess.STDOUT,
            check=True,
            timeout=30,
        )
    with (root / "archive-comparison.json").open("w") as output:
        subprocess.run(
            [
                str(args.rama),
                "ua",
                "compare",
                "--literal",
                str(root / "profiles.json"),
                str(root / "replay-profiles.json"),
            ],
            env=environment,
            stdout=output,
            check=True,
            timeout=30,
        )
    return {
        "connection_variants": len(variants),
        "wire": wire_report,
        "fields": fields,
        "connection_fields": connection_fields,
        "tls": tls,
        "bodies": replay.bodies,
        "scope": "six CLI operations, independent retained TLS/header membership and body semantics, separate literal archive comparison",
    }
