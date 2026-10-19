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
from urllib.parse import urlsplit, urlunsplit

from capture_fields import compare_capture_fields
from connection_fields import (
    compare_connection_fields,
    compare_h1_connections,
    h2_prefixes,
)
from h3_sequence_wire import sequence_evidence
from native_h3_response import response_sequences
from quic_wire import client_settings, compare_quic_captures, first_flights
from qpack_fields_wire import (
    compare_field_metadata,
    compare_replay_policy,
    sections_from_wire,
)
from fixture_process import running, wait_ready
from flow_bodies import WEBSOCKET_PROBE
from flows import (
    FLOWS,
    ReplayTarget,
    compare_requests,
    flow_protocols,
    operation_flow,
    replay_args,
    require,
)
from tls_wire import (
    PRE_SHARED_KEY_EXTENSION,
    TRUST_ANCHORS_EXTENSION,
    client_hellos,
    compare_tls_captures,
)
from wire import drain_capture
from request_wire import request_from_stream
from preliminary import plan_preliminary, preliminary_arguments, rebind_preliminary
from preliminary_inventory import PreliminaryInventory


def requests_from_wire(frames, *, operations=None):
    """Keep request bodies with their own connection/stream; skip WS framing."""
    streams = defaultdict(list)
    for frame in frames:
        streams[(frame.protocol, frame.connection, frame.stream)].append(frame)
    requests = defaultdict(list)
    for frames in streams.values():
        heads = [frame for frame in frames if frame.headers and not frame.from_server]
        if not heads:
            continue
        require(len(heads) == 1, "one original request per stream")
        fields = {name.lower(): value for name, value in heads[0].headers}
        flow = operation_flow(heads[0], operations)
        if flow is None:
            continue
        name = flow if operations is None else operations.name(heads[0])
        requests[name].append(request_from_stream(frames, flow=flow))
    names = FLOWS if operations is None else operations.names
    require(
        set(requests) == set(names), "complete declared-operation replay input coverage"
    )
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


def run_replay(
    command, *, flow, log, environment=None, timeout=30, websocket_probe=WEBSOCKET_PROBE
):
    """Keep WebSocket stdin open until the peer echoes and completes its close.

    Immediate stdin EOF starts the CLI close handshake, which can race the echo.
    Other HTTP operations have no stdin and use the ordinary command runner.
    """
    if flow != "ws":
        with log.open("w") as output:
            subprocess.run(
                command,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=output,
                stderr=subprocess.STDOUT,
                check=True,
                timeout=timeout,
            )
        return

    with running(command, log, environment, stdin=subprocess.PIPE) as process:
        try:
            process.stdin.write((websocket_probe + "\n").encode())
            process.stdin.flush()
            code = process.wait(timeout=timeout)
            if code:
                raise subprocess.CalledProcessError(code, command)
        finally:
            process.stdin.close()
    require(
        log.read_text().splitlines().count(websocket_probe) == 1,
        "CLI WebSocket echo missing or repeated",
    )


def connection_protocol(capture):
    """Classify native connection slots, never infer from numeric connection IDs."""
    slots = {slot["kind"] for slot in capture.get("slots", [])}
    if "QuicTls" in slots:
        require("TcpTls" not in slots, "ambiguous retained transport")
        return "h3"
    require("TcpTls" in slots, "retained connection needs a TLS transport")
    return "h2" if "Http2EarlyFrames" in slots else "h1"


def tls_hellos(data, protocols):
    """Decode each used native transport once, retaining its own identity space."""
    transports = {"Quic" if protocol == "h3" else "Tcp" for protocol in protocols}
    return [
        hello
        for transport in sorted(transports)
        for hello in client_hellos(data, transport)
    ]


def compare_native_connections(
    inspected,
    data,
    port,
    headers,
    plan,
    *,
    replay=False,
    same_traffic_native=False,
    operations=None,
):
    """Check this journey, optionally attributing its own collected snapshots.

    A replay server's native publication cannot identify the original profile's
    snapshot. Same-traffic response witnesses apply only to its own archive.
    """
    require(
        not (replay and same_traffic_native),
        "replay policy cannot use a new native freeze",
    )
    reports = {}
    for protocol in sorted(set(plan.values())):
        flows = (
            tuple(flow for flow in FLOWS if plan[flow] == protocol)
            if operations is None
            else operations.roles(protocol)
        )
        selected = [block for block in headers if block.protocol == protocol]
        hellos = client_hellos(data, "Quic" if protocol == "h3" else "Tcp")
        arguments = dict(
            expected_flows=flows,
            expected_per_variant_flow=1 if replay and operations is None else None,
            **({"operations": operations} if operations is not None else {}),
        )
        if protocol == "h3":
            reports[protocol] = compare_quic_captures(
                inspected,
                first_flights(data, port),
                hellos,
                client_settings(data, port),
                headers,
                sequence_evidence(data, port),
                native_sequences=(
                    response_sequences(
                        data,
                        port,
                        **(
                            {"operations": operations} if operations is not None else {}
                        ),
                    )
                    if same_traffic_native
                    else None
                ),
                **arguments,
            )
        elif protocol == "h2":
            reports[protocol] = compare_connection_fields(
                inspected,
                hellos,
                h2_prefixes(
                    data, port, connections={block.connection for block in selected}
                ),
                headers,
                **arguments,
            )
        else:
            reports[protocol] = compare_h1_connections(
                inspected, hellos, headers, **arguments
            )
    if replay and operations is not None:
        matrix = operations.check_matrix(headers, reports)
        for protocol, report in reports.items():
            report["operation_matrix"] = [
                row for row in matrix if row["protocol"] == protocol
            ]
    return reports


def connection_variants(inspected, protocol=None):
    """Enumerate actual retained joint IDs so fixed draws cannot miss a shape."""
    variants = sorted(
        {
            bytes(variant["id"]).hex()
            for profile in inspected["profiles"]
            for scope in profile["scopes"]
            for variant in scope["variants"]
            if variant["capture"].get("level") == "Connection"
            and (
                protocol is None or connection_protocol(variant["capture"]) == protocol
            )
        }
    )
    require(
        variants and all(len(value) == 64 for value in variants),
        "retained connection variants required",
    )
    return variants


def connection_warmups(inspected, protocol):
    """Plan preliminary exchanges for HTTP/3; HTTP/2 needs none.

    For a resumed recipe, first obtain a current ticket from its profile's
    full-handshake recipe, then prime the resumed connection. This consumes
    initial QPACK sections before later header policies are compared.
    An offered ticket alone does not prove negotiated resumption.
    """
    require(protocol in ("h2", "h3"), "expected TLS replay protocol")
    if protocol == "h2":
        return {}

    warmups = {}
    for profile in inspected["profiles"]:
        full, ticket = set(), set()
        for scope in profile["scopes"]:
            for variant in scope["variants"]:
                capture = variant["capture"]
                if capture.get("level") != "Connection":
                    continue
                for slot in capture.get("slots", []):
                    if slot["kind"] != "QuicTls":
                        continue
                    identifier = bytes(variant["id"]).hex()
                    needs_ticket = any(
                        extension["id"] == PRE_SHARED_KEY_EXTENSION
                        for extension in slot["capture"]["extensions"]
                    )
                    (ticket if needs_ticket else full).add(identifier)
        require(not ticket or full, "QUIC PSK replay needs a full-handshake recipe")
        warmups.update((identifier, [identifier]) for identifier in full)
        if ticket:
            first_full = min(full)
            warmups.update(
                (identifier, [first_full, identifier]) for identifier in ticket
            )
    return warmups


def check_missing_tls_bindings(command, environment, root, *, protocol, trust_ids):
    """The positive replay must need its CA and any explicit current IDs."""
    # QUIC carries TLS alerts as CRYPTO_ERROR; unknown_ca is alert 48.
    ca_errors = ("certificate",)
    if protocol == "h3":
        ca_errors += (
            "the cryptographic handshake failed: error 48: tls handshake failed",
        )
    probes = [("ca", "--cacert", ca_errors)]
    if trust_ids is not None:
        probes.append(("trust-ids", "--tls-requested-trust-anchors", ("trust-anchor",)))
    for label, option, expected_errors in probes:
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
            any(error in path.read_text().lower() for error in expected_errors),
            "unexpected missing-binding failure; see " + path.name,
        )

    check_tls_hostname(command, environment, root)


def check_tls_hostname(command, environment, root):
    """Keep the fixture CA trusted while connecting with an unrelated identity."""
    destination = urlsplit(command[-1])
    require(
        destination.hostname is not None,
        "hostname control requires a DNS fixture identity",
    )
    port = destination.port or 443
    # Keep SNI length unchanged so an exact QUIC Initial layout remains
    # representable. The unrelated name still fails certificate identity checks.
    hostname = (
        "wronghost"
        if destination.hostname == "localhost"
        else ("x" if destination.hostname[0] != "x" else "y") + destination.hostname[1:]
    )
    arguments = list(command)
    # Replace the fixture route: the CLI accepts one --resolve occurrence.
    # Keeping the old route would reject arguments before checking the certificate.
    if "--resolve" in arguments:
        index = arguments.index("--resolve")
        del arguments[index : index + 2]
    # A client option: it must precede the first request's URI.
    first = (arguments.index("--next") if "--next" in arguments else len(arguments)) - 1
    arguments[first:first] = ["--resolve", f"{hostname}:{port}:127.0.0.1"]
    arguments[-1] = urlunsplit(destination._replace(netloc=f"{hostname}:{port}"))
    arguments = rebind_preliminary(arguments, destination, urlsplit(arguments[-1]))
    path = root / "wrong-hostname.log"
    with path.open("w") as log:
        result = subprocess.run(
            arguments,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=subprocess.STDOUT,
            timeout=30,
        )
    require(result.returncode != 0, "replay unexpectedly accepted the wrong hostname")
    expected_errors = ("certificate",)
    if "--http3" in command:
        # The authenticated QUIC fixture reports bad_certificate as alert 42.
        expected_errors += (
            "the cryptographic handshake failed: error 42: tls handshake failed",
        )
    require(
        any(error in path.read_text().lower() for error in expected_errors),
        "unexpected hostname-control failure; see " + path.name,
    )


def verify_tls_replay(
    args,
    *,
    traffic,
    inspected,
    server_command,
    environment,
    certificate,
    port,
    websocket_probe=WEBSOCKET_PROBE,
    fixture_origin=None,
    operations=None,
):
    """Run all six operations against fresh storage and require independent matches."""
    root = args.output
    source_operation_args = {} if operations is None else {"operations": operations}
    replay_operations = None if operations is None else operations.for_replay()
    replay_operation_args = (
        {} if replay_operations is None else {"operations": replay_operations}
    )
    reference = requests_from_wire(traffic.frames, **source_operation_args)
    plan = flow_protocols(traffic.frames, **source_operation_args)
    protocols = sorted(set(plan.values()))
    variants = {
        protocol: connection_variants(inspected, protocol) for protocol in protocols
    }
    warmups = connection_warmups(inspected, "h3") if "h3" in protocols else {}
    data = (root / "headers.pdml").read_bytes()
    origin = fixture_origin or f"https://localhost:{port}"
    destination = urlsplit(origin)
    require(
        destination.scheme == "https"
        and destination.hostname is not None
        and destination.port == port
        and not destination.path
        and not destination.query
        and not destination.fragment
        and destination.username is None,
        "replay fixture origin must keep its owned TLS port",
    )
    targets = {
        protocol: ReplayTarget(
            protocol,
            origin,
            certificate,
            current_trust_ids(
                client_hellos(data, "Quic" if protocol == "h3" else "Tcp")
            ),
            (f"{destination.hostname}:{port}:127.0.0.1",) if fixture_origin else (),
        )
        for protocol in protocols
    }
    if operations is None:
        runs = [
            dict(
                protocol=protocol,
                variant=variant,
                flow=flow,
                name=flow,
                warmups=tuple(warmups.get(variant, ())),
                request=None,
            )
            for protocol in protocols
            for variant in variants[protocol]
            for flow in FLOWS
            if plan[flow] == protocol
        ]
    else:
        runs = [
            dict(
                protocol=row["operation"].protocol,
                variant=row["operation"].joint,
                flow=row["operation"].flow,
                name=row["operation"].name,
                warmups=row["warmups"],
                request=row["operation"].request,
                operation=row["operation"],
            )
            for row in operations.schedule(inspected, traffic.headers, warmups)
        ]
    explicit_preliminary = operations is not None and "h3" in protocols
    source_sections = sections_from_wire(data, port) if explicit_preliminary else {}
    runs.sort(key=lambda run: protocols.index(run["protocol"]))
    for index, run in enumerate(runs):
        run["label"] = f"{index}-{run['protocol']}-{run['name']}"
        run["output"] = root / (run["label"] + ".response")
        run["reference"] = reference[run["name"]][0]
        run["target"] = targets[run["protocol"]]
        run["preliminary"] = (
            plan_preliminary(
                inspected,
                traffic.frames,
                source_sections,
                operations,
                run["operation"],
                run["warmups"],
            )
            if explicit_preliminary and run["protocol"] == "h3"
            else ()
        )
        run["preliminary_requests"] = (
            preliminary_arguments(run["preliminary"], run["target"])
            if run["preliminary"]
            else ()
        )
    preliminary_plan = (
        PreliminaryInventory(tuple(runs), replay_operations, port, websocket_probe)
        if explicit_preliminary
        else None
    )
    counts = {flow: sum(run["flow"] == flow for run in runs) for flow in FLOWS}
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
            for protocol in protocols:
                target = targets[protocol]
                selected = [run for run in runs if run["protocol"] == protocol]
                probe_run = min(selected, key=lambda run: len(run["warmups"]))
                require(
                    len(probe_run["warmups"]) <= 1,
                    "authentication probe needs a directly usable recipe",
                )
                probe_root = root / (protocol + "-authentication")
                probe_root.mkdir()
                probe = replay_args(
                    args.rama,
                    root / "profiles.json",
                    probe_root / "binding-probe.response",
                    target,
                    probe_run["flow"],
                    reference[probe_run["name"]][0],
                    connection_variant=probe_run["variant"],
                    **(
                        dict(preliminary_requests=probe_run["preliminary_requests"])
                        if explicit_preliminary
                        else dict(warmup_variants=probe_run["warmups"])
                    ),
                    **(
                        {"request_variant": probe_run["request"]}
                        if probe_run["request"] is not None
                        else {}
                    ),
                )
                check_missing_tls_bindings(
                    probe,
                    environment,
                    probe_root,
                    protocol=protocol,
                    trust_ids=target.trust_anchors,
                )
                for run in selected:
                    label = run["label"]
                    command = replay_args(
                        args.rama,
                        root / "profiles.json",
                        run["output"],
                        target,
                        run["flow"],
                        reference[run["name"]][0],
                        connection_variant=run["variant"],
                        **(
                            dict(preliminary_requests=run["preliminary_requests"])
                            if explicit_preliminary
                            else dict(warmup_variants=run["warmups"])
                        ),
                        **(
                            {"request_variant": run["request"]}
                            if run["request"] is not None
                            else {}
                        ),
                    )
                    run_replay(
                        command,
                        flow=run["flow"],
                        log=root / (label + "-replay.log"),
                        environment=environment,
                        websocket_probe=websocket_probe,
                    )
            replay = drain_capture(
                packets,
                capture=root / "replay.pcapng",
                keylog=root / "replay.keys",
                protocol="mixed",
                server_port=port,
                output=root / "replay.pdml",
                expected_per_flow=counts,
                websocket_probe=websocket_probe,
                expected_warmups=sum(
                    len(run["preliminary"] if explicit_preliminary else run["warmups"])
                    for run in runs
                ),
                **(
                    {"preliminary_plan": preliminary_plan}
                    if preliminary_plan is not None
                    else {}
                ),
                **replay_operation_args,
            )
    require(
        server.returncode == packets.returncode == 0, "replay fixture process failed"
    )
    if preliminary_plan is not None:
        replay_operations = replay.operations
        replay_operation_args = {"operations": replay_operations}

    # Use the original profile as oracle for both original capture and replay.
    # A separate replay archive must also pass the explicitly selected replay comparison.
    comparisons = compare_requests(
        reference,
        requests_from_wire(replay.frames, **replay_operation_args),
        expected_per_flow=counts,
        **replay_operation_args,
    )
    wire_report = {
        "scope": "six-operation exact protocol/method/path/ordered headers/body tuples",
        "flow_protocols": plan,
        "comparisons": comparisons,
        "limits": "same-origin credential-free fixture; WebSocket DATA framing is checked separately",
    }
    (root / "wire-comparison.json").write_text(json.dumps(wire_report, indent=2) + "\n")
    require(
        all(item["match"] for item in comparisons),
        "exact request tuple mismatch; see wire-comparison.json",
    )
    fields = compare_capture_fields(inspected, replay.headers, **replay_operation_args)
    tls = compare_tls_captures(
        inspected,
        tls_hellos((root / "replay.pdml").read_bytes(), protocols),
        replay.headers,
    )
    data = (root / "replay.pdml").read_bytes()
    require(
        flow_protocols(replay.frames, **replay_operation_args) == plan,
        "replay changed per-flow protocol",
    )
    connection_fields = compare_native_connections(
        inspected,
        data,
        port,
        replay.headers,
        plan,
        replay=True,
        **replay_operation_args,
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
    # Validate the replay collector itself against raw QPACK before comparing policies.
    qpack_fields = qpack_policy = None
    if "h3" in protocols:
        with (root / "replay-inspected.json").open("w") as output:
            subprocess.run(
                [
                    str(args.rama),
                    "ua",
                    "view",
                    "--json",
                    str(root / "replay-profiles.json"),
                ],
                env=environment,
                stdout=output,
                check=True,
                timeout=30,
            )
        replay_inspected = json.loads((root / "replay-inspected.json").read_text())
        sections = sections_from_wire(data, port)
        # The replay collector references its own canonical request IDs. Verify
        # its native joints independently before using their Bootstrap references.
        replay_connections = compare_native_connections(
            replay_inspected,
            data,
            port,
            replay.headers,
            plan,
            same_traffic_native=True,
            **replay_operation_args,
        )
        h3_flows = (
            {flow for flow in FLOWS if plan[flow] == "h3"}
            if operations is None
            else set(operations.roles("h3"))
        )
        qpack_fields = compare_field_metadata(
            replay_inspected,
            replay.headers,
            sections,
            expected_flows=h3_flows,
            connection_joints=replay_connections["h3"]["connection_joints"],
            **replay_operation_args,
        )
        qpack_policy = compare_replay_policy(
            inspected,
            replay.headers,
            sections,
            expected_flows=h3_flows,
            connection_joints=connection_fields["h3"]["connection_joints"],
            **replay_operation_args,
        )
        (root / "replay-qpack-fields.json").write_text(
            json.dumps(qpack_fields, indent=2) + "\n"
        )
        (root / "replay-qpack-policy.json").write_text(
            json.dumps(qpack_policy, indent=2) + "\n"
        )

    with (root / "archive-comparison.json").open("w") as output:
        subprocess.run(
            [
                str(args.rama),
                "ua",
                "compare",
                "--replay",
                str(root / "profiles.json"),
                str(root / "replay-profiles.json"),
            ],
            env=environment,
            stdout=output,
            check=True,
            timeout=30,
        )
    return {
        "connection_variants": {
            protocol: len(values) for protocol, values in variants.items()
        },
        "flow_protocols": plan,
        "wire": wire_report,
        "fields": fields,
        "connection_fields": connection_fields,
        "qpack_fields": qpack_fields,
        "qpack_policy": qpack_policy,
        "tls": tls,
        "bodies": replay.bodies,
        "preliminary": replay.preliminary_report,
        "scope": "six CLI operations, independent retained TLS/header membership and body semantics, separate replay-projection archive comparison",
    }
