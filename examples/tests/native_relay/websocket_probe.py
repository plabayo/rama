"""Independent WebSocket tunnel checks for the native relay fixture.

Tshark decrypts each leg. wsproto, independently of the Go peer's gobwas/ws,
validates masking, fragmentation, UTF-8 and close semantics on reassembled bytes.
Only generated test messages are retained; decoding keys are always deleted.
"""

from contextlib import ExitStack
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import h11
from wsproto import Connection, ConnectionType
from wsproto.utilities import generate_accept_token
from wsproto.events import BytesMessage, CloseConnection, Ping, Pong, TextMessage

sys.path.append(str(Path(__file__).parents[1] / "browser_profile"))

from fixture_process import running, wait_ready
from flows import require
from comparison import compare_connection_facts
from wire import one, parse_pdml, pdml_packets, values

MAX_STREAM_BYTES = 65536
TEXT = "native relay UTF-8: café 🐢"
FRAGMENTED = "fragmented UTF-8 relay message: café 🐢"
BINARY = bytes((0, 1, 127, 128, 254, 255)).hex()
PING = b"relay ping".hex()


def peer_environment():
    """Enable x/net's Extended CONNECT support only in owned Go test peers."""
    environment = dict(os.environ)
    settings = environment.get("GODEBUG", "")
    environment["GODEBUG"] = settings + ("," if settings else "") + "http2xconnect=1"
    return environment


def decode_messages(data, from_server):
    require(len(data) <= MAX_STREAM_BYTES, "WebSocket stream byte limit")
    receiver = Connection(
        ConnectionType.CLIENT if from_server else ConnectionType.SERVER
    )
    messages, partial, fragmented = [], None, 0
    # Bytewise admission identifies the exact Close boundary. Feeding the whole
    # buffer at once can let a library stop at Close and hide trailing bytes.
    for position, value in enumerate(data):
        receiver.receive_data(bytes((value,)))
        for event in receiver.events():
            if isinstance(event, (TextMessage, BytesMessage)):
                kind = "text" if isinstance(event, TextMessage) else "binary"
                if partial is None:
                    partial = (kind, [])
                require(partial[0] == kind, "WebSocket message kind changed")
                partial[1].append(event.data)
                if event.frame_finished and not event.message_finished:
                    fragmented += 1
                if event.message_finished:
                    payload = (
                        "".join(partial[1])
                        if kind == "text"
                        else b"".join(partial[1]).hex()
                    )
                    messages.append((kind, payload))
                    partial = None
            elif isinstance(event, (Ping, Pong)):
                messages.append(
                    (
                        "ping" if isinstance(event, Ping) else "pong",
                        bytes(event.payload).hex(),
                    )
                )
            elif isinstance(event, CloseConnection):
                require(
                    event.code == 1000 and event.reason == "complete",
                    "WebSocket close differs",
                )
                require(position == len(data) - 1, "bytes follow WebSocket close")
                messages.append(("close", 1000))
            else:
                raise ValueError("unexpected WebSocket event")
    require(partial is None, "incomplete WebSocket message")
    expected = [("text", TEXT), ("binary", BINARY)]
    if from_server:
        expected.insert(0, ("text", "hello from independent origin"))
    expected += [
        ("pong" if from_server else "ping", PING),
        ("text", FRAGMENTED),
        ("close", 1000),
    ]
    require(messages == expected, "WebSocket probe coverage or payload differs")
    require(from_server or fragmented > 0, "fragmented WebSocket probe missing")
    return dict(messages=len(messages), fragmented_frames=fragmented, close=1000)


def multiplexed_streams(data, protocol, port):
    blocks = parse_pdml(data, protocol, port, include_data=True)
    requests = [
        block
        for block in blocks
        if not block.from_server and dict(block.headers).get(":protocol") == "websocket"
    ]
    require(len(requests) == 1, "expected one WebSocket CONNECT")
    request = requests[0]
    require(dict(request.headers).get(":method") == "CONNECT", "WebSocket method")
    require(dict(request.headers).get(":path") == "/ws", "WebSocket path")
    selected = [
        block
        for block in blocks
        if (block.connection, block.stream) == (request.connection, request.stream)
    ]
    responses = [
        block
        for block in selected
        if block.from_server and ":status" in dict(block.headers)
    ]
    require(len(responses) == 1, "WebSocket response association")
    headers = dict(responses[0].headers)
    require(headers.get(":status") == "200", "WebSocket CONNECT status")
    require(headers.get("sec-websocket-protocol") == "interop", "WebSocket subprotocol")
    return {
        side: b"".join(block.data for block in selected if block.from_server == side)
        for side in (False, True)
    }


def tls_follow_index(packet):
    """Wireshark 4.6 names TLS streams; older releases use the TCP stream index."""
    identities = set(values(packet, "tls.stream") or values(packet, "tcp.stream"))
    require(len(identities) == 1, "ambiguous tunnel TLS stream")
    return identities.pop()


def tls_streams(text, port):
    """Read bounded TLS-follow output and bind direction to the actual endpoint."""
    require(len(text) <= 4 * MAX_STREAM_BYTES, "TLS-follow byte limit")
    parts, server = {0: bytearray(), 1: bytearray()}, None
    for line in text.splitlines():
        node = re.fullmatch(r"Node ([01]): 127\.0\.0\.1:(\d+)", line)
        if node and int(node[2]) == port:
            require(server is None, "ambiguous TLS-follow endpoint")
            server = int(node[1])
        if re.fullmatch(r"\t?[0-9a-fA-F]+", line):
            parts[int(line.startswith("\t"))].extend(bytes.fromhex(line.strip()))
    require(server is not None, "TLS-follow server endpoint missing")
    return {False: bytes(parts[1 - server]), True: bytes(parts[server])}


def h1_streams(text, port):
    """Let h11 admit the Upgrade boundary before wsproto reads frame bytes."""
    parts = tls_streams(text, port)
    request_parser = h11.Connection(h11.SERVER, max_incomplete_event_size=16384)
    request_parser.receive_data(parts[False])
    request = request_parser.next_event()
    require(isinstance(request, h11.Request), "WebSocket Upgrade request missing")
    require(
        request.method == b"GET" and request.target == b"/ws",
        "WebSocket Upgrade target",
    )
    require(
        isinstance(request_parser.next_event(), h11.EndOfMessage),
        "WebSocket Upgrade body",
    )
    headers = dict(request.headers)
    require(
        headers.get(b"upgrade", b"").lower() == b"websocket", "WebSocket Upgrade field"
    )
    response_parser = h11.Connection(h11.CLIENT, max_incomplete_event_size=16384)
    response_parser.send(request)
    response_parser.send(h11.EndOfMessage())
    response_parser.receive_data(parts[True])
    response = response_parser.next_event()
    require(
        isinstance(response, h11.InformationalResponse) and response.status_code == 101,
        "WebSocket Upgrade response missing",
    )
    accepted = dict(response.headers)
    key = headers.get(b"sec-websocket-key", b"")
    require(bool(key), "WebSocket key missing")
    expected = generate_accept_token(key)
    require(
        accepted.get(b"sec-websocket-accept") == expected, "WebSocket accept differs"
    )
    require(
        accepted.get(b"sec-websocket-protocol") == b"interop", "WebSocket subprotocol"
    )
    return {
        False: request_parser.trailing_data[0],
        True: response_parser.trailing_data[0],
    }


def compare_streams(ingress, egress):
    report = {}
    for from_server in (False, True):
        direction = "server" if from_server else "client"
        before, after = ingress[from_server], egress[from_server]
        checks = [decode_messages(stream, from_server) for stream in (before, after)]
        require(before == after, "WebSocket tunnel bytes differ between legs")
        report[direction] = dict(
            bytes=len(before),
            sha256=hashlib.sha256(before).hexdigest(),
            ingress=checks[0],
            egress=checks[1],
        )
    return dict(byte_preservation=True, directions=report)


def run_probe(args, authority, address, origin_port):
    """Use the running native relay and origin; own only this capture and client."""
    root = args.output / "websocket"
    root.mkdir()
    port = int(address.rsplit(":", 1)[1])
    transport = "udp" if args.protocol == "h3" else "tcp"
    dissector = "quic" if args.protocol == "h3" else "tls"
    capture, keylog = root / "wire.pcapng", root / "client.keys"
    try:
        with ExitStack() as owned:
            log = root / "dumpcap.log"
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
                    log,
                )
            )
            wait_ready(recorder, log, lambda text: "File:" in text)
            with (root / "client.log").open("w") as output:
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
                        "websocket",
                        "--ca",
                        str(authority.certificate),
                        "--url",
                        "https://" + address,
                        "--keylog",
                        str(keylog),
                    ],
                    env=peer_environment(),
                    stdout=output,
                    stderr=subprocess.STDOUT,
                    timeout=30,
                )
            recorder.wait(timeout=10)
            require(recorder.returncode == 0, "WebSocket capture failed")
            require(capture.stat().st_size <= 40 * 1024 * 1024, "capture byte limit")
            streams, legs = {}, {}
            for side, destination, keys in (
                ("ingress", port, keylog),
                ("egress", origin_port, args.output / "origin.keys"),
            ):
                command = [
                    "tshark",
                    "--disable-protocol",
                    "websocket",
                    "-r",
                    str(capture),
                    "-d",
                    f"{transport}.port=={destination},{dissector}",
                    "-o",
                    "tls.keylog_file:" + str(keys),
                ]
                path = root / (side + ".pdml")
                with path.open("xb") as output:
                    subprocess.run(
                        command
                        + ["-Y", f"{transport}.port=={destination}"]
                        + ["-o", "tcp.relative_sequence_numbers:TRUE", "-T", "pdml"],
                        stdout=output,
                        check=True,
                        timeout=15,
                    )
                data = path.read_bytes()
                legs[side] = data
                packets = pdml_packets(data)
                if args.protocol == "h1":
                    upgrades = [
                        packet
                        for packet in packets
                        if values(packet, "http.request.method") == ["GET"]
                        and values(packet, "http.request.uri") == ["/ws"]
                    ]
                else:
                    requests = [
                        block
                        for block in parse_pdml(data, args.protocol, destination)
                        if not block.from_server
                        and dict(block.headers).get(":protocol") == "websocket"
                    ]
                    require(len(requests) == 1, "expected one WebSocket CONNECT")
                    upgrades = [
                        packet
                        for packet in packets
                        if one(packet, "frame.number") == str(requests[0].packet)
                    ]
                require(len(upgrades) == 1, "expected one WebSocket handshake")
                if args.protocol != "h1":
                    streams[side] = multiplexed_streams(
                        data, args.protocol, destination
                    )
                    continue
                index = tls_follow_index(upgrades[0])
                follow = root / (side + ".tls-stream.txt")
                with follow.open("xb") as output:
                    subprocess.run(
                        command + ["-q", "-z", "follow,tls,raw," + index],
                        stdout=output,
                        check=True,
                        timeout=15,
                    )
                streams[side] = h1_streams(follow.read_text(), destination)
            require(result.returncode == 0, "external WebSocket client failed")
            report = compare_streams(streams["ingress"], streams["egress"])
            report.update(
                compare_connection_facts(
                    legs["ingress"],
                    legs["egress"],
                    args.protocol,
                    port,
                    origin_port,
                    quic_version=args.quic_version,
                )
            )
            (root / "comparison.json").write_text(json.dumps(report, indent=2) + "\n")
            return report
    finally:
        keylog.unlink(missing_ok=True)
