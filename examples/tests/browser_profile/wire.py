"""Independent tshark wire verification for H1, H2 and H3.

H1 uses decoded request/response rows and Upgrade bindings. H2/H3 use PDML
stream identity and Extended CONNECT. Protocol-specific decoding lives here;
browser journeys and replay inputs are shared elsewhere.
"""

import base64
import csv
import hashlib
import io
import json
import re
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from capture_health import require_quic_decoding
from collections import Counter
from dataclasses import dataclass
from flow_bodies import WEBSOCKET_PROBE, check_flow_bodies, check_websocket_messages
from flows import FLOWS, compare_requests, flow_counts, flow_name, operation_flow
from pathlib import Path
from pdml import MAX_CAPTURE_BYTES, MAX_PDML_BYTES, one, pdml_packets, values
from qpack_decode_wire import resolve_blocked_headers


# TCP accounting reads relative sequence numbers; never inherit a user preference.
PDML_OUTPUT = ("-o", "tcp.relative_sequence_numbers:TRUE", "-T", "pdml")


# H2/H3 decoding preserves connection and stream identity.


@dataclass(frozen=True)
class HeaderBlock:
    protocol: str
    packet: int
    connection: int
    stream: int
    from_server: bool
    headers: tuple[tuple[str, str], ...]
    data: bytes = b""
    websocket_text: tuple[str, ...] = ()
    header_decoder: str = "tshark"


def data_payloads(frame, protocol):
    """Read frame bytes, excluding application-body copies under trailer HEADERS.

    HTTP/2 exposes an original DATA segment separately when it also dissects a
    reassembled application body. Prefer that segment so each wire byte counts
    once. H3 DATA likewise belongs only to DATA frames, never trailing HEADERS.
    """
    names = (
        ("http2.data.segment", "http2.data.data")
        if protocol == "h2"
        else ("http3.data",)
    )
    # Reassembled/decompressed trees can reuse DATA field names in descendants.
    # Native H2 segments belong directly to this frame; H3's existing tree differs.
    native_fields = frame.findall if protocol == "h2" else frame.iter
    payloads = [
        [field for field in native_fields("field") if field.get("name") == name]
        for name in names
    ]
    if not any(payloads):
        return []
    type_name = "http2.type" if protocol == "h2" else "http3.frame_type"
    if int(one(frame, type_name), 0) != 0:
        return []
    return next(fields for fields in payloads if fields)


def parse_pdml(
    data,
    protocol,
    server_port,
    *,
    include_data=False,
    allow_empty=False,
    websocket_probe=WEBSOCKET_PROBE,
    packets=None,
):
    """Reject ambiguous frame identity; preserve duplicate header names and order."""
    if packets is None:
        packets = pdml_packets(data)
    if protocol == "mixed":
        blocks = []
        # Separate decoders retain the native TCP/QUIC namespaces. Empty
        # protocols are permitted here; aggregate body/flow checks remain strict.
        for selected in ("h2", "h3"):
            blocks.extend(
                parse_pdml(
                    data,
                    selected,
                    server_port,
                    include_data=include_data,
                    allow_empty=True,
                    packets=packets,
                )
            )
        blocks.extend(
            parse_h1_pdml(
                data,
                server_port,
                include_data=include_data,
                websocket_probe=websocket_probe,
                packets=packets,
            )
        )
        if not blocks:
            raise ValueError("no decrypted header blocks; check protocol and key log")
        return sorted(blocks, key=lambda block: block.packet)
    if protocol not in ("h2", "h3"):
        raise ValueError("expected h2, h3 or mixed")
    qpack_by_direction = {
        direction: resolve_blocked_headers(packets, server_port, from_server=direction)
        for direction in (False, True)
    } if protocol == "h3" else {}
    qpack = None
    blocks = []
    for packet in packets:
        containers = [
            field
            for field in packet.iter("field")
            if field.get("name")
            == ("http2.stream" if protocol == "h2" else "http3.frame")
        ]
        if not containers:
            continue
        if qpack_by_direction:
            qpack = qpack_by_direction[int(one(packet, "udp.srcport")) == server_port]
        header_name = "http2.header" if protocol == "h2" else "http3.headers.header"
        decoded_frames = [
            (frame, data_payloads(frame, protocol)) for frame in containers
        ]
        data_frames = [frame for frame, payloads in decoded_frames if payloads]
        websocket_text = (
            tuple(values(packet, "websocket.payload.text")) if include_data else ()
        )
        # Wireshark exposes WebSocket dissection as a sibling protocol, without
        # a stream ID. Attach it once only when all DATA frames share a stream.
        stream_name = "http2.streamid" if protocol == "h2" else "http3.frame_streamid"
        if (
            websocket_text
            and len({one(frame, stream_name) for frame in data_frames}) != 1
        ):
            raise ValueError("ambiguous WebSocket DATA stream association")
        for frame, payloads in decoded_frames:
            headers = [
                field
                for field in frame.iter("field")
                if field.get("name") == header_name
            ]
            recovered_key = None
            if (
                qpack is not None
                and qpack.headers
                and values(frame, "http3.frame_streamid")
                and len(values(frame, "http3.frame_type")) == 1
                and int(one(frame, "http3.frame_type"), 0) == 1
            ):
                recovered_key = (
                    int(one(packet, "frame.number")),
                    int(next(iter(set(values(packet, "quic.connection.number"))))),
                    int(one(frame, "http3.frame_streamid")),
                )
            if (
                not headers
                and not (include_data and payloads)
                and not (qpack is not None and recovered_key in qpack.recovered)
            ):
                continue
            transport = "tcp" if protocol == "h2" else "udp"
            source = int(one(packet, transport + ".srcport"))
            destination = int(one(packet, transport + ".dstport"))
            if (source == server_port) == (destination == server_port):
                raise ValueError(
                    "packet does not identify exactly one fixture endpoint"
                )
            stream = int(
                one(
                    frame,
                    "http2.streamid" if protocol == "h2" else "http3.frame_streamid",
                )
            )
            # One UDP datagram can contain multiple QUIC packets from the same
            # connection. Repeated identical connection IDs remain unambiguous.
            connections = set(
                values(
                    packet,
                    "tcp.stream" if protocol == "h2" else "quic.connection.number",
                )
            )
            if len(connections) != 1:
                raise ValueError("ambiguous connection identity")
            pairs = []
            for header in headers:
                name = one(
                    header,
                    (
                        "http2.header.name"
                        if protocol == "h2"
                        else "http3.header.header.name"
                    ),
                )
                value = one(
                    header,
                    (
                        "http2.header.value"
                        if protocol == "h2"
                        else "http3.headers.header.value"
                    ),
                )
                pairs.append((name, value))
            if qpack is not None and recovered_key in qpack.recovered:
                pairs = list(qpack.headers[recovered_key])
            payload = b""
            if include_data:
                for field in payloads:
                    if "value" not in field.attrib and field.get("size") != "0":
                        raise ValueError("DATA field has no raw bytes")
                    decoded = bytes.fromhex(field.get("value", ""))
                    if len(decoded) != int(field.get("size")):
                        raise ValueError("DATA field byte length mismatch")
                    payload += decoded
            blocks.append(
                HeaderBlock(
                    protocol,
                    int(one(packet, "frame.number")),
                    int(connections.pop()),
                    stream,
                    source == server_port,
                    tuple(pairs),
                    payload,
                    websocket_text if payloads and frame is data_frames[0] else (),
                    (
                        "ls-qpack"
                        if qpack is not None and recovered_key in qpack.recovered
                        else "tshark"
                    ),
                )
            )
    if not blocks and not allow_empty:
        raise ValueError("no decrypted header blocks; check protocol and key log")
    return blocks


def pdml_header_lines(node, name):
    """Read original H1 octets; tshark's display text folds CRLF into spaces."""
    lines = []
    for field in node.iter("field"):
        if field.get("name") != name:
            continue
        raw = bytes.fromhex(field.get("value", ""))
        require(len(raw) == int(field.get("size", "-1")), "H1 field byte length")
        require(raw.endswith(b"\r\n"), "complete H1 header line required")
        line = raw[:-2].decode("latin-1")
        require("\r" not in line and "\n" not in line, "ambiguous H1 header line")
        lines.append(line)
    return lines


def h1_message_body(proto, fields, *, response, method=None, status=None):
    """Require complete bounded H1 framing without altering encoded body bytes."""
    payloads = [
        field for field in proto.iter("field") if field.get("name") == "http.file_data"
    ]
    require(len(payloads) <= 1, "ambiguous H1 reassembled body")
    body = b""
    if payloads:
        field = payloads[0]
        body = bytes.fromhex(field.get("value", ""))
        require(len(body) == int(field.get("size", "-1")), "H1 body byte length")
    limit = 1024 * 1024 if response else 65536
    require(len(body) <= limit, "H1 body byte limit")
    lengths = [value for name, value in fields if name.lower() == "content-length"]
    transfers = [
        value.lower() for name, value in fields if name.lower() == "transfer-encoding"
    ]
    require(
        len(lengths) <= 1 and not (lengths and transfers),
        "ambiguous H1 transfer framing",
    )
    if response and (method == "HEAD" or status in (101, 204, 304)):
        # HEAD/304 metadata describes the representation, never a wire body.
        require(
            not body
            and not any(
                node.get("name")
                in ("http.chunk_size", "http.chunk_data", "http.trailer")
                for node in proto.iter("field")
            ),
            "body on a bodyless H1 response",
        )
        if status in (101, 204):
            require(not lengths and not transfers, "forbidden H1 bodyless framing")
        elif lengths:
            require(
                lengths[0].isascii() and lengths[0].isdecimal(),
                "invalid H1 representation Content-Length",
            )
    elif transfers:
        require(transfers == ["chunked"], "unsupported H1 transfer coding")
        sizes, chunks = [], []
        for field in proto.iter("field"):
            if field.get("name") == "http.chunk_size":
                raw = bytes.fromhex(field.get("value", ""))
                require(
                    len(raw) == int(field.get("size", "-1")) and raw.endswith(b"\r\n"),
                    "incomplete H1 chunk size",
                )
                token = raw[:-2].partition(b";")[0]
                require(
                    token
                    and all(value in b"0123456789abcdefABCDEF" for value in token),
                    "invalid H1 chunk size",
                )
                sizes.append(int(token, 16))
            elif field.get("name") == "http.chunk_data":
                raw = bytes.fromhex(field.get("value", ""))
                require(
                    len(raw) == int(field.get("size", "-1")), "H1 chunk byte length"
                )
                chunks.append(raw)
        require(
            sizes and sizes[-1] == 0 and all(size > 0 for size in sizes[:-1]),
            "incomplete H1 terminal chunk",
        )
        require(
            sizes[:-1] == [len(chunk) for chunk in chunks] and b"".join(chunks) == body,
            "H1 chunk/reassembled body mismatch",
        )
    elif lengths:
        require(
            lengths[0].isascii()
            and lengths[0].isdecimal()
            and int(lengths[0]) == len(body),
            "H1 Content-Length mismatch",
        )
    else:
        require(not response and not body, "unverified close-delimited H1 body")
    return body


def parse_h1_pdml(data, server_port, *, include_data, websocket_probe=WEBSOCKET_PROBE, packets=None):
    """Preserve H1 requests, complete responses and ordinary Upgrade messages.

    Frame references bind messages to their real TCP connection. Raw header
    spelling/order stays intact; body framing and WS nonce/message checks are
    separate. Close-delimited responses require a future explicit adapter.
    """
    if packets is None:
        packets = pdml_packets(data)
    requests, responses, blocks = {}, {}, []
    for packet in packets:
        for proto in packet.findall("proto[@name='http']"):
            methods, statuses = values(proto, "http.request.method"), values(
                proto, "http.response.code"
            )
            if not methods and not statuses:
                continue
            require(bool(methods) != bool(statuses), "ambiguous H1 message direction")
            number, connection = int(one(packet, "frame.number")), int(
                one(packet, "tcp.stream")
            )
            source, destination = int(one(packet, "tcp.srcport")), int(
                one(packet, "tcp.dstport")
            )
            require(
                (source == server_port) != (destination == server_port),
                "ambiguous H1 fixture endpoint",
            )
            if methods:
                require(
                    destination == server_port and len(methods) == 1,
                    "H1 request direction",
                )
                method, uri = methods[0], one(proto, "http.request.uri")
                require(
                    one(proto, "http.request.version") == "HTTP/1.1", "wire protocol"
                )
                lines = pdml_header_lines(proto, "http.request.line")
                fields = tuple(
                    (name, value.lstrip(" \t"))
                    for name, value in (line.split(":", 1) for line in lines)
                )
                hosts = [value for name, value in fields if name.lower() == "host"]
                require(hosts == [one(proto, "http.host")], "ambiguous H1 Host binding")
                body = h1_message_body(proto, fields, response=False)
                key = connection, number
                require(key not in requests, "repeated H1 request identity")
                requests[key] = {
                    "frame.number": str(number),
                    "http.request.method": method,
                    "http.request.uri": uri,
                    "http.request.version": "HTTP/1.1",
                    "http.host": hosts[0],
                    "http.request.line": "\x1f".join(lines),
                    "http.file_data": body.hex(),
                }
                blocks.append(
                    HeaderBlock(
                        "h1",
                        number,
                        connection,
                        number,
                        False,
                        ((":method", method), (":path", uri), *fields),
                        body if include_data else b"",
                    )
                )
            else:
                require(
                    source == server_port and len(statuses) == 1,
                    "H1 response direction",
                )
                status = int(statuses[0])
                if 100 <= status < 200 and status != 101:
                    continue  # Only the final response completes the HTTP operation.
                require(101 <= status <= 599, "invalid H1 final response status")
                key = connection, int(one(proto, "http.request_in"))
                require(key not in responses, "repeated H1 final response")
                lines = pdml_header_lines(proto, "http.response.line")
                fields = tuple(
                    (name, value.lstrip(" \t"))
                    for name, value in (line.split(":", 1) for line in lines)
                )
                responses[key] = (number, status, fields, lines, proto)
    for key, (number, status, fields, lines, proto) in responses.items():
        require(key in requests, "H1 response connection mismatch")
        request = requests[key]
        body = h1_message_body(
            proto,
            fields,
            response=True,
            method=request["http.request.method"],
            status=status,
        )
        blocks.append(
            HeaderBlock(
                "h1",
                number,
                key[0],
                key[1],
                True,
                ((":status", str(status)), *fields),
                body if include_data else b"",
            )
        )
    for key, request in requests.items():
        require(key in responses, "missing complete H1 response")
        if request["http.request.uri"] != "/api/ws":
            continue
        number, status, _fields, lines, _proto = responses[key]
        decode_rows(
            [request],
            [
                {
                    "http.request_in": str(key[1]),
                    "http.response.code": str(status),
                    "http.response.line": "\x1f".join(lines),
                }
            ],
            server_port,
            False,
            secure=True,
            authority=request["http.host"],
            expected_per_flow=1,
            expected_flows=("ws",),
        )
    if not include_data:
        return blocks
    upgrades = {
        connection: stream
        for (connection, stream), request in requests.items()
        if request["http.request.uri"] == "/api/ws"
    }
    require(
        len(upgrades)
        == sum(
            request["http.request.uri"] == "/api/ws" for request in requests.values()
        ),
        "one H1 Upgrade per TCP connection required",
    )
    websocket_packets = []
    for packet in packets:
        if not packet.findall("proto[@name='websocket']"):
            continue
        tcp_ids = values(packet, "tcp.stream")
        if len(tcp_ids) != 1 or int(tcp_ids[0]) not in upgrades:
            continue
        connection = int(tcp_ids[0])
        websocket_packets.append(packet)
        texts = tuple(values(packet, "websocket.payload.text"))
        if texts:
            blocks.append(
                HeaderBlock(
                    "h1",
                    int(one(packet, "frame.number")),
                    connection,
                    upgrades[connection],
                    int(one(packet, "tcp.srcport")) == server_port,
                    (),
                    websocket_text=texts,
                )
            )
    if upgrades:
        document = ET.Element("pdml")
        document.extend(websocket_packets)
        h1_websocket_evidence(
            ET.tostring(document),
            server_port,
            [
                block
                for block in blocks
                if not block.from_server
                and block.headers
                and block.connection in upgrades
                and block.stream == upgrades[block.connection]
            ],
            expected_connections=len(upgrades),
            websocket_probe=websocket_probe,
        )
    return blocks


def read_header_blocks(
    capture,
    keylog,
    protocol,
    server_port,
    output,
    *,
    include_data=False,
    websocket_probe=WEBSOCKET_PROBE,
):
    """Decode into a caller-owned temporary file; never embed TLS keys in captures."""
    capture, keylog, output = map(Path, (capture, keylog, output))
    if capture.stat().st_size > MAX_CAPTURE_BYTES:
        raise ValueError("capture byte limit exceeded")
    if not keylog.is_file():
        raise ValueError("missing TLS key log")
    # Fragment-only QUIC Initials precede the packet containing reassembled TLS.
    # Keep them (and control/QPACK streams) for complete connection verification.
    display_filter = {
        "h2": f"tcp.port == {server_port}",
        "h3": "quic",
        "mixed": f"tcp.port == {server_port} or quic",
    }[protocol]
    with output.open("xb") as decoded:
        subprocess.run(
            [
                "tshark",
                "-r",
                str(capture),
                *http_decode_args(server_port, keylog),
                "-Y",
                display_filter,
                *PDML_OUTPUT,
            ],
            stdout=decoded,
            stderr=subprocess.PIPE,
            check=True,
            timeout=30,
        )
    if output.stat().st_size > MAX_PDML_BYTES:
        raise ValueError("decoded byte limit exceeded")
    data = output.read_bytes()
    packets = pdml_packets(data)
    require_quic_decoding(data, output.with_suffix(".diagnostics.json"), capture=capture, packets=packets)
    return parse_pdml(
        data,
        protocol,
        server_port,
        packets=packets,
        include_data=include_data,
        websocket_probe=websocket_probe,
    )


@dataclass(frozen=True)
class Traffic:
    headers: tuple[HeaderBlock, ...]
    frames: tuple[HeaderBlock, ...]
    bodies: dict
    operations: object = None
    preliminary_report: dict | None = None


def drain_capture(
    process,
    *,
    capture,
    keylog,
    protocol,
    server_port,
    output,
    timeout=15,
    expected_per_flow=None,
    expected_warmups=0,
    preliminary_plan=None,
    websocket_probe=WEBSOCKET_PROBE,
    operations=None,
):
    """Wait for all decoded flows, including responses and both WebSocket directions.

    A dumpcap file announcement proves readiness, not that BPF has flushed the
    final packets. Keep decoding until full body coverage is visible.
    """
    if type(expected_warmups) is not int or expected_warmups < 0:
        raise ValueError("nonnegative warmup count required")
    expected_counts = (
        None if expected_per_flow is None else flow_counts(expected_per_flow)
    )
    deadline = time.monotonic() + timeout
    last_error = None
    while time.monotonic() < deadline:
        output.unlink(missing_ok=True)
        try:
            frames = read_header_blocks(
                capture,
                keylog,
                protocol,
                server_port,
                output,
                include_data=True,
                websocket_probe=websocket_probe,
            )
            bound_operations = operations
            preliminary_report = None
            if preliminary_plan is not None:
                bound_operations, preliminary_report = preliminary_plan.bind(
                    output.read_bytes(), frames
                )
            bodies = check_flow_bodies(
                frames,
                websocket_probe=websocket_probe,
                **(
                    {"operations": bound_operations}
                    if bound_operations is not None
                    else {}
                ),
            )
            if expected_per_flow is not None:
                counts = Counter(
                    operation_flow(frame, bound_operations)
                    for frame in frames
                    if frame.headers and not frame.from_server
                )
                warmups = [
                    dict(frame.headers)
                    for frame in frames
                    if frame.headers
                    and not frame.from_server
                    and operation_flow(frame, bound_operations) is None
                ]
                if (
                    counts[None] != expected_warmups
                    or preliminary_plan is None
                    and any(
                        headers.get(":method") != "GET"
                        or headers.get(":path") != "/"
                        or ":protocol" in headers
                        for headers in warmups
                    )
                    or any(counts[flow] != expected_counts[flow] for flow in FLOWS)
                ):
                    raise ValueError("incomplete or unexpected replay request counts")
            return Traffic(
                tuple(frame for frame in frames if frame.headers),
                tuple(frames),
                bodies,
                bound_operations,
                preliminary_report,
            )
        except (OSError, ValueError, subprocess.CalledProcessError) as error:
            last_error = error
        if process.poll() is not None:
            break
        time.sleep(0.1)
    raise RuntimeError("incomplete independently decoded capture") from last_error


# H1 decoding preserves request lines, repeated headers and Upgrade bindings.

GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def require(condition, message):
    if not condition:
        raise ValueError(message)


@dataclass(frozen=True)
class Request:
    method: str
    uri: str
    headers: tuple
    body: bytes
    bindings: dict
    protocol: str | None = None

    def wire_tuple(self):
        return self.protocol, self.method, self.uri, self.headers, self.body


def http_decode_args(port, keylog=None):
    """Select the transport dissector without ever embedding session secrets."""
    if keylog is None:
        return ["-d", f"tcp.port=={port},http"]
    require(Path(keylog).is_file(), "missing TLS key log")
    return [
        "-d",
        f"tcp.port=={port},tls",
        "-o",
        f"tls.keylog_file:{keylog}",
        "-o",
        "http.decompress_body:FALSE",
    ]


def field_rows(path, port, display_filter, fields, *, keylog=None, output=None):
    require(path.stat().st_size <= 40 * 1024 * 1024, "capture byte limit")
    args = [
        "tshark",
        "-r",
        str(path),
        *http_decode_args(port, keylog),
        "-Y",
        display_filter,
        "-T",
        "fields",
        "-E",
        "header=y",
        "-E",
        "quote=d",
        "-E",
        "separator=\t",
        "-E",
        "aggregator=\x1f",
    ]
    for field in fields:
        args += ["-e", field]
    text = subprocess.check_output(args, text=True, timeout=15)
    require(len(text) <= 4 * 1024 * 1024, "decoded field byte limit")
    rows = list(csv.DictReader(io.StringIO(text), delimiter="\t"))
    require(len(rows) <= 4096, "decoded row limit")
    if output is not None:
        output.write_text(text)
    return rows


def header_lines(value):
    return [line.removesuffix(r"\r\n") for line in value.split("\x1f") if line]


def decode_rows(
    requests,
    responses,
    port,
    reference,
    *,
    secure=False,
    expected_per_flow=1,
    expected_flows=FLOWS,
    authority=None,
):
    replies = {}
    for row in responses:
        frame = row["http.request_in"]
        require(frame not in replies, "ambiguous response association")
        replies[frame] = row
    output = {}
    for row in requests:
        method, uri = row["http.request.method"], row["http.request.uri"]
        if (
            reference
            and method == "GET"
            and (uri.startswith("/assets/") or uri == "/favicon.ico")
        ):
            continue
        flow = (
            "navigate"
            if uri == "/report" and method == "GET"
            else (
                "fetch"
                if re.fullmatch(r"/api/fetch/number/[0-9]+", uri) and method == "POST"
                else (
                    "xhr"
                    if re.fullmatch(r"/api/xml/number/[0-9]+", uri) and method == "POST"
                    else (
                        "form"
                        if uri == "/form" and method == "POST"
                        else (
                            "form_get"
                            if uri == "/form?source=web&turtles=yes" and method == "GET"
                            else "ws" if uri == "/api/ws" and method == "GET" else None
                        )
                    )
                )
            )
        )
        require(flow is not None, f"unexpected request: {method} {uri}")
        require(row["http.request.version"] == "HTTP/1.1", "wire protocol")
        authority = authority or (
            f"localhost:{port}" if secure else f"127.0.0.1:{port}"
        )
        require(row["http.host"] == authority, "loopback authority")
        body = bytes.fromhex(row["http.file_data"])
        require(len(body) <= 65536, "request body limit")
        normalized, bindings = [], {}
        key = None
        host_count = 0
        for line in header_lines(row["http.request.line"]):
            name, raw = line.split(":", 1)
            value = raw.lstrip(" \t")
            prefix = raw[: len(raw) - len(value)]
            lower = name.lower()
            require(
                lower
                not in (
                    "cookie",
                    "authorization",
                    "proxy-authorization",
                    "transfer-encoding",
                ),
                "fixture requires credential-free, fixed-length requests",
            )
            if lower in (
                "connection",
                "content-type",
                "content-length",
                "origin",
                "sec-websocket-protocol",
                "sec-websocket-extensions",
                "x-rama-custom-header-marker",
            ):
                require(lower not in bindings, "duplicate request-owned field")
                bindings[lower] = value
            if lower == "host":
                host_count += 1
                require(value == authority, "Host binding")
                value = "<authority>"
            elif lower == "origin" and value != "null":
                scheme = "https" if secure else "http"
                require(value == scheme + "://" + authority, "Origin binding")
                value = scheme + "://<authority>"
            elif lower == "sec-websocket-key":
                require(flow == "ws" and key is None, "unexpected WebSocket key")
                key = value
                require(
                    len(base64.b64decode(value, validate=True)) == 16,
                    "WebSocket key length",
                )
                value = "<websocket-key>"
            normalized.append(name + ":" + prefix + value)
        require(host_count == 1, "single Host field")
        if "content-length" in bindings:
            require(
                bindings["content-length"].isdecimal()
                and int(bindings["content-length"]) == len(body),
                "Content-Length binding",
            )
        else:
            require(not body, "missing request framing")
        reply = replies.get(row["frame.number"])
        require(reply is not None, "missing response")
        require(
            reply["http.response.code"] == ("101" if flow == "ws" else "200"),
            "response status",
        )
        if flow == "ws":
            require(key is not None, "missing WebSocket key")
            accepts = [
                line.split(":", 1)[1].strip()
                for line in header_lines(reply["http.response.line"])
                if line.split(":", 1)[0].lower() == "sec-websocket-accept"
            ]
            expected = base64.b64encode(
                hashlib.sha1((key + GUID).encode("ascii")).digest()
            ).decode("ascii")
            require(accepts == [expected], "WebSocket accept binding")
        output.setdefault(flow, []).append(
            Request(method, uri, tuple(normalized), body, bindings)
        )
    require(
        set(output) == set(expected_flows),
        (
            "six-operation coverage"
            if set(expected_flows) == set(FLOWS)
            else "expected H1 operation coverage"
        ),
    )
    for flow, rows in output.items():
        require(
            (reference and (len(rows) == 1 or (flow == "navigate" and len(rows) <= 8)))
            or (not reference and len(rows) == expected_per_flow),
            "ambiguous repeated flow",
        )
    return output


def read_capture(path, port, reference, *, keylog=None, expected_per_flow=1):
    responses = field_rows(
        path,
        port,
        "http.response",
        ["http.request_in", "http.response.code", "http.response.line"],
        keylog=keylog,
        output=path.with_suffix(".responses.tsv"),
    )
    requests = field_rows(
        path,
        port,
        "http.request",
        [
            "frame.number",
            "http.request.method",
            "http.request.uri",
            "http.request.version",
            "http.host",
            "http.request.line",
            "http.file_data",
        ],
        keylog=keylog,
        output=path.with_suffix(".requests.tsv"),
    )
    return decode_rows(
        requests,
        responses,
        port,
        reference,
        secure=keylog is not None,
        expected_per_flow=expected_per_flow,
    )


def h1_header_blocks(rows):
    """Keep exact H1 field spelling/order and real TCP/frame coordinates.

    Method/path classify an observation; they are not H1 pseudo-headers on wire.
    The caller separately admits request/response/body bindings with decode_rows.
    """
    blocks = []
    for row in rows:
        uri = row["http.request.uri"]
        if uri.startswith("/assets/") or uri == "/favicon.ico":
            continue
        require(row["http.request.version"] == "HTTP/1.1", "wire protocol")
        require(row["frame.number"].isdecimal(), "ambiguous request frame")
        require(row["tcp.stream"].isdecimal(), "ambiguous request TCP stream")
        fields = []
        for line in header_lines(row["http.request.line"]):
            name, value = line.split(":", 1)
            require(name and not name.startswith(":"), "invalid H1 field name")
            fields.append((name, value.lstrip(" \t")))
        blocks.append(
            HeaderBlock(
                "h1",
                int(row["frame.number"]),
                int(row["tcp.stream"]),
                int(row["frame.number"]),
                False,
                ((":method", row["http.request.method"]), (":path", uri), *fields),
            )
        )
    require(blocks, "no decoded H1 fixture operations")
    return blocks


def read_h1_header_blocks(capture, port, *, keylog=None):
    rows = field_rows(
        capture,
        port,
        "http.request",
        [
            "frame.number",
            "tcp.stream",
            "http.request.method",
            "http.request.uri",
            "http.request.version",
            "http.request.line",
        ],
        keylog=keylog,
        output=capture.with_suffix(".headers.tsv"),
    )
    return h1_header_blocks(rows)


def h1_websocket_evidence(
    data,
    server_port,
    requests,
    *,
    expected_connections=1,
    websocket_probe=WEBSOCKET_PROBE,
):
    """Bind decoded frames to Upgrade requests on their actual TCP connections.

    Tshark handles masking, decompression and TCP reassembly. This fixture checks
    one complete text exchange and a close in both directions; it deliberately
    rejects fragmented/binary messages rather than claiming their coverage.
    """
    require(expected_connections > 0, "missing expected WebSocket connections")
    upgrades = [
        request
        for request in requests
        if flow_name(request.headers, protocol="h1") == "ws"
    ]
    connections = {request.connection: request.packet for request in upgrades}
    require(
        len(upgrades) == len(connections) == expected_connections,
        "WebSocket Upgrade connection count",
    )
    frames = {connection: [] for connection in connections}

    for packet in pdml_packets(data):
        decoded = [
            proto for proto in packet.iter("proto") if proto.get("name") == "websocket"
        ]
        if not decoded:
            continue
        connection = int(one(packet, "tcp.stream"))
        require(connection in connections, "WebSocket frame has no Upgrade request")
        require(
            int(one(packet, "frame.number")) > connections[connection],
            "WebSocket frame precedes its Upgrade request",
        )
        source = int(one(packet, "tcp.srcport"))
        destination = int(one(packet, "tcp.dstport"))
        require(
            (source == server_port) != (destination == server_port),
            "ambiguous WebSocket fixture endpoint",
        )
        from_server = source == server_port

        for proto in decoded:
            require(
                one(proto, "websocket.fin") == "True", "fragmented WebSocket fixture"
            )
            require(
                one(proto, "websocket.mask") == ("False" if from_server else "True"),
                "WebSocket masking direction",
            )
            opcode = one(proto, "websocket.opcode")
            require(opcode in ("1", "8"), "unexpected WebSocket fixture opcode")
            text = values(proto, "websocket.payload.text")
            require(
                len(text) == (1 if opcode == "1" else 0), "ambiguous WebSocket text"
            )
            if opcode == "8":
                require(
                    one(proto, "websocket.payload.close.status_code") == "1000",
                    "WebSocket close is not normal",
                )
            frames[connection].append((from_server, opcode, text[0] if text else None))

    for messages in frames.values():
        incoming, outgoing = [], []
        closed = {False: False, True: False}
        for from_server, opcode, text in messages:
            require(not closed[from_server], "WebSocket frame follows its close")
            if opcode == "8":
                closed[from_server] = True
            else:
                (outgoing if from_server else incoming).append(text)
        check_websocket_messages("h1", incoming, outgoing, probe=websocket_probe)
        require(all(closed.values()), "WebSocket close missing in one direction")

    return {
        "connections_checked": len(connections),
        "client_messages_checked": len(connections),
        "server_messages_checked": 2 * len(connections),
        "close_frames_checked": 2 * len(connections),
        "scope": "independent H1 WebSocket greeting, UTF-8 probe, echo, masking and close",
        "limits": "one unfragmented text exchange per Upgrade; no binary or long-lived coverage",
    }


def read_h1_websocket_evidence(
    capture,
    port,
    requests,
    *,
    keylog=None,
    expected_connections=1,
    websocket_probe=WEBSOCKET_PROBE,
):
    """Retain a bounded, decrypted dissection before ephemeral keys are removed."""
    require(capture.stat().st_size <= MAX_CAPTURE_BYTES, "capture byte limit")
    output = capture.with_suffix(".websocket.pdml")
    with output.open("xb") as decoded:
        subprocess.run(
            [
                "tshark",
                "-r",
                str(capture),
                *http_decode_args(port, keylog),
                "-Y",
                "websocket",
                *PDML_OUTPUT,
            ],
            stdout=decoded,
            check=True,
            timeout=15,
        )
    return h1_websocket_evidence(
        output.read_bytes(),
        port,
        requests,
        expected_connections=expected_connections,
        websocket_probe=websocket_probe,
    )


def h1_tls_evidence(capture, keylog, port, output, inspected):
    """Check TCP TLS on streams carrying the six profiled fixture operations.

    Static assets can use separate browser connections without creating profile
    observations. Exclude only those known asset requests, as read_capture does.
    """
    # tls_wire shares the bounded PDML parser above; defer to avoid an import cycle.
    from tls_wire import client_hellos, compare_tls_captures

    require(capture.stat().st_size <= MAX_CAPTURE_BYTES, "capture byte limit")
    with output.open("xb") as decoded:
        subprocess.run(
            [
                "tshark",
                "-r",
                str(capture),
                *http_decode_args(port, keylog),
                "-Y",
                f"tcp.port == {port}",
                *PDML_OUTPUT,
            ],
            stdout=decoded,
            check=True,
            timeout=15,
        )
    rows = field_rows(
        capture,
        port,
        "http.request",
        ["frame.number", "tcp.stream", "http.user_agent", "http.request.uri"],
        keylog=keylog,
        output=capture.with_suffix(".tls-requests.tsv"),
    )
    requests = []
    asset_requests = 0
    for row in rows:
        uri = row["http.request.uri"]
        require(uri and "\x1f" not in uri, "missing or ambiguous request URI")
        if uri.startswith("/assets/") or uri == "/favicon.ico":
            asset_requests += 1
            continue
        require(row["frame.number"].isdecimal(), "ambiguous request frame")
        require(row["tcp.stream"].isdecimal(), "ambiguous request TCP stream")
        require(
            row["http.user_agent"] and "\x1f" not in row["http.user_agent"],
            "missing or ambiguous request user agent",
        )
        requests.append(
            HeaderBlock(
                "h1",
                int(row["frame.number"]),
                int(row["tcp.stream"]),
                int(row["frame.number"]),
                False,
                (("user-agent", row["http.user_agent"]),),
            )
        )
    report = compare_tls_captures(
        inspected, client_hellos(output.read_bytes(), "Tcp"), requests
    )
    report["unprofiled_asset_requests"] = asset_requests
    return report


def verify_h1_flows(root, reference_port, replay_port, *, secure=False, variants=1):
    reports = compare_requests(
        read_capture(
            root / "reference-wire.pcapng",
            reference_port,
            True,
            keylog=root / "browser.keys" if secure else None,
        ),
        read_capture(
            root / "replay-wire.pcapng",
            replay_port,
            False,
            keylog=root / "replay.keys" if secure else None,
            expected_per_flow=variants,
        ),
        expected_per_flow=variants,
    )
    report = {
        "scope": "HTTP/1 six-operation request header tuples and bodies",
        "normalization": "validated Host/Origin authorities and WebSocket nonce with checked response accept",
        "transport": "TLS" if secure else "plaintext",
        "limits": "credential-free same-origin H1 fixture; TLS shape checks are separate; no H2/H3 or distribution claim",
        "comparisons": reports,
    }
    (root / "wire-comparison.json").write_text(json.dumps(report, indent=2) + "\n")
    require(
        all(item["match"] for item in reports),
        "six-operation wire mismatch; see wire-comparison.json",
    )
    print(
        json.dumps({"result": "PASS", "flows": list(FLOWS), "scope": report["scope"]})
    )


# Navigation-only checks retain the optional small H1 smoke test.


def decode_requests(text, port):
    rows = list(csv.DictReader(io.StringIO(text), delimiter="\t"))
    selected = [
        row
        for row in rows
        if row["http.request.method"] == "GET" and row["http.request.uri"] == "/report"
    ]
    if not selected:
        raise ValueError("no decoded GET /report")
    result = []
    for row in selected:
        if row["http.request.version"] != "HTTP/1.1":
            raise ValueError("incorrect wire protocol")
        if row["http.host"] != f"127.0.0.1:{port}":
            raise ValueError("incorrect request-owned authority")
        lines = row["http.request.line"].split("\x1f")
        if len(lines) < 4:
            raise ValueError("missing decoded HTTP header lines")
        lines = [
            re.sub(r"(?i)^(host:\s*)127\.0\.0\.1:\d+", r"\1<request-authority>", line)
            for line in lines
        ]
        result.append(lines)
    return result


def compare_navigation(reference, replay):
    if len(replay) != 1:
        raise ValueError("replay request count")
    if replay[0] not in reference:
        raise ValueError(
            "wire header names/order/values differ from retained browser requests"
        )
    return len(replay[0])


def verify_h1_navigation(root, reference_port, replay_port):
    def requests(label, port):
        args = [
            "tshark",
            "-r",
            str(root / (label + ".pcapng")),
            "-d",
            f"tcp.port=={port},http",
            "-Y",
            "http.request",
            "-T",
            "fields",
            "-E",
            "header=y",
            "-E",
            "quote=d",
            "-E",
            "separator=\t",
            "-E",
            "aggregator=\x1f",
        ]
        for field in [
            "http.request.method",
            "http.request.uri",
            "http.request.version",
            "http.host",
            "http.request.line",
        ]:
            args += ["-e", field]
        text = subprocess.check_output(args, text=True, timeout=10)
        (root / (label + ".tsv")).write_text(text)
        return decode_requests(text, port)

    reference = requests("reference-wire", reference_port)
    replay = requests("replay-wire", replay_port)
    header_count = compare_navigation(reference, replay)
    report = {
        "result": "PASS",
        "scope": "independent tshark HTTP/1 GET /report header names, order and values",
        "reference_requests": len(reference),
        "replay_requests": len(replay),
        "header_count": header_count,
        "normalization": "Host value only; verified separately against each listener",
        "limits": "No TLS, HTTP/2, HTTP/3 or distribution coverage claim",
    }
    (root / "wire-comparison.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))
