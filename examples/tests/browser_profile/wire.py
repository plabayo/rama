"""Independent tshark wire verification for H1, H2 and H3.

H1 uses decoded request/response rows and Upgrade bindings. H2/H3 use PDML
stream identity and Extended CONNECT. Protocol-specific decoding lives here;
browser journeys and replay inputs are shared elsewhere.
"""

from dataclasses import dataclass
from pathlib import Path
import subprocess
import xml.etree.ElementTree as ET
import base64
import csv
import difflib
import hashlib
import io
import json
import re
import sys

from flows import FLOWS

MAX_CAPTURE_BYTES = 40 * 1024 * 1024


MAX_PDML_BYTES = 64 * 1024 * 1024


MAX_PACKETS = 8192


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


def values(node, name):
    return [
        field.get("show", "")
        for field in node.iter("field")
        if field.get("name") == name
    ]


def one(node, name):
    found = values(node, name)
    if len(found) != 1:
        raise ValueError(f"expected one {name}, found {len(found)}")
    return found[0]


def pdml_packets(data, *, byte_limit=None, packet_limit=None):
    """Admit one bounded tshark document before protocol-specific decoding."""
    byte_limit = MAX_PDML_BYTES if byte_limit is None else byte_limit
    packet_limit = MAX_PACKETS if packet_limit is None else packet_limit
    if len(data) > byte_limit:
        raise ValueError("decoded byte limit exceeded")
    # Tshark emits UTF-8. NUL bytes must be rejected separately: an ASCII
    # UTF-16 document also decodes as UTF-8, but XML parsers detect its encoding
    # from those NULs and could expand declarations hidden from the byte scan.
    if b"\0" in data:
        raise ValueError("PDML must use UTF-8 without NUL bytes")
    try:
        data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("PDML must use UTF-8") from error

    if b"<!DOCTYPE" in data or b"<!ENTITY" in data:
        raise ValueError("external/entity declarations are not valid tshark output")
    root = ET.fromstring(data)
    if root.tag != "pdml":
        raise ValueError("expected tshark PDML")
    packets = root.findall("packet")
    if len(packets) > packet_limit:
        raise ValueError("decoded packet limit exceeded")
    return packets


def parse_pdml(data, protocol, server_port, *, include_data=False):
    """Reject ambiguous frame identity; preserve duplicate header names and order."""
    if protocol not in ("h2", "h3"):
        raise ValueError("expected h2 or h3")
    packets = pdml_packets(data)
    blocks = []
    for packet in packets:
        containers = [
            field
            for field in packet.iter("field")
            if field.get("name")
            == ("http2.stream" if protocol == "h2" else "http3.frame")
        ]
        header_name = "http2.header" if protocol == "h2" else "http3.headers.header"
        data_name = "http2.data.data" if protocol == "h2" else "http3.data"
        data_frames = [
            frame
            for frame in containers
            if any(field.get("name") == data_name for field in frame.iter("field"))
        ]
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
        for frame in containers:
            headers = [
                field
                for field in frame.iter("field")
                if field.get("name") == header_name
            ]
            payloads = [
                field for field in frame.iter("field") if field.get("name") == data_name
            ]
            if not headers and not (include_data and payloads):
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
                )
            )
    if not blocks:
        raise ValueError("no decrypted header blocks; check protocol and key log")
    return blocks


def read_header_blocks(capture, keylog, protocol, server_port, output):
    """Decode into a caller-owned temporary file; never embed TLS keys in captures."""
    capture, keylog, output = map(Path, (capture, keylog, output))
    if capture.stat().st_size > MAX_CAPTURE_BYTES:
        raise ValueError("capture byte limit exceeded")
    if not keylog.is_file():
        raise ValueError("missing TLS key log")
    prefix = "http2" if protocol == "h2" else "http3"
    with output.open("xb") as decoded:
        subprocess.run(
            [
                "tshark",
                "-r",
                str(capture),
                "-o",
                "tls.keylog_file:" + str(keylog),
                "-Y",
                f"{prefix} or tls.handshake.type == 1",
                "-T",
                "pdml",
            ],
            stdout=decoded,
            stderr=subprocess.PIPE,
            check=True,
            timeout=30,
        )
    if output.stat().st_size > MAX_PDML_BYTES:
        raise ValueError("decoded byte limit exceeded")
    return parse_pdml(output.read_bytes(), protocol, server_port)


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

    def wire_tuple(self):
        return self.method, self.uri, self.headers, self.body


def field_rows(path, port, display_filter, fields):
    require(path.stat().st_size <= 40 * 1024 * 1024, "capture byte limit")
    args = [
        "tshark",
        "-r",
        str(path),
        "-d",
        f"tcp.port=={port},http",
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
    return rows


def header_lines(value):
    return [line.removesuffix(r"\r\n") for line in value.split("\x1f") if line]


def decode_rows(requests, responses, port, reference):
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
        authority = f"127.0.0.1:{port}"
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
            ):
                require(lower not in bindings, "duplicate request-owned field")
                bindings[lower] = value
            if lower == "host":
                host_count += 1
                require(value == authority, "Host binding")
                value = "<authority>"
            elif lower == "origin" and value != "null":
                require(value == "http://" + authority, "Origin binding")
                value = "http://<authority>"
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
    require(set(output) == set(FLOWS), "six-operation coverage")
    for flow, rows in output.items():
        require(
            len(rows) == 1 or (reference and flow == "navigate" and len(rows) <= 8),
            "ambiguous repeated flow",
        )
    return output


def read_capture(path, port, reference):
    responses = field_rows(
        path,
        port,
        "http.response",
        ["http.request_in", "http.response.code", "http.response.line"],
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
    )
    return decode_rows(requests, responses, port, reference)


def compare_h1(reference, replay):
    require(
        set(reference) == set(FLOWS) == set(replay), "six-operation comparison coverage"
    )
    reports = []
    for flow in FLOWS:
        require(len(replay[flow]) == 1, "one replay request per flow")
        observed = replay[flow][0]
        matched = any(
            observed.wire_tuple() == candidate.wire_tuple()
            for candidate in reference[flow]
        )
        reports.append(
            {
                "flow": flow,
                "match": matched,
                "body_match": any(
                    observed.body == candidate.body for candidate in reference[flow]
                ),
                "differences": (
                    []
                    if matched
                    else list(
                        difflib.unified_diff(
                            reference[flow][0].headers, observed.headers, lineterm=""
                        )
                    )
                ),
            }
        )
    return reports


def verify_h1_flows(root, reference_port, replay_port):
    reports = compare_h1(
        read_capture(root / "reference-wire.pcapng", reference_port, True),
        read_capture(root / "replay-wire.pcapng", replay_port, False),
    )
    report = {
        "scope": "HTTP/1 six-operation request header tuples and bodies",
        "normalization": "validated Host/Origin authorities and WebSocket nonce with checked response accept",
        "limits": "credential-free same-origin fixture; no TLS, H2, H3 or distribution claim",
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
