"""Correlate one driver's existing page results with its independently decoded traffic."""

from collections import Counter, defaultdict
from html.parser import HTMLParser
import ipaddress
from urllib.parse import urlsplit

from flow_bodies import json_object
from flows import FLOWS, flow_name, operation_flow, request_authority
from operations import DISCOVERY
from native_h3_response import decoded_body, native_view, response_data
from tls_wire import identity
from wire import one, parse_h1_pdml, pdml_packets, values

MAX_PAGE_BYTES = 1024 * 1024
MAX_DISCOVERY_REQUESTS = 32
VERSIONS = {"h1": "HTTP/1.1", "h2": "HTTP/2.0", "h3": "HTTP/3.0"}


class RequestTables(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.tables, self.rows, self.cells, self.text = [], None, None, None

    def handle_starttag(self, tag, attrs):
        if tag == "table":
            if self.rows is not None:
                raise ValueError("nested page table")
            self.rows = []
        elif self.rows is not None and tag == "tr":
            self.cells = []
        elif self.cells is not None and tag == "td":
            self.text = []

    def handle_data(self, text):
        if self.text is not None:
            self.text.append(text)

    def handle_endtag(self, tag):
        if tag == "td" and self.text is not None:
            self.cells.append("".join(self.text))
            self.text = None
        elif tag == "tr" and self.cells is not None:
            self.rows.append(self.cells)
            self.cells = None
        elif tag == "table" and self.rows is not None:
            self.tables.append(self.rows)
            self.rows = None


def request_info(page):
    if not isinstance(page, str) or len(page.encode()) > MAX_PAGE_BYTES:
        raise ValueError("bounded driver-observed page required")
    parser = RequestTables()
    parser.feed(page)
    parser.close()
    required = {"Version", "Method", "Scheme", "Authority", "Path", "Socket Address"}
    candidates = []
    for table in parser.tables:
        selected = [row for row in table if len(row) == 2 and row[0] in required]
        if {row[0] for row in selected} == required:
            if len(selected) != len(required):
                raise ValueError("duplicate native Request Info row")
            candidates.append(dict(selected))
    if len(candidates) != 1:
        raise ValueError("missing or ambiguous native Request Info table")
    value = candidates[0]
    return {
        name: value[label]
        for name, label in dict(
            version="Version",
            method="Method",
            scheme="Scheme",
            authority="Authority",
            path="Path",
            peer_addr="Socket Address",
        ).items()
    }


def peer_socket(value):
    if not isinstance(value, str) or len(value) > 128:
        raise ValueError("missing native peer socket")
    parsed = urlsplit("//" + value)
    if (
        not parsed.hostname
        or parsed.port is None
        or parsed.path
        or parsed.query
        or parsed.fragment
        or parsed.username
    ):
        raise ValueError("invalid native peer socket")
    return str(ipaddress.ip_address(parsed.hostname)), parsed.port


def packet_peers(data, port):
    peers = {}
    for packet in pdml_packets(data):
        number = int(one(packet, "frame.number"))
        for protocol, transport in (("h1", "tcp"), ("h2", "tcp"), ("h3", "udp")):
            destination = values(packet, transport + ".dstport")
            if not destination or set(destination) != {str(port)}:
                continue
            addresses = set(values(packet, "ip.src") + values(packet, "ipv6.src"))
            ports = set(values(packet, transport + ".srcport"))
            if len(addresses) != 1 or len(ports) != 1:
                raise ValueError("ambiguous packet source socket")
            peers[(protocol, number)] = (
                str(ipaddress.ip_address(addresses.pop())),
                int(ports.pop()),
            )
    return peers


def captured_connections(data, port):
    """Keep undecoded or requestless traffic from being silently ignored."""
    connections = set()
    for packet in pdml_packets(data):
        for transport, field in (
            ("tcp", "tcp.stream"),
            ("udp", "quic.connection.number"),
        ):
            ports = values(packet, transport + ".srcport") + values(
                packet, transport + ".dstport"
            )
            if str(port) in ports:
                connections.add((transport, identity(packet, field)))
    return connections


def group_for(frames, key):
    return [
        block
        for block in frames
        if (block.protocol, block.connection, block.stream) == key
    ]


def response_object(frames):
    heads = [block for block in frames if block.from_server and block.headers]
    if len(heads) != 1 or dict(heads[0].headers).get(":status") != "200":
        raise ValueError("one successful source response required")
    coding = [
        value for name, value in heads[0].headers if name.lower() == "content-encoding"
    ]
    if len(coding) > 1:
        raise ValueError("ambiguous source content coding")
    return decoded_body(
        b"".join(block.data for block in frames if block.from_server),
        coding[0] if coding else None,
    )


def complete_responses(data, port):
    complete = {
        ("h3", connection, stream) for connection, stream in response_data(data, port)
    }
    for packet in pdml_packets(data):
        if set(values(packet, "tcp.srcport")) != {str(port)}:
            continue
        for frame in packet.iter("field"):
            if frame.get("name") != "http2.stream":
                continue
            flags = [
                item
                for item in frame.iter("field")
                if item.get("name") == "http2.flags"
            ]
            if not flags:
                continue
            if len(flags) != 1:
                raise ValueError("ambiguous H2 response flags")
            # The parent owns the byte; masked children can have odd-width values.
            raw = bytes.fromhex(flags[0].get("value", ""))
            if len(raw) != 1 or flags[0].get("size") != "1":
                raise ValueError("ambiguous H2 response flags")
            if raw[0] & 1:
                complete.add(
                    (
                        "h2",
                        identity(packet, "tcp.stream"),
                        int(one(frame, "http2.streamid")),
                    )
                )
    complete.update(
        ("h1", block.connection, block.stream)
        for block in parse_h1_pdml(data, port, include_data=False)
        if block.from_server and block.headers
    )
    return complete


def admit(data, frames, page, origin, *, operations=None):
    """Require exact per-flow native peer binding and one driver-known WS probe.

    Native JSON redacts raw CIDs. We bind peer/request streams, while the ordinary
    QUIC verifier establishes its own wire CID/connection continuity separately.
    """
    if not isinstance(page, dict) or set(page.get("protocols", {})) != set(FLOWS):
        raise ValueError("complete driver protocols required")
    protocols = page["protocols"]
    results = page.get("page_results")
    if not isinstance(results, dict):
        raise ValueError("driver page results missing")
    destination = urlsplit(origin)
    authority = destination.netloc
    heads = [block for block in frames if block.headers and not block.from_server]
    if any(
        name.lower() in {"cookie", "authorization", "proxy-authorization"}
        for block in heads
        for name, _ in block.headers
    ):
        raise ValueError("owned source journey must remain credential-free")
    user_agent = page.get("user_agent")
    if not isinstance(user_agent, str) or not user_agent or len(user_agent) > 4096:
        raise ValueError("driver User-Agent identity missing")
    if any(
        [value for name, value in block.headers if name.lower() == "user-agent"]
        != [user_agent]
        for block in heads
    ):
        raise ValueError("source contains a different or ambiguous User-Agent")
    request_connections = {
        ("udp" if block.protocol == "h3" else "tcp", block.connection)
        for block in heads
    }
    if captured_connections(data, destination.port) != request_connections:
        raise ValueError("unattributed requestless or undecoded source connection")
    peers = packet_peers(data, destination.port)
    html_pages = {
        flow: page[key]
        for flow, key in (
            ("navigate", "report_html"),
            ("form", "form_html"),
            ("form_get", "get_form_html"),
        )
    }
    native_h3 = {
        flow: native_view(document.encode(), "text/html; charset=utf-8")
        for flow, document in html_pages.items()
        if protocols[flow] == "h3"
    }
    completed = complete_responses(data, destination.port)
    native = {
        flow: request_info(page[key])
        for flow, key in (
            ("navigate", "report_html"),
            ("form", "form_html"),
            ("form_get", "get_form_html"),
        )
    }
    for flow in ("fetch", "xhr"):
        try:
            native[flow] = results[flow]["fp"]["request_info"]
        except (KeyError, TypeError) as error:
            raise ValueError("driver native response missing") from error
        if protocols[flow] == "h3":
            native_h3[flow] = results[flow]["fp"]["http_info"].get("h3")
    selected = {}
    keys = set()
    for flow, info in native.items():
        if (
            not isinstance(info, dict)
            or info.get("version") != VERSIONS.get(protocols[flow])
            or info.get("authority") != authority
            or info.get("scheme") != "https"
        ):
            raise ValueError("driver native request identity differs")
        candidates = []
        for block in heads:
            fields = dict(block.headers)
            if (
                operation_flow(block, operations) == flow
                and (operations is None or operations.name(block) == flow)
                and block.protocol == protocols[flow]
                and fields.get(":method") == info.get("method")
                and urlsplit(fields.get(":path", "")).path == info.get("path")
                and request_authority(block) == authority
                and (
                    flow not in ("fetch", "xhr")
                    or info.get("uri") == origin + fields.get(":path", "")
                )
                and peers.get((block.protocol, block.packet))
                == peer_socket(info.get("peer_addr"))
            ):
                if block.protocol == "h3" and (
                    not isinstance(native_h3[flow], dict)
                    or native_h3[flow].get("request_stream_id") != block.stream
                ):
                    continue
                candidates.append(block)
        if len(candidates) != 1:
            raise ValueError(
                "driver flow has no unique packet/native association: " + flow
            )
        block = candidates[0]
        key = (block.protocol, block.connection, block.stream)
        if key in keys:
            raise ValueError("two driver operations share one HTTP stream")
        if key not in completed:
            raise ValueError("source HTTP response completion is missing")
        response = response_object(group_for(frames, key))
        if flow in ("fetch", "xhr"):
            if json_object(response) != results[flow]:
                raise ValueError("driver JSON response differs from its wire stream")
        elif request_info(response.decode()) != info:
            raise ValueError("driver Request Info differs from its wire response")
        keys.add(key)
        selected[flow] = key
    if operations is not None:
        operations.validate_heads(heads)
        for operation in operations.operations:
            if operation.name != DISCOVERY:
                continue
            block = next(
                block for block in heads if operations.name(block) == DISCOVERY
            )
            key = operation.key
            if key in keys or key not in completed:
                raise ValueError(
                    "discovery navigation response missing or shares a measured stream"
                )
            response = response_object(group_for(frames, key))
            info = request_info(response.decode())
            if (
                info["version"] != VERSIONS[operation.protocol]
                or info["method"] != operation.method
                or info["scheme"] != "https"
                or info["authority"] != authority
                or info["path"] != urlsplit(operation.uri).path
                or peers.get((block.protocol, block.packet))
                != peer_socket(info["peer_addr"])
            ):
                raise ValueError(
                    "discovery native response is not bound to its source request"
                )
            if operation.protocol == "h3":
                view = native_view(response, "text/html; charset=utf-8")
                if (
                    not isinstance(view, dict)
                    or type(view.get("request_stream_id")) is not int
                    or view["request_stream_id"] != block.stream
                ):
                    raise ValueError("discovery native H3 response stream differs")
            keys.add(key)
            selected[DISCOVERY] = key
    try:
        probe = results["websocket"]["probe"]
        greeting = results["websocket"]["greeting"]
    except (KeyError, TypeError) as error:
        raise ValueError("driver WS result missing") from error
    grouped = defaultdict(list)
    for block in frames:
        grouped[(block.protocol, block.connection, block.stream)].append(block)
    websocket = []
    for key, blocks in grouped.items():
        requests = [
            b
            for b in blocks
            if b.headers
            and not b.from_server
            and flow_name(b.headers, protocol=b.protocol) == "ws"
        ]
        incoming = [
            text for b in blocks if not b.from_server for text in b.websocket_text
        ]
        outgoing = [text for b in blocks if b.from_server for text in b.websocket_text]
        if probe in incoming or probe in outgoing:
            if (
                len(requests) != 1
                or key[0] != protocols["ws"]
                or incoming != [probe]
                or len(outgoing) != 2
                or outgoing[1] != probe
                or json_object(outgoing[0]) != greeting
            ):
                raise ValueError("driver WS probe/greeting differs on wire")
            websocket.append(key)
    if len(websocket) != 1:
        raise ValueError("driver WS probe has no unique packet stream")
    selected["ws"] = websocket[0]
    keys.add(websocket[0])
    discovery = Counter()
    for block in heads:
        key = (block.protocol, block.connection, block.stream)
        if key in keys:
            continue
        if (block.protocol, block.connection) not in {
            (protocol, connection) for protocol, connection, _stream in keys
        }:
            raise ValueError("unattributed additional source connection")
        fields = dict(block.headers)
        path = fields.get(":path")
        if fields.get(":method") != "GET" or path not in {
            "/assets/style.css",
            "/assets/script.js",
            "/favicon.ico",
            "/report?h3_probe=1",
            "/",
        }:
            raise ValueError("unexpected additional source operation")
        discovery[path] += 1
    if sum(discovery.values()) > MAX_DISCOVERY_REQUESTS:
        raise ValueError("source discovery request limit")
    # Archive/native verifiers subsequently require every retained joint to match.
    return dict(
        flows={flow: list(key) for flow, key in selected.items() if flow in FLOWS},
        declared_operations={name: list(key) for name, key in selected.items()},
        discovery=dict(discovery),
        scope="driver-native peer/method/path/protocol and same HTTP stream; exact driver-known WS probe",
        limits="raw native CIDs are redacted; independent QUIC wire continuity is checked separately",
    )
