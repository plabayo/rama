"""Native H1 PDML with raw spelling, complete framing and real peer coordinates."""

import json
import xml.etree.ElementTree as ET

from flows import FLOWS, FETCH_CONTEXT_FIELDS, flow_name
from remote.tests.fixtures import html_info
from test_flow_bodies import fixture
from test_mixed_journey import h1_document

ORIGIN = "https://h1.capture.test:65320"
JOINT = "67" * 32
PROBE = "rama-fp echo: " + "🐢" * 32


def field(parent, name, value, *, raw=False):
    data = dict(name=name)
    if raw:
        data.update(value=value.hex(), size=str(len(value)))
    else:
        data["show"] = str(value)
    return ET.SubElement(parent, "field", **data)


def journey():
    document = h1_document()
    # Existing independent WS frame fixture uses TCP connection4 and this peer.
    for node in document.iter("field"):
        if node.get("name") in ("http.request.line", "http.response.line"):
            raw = bytes.fromhex(node.get("value"))
            raw = raw.replace(b"localhost:65320", b"h1.capture.test:65320")
            node.set("value", raw.hex())
            node.set("size", str(len(raw)))
        elif node.get("name") == "http.host":
            node.set("show", "h1.capture.test:65320")
    for packet in document:
        field(packet, "ip.src", "198.51.100.7")
    page = dict(
        user_agent="fixture",
        protocols=dict.fromkeys(FLOWS, "h1"),
        report_url=ORIGIN + "/report",
        page_results={},
    )
    for index, source in enumerate(fixture("h2")[::2]):
        if index == 3:
            continue
        method, uri = dict(source.headers)[":method"], dict(source.headers)[":path"]
        flow = FLOWS[index]
        number, stream = 10 + index * 2, 10 + index * 2
        info = dict(
            version="HTTP/1.1",
            method=method,
            scheme="https",
            authority="h1.capture.test:65320",
            path=uri.split("?")[0],
            peer_addr="198.51.100.7:65345",
        )
        if flow in ("fetch", "xhr"):
            info["uri"] = ORIGIN + uri
            value = dict(fp=dict(request_info=info), number=7 if flow == "fetch" else 8)
            body = json.dumps(value).encode()
            page["page_results"][flow] = value
        else:
            value = html_info(info)
            body = value.encode()
            page[
                {
                    "navigate": "report_html",
                    "form": "form_html",
                    "form_get": "get_form_html",
                }[flow]
            ] = value
        for response in (False, True):
            packet = ET.SubElement(document, "packet")
            for name, value in (
                ("frame.number", number + 1 if response else number),
                ("tcp.stream", 1),
                ("tcp.srcport", 65320 if response else 65345),
                ("tcp.dstport", 65345 if response else 65320),
                ("ip.src", "198.51.100.7"),
            ):
                field(packet, name, value)
            http = ET.SubElement(packet, "proto", name="http")
            if response:
                field(http, "http.response.code", "200")
                field(http, "http.request_in", str(stream))
                headers = [
                    "Content-Length: " + str(len(body)),
                    "Content-Type: "
                    + ("application/json" if flow in ("fetch", "xhr") else "text/html"),
                ]
                payload = body
            else:
                field(http, "http.request.method", method)
                field(http, "http.request.uri", uri)
                field(http, "http.request.version", "HTTP/1.1")
                field(http, "http.host", "h1.capture.test:65320")
                headers = [
                    "hOsT: h1.capture.test:65320",
                    "User-Agent: fixture",
                    "x-eXoTiC: first",
                    "x-eXoTiC: second",
                ]
                payload = source.data
                if payload:
                    headers.append("Content-Length: " + str(len(payload)))
            for line in headers:
                field(
                    http,
                    "http.response.line" if response else "http.request.line",
                    (line + "\r\n").encode(),
                    raw=True,
                )
            if payload:
                field(http, "http.file_data", payload, raw=True)
    page["page_results"]["websocket"] = dict(
        probe=PROBE,
        greeting={
            "h3": "unsupported_or_not_negotiated",
            "initiator": "ws",
            "version": "HTTP/1.1",
        },
    )
    return document, page


def inspected(blocks):
    scopes = [
        dict(
            context={"connection": {"resumption": "Unknown"}},
            variants=[
                dict(
                    id=list(bytes.fromhex(JOINT)),
                    capture=dict(
                        level="Connection",
                        slots=[dict(kind="TcpTls", capture={"extensions": []})],
                    ),
                )
            ],
        )
    ]
    for index, block in enumerate(
        block for block in blocks if block.headers and not block.from_server
    ):
        fields = dict((name.lower(), value) for name, value in block.headers)
        flow = flow_name(block.headers, protocol="h1")
        regular = []
        counts = {}
        for name, value in block.headers:
            if name.startswith(":"):
                continue
            ordinal = counts.get(name.lower(), 0)
            counts[name.lower()] = ordinal + 1
            regular.append(
                dict(
                    name=name,
                    occurrence=ordinal,
                    value={"Profile": list(value.encode("latin-1"))},
                )
            )
        scopes.append(
            dict(
                context={"connection": {"resumption": "Unknown"}},
                flow={
                    "Http": dict(
                        version="HTTP/1.1",
                        method=fields[":method"],
                        initiator="form" if flow == "form_get" else flow,
                        fetch={
                            key: fields[header]
                            for key, header in FETCH_CONTEXT_FIELDS
                            if header in fields
                        },
                    )
                },
                variants=[
                    dict(
                        id=[80 + index] * 32,
                        capture=dict(
                            level="Request",
                            slots=[
                                dict(
                                    kind="Headers",
                                    capture=dict(version="HTTP/1.1", fields=regular),
                                )
                            ],
                        ),
                    )
                ],
            )
        )
    return dict(
        format_version=1, profiles=[dict(key={"user_agent": "fixture"}, scopes=scopes)]
    )
