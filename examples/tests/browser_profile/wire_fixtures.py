"""Shared packet builders and six-flow fixtures for the independent wire oracles."""


import base64
import h3_sequence_wire as sequence
import hashlib
import json
import native_h3_response as native
import quic_stream_wire as streams
import xml.etree.ElementTree as ET
from connection_fields import h2_prefixes
from copy import deepcopy
from dataclasses import asdict, replace
from flow_bodies import WEBSOCKET_PROBE
from flows import FLOWS
from h3_sequence_wire import SequenceEvidence, stream_prefixes
from pathlib import Path
from qpack_fields_wire import Representation
from qpack_wire import encoder_instruction_evidence
from quic_stream_wire import StreamPrefix
from quic_wire import client_settings, compare_quic_captures, first_flights
from tls_wire import TlsHello
from types import SimpleNamespace
from wire import GUID, HeaderBlock

def flow_fixture(protocol):
    rows = []
    for stream, (method, path, body) in enumerate(
        [
            ("GET", "/report", b""),
            (
                "POST",
                "/api/fetch/number/7",
                b'{"number":7,"jsWebApis":{"navigator":{"userAgent":"fixture"}}}',
            ),
            ("POST", "/api/xml/number/8", b'{"number":8}'),
            ("CONNECT", "/api/ws", b""),
            ("POST", "/form", b"source=web&rating=3"),
            ("GET", "/form?source=web&turtles=yes", b""),
        ]
    ):
        headers = ((":method", method), (":path", path), ("user-agent", "fixture"))
        greeting = ()
        if method == "CONNECT":
            headers += ((":protocol", "websocket"),)
            greeting = (
                json.dumps(
                    {
                        "initiator": "ws",
                        "version": {"h2": "HTTP/2.0", "h3": "HTTP/3.0"}[protocol],
                    }
                ),
                WEBSOCKET_PROBE,
            )
        rows += [
            HeaderBlock(
                protocol,
                stream + 1,
                0,
                stream,
                False,
                headers,
                body,
                websocket_text=(WEBSOCKET_PROBE,) if method == "CONNECT" else (),
            ),
            HeaderBlock(
                protocol,
                stream + 1,
                0,
                stream,
                True,
                ((":status", "200"),),
                websocket_text=greeting,
            ),
        ]
    return rows


def scalar(name, raw, *, show=None, position=0):
    show = int.from_bytes(raw, "big") if show is None else show
    return f'<field name="{name}" pos="{position}" size="{len(raw)}" value="{raw.hex()}" show="{show}"/>'


def computed(name, value):
    return f'<field name="{name}" show="{value}" size="0" pos="0"/>'


def parameter_extension():
    # Reusable integer value plus a connection-owned CID. The latter must only
    # be compared by its retained length, never copied into a profile/report.
    body = b"\x04\x02\x40\x64\x0f\x0a" + b"private-id"
    body += b"\x11\x0c" + bytes.fromhex("00000001000000011a1a1a1a")
    raw = b"\x00\x39" + len(body).to_bytes(2, "big") + body
    return (
        f'<field name="tls.handshake.extension" pos="100" size="{len(raw)}" value="{raw.hex()}">'
        + scalar("tls.handshake.extension.type", b"\x00\x39", position=100)
        + "</field>"
    )


def datagram(number, *, complete=False, number_width=1):
    # Two authenticated Initial payloads. Only packet 2 contains the dissector's
    # reassembled ClientHello node; packet 1 still belongs to the first flight.
    crypto = (
        '<field name="quic.frame" size="35">'
        + scalar("quic.frame_type", b"\x06")
        + scalar("quic.crypto.offset", bytes([(number - 1) * 32]))
        + scalar("quic.crypto.length", b"\x20")
        + "</field>"
    )
    padding = (
        f'<field name="quic.frame" size="{1181 - number_width}">'
        + scalar("quic.frame_type", b"\x00")
        + computed("quic.padding_length", 1181 - number_width)
        + "</field>"
    )
    hello = (
        '<field name="tls.handshake">'
        + computed("tls.handshake.type", 1)
        + parameter_extension()
        + "</field>"
        if complete
        else ""
    )
    return (
        "<packet>"
        + computed("frame.number", number)
        + scalar("udp.srcport", (10000).to_bytes(2, "big"))
        + scalar("udp.dstport", (443).to_bytes(2, "big"))
        + scalar("udp.length", (1258).to_bytes(2, "big"))
        + '<proto name="quic" pos="32" size="1250">'
        + computed("quic.connection.number", 7)
        + computed("quic.packet_length", 1250)
        + computed("quic.long.packet_type", 0)
        + scalar("quic.version", b"\x00\x00\x00\x01")
        + scalar("quic.dcil", b"\x08")
        + scalar("quic.scil", b"\x00")
        + scalar("quic.token_length", b"\x00")
        + scalar("quic.length", b"\x44\xd0", show=1232, position=48)
        # Raw PN bytes are protected; the displayed PN and extent are decoded.
        + scalar("quic.packet_number", b"\xab" * number_width, show=number)
        + crypto
        + padding
        + hello
        + "</proto></packet>"
    )


def initial_document(*, complete=True):
    return (
        "<pdml>" + datagram(1) + datagram(2, complete=complete) + "</pdml>"
    ).encode()


def padded_document():
    """Two valid Initials followed by Firefox-style diagnostic padding spans."""
    root = ET.fromstring(initial_document())
    for packet, length in zip(root.findall("packet"), (994, 991)):
        udp = packet.find("field[@name='udp.length']")
        udp.set("value", (1260).to_bytes(2, "big").hex())
        udp.set("show", "1260")
        proto = packet.find("proto")
        proto.set("size", str(length))
        proto.find("field[@name='quic.packet_length']").set("show", str(length))
        encoded = proto.find("field[@name='quic.length']")
        encoded.set("value", (0x4000 | (length - 18)).to_bytes(2, "big").hex())
        encoded.set("show", str(length - 18))
        padding = proto.findall("field[@name='quic.frame']")[1]
        padding.set("size", str(length - 70))
        padding.find("field[@name='quic.padding_length']").set("show", str(length - 70))
        tail = ET.SubElement(
            packet, "proto", name="quic", pos=str(32 + length), size=str(1252 - length)
        )
        expert = ET.SubElement(tail, "field", name="_ws.expert")
        ET.SubElement(expert, "field", name="quic.coalesced_padding_data", show="")
        ET.SubElement(
            expert,
            "field",
            name="_ws.expert.message",
            show="(Random) padding data appended to the datagram",
        )
    return root


def settings_document():
    payload = bytes.fromhex("0140642107")
    native = b"\x00\x04\x05" + payload
    return (
        "<pdml><packet>"
        + computed("quic.connection.number", 7)
        + scalar("udp.srcport", (10000).to_bytes(2, "big"))
        + scalar("udp.dstport", (443).to_bytes(2, "big"))
        + '<field name="quic.frame" size="11">'
        + scalar("quic.frame_type", b"\x0a")
        + scalar("quic.stream.stream_id", b"\x02")
        + scalar("quic.stream.length", bytes([len(native)]))
        + scalar("quic.stream_data", native)
        + '</field><field name="http3.frame" size="7">'
        + computed("http3.frame_streamid", 2)
        + scalar("http3.frame_type", b"\x04")
        + scalar("http3.frame_length", b"\x05")
        + scalar("http3.frame_payload", payload)
        + "</field></packet></pdml>"
    ).encode()


def comparison_fixture():
    observed = first_flights(initial_document(), 443)[0]
    tls = {"transport": "Quic", "ciphers": [4865]}
    retained_parameters = dict(
        completeness="Complete",
        namespace="QuicParameter",
        fields=[
            {"id": 4, "value": {"Literal": [64, 100]}},
            {"id": 15, "value": {"ConnectionLength": 10}},
            {
                "id": 17,
                "value": {"Literal": list(bytes.fromhex("00000001000000011a1a1a1a"))},
            },
        ],
    )
    slots = [
        {"kind": "QuicTls", "capture": tls},
        {"kind": "QuicParameters", "capture": retained_parameters},
        {
            "kind": "QuicFirstFlight",
            "capture": {
                "completeness": "Complete",
                "flight": deepcopy(observed.flight),
            },
        },
        {
            "kind": "Http3Settings",
            "capture": client_settings(settings_document(), 443)[7],
        },
        {
            "kind": "Http3Sequence",
            "capture": {
                "completeness": "Complete",
                "local_settings": {},
                "events": [
                    {"Stream": {"stream_id": 2, "stream_type": 0}},
                    {
                        "Control": {
                            "frame_type": 4,
                            "length": 0,
                            "element_id": None,
                            "value": [],
                        }
                    },
                ],
                "encoder_instructions": [],
            },
        },
    ]
    archive = dict(
        format_version=1,
        profiles=[
            dict(
                key={"user_agent": "fixture"},
                scopes=[
                    dict(
                        variants=[
                            dict(
                                id=[1] * 32,
                                capture=dict(level="Connection", slots=slots),
                            )
                        ]
                    )
                ],
            )
        ],
    )
    hello = TlsHello(2, 7, tls)
    request = SimpleNamespace(
        protocol="h3",
        connection=7,
        from_server=False,
        headers=(("user-agent", "fixture"),),
    )
    return archive, observed, hello, request


def sequence_fixture():
    return {
        7: SequenceEvidence(
            (StreamPrefix(2, 0, b""),),
            ({"frame_type": 4, "length": 0, "element_id": None, "value": []},),
            {},
        )
    }


def number(value):
    width = next(size for size in (1, 2, 4, 8) if value < 1 << (8 * size - 2))
    return (value | ({1: 0, 2: 1, 4: 2, 8: 3}[width] << (8 * width - 2))).to_bytes(
        width, "big"
    )


def frame(kind, payload):
    return number(kind) + number(len(payload)) + payload


def stream_packet(stream_id, payload, *, offset=0, server=False, connection=7, fin=False):
    fields = scalar("quic.frame_type", bytes([15 if fin else 14]))
    fields += scalar("quic.stream.stream_id", number(stream_id), show=stream_id)
    fields += scalar("quic.stream.offset", number(offset), show=offset)
    fields += scalar("quic.stream.length", number(len(payload)), show=len(payload))
    fields += scalar("quic.stream_data", payload, show="payload")
    size = (
        1
        + len(number(stream_id))
        + len(number(offset))
        + len(number(len(payload)))
        + len(payload)
    )
    return (
        "<packet>"
        + computed("quic.connection.number", connection)
        + scalar("udp.srcport", (443 if server else 10000).to_bytes(2, "big"))
        + scalar("udp.dstport", (10000 if server else 443).to_bytes(2, "big"))
        + f'<field name="quic.frame" size="{size}">'
        + fields
        + "</field></packet>"
    )


def document(*packets):
    return ("<pdml>" + "".join(packets) + "</pdml>").encode()


def evidence():
    settings = dict(completeness="Complete", namespace="Http3Setting", fields=[])
    payload = frame(4, b"") + frame(0xF0700, b"\x00u=1, i") + frame(33, b"ignored")
    stream = sequence.StreamPrefix(2, 0, payload)
    return sequence.SequenceEvidence(
        (stream, sequence.StreamPrefix(6, 2, b"")),
        tuple(sequence.control_frames(stream)),
        settings,
    )


def capture():
    observed = evidence()
    return dict(
        completeness="Complete",
        local_settings=observed.local_settings,
        events=[{"Stream": {"stream_id": 2, "stream_type": 0}}]
        + [{"Control": item} for item in observed.controls],
        encoder_instructions=[],
    )


def connection_fields_scalar(name, value, size):
    return f'<field name="{name}" show="{value}" size="{size}" value="{value:0{size * 2}x}"/>'


def connection_fields_document(*, magic=True, setting=4096):
    fields = (
        connection_fields_scalar("tcp.srcport", 12345, 2)
        + connection_fields_scalar("tcp.dstport", 443, 2)
        + connection_fields_scalar("tcp.stream", 7, 4)
    )
    prefix = (
        '<field name="http2.stream"><field name="http2.magic" show="preface"/></field>'
        if magic
        else ""
    )
    settings = (
        '<field name="http2.stream">'
        + connection_fields_scalar("http2.type", 4, 1)
        + connection_fields_scalar("http2.length", 6, 3)
        + connection_fields_scalar("http2.flags", 0, 1)
        + connection_fields_scalar("http2.streamid", 0, 4)
        + '<field name="http2.settings">'
        + connection_fields_scalar("http2.settings.id", 1, 2)
        + connection_fields_scalar("http2.settings.header_table_size", setting, 4)
        + "</field></field>"
    )
    boundary = (
        '<field name="http2.stream">'
        + connection_fields_scalar("http2.type", 1, 1)
        + connection_fields_scalar("http2.streamid", 3, 4)
        + connection_fields_scalar("http2.flags", 4, 1)
        + "</field>"
    )
    return (
        "<pdml><packet>"
        + fields
        + prefix
        + settings
        + boundary
        + settings
        + "</packet></pdml>"
    ).encode()


def connection_fields_fixture():
    prefix = h2_prefixes(connection_fields_document(), 443)[7]
    tls = {"transport": "Tcp", "ciphers": [4865]}
    joint = {
        "level": "Connection",
        "slots": [
            {"kind": "TcpTls", "capture": tls},
            {"kind": "Http2EarlyFrames", "capture": prefix},
        ],
    }
    archive = {
        "format_version": 1,
        "profiles": [
            {
                "key": {"user_agent": "fixture"},
                "scopes": [{"variants": [{"id": [1] * 32, "capture": joint}]}],
            }
        ],
    }
    hello = SimpleNamespace(connection=7, capture=tls)
    request = SimpleNamespace(
        protocol="h2", connection=7, from_server=False, headers=(("user-agent", "fixture"),)
    )
    return archive, hello, request, prefix


def connection_fields_post_header_document(
    *, stream=3, increment=100, fragmented=False, ack=False, interposed=None
):
    data = connection_fields_document().decode()
    # Remove the deliberately ignored post-HEADERS SETTINGS in the old fixture.
    last_setting = data.rfind('<field name="http2.stream">')
    data = data[:last_setting] + "</packet></pdml>"
    continuation = ""
    if fragmented:
        data = data.replace(connection_fields_scalar("http2.flags", 4, 1), connection_fields_scalar("http2.flags", 0, 1))
        continuation = (
            '<field name="http2.stream">'
            + connection_fields_scalar("http2.type", 9, 1)
            + connection_fields_scalar("http2.streamid", 3, 4)
            + connection_fields_scalar("http2.flags", 4, 1)
            + "</field>"
        )
    acknowledgement = ""
    if ack:
        acknowledgement = (
            '<field name="http2.stream">'
            + connection_fields_scalar("http2.type", 4, 1)
            + connection_fields_scalar("http2.streamid", 0, 4)
            + connection_fields_scalar("http2.flags", 1, 1)
            + connection_fields_scalar("http2.length", 0, 3)
            + "</field>"
        )
    update = (
        '<field name="http2.stream">'
        + connection_fields_scalar("http2.type", 8, 1)
        + connection_fields_scalar("http2.streamid", stream, 4)
        + connection_fields_scalar("http2.length", 4, 3)
        + connection_fields_scalar("http2.window_update.window_size_increment", increment, 4)
        + "</field>"
    )
    interposed_frame = (
        ""
        if interposed is None
        else (
            '<field name="http2.stream">'
            + connection_fields_scalar("http2.type", interposed, 1)
            + connection_fields_scalar("http2.streamid", 0, 4)
            + "</field>"
        )
    )
    return data.replace(
        "</packet>",
        continuation + acknowledgement + interposed_frame + update + "</packet>",
    ).encode()


def wire_streams_packet(protocol, streams):
    h2 = protocol == "h2"
    transport = "tcp" if h2 else "udp"
    content = computed("frame.number", "7") + computed(transport + ".srcport", "50000")
    content += computed(transport + ".dstport", "443")
    content += computed("tcp.stream" if h2 else "quic.connection.number", "2")
    for stream, pairs in streams:
        content += '<field name="' + ("http2.stream" if h2 else "http3.frame") + '">'
        content += computed(
            "http2.streamid" if h2 else "http3.frame_streamid", str(stream)
        )
        for name, value in pairs:
            content += (
                '<field name="'
                + ("http2.header" if h2 else "http3.headers.header")
                + '">'
            )
            content += computed(
                "http2.header.name" if h2 else "http3.header.header.name", name
            )
            content += computed(
                "http2.header.value" if h2 else "http3.headers.header.value", value
            )
            content += "</field>"
        content += "</field>"
    return ("<pdml><packet>" + content + "</packet></pdml>").encode()


def tls_wire_vector(data, width=2):
    return len(data).to_bytes(width, "big") + data


def tls_wire_span(data):
    return ET.fromstring(
        f'<field pos="10" size="{len(data)}">'
        f'<field pos="10" size="{len(data)}" value="{data.hex()}"/>'
        "</field>"
    )


def tls_wire_comparison_fixture():
    capture = dict(
        completeness="Complete",
        transport="Tcp",
        protocol_version=771,
        ciphers=[4865],
        compression=[0],
        extensions=[],
    )
    hello = TlsHello(1, 7, capture)
    request = SimpleNamespace(
        protocol="h2", connection=7, from_server=False, headers=(("user-agent", "fixture"),)
    )
    archive = dict(
        format_version=1,
        profiles=[
            dict(
                key={"user_agent": "fixture"},
                scopes=[
                    dict(
                        variants=[
                            dict(
                                capture=dict(
                                    slots=[dict(kind="TcpTls", capture=capture)]
                                )
                            )
                        ]
                    )
                ],
            )
        ],
    )
    return archive, hello, request


def mixed_connections_mixed_fixture():
    archive, tcp_hello, tcp_request, prefix = connection_fields_fixture()
    quic_archive, flight, quic_hello, quic_request = comparison_fixture()
    quic_archive["profiles"][0]["key"]["user_agent"] = "quic-browser"
    quic_request.headers = (("user-agent", "quic-browser"),)
    archive["profiles"].extend(quic_archive["profiles"])
    return archive, [tcp_hello, quic_hello], [tcp_request, quic_request], prefix, flight


def mixed_connections_hello_packet(transport, cipher, packet):
    """Construct complete dissection spans with independently numbered transports."""
    body = (
        b"\x03\x03" + bytes(32) + b"\x00\x00\x02"
        + cipher.to_bytes(2, "big") + b"\x01\x00\x00\x00"
    )
    raw = b"\x01" + len(body).to_bytes(3, "big") + body
    identity = "tcp.stream" if transport == "Tcp" else "quic.connection.number"
    return (
        f'<packet><field name="frame.number" show="{packet}"/>'
        f'<field name="{identity}" show="7"/>'
        f'<field name="tls.handshake" pos="0" size="{len(raw)}" value="{raw.hex()}">'
        '<field name="tls.handshake.type" show="1" pos="0" size="1" value="01"/>'
        '</field></packet>'
    )


MIXED_JOURNEY_HERE = Path(__file__).parent


def mixed_journey_mixed_frames(websocket_protocol):
    """A real six-flow body fixture, with only WS using the browser's fallback."""
    frames = [frame for frame in flow_fixture("h3") if frame.stream != 3]
    for frame in flow_fixture("h2"):
        if frame.stream != 3:
            continue
        headers = frame.headers
        if not frame.from_server:
            headers += (("sec-websocket-protocol", "a,b"),)
        frames.append(replace(frame, protocol=websocket_protocol, headers=headers))
    return frames


def mixed_journey_h1_document():
    """Credential-free Upgrade plus retained independently decoded text frames."""
    root = ET.Element("pdml")
    key = base64.b64encode(b"0123456789abcdef").decode()
    accept = base64.b64encode(hashlib.sha1((key + GUID).encode()).digest()).decode()
    for number, response in ((56, False), (58, True)):
        wire_streams_packet = ET.SubElement(root, "packet")
        for name, value in (
            ("frame.number", number),
            ("tcp.stream", 4),
            ("tcp.srcport", 65320 if response else 65345),
            ("tcp.dstport", 65345 if response else 65320),
        ):
            ET.SubElement(wire_streams_packet, "field", name=name, show=str(value))
        http = ET.SubElement(wire_streams_packet, "proto", name="http")
        fields = (
            {"http.request_in": "56", "http.response.code": "101"}
            if response
            else {
                "http.request.method": "GET",
                "http.request.uri": "/api/ws",
                "http.request.version": "HTTP/1.1",
                "http.host": "localhost:65320",
            }
        )
        for name, value in fields.items():
            ET.SubElement(http, "field", name=name, show=value)
        lines = (
            ["Sec-WebSocket-Accept: " + accept]
            if response
            else [
                "Host: localhost:65320",
                "User-Agent: fixture",
                "Connection: Upgrade",
                "Upgrade: websocket",
                "Origin: https://localhost:65320",
                "Sec-WebSocket-Key: " + key,
                "Sec-WebSocket-Protocol: a, b",
            ]
        )
        for line in lines:
            raw = (line + "\r\n").encode()
            ET.SubElement(
                http,
                "field",
                name="http.response.line" if response else "http.request.line",
                value=raw.hex(),
                size=str(len(raw)),
            )
    root.extend(ET.fromstring((MIXED_JOURNEY_HERE / "tests/fixtures/websocket.pdml").read_bytes()))
    return root


QPACK_FIELDS_WIRE_PAYLOAD = b"\x00\x00\xd1\x51\x07/report\x27\x03user-agent\x07fixture"


QPACK_FIELDS_WIRE_HEADERS = ((":method", "GET"), (":path", "/report"), ("user-agent", "fixture"))


QPACK_FIELDS_WIRE_METADATA = (
    Representation("StaticIndex", 17),
    Representation("LiteralStaticName", 1),
    Representation("LiteralName"),
)


def qpack_fields_wire_field(parent, name, show, raw=None):
    attributes = {"name": name, "show": str(show), "size": "0", "pos": "0"}
    if raw is not None:
        attributes.update(value=raw.hex(), size=str(len(raw)))
    return ET.SubElement(parent, "field", attributes)


def qpack_fields_wire_document():
    root = ET.Element("pdml")
    packet = ET.SubElement(root, "packet")
    for name, value in [
        ("frame.number", 1),
        ("udp.srcport", 50000),
        ("udp.dstport", 443),
        ("quic.connection.number", 0),
    ]:
        qpack_fields_wire_field(packet, name, value)
    frame = ET.SubElement(packet, "field", name="http3.frame", size=str(2 + len(QPACK_FIELDS_WIRE_PAYLOAD)))
    qpack_fields_wire_field(frame, "http3.frame_type", 1, b"\x01")
    qpack_fields_wire_field(frame, "http3.frame_length", len(QPACK_FIELDS_WIRE_PAYLOAD), bytes([len(QPACK_FIELDS_WIRE_PAYLOAD)]))
    qpack_fields_wire_field(frame, "http3.frame_streamid", 0)
    qpack_fields_wire_field(frame, "http3.frame_payload", "", QPACK_FIELDS_WIRE_PAYLOAD)
    qpack_fields_wire_field(frame, "http3.headers.count", len(QPACK_FIELDS_WIRE_HEADERS))
    return root


def qpack_fields_wire_inspected():
    regular = {
        "name": "user-agent",
        "occurrence": 0,
        "value": {"Profile": list(b"fixture")},
        "representation": asdict(QPACK_FIELDS_WIRE_METADATA[2]),
    }
    pseudo = [
        {"name": name, "representation": asdict(metadata)}
        for (name, _), metadata in zip(QPACK_FIELDS_WIRE_HEADERS[:2], QPACK_FIELDS_WIRE_METADATA[:2])
    ]
    capture = {"slots": [
        {"kind": "Headers", "capture": {"fields": [regular]}},
        {"kind": "PseudoHeaders", "capture": {"fields": pseudo}},
    ]}
    scope = {
        "flow": {"Http": {
            "version": "HTTP/3.0",
            "method": "GET",
            "initiator": "navigate",
            "fetch": None,
        }},
        "variants": [{"capture": capture}],
    }
    profile = {"key": {"user_agent": "fixture"}, "scopes": [scope]}
    return {"format_version": 1, "profiles": [profile]}


def qpack_fields_wire_fixture_variants(archive):
    profile = archive["profiles"][0]
    scope = profile["scopes"][0]
    return scope["variants"]


def qpack_fields_wire_field_slots(capture):
    return {
        slot["kind"]: slot["capture"]["fields"]
        for slot in capture["slots"]
    }


QPACK_WIRE_CAPACITY = "http3.qpack.encoder.opcode.dtable_cap"


QPACK_WIRE_REFERENCE = "http3.qpack.encoder.opcode.insert_indexed"


QPACK_WIRE_LITERAL = "http3.qpack.encoder.opcode.insert"


QPACK_WIRE_DUPLICATE = "http3.qpack.encoder.opcode.duplicate"


def qpack_wire_instruction(kind, raw, *, name=None):
    children = (
        "" if name is None else scalar(QPACK_WIRE_LITERAL + ".name", name, show="decoded name")
    )
    return (
        f'<field name="{kind}" size="{len(raw)}" value="{raw.hex()}">'
        + children
        + "</field>"
    )


def qpack_wire_fixture(*nodes, raw=b"\x20", server=False):
    packet = stream_packet(7 if server else 6, b"\x02" + raw, server=server)
    packet = packet.replace("</packet>", "".join(nodes) + "</packet>")
    data = document(packet)
    return data, stream_prefixes(data, 443)


def qpack_bootstrap_wire_bootstrap_fixture():
    archive, flight, hello, _request = comparison_fixture()
    profile = archive["profiles"][0]
    connection_scope = profile["scopes"][0]
    slots = connection_scope["variants"][0]["capture"]["slots"]
    sequence = slots[-1]["capture"]
    sequence["events"].append({"Stream": {"stream_id": 6, "stream_type": 2}})

    # Capacity4096; static :authority name with a current connection-owned value;
    # then Huffman literal a:b. The independent decoder must resolve both forms.
    secret = b"private-current-origin"
    raw = (
        b"\x3f\xe1\x1f",
        b"\xc0" + bytes([len(secret)]) + secret,
        b"\x61\x1f\x81\x8f",
    )
    data, streams = qpack_wire_fixture(
        qpack_wire_instruction(QPACK_WIRE_CAPACITY, raw[0]),
        qpack_wire_instruction(QPACK_WIRE_REFERENCE, raw[1]),
        qpack_wire_instruction(QPACK_WIRE_LITERAL, raw[2], name=b"a"),
        raw=b"".join(raw),
    )
    metadata, encoded = encoder_instruction_evidence(data, 443, streams)[7]
    sequence["encoder_instructions"] = list(metadata)
    observed = sequence_fixture()[7]
    observed = replace(
        observed,
        streams=(*observed.streams, StreamPrefix(6, 2, b"".join(raw))),
        encoder_instructions=metadata,
        encoder_bytes=encoded,
    )
    headers = (
        (":method", "GET"),
        (":path", "/report"),
        (":authority", secret.decode()),
        ("user-agent", "fixture"),
        ("a", "b"),
    )
    request = SimpleNamespace(
        protocol="h3",
        connection=7,
        stream=0,
        packet=10,
        from_server=False,
        headers=headers,
    )
    request_scope = qpack_fields_wire_inspected()["profiles"][0]["scopes"][0]
    request_scope["variants"][0]["id"] = [2] * 32
    capture = request_scope["variants"][0]["capture"]
    capture["level"] = "Request"
    capture["slots"][0]["capture"]["fields"].append(
        {
            "name": "a",
            "occurrence": 0,
            "value": {"Profile": list(b"b")},
        }
    )
    capture["slots"][1]["capture"]["fields"].append({"name": ":authority"})
    profile["scopes"].append(request_scope)
    binding = {
        "request": [2] * 32,
        "method": "GET",
        "fields": len(headers),
        "bindings": {
            "stream_id": 0,
            "complete": True,
            "insertions": [
                {
                    "instruction_index": 1,
                    "insertion_index": 0,
                    "field": {"Unique": {"field_index": 2}},
                },
                {
                    "instruction_index": 2,
                    "insertion_index": 1,
                    "field": {"Unique": {"field_index": 4}},
                },
            ],
        },
    }
    slots.append({"kind": "Http3Bootstrap", "capture": binding})
    return archive, flight, hello, request, observed, binding


def qpack_bootstrap_wire_compare_fixture(archive, flight, hello, request, observed, _binding, *, replay=False):
    return compare_quic_captures(
        archive,
        [flight],
        [hello],
        client_settings(settings_document(), 443),
        [request],
        {7: observed},
        replay=replay,
    )


def quic_settings_stream_decoded(payload=b"\x01\x10", *, stream=2):
    return (
        f'<field name="http3.frame" size="{len(frame(4, payload))}">'
        + computed("http3.frame_streamid", stream)
        + scalar("http3.frame_type", b"\x04")
        + scalar("http3.frame_length", number(len(payload)))
        + scalar("http3.frame_payload", payload)
        + "</field>"
    )


def quic_settings_stream_control(payload=None, *, stream=2, server=False, offset=0, witness=True):
    data = b"\x00" + frame(4, b"\x01\x10") if payload is None else payload
    packet = stream_packet(stream, data, server=server, offset=offset)
    if witness:
        packet = packet.replace("</packet>", quic_settings_stream_decoded(stream=stream) + "</packet>")
    return packet


def native_h3_response_view():
    return dict(
        request_stream_id=4,
        connection_revision=8,
        settings_status="received",
        completeness={
            name: True
            for name in (
                "snapshot",
                "streams",
                "control",
                "qpack",
                "settings",
                "local_settings",
                "fields",
            )
        },
        local_settings=[dict(id=1, value=4096, grease=False)],
        streams=[dict(sequence=2, stream_id=2, stream_type=0, grease=False)],
        control=[dict(sequence=3, frame_type=4, length=0, element_id=None, value=[])],
        qpack=[],
    )


def native_h3_response_encoded_view(value=None):
    return json.dumps(
        {"fp": {"http_info": {"h3": native_h3_response_view() if value is None else value}}}
    ).encode()


def native_h3_response_packet(payload, *, offset=0, fin=True, connection=7, stream=4):
    return stream_packet(stream, payload, offset=offset, fin=fin,
                         connection=connection, server=True)


def native_h3_response_blocks(payload, *, connection=7, stream=4, response_headers=()):
    return [
        HeaderBlock(
            "h3",
            1,
            connection,
            stream,
            False,
            ((":method", "GET"), (":path", "/report")),
        ),
        HeaderBlock(
            "h3",
            2,
            connection,
            stream,
            True,
            ((":status", "200"), ("content-type", "application/json"))
            + response_headers,
            data=payload,
        ),
    ]


def native_h3_response_numbered(raw, number):
    return raw.replace(
        "<packet>", f'<packet><field name="frame.number" show="{number}"/>', 1
    )


def wire_flows_fixture():
    requests, responses = [], []
    key = base64.b64encode(b"0123456789abcdef").decode()
    for index, (flow, uri) in enumerate(
        zip(
            FLOWS,
            (
                "/report",
                "/api/fetch/number/1",
                "/api/xml/number/2",
                "/api/ws",
                "/form",
                "/form?source=web&turtles=yes",
            ),
        ),
        1,
    ):
        body = b"hello" if flow in ("fetch", "xhr", "form") else b""
        headers = ["Host: 127.0.0.1:1234", "Connection: keep-alive"]
        if body:
            headers += [
                "Content-Type: text/plain;charset=UTF-8",
                "Content-Length: 5",
                "Origin: http://127.0.0.1:1234",
            ]
        if flow == "ws":
            headers += [
                "Sec-WebSocket-Key: " + key,
                "Sec-WebSocket-Protocol: a, b",
                "Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits",
            ]
        requests.append(
            {
                "frame.number": str(index),
                "http.request.method": "POST" if body else "GET",
                "http.request.uri": uri,
                "http.request.version": "HTTP/1.1",
                "http.host": "127.0.0.1:1234",
                "http.request.line": "\x1f".join(headers),
                "http.file_data": body.hex(),
            }
        )
        accept = base64.b64encode(hashlib.sha1((key + GUID).encode()).digest()).decode()
        responses.append(
            {
                "http.request_in": str(index),
                "http.response.code": "101" if flow == "ws" else "200",
                "http.response.line": (
                    "Sec-WebSocket-Accept: " + accept if flow == "ws" else ""
                ),
            }
        )
    return requests, responses
