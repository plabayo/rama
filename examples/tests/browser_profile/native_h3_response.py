"""Bind native H3 snapshots to complete responses in the same packet capture.

The server's native view identifies its retained snapshot. Independent wire
checks still verify its contents; native publication order is not wire evidence.
"""

from collections import defaultdict
from dataclasses import dataclass
import heapq
from html.parser import HTMLParser

import zstandard

from flow_bodies import json_object
from h3_sequence_wire import (
    FIRST_RESERVED_FRAME,
    RESERVED_FRAME_STEP,
    PRIORITY_UPDATE_REQUEST,
    PRIORITY_UPDATE_PUSH,
)
from flows import operation_flow
from quic_stream_wire import varint, varint_field
from tls_wire import Reader, byte_span, identity
from wire import one, parse_pdml, pdml_packets

MAX_RESPONSE_BYTES = 262144
MAX_CAPTURE_BYTES = 4 * 1024 * 1024
MAX_RESPONSES = 128
MAX_ELEMENTS = 256
MAX_WINDOW_BYTES = 2 * 1024 * 1024


def integer(value, *, limit=1 << 62):
    if type(value) is not int or not 0 <= value < limit:
        raise ValueError("invalid native H3 integer")
    return value


def bounded_list(value):
    if not isinstance(value, list) or len(value) > MAX_ELEMENTS:
        raise ValueError("invalid native H3 element count")
    return value


def flag(value):
    if type(value) is not bool:
        raise ValueError("invalid native H3 flag")
    return value


@dataclass(frozen=True)
class ResponseStream:
    """A complete decoded body and its optional independently recounted packet boundary."""

    body: bytes
    complete_packet: int | None


def response_data(data, server_port):
    """Require gap-free server STREAM bytes ending at one consistent FIN."""
    return {
        key: stream.body
        for key, stream in _response_streams(
            data, server_port, with_packets=False
        ).items()
    }


def response_evidence(data, server_port):
    """Retain the first packet boundary with complete response bytes and FIN."""
    return _response_streams(data, server_port, with_packets=True)


def _response_streams(data, server_port, *, with_packets):
    fragments, endings, fin_packets = defaultdict(list), {}, {}
    total = 0
    for packet in pdml_packets(data):
        frames = [
            node
            for node in packet.iter("field")
            if node.get("name") == "quic.frame"
            and node.find("field[@name='quic.stream.stream_id']") is not None
        ]
        if not frames:
            continue
        source, destination = int(one(packet, "udp.srcport")), int(
            one(packet, "udp.dstport")
        )
        if (source == server_port) == (destination == server_port):
            raise ValueError("ambiguous native response endpoint")
        if source != server_port:
            continue
        connection = identity(packet, "quic.connection.number")
        for frame in frames:
            stream, width = varint_field(frame, "quic.stream.stream_id")
            if stream & 3:
                continue  # Only client-initiated bidirectional request streams.
            kind, size = varint_field(frame, "quic.frame_type")
            if not 8 <= kind <= 15:
                raise ValueError("invalid native response STREAM type")
            width += size
            offset = 0
            if kind & 4:
                offset, size = varint_field(frame, "quic.stream.offset")
                width += size
            payloads = [
                node
                for node in frame.iter("field")
                if node.get("name") == "quic.stream_data"
            ]
            if len(payloads) > 1:
                raise ValueError("ambiguous native response STREAM payload")
            payload = byte_span(payloads[0]) if payloads else b""
            if kind & 2:
                length, size = varint_field(frame, "quic.stream.length")
                width += size
                if length != len(payload):
                    raise ValueError("native response STREAM length mismatch")
            if int(frame.get("size", "-1")) != width + len(payload):
                raise ValueError("native response STREAM extent mismatch")
            key, end = (connection, stream), offset + len(payload)
            total += len(payload)
            if end > MAX_RESPONSE_BYTES or total > MAX_CAPTURE_BYTES:
                raise ValueError("native response byte limit")
            if key not in fragments and len(fragments) >= MAX_RESPONSES:
                raise ValueError("native response count limit")
            number = int(one(packet, "frame.number")) if with_packets else None
            fragments[key].append((offset, payload, number))
            if kind & 1:
                if key in endings and endings[key] != end:
                    raise ValueError("conflicting native response FIN")
                endings[key] = end
                if with_packets:
                    fin_packets[key] = min(fin_packets.get(key, number), number)
    result = {}
    for key, end in endings.items():
        joined = bytearray()
        for offset, payload, _packet in sorted(fragments[key]):
            if offset > len(joined):
                raise ValueError("gap in native response STREAM")
            overlap = min(len(payload), len(joined) - offset)
            if joined[offset : offset + overlap] != payload[:overlap]:
                raise ValueError("conflicting native response retransmission")
            joined.extend(payload[overlap:])
        if len(joined) != end:
            raise ValueError("native response bytes beyond FIN")
        source, body = Reader(bytes(joined)), bytearray()
        while source.remaining():
            kind, length = varint(source), varint(source)
            payload = source.take(length)
            if kind == 0:
                body.extend(payload)
        complete = None
        if with_packets:
            prefix, pending, complete = 0, [], None
            for offset, payload, packet in sorted(
                fragments[key], key=lambda item: item[2]
            ):
                heapq.heappush(pending, (offset, offset + len(payload)))
                while pending and pending[0][0] <= prefix:
                    _start, stop = heapq.heappop(pending)
                    prefix = max(prefix, stop)
                if packet >= fin_packets[key] and prefix == end:
                    complete = packet
                    break
            if complete is None:
                raise ValueError("missing complete native response packet boundary")
        result[key] = ResponseStream(bytes(body), complete)
    return result


def decoded_body(payload, encoding):
    """Decode one bounded identity or dictionary-free zstd representation."""
    if len(payload) > MAX_RESPONSE_BYTES:
        raise ValueError("native response encoded byte limit")
    if encoding is None:
        return payload
    if encoding != "zstd":
        raise ValueError("unsupported native response content encoding")
    try:
        parameters = zstandard.get_frame_parameters(payload)
        if (
            parameters.dict_id
            or parameters.window_size > MAX_WINDOW_BYTES
            or parameters.content_size not in (zstandard.CONTENTSIZE_UNKNOWN,)
            and parameters.content_size > MAX_RESPONSE_BYTES
        ):
            raise ValueError("native response zstd resource limit")
        body = zstandard.ZstdDecompressor().decompress(
            payload,
            max_output_size=MAX_RESPONSE_BYTES,
            allow_extra_data=False,
        )
        # Unknown-size frames need an explicit boundary check in zstandard 0.25.
        # The bounded first pass has already established this frame's output cap.
        boundary = zstandard.ZstdDecompressor().decompressobj()
        boundary.decompress(payload)
        if not boundary.eof or boundary.unused_data:
            raise ValueError("native response zstd trailing or incomplete frame")
    except zstandard.ZstdError as error:
        raise ValueError("invalid native response zstd frame") from error
    if len(body) > MAX_RESPONSE_BYTES:
        raise ValueError("native response decoded byte limit")
    return body


class ObservationTable(HTMLParser):
    """Read the existing display row, without executing or scraping scripts."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.tables = 0
        self.cells = None
        self.text = None
        self.views = []

    def handle_starttag(self, tag, attrs):
        if tag == "table":
            self.tables += 1
        elif self.tables and tag == "tr":
            if self.cells is not None:
                raise ValueError("nested native response row")
            self.cells = []
        elif self.cells is not None and tag == "td":
            if self.text is not None:
                raise ValueError("nested native response cell")
            self.text = []
        elif (
            self.text is not None
            and self.cells == ["HTTP/3 observation"]
            and tag != "code"
        ):
            raise ValueError("unexpected markup in native response cell")

    def handle_data(self, text):
        if self.text is not None:
            self.text.append(text)

    def handle_endtag(self, tag):
        if tag == "td" and self.text is not None:
            self.cells.append("".join(self.text))
            self.text = None
        elif tag == "tr" and self.cells is not None:
            if self.text is not None:
                raise ValueError("unclosed native response cell")
            if self.cells and self.cells[0] == "HTTP/3 observation":
                if len(self.cells) != 2:
                    raise ValueError("ambiguous native response row")
                self.views.append(json_object(self.cells[1]))
            self.cells = None
        elif tag == "table":
            self.tables -= 1


def native_view(body, content_type):
    if content_type == "application/json":
        try:
            return json_object(body)["fp"]["http_info"]["h3"]
        except (KeyError, TypeError) as error:
            raise ValueError("missing JSON native H3 view") from error
    if content_type != "text/html; charset=utf-8":
        raise ValueError("unsupported native response content type")
    parser = ObservationTable()
    parser.feed(body.decode("utf-8"))
    parser.close()
    if parser.tables or parser.cells is not None or len(parser.views) != 1:
        raise ValueError("missing or ambiguous HTML native H3 view")
    return parser.views[0]


def native_sequence(view, stream):
    """Project the native view using the profile's existing privacy policy."""
    if not isinstance(view, dict) or view.get("settings_status") != "received":
        raise ValueError("incomplete native H3 view")
    if integer(view.get("request_stream_id")) != stream:
        raise ValueError("native H3 request stream mismatch")
    complete = view.get("completeness")
    names = {
        "snapshot",
        "streams",
        "control",
        "qpack",
        "settings",
        "local_settings",
        "fields",
    }
    if (
        not isinstance(complete, dict)
        or set(complete) != names
        or any(flag(complete[name]) is not True for name in names)
    ):
        raise ValueError("incomplete native H3 snapshot")
    revision = integer(view.get("connection_revision"), limit=1 << 64)
    events, ordinals, settings, setting_ids, stream_ids = [], set(), [], set(), set()
    for entry in bounded_list(view.get("local_settings")):
        if not isinstance(entry, dict):
            raise ValueError("invalid native H3 setting")
        identifier, value = integer(entry.get("id")), integer(entry.get("value"))
        flag(entry.get("grease"))
        if identifier in setting_ids:
            raise ValueError("duplicate native H3 local setting")
        setting_ids.add(identifier)
        settings.append(
            dict(id=identifier, value={"Literal": list(value.to_bytes(8, "big"))})
        )
    for entry in bounded_list(view.get("streams")):
        if not isinstance(entry, dict):
            raise ValueError("invalid native H3 stream")
        identifier, kind = integer(entry.get("stream_id")), integer(
            entry.get("stream_type")
        )
        flag(entry.get("grease"))
        if identifier & 3 != 2 or identifier in stream_ids:
            raise ValueError("invalid native H3 stream identity")
        stream_ids.add(identifier)
        events.append(
            (
                entry.get("sequence"),
                {"Stream": dict(stream_id=identifier, stream_type=kind)},
            )
        )
    for entry in bounded_list(view.get("control")):
        if not isinstance(entry, dict):
            raise ValueError("invalid native H3 control frame")
        kind, length = integer(entry.get("frame_type")), integer(entry.get("length"))
        if "element_id" not in entry:
            raise ValueError("missing native H3 control element")
        element = entry["element_id"]
        if element is not None:
            integer(element)
        value = entry.get("value")
        if not isinstance(value, list) or len(value) > MAX_RESPONSE_BYTES:
            raise ValueError("native H3 control payload limit")
        for byte in value:
            integer(byte, limit=256)
        retained = (
            kind in (PRIORITY_UPDATE_REQUEST, PRIORITY_UPDATE_PUSH)
            or kind >= FIRST_RESERVED_FRAME
            and (kind - FIRST_RESERVED_FRAME) % RESERVED_FRAME_STEP == 0
        )
        events.append(
            (
                entry.get("sequence"),
                {
                    "Control": dict(
                        frame_type=kind,
                        length=length,
                        element_id=element,
                        value=value if retained else [],
                    )
                },
            )
        )
    for ordinal, _ in events:
        integer(ordinal, limit=1 << 64)
        if not 0 < ordinal <= revision or ordinal in ordinals:
            raise ValueError("invalid native H3 sequence ordinal")
        ordinals.add(ordinal)
    events.sort(key=lambda item: item[0])
    instructions = []
    schemas = {
        "Capacity": {"capacity": int},
        "Duplicate": {"index": int},
        "InsertNameReference": {
            "is_static": bool,
            "index": int,
            "value_bytes": int,
            "value_huffman": bool,
        },
        "InsertLiteral": {
            "name_bytes": int,
            "value_bytes": int,
            "name_huffman": bool,
            "value_huffman": bool,
        },
    }
    for instruction in bounded_list(view.get("qpack")):
        if not isinstance(instruction, dict) or len(instruction) != 1:
            raise ValueError("invalid native H3 QPACK instruction")
        kind, fields = next(iter(instruction.items()))
        if (
            kind not in schemas
            or not isinstance(fields, dict)
            or set(fields) != set(schemas[kind])
        ):
            raise ValueError("invalid native H3 QPACK fields")
        for name, ty in schemas[kind].items():
            flag(fields[name]) if ty is bool else integer(fields[name])
        fields = dict(fields)
        if "value_bytes" in fields:
            fields["value_bytes"] = 0
        instructions.append({kind: fields})
    return dict(
        completeness="Complete",
        local_settings=dict(
            completeness="Complete", namespace="Http3Setting", fields=settings
        ),
        events=[event for _, event in events],
        encoder_instructions=instructions,
    )


def response_sequences(data, server_port, *, operations=None):
    """Return exact native attribution for each H3 journey connection."""
    bodies = response_data(data, server_port)
    streams = defaultdict(list)
    for block in parse_pdml(data, "h3", server_port, include_data=True):
        streams[(block.connection, block.stream)].append(block)
    result = {}
    for key, frames in streams.items():
        heads = [block for block in frames if block.headers and not block.from_server]
        if not heads:
            continue
        flow = operation_flow(heads[0], operations)
        if flow is None:
            # Root redirects are explicit startup exchanges, not failed views.
            # Explicit discovery operations are selected by the caller's ledger;
            # other assets and probes are outside the selected journey.
            if dict(heads[0].headers).get(":path") == "/":
                replies = [
                    block for block in frames if block.headers and block.from_server
                ]
                if (
                    len(heads) != 1
                    or len(replies) != 1
                    or key not in bodies
                    or dict(replies[0].headers).get(":status") != "307"
                    or bodies[key]
                ):
                    raise ValueError("invalid native response startup redirect")
            continue
        if flow == "ws":
            continue  # A WS greeting has no native view; ambiguity still fails.
        responses = [block for block in frames if block.headers and block.from_server]
        if len(heads) != 1 or len(responses) != 1 or key not in bodies:
            raise ValueError("missing or ambiguous complete native response")
        pairs = responses[0].headers
        singleton = {":status", "content-type", "content-encoding", "content-length"}
        for name in singleton:
            if sum(key == name for key, _ in pairs) > 1:
                raise ValueError("duplicate native response binding header")
        headers = dict(pairs)
        payload = b"".join(block.data for block in frames if block.from_server)
        if headers.get(":status") != "200" or payload != bodies[key]:
            raise ValueError("native response DATA differs from complete STREAM bytes")
        length = headers.get("content-length")
        if length is not None and (
            not length.isascii()
            or not length.isdecimal()
            or int(length) != len(payload)
        ):
            raise ValueError("native response Content-Length mismatch")
        body = decoded_body(payload, headers.get("content-encoding"))
        sequence = native_sequence(
            native_view(body, headers.get("content-type")), key[1]
        )
        if key[0] in result and result[key[0]] != sequence:
            raise ValueError("conflicting native H3 response snapshots")
        result[key[0]] = sequence
    return result
