"""Check HTTP/3 recorder prefixes against independently decoded stream bytes.

QUIC reassembly here only joins tshark's decrypted STREAM payloads. Recorder
scheduling across streams is not observable on the wire: these checks establish
prefix contents, not the exact first-request freeze or cross-stream event order.
No request values or QPACK strings are returned in reports.
"""

from collections import defaultdict
from dataclasses import dataclass, field as data_field

from quic_wire import H3_SETTINGS, client_settings, varint, varint_field
from qpack_wire import ENCODER_STREAM, encoder_instructions
from tls_wire import Reader, byte_span, identity
from wire import one, pdml_packets

CONTROL_STREAM = 0
CANCEL_PUSH = 3
GOAWAY = 7
MAX_PUSH_ID = 13
PRIORITY_UPDATE_REQUEST = 0xF0700
PRIORITY_UPDATE_PUSH = 0xF0701
# These are role/capability advertisements, added after the decoder context is
# configured. The recorder retains that context, not these two capabilities.
ENABLE_CONNECT_PROTOCOL = 8
H3_DATAGRAM = 0x33
MAX_STREAMS = 32
MAX_STREAM_BYTES = 65536
MAX_TOTAL_BYTES = 262144
MAX_CONTROL_FRAMES = 256


@dataclass(frozen=True)
class StreamPrefix:
    stream_id: int
    stream_type: int
    payload: bytes = data_field(repr=False)


def stream_prefixes(data, server_port):
    """Reassemble bounded unidirectional streams; reject conflicting overlaps.

    Retransmissions may repeat or partially overlap existing data. Gaps cannot
    establish a complete prefix and fail instead of silently joining fragments.
    Directions have independent stream IDs and must never share a byte buffer.
    """
    streams = defaultdict(list)
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
            raise ValueError("ambiguous HTTP/3 fixture endpoint")
        from_server = source == server_port
        connection = identity(packet, "quic.connection.number")
        for frame in frames:
            stream_id, id_width = varint_field(frame, "quic.stream.stream_id")
            if not stream_id & 2:
                continue  # Bidirectional request streams have no stream-type prefix.
            if bool(stream_id & 1) != from_server:
                raise ValueError("unidirectional stream sent by the wrong endpoint")
            kind, width = varint_field(frame, "quic.frame_type")
            if not 8 <= kind <= 15:
                raise ValueError("invalid QUIC STREAM frame type")
            width += id_width
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
                raise ValueError("ambiguous QUIC STREAM payload")
            # A zero-length STREAM/FIN may have no data field. The declared
            # length and parent extent below still reject missing nonempty data.
            payload = byte_span(payloads[0]) if payloads else b""
            if kind & 2:
                length, size = varint_field(frame, "quic.stream.length")
                width += size
                if length != len(payload):
                    raise ValueError("QUIC STREAM payload length mismatch")
            if int(frame.get("size", "-1")) != width + len(payload):
                raise ValueError("QUIC STREAM frame extent mismatch")
            if offset + len(payload) > MAX_STREAM_BYTES:
                raise ValueError("HTTP/3 stream byte limit")
            total += len(payload)  # Count duplicate data too; retransmits are bounded.
            if total > MAX_TOTAL_BYTES:
                raise ValueError("HTTP/3 aggregate stream byte limit")
            key = (connection, from_server, stream_id)
            streams[key].append((offset, payload))
            if len(streams) > MAX_STREAMS:
                raise ValueError("HTTP/3 stream count limit")

    result = defaultdict(list)
    for (connection, from_server, stream_id), fragments in streams.items():
        joined = bytearray()
        for offset, payload in sorted(fragments):
            if offset > len(joined):
                raise ValueError("gap in HTTP/3 stream prefix")
            overlap = min(len(payload), len(joined) - offset)
            if joined[offset : offset + overlap] != payload[:overlap]:
                raise ValueError("conflicting HTTP/3 stream retransmission")
            joined.extend(payload[overlap:])
        source = Reader(bytes(joined))
        stream_type = varint(source)
        result[(connection, from_server)].append(
            StreamPrefix(stream_id, stream_type, source.take(source.remaining()))
        )
    return dict(result)


def control_frames(stream):
    """Decode recorder-visible control metadata without retaining ignored bodies."""
    if stream.stream_type != CONTROL_STREAM:
        raise ValueError("expected HTTP/3 control stream")
    source, result = Reader(stream.payload), []
    while source.remaining():
        kind, length = varint(source), varint(source)
        body = Reader(source.take(length))
        element, value = None, []
        if kind in (CANCEL_PUSH, GOAWAY, MAX_PUSH_ID):
            element = varint(body)
            body.finish()
        elif kind in (PRIORITY_UPDATE_REQUEST, PRIORITY_UPDATE_PUSH):
            element = varint(body)
            value = list(body.take(body.remaining()))
        # SETTINGS and unknown frame bodies are intentionally absent from the
        # recorder. SETTINGS values have their own independent comparison.
        result.append(
            dict(frame_type=kind, length=length, element_id=element, value=value)
        )
        if len(result) > MAX_CONTROL_FRAMES:
            raise ValueError("HTTP/3 control frame limit")
    if not result or result[0]["frame_type"] != H3_SETTINGS:
        raise ValueError("HTTP/3 control stream must begin with SETTINGS")
    if sum(frame["frame_type"] == H3_SETTINGS for frame in result) != 1:
        raise ValueError("repeated HTTP/3 control SETTINGS")
    return result


@dataclass(frozen=True)
class SequenceEvidence:
    streams: tuple[StreamPrefix, ...]
    controls: tuple[dict, ...]
    local_settings: dict
    encoder_instructions: tuple[dict, ...] = ()

    def matches(self, capture):
        return sequence_matches(capture, self)


def sequence_evidence(data, server_port):
    """Associate browser prefixes and server decoder context with one connection."""
    streams = stream_prefixes(data, server_port)
    settings = client_settings(data, server_port, from_server=True)
    instructions = encoder_instructions(data, server_port, streams)
    result = {}
    for (connection, from_server), prefixes in streams.items():
        if from_server:
            continue
        control = [
            stream for stream in prefixes if stream.stream_type == CONTROL_STREAM
        ]
        if len(control) != 1 or connection not in settings:
            raise ValueError("missing control stream or server decoder SETTINGS")
        context = dict(settings[connection])
        context["fields"] = [
            entry
            for entry in context["fields"]
            if entry["id"] not in (ENABLE_CONNECT_PROTOCOL, H3_DATAGRAM)
        ]
        result[connection] = SequenceEvidence(
            tuple(prefixes),
            tuple(control_frames(control[0])),
            context,
            instructions.get(connection, ()),
        )
    return result


def sequence_matches(capture, evidence):
    """Require one wire-backed prefix; cross-stream freeze order stays unverified.

    Empty instruction prefixes remain valid despite later table activity. A
    nonempty prefix must match decoded encoder metadata in its own stream order;
    this still does not establish the recorder's exact first-request cutoff.
    """
    if (
        capture.get("completeness") != "Complete"
        or capture.get("local_settings") != evidence.local_settings
    ):
        return False
    instructions = capture.get("encoder_instructions", [])
    if instructions != list(evidence.encoder_instructions[: len(instructions)]):
        return False
    observed = {stream.stream_id: stream.stream_type for stream in evidence.streams}
    seen, controls = set(), []
    control_seen = False
    for event in capture.get("events", []):
        if set(event) == {"Stream"}:
            stream = event["Stream"]
            identifier, kind = stream["stream_id"], stream["stream_type"]
            if identifier in seen or observed.get(identifier) != kind:
                return False
            seen.add(identifier)
            control_seen |= kind == CONTROL_STREAM
        elif set(event) == {"Control"}:
            if not control_seen:
                return False
            controls.append(event["Control"])
        else:
            raise ValueError("unknown captured HTTP/3 sequence event")
    if instructions and not any(
        observed[identifier] == ENCODER_STREAM for identifier in seen
    ):
        return False
    return bool(controls) and controls == list(evidence.controls[: len(controls)])
