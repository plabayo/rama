"""Bounded native QUIC unidirectional stream ownership and byte reassembly."""

from collections import defaultdict
from dataclasses import dataclass, field as data_field
from pdml import field, identity, one, pdml_packets, values
from tls_wire import Reader, byte_span



def varint(source):
    """Read one RFC 9000 integer, preserving the caller's payload bytes."""
    first = source.integer(1)
    width = 1 << (first >> 6)
    return ((first & 63) << (8 * (width - 1))) | int.from_bytes(
        source.take(width - 1), "big"
    )


def varint_field(node, name):
    value = field(node, name)
    raw = bytes.fromhex(value.get("value", ""))
    if len(raw) != int(value.get("size", "-1")):
        raise ValueError("incomplete QUIC integer span: " + name)
    source = Reader(raw)
    decoded = varint(source)
    source.finish()
    if decoded != int(value.get("show", ""), 0):
        raise ValueError("QUIC integer display/raw mismatch: " + name)
    return decoded, len(raw)


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
    for packet in pdml_packets(data):
        frames = [
            node for node in packet.iter("field") if node.get("name") == "quic.frame"
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
            kind, width = varint_field(frame, "quic.frame_type")
            if not 8 <= kind <= 15:
                if any(
                    node.get("name") in ("quic.stream_data", "quic.stream.stream_id")
                    for node in frame.iter("field")
                ):
                    raise ValueError("undeclared QUIC STREAM fields")
                continue
            stream_id, id_width = varint_field(frame, "quic.stream.stream_id")
            if stream_id & 2 and bool(stream_id & 1) != from_server:
                raise ValueError("unidirectional stream sent by the wrong endpoint")
            width += id_width
            offset = 0
            if kind & 4:
                offset, size = varint_field(frame, "quic.stream.offset")
                width += size
            elif frame.find("field[@name='quic.stream.offset']") is not None:
                raise ValueError("unexpected QUIC STREAM offset field")
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
            elif frame.find("field[@name='quic.stream.length']") is not None:
                raise ValueError("unexpected QUIC STREAM length field")
            if int(frame.get("size", "-1")) != width + len(payload):
                raise ValueError("QUIC STREAM frame extent mismatch")
            if not stream_id & 2:
                continue  # Request bytes have no unidirectional stream-type prefix.
            key = (connection, from_server, stream_id)
            streams[key].append((offset, payload))

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


DATAGRAM_PADDING = frozenset(
    (
        "_ws.expert",
        "_ws.expert.message",
        "_ws.expert.severity",
        "_ws.expert.group",
        "quic.coalesced_padding_data",
    )
)


# Frames naming one stream by ID, mapped to the field carrying it.
STREAM_FRAME_IDS = {
    0x04: "quic.rsts.stream_id",
    0x05: "quic.ss.stream_id",
    0x11: "quic.msd.stream_id",
    0x15: "quic.sdb.stream_id",
}
STREAM_FRAMES = range(0x08, 0x10)
CONNECTION_CLOSE = {
    0x1C: ("quic.cc.error_code",),
    0x1D: ("quic.cc.error_code.app", "quic.cc.error_code"),
}


def bidirectional_stream(frame, kind):
    if kind in STREAM_FRAMES:
        name = "quic.stream.stream_id"
    elif kind in STREAM_FRAME_IDS:
        name = STREAM_FRAME_IDS[kind]
    else:
        return False
    return not varint_field(frame, name)[0] & 2


def closed_with_error(frame, kind):
    if kind not in CONNECTION_CLOSE:
        return False
    names = [name for name in CONNECTION_CLOSE[kind] if values(frame, name)]
    # An unreadable error code cannot prove a clean close.
    return not names or varint_field(frame, names[0])[0] != 0


def requestless_connections(data, server_port):
    """Native QUIC connections whose every packet decrypted without a request stream.

    Unanswered Initial attempts and connections carrying only control/QPACK
    streams qualify; they are reported, not attributed to the browser. Any
    undecrypted packet, frame naming a bidirectional stream, or CONNECTION_CLOSE
    with an error excludes the connection. A client packet without a native QUIC
    element or connection number cannot be attributed, so it excludes all; such a
    server packet carries no request and is skipped.
    """
    decoded, excluded = set(), set()
    for packet in pdml_packets(data):
        ports = {
            int(port)
            for port in values(packet, "udp.srcport") + values(packet, "udp.dstport")
        }
        if server_port not in ports:
            continue
        from_server = int(one(packet, "udp.srcport")) == server_port
        protos = packet.findall("proto[@name='quic']")
        if not protos:
            if from_server:
                continue
            return set()
        for proto in protos:
            names = {node.get("name", "") for node in proto.iter("field")}
            if "quic.coalesced_padding_data" in names and names <= DATAGRAM_PADDING:
                continue  # Bytes appended after the datagram's last QUIC packet.
            if not values(proto, "quic.connection.number"):
                if from_server:
                    continue
                return set()  # An unattributable client packet could belong to any connection.
            connection = identity(proto, "quic.connection.number")
            decoded.add(connection)
            frames = [
                node for node in proto.iter("field") if node.get("name") == "quic.frame"
            ]
            if not frames or not values(proto, "quic.packet_number"):
                excluded.add(connection)
            for frame in frames:
                kind, _ = varint_field(frame, "quic.frame_type")
                if bidirectional_stream(frame, kind) or closed_with_error(frame, kind):
                    excluded.add(connection)
    return decoded - excluded
