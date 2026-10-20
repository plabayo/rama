"""Resolve explicitly blocked tshark request or response heads with independent ls-qpack.

Only decrypted PDML bytes are admitted. Encoder events retain packet order;
blocked heads resume under their original packet/connection/stream identity.
Already decoded heads must agree with ls-qpack. This compensates for tshark's
cached blocked-header result, not missing packets, keys or native observations.
"""

import pylsqpack
from dataclasses import dataclass, field
from pdml import MAX_PDML_BYTES, field as single, fields as nodes

MAX_BLOCKED = 64
MAX_CAPACITY = 65536


def number(node, name):
    values = {item.get("show") for item in nodes(node, name)}
    if len(values) != 1 or None in values:
        raise ValueError("ambiguous QPACK identity: " + name)
    value = int(values.pop())
    if not 0 <= value < 1 << 62:
        raise ValueError("QPACK identity range")
    return value


def raw(node):
    payload = bytes.fromhex(node.get("value", ""))
    if len(payload) != int(node.get("size", "-1")):
        raise ValueError("incomplete raw QPACK witness")
    return payload


def varint(payload):
    if not payload:
        raise ValueError("truncated QUIC integer")
    width = 1 << (payload[0] >> 6)
    if len(payload) != width:
        raise ValueError("truncated QUIC integer")
    return int.from_bytes(payload, "big") & ((1 << (width * 8 - 2)) - 1)


def integer(node, name):
    value = single(node, name)
    encoded = raw(value)
    decoded = varint(encoded)
    if decoded != int(value.get("show"), 0):
        raise ValueError("QUIC integer display/raw mismatch")
    return decoded, len(encoded)


def blocked(frame):
    """Require the dissector's explicit blocked flag, never infer missing heads."""
    marks = nodes(frame, "http3.header.qpack.blocked")
    if not marks:
        return False
    if len(marks) != 1 or marks[0].get("show") not in ("1", "True", "true"):
        raise ValueError("ambiguous QPACK blocked marker")
    return True


def displayed_headers(frame):
    return tuple(
        (
            single(item, "http3.header.header.name").get("show", ""),
            single(item, "http3.headers.header.value").get("show", ""),
        )
        for item in nodes(frame, "http3.headers.header")
    )


@dataclass
class EncoderWitness:
    """Bound one native encoder stream to its chronological dissector chunks."""

    fragments: dict = field(default_factory=dict)
    decoded: bytearray = field(default_factory=bytearray)

    def add(self, offset, payload):
        for index, byte in enumerate(payload, offset):
            if index in self.fragments and self.fragments[index] != byte:
                raise ValueError("conflicting QPACK encoder retransmission")
            self.fragments[index] = byte

    def prefix(self):
        length = 0
        while length in self.fragments:
            length += 1
        joined = bytes(self.fragments[index] for index in range(length))
        if not joined or len(joined) < 1 << (joined[0] >> 6):
            return None
        width = 1 << (joined[0] >> 6)
        return varint(joined[:width]), joined[width:]

    def verify(self):
        if not self.fragments or self.prefix() is None:
            raise ValueError("missing native QPACK encoder stream")
        if len(self.fragments) != max(self.fragments) + 1:
            raise ValueError("gap in QPACK encoder stream")
        return self.prefix()


@dataclass(frozen=True)
class ResolvedHeaders:
    headers: dict
    recovered: frozenset


def resolve_blocked_headers(packets, server_port, *, from_server=False):
    """Return independently checked heads only when explicit blocking occurred.

    Each direction has its own decoder and native encoder stream witnesses.
    Native encoder bytes must match every fed opcode byte. Unresolved heads,
    ambiguous identities and malformed or excessive observations fail closed.
    Values stay transient inside this verifier and are never diagnostic text.
    """
    if not any(
        blocked(frame)
        and number(packet, "udp.srcport" if from_server else "udp.dstport") == server_port
        for packet in packets
        for frame in nodes(packet, "http3.frame")
    ):
        return ResolvedHeaders({}, frozenset())

    decoders, witnesses, encoder_streams = {}, {}, {}
    sections, pending, resolved, recovered = {}, {}, {}, set()
    previous_packet = 0

    def decoder(connection):
        if connection not in decoders:
            decoders[connection] = pylsqpack.Decoder(MAX_CAPACITY, MAX_BLOCKED)
        return decoders[connection]

    def finish(key, fields):
        if sum(len(name) + len(value) for name, value in fields) > MAX_PDML_BYTES:
            raise ValueError("QPACK decoded byte limit")
        try:
            headers = tuple(
                (name.decode("utf-8"), value.decode("utf-8")) for name, value in fields
            )
        except UnicodeDecodeError:
            raise ValueError("QPACK header text is not UTF-8") from None
        frame = sections[key]
        if blocked(frame):
            if displayed_headers(frame):
                raise ValueError("partially decoded blocked QPACK head")
            recovered.add(key)
        elif displayed_headers(frame) != headers:
            raise ValueError("independent QPACK/tshark header mismatch")
        resolved[key] = headers

    try:
        for packet in packets:
            if not nodes(packet, "http3.frame") and not nodes(
                packet, "quic.stream.stream_id"
            ):
                continue
            packet_number = number(packet, "frame.number")
            if packet_number <= previous_packet:
                raise ValueError("nonchronological QPACK packets")
            previous_packet = packet_number
            source, destination = number(packet, "udp.srcport"), number(
                packet, "udp.dstport"
            )
            if (source == server_port) == (destination == server_port):
                raise ValueError("ambiguous QPACK fixture endpoint")
            if (source == server_port) != from_server:
                continue
            connection = number(packet, "quic.connection.number")
            current = decoder(connection)

            # Retain original STREAM offsets as a second witness for encoder bytes.
            for frame in nodes(packet, "quic.frame"):
                if not nodes(frame, "quic.stream.stream_id"):
                    continue
                stream, _ = integer(frame, "quic.stream.stream_id")
                if stream & 3 != (3 if from_server else 2):
                    continue
                key = connection, stream
                if key not in witnesses:
                    witnesses[key] = EncoderWitness()
                offset = (
                    integer(frame, "quic.stream.offset")[0]
                    if nodes(frame, "quic.stream.offset")
                    else 0
                )
                payloads = nodes(frame, "quic.stream_data")
                if len(payloads) > 1:
                    raise ValueError("ambiguous QPACK STREAM payload")
                payload = raw(payloads[0]) if payloads else b""
                kind, width = integer(frame, "quic.frame_type")
                if not 8 <= kind <= 15:
                    raise ValueError("invalid native QUIC STREAM frame")
                width += integer(frame, "quic.stream.stream_id")[1]
                if kind & 4:
                    width += integer(frame, "quic.stream.offset")[1]
                elif offset:
                    raise ValueError("unexpected native QUIC STREAM offset")
                if kind & 2:
                    declared, size = integer(frame, "quic.stream.length")
                    width += size
                    if declared != len(payload):
                        raise ValueError("native QUIC STREAM length mismatch")
                if int(frame.get("size", "-1")) != width + len(payload):
                    raise ValueError("native QUIC STREAM extent mismatch")
                witnesses[key].add(offset, payload)

            # Tshark's HTTP/3 subtrees follow the native frame order within a packet.
            for event in packet.iter("field"):
                name = event.get("name")
                if name == "http3.qpack.encoder":
                    payload = raw(event)
                    if not payload:
                        raise ValueError("empty QPACK encoder witness")
                    stream_keys = [
                        key
                        for key, witness in witnesses.items()
                        if key[0] == connection
                        and witness.prefix() is not None
                        and witness.prefix()[0] == 2
                    ]
                    if len(stream_keys) != 1:
                        raise ValueError("ambiguous native QPACK encoder stream")
                    stream_key = stream_keys[0]
                    encoder_streams[connection] = stream_key
                    witness = witnesses[stream_key]
                    witness.decoded.extend(payload)
                    if not witness.prefix()[1].startswith(witness.decoded):
                        raise ValueError(
                            "QPACK encoder bytes precede their native witness"
                        )
                    for stream in current.feed_encoder(payload):
                        key = pending.pop((connection, stream), None)
                        if key is None:
                            raise ValueError("unexpected QPACK resumed stream")
                        _feedback, fields = current.resume_header(stream)
                        finish(key, fields)
                elif (
                    name == "http3.frame"
                    and nodes(event, "http3.frame_type")
                    and integer(event, "http3.frame_type")[0] == 1
                ):
                    stream = number(event, "http3.frame_streamid")
                    if stream & 3:
                        raise ValueError("QPACK bidirectional stream role")
                    key = packet_number, connection, stream
                    if key in sections or any(
                        existing[1:] == key[1:] for existing in sections
                    ):
                        raise ValueError("ambiguous QPACK HEADERS")
                    payload = raw(single(event, "http3.frame_payload"))
                    length, length_width = integer(event, "http3.frame_length")
                    _kind, type_width = integer(event, "http3.frame_type")
                    if (
                        len(payload) != length
                        or int(event.get("size", "-1"))
                        != type_width + length_width + length
                    ):
                        raise ValueError("QPACK HEADERS extent mismatch")
                    sections[key] = event
                    try:
                        _feedback, fields = current.feed_header(stream, payload)
                    except pylsqpack.StreamBlocked:
                        pending[connection, stream] = key
                        if (
                            sum(owner == connection for owner, _stream in pending)
                            > MAX_BLOCKED
                        ):
                            raise ValueError("QPACK blocked stream limit")
                    else:
                        finish(key, fields)
    except (pylsqpack.DecompressionFailed, pylsqpack.EncoderStreamError):
        raise ValueError("independent QPACK decoding failed") from None

    if pending or set(sections) != set(resolved):
        raise ValueError("unresolved QPACK HEADERS")
    for connection, stream_key in encoder_streams.items():
        witness = witnesses[stream_key]
        kind, payload = witness.verify()
        if kind != 2 or payload != bytes(witness.decoded):
            raise ValueError("QPACK encoder/native byte mismatch")
    if not recovered:
        raise ValueError("blocked QPACK head has no independent resolution")
    return ResolvedHeaders(resolved, frozenset(recovered))
