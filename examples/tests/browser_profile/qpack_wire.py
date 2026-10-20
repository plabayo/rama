"""Independent QPACK encoder metadata from tshark and decrypted stream bytes.

Tshark decodes Huffman names. Raw instruction prefixes determine opcodes,
indices and Huffman flags; complete instruction bytes must reconstruct the
encoder stream exactly. Metadata discards inserted values. A bounded raw-byte
witness supports separate bootstrap checks and must never enter a report.
"""

from collections import defaultdict
from pdml import field, identity, one, pdml_packets
from tls_wire import Reader

ENCODER_STREAM = 2
OPCODES = {
    "http3.qpack.encoder.opcode.dtable_cap",
    "http3.qpack.encoder.opcode.duplicate",
    "http3.qpack.encoder.opcode.insert",
    "http3.qpack.encoder.opcode.insert_indexed",
}


def prefixed_integer(source, width):
    """Read an RFC 9204 prefixed integer, bounded to a QUIC integer's range."""
    first = source.integer(1)
    value = first & ((1 << width) - 1)
    if value == (1 << width) - 1:
        shift = 0
        while True:
            byte = source.integer(1)
            value += (byte & 127) << shift
            if value >= 1 << 62:
                raise ValueError("QPACK integer overflow")
            if not byte & 128:
                break
            shift += 7
            if shift > 56:
                raise ValueError("QPACK integer continuation limit")
    return first, value


def string(source, width):
    first, length = prefixed_integer(source, width)
    return bool(first & (1 << width)), source.take(length)


def decode_instruction(node):
    raw = bytes.fromhex(node.get("value", ""))
    if not raw or len(raw) != int(node.get("size", "-1")):
        raise ValueError("incomplete QPACK instruction extent")
    source = Reader(raw)
    first = raw[0]
    if first & 128:
        expected = "http3.qpack.encoder.opcode.insert_indexed"
        _, index = prefixed_integer(source, 6)
        huffman, _ = string(source, 7)
        result = {
            "InsertNameReference": dict(
                is_static=bool(first & 64),
                index=index,
                value_bytes=0,
                value_huffman=huffman,
            )
        }
    elif first & 64:
        expected = "http3.qpack.encoder.opcode.insert"
        name_huffman, encoded_name = string(source, 5)
        value_huffman, _ = string(source, 7)
        # This is a generated decoded field, not a physical packet span. The
        # Huffman bytes are independently decoded by tshark, not by Rama's codec.
        name = field(node, expected + ".name")
        decoded = bytes.fromhex(name.get("value", ""))
        if len(decoded) != int(name.get("size", "-1")):
            raise ValueError("incomplete decoded QPACK name")
        if not name_huffman and encoded_name != decoded:
            raise ValueError("QPACK literal name display/raw mismatch")
        result = {
            "InsertLiteral": dict(
                name_bytes=len(decoded),
                value_bytes=0,
                name_huffman=name_huffman,
                value_huffman=value_huffman,
            )
        }
    elif first & 32:
        expected = "http3.qpack.encoder.opcode.dtable_cap"
        _, capacity = prefixed_integer(source, 5)
        result = {"Capacity": {"capacity": capacity}}
    else:
        expected = "http3.qpack.encoder.opcode.duplicate"
        _, index = prefixed_integer(source, 5)
        result = {"Duplicate": {"index": index}}
    source.finish()
    if node.get("name") != expected:
        raise ValueError("QPACK opcode display/raw mismatch")
    return raw, result


def encoder_instruction_evidence(data, server_port, streams):
    """Require decoded opcodes to cover each client encoder stream exactly once."""
    encoded, decoded = defaultdict(bytearray), defaultdict(list)
    instruction_bytes = defaultdict(list)
    for packet in pdml_packets(data):
        nodes = [node for node in packet.iter("field") if node.get("name") in OPCODES]
        if not nodes:
            continue
        source, destination = int(one(packet, "udp.srcport")), int(
            one(packet, "udp.dstport")
        )
        if (source == server_port) == (destination == server_port):
            raise ValueError("ambiguous QPACK fixture endpoint")
        if source == server_port:
            continue
        connection = identity(packet, "quic.connection.number")
        for node in nodes:
            raw, instruction = decode_instruction(node)
            encoded[connection].extend(raw)
            instruction_bytes[connection].append(raw)
            decoded[connection].append(instruction)

    checked = set()
    for (connection, from_server), prefixes in streams.items():
        if from_server:
            continue
        encoders = [
            stream for stream in prefixes if stream.stream_type == ENCODER_STREAM
        ]
        if len(encoders) > 1:
            raise ValueError("multiple QPACK encoder streams")
        if encoders:
            if encoders[0].payload != encoded[connection]:
                raise ValueError(
                    "decoded QPACK instructions do not cover encoder stream"
                )
            checked.add(connection)
    if set(encoded) - checked:
        raise ValueError("QPACK instructions lack their encoder stream")
    return {
        connection: (tuple(instructions), tuple(instruction_bytes[connection]))
        for connection, instructions in decoded.items()
    }


def encoder_instructions(data, server_port, streams):
    """Return redacted metadata after complete encoder-stream correspondence."""
    return {
        connection: metadata
        for connection, (metadata, _raw) in encoder_instruction_evidence(
            data, server_port, streams
        ).items()
    }
