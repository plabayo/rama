"""Check retained QPACK field metadata against raw, decrypted HEADERS bytes.

The byte parser is independent of Rama. Tshark supplies the decoded HTTP fields;
we read field-line prefixes, indexes, Huffman flags and never-index bits ourselves.
Literal contents are discarded. This verifies capture accuracy, not equivalence
between compression states on different connections. Replay policy additionally
compares families, static indexes and flags with one original request joint;
tshark's resolved fields establish what each fresh-table reference denotes.
"""

from dataclasses import asdict, dataclass

from capture_fields import matching_fields, request_candidates
from flows import FLOW_NAMES, flow_name
from qpack_wire import prefixed_integer
from quic_wire import varint_field
from tls_wire import Reader, byte_span, identity
from wire import one, pdml_packets

MAX_FIELDS = 256
MAX_LITERAL_BYTES = 65536


@dataclass(frozen=True)
class Representation:
    representation: str
    index: int | None = None
    name_huffman: bool = False
    value_huffman: bool = False
    never_index: bool = False


@dataclass(frozen=True)
class Section:
    packet: int
    connection: int
    stream: int
    encoded_insert_count: int
    negative_base: bool
    delta_base: int
    fields: tuple[Representation, ...]


def literal_huffman(source, width):
    """Read a string's flag and skip its bounded, intentionally unretained bytes."""
    first, length = prefixed_integer(source, width)
    if length > MAX_LITERAL_BYTES:
        raise ValueError("QPACK literal byte limit")
    source.take(length)
    return bool(first & (1 << width))


def field_representation(source):
    first = source.data[source.offset]
    if first & 128:
        _, index = prefixed_integer(source, 6)
        return Representation("StaticIndex" if first & 64 else "DynamicIndex", index)
    if first & 64:
        _, index = prefixed_integer(source, 4)
        return Representation(
            "LiteralStaticName" if first & 16 else "LiteralDynamicName",
            index,
            value_huffman=literal_huffman(source, 7),
            never_index=bool(first & 32),
        )
    if first & 32:
        name_huffman = literal_huffman(source, 3)
        return Representation(
            "LiteralName",
            name_huffman=name_huffman,
            value_huffman=literal_huffman(source, 7),
            never_index=bool(first & 16),
        )
    if first & 16:
        _, index = prefixed_integer(source, 4)
        return Representation("DynamicPostBaseIndex", index)
    _, index = prefixed_integer(source, 3)
    return Representation(
        "LiteralPostBaseName",
        index,
        value_huffman=literal_huffman(source, 7),
        never_index=bool(first & 8),
    )


def decode_section(payload):
    """Decode a section's raw coordinate system and field-line metadata."""
    source = Reader(payload)
    _, count = prefixed_integer(source, 8)
    prefix, delta = prefixed_integer(source, 7)
    fields = []
    while source.offset < len(source.data):
        if len(fields) >= MAX_FIELDS:
            raise ValueError("QPACK field count limit")
        fields.append(field_representation(source))
    source.finish()
    return count, bool(prefix & 128), delta, tuple(fields)


def sections_from_wire(data, server_port):
    """Require complete client HEADERS payloads and unique packet/stream identity."""
    result = {}
    for packet in pdml_packets(data):
        frames = [
            node
            for node in packet.iter("field")
            if node.get("name") == "http3.frame"
            and varint_field(node, "http3.frame_type")[0] == 1
        ]
        if not frames:
            continue
        source = int(one(packet, "udp.srcport"))
        destination = int(one(packet, "udp.dstport"))
        if (source == server_port) == (destination == server_port):
            raise ValueError("ambiguous QPACK fixture endpoint")
        if source == server_port:
            continue
        connection = identity(packet, "quic.connection.number")
        number = int(one(packet, "frame.number"))
        for frame in frames:
            payloads = [
                node
                for node in frame.iter("field")
                if node.get("name") == "http3.frame_payload"
            ]
            if len(payloads) != 1:
                raise ValueError("incomplete HEADERS payload")
            payload = byte_span(payloads[0])
            _, type_width = varint_field(frame, "http3.frame_type")
            length, length_width = varint_field(frame, "http3.frame_length")
            if (
                len(payload) != length
                or int(frame.get("size", "-1")) != type_width + length_width + length
            ):
                raise ValueError("HEADERS payload extent mismatch")
            count, negative, delta, fields = decode_section(payload)
            if len(fields) != int(one(frame, "http3.headers.count")):
                raise ValueError("raw/tshark header count mismatch")
            stream = int(one(frame, "http3.frame_streamid"))
            if not 0 <= stream < 1 << 62 or stream & 3:
                raise ValueError(
                    "client HEADERS requires a client bidirectional stream"
                )
            key = (number, connection, stream)
            if key in result:
                raise ValueError("ambiguous HEADERS frame identity")
            result[key] = Section(
                number, connection, stream, count, negative, delta, fields
            )
    return result


DYNAMIC_REFERENCES = frozenset(
    {
        "DynamicIndex",
        "DynamicPostBaseIndex",
        "LiteralDynamicName",
        "LiteralPostBaseName",
    }
)


def policy_key(metadata):
    """Keep every choice except a validated connection-local dynamic index."""
    field = Representation(**metadata)
    index = field.index
    if field.representation in DYNAMIC_REFERENCES:
        if type(index) is not int or not 0 <= index < 1 << 62:
            raise ValueError("invalid dynamic reference index")
        index = None
    return (
        field.representation,
        index,
        field.name_huffman,
        field.value_huffman,
        field.never_index,
    )


def matching_representations(capture, headers, representations, *, fresh_table=False):
    """Keep pseudo/regular metadata in the same joint as its actual HTTP fields."""
    if (
        len(headers) != len(representations)
        or matching_fields(capture, headers) is None
    ):
        return False
    slots = {slot["kind"]: slot["capture"] for slot in capture["slots"]}
    for kind, pseudo in [("Headers", False), ("PseudoHeaders", True)]:
        raw = [
            asdict(metadata)
            for (name, _), metadata in zip(headers, representations)
            if name.startswith(":") == pseudo
        ]
        if fresh_table:
            retained = [
                policy_key(field["representation"]) for field in slots[kind]["fields"]
            ]
            if retained != [policy_key(field) for field in raw]:
                return False
        elif [field["representation"] for field in slots[kind]["fields"]] != raw:
            return False
    return True


def _compare_fields(inspected, blocks, sections, *, fresh_table, expected_flows):
    """Require one complete original joint for every independently decoded request."""
    if inspected["format_version"] != 1:
        raise ValueError("unsupported inspection format")
    expected_flows = set(FLOW_NAMES if expected_flows is None else expected_flows)
    if not expected_flows or not expected_flows <= FLOW_NAMES:
        raise ValueError("explicit known QPACK flow subset required")
    requests = fields = 0
    covered = set()
    for block in blocks:
        if (
            block.protocol != "h3"
            or block.from_server
            or (flow := flow_name(block.headers)) is None
        ):
            continue
        key = (block.packet, block.connection, block.stream)
        if key not in sections:
            raise ValueError("decoded HTTP request lacks raw QPACK metadata")
        section = sections[key]
        if len(section.fields) != len(block.headers):
            raise ValueError("QPACK/HTTP field count mismatch")
        candidates = request_candidates(inspected, block, flow)
        if not any(
            matching_representations(
                capture, block.headers, section.fields, fresh_table=fresh_table
            )
            for capture in candidates
        ):
            raise ValueError(
                "retained QPACK metadata has no matching request joint "
                f"(connection={block.connection}, stream={block.stream}, flow={flow})"
            )
        requests += 1
        fields += len(section.fields)
        covered.add(flow)
    if covered != expected_flows:
        raise ValueError("incomplete QPACK field flow coverage")
    return {
        "requests_checked": requests,
        "fields_checked": fields,
        "flows": sorted(covered),
    }


def compare_field_metadata(inspected, blocks, sections, *, expected_flows=None):
    """Match actual raw indexes and flags with that connection's retained capture."""
    report = _compare_fields(
        inspected, blocks, sections, fresh_table=False, expected_flows=expected_flows
    )
    return {
        **report,
        "scope": "raw field-line families, indexes, Huffman and never-index flags",
        "limits": "capture accuracy only; fresh-connection compression policy is separate",
    }


def compare_replay_policy(inspected, blocks, sections, *, expected_flows=None):
    """Match original policy after tshark resolves the replay's fresh references.

    The same joint must supply the resolved fields, representation families,
    static indexes and flags. Only validated dynamic-table indexes may differ.
    Literal retained evidence and the replay-capture accuracy check remain exact.
    """
    report = _compare_fields(
        inspected, blocks, sections, fresh_table=True, expected_flows=expected_flows
    )
    return {
        **report,
        "scope": "original joint field policy and independently resolved replay references",
        "exclusions": [
            "QPACK dynamic-table reference indexes (connection-local state)"
        ],
        "limits": "measured field policy; not byte-identical QPACK history or distribution fidelity",
    }
