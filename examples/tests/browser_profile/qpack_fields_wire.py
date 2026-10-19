"""Check retained QPACK field metadata against raw, decrypted HEADERS bytes.

The byte parser is independent of Rama. Tshark supplies decoded HTTP fields;
explicitly blocked heads use independent ls-qpack with native encoder witnesses.
We read field-line prefixes, indexes, Huffman flags and never-index bits ourselves.
Literal contents are discarded. This verifies capture accuracy, not equivalence
between compression states on different connections. Replay policy additionally
compares families, static indexes and flags with one original request joint;
independently resolved fields establish what each fresh-table reference denotes.
"""

from dataclasses import asdict, dataclass

from qpack_decode_wire import resolve_blocked_headers

from capture_fields import connection_user_agents, matching_fields, request_candidates
from flows import FLOW_NAMES, operation_flow
from qpack_bootstrap_wire import bootstrap_request
from qpack_wire import prefixed_integer
from quic_stream_wire import varint_field
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
    packets = pdml_packets(data)
    resolved = resolve_blocked_headers(packets, server_port)
    for packet in packets:
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
            stream = int(one(frame, "http3.frame_streamid"))
            key = (number, connection, stream)
            field_count = (
                len(resolved.headers[key])
                if key in resolved.recovered
                else int(one(frame, "http3.headers.count"))
            )
            if len(fields) != field_count:
                raise ValueError("raw/independent header count mismatch")
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


def _bootstrap_fields(inspected, blocks, sections, connection_joints, *, fresh_table):
    """Check initial HEADERS against its exact native joint's request reference.

    These heads can be internal navigation probes or explicit CLI warmups. They
    do not replace any of the six ordinary operations required below.
    """
    has_bootstrap = any(
        slot["kind"] == "Http3Bootstrap"
        for profile in inspected["profiles"]
        for scope in profile["scopes"]
        for variant in scope["variants"]
        for slot in variant["capture"].get("slots", [])
    )
    if not has_bootstrap:
        return {"bootstrap_requests_checked": 0, "bootstrap_fields_checked": 0}
    if connection_joints is None:
        raise ValueError(
            "Bootstrap field checks require verified native connection joints"
        )
    heads = [
        block
        for block in blocks
        if block.protocol == "h3" and not block.from_server and block.headers
    ]
    agents = {
        connection: agent
        for (_transport, connection), agent in connection_user_agents(heads).items()
    }
    if set(connection_joints) != set(agents):
        raise ValueError("incomplete Bootstrap native connection coverage")
    requests = fields = 0
    for connection, agent in agents.items():
        candidates = [
            (profile, scope, variant["capture"])
            for profile in inspected["profiles"]
            if profile["key"]["user_agent"] == agent
            for scope in profile["scopes"]
            for variant in scope["variants"]
            if variant["capture"].get("level") == "Connection"
            and bytes(variant["id"]).hex() == connection_joints[connection]
        ]
        if len(candidates) != 1:
            raise ValueError("Bootstrap native joint has no unique scoped capture")
        profile, scope, capture = candidates[0]
        bindings = [
            slot["capture"]
            for slot in capture.get("slots", [])
            if slot["kind"] == "Http3Bootstrap"
        ]
        if not bindings:
            continue
        if len(bindings) != 1:
            raise ValueError("duplicate native Bootstrap slot")
        initial, request_capture = bootstrap_request(
            bindings[0],
            profile,
            scope,
            [block for block in heads if block.connection == connection],
        )
        section = sections.get((initial.packet, connection, initial.stream))
        if section is None:
            raise ValueError("Bootstrap request lacks raw QPACK metadata")
        if not matching_representations(
            request_capture, initial.headers, section.fields, fresh_table=fresh_table
        ):
            raise ValueError(
                "Bootstrap raw QPACK metadata differs from referenced request joint"
            )
        requests += 1
        fields += len(section.fields)
    return {"bootstrap_requests_checked": requests, "bootstrap_fields_checked": fields}


def _compare_fields(
    inspected,
    blocks,
    sections,
    *,
    fresh_table,
    expected_flows,
    connection_joints,
    operations=None,
):
    """Require one complete original joint for every independently decoded request."""
    if inspected["format_version"] != 1:
        raise ValueError("unsupported inspection format")
    expected_flows = set(FLOW_NAMES if expected_flows is None else expected_flows)
    if not expected_flows or not expected_flows <= FLOW_NAMES:
        raise ValueError("explicit known QPACK flow subset required")
    bootstrap = _bootstrap_fields(
        inspected, blocks, sections, connection_joints, fresh_table=fresh_table
    )
    requests = fields = 0
    covered = set()
    for block in blocks:
        if (
            block.protocol != "h3"
            or block.from_server
            or (flow := operation_flow(block, operations)) is None
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
        "independent_qpack_requests_checked": sum(
            block.protocol == "h3"
            and not block.from_server
            and block.header_decoder == "ls-qpack"
            for block in blocks
        ),
        "flows": sorted(covered),
        **bootstrap,
    }


def compare_field_metadata(
    inspected,
    blocks,
    sections,
    *,
    expected_flows=None,
    connection_joints=None,
    operations=None,
):
    """Match actual raw indexes and flags with that connection's retained capture."""
    report = _compare_fields(
        inspected,
        blocks,
        sections,
        fresh_table=False,
        expected_flows=expected_flows,
        connection_joints=connection_joints,
        operations=operations,
    )
    return {
        **report,
        "scope": "raw field-line families, indexes, Huffman and never-index flags",
        "limits": "capture accuracy only; fresh-connection compression policy is separate",
    }


def compare_replay_policy(
    inspected,
    blocks,
    sections,
    *,
    expected_flows=None,
    connection_joints=None,
    operations=None,
):
    """Match original policy after tshark resolves the replay's fresh references.

    The same joint must supply the resolved fields, representation families,
    static indexes and flags. Only validated dynamic-table indexes may differ.
    Literal retained evidence and the replay-capture accuracy check remain exact.
    """
    report = _compare_fields(
        inspected,
        blocks,
        sections,
        fresh_table=True,
        expected_flows=expected_flows,
        connection_joints=connection_joints,
        operations=operations,
    )
    return {
        **report,
        "scope": "original joint field policy and independently resolved replay references",
        "exclusions": [
            "QPACK dynamic-table reference indexes (connection-local state)"
        ],
        "limits": "measured field policy; not byte-identical QPACK history or distribution fidelity",
    }
