"""Verify retained QUIC first-flight facts using independent tshark decoding.

Tshark removes Initial protection and reassembles ClientHello. Raw varints and
frame extents supply layout facts; no QUIC crypto implementation lives here.
Transport-parameter bodies stay transient: compare retained literals exactly and
redacted bindings by length, without returning connection identifiers in reports.
"""

from collections import defaultdict
from dataclasses import dataclass, field as data_field

from capture_fields import connection_user_agents
from connection_fields import field, integer
from tls_wire import Reader, byte_span, identity
from wire import one, pdml_packets

VERSION_1 = 1
VERSION_2 = 0x6B3343CF
INITIAL_PACKET_TYPES = {VERSION_1: 0, VERSION_2: 1}
QUIC_PADDING = 0
QUIC_PING = 1
QUIC_ACK = 2
QUIC_ACK_ECN = 3
QUIC_CRYPTO = 6
QUIC_CONNECTION_CLOSE = 28
QUIC_APPLICATION_CLOSE = 29
H3_SETTINGS = 4
UDP_HEADER_LEN = 8
INITIAL_AEAD_TAG_LEN = 16
TRANSPORT_PARAMETERS = 57
VERSION_INFORMATION = 17
MAX_DATAGRAMS = 32
MAX_PACKETS = 64
MAX_FRAMES = 256


@dataclass(frozen=True)
class QuicFlight:
    connection: int
    flight: dict
    parameters: tuple[tuple[int, bytes], ...] = data_field(repr=False)


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


def parameters(extension):
    raw = Reader(byte_span(extension))
    if raw.integer(2) != TRANSPORT_PARAMETERS:
        raise ValueError("expected QUIC transport parameters")
    body = Reader(raw.vector(2))
    raw.finish()
    result, seen = [], set()
    while body.remaining():
        identifier, length = varint(body), varint(body)
        if identifier in seen or len(result) >= 256:
            raise ValueError("duplicate or excessive QUIC transport parameters")
        seen.add(identifier)
        result.append((identifier, body.take(length)))
    return tuple(result)


def initial_frames(proto):
    """Keep complete frame shapes; encrypted packet-number bytes are not plaintext."""
    frames, payload_size = [], 0
    for node in proto.findall("field[@name='quic.frame']"):
        kind, width = varint_field(node, "quic.frame_type")
        size = int(node.get("size", "-1"))
        if size < width:
            raise ValueError("incomplete QUIC frame extent")
        if kind == QUIC_PADDING:
            length = identity(node, "quic.padding_length")
            if length != size or length < 1:
                raise ValueError("QUIC padding extent mismatch")
            observed = {"Padding": {"len": length}}
        elif kind == QUIC_PING:
            if size != width:
                raise ValueError("QUIC PING extent mismatch")
            observed = "Ping"
        elif kind in (QUIC_ACK, QUIC_ACK_ECN):
            observed = "Ack"
        elif kind == QUIC_CRYPTO:
            offset, offset_width = varint_field(node, "quic.crypto.offset")
            length, length_width = varint_field(node, "quic.crypto.length")
            if size != width + offset_width + length_width + length:
                raise ValueError("QUIC CRYPTO extent mismatch")
            observed = {"Crypto": {"offset": offset, "len": length}}
        elif kind in (QUIC_CONNECTION_CLOSE, QUIC_APPLICATION_CLOSE):
            observed = {"Other": {"ty": kind}}
        else:
            raise ValueError("unmodeled Initial frame type")
        frames.append(observed)
        payload_size += size
        if len(frames) > MAX_FRAMES:
            raise ValueError("QUIC Initial frame limit")
    if not frames:
        raise ValueError("missing decrypted Initial frames")
    length, _ = varint_field(proto, "quic.length")
    # Length includes the protected packet number and AEAD's 16-byte tag. The
    # remaining sizes come from authenticated, completely decoded frame extents.
    number_width = length - payload_size - INITIAL_AEAD_TAG_LEN
    number = field(proto, "quic.packet_number")
    if not 1 <= number_width <= 4 or int(number.get("size", "-1")) != number_width:
        raise ValueError("incomplete QUIC packet-number extent")
    packet_number = int(number.get("show", "-1"))
    if not 0 <= packet_number < (1 << 62):
        raise ValueError("invalid decrypted QUIC packet number")
    return frames, packet_number, number_width


def _client_hello_boundaries(packets, server_port):
    """Find each complete ClientHello and its transient parameter bodies."""
    boundaries, parameter_lists = {}, {}
    for packet in packets:
        if not packet.findall("proto[@name='quic']"):
            continue
        if int(one(packet, "udp.dstport")) != server_port:
            continue
        for hello in packet.iter("field"):
            if hello.get("name") != "tls.handshake":
                continue
            kind = hello.find("field[@name='tls.handshake.type']")
            if kind is None or kind.get("show") != "1":
                continue
            connection = identity(packet, "quic.connection.number")
            if connection in boundaries:
                raise ValueError("multiple ClientHellos in one QUIC connection")
            extensions = [
                node
                for node in hello.iter("field")
                if any(
                    child.get("name") == "tls.handshake.extension.type"
                    and child.get("show") == str(TRANSPORT_PARAMETERS)
                    for child in node
                )
            ]
            if len(extensions) != 1:
                raise ValueError("missing or ambiguous QUIC transport parameters")
            boundaries[connection] = identity(packet, "frame.number")
            parameter_lists[connection] = parameters(extensions[0])

    return boundaries, parameter_lists


def first_flights(data, server_port):
    """Include every client datagram through the complete first ClientHello."""
    packets = pdml_packets(data)
    boundaries, parameter_lists = _client_hello_boundaries(packets, server_port)
    flights, seen_numbers = {}, defaultdict(set)
    for packet in packets:
        protos = packet.findall("proto[@name='quic']")
        if not protos or int(one(packet, "udp.dstport")) != server_port:
            continue
        connection = identity(packet, "quic.connection.number")
        if (
            connection not in boundaries
            or identity(packet, "frame.number") > boundaries[connection]
        ):
            continue
        datagram_size = integer(packet, "udp.length", 2) - UDP_HEADER_LEN
        packet_sizes = [identity(proto, "quic.packet_length") for proto in protos]
        trailing = datagram_size - sum(packet_sizes)
        if not 1200 <= datagram_size <= 65527 or not 0 <= trailing <= datagram_size:
            raise ValueError("invalid Initial datagram extent")
        for proto, packet_size in zip(protos, packet_sizes):
            version = integer(proto, "quic.version", 4)
            packet_type = int(one(proto, "quic.long.packet_type"))
            initial_type = INITIAL_PACKET_TYPES.get(version)
            if initial_type is None:
                raise ValueError("unsupported QUIC wire version")
            if packet_type != initial_type:
                if connection not in flights:
                    raise ValueError("first QUIC packet is not Initial")
                flights[connection]["coalesced"] = True
                continue
            frames, number, width = initial_frames(proto)
            length, length_width = varint_field(proto, "quic.length")
            length_position = int(field(proto, "quic.length").get("pos"))
            if (
                packet_size
                != length_position - int(proto.get("pos")) + length_width + length
            ):
                raise ValueError("QUIC packet extent mismatch")
            if connection not in flights:
                token_length, _ = varint_field(proto, "quic.token_length")
                flights[connection] = dict(
                    datagram_sizes=[],
                    trailing_bytes=[],
                    version=version,
                    dcid_len=integer(proto, "quic.dcil", 1),
                    scid_len=integer(proto, "quic.scil", 1),
                    token_len=token_length,
                    first_packet_number=number,
                    packet_number_len=width,
                    frames=[],
                    padding="Frames",
                    coalesced=False,
                    parameters=[
                        identifier for identifier, _ in parameter_lists[connection]
                    ],
                    chosen_version=None,
                    available_versions=[],
                    packet_numbers=[],
                    complete=True,
                )
            flight = flights[connection]
            flight["packet_numbers"].append(number)
            if number not in seen_numbers[connection]:
                flight["frames"].append(frames)
                seen_numbers[connection].add(number)
            if (
                len(flight["packet_numbers"]) > MAX_PACKETS
                or sum(map(len, flight["frames"])) > MAX_FRAMES
            ):
                raise ValueError("QUIC first-flight packet/frame limit")
        flight = flights[connection]
        flight["datagram_sizes"].append(datagram_size)
        flight["trailing_bytes"].append(trailing)
        if trailing:
            flight["padding"] = "DatagramTail"
        if len(flight["datagram_sizes"]) > MAX_DATAGRAMS:
            raise ValueError("QUIC first-flight datagram limit")

    result = []
    for connection, flight in flights.items():
        for identifier, body in parameter_lists[connection]:
            if identifier == VERSION_INFORMATION:
                if len(body) < 4 or len(body) % 4:
                    raise ValueError("invalid QUIC version information")
                versions = [
                    int.from_bytes(body[start : start + 4], "big")
                    for start in range(0, len(body), 4)
                ]
                flight["chosen_version"], flight["available_versions"] = (
                    versions[0],
                    versions[1:],
                )
        result.append(QuicFlight(connection, flight, parameter_lists[connection]))
    if not result:
        raise ValueError("no complete QUIC first flight")
    return result


def parameters_match(captured, observed):
    if (
        captured.get("completeness") != "Complete"
        or captured.get("namespace") != "QuicParameter"
    ):
        return False
    fields = captured["fields"]
    if len(fields) != len(observed):
        return False
    for retained, (identifier, body) in zip(fields, observed):
        if retained["id"] != identifier:
            return False
        value = retained["value"]
        if set(value) == {"Literal"}:
            if bytes(value["Literal"]) != body:
                return False
        elif set(value) == {"ConnectionLength"}:
            if value["ConnectionLength"] != len(body):
                return False
        else:
            raise ValueError("unknown retained QUIC parameter binding")
    return True


def client_settings(data, server_port, *, from_server=False):
    """Read one endpoint's ordered SETTINGS from decrypted frame payloads."""
    result = {}
    for packet in pdml_packets(data):
        frames = [
            node for node in packet.iter("field") if node.get("name") == "http3.frame"
        ]
        if not frames:
            continue
        source, destination = int(one(packet, "udp.srcport")), int(
            one(packet, "udp.dstport")
        )
        if (source == server_port) == (destination == server_port):
            raise ValueError("ambiguous HTTP/3 fixture endpoint")
        if (source == server_port) != from_server:
            continue
        connection = identity(packet, "quic.connection.number")
        for frame in frames:
            kind, type_width = varint_field(frame, "http3.frame_type")
            if kind != H3_SETTINGS:
                continue
            length, length_width = varint_field(frame, "http3.frame_length")
            body = Reader(byte_span(field(frame, "http3.frame_payload")))
            if (
                length != body.remaining()
                or int(frame.get("size", "-1")) != type_width + length_width + length
            ):
                raise ValueError("HTTP/3 SETTINGS extent mismatch")
            if connection in result:
                raise ValueError("multiple HTTP/3 SETTINGS frames")
            settings, seen = [], set()
            while body.remaining():
                identifier, value = varint(body), varint(body)
                if identifier in seen or len(settings) >= 256:
                    raise ValueError("duplicate or excessive HTTP/3 SETTINGS")
                seen.add(identifier)
                settings.append(
                    dict(
                        id=identifier, value={"Literal": list(value.to_bytes(8, "big"))}
                    )
                )
            result[connection] = dict(
                completeness="Complete", namespace="Http3Setting", fields=settings
            )
    return result


def compare_quic_captures(archive, observed, hellos, settings, requests, sequences):
    """Correlate four complete slots and wire-backed sequence prefix contents."""
    if archive.get("format_version") != 1:
        raise ValueError("unsupported inspection format")
    agents = connection_user_agents(requests)
    tls = defaultdict(list)
    flights = defaultdict(list)
    for hello in hellos:
        tls[hello.connection].append(hello.capture)
    for flight in observed:
        flights[flight.connection].append(flight)
    candidates = []
    for profile in archive["profiles"]:
        if profile["key"]["user_agent"] not in agents.values():
            continue
        for scope in profile["scopes"]:
            for variant in scope["variants"]:
                if variant["capture"].get("level") != "Connection":
                    continue
                slots = {
                    slot["kind"]: slot["capture"]
                    for slot in variant["capture"]["slots"]
                }
                if set(slots) != {
                    "QuicTls",
                    "QuicParameters",
                    "QuicFirstFlight",
                    "Http3Settings",
                    "Http3Sequence",
                }:
                    raise ValueError("unverified QUIC connection slots")
                candidates.append((profile["key"]["user_agent"], slots))
    checked = set()
    for connection, agent in agents.items():
        if (
            len(tls[connection]) != 1
            or len(flights[connection]) != 1
            or connection not in settings
            or connection not in sequences
        ):
            raise ValueError("missing or ambiguous QUIC connection evidence")
        flight = flights[connection][0]
        matches = [
            index
            for index, (identity, slots) in enumerate(candidates)
            if identity == agent
            and slots["QuicTls"] == tls[connection][0]
            and slots["QuicFirstFlight"]
            == {"completeness": "Complete", "flight": flight.flight}
            and parameters_match(slots["QuicParameters"], flight.parameters)
            and slots["Http3Settings"] == settings[connection]
            and sequences[connection].matches(slots["Http3Sequence"])
        ]
        if not matches:
            raise ValueError(
                "QUIC TLS/parameters/first flight have no matching retained joint"
            )
        if len(matches) != 1:
            raise ValueError("ambiguous retained QUIC joint projection")
        checked.update(matches)
    if len(checked) != len(candidates):
        raise ValueError("retained QUIC joint has no wire observation")
    return dict(
        connections_checked=len(agents),
        retained_joints_checked=len(checked),
        verified_slots=[
            "QuicTls",
            "QuicParameters",
            "QuicFirstFlight",
            "Http3Settings",
        ],
        partially_verified_slots={
            "Http3Sequence": "local decoder context, stream identities/types, control and QPACK encoder prefix contents"
        },
        unverified_slots=["Http3Sequence"],
        sequence_limits="first-request freeze and cross-stream event order remain unverified",
    )
