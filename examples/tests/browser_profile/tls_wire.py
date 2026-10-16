"""Independent TLS capture projection from tshark PDML.

Tshark owns TCP/QUIC reassembly. This module reads its byte spans and projects
only profile-retained fields; cryptographic material is never returned.
This checks retained TLS metadata; other connection slots have separate checks.
"""

from dataclasses import dataclass
from capture_fields import connection_user_agents
from wire import MAX_PDML_BYTES, MAX_PACKETS, pdml_packets

TRUST_ANCHORS_EXTENSION = 51764


# Match the capture policy in rama_tls::client::client_hello_extension_is_connection_bound.
# These bodies contain per-connection identities, certificates or secrets.
CONNECTION_BOUND = {
    2,  # client_certificate_url
    3,  # trusted_ca_keys
    5,  # status_request
    6,  # user_mapping
    7,  # client_authz
    8,  # server_authz
    12,  # srp
    17,  # status_request_v2
    25,  # cached_info
    29,  # pwd_protect
    30,  # pwd_clear
    31,  # password_salt
    32,  # ticket_pinning
    33,  # tls_cert_with_extern_psk
    35,  # session_ticket
    36,  # tlmsp
    37,  # tlmsp_proxying
    38,  # tlmsp_delegate
    40,  # historical reserved extension
    44,  # cookie
    47,  # certificate_authorities
    48,  # oid_filters
    53,  # connection_id_deprecated
    54,  # connection_id
    55,  # external_id_hash
    56,  # external_session_id
    57,  # quic_transport_parameters
    59,  # dnssec_chain
    TRUST_ANCHORS_EXTENSION,  # trust_anchors
    65281,  # renegotiation_info
    0xFFCE,  # historical encrypted_server_name
    0xFFA5,  # historical QUIC transport parameters
    *range(0xFE08, 0xFE0D),  # historical ECH drafts
}


@dataclass(frozen=True)
class TlsHello:
    packet: int
    connection: int
    capture: dict


def identity(node, name):
    values = {
        field.get("show") for field in node.iter("field") if field.get("name") == name
    }
    if len(values) != 1 or None in values:
        raise ValueError("ambiguous or missing " + name)
    return int(values.pop())


class Reader:
    def __init__(self, data):
        self.data = memoryview(data)
        self.offset = 0

    def take(self, size):
        end = self.offset + size
        if size < 0 or end > len(self.data):
            raise ValueError("truncated TLS vector")
        result = bytes(self.data[self.offset : end])
        self.offset = end
        return result

    def integer(self, width):
        return int.from_bytes(self.take(width), "big")

    def vector(self, width):
        return self.take(self.integer(width))

    def remaining(self):
        return len(self.data) - self.offset

    def finish(self):
        if self.remaining():
            raise ValueError("trailing TLS vector bytes")


def byte_span(node):
    """Require complete, mutually consistent raw-byte coverage from tshark."""
    start, size = int(node.get("pos")), int(node.get("size"))
    if not 0 <= size <= 65539:
        raise ValueError("TLS extension byte limit")
    values = [None] * size
    for field in node.iter("field"):
        value = field.get("value")
        if value is None:
            continue
        raw = bytes.fromhex(value)
        position, length = int(field.get("pos")), int(field.get("size"))
        # Generated dissector fields need not describe a physical byte span.
        if len(raw) != length or position < start or position + length > start + size:
            continue
        for index, byte in enumerate(raw, position - start):
            if values[index] is not None and values[index] != byte:
                raise ValueError("conflicting tshark raw byte spans")
            values[index] = byte
    if None in values:
        raise ValueError("incomplete tshark raw byte spans")
    return bytes(values)


def integers(data, width):
    source = Reader(data)
    result = []
    while source.remaining():
        result.append(source.integer(width))
    return result


def extension_value(identifier, data):
    """Decode the retained shape without retaining destination or session bytes."""
    source = Reader(data)
    if identifier == 0:
        names = Reader(source.vector(2))
        present = False
        while names.remaining():
            kind, name = names.integer(1), names.vector(2)
            if kind != 0 or not name or present:
                raise ValueError("invalid server name list")
            present = True
        value = {"ServerName": {"present": present}}
    elif identifier in (10, 13, 34, 50):
        value = {"U16List": integers(source.vector(2), 2)}
    elif identifier in (27, 43):
        value = {"U16List": integers(source.vector(1), 2)}
    elif identifier in (11, 45):
        value = {"U8List": list(source.vector(1))}
    elif identifier == 28:
        value = {"U16List": [source.integer(2)]}
    elif identifier in (16, 17513, 17613):
        protocols = Reader(source.vector(2))
        items = []
        while protocols.remaining():
            protocol = protocols.vector(1)
            if not protocol:
                raise ValueError("empty application protocol")
            items.append(list(protocol))
        value = {"Protocols": items}
    elif identifier == 51:
        shares = Reader(source.vector(2))
        items = []
        while shares.remaining():
            group, key = shares.integer(2), shares.vector(2)
            items.append({"group": group, "length": len(key)})
        value = {"KeyShares": items}
    elif identifier == 41:
        identities = Reader(source.vector(2))
        lengths = []
        while identities.remaining():
            lengths.append(len(identities.vector(2)))
            identities.take(4)  # obfuscated ticket age is connection-owned.
        binders = Reader(source.vector(2))
        binder_lengths = []
        while binders.remaining():
            binder_lengths.append(len(binders.vector(1)))
        value = {"PreSharedKeys": {"identities": lengths, "binders": binder_lengths}}
    elif identifier == 65037:
        kind = source.integer(1)
        if kind == 1:
            value = "EchInner"
        elif kind == 0:
            kdf, aead = source.integer(2), source.integer(2)
            source.take(1)  # Fresh config ID is not a profile literal.
            enc, payload = source.vector(2), source.vector(2)
            value = {
                "EchOuter": {
                    "kdf": kdf,
                    "aead": aead,
                    "enc": len(enc),
                    "payload": len(payload),
                }
            }
        else:
            raise ValueError("invalid ECH ClientHello type")
    elif identifier == 21:
        if any(source.take(source.remaining())):
            raise ValueError("nonzero TLS padding")
        value = {"ConnectionLength": 0}
    elif identifier in CONNECTION_BOUND:
        value = {"ConnectionLength": len(source.take(source.remaining()))}
    else:
        value = {"Literal": list(source.take(source.remaining()))}
    source.finish()
    return value


def decode_client_hello(data, transport):
    """Project one fully reassembled TLS handshake; validate all vector boundaries."""
    message = Reader(data)
    if message.integer(1) != 1:
        raise ValueError("expected ClientHello")
    body = Reader(message.vector(3))
    message.finish()
    version = body.integer(2)
    body.take(32)  # Random is generated anew, never a profile field.
    body.vector(1)  # Session ID is connection-owned.
    ciphers = integers(body.vector(2), 2)
    compression = list(body.vector(1))
    extensions = Reader(body.vector(2))
    body.finish()
    if not ciphers or not compression:
        raise ValueError("empty ClientHello negotiation list")
    seen = set()
    values = []
    while extensions.remaining():
        identifier, payload = extensions.integer(2), extensions.vector(2)
        if identifier in seen:
            raise ValueError("duplicate ClientHello extension")
        seen.add(identifier)
        if identifier == 41 and extensions.remaining():
            raise ValueError("PSK must be the last ClientHello extension")
        values.append({"id": identifier, "value": extension_value(identifier, payload)})
    return dict(
        completeness="Complete",
        transport=transport,
        protocol_version=version,
        ciphers=ciphers,
        compression=compression,
        extensions=values,
    )


def client_hellos(data, transport):
    if transport not in ("Tcp", "Quic"):
        raise ValueError("unknown TLS transport")
    packets = pdml_packets(data, byte_limit=MAX_PDML_BYTES, packet_limit=MAX_PACKETS)
    results = []
    for packet in packets:
        for node in packet.iter("field"):
            if node.get("name") != "tls.handshake":
                continue
            kind = node.find("field[@name='tls.handshake.type']")
            if kind is None or kind.get("show") != "1":
                continue  # Fragment-only dissector nodes are not complete hellos.
            capture = decode_client_hello(byte_span(node), transport)
            results.append(
                TlsHello(
                    packet=identity(packet, "frame.number"),
                    connection=identity(
                        packet,
                        (
                            "tcp.stream"
                            if transport == "Tcp"
                            else "quic.connection.number"
                        ),
                    ),
                    capture=capture,
                )
            )
    if not results:
        raise ValueError("no complete ClientHello")
    return results


def compare_tls_captures(archive, hellos, requests):
    """Match complete TLS observations for each request-bearing browser connection.

    This verifies TLS alone. Other slots in the same connection tuple need their
    own wire comparisons before claiming complete connection fidelity.
    """
    if archive.get("format_version") != 1:
        raise ValueError("unsupported inspection format")
    user_agents = connection_user_agents(requests)

    checked = set()
    matched = []
    ignored = 0
    for hello in hellos:
        if hello.connection not in user_agents:
            ignored += 1  # Browser preconnections need not produce a request.
            continue
        candidates = [
            slot["capture"]
            for profile in archive["profiles"]
            if profile["key"]["user_agent"] == user_agents[hello.connection]
            for scope in profile["scopes"]
            for variant in scope["variants"]
            for slot in variant["capture"].get("slots", [])
            if slot["kind"] in ("TcpTls", "QuicTls")
        ]
        if hello.capture not in candidates:
            raise ValueError("no matching TLS capture for request connection")
        agent = user_agents[hello.connection]
        matched.append((agent, hello.capture))
        checked.add(hello.connection)
    if checked != set(user_agents):
        raise ValueError("incomplete request-bearing TLS connection coverage")

    # Exported observations must also have independent wire evidence. Checking
    # only wire-to-profile membership could conceal extra fabricated variants.
    # Keep the User-Agent and the capture's transport in both directions: one
    # browser connection cannot establish another browser's retained variant.
    agents = set(user_agents.values())
    retained = [
        (profile["key"]["user_agent"], slot["capture"])
        for profile in archive["profiles"]
        if profile["key"]["user_agent"] in agents
        for scope in profile["scopes"]
        for variant in scope["variants"]
        for slot in variant["capture"].get("slots", [])
        if slot["kind"] in ("TcpTls", "QuicTls")
    ]
    if any(capture not in matched for capture in retained):
        raise ValueError("retained TLS capture lacks request-bearing wire evidence")
    return dict(
        connections_checked=len(checked),
        retained_observations=len(retained),
        non_request_hellos=ignored,
        scope="retained TLS fields and shapes",
    )
