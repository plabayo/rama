"""Account for separately observed traffic without attributing it to the driver."""

from collections import defaultdict
import hashlib
import json
from urllib.parse import urlsplit

from flows import request_authority, require
from remote.admission import captured_connections, complete_responses, packet_peers
from tls_wire import identity
from wire import pdml_packets, values

MAX_INDEPENDENT_REQUESTS = 16
MAX_INDEPENDENT_BYTES = 1024 * 1024


def connection(block):
    return "udp" if block.protocol == "h3" else "tcp", block.connection


def header_digest(headers):
    encoded = json.dumps(headers, ensure_ascii=True, separators=(",", ":")).encode()
    require(len(encoded) <= 65536, "independent header byte budget")
    return hashlib.sha256(encoded).hexdigest()


def native_request_streams(data, independent_connections):
    """Inventory every non-control H2 stream, including undecoded frames."""
    streams = set()
    for packet in pdml_packets(data):
        if not values(packet, "tcp.stream"):
            continue
        number = identity(packet, "tcp.stream")
        if ("tcp", number) not in independent_connections:
            continue
        for frame in packet.iter("field"):
            if frame.get("name") != "http2.stream":
                continue
            preface = frame.findall("field[@name='http2.magic']")
            if preface:
                require(
                    len(preface) == len(list(frame)) == 1
                    and preface[0].get("size") == "24"
                    and bytes.fromhex(preface[0].get("value", ""))
                    == b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
                    "invalid independent H2 connection preface",
                )
                continue
            stream = identity(frame, "http2.streamid")
            require(0 <= stream < 1 << 31, "invalid independent H2 stream ID")
            if stream:  # Stream zero carries connection controls, not requests.
                streams.add(("h2", number, stream))
    return streams


def partition(data, frames, page, origin, inspected, *, requestless_connections=()):
    """Return an explicit owned projection and complete independent inventory.

    Peers come from packet sockets; subsequent ordinary admission still binds
    every owned operation to its driver/native response. Provider provenance of
    independent traffic remains unknown. Independent inventory currently supports
    H2 only; exhaustive H1 and H3 non-request stream classification is unsupported.
    """
    heads = [block for block in frames if block.headers and not block.from_server]
    agent = page.get("user_agent")
    require(isinstance(agent, str) and agent, "driver User-Agent identity missing")
    agents = {}
    for head in heads:
        values = [value for name, value in head.headers if name.lower() == "user-agent"]
        require(
            len(values) == 1 and values[0] and len(values[0]) <= 4096,
            "unresolved source User-Agent identity",
        )
        agents[id(head)] = values[0]
    independent = [head for head in heads if agents[id(head)] != agent]
    if not independent:
        return tuple(frames), None, frozenset()
    require(len(independent) <= MAX_INDEPENDENT_REQUESTS, "independent request budget")
    require(
        {profile.get("key", {}).get("user_agent") for profile in inspected["profiles"]}
        == {agent},
        "independent traffic has a retained foreign profile",
    )
    require(
        not any(
            name.lower() in {"cookie", "authorization", "proxy-authorization"}
            for head in heads
            for name, _value in head.headers
        ),
        "owned source journey must remain credential-free",
    )
    owned = [head for head in heads if agents[id(head)] == agent]
    require(owned, "owned source requests missing")
    owned_connections = {connection(head) for head in owned}
    independent_connections = {connection(head) for head in independent}
    require(
        not owned_connections & independent_connections,
        "independent request shares an owned native connection",
    )
    port = urlsplit(origin).port
    peers = packet_peers(data, port)
    owned_peers = {peers.get((head.protocol, head.packet)) for head in owned}
    require(None not in owned_peers, "owned packet peer is unresolved")
    grouped = defaultdict(list)
    for block in frames:
        grouped[block.protocol, block.connection, block.stream].append(block)
    independent_rows = [
        block for block in frames if connection(block) in independent_connections
    ]
    # Count every decoded payload before rejecting orphan keys: otherwise the very
    # bytes missing from the inventory could also evade its resource bound. Decoded
    # WebSocket text counts too, even when it duplicates retained DATA bytes.
    total = sum(
        len(block.data)
        + sum(len(text.encode("utf-8")) for text in block.websocket_text)
        for block in independent_rows
    )
    require(total <= MAX_INDEPENDENT_BYTES, "independent body byte budget")
    require(
        all(head.protocol == "h2" for head in independent),
        "independent H1/H3 stream inventory is unsupported",
    )
    request_keys = {
        (head.protocol, head.connection, head.stream) for head in independent
    }
    require(
        len(request_keys) == len(independent), "ambiguous independent request stream"
    )
    require(
        all(
            (block.protocol, block.connection, block.stream) in request_keys
            for block in independent_rows
        ),
        "unattributed independent decoded stream",
    )
    require(
        native_request_streams(data, independent_connections) == request_keys,
        "unattributed independent native or undecoded stream",
    )
    completed = complete_responses(data, port)
    connection_peers, details = {}, []
    for head in independent:
        native = connection(head)
        peer = peers.get((head.protocol, head.packet))
        require(
            peer is not None and peer not in owned_peers,
            "independent peer is unresolved or shared with owned traffic",
        )
        require(
            connection_peers.setdefault(native, peer) == peer,
            "independent native connection has conflicting peers",
        )
        require(
            request_authority(head) == urlsplit(origin).netloc,
            "independent request uses a different origin",
        )
        key = head.protocol, head.connection, head.stream
        rows = grouped[key]
        requests = [block for block in rows if not block.from_server and block.headers]
        responses = [block for block in rows if block.from_server and block.headers]
        require(
            len(requests) == len(responses) == 1 and key in completed,
            "independent response is incomplete or ambiguous",
        )
        request_body = b"".join(block.data for block in rows if not block.from_server)
        response_body = b"".join(block.data for block in rows if block.from_server)
        fields = dict(head.headers)
        details.append(
            dict(
                classification="unattributed_independent",
                provider_provenance="unknown",
                protocol=head.protocol,
                connection=head.connection,
                stream=head.stream,
                packet=head.packet,
                peer_socket=list(peer),
                user_agent=agents[id(head)],
                method=fields[":method"],
                uri=fields[":path"],
                request_headers_sha256=header_digest(head.headers),
                response_headers_sha256=header_digest(responses[0].headers),
                request_bytes=len(request_body),
                response_bytes=len(response_body),
                request_body_sha256=hashlib.sha256(request_body).hexdigest(),
                response_body_sha256=hashlib.sha256(response_body).hexdigest(),
                response_complete=True,
            )
        )
    require(
        captured_connections(data, port)
        == owned_connections | independent_connections | set(requestless_connections),
        "unattributed requestless or undecoded source connection",
    )
    report = dict(
        scope="driver browser projection plus separately reported independent observations",
        source_pdml_sha256=hashlib.sha256(data).hexdigest(),
        owned_requests=len(owned),
        independent_requests=len(independent),
        independent_connections=[
            list(item) for item in sorted(independent_connections)
        ],
        observations=details,
        limits="independent inventory supports H2 only; actors are unknown; their bytes remain in the complete private capture and do not count as browser/profile fidelity evidence",
    )
    return (
        tuple(block for block in frames if connection(block) in owned_connections),
        report,
        frozenset(independent_connections),
    )
