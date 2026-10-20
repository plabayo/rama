"""Recount cumulative initial H2 connection credit from independent PDML legs.

The boundary is the first decoded complete request/response HEADERS block per
sender. The surrounding functional checks supply acceptance evidence; this is
not an HPACK validator or a frame-timing transparency claim.
"""

from flows import require
from wire import one, pdml_packets

INITIAL_WINDOW = 65535
MAX_WINDOW = (1 << 31) - 1
MAX_FRAMES = 100000
PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


def _field(node, name):
    require(node is not None, "missing initial-credit native container")
    fields = [field for field in node if field.get("name") == name]
    require(len(fields) == 1, "ambiguous or missing initial-credit " + name)
    return fields[0]


def _raw(field, size):
    # Masked fields may have a shortened `value`; unmaskedvalue retains all
    # original octets, including the reserved high bit.
    value = field.get("unmaskedvalue", field.get("value"))
    require(isinstance(value, str), "missing initial-credit literal bytes")
    try:
        data = bytes.fromhex(value)
    except ValueError as error:
        raise ValueError("invalid initial-credit literal bytes") from error
    require(
        field.get("size") == str(size) and len(data) == size,
        "initial-credit literal byte length differs",
    )
    return data


def _number(node, name, size, position=None):
    field = _field(node, name)
    if position is not None:
        require(
            field.get("pos") == str(position), "initial-credit field extent differs"
        )
    return int.from_bytes(_raw(field, size), "big")


def _endpoint(packet, port):
    source = _number(packet.find("proto[@name='tcp']"), "tcp.srcport", 2)
    destination = _number(packet.find("proto[@name='tcp']"), "tcp.dstport", 2)
    require((source == port) != (destination == port), "ambiguous H2 credit endpoint")
    endpoints = (source, destination)
    return ("server", endpoints[::-1]) if source == port else ("client", endpoints)


def _header(frame):
    try:
        position = int(frame.get("pos", ""))
        size = int(frame.get("size", ""))
    except ValueError as error:
        raise ValueError("invalid initial-credit frame extent") from error
    require(position >= 0, "invalid initial-credit frame position")
    length = _number(frame, "http2.length", 3, position)
    kind = _number(frame, "http2.type", 1, position + 3)
    flags = _number(frame, "http2.flags", 1, position + 4)
    stream = _number(frame, "http2.streamid", 4, position + 5) & MAX_WINDOW
    require(size == length + 9, "incomplete initial-credit H2 frame")
    return position, length, kind, flags, stream


def _fragment(frame, position, length, kind, flags):
    offset, padding = 9, 0
    if kind == 1 and flags & 8:
        padding = _number(frame, "http2.padding", 1, position + offset)
        offset += 1
    if kind == 1 and flags & 32:
        _number(frame, "http2.stream_dependency", 4, position + offset)
        _number(frame, "http2.headers.weight", 1, position + offset + 4)
        offset += 5
    count = length - (offset - 9) - padding
    require(count >= 0, "invalid initial-credit HEADERS padding")
    name = "http2.headers" if kind == 1 else "http2.continuation.header"
    fragment = _field(frame, name)
    require(fragment.get("pos") == str(position + offset), "HEADERS fragment extent")
    _raw(fragment, count)
    if padding:
        pad = _field(frame, "http2.headers.padding")
        require(
            pad.get("pos") == str(position + offset + count),
            "HEADERS padding extent",
        )
        _raw(pad, padding)


def initial_credit(data, server_port):
    """Require one complete TCP leg and recount each sender's initial target."""
    packets = pdml_packets(data)
    roles = {
        role: dict(
            target=INITIAL_WINDOW,
            updates=0,
            pending=None,
            boundary=None,
            data=False,
            started=False,
        )
        for role in ("client", "server")
    }
    connection, endpoints, previous_packet, count = None, None, -1, 0
    preface = False
    for packet in packets:
        frames = [
            field
            for field in packet.iter("field")
            if field.get("name") == "http2.stream"
        ]
        if not frames:
            continue
        identity = one(packet, "tcp.stream")
        require(identity.isdecimal(), "invalid H2 credit TCP connection")
        identity = int(identity)
        role, pair = _endpoint(packet, server_port)
        if connection is None:
            connection, endpoints = identity, pair
        require(
            identity == connection and pair == endpoints, "mixed H2 credit connections"
        )
        number = one(packet, "frame.number")
        require(number.isdecimal(), "invalid H2 credit packet identity")
        number = int(number)
        require(number > previous_packet, "unordered or duplicate H2 credit packets")
        previous_packet = number
        state = roles[role]
        for frame in frames:
            count += 1
            require(count <= MAX_FRAMES, "initial-credit frame limit")
            magic = [field for field in frame if field.get("name") == "http2.magic"]
            if magic:
                require(
                    role == "client"
                    and not preface
                    and not state["started"]
                    and len(frame) == 1
                    and len(magic) == 1
                    and frame.get("size") == "24"
                    and frame.get("pos") == magic[0].get("pos")
                    and _raw(magic[0], 24) == PREFACE,
                    "invalid or duplicate H2 credit preface",
                )
                preface = True
                continue
            position, length, kind, flags, stream = _header(frame)
            require(role != "client" or preface, "missing H2 credit client preface")
            if not state["started"]:
                require(
                    kind == 4 and stream == 0 and not flags & 1 and length % 6 == 0,
                    "missing initial H2 credit SETTINGS",
                )
                state["started"] = True
            if kind == 0:
                require(stream != 0, "DATA has connection stream ID")
                require(state["boundary"] is not None, "DATA precedes sender HEADERS")
                if length:
                    other = roles["client" if role == "server" else "server"]
                    if other["boundary"] is None:
                        other["data"] = True
            if state["boundary"] is not None:
                continue  # Later growth is not initial credit.
            pending = state["pending"]
            require(
                pending is None or (kind == 9 and stream == pending["stream"]),
                "interleaved or swapped initial HEADERS continuation",
            )
            if kind == 8:
                require(length == 4, "invalid initial WINDOW_UPDATE length")
                increment = (
                    _number(
                        frame,
                        "http2.window_update.window_size_increment",
                        4,
                        position + 9,
                    )
                    & MAX_WINDOW
                )
                require(increment != 0, "zero initial WINDOW_UPDATE increment")
                if stream == 0:
                    require(
                        not state["data"], "connection credit after opposite-role DATA"
                    )
                    target = state["target"] + increment
                    require(target <= MAX_WINDOW, "initial connection credit overflow")
                    state["target"], state["updates"] = target, state["updates"] + 1
            elif kind in (1, 9):
                require(stream != 0, "HEADERS has connection stream ID")
                require(kind == 1 or pending is not None, "orphan initial CONTINUATION")
                _fragment(frame, position, length, kind, flags)
                if pending is None:
                    pending = dict(
                        stream=stream,
                        first_packet=number,
                        continuations=0,
                        witnesses=[],
                    )
                    state["pending"] = pending
                else:
                    pending["continuations"] += 1
                fields = tuple(
                    (one(node, "http2.header.name"), one(node, "http2.header.value"))
                    for node in frame.iter("field")
                    if node.get("name") == "http2.header"
                )
                if fields:
                    pending["witnesses"].append(fields)
                if flags & 4:
                    witnesses = pending.pop("witnesses")
                    require(
                        len(witnesses) == 1,
                        "missing or ambiguous decoded first HEADERS",
                    )
                    headers = witnesses[0]
                    key = ":status" if role == "server" else ":method"
                    values = [value for name, value in headers if name == key]
                    require(
                        len(values) == 1 and values[0],
                        "first HEADERS sender role differs",
                    )
                    require(
                        not any(
                            name == (":method" if role == "server" else ":status")
                            for name, _ in headers
                        ),
                        "first HEADERS mixes request and response",
                    )
                    state["boundary"] = dict(**pending, last_packet=number)
                    state["pending"] = None
            else:
                require(kind not in (3, 7), "source terminated before first HEADERS")
    require(connection is not None and preface, "missing H2 credit connection/preface")
    require(
        all(state["boundary"] is not None for state in roles.values()),
        "incomplete H2 credit source roles",
    )
    return dict(
        tcp_connection=connection,
        client_preface=True,
        endpoints=dict(client_port=endpoints[0], server_port=endpoints[1]),
        roles={
            role: dict(
                target=state["target"],
                window_updates=state["updates"],
                boundary=state["boundary"],
            )
            for role, state in roles.items()
        },
    )


def compare_initial_credit(ingress, egress, ingress_port, egress_port):
    """Compare the client's cumulative target, retaining both roles for review.

    Only the client's initial connection credit is mirrored; the server role on
    each hop is that hop's own flow control and is reported, not compared.
    """
    legs = dict(
        ingress=initial_credit(ingress, ingress_port),
        egress=initial_credit(egress, egress_port),
    )
    matches = all(
        legs["ingress"]["roles"][role]["target"]
        == legs["egress"]["roles"][role]["target"]
        for role in ("client",)
    )
    return dict(h2_initial_credit=legs, h2_initial_credit_match=matches)
