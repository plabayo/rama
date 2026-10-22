"""Verify WebSockets across H2/H3 DATA boundaries, independently of tshark."""

from dataclasses import replace
from wsproto import Connection, ConnectionType
from wsproto.events import TextMessage, CloseConnection
from wsproto.extensions import PerMessageDeflate
from flows import require

MAX_TUNNEL_BYTES = 65536


def decode(data, from_server, extensions):
    require(len(data) <= MAX_TUNNEL_BYTES, "WebSocket tunnel byte budget")
    configured = []
    if extensions:
        require(len(extensions) == 1 and extensions[0].split(';', 1)[0].strip() == 'permessage-deflate',
                "unsupported WebSocket extension")
        extension = PerMessageDeflate()
        extension.finalize(extensions[0])
        configured.append(extension)
    receiver = Connection(ConnectionType.CLIENT if from_server else ConnectionType.SERVER,
                          extensions=configured)
    messages, partial, closed = [], '', False
    for position, value in enumerate(data):
        require(not closed, "bytes follow WebSocket close")
        receiver.receive_data(bytes([value]))
        for event in receiver.events():
            if isinstance(event, TextMessage):
                partial += event.data
                require(len(partial.encode('utf-8')) <= MAX_TUNNEL_BYTES, "WebSocket message byte budget")
                if event.message_finished:
                    messages.append(partial)
                    partial = ''
            elif isinstance(event, CloseConnection):
                require(event.code == 1000 and not partial, "incomplete or invalid WebSocket close")
                require(position == len(data) - 1, "bytes follow WebSocket close")
                closed = True
            else:
                raise ValueError("unexpected WebSocket fixture event")
    require(closed and not partial, "WebSocket tunnel lacks complete close")
    return tuple(messages)


def attach_messages(blocks):
    result = list(blocks)
    streams = {(b.connection, b.stream) for b in blocks
               if not b.from_server and dict(b.headers).get(':protocol') == 'websocket'}
    for connection, stream in streams:
        selected = [(i, b) for i, b in enumerate(blocks)
                    if (b.connection, b.stream) == (connection, stream)]
        replies = [b for _, b in selected if b.from_server and b.headers]
        require(len(replies) == 1 and dict(replies[0].headers).get(':status') == '200',
                "WebSocket tunnel response is not successful")
        extensions = [v for k, v in replies[0].headers if k == 'sec-websocket-extensions']
        for side in (False, True):
            frames = [(i, b) for i, b in selected if b.from_server == side and b.data]
            require(frames, "WebSocket tunnel direction has no DATA")
            messages = decode(b''.join(b.data for _, b in frames), side, extensions)
            for i, b in frames:
                result[i] = replace(b, websocket_text=())
            i, b = frames[-1]
            result[i] = replace(b, websocket_text=messages)
    return result


def h1_messages(packets, server_port, upgrades):
    from pdml import one, values, fields
    result = {}
    for packet in packets:
        # H2 Extended CONNECT payload is decoded from DATA by attach_messages;
        # only bare H1 tunnel bytes require an HTTP/1 Upgrade association here.
        if fields(packet, "rama_ws_tunnel.data") and not fields(packet, "http2.data.data"):
            require(int(one(packet, "tcp.stream")) in upgrades,
                    "WebSocket tunnel payload has no Upgrade request")
    for connection, request_packet in upgrades.items():
        selected = [p for p in packets if values(p, "tcp.stream") == [str(connection)]]
        replies = [p for p in selected if values(p, "http.response.code") == ["101"]]
        require(len(replies) == 1, "WebSocket requires one Upgrade response")
        extensions = []
        for line in values(replies[0], "http.response.line"):
            name, separator, value = line.partition(":")
            if separator and name.lower() == "sec-websocket-extensions":
                extensions.append(value.strip().replace("\\r\\n", ""))
        for side in (False, True):
            chunks = []
            for packet in selected:
                payloads = fields(packet, "rama_ws_tunnel.data")
                if not payloads:
                    continue
                source = int(one(packet, "tcp.srcport"))
                destination = int(one(packet, "tcp.dstport"))
                require((source == server_port) != (destination == server_port), "ambiguous WebSocket endpoint")
                require(int(one(packet, "frame.number")) > request_packet, "WebSocket precedes Upgrade")
                if (source == server_port) != side:
                    continue
                for field in payloads:
                    data = bytes.fromhex(field.get("value", ""))
                    require(len(data) == int(field.get("size", "-1")), "WebSocket tunnel byte extent")
                    chunks.append(data)
            result[connection, side] = decode(b"".join(chunks), side, extensions)
    return result
