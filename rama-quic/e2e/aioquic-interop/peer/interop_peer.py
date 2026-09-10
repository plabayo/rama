"""The aioquic side of the interoperability tests.

One process per role, driven from the Rust test over a line protocol on stdout: one JSON
object per line, flushed as it happens. Every payload is reported by length and SHA-256, so
the Rust side checks bytes rather than the peer's own account of them. Anything unexpected is
reported as a `failed` line and leaves a non-zero exit status.
"""

import argparse
import asyncio
import hashlib
import ipaddress
import json
import socket
import sys
import threading

from aioquic.asyncio import connect, serve
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic import tls as quic_tls
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import (
    ConnectionTerminated,
    DatagramFrameReceived,
    HandshakeCompleted,
)

# What a stream may carry. A peer that sends more is a fault, not a larger test.
STREAM_LIMIT = 1 << 20
# PATH_RESPONSE, RFC 9000 §19.18.
PATH_RESPONSE = 0x1B
# What one order on stdin may carry, counted as `readline` counts a text stream. Orders are
# single words.
ORDER_LIMIT = 64


def say(**fields):
    sys.stdout.write(json.dumps(fields) + "\n")
    sys.stdout.flush()


def digest(payload):
    return hashlib.sha256(payload).hexdigest()


async def read_stream(reader):
    """Read one stream to its end, refusing more than the limit."""
    received = bytearray()
    while True:
        chunk = await reader.read(65536)
        if not chunk:
            return bytes(received)
        received.extend(chunk)
        if len(received) > STREAM_LIMIT:
            raise RuntimeError(f"a stream carried more than {STREAM_LIMIT} bytes")


def client_configuration(arguments):
    configuration = QuicConfiguration(
        is_client=True,
        alpn_protocols=[arguments.alpn],
        idle_timeout=arguments.idle_timeout,
        server_name=arguments.server_name,
        max_datagram_frame_size=arguments.datagram_frame or None,
    )
    configuration.load_verify_locations(cafile=arguments.ca)
    return configuration


def server_configuration(arguments):
    configuration = QuicConfiguration(
        is_client=False,
        alpn_protocols=[arguments.alpn],
        idle_timeout=arguments.idle_timeout,
        max_datagram_frame_size=arguments.datagram_frame or None,
    )
    configuration.load_cert_chain(arguments.cert, arguments.key)
    return configuration


async def run_server(arguments):
    """Serve until the asked-for number of connections have ended.

    Every stream is reported by digest and the bidirectional ones are echoed. A stream handler
    that raises stops the whole peer, so a fault is a failure rather than a silent stall.
    """
    loop = asyncio.get_running_loop()
    quiet = loop.create_future()
    ended = 0

    def stop(reason=None):
        if quiet.done():
            return
        if reason is None:
            quiet.set_result(None)
        else:
            quiet.set_exception(reason)

    serving = {}

    class Served(QuicConnectionProtocol):
        def connection_made(self, transport):
            serving["protocol"] = self
            if arguments.never_act_on_path_responses:
                ignore_path_responses(self._quic)
            super().connection_made(transport)

        def quic_event_received(self, event):
            nonlocal ended
            if isinstance(event, HandshakeCompleted):
                say(
                    event="handshake",
                    alpn=event.alpn_protocol,
                    resumed=event.session_resumed,
                    early=event.early_data_accepted,
                )
            elif isinstance(event, DatagramFrameReceived):
                report_datagram(self, event, echo=True, answer=datagram_answer(arguments))
            elif isinstance(event, ConnectionTerminated):
                ended += 1
                say(event="ended", code=event.error_code, reason=event.reason_phrase)
                if ended >= arguments.connections:
                    stop()
            super().quic_event_received(event)

    def handle(reader, writer):
        async def serve_stream():
            stream_id = writer.get_extra_info("stream_id")
            received = await read_stream(reader)
            say(event="stream", id=stream_id, len=len(received), sha256=digest(received))
            # Where this side is talking to now, for the cases about a peer that moves. Its own
            # verdict on that path is meaningful here: the path is the peer's.
            if arguments.report_paths:
                say(
                    event="path",
                    **await settled_path(
                        serving["protocol"], timeout=arguments.validation_wait
                    ),
                )
            # Bidirectional streams have ids that are multiples of four here, so those are the
            # ones that can be answered. A shared scenario asks for an answer of its own rather
            # than an echo, named by the two numbers it follows from.
            if stream_id % 4 == 0:
                if arguments.answer_length is not None:
                    writer.write(
                        shared_payload(arguments.answer_seed, arguments.answer_length)
                    )
                else:
                    writer.write(received)
                writer.write_eof()

        task = loop.create_task(serve_stream())
        task.add_done_callback(lambda done: stop(done.exception()) if done.exception() else None)

    # A ticket store of its own, so a second connection can resume against this process. It is
    # in memory and lives as long as the peer does.
    tickets = {}
    server = await serve(
        arguments.host,
        0,
        configuration=server_configuration(arguments),
        create_protocol=Served,
        stream_handler=handle,
        session_ticket_fetcher=tickets.get if arguments.tickets else None,
        session_ticket_handler=(
            (lambda ticket: tickets.__setitem__(ticket.ticket, ticket))
            if arguments.tickets
            else None
        ),
    )
    # aioquic offers no accessor for the address it bound, so the transport's socket answers it.
    _, port = server._transport.get_extra_info("socket").getsockname()[:2]
    say(event="listening", port=port)
    if arguments.orders:
        take_orders(loop, server, stop, serving)
    try:
        await quiet
    finally:
        server.close()


def report_datagram(protocol, event, echo, answer=None):
    """Report a datagram by length and digest, then answer it if this side answers.

    A shared scenario supplies its own answer, named by a seed and a length; without one the
    answer is the datagram itself.
    """
    say(event="datagram", len=len(event.data), sha256=digest(event.data))
    if echo:
        send_datagram(protocol, event.data if answer is None else answer)


def send_datagram(protocol, data):
    """aioquic offers no datagram method on the protocol, so this goes through the connection."""
    protocol._quic.send_datagram_frame(data)
    protocol.transmit()


def datagram_answer(arguments):
    """The datagram a shared scenario asks this side to answer with, if it named one."""
    if arguments.datagram_answer_length is None:
        return None
    return shared_payload(
        arguments.datagram_answer_seed, arguments.datagram_answer_length
    )


def shared_payload(seed, length):
    """The payload the shared scenarios define: byte `i` is `i` truncated, exclusive-ored with
    the seed. The Rust side derives the same bytes from the same two numbers."""
    return bytes(((index & 0xFF) ^ seed) for index in range(length))


async def run_client(arguments):
    """Connect, send what the test asked for, and report what came back."""
    payload = bytes((index % 251) ^ arguments.seed for index in range(arguments.length))
    echoes = asyncio.Event()
    counted = {"datagrams": 0}
    if arguments.datagrams == 0:
        echoes.set()

    class Watched(QuicConnectionProtocol):
        """A client connection: it reports what it sees and does not answer datagrams, so a
        test that echoes on the other side sees one round trip rather than a loop."""

        def quic_event_received(self, event):
            if isinstance(event, HandshakeCompleted):
                say(event="handshake", alpn=event.alpn_protocol)
            elif isinstance(event, DatagramFrameReceived):
                report_datagram(self, event, echo=False)
                counted["datagrams"] += 1
                if counted["datagrams"] >= arguments.datagrams:
                    echoes.set()
            elif isinstance(event, ConnectionTerminated):
                say(event="ended", code=event.error_code, reason=event.reason_phrase)
            super().quic_event_received(event)

    async with connect(
        arguments.host,
        arguments.port,
        configuration=client_configuration(arguments),
        create_protocol=Watched,
    ) as client:
        say(event="connected")

        # A shared trust case asks for exactly one bidirectional probe and no upload, so it is
        # handled before the generic stream traffic rather than alongside it.
        if arguments.probe_length is not None:
            probe = shared_payload(arguments.probe_seed, arguments.probe_length)
            reader, writer = await client.create_stream()
            writer.write(probe)
            writer.write_eof()
            answered = await read_stream(reader)
            say(
                event="stream",
                id=writer.get_extra_info("stream_id"),
                len=len(answered),
                sha256=digest(answered),
            )
        elif arguments.streams:
            # A shared scenario names its payloads by seed and length rather than sending the
            # bytes here, and its question is answered with different bytes than it carried.
            up = payload
            question = payload
            if arguments.up_length is not None:
                up = shared_payload(arguments.up_seed, arguments.up_length)
            if arguments.question_length is not None:
                question = shared_payload(
                    arguments.question_seed, arguments.question_length
                )

            uni_reader, uni_writer = await client.create_stream(is_unidirectional=True)
            del uni_reader
            uni_writer.write(up)
            uni_writer.write_eof()

            reader, writer = await client.create_stream()
            writer.write(question)
            writer.write_eof()
            answered = await read_stream(reader)
            say(
                event="stream",
                id=writer.get_extra_info("stream_id"),
                len=len(answered),
                sha256=digest(answered),
            )

        # A shared scenario names the datagram this side sends; without one the client sends
        # the payload it was given.
        outgoing = payload
        if arguments.datagram_out_length is not None:
            outgoing = shared_payload(
                arguments.datagram_out_seed, arguments.datagram_out_length
            )
        for _ in range(arguments.datagrams):
            send_datagram(client, outgoing)
        # Every datagram sent is answered before the connection is closed, so a close cannot
        # discard what this test is about.
        await echoes.wait()

        client.close()
        await client.wait_closed()
    say(event="done")


async def run_resuming_client(arguments):
    """Two connections in one process: the second offers the session ticket the first was
    given, and where the test asks for it, early data goes out before the handshake finishes.

    The ports are given up front, so a test that wants the second attempt to meet a server
    that never kept the session can point the two connections at different ones.
    """
    ticket = None

    def keep(new_ticket):
        nonlocal ticket
        ticket = new_ticket

    class Watched(QuicConnectionProtocol):
        """A client connection, reporting what it is told about the handshake."""

        def quic_event_received(self, event):
            if isinstance(event, HandshakeCompleted):
                say(
                    event="handshake",
                    alpn=event.alpn_protocol,
                    resumed=event.session_resumed,
                    early=event.early_data_accepted,
                )
            elif isinstance(event, ConnectionTerminated):
                say(event="ended", code=event.error_code, reason=event.reason_phrase)
            super().quic_event_received(event)

    configuration = client_configuration(arguments)
    async with connect(
        arguments.host,
        arguments.port,
        configuration=configuration,
        create_protocol=Watched,
        session_ticket_handler=keep,
    ) as client:
        # The handshake event says the connection is up; nothing else needs saying here.
        await exchange(client, shared_payload(arguments.warm_seed, arguments.warm_length))
        client.close()
        await client.wait_closed()
    # Whether there is a ticket to offer is its own fact, said before anything is made of it.
    say(event="ticket", present=ticket is not None)

    configuration.session_ticket = ticket
    offers_early_data = arguments.early_length is not None
    async with connect(
        arguments.host,
        arguments.second_port,
        configuration=configuration,
        create_protocol=Watched,
        session_ticket_handler=keep,
        # A client that waits for the handshake has nothing left to send early.
        wait_connected=not offers_early_data,
    ) as client:
        if offers_early_data:
            early = shared_payload(arguments.early_seed, arguments.early_length)
            _, writer = await client.create_stream(is_unidirectional=True)
            writer.write(early)
            writer.write_eof()
            await client.wait_connected()
        await exchange(
            client, shared_payload(arguments.barrier_seed, arguments.barrier_length)
        )
        client.close()
        await client.wait_closed()
    say(event="done")


async def exchange(client, payload):
    """One bidirectional exchange, reported by length and digest of what came back."""
    held = await send_half_of(client, payload)
    await answer_half_of(held)


async def send_half_of(client, payload):
    """Put a whole payload on a new stream and end it, without waiting for the answer."""
    reader, writer = await client.create_stream()
    writer.write(payload)
    writer.write_eof()
    return reader, writer


async def answer_half_of(held):
    """Wait for what comes back on that stream and report it by length and digest."""
    reader, writer = held
    answered = await read_stream(reader)
    say(
        event="stream",
        id=writer.get_extra_info("stream_id"),
        len=len(answered),
        sha256=digest(answered),
    )


async def run_key_client(arguments):
    """One connection with an exchange either side of a key update.

    Whether this side asks for the update is a flag rather than an order, because the sequence
    is this side's own: the server has already answered the first exchange and read its count
    before this client can ask.
    """

    class Watched(QuicConnectionProtocol):
        """A client connection, reporting what it is told about the handshake."""

        def quic_event_received(self, event):
            if isinstance(event, HandshakeCompleted):
                say(event="handshake", alpn=event.alpn_protocol)
            elif isinstance(event, ConnectionTerminated):
                say(event="ended", code=event.error_code, reason=event.reason_phrase)
            super().quic_event_received(event)

    async with connect(
        arguments.host,
        arguments.port,
        configuration=client_configuration(arguments),
        create_protocol=Watched,
    ) as client:
        settling = shared_payload(arguments.settling_seed, arguments.settling_length)
        if arguments.settling_length:
            # Carries the other side's warm-up update over here. The phase is said straight
            # afterwards, before anything this side sends can release the measured update, so
            # the two phases are either side of that update and of nothing else.
            await exchange(client, settling)
        say(event="phase", phase=key_phase(client))
        await exchange(client, shared_payload(arguments.before_seed, arguments.before_length))
        if arguments.ask_for_a_key_update:
            client._quic.request_key_update()
            client.transmit()
            # One exchange behind the request, so the new phase travels rather than waiting
            # for something else to send.
            await exchange(client, settling)
        await exchange(client, shared_payload(arguments.after_seed, arguments.after_length))
        say(event="phase", phase=key_phase(client))
        client.close()
        await client.wait_closed()
    say(event="done")


def key_phase(protocol):
    """The phase the 1-RTT keys are in. aioquic offers no accessor, so the crypto pair
    answers it."""
    return int(protocol._quic._cryptos[quic_tls.Epoch.ONE_RTT].key_phase)


async def run_close_client(arguments):
    """Connect, exchange where the test asks for one, and close with a code and a reason."""

    class Watched(QuicConnectionProtocol):
        def quic_event_received(self, event):
            if isinstance(event, HandshakeCompleted):
                say(event="handshake", alpn=event.alpn_protocol)
            super().quic_event_received(event)

    async with connect(
        arguments.host,
        arguments.port,
        configuration=client_configuration(arguments),
        create_protocol=Watched,
    ) as client:
        if arguments.before_length:
            await exchange(
                client, shared_payload(arguments.before_seed, arguments.before_length)
            )
        client.close(
            error_code=arguments.close_code,
            reason_phrase=arguments.close_reason,
        )
        await client.wait_closed()
    say(event="done")


async def run_moving_client(arguments):
    """One connection that changes the socket it sends from, and says what it made of it.

    aioquic keeps the transport it sends through on the protocol, so a second datagram
    endpoint handed to it moves the connection without touching the library. What arrives on
    the new socket is given to the same protocol, so the connection carries on.

    Both sockets are bound to the concrete address they send from. `aioquic.asyncio.connect`
    binds the wildcard, and a wildcard `getsockname` is this side's bind address rather than
    the endpoint the server sees, so the connection is set up here instead.
    """

    class Watched(QuicConnectionProtocol):
        """The connection, which stops hearing the address it moves off.

        A client whose network changed never reads what still arrives there, and reading it
        after the move back would time a round trip that did not happen.
        """

        def __init__(self, *arguments, **named):
            super().__init__(*arguments, **named)
            self.moved_away = False

        def quic_event_received(self, event):
            if isinstance(event, HandshakeCompleted):
                say(event="handshake", alpn=event.alpn_protocol)
            elif isinstance(event, ConnectionTerminated):
                say(event="ended", code=event.error_code, reason=event.reason_phrase)
            super().quic_event_received(event)

        def datagram_received(self, data, addr):
            if not self.moved_away:
                self.take(data, addr)

        def take(self, data, addr):
            super().datagram_received(data, addr)

    class Arriving(asyncio.DatagramProtocol):
        """The new socket's reader: what it takes goes to the connection that moved, and it
        counts what arrived so a refused move is a number rather than a wait."""

        def __init__(self, client):
            self._client = client
            self.received = 0

        def datagram_received(self, data, addr):
            self.received += 1
            self._client.take(data, addr)

    loop = asyncio.get_running_loop()
    destination = mapped_destination(arguments.host, arguments.port)
    first = concrete_socket(destination)
    transports = []
    try:
        transport, client = await endpoint_on(
            loop,
            lambda: Watched(QuicConnection(configuration=client_configuration(arguments))),
            first,
        )
        transports.append(transport)
        client.connect(destination)
        await client.wait_connected()
        say(event="address", addr=concrete_endpoint(first))
        await exchange(client, shared_payload(arguments.before_seed, arguments.before_length))

        second = concrete_socket(destination)
        moved, arriving = await endpoint_on(loop, lambda: Arriving(client), second)
        transports.append(moved)
        counted = Counted(moved)
        client._transport = counted
        client.transmit()
        say(event="address", addr=concrete_endpoint(second))

        after = shared_payload(arguments.after_seed, arguments.after_length)
        if arguments.the_move_is_refused:
            # The counts are reported before the answer is waited for, so they say what the
            # new address did whether or not the peer honoured its own policy.
            client.moved_away = True
            held = await send_half_of(client, after)
            await asyncio.sleep(arguments.quiet_for)
            say(event="refused", sent=counted.sent, received=arriving.received)
            client.moved_away = False
            client._transport = transport
            client.transmit()
            say(event="address", addr=concrete_endpoint(first))
            await answer_half_of(held)
        else:
            await exchange(client, after)
        say(event="path", **await settled_path(client))
        client.close()
        await client.wait_closed()
    finally:
        for transport in transports:
            transport.close()
    say(event="done")


def mapped_destination(host, port):
    """The destination as a dual-stack socket addresses it: an IPv4 address v4-mapped, which
    is what aioquic's own client does before it connects."""
    resolved = socket.getaddrinfo(host, port, type=socket.SOCK_DGRAM)[0][4]
    if len(resolved) == 2:
        return ("::ffff:" + resolved[0], resolved[1], 0, 0)
    return resolved


def source_for(destination):
    """The address this host sends to `destination` from, asked of the routing table. A
    connected UDP socket puts nothing on the wire; it only settles the source."""
    scratch = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    try:
        scratch.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        scratch.connect(destination)
        chosen = scratch.getsockname()
        return chosen[0], chosen[3]
    finally:
        scratch.close()


def concrete_socket(destination):
    """A dual-stack socket bound to the address it will send from, on a port of the kernel's
    choosing."""
    host, scope = source_for(destination)
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        sock.bind((host, 0, 0, scope))
    except BaseException:
        sock.close()
        raise
    return sock


class Counted:
    """A transport that counts the datagrams put through it."""

    def __init__(self, transport):
        self._transport = transport
        self.sent = 0

    def sendto(self, data, addr=None):
        self.sent += 1
        self._transport.sendto(data, addr)

    def get_extra_info(self, name, default=None):
        return self._transport.get_extra_info(name, default)

    def close(self):
        self._transport.close()


async def endpoint_on(loop, factory, sock):
    """A datagram endpoint over a socket already bound, closing it if it cannot be made."""
    try:
        return await loop.create_datagram_endpoint(factory, sock=sock)
    except BaseException:
        sock.close()
        raise


def concrete_endpoint(sock):
    """The endpoint this socket sends from, with its family in the spelling and its scope
    when it has one. A wildcard is a bind address and not an answer, so it is refused."""
    name = sock.getsockname()
    host, port = name[0], name[1]
    scope = name[3] if len(name) == 4 else 0
    if ipaddress.ip_address(host).is_unspecified:
        raise RuntimeError(f"the socket is bound to the wildcard {host}, not to a source")
    if ":" not in host:
        return f"{host}:{port}"
    return f"[{host}%{scope}]:{port}" if scope else f"[{host}]:{port}"


def current_path(protocol):
    """The path aioquic is using, which it keeps at the front of its list."""
    return protocol._quic._network_paths[0]


def path_is_validated(protocol):
    return bool(current_path(protocol).is_validated)


def path_address(protocol):
    """The path's address in a form that parses on the other side: an IPv6 host is bracketed,
    and a dual-stack socket reports an IPv4 peer v4-mapped."""
    host, port = current_path(protocol).addr[:2]
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


async def settled_path(protocol, timeout=5.0):
    """The path this side is on, once it has validated it or the wait runs out. A move is
    answered before the challenge on the new path is, so reading it straight away would catch
    a path this side has not finished validating."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while not path_is_validated(protocol) and loop.time() < deadline:
        await asyncio.sleep(0.01)
    return dict(validated=path_is_validated(protocol), addr=path_address(protocol))


def ignore_path_responses(connection):
    """Take the answer to this side's own PATH_CHALLENGE out of the connection, so a path it
    challenges stays unvalidated while the rest of the connection carries on.

    The frame is still consumed off the wire, so nothing else about parsing changes; only the
    verdict it would have settled is withheld.
    """
    handlers = connection._QuicConnection__frame_handlers

    def consume_without_believing(context, frame_type, buf):
        buf.pull_bytes(8)

    handlers[PATH_RESPONSE] = (consume_without_believing, handlers[PATH_RESPONSE][1])


async def run_silent(arguments):
    """Hold a bound socket and answer nothing, for the tests about deadlines."""
    held = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    held.bind((arguments.host, 0))
    say(event="listening", port=held.getsockname()[1])
    try:
        await asyncio.Event().wait()
    finally:
        held.close()


def take_orders(loop, server, stop, serving):
    """Take one-word orders on stdin, so a test can steer the peer without relying on timing.

    `deaf` drops every datagram at the socket, which stops acknowledgements and so stalls the
    other side's transport rather than only its application reads. `hear` restores them.
    `update-keys` asks for a key update, and `key-phase` answers the phase the 1-RTT keys are
    in. Each order is acknowledged on stdout once it has taken effect.

    The read itself is bounded: `readline` is given ORDER_LIMIT + 1 as its size, which for a
    text stream counts characters, so a line longer than that is refused rather than buffered.
    One order is outstanding at a time, since the reader waits for the acknowledgment before
    reading again, so nothing queues up behind a slow one. The reader is a daemon thread and
    ends with the process.
    """
    hearing = {"on": True}
    delivering = server.datagram_received

    def datagram_received(data, addr):
        if hearing["on"]:
            delivering(data, addr)

    server.datagram_received = datagram_received

    def apply(order, done):
        extra = {}
        if order == "deaf":
            hearing["on"] = False
        elif order == "hear":
            hearing["on"] = True
        elif order == "key-phase":
            served = serving.get("protocol")
            if served is None:
                stop(RuntimeError("no connection to read a key phase from"))
                done.set()
                return
            # aioquic offers no accessor for the phase, so the crypto pair answers it. It rides
            # back on the acknowledgment, so one order is still one line.
            extra["phase"] = key_phase(served)
        elif order == "update-keys":
            served = serving.get("protocol")
            if served is None:
                stop(RuntimeError("no connection to update keys on"))
                done.set()
                return
            served._quic.request_key_update()
            served.transmit()
        else:
            stop(RuntimeError(f"unknown order: {order}"))
            done.set()
            return
        say(event="ack", order=order, **extra)
        done.set()

    def reading():
        while True:
            line = sys.stdin.readline(ORDER_LIMIT + 1)
            if not line:
                return
            if len(line) > ORDER_LIMIT:
                loop.call_soon_threadsafe(
                    stop, RuntimeError(f"an order ran past {ORDER_LIMIT} characters")
                )
                return
            order = line.strip()
            if not order:
                continue
            done = threading.Event()
            loop.call_soon_threadsafe(apply, order, done)
            # One order at a time: the next line is not read until this one has taken effect.
            done.wait()

    threading.Thread(target=reading, daemon=True).start()


ROLES = {
    "server": run_server,
    "client": run_client,
    "resuming-client": run_resuming_client,
    "key-client": run_key_client,
    "close-client": run_close_client,
    "moving-client": run_moving_client,
    "silent": run_silent,
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("role", choices=sorted(ROLES))
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--alpn", required=True)
    parser.add_argument("--ca")
    parser.add_argument("--cert")
    parser.add_argument("--key")
    parser.add_argument("--server-name", default="localhost")
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--length", type=int, default=0)
    # A shared scenario's payloads, each named by a seed and a length. Omitted means this peer
    # is not running one and keeps its own behaviour; a length of zero is a payload of no bytes
    # and is not the same thing.
    parser.add_argument("--up-seed", type=int, default=None)
    parser.add_argument("--up-length", type=int, default=None)
    parser.add_argument("--question-seed", type=int, default=None)
    parser.add_argument("--question-length", type=int, default=None)
    parser.add_argument("--answer-seed", type=int, default=None)
    parser.add_argument("--answer-length", type=int, default=None)
    parser.add_argument("--datagram-answer-seed", type=int, default=None)
    parser.add_argument("--datagram-answer-length", type=int, default=None)
    parser.add_argument("--datagram-out-seed", type=int, default=None)
    parser.add_argument("--datagram-out-length", type=int, default=None)
    parser.add_argument("--probe-seed", type=int, default=None)
    parser.add_argument("--probe-length", type=int, default=None)
    parser.add_argument("--second-port", type=int, default=0)
    parser.add_argument("--settling-seed", type=int, default=0)
    parser.add_argument("--settling-length", type=int, default=0)
    parser.add_argument("--before-seed", type=int, default=0)
    parser.add_argument("--before-length", type=int, default=0)
    parser.add_argument("--after-seed", type=int, default=0)
    parser.add_argument("--after-length", type=int, default=0)
    parser.add_argument("--the-move-is-refused", action="store_true")
    parser.add_argument("--quiet-for", type=float, default=0.5)
    parser.add_argument("--ask-for-a-key-update", action="store_true")
    parser.add_argument("--close-code", type=int, default=0)
    parser.add_argument("--close-reason", default="")
    parser.add_argument("--warm-seed", type=int, default=0)
    parser.add_argument("--warm-length", type=int, default=0)
    parser.add_argument("--early-seed", type=int, default=None)
    parser.add_argument("--early-length", type=int, default=None)
    parser.add_argument("--barrier-seed", type=int, default=0)
    parser.add_argument("--barrier-length", type=int, default=0)
    parser.add_argument("--idle-timeout", type=float, default=20.0)
    parser.add_argument("--connections", type=int, default=1)
    parser.add_argument("--datagram-frame", type=int, default=0)
    parser.add_argument("--datagrams", type=int, default=0)
    parser.add_argument("--streams", type=int, default=1)
    parser.add_argument("--orders", action="store_true")
    parser.add_argument("--tickets", action="store_true")
    # Report the path each stream was served over, for the cases about a peer that moves.
    parser.add_argument("--report-paths", action="store_true")
    parser.add_argument("--never-act-on-path-responses", action="store_true")
    parser.add_argument("--validation-wait", type=float, default=5.0)
    arguments = parser.parse_args()
    try:
        asyncio.run(ROLES[arguments.role](arguments))
    except Exception as reason:
        say(event="failed", error=f"{type(reason).__name__}: {reason}")
        sys.exit(1)


if __name__ == "__main__":
    main()
