"""The aioquic side of the interoperability tests.

One process per role, driven from the Rust test over a line protocol on stdout: one JSON
object per line, flushed as it happens. Every payload is reported by length and SHA-256, so
the Rust side checks bytes rather than the peer's own account of them. Anything unexpected is
reported as a `failed` line and leaves a non-zero exit status.
"""

import argparse
import asyncio
import hashlib
import json
import socket
import sys

from aioquic.asyncio import connect, serve
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ConnectionTerminated, HandshakeCompleted

# What a stream may carry. A peer that sends more is a fault, not a larger test.
STREAM_LIMIT = 1 << 20


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
    )
    configuration.load_verify_locations(cafile=arguments.ca)
    return configuration


def server_configuration(arguments):
    configuration = QuicConfiguration(
        is_client=False,
        alpn_protocols=[arguments.alpn],
        idle_timeout=arguments.idle_timeout,
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

    class Served(QuicConnectionProtocol):
        def quic_event_received(self, event):
            nonlocal ended
            if isinstance(event, HandshakeCompleted):
                say(event="handshake", alpn=event.alpn_protocol)
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
            # Bidirectional streams have ids that are multiples of four here, so those are the
            # ones that can be answered.
            if stream_id % 4 == 0:
                writer.write(received)
                writer.write_eof()

        task = loop.create_task(serve_stream())
        task.add_done_callback(lambda done: stop(done.exception()) if done.exception() else None)

    server = await serve(
        arguments.host,
        0,
        configuration=server_configuration(arguments),
        create_protocol=Served,
        stream_handler=handle,
    )
    # aioquic offers no accessor for the address it bound, so the transport's socket answers it.
    _, port = server._transport.get_extra_info("socket").getsockname()[:2]
    say(event="listening", port=port)
    try:
        await quiet
    finally:
        server.close()


class Watched(QuicConnectionProtocol):
    """A connection that reports what the handshake settled and how the connection ended."""

    def quic_event_received(self, event):
        if isinstance(event, HandshakeCompleted):
            say(event="handshake", alpn=event.alpn_protocol)
        elif isinstance(event, ConnectionTerminated):
            say(event="ended", code=event.error_code, reason=event.reason_phrase)
        super().quic_event_received(event)


async def run_client(arguments):
    """Connect, send the payloads the test asked for, and report what came back."""
    payload = bytes((index % 251) ^ arguments.seed for index in range(arguments.length))
    async with connect(
        arguments.host,
        arguments.port,
        configuration=client_configuration(arguments),
        create_protocol=Watched,
    ) as client:
        say(event="connected")

        uni_reader, uni_writer = await client.create_stream(is_unidirectional=True)
        del uni_reader
        uni_writer.write(payload)
        uni_writer.write_eof()

        reader, writer = await client.create_stream()
        writer.write(payload)
        writer.write_eof()
        answered = await read_stream(reader)
        say(event="stream", id=writer.get_extra_info("stream_id"),
            len=len(answered), sha256=digest(answered))

        client.close()
        await client.wait_closed()
    say(event="done")


async def run_silent(arguments):
    """Hold a bound socket and answer nothing, for the tests about deadlines."""
    held = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    held.bind((arguments.host, 0))
    say(event="listening", port=held.getsockname()[1])
    try:
        await asyncio.Event().wait()
    finally:
        held.close()


ROLES = {"server": run_server, "client": run_client, "silent": run_silent}


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
    parser.add_argument("--idle-timeout", type=float, default=20.0)
    parser.add_argument("--connections", type=int, default=1)
    arguments = parser.parse_args()
    try:
        asyncio.run(ROLES[arguments.role](arguments))
    except Exception as reason:
        say(event="failed", error=f"{type(reason).__name__}: {reason}")
        sys.exit(1)


if __name__ == "__main__":
    main()
