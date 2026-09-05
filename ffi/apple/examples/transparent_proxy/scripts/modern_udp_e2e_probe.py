#!/usr/bin/env python3
"""Protocol-aware public UDP probes used by the signed macOS NE E2E."""

import argparse
import concurrent.futures
import hashlib
import ipaddress
import json
import os
import secrets
import signal
import socket
import struct
import sys
import threading
import time
import uuid


PRODUCT_VIOLATION_EXIT = 10
PROBE_ERROR_EXIT = 20
PRESSURE_MARKER_PREFIX = b"rama-udp-e2e-pressure-v1 "
QUIC_SHAPED_MARKER = b"rama-quic-shaped-not-valid-quic-v1\0"
QUIC_SHAPED_VERSION = 0xFACEB00C
CONTROLLED_ECHO_SCHEMA_VERSION = 1
MAX_LOAD_BYTES = 256 * 1024 * 1024


class ProductViolation(RuntimeError):
    """A valid response disproved the requested product behavior."""


def dns_query(server: str, name: str, timeout: float, expect_no_response: bool) -> None:
    transaction_id = secrets.randbits(16)
    labels = name.rstrip(".").split(".")
    qname = b"".join(bytes((len(label),)) + label.encode("ascii") for label in labels) + b"\0"
    query = struct.pack("!HHHHHH", transaction_id, 0x0100, 1, 0, 0, 0)
    query += qname + struct.pack("!HH", 1, 1)  # A, IN

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(query, (server, 53))
        try:
            response, peer = sock.recvfrom(65535)
        except socket.timeout as error:
            if expect_no_response:
                print(f"DNS {server}:53 produced no response as expected ({error})")
                return
            raise
        except OSError:
            # A local routing, permission, or socket failure is not evidence that
            # the proxy blocked a valid DNS response.
            raise
    finally:
        try:
            sock.close()
        except OSError:
            # Closing the NE flow is allowed to invalidate the originating UDP
            # socket. That is additional block evidence, not a probe failure.
            if not expect_no_response:
                raise

    if len(response) < 12:
        raise RuntimeError(f"DNS {server}:53 returned a truncated header")

    response_id, flags, question_count, answer_count, _, _ = struct.unpack(
        "!HHHHHH", response[:12]
    )
    if response_id != transaction_id:
        raise RuntimeError(
            f"DNS {server}:53 transaction mismatch: {response_id} != {transaction_id}"
        )
    if not flags & 0x8000:
        raise RuntimeError(f"DNS {server}:53 packet was not a response")
    if flags & 0x000F:
        raise RuntimeError(f"DNS {server}:53 returned rcode={flags & 0x000F}")
    if question_count != 1 or answer_count < 1:
        raise RuntimeError(
            f"DNS {server}:53 missing expected answer (qd={question_count}, an={answer_count})"
        )
    if peer[0] != server or peer[1] != 53:
        raise RuntimeError(
            f"DNS {server}:53 response came from unexpected peer {peer[0]}:{peer[1]}"
        )
    if expect_no_response:
        raise ProductViolation(
            f"blocked DNS endpoint {server}:53 returned a valid matching response"
        )
    print(f"DNS {name} round-trip ok via {peer[0]}:{peer[1]}")


def ntp_query(server: str, timeout: float) -> None:
    # Client mode, NTPv4. Echoing the transmit timestamp into the response's
    # originate field binds the response to this exact request.
    packet = bytearray(48)
    packet[0] = 0x23
    ntp_seconds = time.time() + 2_208_988_800
    seconds = int(ntp_seconds)
    fraction = int((ntp_seconds - seconds) * (1 << 32))
    transmit_timestamp = struct.pack("!II", seconds, fraction)
    packet[40:48] = transmit_timestamp

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(packet, (server, 123))
        response, peer = sock.recvfrom(65535)
    finally:
        sock.close()

    if len(response) < 48:
        raise RuntimeError(f"NTP {server}:123 returned only {len(response)} bytes")
    mode = response[0] & 0x07
    stratum = response[1]
    if mode not in (4, 5):
        raise RuntimeError(f"NTP {server}:123 returned invalid mode={mode}")
    if not 1 <= stratum <= 15:
        raise RuntimeError(f"NTP {server}:123 returned invalid stratum={stratum}")
    if response[24:32] != transmit_timestamp:
        raise RuntimeError(f"NTP {server}:123 originate timestamp mismatch")
    if peer[0] != server or peer[1] != 123:
        raise RuntimeError(
            f"NTP {server}:123 response came from unexpected peer {peer[0]}:{peer[1]}"
        )
    print(f"NTP round-trip ok via {peer[0]}:{peer[1]} (stratum={stratum})")


def pressure_burst(server: str, count: int, payload_bytes: int, settle: float) -> None:
    """Burst one intercepted flow, then leave time for its resume callback."""
    if not 64 <= count <= 100_000:
        raise ValueError("pressure count must be in 64..100000")
    if not 64 <= payload_bytes <= 60_000:
        raise ValueError("pressure payload bytes must be in 64..60000")
    if count * payload_bytes > MAX_LOAD_BYTES:
        raise ValueError("pressure byte product exceeds the bounded load budget")
    if not 0 <= settle <= 30:
        raise ValueError("pressure settle seconds must be in 0..30")

    address = ipaddress.ip_address(server)
    if address.version != 4:
        raise ValueError("pressure server must be an IPv4 literal")
    marker = PRESSURE_MARKER_PREFIX + f"{address}:123".encode("ascii") + b"\0"
    sequence_offset = len(marker)
    if sequence_offset + 8 > payload_bytes:
        raise ValueError("pressure payload is too small for its endpoint marker")
    packet = bytearray(payload_bytes)
    packet[:sequence_offset] = marker
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2.0)
    sent = 0
    try:
        for sequence in range(count):
            packet[sequence_offset:sequence_offset + 8] = sequence.to_bytes(8, "big")
            if sock.sendto(packet, (server, 123)) != len(packet):
                raise RuntimeError("pressure burst sent a partial datagram")
            sent += 1
    finally:
        sock.close()
    if sent != count:
        raise RuntimeError(f"pressure burst sent {sent} of {count} datagrams")
    time.sleep(settle)
    print(
        f"UDP pressure burst sent {sent} datagrams ({payload_bytes} bytes each) "
        f"to {server}:123 and settled for {settle:.3f}s"
    )


def canonical_uuid(value: str) -> str:
    parsed = uuid.UUID(value)
    if str(parsed) != value:
        raise ValueError("run UUID must use canonical lowercase text")
    return value


def quic_shaped_payload(
    run_uuid: str, socket_index: int, sequence: int, payload_bytes: int
) -> bytes:
    """Build a QUIC-shaped test datagram that is deliberately not valid QUIC."""
    canonical_uuid(run_uuid)
    if not 0 <= socket_index <= 0xFFFF_FFFF or not 0 <= sequence <= 0xFFFF_FFFF:
        raise ValueError("QUIC-shaped payload identity exceeds u32")
    # Long-header and fixed bits plus a deliberately unimplemented version and
    # cleartext evidence marker make this visually QUIC-shaped without claiming
    # to be a valid QUIC packet or interoperable protocol message.
    dcid = struct.pack("!II", socket_index, sequence)
    scid = secrets.token_bytes(8)
    prefix = (
        struct.pack("!BI", 0xC0, QUIC_SHAPED_VERSION)
        + bytes((len(dcid),)) + dcid
        + bytes((len(scid),)) + scid
        + QUIC_SHAPED_MARKER
        + run_uuid.encode("ascii") + b"\0"
        + struct.pack("!II", socket_index, sequence)
    )
    if not len(prefix) <= payload_bytes <= 60_000:
        raise ValueError(
            f"payload bytes must be in {len(prefix)}..60000 for the evidence identity"
        )
    return prefix + hashlib.shake_256(prefix).digest(payload_bytes - len(prefix))


def parse_quic_shaped_payload(payload: bytes, run_uuid: str) -> tuple[int, int]:
    canonical_uuid(run_uuid)
    fixed = 1 + 4 + 1 + 8 + 1 + 8
    if len(payload) < fixed + len(QUIC_SHAPED_MARKER) + 36 + 1 + 8:
        raise ValueError("truncated QUIC-shaped datagram")
    first, version = struct.unpack("!BI", payload[:5])
    if first != 0xC0 or version != QUIC_SHAPED_VERSION:
        raise ValueError("invalid QUIC-shaped header")
    if payload[5] != 8 or payload[14] != 8:
        raise ValueError("invalid QUIC-shaped connection-id lengths")
    offset = fixed
    if payload[offset:offset + len(QUIC_SHAPED_MARKER)] != QUIC_SHAPED_MARKER:
        raise ValueError("missing non-QUIC evidence marker")
    offset += len(QUIC_SHAPED_MARKER)
    if payload[offset:offset + 36] != run_uuid.encode("ascii") or payload[offset + 36] != 0:
        raise ValueError("QUIC-shaped payload run UUID mismatch")
    offset += 37
    socket_index, sequence = struct.unpack("!II", payload[offset:offset + 8])
    dcid_socket, dcid_sequence = struct.unpack("!II", payload[6:14])
    if (socket_index, sequence) != (dcid_socket, dcid_sequence):
        raise ValueError("QUIC-shaped payload identity mismatch")
    expected = quic_shaped_payload_without_random_scid_check(payload, offset + 8)
    if payload != expected:
        raise ValueError("QUIC-shaped payload padding mismatch")
    return socket_index, sequence


def quic_shaped_payload_without_random_scid_check(payload: bytes, prefix_len: int) -> bytes:
    """Recompute deterministic padding while retaining the transmitted SCID."""
    prefix = payload[:prefix_len]
    return prefix + hashlib.shake_256(prefix).digest(len(payload) - prefix_len)


def write_json_result(path: str, result: dict) -> None:
    temporary = f"{path}.tmp.{os.getpid()}"
    with open(temporary, "w", encoding="utf-8") as output:
        json.dump(result, output, sort_keys=True, separators=(",", ":"))
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())
    os.replace(temporary, path)


def payload_set_sha256(payloads: dict[tuple[int, int], bytes]) -> str:
    digest = hashlib.sha256()
    for identity, payload in sorted(payloads.items()):
        digest.update(struct.pack("!IIQ", identity[0], identity[1], len(payload)))
        digest.update(payload)
    return digest.hexdigest()


def controlled_echo_server(
    bind: str,
    port: int,
    run_uuid: str,
    expected_count: int,
    max_seconds: float,
    ready_file: str,
    result_file: str,
) -> None:
    canonical_uuid(run_uuid)
    if not 1 <= expected_count <= 65_536:
        raise ValueError("expected echo count must be in 1..65536")
    if not 1 <= max_seconds <= 600:
        raise ValueError("echo server max seconds must be in 1..600")
    address = ipaddress.ip_address(bind)
    family = socket.AF_INET if address.version == 4 else socket.AF_INET6
    sock = socket.socket(family, socket.SOCK_DGRAM)
    sock.settimeout(0.25)
    sock.bind((str(address), port))
    endpoint = sock.getsockname()
    endpoint_text = (
        f"[{endpoint[0]}]:{endpoint[1]}" if address.version == 6
        else f"{endpoint[0]}:{endpoint[1]}"
    )
    stop = threading.Event()

    def request_stop(_signum, _frame):
        stop.set()

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    received = {}
    duplicate_count = 0
    malformed_count = 0
    echo_count = 0
    started = time.monotonic()
    write_json_result(ready_file, {
        "schema_version": CONTROLLED_ECHO_SCHEMA_VERSION,
        "run_uuid": run_uuid,
        "endpoint": endpoint_text,
        "server_pid": os.getpid(),
        "schema_complete": True,
    })
    try:
        while (
            not stop.is_set()
            and len(received) < expected_count
            and time.monotonic() - started < max_seconds
        ):
            try:
                payload, peer = sock.recvfrom(65_535)
            except socket.timeout:
                continue
            try:
                identity = parse_quic_shaped_payload(payload, run_uuid)
            except ValueError:
                malformed_count += 1
                continue
            if identity in received:
                duplicate_count += 1
                continue
            received[identity] = payload
            if sock.sendto(payload, peer) != len(payload):
                raise RuntimeError("controlled echo server sent a partial datagram")
            echo_count += 1
    finally:
        sock.close()
        result = {
            "schema_version": CONTROLLED_ECHO_SCHEMA_VERSION,
            "kind": "controlled_echo_server",
            "run_uuid": run_uuid,
            "endpoint": endpoint_text,
            "expected_count": expected_count,
            "received_count": len(received),
            "echo_count": echo_count,
            "duplicate_count": duplicate_count,
            "malformed_count": malformed_count,
            "payload_set_sha256": payload_set_sha256(received),
            "passed": len(received) == expected_count
                and echo_count == expected_count
                and duplicate_count == 0
                and malformed_count == 0,
            "schema_complete": True,
        }
        write_json_result(result_file, result)
    if not result["passed"]:
        raise RuntimeError("controlled echo server did not receive one exact payload per identity")


def controlled_echo_load(
    server: str,
    port: int,
    run_uuid: str,
    socket_count: int,
    datagrams_per_socket: int,
    payload_bytes: int,
    concurrency: int,
    timeout: float,
    result_file: str,
    interval_ms: int = 0,
) -> None:
    canonical_uuid(run_uuid)
    address = ipaddress.ip_address(server)
    if not 1 <= socket_count <= 512:
        raise ValueError("socket count must be in 1..512")
    if not 1 <= datagrams_per_socket <= 64:
        raise ValueError("datagrams per socket must be in 1..64")
    if not 1 <= concurrency <= min(socket_count, 128):
        raise ValueError("concurrency must be in 1..min(socket_count, 128)")
    if socket_count > concurrency * 16:
        raise ValueError("socket count must be at most 16 times concurrency")
    if socket_count * datagrams_per_socket * payload_bytes > MAX_LOAD_BYTES:
        raise ValueError("echo byte product exceeds the bounded load budget")
    if not 0.1 <= timeout <= 10:
        raise ValueError("echo timeout must be in 0.1..10")
    if type(interval_ms) is not int or not 0 <= interval_ms <= 10_000:
        raise ValueError("echo interval must be an integer in 0..10000 milliseconds")
    expected = {
        (socket_index, sequence): quic_shaped_payload(
            run_uuid, socket_index, sequence, payload_bytes
        )
        for socket_index in range(socket_count)
        for sequence in range(datagrams_per_socket)
    }

    family = socket.AF_INET if address.version == 4 else socket.AF_INET6
    sockets = []
    try:
        for _ in range(socket_count):
            sock = socket.socket(family, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sockets.append(sock)
    except Exception:
        for sock in sockets:
            sock.close()
        raise

    start_epoch_ms = time.time_ns() // 1_000_000
    start_monotonic_ns = time.clock_gettime_ns(time.CLOCK_MONOTONIC)

    def one_socket(socket_index: int):
        sock = sockets[socket_index]
        sent = received = exact = 0
        echoed = {}
        timings = []
        try:
            for sequence in range(datagrams_per_socket):
                if timings and interval_ms:
                    deadline = timings[-1][2] + interval_ms * 1_000_000
                    while True:
                        remaining = deadline - time.clock_gettime_ns(time.CLOCK_MONOTONIC)
                        if remaining <= 0:
                            break
                        time.sleep(remaining / 1_000_000_000)
                payload = expected[(socket_index, sequence)]
                sent_ns = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
                if sock.sendto(payload, (str(address), port)) != len(payload):
                    raise RuntimeError("controlled echo client sent a partial datagram")
                sent += 1
                response, peer = sock.recvfrom(65_535)
                received_ns = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
                received += 1
                if peer[0] != str(address) or peer[1] != port:
                    raise ProductViolation(f"echo response came from unexpected peer {peer}")
                if response != payload:
                    raise ProductViolation("echo response did not exactly match its request")
                if parse_quic_shaped_payload(response, run_uuid) != (socket_index, sequence):
                    raise ProductViolation("echo response carried the wrong flow identity")
                echoed[(socket_index, sequence)] = response
                timings.append([socket_index, sequence, sent_ns, received_ns])
                exact += 1
            local = sock.getsockname()
            local_endpoint = (
                f"[{local[0]}]:{local[1]}" if address.version == 6
                else f"{local[0]}:{local[1]}"
            )
            return sent, received, exact, echoed, local_endpoint, None, timings
        except Exception as error:
            return sent, received, exact, echoed, None, error, timings

    rows = []
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
            futures = [executor.submit(one_socket, index) for index in range(socket_count)]
            rows = [future.result() for future in futures]
    finally:
        for sock in sockets:
            sock.close()
    end_monotonic_ns = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
    end_epoch_ms = time.time_ns() // 1_000_000
    echoed = {}
    for row in rows:
        echoed.update(row[3])
    local_endpoints = [row[4] for row in rows if row[4] is not None]
    errors = [row[5] for row in rows if row[5] is not None]
    expected_count = socket_count * datagrams_per_socket
    sent_count = sum(row[0] for row in rows)
    received_count = sum(row[1] for row in rows)
    exact_echo_count = sum(row[2] for row in rows)
    result = {
        "schema_version": CONTROLLED_ECHO_SCHEMA_VERSION,
        "kind": "controlled_echo_client",
        "run_uuid": run_uuid,
        "endpoint": f"[{address}]:{port}" if address.version == 6 else f"{address}:{port}",
        "socket_count": socket_count,
        "datagrams_per_socket": datagrams_per_socket,
        "payload_bytes": payload_bytes,
        "interval_ms": interval_ms,
        "start_epoch_ms": start_epoch_ms,
        "end_epoch_ms": end_epoch_ms,
        "start_monotonic_ns": start_monotonic_ns,
        "end_monotonic_ns": end_monotonic_ns,
        "packet_timings_ns": [timing for row in rows for timing in row[6]],
        "expected_count": expected_count,
        "sent_count": sent_count,
        "received_count": received_count,
        "exact_echo_count": exact_echo_count,
        "unique_echo_count": len(echoed),
        "independent_socket_count": len(set(local_endpoints)),
        "local_endpoints": sorted(local_endpoints),
        "local_endpoint_set_sha256": hashlib.sha256(
            "\n".join(sorted(local_endpoints)).encode("utf-8")
        ).hexdigest(),
        "payload_set_sha256": payload_set_sha256(expected),
        "echo_set_sha256": payload_set_sha256(echoed),
        "error_count": len(errors),
        "passed": not errors
            and sent_count == received_count == exact_echo_count == expected_count
            and len(echoed) == expected_count
            and len(local_endpoints) == len(set(local_endpoints)) == socket_count
            and payload_set_sha256(expected) == payload_set_sha256(echoed),
        "schema_complete": True,
    }
    write_json_result(result_file, result)
    if not result["passed"]:
        if any(isinstance(error, ProductViolation) for error in errors):
            raise ProductViolation("controlled echo returned invalid payload evidence")
        raise RuntimeError("controlled echo load did not complete exact cardinality")
    print(
        f"QUIC-shaped UDP controlled echo ok: sockets={socket_count} "
        f"datagrams={expected_count} bytes={payload_bytes} sha256={result['echo_set_sha256']}"
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    dns = subparsers.add_parser("dns")
    dns.add_argument("--server", required=True)
    dns.add_argument("--name", default="example.com")
    dns.add_argument("--timeout", type=float, default=8.0)
    dns.add_argument("--expect-no-response", action="store_true")

    ntp = subparsers.add_parser("ntp")
    ntp.add_argument("--server", required=True)
    ntp.add_argument("--timeout", type=float, default=8.0)

    pressure = subparsers.add_parser("pressure")
    pressure.add_argument("--server", required=True)
    pressure.add_argument("--count", type=int, default=512)
    pressure.add_argument("--payload-bytes", type=int, default=4096)
    pressure.add_argument("--settle", type=float, default=4.0)

    echo_server = subparsers.add_parser("echo-server")
    echo_server.add_argument("--bind", default="127.0.0.1")
    echo_server.add_argument("--port", type=int, default=0)
    echo_server.add_argument("--run-uuid", required=True)
    echo_server.add_argument("--expected-count", type=int, required=True)
    echo_server.add_argument("--max-seconds", type=float, default=180.0)
    echo_server.add_argument("--ready-file", required=True)
    echo_server.add_argument("--result-file", required=True)

    echo_load = subparsers.add_parser("echo-load")
    echo_load.add_argument("--server", required=True)
    echo_load.add_argument("--port", required=True, type=int)
    echo_load.add_argument("--run-uuid", required=True)
    echo_load.add_argument("--socket-count", type=int, default=128)
    echo_load.add_argument("--datagrams-per-socket", type=int, default=1)
    echo_load.add_argument("--payload-bytes", type=int, default=1200)
    echo_load.add_argument("--concurrency", type=int, default=32)
    echo_load.add_argument("--timeout", type=float, default=8.0)
    echo_load.add_argument("--interval-ms", type=int, default=0)
    echo_load.add_argument("--result-file", required=True)

    args = parser.parse_args()
    if args.command == "dns":
        dns_query(args.server, args.name, args.timeout, args.expect_no_response)
    elif args.command == "ntp":
        ntp_query(args.server, args.timeout)
    elif args.command == "pressure":
        pressure_burst(args.server, args.count, args.payload_bytes, args.settle)
    elif args.command == "echo-server":
        controlled_echo_server(
            args.bind, args.port, args.run_uuid, args.expected_count,
            args.max_seconds, args.ready_file, args.result_file,
        )
    else:
        controlled_echo_load(
            args.server, args.port, args.run_uuid, args.socket_count,
            args.datagrams_per_socket, args.payload_bytes, args.concurrency,
            args.timeout, args.result_file, args.interval_ms,
        )


if __name__ == "__main__":
    try:
        main()
    except ProductViolation as error:
        print(f"modern UDP E2E product violation: {error}", file=sys.stderr)
        raise SystemExit(PRODUCT_VIOLATION_EXIT)
    except Exception as error:
        print(f"modern UDP E2E probe failed: {error}", file=sys.stderr)
        raise SystemExit(PROBE_ERROR_EXIT)
