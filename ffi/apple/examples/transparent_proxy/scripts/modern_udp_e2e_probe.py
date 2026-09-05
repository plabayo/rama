#!/usr/bin/env python3
"""Protocol-aware public UDP probes used by the signed macOS NE E2E."""

import argparse
import ipaddress
import secrets
import socket
import struct
import sys
import time


PRODUCT_VIOLATION_EXIT = 10
PROBE_ERROR_EXIT = 20
PRESSURE_MARKER_PREFIX = b"rama-udp-e2e-pressure-v1 "


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
            sock.sendto(packet, (server, 123))
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

    args = parser.parse_args()
    if args.command == "dns":
        dns_query(args.server, args.name, args.timeout, args.expect_no_response)
    elif args.command == "ntp":
        ntp_query(args.server, args.timeout)
    else:
        pressure_burst(args.server, args.count, args.payload_bytes, args.settle)


if __name__ == "__main__":
    try:
        main()
    except ProductViolation as error:
        print(f"modern UDP E2E product violation: {error}", file=sys.stderr)
        raise SystemExit(PRODUCT_VIOLATION_EXIT)
    except Exception as error:
        print(f"modern UDP E2E probe failed: {error}", file=sys.stderr)
        raise SystemExit(PROBE_ERROR_EXIT)
