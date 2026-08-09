#!/usr/bin/env python3
"""Protocol-aware public UDP probes used by the signed macOS NE E2E."""

import argparse
import secrets
import socket
import struct
import sys
import time


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
        except (socket.timeout, OSError) as error:
            if expect_no_response:
                print(f"DNS {server}:53 produced no response as expected ({error})")
                return
            raise
    finally:
        try:
            sock.close()
        except OSError:
            # Closing the NE flow is allowed to invalidate the originating UDP
            # socket. That is additional block evidence, not a probe failure.
            if not expect_no_response:
                raise

    if expect_no_response:
        raise RuntimeError(f"blocked DNS endpoint {server}:53 unexpectedly replied")
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
    print(f"NTP round-trip ok via {peer[0]}:{peer[1]} (stratum={stratum})")


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

    args = parser.parse_args()
    if args.command == "dns":
        dns_query(args.server, args.name, args.timeout, args.expect_no_response)
    else:
        ntp_query(args.server, args.timeout)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"modern UDP E2E probe failed: {error}", file=sys.stderr)
        raise
