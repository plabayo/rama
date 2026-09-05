#!/usr/bin/env python3
"""Protocol-aware public UDP probes used by the signed macOS NE E2E."""

import argparse
import concurrent.futures
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import signal
import socket
import stat
import struct
import sys
import tempfile
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
PRESSURE_INITIAL_DATAGRAMS = 66
PRESSURE_INTERVAL_SECONDS = 0.02
PRESSURE_RECOVERY_SECONDS = 2.5
PRESSURE_SEND_TIMEOUT_SECONDS = 5.0
PRESSURE_DEADLINE_SECONDS = 120.0


class ProductViolation(RuntimeError):
    """A valid response disproved the requested product behavior."""


def dns_request(transaction_id: int, name: str) -> bytes:
    labels = name.rstrip(".").split(".")
    if any(not 1 <= len(label.encode("ascii")) <= 63 for label in labels):
        raise ValueError("invalid DNS label length")
    qname = b"".join(bytes((len(label),)) + label.encode("ascii") for label in labels) + b"\0"
    if len(qname) > 255:
        raise ValueError("DNS name exceeds its wire bound")
    query = struct.pack("!HHHHHH", transaction_id, 0x0100, 1, 0, 0, 0)
    return query + qname + struct.pack("!HH", 1, 1)  # A, IN


def _dns_name(packet, offset, limit, names):
    """Read one RFC 1035 name without recursion, within its enclosing field.

    Pointers address prior bytes; visited offsets reject cycles. Memoized
    suffixes avoid repeatedly walking pointer chains across resource records.
    Only the protocol's 255-octet expanded-name bound limits label count.
    """
    path, visited = [], set()
    following = None
    while True:
        if offset in visited:
            raise RuntimeError("DNS compression pointer loop")
        visited.add(offset)
        if following is not None and offset in names:
            name = names[offset]
            break
        if offset >= limit:
            raise RuntimeError("DNS truncated name")
        length = packet[offset]
        if length & 0xC0 == 0xC0:
            if offset + 2 > limit:
                raise RuntimeError("DNS truncated compression pointer")
            target = ((length & 0x3F) << 8) | packet[offset + 1]
            if not 12 <= target < offset:
                raise RuntimeError("DNS compression pointer does not refer to a prior name")
            if following is None:
                following = offset + 2
            path.append((offset, None))
            offset, limit = target, len(packet)
        elif length & 0xC0:
            raise RuntimeError("DNS invalid label encoding")
        elif not length:
            name = ()
            names[offset] = name
            if following is None:
                following = offset + 1
            break
        else:
            if offset + 1 + length > limit:
                raise RuntimeError("DNS truncated label")
            path.append((offset, packet[offset + 1:offset + 1 + length].lower()))
            offset += 1 + length
    expanded = 1 + sum(1 + len(label) for label in name)
    for position, label in reversed(path):
        if label is not None:
            expanded += 1 + len(label)
            if expanded > 255:
                raise RuntimeError("DNS name exceeds its wire bound")
            name = (label,) + name
        names[position] = name
    return name, following


def validate_dns_response(query: bytes, response: bytes, peer, server: str) -> None:
    """Require a complete matching A/IN answer, directly or through CNAMEs.

    This bounded UDP probe checks all RR envelopes, A/CNAME data and EDNS
    option framing. Other RDATA remains opaque; this is not a DNS resolver.
    """
    if not 12 <= len(query) <= 271 or len(response) > 65_535:
        raise RuntimeError("DNS packet exceeds the probe's wire bounds")
    if len(response) < 12:
        raise RuntimeError(f"DNS {server}:53 returned a truncated header")

    transaction_id, *request_header = struct.unpack("!HHHHHH", query[:12])
    requested_name, request_end = _dns_name(query, 12, len(query), {})
    if (request_header != [0x0100, 1, 0, 0, 0]
            or request_end + 4 != len(query) or query[request_end:] != b"\x00\x01\x00\x01"):
        raise RuntimeError("DNS probe requires one complete A/IN question")
    response_id, flags, question_count, answer_count, authority_count, additional_count = struct.unpack(
        "!HHHHHH", response[:12]
    )
    if response_id != transaction_id:
        raise RuntimeError(
            f"DNS {server}:53 transaction mismatch: {response_id} != {transaction_id}"
        )
    if not flags & 0x8000:
        raise RuntimeError(f"DNS {server}:53 packet was not a response")
    if flags & 0x7800:
        raise RuntimeError(f"DNS {server}:53 returned a mismatched opcode")
    if flags & 0x0200:
        raise RuntimeError(f"DNS {server}:53 returned a truncated response (TC)")
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
    names = {}
    question, offset = _dns_name(response, 12, len(response), names)
    if question != requested_name or response[offset:offset + 4] != b"\x00\x01\x00\x01":
        raise RuntimeError(f"DNS {server}:53 returned a mismatched or truncated question")
    offset += 4
    addresses, aliases = set(), {}
    seen_opt = False
    for section, count in enumerate((answer_count, authority_count, additional_count)):
        for _ in range(count):
            owner, offset = _dns_name(response, offset, len(response), names)
            if offset + 10 > len(response):
                raise RuntimeError("DNS truncated resource record header")
            kind, record_class, ttl, size = struct.unpack_from("!HHIH", response, offset)
            offset += 10
            end = offset + size
            if end > len(response):
                raise RuntimeError("DNS truncated resource record data")
            if kind == 1 and record_class == 1:
                if size != 4:
                    raise RuntimeError("DNS A record has an invalid RDLENGTH")
                if section == 0:
                    addresses.add(owner)
            elif kind == 5:
                target, name_end = _dns_name(response, offset, end, names)
                if name_end != end:
                    raise RuntimeError("DNS CNAME record has an invalid RDLENGTH")
                if section == 0 and record_class == 1:
                    if owner in aliases and aliases[owner] != target:
                        raise RuntimeError("DNS answer has conflicting CNAME records")
                    aliases[owner] = target
            elif kind == 41:  # RFC 6891 OPT: keep extended errors from looking successful.
                if section != 2 or owner or seen_opt or ttl >> 16:
                    raise RuntimeError("DNS invalid OPT record or extended error/version")
                seen_opt = True
                option = offset
                while option < end:
                    if option + 4 > end:
                        raise RuntimeError("DNS truncated EDNS option header")
                    option += 4 + struct.unpack_from("!H", response, option + 2)[0]
                    if option > end:
                        raise RuntimeError("DNS truncated EDNS option data")
            offset = end
    if offset != len(response):
        raise RuntimeError("DNS response has trailing bytes outside its records")
    if addresses.intersection(aliases):
        raise RuntimeError("DNS answer has both A and CNAME records for one owner")
    visited = set()
    while requested_name not in addresses:
        if requested_name in visited or requested_name not in aliases:
            raise RuntimeError(f"DNS {server}:53 missing the requested A/IN answer")
        visited.add(requested_name)
        requested_name = aliases[requested_name]


def validate_ntp_response(packet: bytes, response: bytes, peer, server: str) -> None:
    """Replay the probe's NTP mode, stratum, originate, and peer contract."""
    if len(response) < 48:
        raise RuntimeError(f"NTP {server}:123 returned only {len(response)} bytes")
    mode = response[0] & 0x07
    stratum = response[1]
    if mode not in (4, 5):
        raise RuntimeError(f"NTP {server}:123 returned invalid mode={mode}")
    if not 1 <= stratum <= 15:
        raise RuntimeError(f"NTP {server}:123 returned invalid stratum={stratum}")
    if response[24:32] != packet[40:48]:
        raise RuntimeError(f"NTP {server}:123 originate timestamp mismatch")
    if peer[0] != server or peer[1] != 123:
        raise RuntimeError(
            f"NTP {server}:123 response came from unexpected peer {peer[0]}:{peer[1]}"
        )


PROBE_LABELS = ("passthrough", "ntp", "control", "recovery", "blocked")
PROBE_RECEIPT_MAX_BYTES = 2 * 65_535 + 4096  # one hex UDP response plus bounded metadata
PROBE_RECEIPT_KEYS = {
    "schema_version", "kind", "run_uuid", "probe_label", "source_pid",
    "protocol", "endpoint", "dns_name", "expect_no_response", "timeout_ns",
    "request_hex", "sent_bytes", "response_hex", "response_peer", "receive_outcome",
    "start_epoch_ms", "end_epoch_ms", "start_monotonic_ns",
    "receive_started_monotonic_ns", "receive_completed_monotonic_ns",
    "end_monotonic_ns", "close_error", "exit_code", "schema_complete",
}


def read_probe_receipt(path):
    """Read one bounded regular receipt without following a terminal symlink."""
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as source:
        before = os.fstat(source.fileno())
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= PROBE_RECEIPT_MAX_BYTES:
            raise ValueError("UDP probe receipt is not a bounded regular file")
        content = source.read(PROBE_RECEIPT_MAX_BYTES + 1)
        after = os.fstat(source.fileno())
    if (len(content) != before.st_size or before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns or before.st_ctime_ns != after.st_ctime_ns):
        raise ValueError("UDP probe receipt changed during its bounded read")

    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate UDP probe receipt field")
            result[key] = value
        return result

    try:
        value = json.loads(content.decode("utf-8", errors="strict"), object_pairs_hook=unique_object)
    except (UnicodeError, RecursionError) as error:
        raise ValueError("malformed UDP probe receipt") from error
    if not isinstance(value, dict) or set(value) != PROBE_RECEIPT_KEYS:
        raise ValueError("incorrect UDP probe receipt field set")
    return value


def replay_probe_receipt(value, run_uuid, label, source_pid, endpoint):
    """Derive the result from saved bytes/peer/clock samples, then check the child claim.

    This applies the same DNS wire and NTP probe contracts as the live probes. It does not
    authenticate the capture host or treat a manifest as a signed network trace.
    """
    if not isinstance(value, dict) or set(value) != PROBE_RECEIPT_KEYS or label not in PROBE_LABELS:
        raise ValueError("incorrect UDP probe receipt field set/label")
    canonical_uuid(run_uuid)
    protocol = "ntp" if label in ("ntp", "recovery") else "dns"
    server, port = endpoint.rsplit(":", 1)
    if str(ipaddress.IPv4Address(server)) != server or port != ("53" if protocol == "dns" else "123"):
        raise ValueError("incorrect UDP probe receipt endpoint")
    expected = {
        "kind": "udp_protocol_probe", "run_uuid": run_uuid, "probe_label": label,
        "protocol": protocol, "endpoint": endpoint,
        "dns_name": "example.com" if protocol == "dns" else None,
    }
    if any(value[key] != item for key, item in expected.items()):
        raise ValueError("UDP probe receipt identity mismatch")
    if (type(value["schema_version"]) is not int or value["schema_version"] != 1
            or value["schema_complete"] is not True
            or value["expect_no_response"] is not (label == "blocked")
            or type(value["close_error"]) is not bool):
        raise ValueError("UDP probe receipt schema/expectation mismatch")
    integers = ("source_pid", "timeout_ns", "sent_bytes", "start_epoch_ms", "end_epoch_ms",
                "start_monotonic_ns", "end_monotonic_ns", "exit_code")
    if any(type(value[key]) is not int or not 0 <= value[key] < 2**63 for key in integers):
        raise ValueError("UDP probe receipt contains a non-canonical integer")
    if not 0 < value["source_pid"] == source_pid < 2**31:
        raise ValueError("UDP probe receipt source PID mismatch")
    # These are the existing harness contracts: eight seconds per positive
    # canary, four seconds for the expected timeout, and one 30-second join.
    if value["timeout_ns"] != (4 if label == "blocked" else 8) * 1_000_000_000:
        raise ValueError("UDP probe receipt changed the configured timeout")
    start, end = value["start_monotonic_ns"], value["end_monotonic_ns"]
    if (not 0 < start <= end or end - start > 30_000_000_000
            or not 0 < value["start_epoch_ms"] <= value["end_epoch_ms"]
            or abs((value["end_epoch_ms"] - value["start_epoch_ms"]) * 1_000_000
                   - (end - start)) > 2_000_000_000):
        raise ValueError("UDP probe receipt clock window is invalid")

    def payload(key, maximum):
        encoded = value[key]
        if (not isinstance(encoded, str) or len(encoded) > maximum * 2
                or re.fullmatch(r"(?:[0-9a-f]{2})*", encoded) is None):
            raise ValueError("UDP probe receipt has malformed/big packet bytes")
        return bytes.fromhex(encoded)

    request = payload("request_hex", 271 if protocol == "dns" else 48)
    if protocol == "dns":
        if len(request) < 2 or request != dns_request(int.from_bytes(request[:2], "big"), "example.com"):
            raise ValueError("UDP probe receipt DNS request mismatch")
    elif len(request) != 48 or request[:40] != bytes((0x23,)) + bytes(39):
        raise ValueError("UDP probe receipt NTP request mismatch")
    if value["sent_bytes"] > len(request):
        raise ValueError("UDP probe receipt sent-byte count exceeds its request")
    outcome = value["receive_outcome"]
    receiving, received = value["receive_started_monotonic_ns"], value["receive_completed_monotonic_ns"]
    if outcome == "not_started":
        if receiving is not None or received is not None:
            raise ValueError("UDP probe receipt has impossible receive timing")
    elif outcome in ("response", "timeout", "error"):
        if (type(receiving) is not int or type(received) is not int
                or not start <= receiving <= received <= end
                or value["sent_bytes"] != len(request)):
            raise ValueError("UDP probe receipt receive timing/send count mismatch")
    else:
        raise ValueError("UDP probe receipt has an unknown receive outcome")
    result = PROBE_ERROR_EXIT
    if outcome == "response":
        response = payload("response_hex", 65_535)
        peer = value["response_peer"]
        if (not isinstance(peer, list) or len(peer) != 2 or not isinstance(peer[0], str)
                or type(peer[1]) is not int or not 0 < peer[1] <= 65_535
                or str(ipaddress.IPv4Address(peer[0])) != peer[0]):
            raise ValueError("UDP probe receipt response peer is malformed")
        try:
            if protocol == "dns":
                validate_dns_response(request, response, peer, server)
            else:
                validate_ntp_response(request, response, peer, server)
        except RuntimeError:
            pass
        else:
            result = PRODUCT_VIOLATION_EXIT if label == "blocked" else 0
    elif value["response_hex"] is not None or value["response_peer"] is not None:
        raise ValueError("UDP probe receipt claims bytes without a response")
    elif outcome == "timeout" and label == "blocked":
        if received - receiving < value["timeout_ns"]:
            raise ValueError("UDP blocked probe did not observe its full timeout")
        result = 0
    if value["close_error"] and label != "blocked":
        result = PROBE_ERROR_EXIT
    if value["exit_code"] != result:
        raise ValueError("UDP probe receipt child result disagrees with raw protocol evidence")
    return result


def _publish_probe_receipt(path: str, receipt: dict) -> None:
    """Publish one complete file atomically; a duplicate label cannot overwrite it."""
    destination = Path(path)
    content = (json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n").encode()
    if len(content) > PROBE_RECEIPT_MAX_BYTES:
        raise ValueError("UDP probe receipt exceeds its bound")
    with tempfile.NamedTemporaryFile(dir=destination.parent, prefix=".udp-probe-", suffix=".tmp") as output:
        output.write(content)
        output.flush()
        os.fsync(output.fileno())
        # link is an atomic no-replace publication within the same directory;
        # the temporary link is removed before the child returns to its parent.
        os.link(output.name, destination)


def _exchange_probe(protocol, server, query, timeout, expect_no_response, name,
                    run_uuid, probe_label, result_file):
    receipt = None
    if any(value is not None for value in (run_uuid, probe_label, result_file)):
        canonical_uuid(run_uuid)
        if probe_label not in PROBE_LABELS or result_file is None:
            raise ValueError("UDP probe receipt requires one exact label and result file")
        if str(ipaddress.IPv4Address(server)) != server or not 0 < timeout <= 30:
            raise ValueError("UDP probe receipt requires an IPv4 literal and bounded timeout")
        receipt = {
            "schema_version": 1, "kind": "udp_protocol_probe", "run_uuid": run_uuid,
            "probe_label": probe_label, "source_pid": os.getpid(), "protocol": protocol,
            "endpoint": f"{server}:{53 if protocol == 'dns' else 123}", "dns_name": name,
            "expect_no_response": expect_no_response, "timeout_ns": int(timeout * 1_000_000_000),
            "request_hex": query.hex(), "sent_bytes": 0, "response_hex": None,
            "response_peer": None, "receive_outcome": "not_started",
            "start_epoch_ms": time.time_ns() // 1_000_000,
            "start_monotonic_ns": time.clock_gettime_ns(time.CLOCK_MONOTONIC),
            "receive_started_monotonic_ns": None, "receive_completed_monotonic_ns": None,
            "close_error": False, "exit_code": PROBE_ERROR_EXIT, "schema_complete": True,
        }
    sock = None
    response = peer = None
    try:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            written = sock.sendto(query, (server, 53 if protocol == "dns" else 123))
            if receipt is not None:
                receipt["sent_bytes"] = written
                if written != len(query):
                    raise RuntimeError("UDP probe sent a partial datagram")
                receipt["receive_outcome"] = "error"
                receipt["receive_started_monotonic_ns"] = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
            try:
                response, peer = sock.recvfrom(65_535)
                if receipt is not None:
                    receipt["receive_outcome"] = "response"
                    receipt["response_hex"] = response.hex()
                    receipt["response_peer"] = list(peer)
            except socket.timeout:
                if receipt is not None:
                    receipt["receive_outcome"] = "timeout"
                if not expect_no_response:
                    raise
            finally:
                if receipt is not None:
                    receipt["receive_completed_monotonic_ns"] = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    if receipt is not None:
                        receipt["close_error"] = True
                    # Preserve the existing NE blocked-flow close exception.
                    # A routing/send/receive error still propagates separately.
                    if not expect_no_response:
                        raise
        if response is not None:
            if protocol == "dns":
                validate_dns_response(query, response, peer, server)
            else:
                validate_ntp_response(query, response, peer, server)
            if expect_no_response:
                raise ProductViolation(f"blocked DNS endpoint {server}:53 returned a valid matching response")
        if receipt is not None:
            receipt["exit_code"] = 0
    except ProductViolation:
        if receipt is not None:
            receipt["exit_code"] = PRODUCT_VIOLATION_EXIT
        raise
    finally:
        if receipt is not None:
            receipt["end_monotonic_ns"] = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
            receipt["end_epoch_ms"] = time.time_ns() // 1_000_000
            _publish_probe_receipt(result_file, receipt)
    return response, peer


def dns_query(server: str, name: str, timeout: float, expect_no_response: bool,
              *, run_uuid=None, probe_label=None, result_file=None) -> None:
    query = dns_request(secrets.randbits(16), name)
    response, peer = _exchange_probe(
        "dns", server, query, timeout, expect_no_response, name,
        run_uuid, probe_label, result_file,
    )
    if response is None:
        print(f"DNS {server}:53 produced no response as expected (timeout)")
    else:
        print(f"DNS {name} round-trip ok via {peer[0]}:{peer[1]}")


def ntp_query(server: str, timeout: float, *, run_uuid=None, probe_label=None, result_file=None) -> None:
    # Client mode, NTPv4; the response must echo this request's transmit timestamp.
    packet = bytearray(48)
    packet[0] = 0x23
    ntp_seconds = time.time() + 2_208_988_800
    seconds = int(ntp_seconds)
    fraction = int((ntp_seconds - seconds) * (1 << 32))
    packet[40:48] = struct.pack("!II", seconds, fraction)
    response, peer = _exchange_probe(
        "ntp", server, bytes(packet), timeout, False, None,
        run_uuid, probe_label, result_file,
    )
    print(f"NTP round-trip ok via {peer[0]}:{peer[1]} (stratum={response[1]})")


def pressure_burst(server: str, count: int, payload_bytes: int, settle: float) -> None:
    """Pace one intercepted flow through pressure and recovery, without retries."""
    if not 64 <= count <= 100_000:
        raise ValueError("pressure count must be in 64..100000")
    if not 64 <= payload_bytes <= 60_000:
        raise ValueError("pressure payload bytes must be in 64..60000")
    if count * payload_bytes > MAX_LOAD_BYTES:
        raise ValueError("pressure byte product exceeds the bounded load budget")
    if not 0 <= settle <= 30:
        raise ValueError("pressure settle seconds must be in 0..30")
    scheduled_seconds = (count - 1) * PRESSURE_INTERVAL_SECONDS + settle
    if count > PRESSURE_INITIAL_DATAGRAMS:
        scheduled_seconds += PRESSURE_RECOVERY_SECONDS - PRESSURE_INTERVAL_SECONDS
    if scheduled_seconds >= PRESSURE_DEADLINE_SECONDS:
        raise ValueError("pressure paced schedule exceeds the whole-probe deadline")

    address = ipaddress.ip_address(server)
    if address.version != 4:
        raise ValueError("pressure server must be an IPv4 literal")
    marker = PRESSURE_MARKER_PREFIX + f"{address}:123".encode("ascii") + b"\0"
    sequence_offset = len(marker)
    if sequence_offset + 8 > payload_bytes:
        raise ValueError("pressure payload is too small for its endpoint marker")
    packet = bytearray(payload_bytes)
    packet[:sequence_offset] = marker
    deadline = time.monotonic() + PRESSURE_DEADLINE_SECONDS
    sent = 0

    def remaining_seconds() -> float:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError(f"pressure probe deadline expired after {sent} sends")
        return remaining

    def pause(seconds: float) -> None:
        if seconds >= remaining_seconds():
            raise TimeoutError(f"pressure probe cannot finish its pause after {sent} sends")
        if seconds:
            time.sleep(seconds)
        remaining_seconds()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        for sequence in range(count):
            if sequence:
                # The scoped service keeps receiving and retaining payloads
                # during its two-second hold. The first 64 canonical 4-KiB
                # datagrams fill the real 256-KiB flow budget; the next two can
                # exercise rejection. Spacing these sends avoids knowingly
                # overrunning Swift's 32-item staging with the entire workload.
                # OS batching and runtime scheduling remain unproved here: the
                # native gate must still observe the exact Rust drop/recovery
                # and reject every Swift staging loss.
                pause(PRESSURE_RECOVERY_SECONDS if sequence == PRESSURE_INITIAL_DATAGRAMS
                      else PRESSURE_INTERVAL_SECONDS)
            # Start each interval after the preceding send completed. A slow
            # send or scheduler delay must never create a catch-up burst. The
            # send timeout exceeds the deliberate service hold, while the one
            # monotonic deadline also bounds cumulative delays and settling.
            sock.settimeout(min(PRESSURE_SEND_TIMEOUT_SECONDS, remaining_seconds()))
            packet[sequence_offset:sequence_offset + 8] = sequence.to_bytes(8, "big")
            try:
                written = sock.sendto(packet, (server, 123))
            except socket.timeout as error:
                raise TimeoutError(
                    f"pressure datagram {sequence + 1}/{count} send timed out "
                    f"after {sent} confirmed sends"
                ) from error
            if written != len(packet):
                raise RuntimeError("pressure burst sent a partial datagram")
            sent += 1
            remaining_seconds()
    finally:
        sock.close()
    if sent != count:
        raise RuntimeError(f"pressure burst sent {sent} of {count} datagrams")
    pause(settle)
    print(
        f"UDP pressure probe sent {sent} paced datagrams ({payload_bytes} bytes each) "
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

    for command in (dns, ntp):
        command.add_argument("--run-uuid", required=True)
        command.add_argument("--probe-label", choices=PROBE_LABELS, required=True)
        command.add_argument("--result-file", required=True)

    verify = subparsers.add_parser("verify-receipt")
    verify.add_argument("path")
    verify.add_argument("--run-uuid", required=True)
    verify.add_argument("--probe-label", choices=PROBE_LABELS, required=True)
    verify.add_argument("--source-pid", type=int, required=True)
    verify.add_argument("--endpoint", required=True)
    verify.add_argument("--exit-code", type=int, required=True)

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
        dns_query(args.server, args.name, args.timeout, args.expect_no_response,
                  run_uuid=args.run_uuid, probe_label=args.probe_label, result_file=args.result_file)
    elif args.command == "ntp":
        ntp_query(args.server, args.timeout, run_uuid=args.run_uuid,
                  probe_label=args.probe_label, result_file=args.result_file)
    elif args.command == "verify-receipt":
        result = replay_probe_receipt(read_probe_receipt(args.path), args.run_uuid,
                                      args.probe_label, args.source_pid, args.endpoint)
        if result != args.exit_code:
            raise ValueError("UDP probe receipt disagrees with the joined child exit")
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
