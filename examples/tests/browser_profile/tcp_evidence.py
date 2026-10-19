"""Bounded TCP/TLS capture accounting, separate from browser attribution.

Native TLS-follow supplies the application-byte witness. Native PDML supplies
record decryption and HTTP/2 frame boundaries. Neither alone proves completeness.
This deliberately supports TLS 1.3 without application-record padding; other
record formats remain inconclusive rather than being silently excluded.
"""

from collections import defaultdict
from copy import copy
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import subprocess
import tempfile

from connection_fields import integer
from flows import require
from tls_wire import byte_span, identity
from wire import MAX_CAPTURE_BYTES, http_decode_args, pdml_packets, values

MAX_TCP_CONNECTIONS = 16
MAX_FOLLOW_BYTES = 2 * MAX_CAPTURE_BYTES + 4096
PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


def field_bytes(node):
    raw = bytes.fromhex(node.get("value", ""))
    require(len(raw) == int(node.get("size", "-1")), "native byte extent differs")
    return raw


def fields(node, name):
    return [field for field in node.iter("field") if field.get("name") == name]


def scalar(node, name):
    found = fields(node, name)
    require(len(found) == 1, "ambiguous native " + name)
    return found[0]


def endpoint(packet, side):
    addresses = set(values(packet, "ip." + side) + values(packet, "ipv6." + side))
    require(len(addresses) == 1, "ambiguous TCP endpoint address")
    return str(ipaddress.ip_address(addresses.pop())), identity(
        packet, "tcp." + side + "port"
    )


def tls_follow(text, expected, stream):
    """Bind native follow directions to both independently captured endpoints."""
    require(len(text) <= MAX_FOLLOW_BYTES, "TLS-follow byte budget")
    parts, nodes = {0: bytearray(), 1: bytearray()}, {}
    for line in text.splitlines():
        node = re.fullmatch(r"Node ([01]): (.+):(\d+)", line)
        if node:
            key = int(node[1])
            require(key not in nodes, "duplicate TLS-follow endpoint")
            nodes[key] = str(ipaddress.ip_address(node[2].strip("[]"))), int(node[3])
        elif re.fullmatch(r"\t?(?:[0-9a-fA-F]{2})+", line):
            parts[int(line.startswith("\t"))].extend(bytes.fromhex(line.strip()))
        else:
            require(
                line
                in {
                    "",
                    "Follow: tls,raw",
                    "=" * 67,
                    "Filter: tls.stream eq " + str(stream),
                    "Filter: tcp.stream eq " + str(stream),
                },
                "unexpected TLS-follow output",
            )
    require(
        set(nodes) == {0, 1} and set(nodes.values()) == set(expected),
        "TLS-follow endpoints differ",
    )
    server = next(index for index in nodes if nodes[index] == expected[1])
    return {False: bytes(parts[1 - server]), True: bytes(parts[server])}


def inventory(data, port):
    """Retain every target-port TCP packet, including undecoded payloads."""
    grouped = defaultdict(list)
    total = 0
    for packet in pdml_packets(data):
        if not values(packet, "tcp.stream"):
            continue
        src, dst = endpoint(packet, "src"), endpoint(packet, "dst")
        if port not in (src[1], dst[1]):
            continue
        require((src[1] == port) != (dst[1] == port), "ambiguous TCP server endpoint")
        size = identity(packet, "tcp.len")
        raw_fields = fields(packet, "tcp.payload")
        require(len(raw_fields) == bool(size), "missing or ambiguous TCP payload")
        raw = field_bytes(raw_fields[0]) if size else b""
        require(len(raw) == size, "truncated TCP payload")
        total += size
        require(total <= MAX_CAPTURE_BYTES, "TCP payload byte budget")
        require(
            identity(packet, "frame.cap_len") == identity(packet, "frame.len"),
            "truncated captured TCP packet",
        )
        flags = int(scalar(packet, "tcp.flags").get("show", ""), 0)
        grouped[identity(packet, "tcp.stream")].append(
            dict(
                packet=packet,
                number=identity(packet, "frame.number"),
                side=src[1] == port,
                peer=(dst, src) if src[1] == port else (src, dst),
                sequence=identity(packet, "tcp.seq"),
                raw=raw,
                position=int(raw_fields[0].get("pos")) if size else 0,
                flags=flags,
            )
        )
    require(len(grouped) <= MAX_TCP_CONNECTIONS, "TCP connection budget")
    return grouped


def reassemble(rows, side):
    selected = [row for row in rows if row["side"] == side]
    syn = [row for row in selected if row["flags"] & 2]
    require(
        syn and all(row["sequence"] == 0 and not row["raw"] for row in syn),
        "TCP capture lacks initial SYN",
    )
    result = bytearray()
    for row in sorted(
        (row for row in selected if row["raw"]), key=lambda row: row["sequence"]
    ):
        offset, raw = row["sequence"] - 1, row["raw"]
        require(0 <= offset <= len(result), "TCP payload sequence gap")
        overlap = min(len(raw), len(result) - offset)
        require(
            result[offset : offset + overlap] == raw[:overlap],
            "conflicting TCP payload overlap",
        )
        result.extend(raw[overlap:])
    finals = {row["sequence"] + len(row["raw"]) for row in selected if row["flags"] & 1}
    require(not finals or finals == {len(result) + 1}, "TCP payload outside FIN extent")
    for reset in (row for row in selected if row["flags"] & 4):
        # A reset after half-close is a terminal TCP control, not evidence of
        # authenticated TLS closure. It must not conceal any later payload.
        require(
            not reset["raw"] and reset["flags"] in (4, 20),
            "reset carries payload or unsupported flags",
        )
        prior_fin = [
            row for row in rows if row["flags"] & 1 and row["number"] < reset["number"]
        ]
        own_fin = [row["number"] for row in prior_fin if row["side"] == side]
        require(prior_fin, "reset before an observed terminal FIN is inconclusive")
        # A closed endpoint answers a late peer ACK with RST.SEQ = SEG.ACK
        # (RFC 9293 §3.5.2); that exact captured ACK must follow our own FIN.
        late_acks = {
            identity(row["packet"], "tcp.ack")
            for row in rows
            if row["side"] != side
            and own_fin
            and min(own_fin) < row["number"] < reset["number"]
            and row["flags"] & 16
            and not row["flags"] & 4
        }
        require(
            reset["sequence"] == len(result) + 1 + bool(own_fin)
            or (
                reset["flags"] == 4
                and reset["sequence"] in late_acks
                and 1 <= reset["sequence"] <= len(result) + 2
            ),
            "reset is outside the captured terminal sequence extent",
        )
        require(
            not any(row["raw"] and row["number"] > reset["number"] for row in rows),
            "payload follows terminal reset",
        )
    return bytes(result), bool(finals)


def record_sources(row, rows, body):
    """Bind a native reassembly source to captured, contiguous TCP fragments."""
    packet = row["packet"]
    sources = fields(packet, "tcp.reassembled.data")
    if not sources:
        return None
    require(len(sources) == 1, "ambiguous native TCP reassembly source")
    source = field_bytes(sources[0])
    fragments = fields(packet, "tcp.segment")
    require(fragments, "native TCP reassembly lacks fragments")
    by_number = {item["number"]: item for item in rows}
    offset, start = 0, None
    for index, fragment in enumerate(fragments):
        size, position = int(fragment.get("size", "-1")), int(fragment.get("pos", "-1"))
        original = by_number.get(int(fragment.get("show", "-1")))
        require(
            original is not None and original["side"] == row["side"],
            "native fragment source differs",
        )
        require(
            position == offset and 0 < size <= len(original["raw"]),
            "native fragment extent differs",
        )
        within = len(original["raw"]) - size if index == 0 else 0
        absolute = original["sequence"] - 1 + within
        if start is None:
            start = absolute
        require(absolute == start + offset, "native fragments are not contiguous")
        require(
            source[offset : offset + size] == original["raw"][within : within + size],
            "native fragment bytes differ",
        )
        offset += size
    require(
        offset == len(source) and body[start : start + offset] == source,
        "native reassembly source differs",
    )
    return start


def decoded_records(rows, bodies):
    records = {}
    for row in rows:
        side, packet = row["side"], row["packet"]
        reassembled = record_sources(row, rows, bodies[side])
        for proto in packet.findall("proto[@name='tls']"):
            base = (
                reassembled
                if int(proto.get("pos", "-1")) < row["position"]
                else row["sequence"] - 1 - row["position"]
            )
            for record in proto.findall("field[@name='tls.record']"):
                require(base is not None, "TLS record source is unresolved")
                offset = base + int(record.get("pos", "-1"))
                length = identity(record, "tls.record.length")
                raw = bodies[side][offset : offset + 5 + length]
                require(
                    len(raw) == 5 + length
                    and int(record.get("size", "-1")) == len(raw),
                    "TLS record extent differs",
                )
                require(
                    raw[1:3] in (b"\x03\x01", b"\x03\x03")
                    and int.from_bytes(raw[3:5], "big") == length,
                    "TLS record header differs",
                )
                kind = identity(record, "tls.record.content_type")
                if raw[0] == 23:
                    require(
                        identity(record, "tls.record.opaque_type") == 23
                        and kind in (21, 22, 23),
                        "protected TLS record is undecoded",
                    )
                    require(
                        fields(record, "tls.record.sequence_number"),
                        "TLS decryption sequence missing",
                    )
                else:
                    require(
                        raw[0] == kind and kind in (20, 22),
                        "unsupported clear TLS record",
                    )
                key = side, offset
                require(key not in records, "duplicate native TLS record extent")
                records[key] = length, kind, record
    return records


def h2_frame_bytes(frame):
    # Decoded HPACK fields use a different data source even when their numeric
    # offsets overlap the compressed frame. Its native raw block is http2.headers.
    source = copy(frame)
    source[:] = [
        child
        for child in frame
        if child.get("name", "").startswith("http2.")
        and child.get("name")
        not in {
            "http2.header",
            "http2.header.length",
            "http2.header.count",
            "http2.body.fragments",
        }
    ]
    return byte_span(source)


def frame_bytes(rows, side):
    return b"".join(
        h2_frame_bytes(frame)
        for row in rows
        if row["side"] == side
        for frame in fields(row["packet"], "http2.stream")
    )


def account_connection(rows, witness):
    require(len({row["peer"] for row in rows}) == 1, "conflicting TCP endpoints")
    bodies, closed = {}, {}
    for side in (False, True):
        bodies[side], closed[side] = reassemble(rows, side)
    records = decoded_records(rows, bodies)
    app_bytes, count = {False: 0, True: 0}, 0
    for side in (False, True):
        offset = 0
        while offset < len(bodies[side]):
            body = bodies[side]
            require(offset + 5 <= len(body), "truncated TLS record header")
            length = int.from_bytes(body[offset + 3 : offset + 5], "big")
            require(offset + 5 + length <= len(body), "truncated TLS record body")
            decoded = records.pop((side, offset), None)
            require(
                decoded is not None and decoded[0] == length,
                "TLS bytes lack native decoded record",
            )
            if body[offset] == 23 and decoded[1] == 23:
                require(length >= 17, "invalid TLS1.3 application record length")
                app_bytes[side] += (
                    length - 17
                )  # TLS1.3 supported AEAD tag + inner type.
            count += 1
            offset += 5 + length
    require(not records, "native TLS record lies outside TCP stream")
    hellos = [
        field
        for row in rows
        for field in fields(row["packet"], "tls.handshake")
        if values(field, "tls.handshake.type") == ["2"]
    ]
    require(
        len(hellos) == 1
        and integer(hellos[0], "tls.handshake.ciphersuite", 2)
        in (0x1301, 0x1302, 0x1303),
        "TLS record accounting requires selected TLS1.3 AEAD",
    )
    h2 = any(fields(row["packet"], "http2.stream") for row in rows)
    requests = set()
    for row in rows:
        for frame in fields(row["packet"], "http2.stream"):
            if fields(frame, "http2.magic"):
                require(
                    byte_span(frame) == PREFACE and not row["side"],
                    "invalid native H2 preface",
                )
                continue
            stream = integer(frame, "http2.streamid", 4, 0x7FFFFFFF)
            require(0 <= stream < 1 << 31, "invalid native H2 stream ID")
            if stream:
                requests.add(stream)
            else:
                kind = integer(frame, "http2.type", 1)
                length = integer(frame, "http2.length", 3)
                flags = integer(frame, "http2.flags", 1)
                require(kind in (4, 6, 7, 8), "unsupported stream-zero H2 control")
                require(
                    (kind == 4 and length % 6 == 0 and (not flags & 1 or length == 0))
                    or (kind == 6 and length == 8)
                    or (kind == 7 and length >= 8)
                    or (kind == 8 and length == 4),
                    "invalid stream-zero H2 control extent",
                )
    for side, name in ((False, "client"), (True, "server")):
        require(
            witness[name]["bytes"] == app_bytes[side],
            "TLS application witness is incomplete or padded",
        )
        if h2:
            raw = frame_bytes(rows, side)
            require(
                len(raw) == app_bytes[side]
                and hashlib.sha256(raw).hexdigest() == witness[name]["sha256"],
                "native H2 frames do not cover TLS application bytes",
            )
    requestless = h2 and not requests
    # Complete TLS accounting with no application byte proves no request was
    # carried; it does not attribute the connection to the browser.
    empty = not any(app_bytes.values())
    if empty:
        require(
            all(
                witness[name]["sha256"] == hashlib.sha256(b"").hexdigest()
                for name in ("client", "server")
            ),
            "TLS application witness is incomplete or padded",
        )
    require(
        not (requestless or empty) or all(closed.values()),
        "requestless connection lifetime is incomplete",
    )
    return dict(
        classification=(
            "unattributed_no_application_data"
            if empty
            else (
                "unattributed_requestless_controls"
                if requestless
                else "request_bearing_or_other_native_protocol"
            )
        ),
        provider_provenance=(
            "unknown" if requestless or empty else "not_attributed_by_tcp_accounting"
        ),
        tls_records=count,
        application_bytes=app_bytes[False] + app_bytes[True],
        native_h2_frames_complete=h2,
        requestless_h2=requestless,
        no_application_data=empty,
        closed_both_directions=all(closed.values()),
    )


def account_tcp(data, port, evidence):
    require(
        evidence.get("revision") == 1
        and evidence.get("source_pdml_sha256") == hashlib.sha256(data).hexdigest(),
        "TCP witness source differs",
    )
    rows = inventory(data, port)
    witnesses = evidence.get("connections")
    require(
        isinstance(witnesses, list) and len(witnesses) == len(rows),
        "TCP witness connection inventory differs",
    )
    by_connection = {item["connection"]: item for item in witnesses}
    require(
        len(by_connection) == len(witnesses) and set(by_connection) == set(rows),
        "ambiguous TCP witness connections",
    )
    details = []
    for connection, packets in rows.items():
        details.append(
            dict(
                connection=connection,
                **account_connection(packets, by_connection[connection])
            )
        )
    return dict(
        complete=True,
        source_pdml_sha256=evidence["source_pdml_sha256"],
        connections=details,
        scope="all captured TCP bytes have native TLS1.3 decryption evidence; H2 application bytes additionally have exhaustive native frame coverage; ordinary H1 message/Upgrade oracles remain separate",
    )


def write_tcp_evidence(capture, keylog, port, data, output):
    """Hash complete native application streams before private keys are deleted."""
    rows = inventory(data, port)
    connections = []
    for connection, packets in rows.items():
        streams = {
            value for row in packets for value in values(row["packet"], "tls.stream")
        }
        # Older tshark releases address TLS-follow with the TCP stream index.
        if not streams:
            streams = {str(connection)}
        require(len(streams) == 1, "TLS-follow stream is unresolved")
        stream = int(streams.pop())
        with tempfile.TemporaryFile() as temporary:
            subprocess.run(
                [
                    "tshark",
                    "-r",
                    str(capture),
                    *http_decode_args(port, keylog),
                    "-q",
                    "-z",
                    "follow,tls,raw," + str(stream),
                ],
                stdout=temporary,
                stderr=subprocess.PIPE,
                check=True,
                timeout=15,
            )
            require(temporary.tell() <= MAX_FOLLOW_BYTES, "TLS-follow byte budget")
            temporary.seek(0)
            parts = tls_follow(
                temporary.read().decode("ascii"), packets[0]["peer"], stream
            )
        connections.append(
            dict(
                connection=connection,
                **{
                    name: dict(
                        bytes=len(parts[side]),
                        sha256=hashlib.sha256(parts[side]).hexdigest(),
                    )
                    for side, name in ((False, "client"), (True, "server"))
                }
            )
        )
    evidence = dict(
        revision=1,
        source_pdml_sha256=hashlib.sha256(data).hexdigest(),
        connections=connections,
    )
    account_tcp(data, port, evidence)
    with Path(output).open("x") as destination:
        destination.write(json.dumps(evidence, indent=2) + "\n")
    return evidence
