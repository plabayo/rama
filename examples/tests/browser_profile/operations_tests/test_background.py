"""Independent traffic cannot borrow driver attribution or retained profile credit."""

from copy import deepcopy
from dataclasses import replace
import hashlib
import unittest
import xml.etree.ElementTree as ET

from admission import admit
from background import MAX_INDEPENDENT_BYTES, partition
from operations_tests.admission_fixtures import ORIGIN, admission_fixture
from wire import HeaderBlock, parse_pdml


def background_fixture():
    raw, rows, page = admission_fixture()
    document = ET.fromstring(raw)

    def packet(number, source, destination, stream, address):
        node = ET.SubElement(document, "packet")
        for name, value in (
            ("frame.number", number),
            ("tcp.srcport", source),
            ("tcp.dstport", destination),
            ("tcp.stream", stream),
            ("ip.src", address),
        ):
            ET.SubElement(node, "field", name=name, show=str(value))
        return node

    # The shared body fixture represents WS frames separately; add its source socket.
    packet(10, 52442, 32543, 0, "198.51.100.7")
    packet(200, 53123, 32543, 9, "203.0.113.9")
    final = packet(201, 32543, 53123, 9, "203.0.113.7")
    stream = ET.SubElement(final, "field", name="http2.stream")
    ET.SubElement(stream, "field", name="http2.flags", value="01", size="1", pos="0")
    ET.SubElement(stream, "field", name="http2.streamid", show="1")
    foreign = HeaderBlock(
        "h2",
        200,
        9,
        1,
        False,
        (
            (":method", "HEAD"),
            (":path", "/report"),
            (":scheme", "https"),
            (":authority", "h3.fp.ramaproxy.org:32543"),
            ("user-agent", "independent-claim"),
        ),
    )
    rows += [
        foreign,
        replace(foreign, packet=201, from_server=True, headers=((":status", "200"),)),
    ]
    inspected = {"profiles": [{"key": {"user_agent": page["user_agent"]}}]}
    return ET.tostring(document), rows, page, inspected


def append_h2_frame(
    document, stream, *, number=202, kind=0, payload=None, headers=(), server=False
):
    packet = ET.SubElement(document, "packet")
    for name, value in (
        ("frame.number", number),
        ("tcp.stream", 9),
        ("tcp.srcport", 32543 if server else 53123),
        ("tcp.dstport", 53123 if server else 32543),
        ("ip.src", "203.0.113.7" if server else "203.0.113.9"),
    ):
        ET.SubElement(packet, "field", name=name, show=str(value))
    protocol = ET.SubElement(packet, "proto", name="http2")
    frame = ET.SubElement(protocol, "field", name="http2.stream")
    for name, value in (
        ("http2.type", kind),
        ("http2.length", len(payload) if payload is not None else 0),
        ("http2.streamid", stream),
    ):
        ET.SubElement(frame, "field", name=name, show=str(value))
    if payload is not None:
        ET.SubElement(
            frame,
            "field",
            name="http2.data.data",
            value=payload.hex(),
            size=str(len(payload)),
        )
    for name, value in headers:
        header = ET.SubElement(frame, "field", name="http2.header")
        ET.SubElement(header, "field", name="http2.header.name", show=name)
        ET.SubElement(header, "field", name="http2.header.value", show=value)
    return frame


class IndependentObservationTests(unittest.TestCase):
    def test_explicit_independent_inventory_preserves_default_failure_and_owned_checks(
        self,
    ):
        raw, frames, page, inspected = background_fixture()
        with self.assertRaisesRegex(ValueError, "User-Agent"):
            admit(raw, frames, page, ORIGIN)
        owned, report, inventory = partition(raw, frames, page, ORIGIN, inspected)
        self.assertEqual(inventory, frozenset({("tcp", 9)}))
        self.assertEqual(
            len(
                admit(raw, owned, page, ORIGIN, independent_connections=inventory)[
                    "flows"
                ]
            ),
            6,
        )
        self.assertEqual(report["independent_requests"], 1)
        self.assertEqual(report["source_pdml_sha256"], hashlib.sha256(raw).hexdigest())
        observed = report["observations"][0]
        self.assertEqual(observed["classification"], "unattributed_independent")
        self.assertEqual(observed["provider_provenance"], "unknown")
        self.assertEqual(
            (
                observed["protocol"],
                observed["packet"],
                observed["stream"],
                observed["method"],
            ),
            ("h2", 200, 1, "HEAD"),
        )
        self.assertTrue(observed["response_complete"])
        self.assertEqual(
            observed["response_body_sha256"], hashlib.sha256(b"").hexdigest()
        )
        self.assertFalse(any(row.connection == 9 for row in owned))
        with self.assertRaisesRegex(ValueError, "undecoded"):
            admit(raw, owned, page, ORIGIN)

    def test_shared_connection_peer_or_retained_foreign_profile_cannot_be_partitioned(
        self,
    ):
        raw, frames, page, inspected = background_fixture()
        wrong = list(frames)
        wrong[-2] = replace(wrong[-2], connection=0)
        with self.assertRaisesRegex(ValueError, "connection"):
            partition(raw, wrong, page, ORIGIN, inspected)
        changed = ET.fromstring(raw)
        packet = next(
            p
            for p in changed
            if p.find("field[@name='frame.number'][@show='200']") is not None
        )
        packet.find("field[@name='ip.src']").set("show", "198.51.100.7")
        packet.find("field[@name='tcp.srcport']").set("show", "52442")
        with self.assertRaisesRegex(ValueError, "peer"):
            partition(ET.tostring(changed), frames, page, ORIGIN, inspected)
        foreign = deepcopy(inspected)
        foreign["profiles"].append({"key": {"user_agent": "independent-claim"}})
        with self.assertRaisesRegex(ValueError, "foreign profile"):
            partition(raw, frames, page, ORIGIN, foreign)

    def test_same_agent_extra_connection_never_becomes_independent_success(self):
        raw, frames, page, inspected = background_fixture()
        frames[-2] = replace(
            frames[-2],
            headers=tuple(
                (name, page["user_agent"] if name == "user-agent" else value)
                for name, value in frames[-2].headers
            ),
        )
        owned, report, inventory = partition(raw, frames, page, ORIGIN, inspected)
        self.assertIsNone(report)
        self.assertFalse(inventory)
        with self.assertRaisesRegex(ValueError, "additional source connection"):
            admit(raw, owned, page, ORIGIN, independent_connections=inventory)

    def test_incomplete_ambiguous_credentialed_or_unresolved_traffic_is_fatal(self):
        for mutation in (
            "end-stream",
            "duplicate-response",
            "credential",
            "requestless",
            "missing-agent",
        ):
            raw, frames, page, inspected = background_fixture()
            document = ET.fromstring(raw)
            if mutation == "end-stream":
                # Only alter the actual independent response's END_STREAM byte.
                response = next(
                    p
                    for p in document
                    if p.find("field[@name='frame.number'][@show='201']") is not None
                )
                response.find("field/field[@name='http2.flags']").set("value", "00")
            elif mutation == "duplicate-response":
                frames.append(frames[-1])
            elif mutation == "credential":
                frames[-2] = replace(
                    frames[-2],
                    headers=frames[-2].headers + (("authorization", "foreign"),),
                )
            elif mutation == "missing-agent":
                frames[-2] = replace(
                    frames[-2],
                    headers=tuple(
                        pair for pair in frames[-2].headers if pair[0] != "user-agent"
                    ),
                )
            else:
                extra = ET.SubElement(document, "packet")
                for name, value in (
                    ("frame.number", 300),
                    ("tcp.stream", 15),
                    ("tcp.dstport", 32543),
                    ("tcp.srcport", 54000),
                    ("ip.src", "203.0.113.15"),
                ):
                    ET.SubElement(extra, "field", name=name, show=str(value))
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                partition(ET.tostring(document), frames, page, ORIGIN, inspected)

    def test_independent_body_budget_is_not_a_way_to_hide_extra_bytes(self):
        raw, frames, page, inspected = background_fixture()
        for payload in (
            dict(data=b"x" * (MAX_INDEPENDENT_BYTES + 1)),
            dict(websocket_text=("x" * (MAX_INDEPENDENT_BYTES + 1),)),
        ):
            changed = frames[:-1] + [replace(frames[-1], **payload)]
            with self.subTest(payload=next(iter(payload))), self.assertRaisesRegex(
                ValueError, "byte budget"
            ):
                partition(raw, changed, page, ORIGIN, inspected)

    def test_native_orphan_data_and_response_only_streams_cannot_disappear(self):
        for server in (False, True):
            raw, frames, page, inspected = background_fixture()
            document = ET.fromstring(raw)
            append_h2_frame(document, 99, payload=b"abc", server=server)
            changed = ET.tostring(document)
            orphan = parse_pdml(
                changed, "h2", 32543, include_data=True, allow_empty=True
            )
            self.assertEqual(len(orphan), 1)
            self.assertEqual(orphan[0].data, b"abc")
            with self.subTest(server=server), self.assertRaisesRegex(
                ValueError, "decoded stream"
            ):
                partition(changed, frames + orphan, page, ORIGIN, inspected)

        raw, frames, page, inspected = background_fixture()
        document = ET.fromstring(raw)
        append_h2_frame(
            document, 99, kind=1, headers=((":status", "200"),), server=True
        )
        changed = ET.tostring(document)
        response = parse_pdml(changed, "h2", 32543, include_data=True, allow_empty=True)
        self.assertEqual(len(response), 1)
        self.assertTrue(response[0].from_server)
        with self.assertRaisesRegex(ValueError, "decoded stream"):
            partition(changed, frames + response, page, ORIGIN, inspected)

    def test_every_orphan_payload_counts_before_its_key_is_rejected(self):
        raw, frames, page, inspected = background_fixture()
        document = ET.fromstring(raw)
        # Native-sized DATA frames exceed the cumulative budget on one orphan stream.
        frame_bytes = 16384
        payloads = [b"x" * frame_bytes] * (MAX_INDEPENDENT_BYTES // frame_bytes) + [
            b"x"
        ]
        for offset, payload in enumerate(payloads):
            append_h2_frame(document, 99, number=202 + offset, payload=payload)
        changed = ET.tostring(document)
        orphan = parse_pdml(changed, "h2", 32543, include_data=True, allow_empty=True)
        self.assertEqual(
            sum(len(row.data) for row in orphan), MAX_INDEPENDENT_BYTES + 1
        )
        with self.assertRaisesRegex(ValueError, "body byte budget"):
            partition(changed, frames + orphan, page, ORIGIN, inspected)

    def test_undecoded_native_h2_streams_require_a_complete_request(self):
        for kind in (1, 3, 8):
            raw, frames, page, inspected = background_fixture()
            document = ET.fromstring(raw)
            append_h2_frame(document, 99, kind=kind)
            changed = ET.tostring(document)
            decoded = parse_pdml(
                changed, "h2", 32543, include_data=True, allow_empty=True
            )
            self.assertEqual(decoded, [])
            with self.subTest(kind=kind), self.assertRaisesRegex(
                ValueError, "native or undecoded stream"
            ):
                partition(changed, frames, page, ORIGIN, inspected)

    def test_native_h2_stream_zero_is_control_and_duplicate_requests_are_not_unique(
        self,
    ):
        raw, frames, page, inspected = background_fixture()
        document = ET.fromstring(raw)
        append_h2_frame(document, 0, kind=4)
        owned, report, _inventory = partition(
            ET.tostring(document), frames, page, ORIGIN, inspected
        )
        self.assertTrue(owned)
        self.assertEqual(report["independent_requests"], 1)
        with self.assertRaisesRegex(ValueError, "ambiguous independent request stream"):
            partition(raw, frames + [frames[-2]], page, ORIGIN, inspected)

    def test_independent_h1_and_h3_are_explicitly_unsupported(self):
        for protocol in ("h1", "h3"):
            for stream, payload in (
                (0, b"\x01\x02\0\0"),
                (2, b"\0\x04\0"),
                (3, b"\x01\0"),
            ):
                raw, frames, page, inspected = background_fixture()
                document = ET.fromstring(raw)
                if protocol == "h3":
                    for packet in document:
                        for field in packet.findall("field"):
                            name = field.get("name", "")
                            if name == "tcp.stream" and field.get("show") == "9":
                                field.set("name", "quic.connection.number")
                                for sibling in packet.findall("field"):
                                    if sibling.get("name", "").startswith("tcp."):
                                        sibling.set(
                                            "name",
                                            sibling.get("name").replace("tcp.", "udp."),
                                        )
                                native = ET.SubElement(
                                    packet, "field", name="quic.frame"
                                )
                                for name, value in (
                                    ("quic.frame_type", b"\x0b"),
                                    ("quic.stream.stream_id", bytes([stream])),
                                    ("quic.stream.length", bytes([len(payload)])),
                                    ("quic.stream_data", payload),
                                ):
                                    ET.SubElement(
                                        native,
                                        "field",
                                        name=name,
                                        value=value.hex(),
                                        size=str(len(value)),
                                        show=str(int.from_bytes(value, "big")),
                                        pos="0",
                                    )
                changed = [
                    (
                        replace(row, protocol=protocol, stream=stream)
                        if row.connection == 9
                        else row
                    )
                    for row in frames
                ]
                with self.subTest(
                    protocol=protocol, stream=stream
                ), self.assertRaisesRegex(
                    ValueError, "H1/H3 stream inventory is unsupported"
                ):
                    partition(ET.tostring(document), changed, page, ORIGIN, inspected)

    def test_only_the_exact_native_h2_preface_can_omit_a_stream_id(self):
        raw, frames, page, inspected = background_fixture()
        document = ET.fromstring(raw)
        preface = append_h2_frame(document, 0, kind=4)
        for field in list(preface):
            preface.remove(field)
        magic = ET.SubElement(
            preface,
            "field",
            name="http2.magic",
            size="24",
            value=b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".hex(),
        )
        owned, report, _inventory = partition(
            ET.tostring(document), frames, page, ORIGIN, inspected
        )
        self.assertTrue(owned)
        self.assertEqual(report["independent_requests"], 1)
        magic.set("value", (b"x" * 24).hex())
        with self.assertRaisesRegex(ValueError, "preface"):
            partition(ET.tostring(document), frames, page, ORIGIN, inspected)
        magic.set("value", b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".hex())
        ET.SubElement(preface, "field", name="http2.streamid", show="99")
        with self.assertRaisesRegex(ValueError, "preface"):
            partition(ET.tostring(document), frames, page, ORIGIN, inspected)

    def test_a_decoded_orphan_without_a_native_witness_still_cannot_be_dropped(self):
        raw, frames, page, inspected = background_fixture()
        orphan = replace(frames[-1], stream=99, headers=(), data=b"abc")
        with self.assertRaisesRegex(
            ValueError, "unattributed independent decoded stream"
        ):
            partition(raw, frames + [orphan], page, ORIGIN, inspected)
