"""Blocked QPACK heads require complete, same-connection native byte evidence."""

from copy import deepcopy
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

from qpack_bootstrap_wire import prefixed
from qpack_decode_wire import resolve_blocked_headers
from qpack_fields_wire import sections_from_wire
from wire import parse_pdml

CAPACITY = prefixed(128, 5, 0x20)
INSERT = b"\x41a\x01b"
DYNAMIC = b"\x02\x00\x80"


def field(parent, name, show="", payload=None):
    attributes = dict(name=name, show=str(show), pos="0", size="0")
    if payload is not None:
        attributes.update(value=payload.hex(), size=str(len(payload)))
    return ET.SubElement(parent, "field", attributes)


def packet(root, ordinal, connection=7):
    result = ET.SubElement(root, "packet")
    for name, value in (
        ("frame.number", ordinal),
        ("udp.srcport", 50000),
        ("udp.dstport", 443),
        ("quic.connection.number", connection),
    ):
        field(result, name, value)
    return result


def native_encoder(parent, payload, *, offset=0, stream=6):
    kind = 0x0E if offset else 0x0A
    result = field(parent, "quic.frame")
    field(result, "quic.frame_type", kind, bytes([kind]))
    field(result, "quic.stream.stream_id", stream, bytes([stream]))
    if offset:
        field(result, "quic.stream.offset", offset, bytes([offset]))
    field(result, "quic.stream.length", len(payload), bytes([len(payload)]))
    field(result, "quic.stream_data", payload=payload)
    result.set("size", str(3 + bool(offset) + len(payload)))
    return result


def encoder(parent, payload):
    return field(parent, "http3.qpack.encoder", payload=payload)


def head(parent, stream, payload, *, blocked=True, decoded=()):
    result = field(parent, "http3.frame")
    result.set("size", str(2 + len(payload)))
    field(result, "http3.frame_type", 1, b"\x01")
    field(result, "http3.frame_length", len(payload), bytes([len(payload)]))
    field(result, "http3.frame_streamid", stream)
    field(result, "http3.frame_payload", payload=payload)
    if blocked:
        field(result, "http3.header.qpack.blocked", 1)
    else:
        field(result, "http3.headers.count", len(decoded))
    for name, value in decoded:
        item = field(result, "http3.headers.header")
        field(item, "http3.header.header.name", name)
        field(item, "http3.headers.header.value", value)
    return result


def fixture():
    root = ET.Element("pdml")
    first = packet(root, 1)
    native_encoder(first, b"\x02" + CAPACITY)
    encoder(first, CAPACITY)
    head(packet(root, 2), 0, DYNAMIC)
    inserted = packet(root, 3)
    native_encoder(inserted, INSERT, offset=1 + len(CAPACITY))
    encoder(inserted, INSERT)
    head(
        packet(root, 4),
        4,
        b"\x00\x00\xd1",
        blocked=False,
        decoded=((":method", "GET"),),
    )
    return root


def resolve(root):
    return resolve_blocked_headers(root.findall("packet"), 443)


class BlockedQpackTests(unittest.TestCase):
    def test_later_encoder_resumes_original_packet_and_stream(self):
        result = resolve(fixture())
        self.assertEqual(result.recovered, {(2, 7, 0)})
        self.assertEqual(result.headers[(2, 7, 0)], (("a", "b"),))
        self.assertEqual(result.headers[(4, 7, 4)], ((":method", "GET"),))

    def test_shared_extractors_retain_decoder_provenance_and_raw_metadata(self):
        root = fixture()
        # DATA shares the recovered head's packet/stream but must not gain headers.
        data = field(root.findall("packet")[1], "http3.frame")
        field(data, "http3.frame_type", 0, b"\0")
        field(data, "http3.frame_streamid", 0)
        field(data, "http3.data", payload=b"payload")
        document = ET.tostring(root)
        frames = parse_pdml(document, "h3", 443, include_data=True)
        self.assertEqual(
            [(item.packet, item.stream, item.header_decoder) for item in frames],
            [(2, 0, "ls-qpack"), (2, 0, "tshark"), (4, 4, "tshark")],
        )
        self.assertEqual(frames[1].headers, ())
        metadata = sections_from_wire(document, 443)
        self.assertEqual(metadata[(2, 7, 0)].fields[0].representation, "DynamicIndex")
        self.assertEqual(metadata[(2, 7, 0)].fields[0].index, 0)

    def test_already_decoded_heads_must_agree_with_independent_decoder(self):
        root = fixture()
        root.find(".//field[@name='http3.headers.header.value']").set("show", "POST")
        with self.assertRaisesRegex(ValueError, "header mismatch"):
            resolve(root)

    def test_missing_heads_need_the_explicit_blocked_marker(self):
        root = fixture()
        first = root.findall("packet")[1]
        second = head(first, 8, DYNAMIC)
        original = first.find("field[@name='http3.frame']")
        original.remove(original.find("field[@name='http3.header.qpack.blocked']"))
        with self.assertRaisesRegex(ValueError, "header mismatch"):
            resolve(root)
        self.assertIsNotNone(second)

    def test_wrong_connection_encoder_cannot_unblock_a_request(self):
        root = fixture()
        for index in (0, 2):
            root.findall("packet")[index].find(
                "field[@name='quic.connection.number']"
            ).set("show", "8")
        with self.assertRaisesRegex(ValueError, "unresolved"):
            resolve(root)

    def test_missing_encoder_instruction_fails_instead_of_inventing_values(self):
        root = fixture()
        root.remove(root.findall("packet")[2])
        with self.assertRaisesRegex(ValueError, "unresolved"):
            resolve(root)

    def test_incomplete_raw_head_and_encoder_witnesses_fail(self):
        for name in ("http3.frame_payload", "http3.qpack.encoder"):
            root = fixture()
            value = root.find(".//field[@name='" + name + "']")
            value.set("size", str(int(value.get("size")) + 1))
            with self.subTest(name=name), self.assertRaisesRegex(
                ValueError, "incomplete raw"
            ):
                resolve(root)

    def test_native_encoder_bytes_and_retransmissions_must_agree(self):
        root = fixture()
        native = root.findall("packet")[2].find(".//field[@name='quic.stream_data']")
        native.set("value", INSERT[:-1].hex() + "63")
        with self.assertRaisesRegex(ValueError, "native witness"):
            resolve(root)
        root = fixture()
        native_encoder(root.findall("packet")[3], b"\x02\xff", offset=0)
        with self.assertRaisesRegex(ValueError, "conflicting"):
            resolve(root)

    def test_future_encoder_bytes_cannot_be_fed_before_native_packet(self):
        root = fixture()
        encoder(root.findall("packet")[0], INSERT)
        with self.assertRaisesRegex(ValueError, "precede their native witness"):
            resolve(root)

    def test_duplicate_head_identity_and_packet_reordering_fail(self):
        root = fixture()
        original = root.findall("packet")[1].find("field[@name='http3.frame']")
        root.findall("packet")[1].append(deepcopy(original))
        with self.assertRaisesRegex(ValueError, "ambiguous QPACK request"):
            resolve(root)
        root = fixture()
        root.findall("packet")[2].find("field[@name='frame.number']").set("show", "1")
        with self.assertRaisesRegex(ValueError, "nonchronological"):
            resolve(root)

    def test_decoding_limits_fail_closed(self):
        for limit, value in (
            ("MAX_FIELDS", 0),
            ("MAX_CONNECTIONS", 0),
            ("MAX_SECTIONS", 0),
            ("MAX_TOTAL_BYTES", 0),
            ("MAX_STREAM_BYTES", 3),
            ("MAX_STREAMS", 0),
        ):
            with self.subTest(limit=limit), patch("qpack_decode_wire." + limit, value):
                with self.assertRaisesRegex(ValueError, "limit"):
                    resolve(fixture())

    def test_native_encoder_gap_and_second_encoder_stream_fail(self):
        root = fixture()
        native_encoder(root.findall("packet")[3], b"\x00", offset=12)
        with self.assertRaisesRegex(ValueError, "gap"):
            resolve(root)
        root = fixture()
        native_encoder(root.findall("packet")[0], b"\x02" + CAPACITY, stream=10)
        with self.assertRaisesRegex(ValueError, "ambiguous native"):
            resolve(root)

    def test_blocked_stream_limit_is_per_connection(self):
        root = fixture()
        head(root.findall("packet")[1], 8, DYNAMIC)
        with patch("qpack_decode_wire.MAX_BLOCKED", 1):
            with self.assertRaisesRegex(ValueError, "limit|decoding failed"):
                resolve(root)

    def test_absent_blocking_does_not_change_other_protocol_extractors(self):
        root = ET.Element("pdml")
        self.assertEqual(resolve(root).headers, {})
        self.assertEqual(resolve(root).recovered, frozenset())


if __name__ == "__main__":
    unittest.main()
