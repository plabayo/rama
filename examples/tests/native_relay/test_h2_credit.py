"""Mutate actual decoded H2 legs to verify the initial-credit wire boundary."""

from copy import deepcopy
import json
from pathlib import Path
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

from comparison import compare_legs
import h2_credit
from h2_credit import compare_initial_credit, initial_credit

FIXTURES = Path(__file__).parent / "tests/fixtures"
PORT = json.loads((FIXTURES / "http-contract-captures.json").read_text())["h2"][
    "ports"
]["ingress"]
ORIGINAL = (FIXTURES / "h2-ingress.pdml").read_bytes()


def field(node, name):
    return next(child for child in node if child.get("name") == name)


def literal(node, name):
    value = field(node, name)
    return int.from_bytes(
        bytes.fromhex(value.get("unmaskedvalue", value.get("value"))), "big"
    )


def put(node, name, value, size):
    child = field(node, name)
    child.set("value", value.to_bytes(size, "big").hex())
    child.set("unmaskedvalue", value.to_bytes(size, "big").hex())
    child.set("size", str(size))


def records(root, kind=None, role=None):
    result = []
    for packet in root.findall("packet"):
        for frame in packet.iter("field"):
            if frame.get("name") != "http2.stream" or not any(
                child.get("name") == "http2.type" for child in frame
            ):
                continue
            source = literal(packet.find("proto[@name='tcp']"), "tcp.srcport")
            sender = "server" if source == PORT else "client"
            if (kind is None or literal(frame, "http2.type") == kind) and (
                role is None or sender == role
            ):
                result.append((packet, frame))
    return result


def shift(node, amount):
    for item in node.iter():
        if item.get("pos") is not None:
            item.set("pos", str(int(item.get("pos")) + amount))


def parents(root):
    return {child: parent for parent in root.iter() for child in parent}


def extra_frame(kind, flags, stream, payload, *, position=0):
    frame = ET.Element(
        "field", name="http2.stream", pos=str(position), size=str(9 + len(payload))
    )
    for name, value, size, offset in [
        ("length", len(payload), 3, 0),
        ("type", kind, 1, 3),
        ("flags", flags, 1, 4),
        ("streamid", stream, 4, 5),
    ]:
        ET.SubElement(
            frame,
            "field",
            name="http2." + name,
            pos=str(position + offset),
            size=str(size),
            value=value.to_bytes(size, "big").hex(),
            show=str(value),
        )
    name = {
        0: "http2.data.data",
        8: "http2.window_update.window_size_increment",
        9: "http2.continuation.header",
    }[kind]
    ET.SubElement(
        frame,
        "field",
        name=name,
        pos=str(position + 9),
        size=str(len(payload)),
        value=payload.hex(),
    )
    return frame


def split_update(root):
    _, original = records(root, 8, "client")[0]
    amount = (
        literal(original, "http2.window_update.window_size_increment")
        & h2_credit.MAX_WINDOW
    )
    clone = deepcopy(original)
    put(original, "http2.window_update.window_size_increment", amount - 17, 4)
    put(clone, "http2.window_update.window_size_increment", 17, 4)
    shift(clone, 13)
    parent = parents(root)[original]
    parent.insert(list(parent).index(original) + 1, clone)
    parent.set("size", str(int(parent.get("size")) + 13))
    return clone


def split_head(root):
    packet, original = records(root, 1, "client")[0]
    raw = field(original, "http2.headers")
    data = bytes.fromhex(raw.get("value"))
    cut = 7
    flags = literal(original, "http2.flags")
    continuation = extra_frame(
        9,
        4,
        literal(original, "http2.streamid"),
        data[cut:],
        position=int(original.get("pos")) + cut + 9,
    )
    for child in list(original):
        if child.get("name") not in {
            "http2.length",
            "http2.type",
            "http2.flags",
            "http2.r",
            "http2.streamid",
            "http2.pad_length",
            "http2.headers",
        }:
            original.remove(child)
            continuation.append(child)
    put(original, "http2.length", cut, 3)
    put(original, "http2.flags", flags & ~4, 1)
    original.set("size", str(cut + 9))
    raw.set("value", data[:cut].hex())
    raw.set("size", str(cut))
    parent = parents(root)[original]
    parent.insert(list(parent).index(original) + 1, continuation)
    parent.set("size", str(int(parent.get("size")) + 9))
    return packet, original, continuation


def with_request_data(root, payload, *, update_after_data):
    packet, head = records(root, 1, "client")[0]
    put(head, "http2.flags", literal(head, "http2.flags") & ~1, 1)
    proto = ET.SubElement(packet, "proto", name="http2")
    proto.append(extra_frame(0, 1, 1, payload))
    if update_after_data:
        _, update = records(root, 8, "server")[0]
        parents(root)[update].remove(update)
        response_packet, response = records(root, 1, "server")[0]
        proto = ET.Element("proto", name="http2")
        shift(update, -int(update.get("pos")))
        proto.append(update)
        response_packet.insert(
            list(response_packet).index(parents(root)[response]), proto
        )


class H2InitialCreditTests(unittest.TestCase):
    def test_real_http_and_websocket_legs_report_each_role_and_boundary(self):
        self.assertEqual(
            initial_credit(ORIGINAL, PORT)["roles"]["client"]["target"],
            65535 + (1 << 30),
        )
        self.assertEqual(
            initial_credit(ORIGINAL, PORT)["roles"]["server"]["target"], 1 << 20
        )
        metadata = json.loads((FIXTURES / "websocket-metadata.json").read_text())["h2"]
        report = compare_initial_credit(
            *[
                (FIXTURES / f"websocket-h2-{side}.pdml").read_bytes()
                for side in ("ingress", "egress")
            ],
            metadata["ingress"],
            metadata["egress"],
        )
        self.assertFalse(report["h2_initial_credit_match"])
        for leg in report["h2_initial_credit"].values():
            for role in ("client", "server"):
                self.assertEqual(leg["roles"][role]["window_updates"], 1)
                self.assertEqual(leg["roles"][role]["boundary"]["stream"], 1)

    def test_actual_http_credit_difference_controls_fingerprint_boolean(self):
        root = ET.fromstring(ORIGINAL)
        _, update = records(root, 8, "client")[0]
        put(update, "http2.window_update.window_size_increment", 3, 4)
        fresh = [
            {"randoms": {"a"}, "shares": {"b"}},
            {"randoms": {"c"}, "shares": {"d"}},
        ]
        with patch("comparison.fresh_values", side_effect=fresh):
            report = compare_legs(
                ORIGINAL, ET.tostring(root), "h2", PORT, PORT, b"external-relay-body"
            )
        self.assertTrue(report["tls_fingerprint_match"])
        self.assertTrue(report["exact_header_wire_match"])
        self.assertTrue(report["h2_settings_match"])
        self.assertTrue(report["bodies_and_trailers_match"])
        self.assertFalse(report["h2_initial_credit_match"])
        self.assertFalse(report["fingerprint_match"])

    def test_literal_octets_ignore_display_and_mask_reserved_increment_bit(self):
        root = ET.fromstring(ORIGINAL)
        _, update = records(root, 8, "client")[0]
        value = field(update, "http2.window_update.window_size_increment")
        value.set("show", "7")
        field(update, "http2.type").set("show", "99")
        field(update, "http2.streamid").set("show", "999")
        put(update, "http2.window_update.window_size_increment", 0xC0000000, 4)
        expected = initial_credit(ORIGINAL, PORT)
        self.assertEqual(initial_credit(ET.tostring(root), PORT), expected)
        put(update, "http2.window_update.window_size_increment", 0xBFFFFFFF, 4)
        changed = initial_credit(ET.tostring(root), PORT)
        self.assertEqual(
            changed["roles"]["client"]["target"],
            expected["roles"]["client"]["target"] - 1,
        )

    def test_multiple_increments_compare_targets_not_frame_counts(self):
        root = ET.fromstring(ORIGINAL)
        split_update(root)
        report = compare_initial_credit(ORIGINAL, ET.tostring(root), PORT, PORT)
        self.assertTrue(report["h2_initial_credit_match"])
        self.assertEqual(
            report["h2_initial_credit"]["egress"]["roles"]["client"]["window_updates"],
            2,
        )
        self.assertEqual(
            report["h2_initial_credit"]["ingress"]["roles"]["client"]["window_updates"],
            1,
        )

    def test_native_connection_ids_differ_but_mixed_connection_is_refused(self):
        root = ET.fromstring(ORIGINAL)
        for packet in root.findall("packet"):
            for node in packet.iter("field"):
                if node.get("name") == "tcp.stream":
                    node.set("show", "99")
        self.assertTrue(
            compare_initial_credit(ORIGINAL, ET.tostring(root), PORT, PORT)[
                "h2_initial_credit_match"
            ]
        )
        packet, _ = records(root, 8, "client")[0]
        field(packet.find("proto[@name='tcp']"), "tcp.stream").set("show", "100")
        with self.assertRaisesRegex(ValueError, "mixed H2 credit connections"):
            initial_credit(ET.tostring(root), PORT)

    def test_literal_ports_determine_role_and_bind_the_peer(self):
        root = ET.fromstring(ORIGINAL)
        packet, _ = records(root, 8, "client")[0]
        tcp = packet.find("proto[@name='tcp']")
        field(tcp, "tcp.srcport").set("show", str(PORT))
        field(tcp, "tcp.dstport").set("show", "9")
        self.assertEqual(
            initial_credit(ET.tostring(root), PORT), initial_credit(ORIGINAL, PORT)
        )
        client = literal(tcp, "tcp.srcport")
        put(tcp, "tcp.srcport", PORT, 2)
        put(tcp, "tcp.dstport", client, 2)
        with self.assertRaisesRegex(ValueError, "preface"):
            initial_credit(ET.tostring(root), PORT)
        put(tcp, "tcp.srcport", client + 1, 2)
        put(tcp, "tcp.dstport", PORT, 2)
        with self.assertRaisesRegex(ValueError, "mixed H2 credit connections"):
            initial_credit(ET.tostring(root), PORT)

    def test_split_headers_finish_only_at_continuation_end_headers(self):
        root = ET.fromstring(ORIGINAL)
        _, original, continuation = split_head(root)
        result = initial_credit(ET.tostring(root), PORT)
        self.assertEqual(result["roles"]["client"]["target"], 65535 + (1 << 30))
        self.assertEqual(result["roles"]["client"]["boundary"]["continuations"], 1)
        put(continuation, "http2.streamid", 3, 4)
        with self.assertRaisesRegex(ValueError, "swapped initial HEADERS"):
            initial_credit(ET.tostring(root), PORT)
        put(continuation, "http2.streamid", 1, 4)
        put(continuation, "http2.flags", 0, 1)
        with self.assertRaises(ValueError):
            initial_credit(ET.tostring(root), PORT)
        self.assertFalse(literal(original, "http2.flags") & 4)

    def test_interleaved_update_cannot_finish_an_incomplete_headers_block(self):
        root = ET.fromstring(ORIGINAL)
        _, original, continuation = split_head(root)
        parent = parents(root)[continuation]
        update = extra_frame(
            8, 0, 0, (1).to_bytes(4, "big"), position=int(continuation.get("pos"))
        )
        parent.insert(list(parent).index(continuation), update)
        with self.assertRaisesRegex(ValueError, "interleaved"):
            initial_credit(ET.tostring(root), PORT)

    def test_later_connection_growth_does_not_change_the_initial_target(self):
        root = ET.fromstring(ORIGINAL)
        packet, head = records(root, 1, "client")[0]
        proto = ET.SubElement(packet, "proto", name="http2")
        proto.append(extra_frame(8, 0, 0, (99).to_bytes(4, "big")))
        self.assertEqual(
            initial_credit(ET.tostring(root), PORT), initial_credit(ORIGINAL, PORT)
        )

    def test_opposite_role_data_makes_following_credit_ambiguous(self):
        root = ET.fromstring(ORIGINAL)
        with_request_data(root, b"x", update_after_data=True)
        with self.assertRaisesRegex(ValueError, "opposite-role DATA"):
            initial_credit(ET.tostring(root), PORT)
        root = ET.fromstring(ORIGINAL)
        with_request_data(root, b"", update_after_data=True)
        self.assertEqual(
            initial_credit(ET.tostring(root), PORT)["roles"]["server"]["target"],
            1 << 20,
        )
        root = ET.fromstring(ORIGINAL)
        with_request_data(root, b"x", update_after_data=False)
        self.assertEqual(
            initial_credit(ET.tostring(root), PORT)["roles"]["server"]["target"],
            1 << 20,
        )

    def test_zero_overflow_and_wrong_update_extent_are_refused(self):
        for change in ("zero", "overflow", "length", "missing", "ambiguous"):
            with self.subTest(change=change):
                root = ET.fromstring(ORIGINAL)
                _, update = records(root, 8, "client")[0]
                if change == "zero":
                    put(
                        update,
                        "http2.window_update.window_size_increment",
                        0x80000000,
                        4,
                    )
                elif change == "overflow":
                    clone = split_update(root)
                    put(
                        clone,
                        "http2.window_update.window_size_increment",
                        h2_credit.MAX_WINDOW,
                        4,
                    )
                elif change == "length":
                    put(update, "http2.length", 3, 3)
                elif change == "missing":
                    update.remove(
                        field(update, "http2.window_update.window_size_increment")
                    )
                else:
                    update.append(
                        deepcopy(
                            field(update, "http2.window_update.window_size_increment")
                        )
                    )
                with self.assertRaises(ValueError):
                    initial_credit(ET.tostring(root), PORT)

    def test_missing_headers_role_and_preface_are_not_complete_sources(self):
        for remove in ("server-heads", "preface", "header-bytes", "decoded-headers"):
            with self.subTest(remove=remove):
                root = ET.fromstring(ORIGINAL)
                if remove == "preface":
                    node = next(
                        x for x in root.iter("field") if x.get("name") == "http2.magic"
                    )
                    parents(root)[node].remove(node)
                else:
                    for _, head in records(root, 1, "server"):
                        if remove == "server-heads":
                            parents(root)[head].remove(head)
                        elif remove == "header-bytes":
                            head.remove(field(head, "http2.headers"))
                        else:
                            for node in list(head):
                                if node.get("name") == "http2.header":
                                    head.remove(node)
                with self.assertRaises(ValueError):
                    initial_credit(ET.tostring(root), PORT)

    def test_capture_ending_before_server_headers_is_incomplete(self):
        root = ET.fromstring(ORIGINAL)
        server_head, _ = records(root, 1, "server")[0]
        first_server_packet = int(
            next(
                node.get("show")
                for node in server_head.iter("field")
                if node.get("name") == "frame.number"
            )
        )
        for packet in list(root):
            number = int(
                next(
                    node.get("show")
                    for node in packet.iter("field")
                    if node.get("name") == "frame.number"
                )
            )
            if number >= first_server_packet:
                root.remove(packet)
        with self.assertRaisesRegex(ValueError, "incomplete H2 credit source roles"):
            initial_credit(ET.tostring(root), PORT)

    def test_frame_budget_and_unknown_native_frame_fail_closed(self):
        with patch.object(h2_credit, "MAX_FRAMES", 1):
            with self.assertRaisesRegex(ValueError, "frame limit"):
                initial_credit(ORIGINAL, PORT)
        root = ET.fromstring(ORIGINAL)
        _, update = records(root, 8, "client")[0]
        update.remove(field(update, "http2.type"))
        with self.assertRaisesRegex(ValueError, "http2.type"):
            initial_credit(ET.tostring(root), PORT)


if __name__ == "__main__":
    unittest.main()
