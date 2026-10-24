"""Exercise real decoded frames, their Upgrade identity and shared text contract."""

from copy import deepcopy
from dataclasses import replace
import json
from pathlib import Path
import unittest
import xml.etree.ElementTree as ET

from flow_bodies import WEBSOCKET_PROBE, check_websocket_messages
from wire import HeaderBlock, h1_websocket_evidence

FIXTURE = Path(__file__).parent / "tests/fixtures/websocket.pdml"
PORT = 65320
UPGRADE = HeaderBlock(
    "h1",
    56,
    4,
    56,
    False,
    ((":method", "GET"), (":path", "/api/ws")),
)


def changed_field(packet, name, value):
    field = next(field for field in packet.iter("field") if field.get("name") == name)
    field.set("show", value)


class WebSocketWireTests(unittest.TestCase):
    def test_page_probe_is_checked_in_actual_decoded_h1_frames(self):
        root = ET.fromstring(FIXTURE.read_bytes())
        probe = WEBSOCKET_PROBE + " #" + "cd" * 16
        for field in root.iter("field"):
            if (
                field.get("name") == "websocket.payload.text"
                and field.get("show") == WEBSOCKET_PROBE
            ):
                field.set("show", probe)
        data = ET.tostring(root)
        report = h1_websocket_evidence(data, PORT, [UPGRADE], websocket_probe=probe)
        self.assertEqual(report["close_frames_checked"], 2)
        with self.assertRaisesRegex(ValueError, "round trip"):
            h1_websocket_evidence(
                data, PORT, [UPGRADE], websocket_probe=probe + "other"
            )

    def test_same_text_contract_for_every_http_version(self):
        versions = (("h1", "HTTP/1.1"), ("h2", "HTTP/2.0"), ("h3", "HTTP/3.0"))
        for protocol, version in versions:
            greeting = json.dumps(dict(initiator="ws", version=version))
            with self.subTest(protocol=protocol):
                check_websocket_messages(
                    protocol,
                    [WEBSOCKET_PROBE],
                    [greeting, WEBSOCKET_PROBE],
                )
                with self.assertRaisesRegex(ValueError, "echo differs"):
                    check_websocket_messages(
                        protocol,
                        [WEBSOCKET_PROBE],
                        [greeting, "wrong"],
                    )

    def test_actual_decoded_frames_cover_both_directions_and_normal_closes(self):
        report = h1_websocket_evidence(FIXTURE.read_bytes(), PORT, [UPGRADE])
        self.assertEqual(report["connections_checked"], 1)
        self.assertEqual(report["client_messages_checked"], 1)
        self.assertEqual(report["server_messages_checked"], 2)
        self.assertEqual(report["close_frames_checked"], 2)

    def test_multiple_variants_cannot_hide_a_missing_exchange(self):
        root = ET.fromstring(FIXTURE.read_bytes())
        for original in list(root.findall("packet")):
            packet = deepcopy(original)
            changed_field(packet, "tcp.stream", "9")
            number = next(
                f for f in packet.iter("field") if f.get("name") == "frame.number"
            )
            number.set("show", str(int(number.get("show")) + 100))
            root.append(packet)
        upgrades = [UPGRADE, replace(UPGRADE, packet=156, connection=9, stream=156)]
        data = ET.tostring(root)
        report = h1_websocket_evidence(data, PORT, upgrades, expected_connections=2)
        self.assertEqual(report["connections_checked"], 2)
        root.remove(root.findall("packet")[-1])
        with self.assertRaisesRegex(ValueError, "close missing"):
            h1_websocket_evidence(
                ET.tostring(root), PORT, upgrades, expected_connections=2
            )
        with self.assertRaisesRegex(ValueError, "connection count"):
            h1_websocket_evidence(data, PORT, upgrades)

    def test_invalid_messages_and_transport_identity_are_rejected(self):
        cases = [
            (
                0,
                "websocket.payload.text",
                '{"initiator":"ws","version":"HTTP/3.0"}',
                "greeting",
            ),
            (2, "websocket.payload.text", "wrong", "echo differs"),
            (1, "websocket.payload.text", "wrong", "round trip"),
            (1, "websocket.mask", "False", "masking direction"),
            (0, "websocket.mask", "True", "masking direction"),
            (1, "websocket.fin", "False", "fragmented"),
            (1, "websocket.opcode", "2", "opcode"),
            (4, "websocket.payload.close.status_code", "1001", "not normal"),
            (1, "tcp.stream", "9", "no Upgrade"),
            (1, "frame.number", "55", "precedes"),
            (1, "tcp.srcport", str(PORT), "ambiguous.*endpoint"),
            (0, "tcp.srcport", "1", "ambiguous.*endpoint"),
        ]
        for index, name, value, message in cases:
            with self.subTest(name=name, value=value):
                root = ET.fromstring(FIXTURE.read_bytes())
                changed_field(root.findall("packet")[index], name, value)
                with self.assertRaisesRegex(ValueError, message):
                    h1_websocket_evidence(ET.tostring(root), PORT, [UPGRADE])

    def test_missing_duplicate_and_late_frames_are_rejected(self):
        missing_frames = (
            (0, "round trip"),
            (1, "round trip"),
            (2, "round trip"),
            (3, "close missing"),
            (4, "close missing"),
        )
        for index, expected in missing_frames:
            with self.subTest(missing=index):
                root = ET.fromstring(FIXTURE.read_bytes())
                root.remove(root.findall("packet")[index])
                with self.assertRaisesRegex(ValueError, expected):
                    h1_websocket_evidence(ET.tostring(root), PORT, [UPGRADE])
        for index in range(5):
            with self.subTest(duplicate=index):
                root = ET.fromstring(FIXTURE.read_bytes())
                root.append(deepcopy(root.findall("packet")[index]))
                with self.assertRaisesRegex(ValueError, "follows its close"):
                    h1_websocket_evidence(ET.tostring(root), PORT, [UPGRADE])

    def test_upgrade_count_and_identity_are_required(self):
        data = FIXTURE.read_bytes()
        for requests, expected in (([], 1), ([UPGRADE, UPGRADE], 2), ([UPGRADE], 0)):
            with self.subTest(expected=expected):
                with self.assertRaisesRegex(ValueError, "connection"):
                    h1_websocket_evidence(
                        data,
                        PORT,
                        requests,
                        expected_connections=expected,
                    )
        with self.assertRaisesRegex(ValueError, "expected one tcp.stream"):
            root = ET.fromstring(data)
            packet = root.findall("packet")[0]
            packet.append(
                deepcopy(
                    next(
                        f for f in packet.iter("field") if f.get("name") == "tcp.stream"
                    )
                )
            )
            h1_websocket_evidence(ET.tostring(root), PORT, [UPGRADE])
