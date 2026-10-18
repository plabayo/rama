"""Corrupt fresh, reduced loopback traces to exercise independent tunnel checks."""

import json
from pathlib import Path
import unittest

from wsproto import Connection, ConnectionType
from wsproto.events import BytesMessage, Ping

from websocket_probe import compare_streams, decode_messages, h1_streams, h2_streams

FIXTURES = Path(__file__).parent / "tests/fixtures"


class WebSocketProbeTests(unittest.TestCase):
    def streams(self, protocol, side):
        ports = json.loads((FIXTURES / "websocket-metadata.json").read_text())
        if protocol == "h1":
            return h1_streams(
                (FIXTURES / f"websocket-h1-{side}.txt").read_text(),
                ports[protocol][side],
            )
        return h2_streams(
            (FIXTURES / f"websocket-h2-{side}.pdml").read_bytes(),
            ports[protocol][side],
        )

    def test_native_tunnels_preserve_every_probe_and_frame_byte(self):
        for protocol in ("h1", "h2"):
            with self.subTest(protocol=protocol):
                result = compare_streams(
                    self.streams(protocol, "ingress"),
                    self.streams(protocol, "egress"),
                )
                self.assertTrue(result["byte_preservation"])
                self.assertGreater(
                    result["directions"]["client"]["ingress"]["fragmented_frames"], 0
                )

    def test_wrong_probe_text_is_rejected(self):
        data = self.streams("h1", "ingress")[True]
        corrupted = data.replace(
            b"hello from independent origin", b"jello from independent origin"
        )
        self.assertNotEqual(corrupted, data)
        with self.assertRaisesRegex(ValueError, "probe coverage or payload"):
            decode_messages(corrupted, True)

    def test_missing_binary_probe_is_rejected(self):
        data = self.streams("h2", "ingress")[True]
        frame = Connection(ConnectionType.SERVER).send(
            BytesMessage(data=bytes((0, 1, 127, 128, 254, 255)))
        )
        self.assertEqual(data.count(frame), 1)
        with self.assertRaisesRegex(ValueError, "probe coverage or payload"):
            decode_messages(data.replace(frame, b""), True)

    def test_truncated_close_is_rejected_in_both_directions(self):
        for protocol in ("h1", "h2"):
            for side, data in self.streams(protocol, "ingress").items():
                with self.subTest(protocol=protocol, from_server=side):
                    with self.assertRaises(ValueError):
                        decode_messages(data[:-1], side)

    def test_masking_role_is_enforced_independently(self):
        for side, data in self.streams("h2", "ingress").items():
            with self.subTest(from_server=side):
                with self.assertRaises(ValueError):
                    decode_messages(data, not side)

    def test_bytes_after_normal_close_are_rejected(self):
        data = self.streams("h1", "ingress")[True]
        extra = Connection(ConnectionType.SERVER).send(Ping(payload=b"late"))
        with self.assertRaisesRegex(ValueError, "bytes follow"):
            decode_messages(data + extra, True)

    def test_admission_limit_precedes_library_parsing(self):
        with self.assertRaisesRegex(ValueError, "stream byte limit"):
            decode_messages(b"x" * 65537, False)

    def test_a_valid_but_different_tunnel_is_not_called_preserved(self):
        ingress = self.streams("h1", "ingress")
        egress = self.streams("h2", "egress")
        # Client masking keys are fresh, although both logical exchanges pass.
        self.assertNotEqual(ingress[False], egress[False])
        with self.assertRaisesRegex(ValueError, "tunnel bytes differ"):
            compare_streams(ingress, egress)
