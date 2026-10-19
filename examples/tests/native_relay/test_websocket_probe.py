"""Corrupt fresh, reduced loopback traces to exercise independent tunnel checks."""

from contextlib import nullcontext
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from xml.etree import ElementTree

from wsproto import Connection, ConnectionType
from wsproto.events import BytesMessage, Ping

from identity import Identity
from websocket_probe import (
    compare_streams,
    decode_messages,
    h1_streams,
    multiplexed_streams,
    run_probe,
    tls_follow_index,
)

FIXTURES = Path(__file__).parent / "tests/fixtures"


class WebSocketProbeTests(unittest.TestCase):
    def streams(self, protocol, side):
        ports = json.loads((FIXTURES / "websocket-metadata.json").read_text())
        if protocol == "h1":
            return h1_streams(
                (FIXTURES / f"websocket-h1-{side}.txt").read_text(),
                ports[protocol][side],
            )
        return multiplexed_streams(
            (FIXTURES / f"websocket-{protocol}-{side}.pdml").read_bytes(),
            protocol,
            ports[protocol][side],
        )

    def test_native_tunnels_preserve_every_probe_and_frame_byte(self):
        for protocol in ("h1", "h2", "h3"):
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
        for protocol in ("h1", "h2", "h3"):
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


class TlsFollowIndexTests(unittest.TestCase):
    def packet(self):
        return next(
            packet
            for packet in ElementTree.fromstring(
                (FIXTURES / "h1-ingress.pdml").read_bytes()
            ).findall("packet")
            if any(field.get("name") == "tls.stream" for field in packet.iter("field"))
        )

    def test_tls_index_takes_precedence_over_tcp_numbering(self):
        packet = self.packet()
        for field in packet.iter("field"):
            if field.get("name") == "tls.stream":
                field.set("show", "7")
        self.assertEqual(tls_follow_index(packet), "7")

    def test_legacy_tcp_index_is_used_when_tls_index_is_unavailable(self):
        packet = self.packet()
        expected = next(
            field.get("show")
            for field in packet.iter("field")
            if field.get("name") == "tcp.stream"
        )
        for parent in packet.iter():
            for field in list(parent):
                if field.get("name") == "tls.stream":
                    parent.remove(field)
        self.assertEqual(tls_follow_index(packet), expected)

    def test_ambiguous_tls_index_is_rejected(self):
        packet = self.packet()
        ElementTree.SubElement(packet, "field", name="tls.stream", show="99")
        with self.assertRaisesRegex(ValueError, "ambiguous tunnel TLS stream"):
            tls_follow_index(packet)

    def test_missing_stream_identity_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "ambiguous tunnel TLS stream"):
            tls_follow_index(ElementTree.Element("packet"))


class WebSocketCreditIntegrationTests(unittest.TestCase):
    def test_actual_probe_recounts_separate_h2_capture_without_losing_functional_result(
        self,
    ):
        metadata = json.loads((FIXTURES / "websocket-metadata.json").read_text())["h2"]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args = SimpleNamespace(
                output=root,
                protocol="h2",
                quic_version=1,
                peer=Path("peer"),
                interface="lo",
            )
            authority = Identity(root / "ca.pem", root / "ca.key")

            def start(command, _log, _environment=None):
                (root / "websocket/wire.pcapng").write_bytes(b"owned capture")
                return nullcontext(Mock(returncode=0))

            def command(arguments, **kwargs):
                if arguments[0] == "peer":
                    return subprocess.CompletedProcess(arguments, 0)
                if arguments[0] == "tshark":
                    decode = arguments[arguments.index("-d") + 1]
                    side = "ingress" if str(metadata["ingress"]) in decode else "egress"
                    tree = ElementTree.fromstring(
                        (FIXTURES / f"websocket-h2-{side}.pdml").read_bytes()
                    )
                    if side == "egress":
                        increment = next(
                            field
                            for field in tree.iter("field")
                            if field.get("name")
                            == "http2.window_update.window_size_increment"
                        )
                        value = int(increment.get("unmaskedvalue"), 16) + 1
                        increment.set("unmaskedvalue", value.to_bytes(4, "big").hex())
                        increment.set("value", value.to_bytes(4, "big").hex())
                    kwargs["stdout"].write(ElementTree.tostring(tree))
                    return subprocess.CompletedProcess(arguments, 0)
                raise AssertionError(arguments)

            with patch("websocket_probe.running", side_effect=start), patch(
                "websocket_probe.wait_ready"
            ), patch("websocket_probe.subprocess.run", side_effect=command):
                report = run_probe(
                    args,
                    authority,
                    f"127.0.0.1:{metadata['ingress']}",
                    metadata["egress"],
                )
            self.assertTrue(report["byte_preservation"])
            self.assertIn("h2_initial_credit_match", report)
            self.assertFalse(report["h2_initial_credit_match"])
            self.assertEqual(
                report["h2_initial_credit"]["egress"]["roles"]["client"]["target"],
                5242881,
            )
            self.assertEqual(
                json.loads((root / "websocket/comparison.json").read_text()), report
            )
            self.assertFalse((root / "websocket/client.keys").exists())
