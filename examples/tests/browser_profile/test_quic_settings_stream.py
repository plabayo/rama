"""SETTINGS count logical stream bytes, including retransmissions and refusals."""

import unittest
from unittest.mock import patch

import quic_stream_wire as streams
import quic_wire
from quic_wire import client_settings
from test_h3_sequence_wire import document, frame, number, stream_packet
from test_quic_wire import computed, scalar


def decoded(payload=b"\x01\x10", *, stream=2):
    return (
        f'<field name="http3.frame" size="{len(frame(4, payload))}">'
        + computed("http3.frame_streamid", stream)
        + scalar("http3.frame_type", b"\x04")
        + scalar("http3.frame_length", number(len(payload)))
        + scalar("http3.frame_payload", payload)
        + "</field>"
    )


def control(payload=None, *, stream=2, server=False, offset=0, witness=True):
    data = b"\x00" + frame(4, b"\x01\x10") if payload is None else payload
    packet = stream_packet(stream, data, server=server, offset=offset)
    if witness:
        packet = packet.replace("</packet>", decoded(stream=stream) + "</packet>")
    return packet


class SettingsStreamTests(unittest.TestCase):
    def test_full_and_partial_retransmissions_count_once_in_each_direction(self):
        for server, stream in [(False, 2), (True, 3)]:
            packet = control(stream=stream, server=server)
            expected = client_settings(document(packet), 443, from_server=server)
            self.assertEqual(expected[7]["fields"][0]["id"], 1)
            for retransmission in ["", '<field name="quic.retransmission" size="0"/>']:
                repeated = packet.replace("</packet>", retransmission + "</packet>")
                self.assertEqual(
                    client_settings(
                        document(packet, repeated), 443, from_server=server
                    ),
                    expected,
                )
            data = b"\x00" + frame(4, b"\x01\x10")
            self.assertEqual(
                client_settings(
                    document(
                        control(data[2:], stream=stream, server=server, offset=2),
                        control(data[:3], stream=stream, server=server, witness=False),
                    ),
                    443,
                    from_server=server,
                ),
                expected,
            )

    def test_absent_offset_uses_zero_without_trusting_retransmission_marker(self):
        packet = (
            "<packet>"
            + computed("quic.connection.number", 7)
            + scalar("udp.srcport", (10000).to_bytes(2, "big"))
            + scalar("udp.dstport", (443).to_bytes(2, "big"))
            + '<field name="quic.frame" size="8">'
            + scalar("quic.frame_type", b"\x0a")
            + scalar("quic.stream.stream_id", b"\x02")
            + scalar("quic.stream.length", b"\x05")
            + scalar("quic.stream_data", b"\x00\x04\x02\x01\x10")
            + "</field>"
            + decoded()
            + "</packet>"
        )
        result = client_settings(document(packet, packet), 443)
        self.assertEqual(len(result), 1)

    def test_actual_second_settings_and_second_control_stream_reject(self):
        for server, stream in [(False, 2), (True, 3)]:
            double = b"\x00" + frame(4, b"\x01\x10") * 2
            with self.assertRaisesRegex(ValueError, "multiple HTTP/3 SETTINGS"):
                client_settings(
                    document(control(double, stream=stream, server=server)),
                    443,
                    from_server=server,
                )
            with self.assertRaisesRegex(ValueError, "multiple HTTP/3 control"):
                client_settings(
                    document(
                        control(stream=stream, server=server),
                        control(stream=stream + 4, server=server, witness=False),
                    ),
                    443,
                    from_server=server,
                )

    def test_conflicting_overlap_gap_and_partial_control_tail_reject(self):
        with self.assertRaisesRegex(ValueError, "conflicting"):
            client_settings(
                document(control(), control(b"\x00\x04\x02\x01\x11", witness=False)),
                443,
            )
        with self.assertRaisesRegex(ValueError, "gap"):
            client_settings(
                document(
                    control(b"\x00", witness=False),
                    control(b"\x04\x02\x01\x10", offset=2),
                ),
                443,
            )
        for tail in [b"\x07", b"\x07\x02\x00"]:
            with self.subTest(tail=tail), self.assertRaisesRegex(
                ValueError, "truncated"
            ):
                client_settings(
                    document(control(b"\x00" + frame(4, b"\x01\x10") + tail)), 443
                )

    def test_decoded_settings_need_exact_native_owner_and_bytes(self):
        for packet in [
            control().replace(decoded(), decoded(stream=6)),
            control().replace(decoded(), decoded(b"\x01\x11")),
            control().replace(computed("http3.frame_streamid", 2), ""),
            control().replace(decoded(), ""),
        ]:
            with self.subTest(packet=packet), self.assertRaises(ValueError):
                client_settings(document(packet), 443)
        detached = (
            control().split('<field name="quic.frame"')[0] + decoded() + "</packet>"
        )
        with self.assertRaises(ValueError):
            client_settings(document(detached), 443)

    def test_wrong_stream_endpoint_and_control_order_reject(self):
        with self.assertRaisesRegex(ValueError, "wrong endpoint"):
            client_settings(
                document(control(server=True, stream=2)), 443, from_server=True
            )
        with self.assertRaisesRegex(ValueError, "begin with SETTINGS"):
            client_settings(
                document(control(b"\x00" + frame(7, b"\x00") + frame(4, b"\x01\x10"))),
                443,
            )

    def test_stream_capture_and_control_budgets_remain_enforced(self):
        for name, value in [
            ("MAX_STREAM_BYTES", 3),
            ("MAX_TOTAL_BYTES", 6),
            ("MAX_CAPTURE_STREAMS", 0),
            ("MAX_STREAMS", 0),
        ]:
            with self.subTest(name=name), patch.object(
                streams, name, value
            ), self.assertRaisesRegex(ValueError, "limit"):
                client_settings(document(control(), control()), 443)
        with patch.object(quic_wire, "MAX_FRAMES", 1), self.assertRaisesRegex(
            ValueError, "frame count limit"
        ):
            client_settings(
                document(control(b"\x00" + frame(4, b"\x01\x10") + frame(33, b""))), 443
            )
