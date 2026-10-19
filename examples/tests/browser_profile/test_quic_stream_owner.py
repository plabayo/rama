"""Malformed native STREAM bytes cannot disappear behind a valid control prefix."""

import unittest
import xml.etree.ElementTree as ET

from quic_wire import client_settings
from test_h3_sequence_wire import document, stream_packet
from test_quic_settings_stream import control
from test_quic_wire import scalar


def changed_packet(packet, change):
    root = ET.fromstring(packet)
    frame = root.find("field[@name='quic.frame']")
    change(frame)
    return ET.tostring(root).decode()


class StreamOwnerTests(unittest.TestCase):
    def test_missing_owner_cannot_hide_retransmitted_or_request_bytes(self):
        for server, stream in [(False, 2), (True, 3)]:
            good = control(stream=stream, server=server)
            unknown = changed_packet(
                good,
                lambda frame: frame.remove(
                    frame.find("field[@name='quic.stream.stream_id']")
                ),
            )
            with self.subTest(server=server), self.assertRaises(ValueError):
                client_settings(document(good, unknown), 443, from_server=server)
        request = changed_packet(
            stream_packet(0, b"request"),
            lambda frame: frame.remove(
                frame.find("field[@name='quic.stream.stream_id']")
            ),
        )
        with self.assertRaises(ValueError):
            client_settings(document(control(), request), 443)

    def test_ambiguous_owner_cannot_be_resolved_by_choosing_first_field(self):
        def duplicate(frame):
            frame.append(ET.fromstring(scalar("quic.stream.stream_id", b"\x02")))

        ambiguous = changed_packet(control(), duplicate)
        with self.assertRaises(ValueError):
            client_settings(document(control(), ambiguous), 443)

    def test_undeclared_data_and_missing_native_type_cannot_be_skipped(self):
        def undeclared(frame):
            frame.find("field[@name='quic.frame_type']").set("value", "01")
            frame.find("field[@name='quic.frame_type']").set("show", "1")
            frame.remove(frame.find("field[@name='quic.stream.stream_id']"))

        bad = changed_packet(control(), undeclared)
        missing_type = changed_packet(
            control(),
            lambda frame: frame.remove(frame.find("field[@name='quic.frame_type']")),
        )
        for unknown in [bad, missing_type]:
            with self.subTest(unknown=unknown), self.assertRaises(ValueError):
                client_settings(document(control(), unknown), 443)

    def test_bidirectional_headers_are_validated_before_excluding_request_data(self):
        request = stream_packet(0, b"request")
        self.assertEqual(
            client_settings(document(control(), request), 443),
            client_settings(document(control()), 443),
        )
        for name in ["quic.stream.length", "quic.frame_type"]:

            def corrupt(frame):
                node = frame.find("field[@name='" + name + "']")
                node.set("value", "01")
                node.set("show", "1")

            malformed = changed_packet(request, corrupt)
            with self.subTest(name=name), self.assertRaises(ValueError):
                client_settings(document(control(), malformed), 443)
        malformed = changed_packet(request, lambda frame: frame.set("size", "999"))
        with self.assertRaises(ValueError):
            client_settings(document(control(), malformed), 443)

    def test_stream_flags_cannot_hide_undeclared_offset_or_length_fields(self):
        # Type8 carries neither offset nor length. A generated physical field
        # outside that declared header cannot become trusted stream metadata.
        request = stream_packet(0, b"request")

        def flags(frame):
            node = frame.find("field[@name='quic.frame_type']")
            node.set("value", "08")
            node.set("show", "8")
            frame.remove(frame.find("field[@name='quic.stream.offset']"))
            frame.remove(frame.find("field[@name='quic.stream.length']"))
            frame.set("size", "9")

        request = changed_packet(request, flags)
        self.assertEqual(
            client_settings(document(control(), request), 443),
            client_settings(document(control()), 443),
        )
        for name in ["quic.stream.offset", "quic.stream.length"]:
            malformed = changed_packet(
                request,
                lambda frame: frame.append(ET.fromstring(scalar(name, b"\x00"))),
            )
            with self.subTest(name=name), self.assertRaises(ValueError):
                client_settings(document(control(), malformed), 443)
