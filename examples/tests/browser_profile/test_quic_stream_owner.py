"""Malformed native STREAM bytes cannot disappear behind a valid control prefix."""

import unittest
import xml.etree.ElementTree as ET
from quic_wire import client_settings
from wire_fixtures import (
    document,
    quic_settings_stream_control as control,
    stream_packet,
)


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
