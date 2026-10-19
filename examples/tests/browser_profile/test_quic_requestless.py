"""Requestless native QUIC connections are reported only when fully decrypted."""

import unittest
import xml.etree.ElementTree as ET

from quic_stream_wire import requestless_connections
from test_h3_sequence_wire import document, stream_packet
from test_quic_wire import scalar


def native(packet, *, decrypted=True, frames=True):
    """Nest a synthetic packet's frames in a native QUIC packet element."""
    root = ET.fromstring(packet)
    proto = ET.SubElement(root, "proto", name="quic")
    if decrypted:
        proto.append(ET.fromstring(scalar("quic.packet_number", b"\x01", show=1)))
    for frame in root.findall("field[@name='quic.frame']"):
        root.remove(frame)
        if frames:
            proto.append(frame)
    return ET.tostring(root).decode()


def control(connection, *, server=False):
    return native(
        stream_packet(3 if server else 2, b"\x00", server=server, connection=connection)
    )


class RequestlessQuicTests(unittest.TestCase):
    def test_control_only_connections_are_requestless_and_request_ones_are_not(self):
        data = document(
            control(1),
            control(1, server=True),
            control(2),
            native(stream_packet(0, b"request", connection=2)),
        )
        self.assertEqual(requestless_connections(data, 443), {1})

    def test_undecrypted_or_frameless_packets_exclude_the_connection(self):
        for options in (dict(decrypted=False), dict(frames=False)):
            data = document(
                control(1),
                native(stream_packet(2, b"\x00", connection=1), **options),
            )
            with self.subTest(options=options):
                self.assertEqual(requestless_connections(data, 443), set())

    def test_appended_datagram_padding_is_not_an_undecrypted_packet(self):
        def padded(fields):
            root = ET.fromstring(control(1))
            proto = ET.SubElement(root, "proto", name="quic")
            expert = ET.SubElement(proto, "field", name="_ws.expert")
            for name in fields:
                ET.SubElement(expert, "field", name=name)
            return ET.tostring(root).decode()

        padding = padded(["quic.coalesced_padding_data", "_ws.expert.message"])
        self.assertEqual(requestless_connections(document(padding), 443), {1})
        for fields in ([], ["quic.coalesced_padding_data", "quic.protected_payload"]):
            with self.subTest(fields=fields):
                data = document(padded(fields))
                self.assertEqual(requestless_connections(data, 443), set())

    def test_packet_without_native_quic_element_excludes_the_connection(self):
        data = document(control(1), stream_packet(2, b"\x00", connection=1))
        self.assertEqual(requestless_connections(data, 443), set())

    def test_other_ports_are_ignored(self):
        self.assertEqual(requestless_connections(document(control(1)), 8443), set())


if __name__ == "__main__":
    unittest.main()
