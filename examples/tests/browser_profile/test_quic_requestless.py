"""Requestless native QUIC connections are reported only when fully decrypted."""

import unittest
import xml.etree.ElementTree as ET
from admission import admit
from flows import DRIVER_FLOWS
from quic_stream_wire import quic_exclusions, requestless_connections
from wire_fixtures import computed, document, scalar, stream_packet


def native(packet, *, decrypted=True, frames=True):
    """Nest a synthetic packet's frames in a native QUIC packet element."""
    root = ET.fromstring(packet)
    proto = ET.SubElement(root, "proto", name="quic")
    # Native PDML carries the connection number inside the QUIC element.
    number = root.find("field[@name='quic.connection.number']")
    root.remove(number)
    proto.append(number)
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

    def test_packet_without_native_quic_element_excludes_every_connection(self):
        data = document(control(1), control(3), stream_packet(2, b"\x00", connection=1))
        self.assertEqual(requestless_connections(data, 443), set())

    def test_unattributable_server_packets_carry_no_request(self):
        server = stream_packet(3, b"\x00", server=True, connection=1)
        data = document(control(1), control(1, server=True), server)
        self.assertEqual(requestless_connections(data, 443), {1})

    def test_bidirectional_stream_frames_and_connection_errors_exclude(self):
        def frame_packet(kind, fields, connection=2):
            body = scalar("quic.frame_type", bytes([kind])) + "".join(fields)
            return native(
                "<packet>"
                + computed("quic.connection.number", connection)
                + scalar("udp.srcport", (10000).to_bytes(2, "big"))
                + scalar("udp.dstport", (443).to_bytes(2, "big"))
                + '<field name="quic.frame">'
                + body
                + "</field></packet>"
            )

        def stream_id(name, value):
            return scalar(name, bytes([value]))

        cases = {
            "reset bidi": (0x04, [stream_id("quic.rsts.stream_id", 0)], True),
            "reset uni": (0x04, [stream_id("quic.rsts.stream_id", 2)], False),
            "stop sending": (0x05, [stream_id("quic.ss.stream_id", 4)], True),
            "max stream data": (0x11, [stream_id("quic.msd.stream_id", 0)], True),
            "data blocked": (0x15, [stream_id("quic.sdb.stream_id", 8)], True),
            "transport close": (0x1C, [scalar("quic.cc.error_code", b"\x0a")], True),
            "clean close": (0x1C, [scalar("quic.cc.error_code", b"\x00")], False),
            "app close": (0x1D, [scalar("quic.cc.error_code.app", b"\x01")], True),
            "app no error": (0x1D, [scalar("quic.cc.error_code.app", b"\x00")], False),
            "h3 no error": (
                0x1D, [scalar("quic.cc.error_code.app", b"\x41\x00", show=0x100)], False
            ),
            "h3 error": (
                0x1D, [scalar("quic.cc.error_code.app", b"\x41\x01", show=0x101)], True
            ),
            "transport 0x100": (
                0x1C, [scalar("quic.cc.error_code", b"\x41\x00", show=0x100)], True
            ),
            "close without code": (0x1C, [], True),
        }
        for name, (kind, fields, excludes) in cases.items():
            data = document(control(1), control(2), frame_packet(kind, fields))
            with self.subTest(name=name):
                self.assertEqual(
                    requestless_connections(data, 443), {1} if excludes else {1, 2}
                )

    def test_exclusions_name_why_a_connection_is_not_requestless(self):
        data = document(
            control(1),
            native(stream_packet(0, b"request", connection=2)),
            native(stream_packet(2, b"\x00", connection=3), decrypted=False),
        )
        decoded, excluded, stray = quic_exclusions(data, 443)
        self.assertEqual(decoded, {1, 2, 3})
        self.assertEqual(set(excluded), {2, 3})
        self.assertTrue(all("request stream" in reason for reason in excluded[2]))
        self.assertEqual(excluded[3], {"undecrypted packet"})
        self.assertIsNone(stray)
        unattributable = document(control(1), stream_packet(2, b"\x00", connection=1))
        self.assertIn("no QUIC element", quic_exclusions(unattributable, 443)[2])

    def test_handshake_packets_may_carry_an_application_close_as_application_error(self):
        def close(code, packet_type):
            kind = scalar("quic.frame_type", b"\x1c") + scalar("quic.cc.error_code", bytes([code]))
            root = ET.fromstring(
                native(
                    "<packet>"
                    + computed("quic.connection.number", 2)
                    + scalar("udp.srcport", (10000).to_bytes(2, "big"))
                    + scalar("udp.dstport", (443).to_bytes(2, "big"))
                    + f'<field name="quic.frame">{kind}</field></packet>'
                )
            )
            if packet_type is not None:
                long = scalar("quic.long.packet_type", b"", show=packet_type)
                root.find("proto[@name='quic']").append(ET.fromstring(long))
            return ET.tostring(root).decode()

        # RFC 9000 §10.2.3: an application close in Initial/Handshake becomes 0x1c APPLICATION_ERROR.
        for code, packet_type, clean in (
            (0x0C, "0", True),
            (0x0C, "2", True),
            (0x0C, "1", False),
            (0x0C, None, False),
            (0x0A, "2", False),
        ):
            data = document(control(1), control(2), close(code, packet_type))
            with self.subTest(code=code, packet_type=packet_type):
                self.assertEqual(requestless_connections(data, 443), {1, 2} if clean else {1})

    def test_coalesced_packets_share_the_first_packets_connection(self):
        def coalesced(dcid, separate=False, first_dcid=b"\xaa"):
            # Tshark numbers only the first QUIC packet; the second carries a request stream.
            root = ET.fromstring(control(1))
            first = root.find("proto[@name='quic']")
            if first_dcid is not None:
                first.append(ET.fromstring(scalar("quic.dcid", first_dcid, show=first_dcid.hex())))
            later = ET.fromstring(control(1)) if separate else root
            if separate:
                later.remove(later.find("proto[@name='quic']"))
            second = ET.SubElement(later, "proto", name="quic")
            if dcid is not None:
                second.append(ET.fromstring(scalar("quic.dcid", dcid, show=dcid.hex())))
            second.append(ET.fromstring(scalar("quic.packet_number", b"\x02", show=2)))
            request = ET.fromstring(native(stream_packet(0, b"request", connection=1)))
            second.append(request.find("proto[@name='quic']").find("field[@name='quic.frame']"))
            packets = [root, later] if separate else [root]
            return document(control(1, server=True), *(ET.tostring(p).decode() for p in packets))

        decoded, excluded, stray = quic_exclusions(coalesced(b"\xaa"), 443)
        self.assertEqual((decoded, stray), ({1}, None))
        self.assertTrue(all("request stream" in reason for reason in excluded[1]))
        # A different DCID, no DCID, or another datagram leaves the packet unattributable.
        for data in (
            coalesced(b"\xbb"),
            coalesced(None),
            coalesced(None, first_dcid=None),
            coalesced(b"\xaa", separate=True),
        ):
            self.assertIn("without a connection number", quic_exclusions(data, 443)[2])

    def test_admission_names_a_stray_client_packet_without_a_connection(self):
        page = {"protocols": dict.fromkeys(DRIVER_FLOWS, "h3"), "page_results": {}, "user_agent": "test"}
        for native in (False, True):
            packet = ET.Element("packet")
            for name, show in (
                ("udp.srcport", "12345"),
                ("udp.dstport", "443"),
                ("frame.number", "152"),
                ("data.data", "40:ab"),
            ):
                ET.SubElement(packet, "field", name=name, show=show)
            if native:
                proto = ET.SubElement(packet, "proto", name="quic")
                ET.SubElement(proto, "field", name="quic.fixed_bit", show="0")
            data = document(control(1), ET.tostring(packet).decode())
            expected = "fixed bit 0" if native else "first byte 0x40"
            with self.subTest(native=native), self.assertRaisesRegex(ValueError, expected):
                admit(data, [], page, "https://localhost:443")

    def test_other_ports_are_ignored(self):
        self.assertEqual(requestless_connections(document(control(1)), 8443), set())


if __name__ == "__main__":
    unittest.main()
