"""Regression fixtures deliberately put different streams in the same packet."""

import unittest
import xml.etree.ElementTree as ET
from unittest.mock import patch
from wire import parse_pdml, pdml_packets


def field(name, value):
    return f'<field name="{name}" show="{value}"/>'


def packet(protocol, streams):
    h2 = protocol == "h2"
    transport = "tcp" if h2 else "udp"
    content = field("frame.number", "7") + field(transport + ".srcport", "50000")
    content += field(transport + ".dstport", "443")
    content += field("tcp.stream" if h2 else "quic.connection.number", "2")
    for stream, pairs in streams:
        content += '<field name="' + ("http2.stream" if h2 else "http3.frame") + '">'
        content += field(
            "http2.streamid" if h2 else "http3.frame_streamid", str(stream)
        )
        for name, value in pairs:
            content += (
                '<field name="'
                + ("http2.header" if h2 else "http3.headers.header")
                + '">'
            )
            content += field(
                "http2.header.name" if h2 else "http3.header.header.name", name
            )
            content += field(
                "http2.header.value" if h2 else "http3.headers.header.value", value
            )
            content += "</field>"
        content += "</field>"
    return ("<pdml><packet>" + content + "</packet></pdml>").encode()


class PdmlAdmissionTests(unittest.TestCase):
    def test_utf16_declarations_cannot_bypass_admission(self):
        document = (
            '<?xml version="1.0" encoding="UTF-16"?>'
            '<!DOCTYPE pdml [<!ENTITY small "expanded">]>'
            '<pdml><packet><field name="fixture" show="&small;"/></packet></pdml>'
        )
        for encoding in ("utf-16", "utf-16-le", "utf-16-be"):
            with self.subTest(encoding=encoding):
                with self.assertRaisesRegex(ValueError, "UTF-8"):
                    pdml_packets(document.encode(encoding))

    def test_utf32_fails_before_xml_parsing(self):
        document = '<pdml><packet><field show="café"/></packet></pdml>'
        alternatives = [
            document.encode(encoding)
            for encoding in ("utf-32", "utf-32-le", "utf-32-be")
        ]
        for data in alternatives:
            with self.subTest(data=data[:16]), patch("wire.ET.fromstring") as parse:
                with self.assertRaisesRegex(ValueError, "UTF-8"):
                    pdml_packets(data)
                parse.assert_not_called()

    def test_non_utf8_text_is_rejected(self):
        document = (
            '<?xml version="1.0" encoding="ISO-8859-1"?>'
            '<pdml><packet><field show="café"/></packet></pdml>'
        )
        with self.assertRaisesRegex(ValueError, "UTF-8"):
            pdml_packets(document.encode("latin-1"))

    def test_utf8_and_its_bom_preserve_non_ascii_fields(self):
        document = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<pdml><packet><field show="café"/></packet></pdml>'
        )
        for encoding in ("utf-8", "utf-8-sig"):
            with self.subTest(encoding=encoding):
                packets = pdml_packets(document.encode(encoding))
                self.assertEqual(packets[0].find("field").get("show"), "café")


class MultiplexedTests(unittest.TestCase):
    def test_pdml_byte_limit_is_enforced_before_decoding(self):
        for protocol in ("h2", "h3"):
            data = packet(protocol, [(0, [(":method", "GET")])])
            with patch("wire.MAX_PDML_BYTES", len(data)):
                self.assertEqual(len(parse_pdml(data, protocol, 443)), 1)
            with patch("wire.MAX_PDML_BYTES", len(data) - 1):
                with self.assertRaisesRegex(ValueError, "decoded byte limit"):
                    parse_pdml(data, protocol, 443)

    def test_pdml_packet_limit_is_enforced(self):
        for protocol in ("h2", "h3"):
            data = packet(protocol, [(0, [(":method", "GET")])])
            with patch("wire.MAX_PACKETS", 1):
                self.assertEqual(len(parse_pdml(data, protocol, 443)), 1)
                doubled = data.replace(b"</packet>", b"</packet><packet/>")
                with self.assertRaisesRegex(ValueError, "decoded packet limit"):
                    parse_pdml(doubled, protocol, 443)

    def test_pdml_declarations_are_rejected(self):
        for protocol in ("h2", "h3"):
            data = packet(protocol, [(0, [(":method", "GET")])])
            for declaration in (
                b"<!DOCTYPE pdml>",
                b'<!DOCTYPE pdml [<!ENTITY harmless "ok">]>',
            ):
                with self.subTest(protocol=protocol, declaration=declaration):
                    with self.assertRaisesRegex(ValueError, "declarations"):
                        parse_pdml(declaration + data, protocol, 443)

    def test_coalesced_streams_keep_header_order_and_repeats(self):
        for protocol in ["h2", "h3"]:
            first = [
                (":method", "GET"),
                (":path", "/report"),
                ("x-test", "a"),
                ("x-test", "b"),
            ]
            second = [
                (":method", "CONNECT"),
                (":path", "/api/ws"),
                (":protocol", "websocket"),
            ]
            blocks = parse_pdml(
                packet(protocol, [(0, first), (4, second)]), protocol, 443
            )
            self.assertEqual([block.stream for block in blocks], [0, 4])
            self.assertEqual(blocks[0].headers, tuple(first))
            self.assertEqual(blocks[1].headers, tuple(second))
            self.assertEqual([block.connection for block in blocks], [2, 2])
            self.assertFalse(any(block.from_server for block in blocks))

    def test_data_bytes_and_websocket_stream_association(self):
        for protocol in ("h2", "h3"):
            data = packet(protocol, [(0, []), (4, [])])
            stream_tag = (
                "http2.streamid" if protocol == "h2" else "http3.frame_streamid"
            )
            data_tag = "http2.data.data" if protocol == "h2" else "http3.data"
            for stream, value in [(0, "6162"), (4, "6364")]:
                marker = field(stream_tag, str(stream)).encode()
                payload = (
                    f'<field name="{data_tag}" size="2" value="{value}"/>'.encode()
                )
                type_tag = "http2.type" if protocol == "h2" else "http3.frame_type"
                data = data.replace(marker, marker + field(type_tag, "0").encode() + payload)
            blocks = parse_pdml(data, protocol, 443, include_data=True)
            self.assertEqual(
                [(x.stream, x.data) for x in blocks], [(0, b"ab"), (4, b"cd")]
            )
            with self.assertRaisesRegex(ValueError, "byte length"):
                parse_pdml(
                    data.replace(b'size="2"', b'size="3"'),
                    protocol,
                    443,
                    include_data=True,
                )
            with self.assertRaisesRegex(ValueError, "raw bytes"):
                parse_pdml(
                    data.replace(b'value="6162"', b""), protocol, 443, include_data=True
                )
            ws = data.replace(
                b"</packet>",
                field("websocket.payload.text", "greeting").encode() + b"</packet>",
            )
            with self.assertRaisesRegex(ValueError, "WebSocket DATA stream"):
                parse_pdml(ws, protocol, 443, include_data=True)
            # Coalesced frames on the same stream are unambiguous. Attach the
            # sibling WebSocket decode once, not once per DATA frame.
            ws = ws.replace(
                field(stream_tag, "4").encode(), field(stream_tag, "0").encode()
            )
            blocks = parse_pdml(ws, protocol, 443, include_data=True)
            self.assertEqual([x.websocket_text for x in blocks], [("greeting",), ()])

    def test_trailer_body_reassembly_does_not_duplicate_wire_data(self):
        # Actual tshark H2 output repeats application bytes under trailer HEADERS.
        # A sibling WebSocket decode must still belong only to the DATA stream.
        for protocol in ("h2", "h3"):
            stream_tag = "http2.streamid" if protocol == "h2" else "http3.frame_streamid"
            type_tag = "http2.type" if protocol == "h2" else "http3.frame_type"
            data_tag = "http2.data.data" if protocol == "h2" else "http3.data"
            data = packet(protocol, [(0, []), (4, [("x-end", "complete")])])
            payload = f'<field name="{data_tag}" size="2" value="6162"/>'.encode()
            for stream, kind in ((0, "0"), (4, "1")):
                identity = field(stream_tag, str(stream)).encode()
                data = data.replace(identity, identity + field(type_tag, kind).encode() + payload)
            blocks = parse_pdml(data, protocol, 443, include_data=True)
            self.assertEqual([block.data for block in blocks], [b"ab", b""])
            self.assertEqual(blocks[1].headers, (("x-end", "complete"),))

            data = data.replace(
                b"</packet>", field("websocket.payload.text", "probe").encode() + b"</packet>",
            )
            blocks = parse_pdml(data, protocol, 443, include_data=True)
            self.assertEqual([block.websocket_text for block in blocks], [("probe",), ()])

    def test_generated_body_subtree_on_zero_data_frame_is_not_fresh_wire_bytes(self):
        document = ET.fromstring(packet("h2", [(1, []), (1, [])]))
        frames = [
            node
            for node in document.iter("field")
            if node.get("name") == "http2.stream"
        ]
        for frame, length in zip(frames, (2, 0)):
            ET.SubElement(frame, "field", name="http2.type", show="0")
            ET.SubElement(frame, "field", name="http2.length", show=str(length))
        ET.SubElement(
            frames[0], "field", name="http2.data.data", value="6162", size="2"
        )
        fragments = ET.SubElement(frames[1], "field", name="http2.body.fragments")
        ET.SubElement(
            fragments,
            "field",
            name="http2.body.reassembled.data",
            value="6162",
            size="2",
        )
        application = ET.SubElement(frames[1], "field", name="", size="2", pos="0")
        ET.SubElement(
            application,
            "field",
            name="http2.data.data",
            value="6465636f646564",
            size="7",
            pos="0",
        )
        rows = parse_pdml(ET.tostring(document), "h2", 443, include_data=True)
        self.assertEqual([row.data for row in rows], [b"ab"])
        self.assertEqual([(row.connection, row.stream) for row in rows], [(2, 1)])
        # An original per-frame segment still wins, even with the generated copy present.
        ET.SubElement(
            frames[0], "field", name="http2.data.segment", value="7879", size="2"
        )
        rows = parse_pdml(ET.tostring(document), "h2", 443, include_data=True)
        self.assertEqual([row.data for row in rows], [b"xy"])

    def test_original_h2_segment_wins_over_reassembled_application_body(self):
        data = packet("h2", [(0, [])])
        identity = field("http2.streamid", "0").encode()
        fields = (
            field("http2.type", "0")
            + '<field name="http2.data.segment" size="2" value="6162"/>'
            + '<field name="http2.data.data" size="4" value="63646162"/>'
        ).encode()
        blocks = parse_pdml(data.replace(identity, identity + fields), "h2", 443, include_data=True)
        self.assertEqual([block.data for block in blocks], [b"ab"])

    def test_ambiguous_connection_is_rejected(self):
        for protocol in ["h2", "h3"]:
            data = packet(protocol, [(0, [(":method", "GET")])])
            identity = "tcp.stream" if protocol == "h2" else "quic.connection.number"
            data = data.replace(
                b"</packet>", field(identity, "3").encode() + b"</packet>"
            )
            with self.assertRaisesRegex(ValueError, "connection identity"):
                parse_pdml(data, protocol, 443)

    def test_wrong_endpoint_and_missing_decryption_are_rejected(self):
        for protocol in ["h2", "h3"]:
            with self.assertRaisesRegex(ValueError, "fixture endpoint"):
                parse_pdml(
                    packet(protocol, [(0, [(":method", "GET")])]), protocol, 8443
                )
            with self.assertRaisesRegex(ValueError, "no decrypted"):
                parse_pdml(b"<pdml><packet/></pdml>", protocol, 443)

    def test_server_direction_is_preserved(self):
        for protocol in ["h2", "h3"]:
            data = packet(protocol, [(0, [(":status", "200")])])
            data = data.replace(b'show="50000"', b'show="443"', 1)
            data = data.replace(b'dstport" show="443"', b'dstport" show="50000"', 1)
            self.assertTrue(parse_pdml(data, protocol, 443)[0].from_server)


if __name__ == "__main__":
    unittest.main()
