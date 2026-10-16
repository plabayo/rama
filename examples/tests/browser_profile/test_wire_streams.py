"""Regression fixtures deliberately put different streams in the same packet."""

import unittest
from unittest.mock import patch
from wire import parse_pdml


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
                data = data.replace(marker, marker + payload)
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
