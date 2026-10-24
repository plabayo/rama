"""Complete H1 messages retain raw case, framing and TCP/request identity."""

import unittest
import xml.etree.ElementTree as ET

from flow_bodies import check_flow_bodies
from operations_tests.http_fixtures import field, journey
from wire import h1_message_body, parse_pdml


class HttpWireTests(unittest.TestCase):
    def test_full_mixed_decoder_preserves_h1_fields_bodies_and_upgrade(self):
        document, _page = journey()
        blocks = parse_pdml(ET.tostring(document), "mixed", 65320, include_data=True)
        self.assertEqual(len(check_flow_bodies(blocks)["flows"]), 6)
        head = next(
            block for block in blocks if not block.from_server and block.stream == 10
        )
        self.assertEqual(head.connection, 1)
        self.assertEqual(
            [pair for pair in head.headers if pair[0] == "x-eXoTiC"],
            [("x-eXoTiC", "first"), ("x-eXoTiC", "second")],
        )
        self.assertEqual(dict(head.headers)["hOsT"], "h1.capture.test:65320")
        for name, value in (("http.request_in", "999"), ("tcp.stream", "999")):
            changed = journey()[0]
            response = next(
                proto
                for proto in changed.findall("packet/proto[@name='http']")
                if proto.find("field[@name='http.request_in'][@show='10']") is not None
            )
            if name == "http.request_in":
                response.find("field[@name='http.request_in']").set("show", value)
            else:
                packet = next(packet for packet in changed if response in list(packet))
                packet.find("field[@name='tcp.stream']").set("show", value)
            with self.subTest(name=name), self.assertRaisesRegex(
                ValueError, "connection mismatch"
            ):
                parse_pdml(ET.tostring(changed), "mixed", 65320, include_data=True)

    def test_truncated_content_length_and_missing_final_response_fail(self):
        for mutation in ("length", "missing"):
            document, _page = journey()
            packet = next(
                packet
                for packet in document
                if packet.find("proto/field[@name='http.request_in'][@show='10']")
                is not None
            )
            if mutation == "missing":
                document.remove(packet)
            else:
                body = packet.find("proto/field[@name='http.file_data']")
                raw = bytes.fromhex(body.get("value"))[:-1]
                body.set("value", raw.hex())
                body.set("size", str(len(raw)))
            with self.subTest(mutation=mutation), self.assertRaisesRegex(
                ValueError, "Content-Length|missing complete"
            ):
                parse_pdml(ET.tostring(document), "mixed", 65320, include_data=True)

    def test_chunked_body_needs_exact_chunks_and_terminal_zero(self):
        document, _page = journey()
        response = next(
            proto
            for proto in document.findall("packet/proto[@name='http']")
            if proto.find("field[@name='http.request_in'][@show='10']") is not None
        )
        length = next(
            node
            for node in response.findall("field[@name='http.response.line']")
            if bytes.fromhex(node.get("value")).startswith(b"Content-Length:")
        )
        response.remove(length)
        field(
            response, "http.response.line", b"Transfer-Encoding: chunked\r\n", raw=True
        )
        body = bytes.fromhex(
            response.find("field[@name='http.file_data']").get("value")
        )
        field(
            response,
            "http.chunk_size",
            format(len(body), "x").encode() + b"\r\n",
            raw=True,
        )
        field(response, "http.chunk_data", body, raw=True)
        terminal = field(response, "http.chunk_size", b"0\r\n", raw=True)
        blocks = parse_pdml(ET.tostring(document), "mixed", 65320, include_data=True)
        self.assertEqual(len(check_flow_bodies(blocks)["flows"]), 6)
        response.remove(terminal)
        with self.assertRaisesRegex(ValueError, "terminal chunk"):
            parse_pdml(ET.tostring(document), "mixed", 65320, include_data=True)
        response.append(terminal)
        chunk = response.find("field[@name='http.chunk_data']")
        chunk.set("value", (body[:-1] + b"X").hex())
        with self.assertRaisesRegex(ValueError, "reassembled body mismatch"):
            parse_pdml(ET.tostring(document), "mixed", 65320, include_data=True)

    def test_conflicting_lengths_hosts_and_close_delimiting_fail_closed(self):
        for mutation in ("duplicate-length", "missing-length", "duplicate-host"):
            document, _page = journey()
            if mutation == "duplicate-host":
                request = next(
                    proto
                    for proto in document.findall("packet/proto[@name='http']")
                    if proto.find("field[@name='http.request.uri'][@show='/report']")
                    is not None
                )
                field(request, "http.request.line", b"Host: other.test\r\n", raw=True)
            else:
                response = next(
                    proto
                    for proto in document.findall("packet/proto[@name='http']")
                    if proto.find("field[@name='http.request_in'][@show='10']")
                    is not None
                )
                length = next(
                    node
                    for node in response.findall("field[@name='http.response.line']")
                    if bytes.fromhex(node.get("value")).startswith(b"Content-Length:")
                )
                if mutation == "missing-length":
                    response.remove(length)
                else:
                    field(
                        response,
                        "http.response.line",
                        bytes.fromhex(length.get("value")),
                        raw=True,
                    )
            with self.subTest(mutation=mutation), self.assertRaisesRegex(
                ValueError, "framing|close-delimited|Host binding"
            ):
                parse_pdml(ET.tostring(document), "mixed", 65320, include_data=True)

    def test_head_and_304_preserve_representation_metadata_without_body(self):
        for method, status in (("HEAD", 200), ("GET", 304)):
            for headers in (
                (("Content-Length", "4096"),),
                (("Transfer-Encoding", "gzip, chunked"),),
                (),
            ):
                proto = ET.Element("proto", name="http")
                with self.subTest(method=method, status=status, headers=headers):
                    self.assertEqual(
                        h1_message_body(
                            proto, headers, response=True, method=method, status=status
                        ),
                        b"",
                    )
                    field(proto, "http.file_data", b"unexpected", raw=True)
                    with self.assertRaisesRegex(ValueError, "bodyless"):
                        h1_message_body(
                            proto, headers, response=True, method=method, status=status
                        )

    def test_bodyless_metadata_does_not_admit_payload_or_invalid_framing(self):
        for method, status, headers, raw_field in (
            ("HEAD", 200, (("Content-Length", "bad"),), None),
            (
                "GET",
                304,
                (("Transfer-Encoding", "chunked"), ("Content-Length", "0")),
                None,
            ),
            ("GET", 101, (("Content-Length", "0"),), None),
            ("GET", 204, (("Transfer-Encoding", "chunked"),), None),
            ("HEAD", 200, (("Transfer-Encoding", "chunked"),), "http.chunk_size"),
            ("GET", 304, (), "http.trailer"),
        ):
            proto = ET.Element("proto", name="http")
            if raw_field:
                field(proto, raw_field, b"0\r\n", raw=True)
            with self.subTest(
                method=method, status=status, headers=headers, raw_field=raw_field
            ):
                with self.assertRaisesRegex(
                    ValueError, "framing|bodyless|Content-Length"
                ):
                    h1_message_body(
                        proto, headers, response=True, method=method, status=status
                    )
