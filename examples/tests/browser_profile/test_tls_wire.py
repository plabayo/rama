import copy
from dataclasses import replace
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET
from tls_wire import (
    Reader,
    TlsHello,
    byte_span,
    extension_value,
    client_hellos,
    compare_tls_captures,
    decode_client_hello,
)


def vector(data, width=2):
    return len(data).to_bytes(width, "big") + data


def span(data):
    return ET.fromstring(
        f'<field pos="10" size="{len(data)}">'
        f'<field pos="10" size="{len(data)}" value="{data.hex()}"/>'
        "</field>"
    )


def comparison_fixture():
    capture = dict(
        completeness="Complete",
        transport="Tcp",
        protocol_version=771,
        ciphers=[4865],
        compression=[0],
        extensions=[],
    )
    hello = TlsHello(1, 7, capture)
    request = SimpleNamespace(
        connection=7, from_server=False, headers=(("user-agent", "fixture"),)
    )
    archive = dict(
        format_version=1,
        profiles=[
            dict(
                key={"user_agent": "fixture"},
                scopes=[
                    dict(
                        variants=[
                            dict(
                                capture=dict(
                                    slots=[dict(kind="TcpTls", capture=capture)]
                                )
                            )
                        ]
                    )
                ],
            )
        ],
    )
    return archive, hello, request


class TlsWireTests(unittest.TestCase):
    def test_complete_client_hello_and_vector_boundaries(self):
        def hello(extensions):
            body = (
                b"\x03\x03"
                + bytes(32)
                + b"\x00"
                + vector(b"\x13\x01")
                + b"\x01\x00"
                + vector(extensions)
            )
            return b"\x01" + vector(body, 3)

        extension = b"\x00\x0a" + vector(vector(b"\x00\x1d"))
        valid = hello(extension)
        capture = decode_client_hello(valid, "Quic")
        self.assertEqual(capture["ciphers"], [4865])
        self.assertEqual(
            capture["extensions"], [{"id": 10, "value": {"U16List": [29]}}]
        )
        for invalid in (
            valid[:-1],
            valid + b"x",
            b"\x02" + valid[1:],
            hello(extension * 2),
        ):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                decode_client_hello(invalid, "Quic")
        psk = b"\x00\x29" + vector(
            vector(vector(b"id") + bytes(4)) + vector(vector(b"binder", 1))
        )
        with self.assertRaisesRegex(ValueError, "PSK"):
            decode_client_hello(hello(psk + extension), "Quic")

    def test_pdml_identity_and_bounds(self):
        body = (
            b"\x03\x03"
            + bytes(32)
            + b"\x00"
            + vector(b"\x13\x01")
            + b"\x01\x00"
            + vector(b"")
        )
        raw = b"\x01" + vector(body, 3)
        for transport, field in (
            ("Tcp", "tcp.stream"),
            ("Quic", "quic.connection.number"),
        ):
            data = (
                f'<pdml><packet><field name="frame.number" show="1"/>'
                f'<field name="{field}" show="7"/>'
                f'<field name="tls.handshake" pos="0" size="{len(raw)}" value="{raw.hex()}">'
                '<field name="tls.handshake.type" show="1" pos="0" size="1" value="01"/>'
                "</field></packet></pdml>"
            ).encode()
            self.assertEqual(client_hellos(data, transport)[0].connection, 7)
            with patch("tls_wire.MAX_PDML_BYTES", len(data) - 1):
                with self.assertRaisesRegex(ValueError, "byte limit"):
                    client_hellos(data, transport)
            with patch("tls_wire.MAX_PDML_BYTES", len(data)):
                self.assertEqual(len(client_hellos(data, transport)), 1)
            with patch("tls_wire.MAX_PACKETS", 1):
                self.assertEqual(len(client_hellos(data, transport)), 1)
                with self.assertRaisesRegex(ValueError, "packet limit"):
                    client_hellos(
                        data.replace(b"</packet>", b"</packet><packet/>"), transport
                    )
            with self.assertRaisesRegex(ValueError, "declarations"):
                client_hellos(b"<!DOCTYPE pdml>" + data, transport)
            with self.assertRaisesRegex(ValueError, "ambiguous"):
                client_hellos(
                    data.replace(
                        b"</packet>",
                        f'<field name="{field}" show="8"/></packet>'.encode(),
                    ),
                    transport,
                )
            with self.assertRaisesRegex(ValueError, "missing"):
                client_hellos(
                    data.replace(f'<field name="{field}" show="7"/>'.encode(), b""),
                    transport,
                )
            with self.assertRaisesRegex(ValueError, "no complete"):
                client_hellos(
                    data.replace(b'name="tls.handshake.type"', b'name="fragment.type"'),
                    transport,
                )

    def test_retained_extension_shapes(self):
        cases = [
            (
                0,
                vector(b"\x00" + vector(b"localhost")),
                {"ServerName": {"present": True}},
            ),
            (10, vector(b"\x00\x1d\x00\x17"), {"U16List": [29, 23]}),
            (43, vector(b"\x03\x04", 1), {"U16List": [772]}),
            (45, vector(b"\x01", 1), {"U8List": [1]}),
            (28, b"\x40\x01", {"U16List": [16385]}),
            (16, vector(vector(b"h2", 1)), {"Protocols": [[104, 50]]}),
            (
                51,
                vector(b"\x00\x1d" + vector(b"abcd")),
                {"KeyShares": [{"group": 29, "length": 4}]},
            ),
            (
                41,
                vector(vector(b"ticket") + bytes(4)) + vector(vector(b"abc", 1)),
                {"PreSharedKeys": {"identities": [6], "binders": [3]}},
            ),
            (
                65037,
                b"\x00\x00\x01\x00\x02\x42" + vector(b"enc") + vector(b"payload"),
                {"EchOuter": {"kdf": 1, "aead": 2, "enc": 3, "payload": 7}},
            ),
            (65037, b"\x01", "EchInner"),
            (21, bytes(9), {"ConnectionLength": 0}),
            (57, b"private", {"ConnectionLength": 7}),
            (0xAAAA, b"literal", {"Literal": list(b"literal")}),
        ]
        for identifier, data, expected in cases:
            with self.subTest(identifier=identifier):
                self.assertEqual(extension_value(identifier, data), expected)

    def test_malformed_extension_vectors_fail(self):
        for identifier, data in [
            (10, b"\x00\x04\x00"),
            (10, vector(b"\x00")),
            (43, vector(b"\x03\x04", 1) + b"x"),
            (16, vector(b"\x00")),
            (21, b"\x00\x01"),
            (65037, b"\x02"),
            (65037, b"\x01x"),
        ]:
            with self.subTest(identifier=identifier, data=data), self.assertRaises(
                ValueError
            ):
                extension_value(identifier, data)

    def test_raw_span_requires_coverage_and_consistency(self):
        self.assertEqual(byte_span(span(b"abc")), b"abc")
        missing = span(b"abc")
        missing[0].set("size", "2")
        with self.assertRaisesRegex(ValueError, "incomplete"):
            byte_span(missing)
        conflict = span(b"abc")
        ET.SubElement(conflict, "field", pos="10", size="1", value="00")
        with self.assertRaisesRegex(ValueError, "conflicting"):
            byte_span(conflict)
        oversized = span(b"a")
        oversized.set("size", "65540")
        with self.assertRaisesRegex(ValueError, "limit"):
            byte_span(oversized)

    def test_connection_binding_and_complete_reverse_coverage(self):
        archive, hello, request = comparison_fixture()
        self.assertEqual(
            compare_tls_captures(archive, [hello], [request])["connections_checked"], 1
        )
        extra = replace(hello, connection=99)
        self.assertEqual(
            compare_tls_captures(archive, [hello, extra], [request])[
                "non_request_hellos"
            ],
            1,
        )
        with self.assertRaisesRegex(ValueError, "coverage"):
            compare_tls_captures(archive, [extra], [request])
        wrong = copy.deepcopy(archive)
        wrong["profiles"][0]["key"]["user_agent"] = "other"
        with self.assertRaisesRegex(ValueError, "no matching"):
            compare_tls_captures(wrong, [hello], [request])
        forged = copy.deepcopy(archive)
        variants = forged["profiles"][0]["scopes"][0]["variants"]
        additional = copy.deepcopy(variants[0])
        additional["capture"]["slots"][0]["capture"]["ciphers"] = [999]
        variants.append(additional)
        with self.assertRaisesRegex(ValueError, "lacks"):
            compare_tls_captures(forged, [hello], [request])

    def test_forward_coverage_requires_the_entire_user_agent(self):
        archive, hello, request = comparison_fixture()
        request.headers = (("user-agent", "fixture-extra"),)
        with self.assertRaisesRegex(ValueError, "no matching"):
            compare_tls_captures(archive, [hello], [request])

    def test_reverse_coverage_preserves_user_agent_association(self):
        archive, first_hello, first_request = comparison_fixture()
        second_profile = copy.deepcopy(archive["profiles"][0])
        second_profile["key"]["user_agent"] = "other"
        second_variant = second_profile["scopes"][0]["variants"][0]
        second_capture = second_variant["capture"]["slots"][0]["capture"]
        second_capture["ciphers"] = [4866]
        archive["profiles"].append(second_profile)
        second_hello = replace(first_hello, connection=8, capture=second_capture)
        second_request = SimpleNamespace(
            connection=8, from_server=False, headers=(("user-agent", "other"),)
        )
        hellos = [first_hello, second_hello]
        requests = [first_request, second_request]
        self.assertEqual(
            compare_tls_captures(archive, hellos, requests)["connections_checked"], 2
        )

        # The first browser's genuine metadata is not evidence for an extra
        # retained observation attributed to the second browser.
        forged = copy.deepcopy(archive)
        variants = forged["profiles"][1]["scopes"][0]["variants"]
        first_variant = archive["profiles"][0]["scopes"][0]["variants"][0]
        variants.append(copy.deepcopy(first_variant))
        with self.assertRaisesRegex(ValueError, "lacks"):
            compare_tls_captures(forged, hellos, requests)

        # Identical metadata remains valid when both browsers actually emit it.
        shared = copy.deepcopy(archive)
        shared["profiles"][1]["scopes"] = copy.deepcopy(shared["profiles"][0]["scopes"])
        shared_hello = replace(second_hello, capture=copy.deepcopy(first_hello.capture))
        self.assertEqual(
            compare_tls_captures(shared, [first_hello, shared_hello], requests)[
                "retained_observations"
            ],
            2,
        )

    def test_reverse_coverage_preserves_transport(self):
        archive, hello, request = comparison_fixture()
        variants = archive["profiles"][0]["scopes"][0]["variants"]
        extra = copy.deepcopy(variants[0])
        slot = extra["capture"]["slots"][0]
        slot["kind"] = "QuicTls"
        slot["capture"]["transport"] = "Quic"
        variants.append(extra)
        with self.assertRaisesRegex(ValueError, "lacks"):
            compare_tls_captures(archive, [hello], [request])

        quic_request = SimpleNamespace(
            connection=8, from_server=False, headers=request.headers
        )
        quic_hello = replace(hello, connection=8, capture=slot["capture"])
        self.assertEqual(
            compare_tls_captures(archive, [hello, quic_hello], [request, quic_request])[
                "retained_observations"
            ],
            2,
        )

    def test_missing_or_mixed_user_agent_fails(self):
        archive, hello, request = comparison_fixture()
        for headers in [(), (("user-agent", "fixture"), ("user-agent", "fixture"))]:
            with self.assertRaisesRegex(ValueError, "user agent"):
                compare_tls_captures(
                    archive,
                    [hello],
                    [SimpleNamespace(connection=7, from_server=False, headers=headers)],
                )
        other = SimpleNamespace(
            connection=7, from_server=False, headers=(("user-agent", "other"),)
        )
        with self.assertRaisesRegex(ValueError, "mixed"):
            compare_tls_captures(archive, [hello], [request, other])


if __name__ == "__main__":
    unittest.main()
