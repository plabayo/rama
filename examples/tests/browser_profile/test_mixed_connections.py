"""Mixed TCP/QUIC evidence must preserve native identity in both directions."""

from copy import deepcopy
import unittest

from capture_fields import connection_user_agents
from connection_fields import compare_connection_fields
from quic_wire import client_settings, compare_quic_captures
from test_connection_fields import fixture as h2_fixture
from test_quic_wire import (
    comparison_fixture as quic_fixture,
    sequence_fixture,
    settings_document,
)
from tls_wire import client_hellos, compare_tls_captures


def mixed_fixture():
    archive, tcp_hello, tcp_request, prefix = h2_fixture()
    quic_archive, flight, quic_hello, quic_request = quic_fixture()
    quic_archive["profiles"][0]["key"]["user_agent"] = "quic-browser"
    quic_request.headers = (("user-agent", "quic-browser"),)
    archive["profiles"].extend(quic_archive["profiles"])
    return archive, [tcp_hello, quic_hello], [tcp_request, quic_request], prefix, flight


def hello_packet(transport, cipher, packet):
    """Construct complete dissection spans with independently numbered transports."""
    body = (
        b"\x03\x03" + bytes(32) + b"\x00\x00\x02"
        + cipher.to_bytes(2, "big") + b"\x01\x00\x00\x00"
    )
    raw = b"\x01" + len(body).to_bytes(3, "big") + body
    identity = "tcp.stream" if transport == "Tcp" else "quic.connection.number"
    return (
        f'<packet><field name="frame.number" show="{packet}"/>'
        f'<field name="{identity}" show="7"/>'
        f'<field name="tls.handshake" pos="0" size="{len(raw)}" value="{raw.hex()}">'
        '<field name="tls.handshake.type" show="1" pos="0" size="1" value="01"/>'
        '</field></packet>'
    )


class MixedConnectionTests(unittest.TestCase):
    def test_tls_dissection_selects_transport_without_renumbering(self):
        document = (
            "<pdml>" + hello_packet("Tcp", 4865, 1)
            + hello_packet("Quic", 4866, 2) + "</pdml>"
        ).encode()
        for transport, cipher in [("Tcp", 4865), ("Quic", 4866)]:
            with self.subTest(transport=transport):
                observed = client_hellos(document, transport)
                self.assertEqual(len(observed), 1)
                self.assertEqual(observed[0].connection, 7)
                self.assertEqual(observed[0].capture["ciphers"], [cipher])
                self.assertEqual(observed[0].capture["transport"], transport)

        ambiguous = document.replace(
            b'<field name="tcp.stream" show="7"/>',
            b'<field name="tcp.stream" show="7"/>'
            b'<field name="quic.connection.number" show="7"/>',
        )
        for transport in ("Tcp", "Quic"):
            with self.subTest(transport=transport), self.assertRaisesRegex(
                ValueError, "ambiguous TLS transport"
            ):
                client_hellos(ambiguous, transport)

    def test_same_numbered_connections_have_independent_tls_and_native_joints(self):
        archive, hellos, requests, prefix, flight = mixed_fixture()
        self.assertEqual(
            connection_user_agents(requests),
            {("Tcp", 7): "fixture", ("Quic", 7): "quic-browser"},
        )
        self.assertEqual(
            compare_tls_captures(archive, hellos, requests)["connections_checked"], 2
        )
        self.assertEqual(
            compare_connection_fields(archive, hellos, {7: prefix}, requests)[
                "connections_checked"
            ],
            1,
        )
        self.assertEqual(
            compare_quic_captures(
                archive, [flight], hellos, client_settings(settings_document(), 443),
                requests, sequence_fixture(),
            )["connections_checked"],
            1,
        )

        # Matching the other transport cannot hide missing or corrupted evidence.
        for index in (0, 1):
            with self.subTest(missing=index), self.assertRaisesRegex(
                ValueError, "incomplete request-bearing"
            ):
                compare_tls_captures(archive, [hellos[1 - index]], requests)
            changed = deepcopy(hellos)
            changed[index].capture["ciphers"] = [4867]
            with self.subTest(corrupted=index), self.assertRaisesRegex(
                ValueError, "no matching TLS capture"
            ):
                compare_tls_captures(archive, changed, requests)

    def test_one_browser_retains_separate_tcp_and_quic_joints(self):
        archive, hellos, requests, prefix, flight = mixed_fixture()
        tcp_profile, quic_profile = archive["profiles"]
        tcp_profile["scopes"].extend(quic_profile["scopes"])
        archive["profiles"] = [tcp_profile]
        requests[1].headers = requests[0].headers

        self.assertEqual(
            compare_tls_captures(archive, hellos, requests)["connections_checked"], 2
        )
        self.assertEqual(
            compare_connection_fields(archive, hellos, {7: prefix}, requests)[
                "retained_joints_checked"
            ],
            1,
        )
        self.assertEqual(
            compare_quic_captures(
                archive, [flight], hellos, client_settings(settings_document(), 443),
                requests, sequence_fixture(),
            )["retained_joints_checked"],
            1,
        )

    def test_h1_header_casing_does_not_change_tcp_identity(self):
        archive, hello, request, _prefix = h2_fixture()
        request.protocol = "h1"
        request.headers = (("uSeR-aGeNt", "fixture"),)
        self.assertEqual(
            compare_tls_captures(archive, [hello], [request])["connections_checked"], 1
        )

        # H1/H2 numbers belong to the same TCP namespace, so their identities
        # must still agree rather than becoming separate browser connections.
        other = deepcopy(request)
        other.protocol = "h2"
        other.headers = (("user-agent", "other"),)
        with self.assertRaisesRegex(ValueError, "mixed connection"):
            connection_user_agents([request, other])


if __name__ == "__main__":
    unittest.main()
