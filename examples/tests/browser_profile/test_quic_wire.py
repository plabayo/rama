"""QUIC fragments, raw extents, bindings and correlated capture regressions."""

from copy import deepcopy
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

from quic_wire import (
    client_settings,
    compare_quic_captures,
    first_flights,
    parameters,
    parameters_match,
    varint,
    varint_field,
)
from tls_wire import Reader, TlsHello
from wire import read_header_blocks


def scalar(name, raw, *, show=None, position=0):
    show = int.from_bytes(raw, "big") if show is None else show
    return f'<field name="{name}" pos="{position}" size="{len(raw)}" value="{raw.hex()}" show="{show}"/>'


def computed(name, value):
    return f'<field name="{name}" size="0" pos="0" show="{value}"/>'


def parameter_extension():
    # Reusable integer value plus a connection-owned CID. The latter must only
    # be compared by its retained length, never copied into a profile/report.
    body = b"\x04\x02\x40\x64\x0f\x0a" + b"private-id"
    body += b"\x11\x0c" + bytes.fromhex("00000001000000011a1a1a1a")
    raw = b"\x00\x39" + len(body).to_bytes(2, "big") + body
    return (
        f'<field name="tls.handshake.extension" pos="100" size="{len(raw)}" value="{raw.hex()}">'
        + scalar("tls.handshake.extension.type", b"\x00\x39", position=100)
        + "</field>"
    )


def datagram(number, *, complete=False):
    # Two authenticated Initial payloads. Only packet 2 contains the dissector's
    # reassembled ClientHello node; packet 1 still belongs to the first flight.
    crypto = (
        '<field name="quic.frame" size="35">'
        + scalar("quic.frame_type", b"\x06")
        + scalar("quic.crypto.offset", bytes([(number - 1) * 32]))
        + scalar("quic.crypto.length", b"\x20")
        + "</field>"
    )
    padding = (
        '<field name="quic.frame" size="1180">'
        + scalar("quic.frame_type", b"\x00")
        + computed("quic.padding_length", 1180)
        + "</field>"
    )
    hello = (
        '<field name="tls.handshake">'
        + computed("tls.handshake.type", 1)
        + parameter_extension()
        + "</field>"
        if complete
        else ""
    )
    return (
        "<packet>"
        + computed("frame.number", number)
        + scalar("udp.srcport", (10000).to_bytes(2, "big"))
        + scalar("udp.dstport", (443).to_bytes(2, "big"))
        + scalar("udp.length", (1258).to_bytes(2, "big"))
        + '<proto name="quic" pos="32" size="1250">'
        + computed("quic.connection.number", 7)
        + computed("quic.packet_length", 1250)
        + computed("quic.long.packet_type", 0)
        + scalar("quic.version", b"\x00\x00\x00\x01")
        + scalar("quic.dcil", b"\x08")
        + scalar("quic.scil", b"\x00")
        + scalar("quic.token_length", b"\x00")
        + scalar("quic.length", b"\x44\xd0", show=1232, position=48)
        # Raw PN bytes are protected; the displayed PN and extent are decoded.
        + scalar("quic.packet_number", b"\xab", show=number)
        + crypto
        + padding
        + hello
        + "</proto></packet>"
    )


def document(*, complete=True):
    return (
        "<pdml>" + datagram(1) + datagram(2, complete=complete) + "</pdml>"
    ).encode()


def settings_document():
    payload = bytes.fromhex("0140642107")
    return (
        "<pdml><packet>"
        + computed("quic.connection.number", 7)
        + scalar("udp.srcport", (10000).to_bytes(2, "big"))
        + scalar("udp.dstport", (443).to_bytes(2, "big"))
        + '<field name="http3.frame" size="7">'
        + scalar("http3.frame_type", b"\x04")
        + scalar("http3.frame_length", b"\x05")
        + scalar("http3.frame_payload", payload)
        + "</field></packet></pdml>"
    ).encode()


def comparison_fixture():
    observed = first_flights(document(), 443)[0]
    tls = {"transport": "Quic", "ciphers": [4865]}
    retained_parameters = dict(
        completeness="Complete",
        namespace="QuicParameter",
        fields=[
            {"id": 4, "value": {"Literal": [64, 100]}},
            {"id": 15, "value": {"ConnectionLength": 10}},
            {
                "id": 17,
                "value": {"Literal": list(bytes.fromhex("00000001000000011a1a1a1a"))},
            },
        ],
    )
    slots = [
        {"kind": "QuicTls", "capture": tls},
        {"kind": "QuicParameters", "capture": retained_parameters},
        {
            "kind": "QuicFirstFlight",
            "capture": {
                "completeness": "Complete",
                "flight": deepcopy(observed.flight),
            },
        },
        {
            "kind": "Http3Settings",
            "capture": client_settings(settings_document(), 443)[7],
        },
        {"kind": "Http3Sequence", "capture": {}},
    ]
    archive = dict(
        format_version=1,
        profiles=[
            dict(
                key={"user_agent": "fixture"},
                scopes=[
                    dict(variants=[dict(capture=dict(level="Connection", slots=slots))])
                ],
            )
        ],
    )
    hello = TlsHello(2, 7, tls)
    request = SimpleNamespace(
        connection=7, from_server=False, headers=(("user-agent", "fixture"),)
    )
    return archive, observed, hello, request


class QuicWireTests(unittest.TestCase):
    def test_fragment_only_initials_remain_in_the_complete_first_flight(self):
        flight = first_flights(document(), 443)[0].flight
        self.assertEqual(flight["datagram_sizes"], [1250, 1250])
        self.assertEqual(flight["packet_numbers"], [1, 2])
        self.assertEqual(flight["frames"][0][0], {"Crypto": {"offset": 0, "len": 32}})
        self.assertEqual(flight["frames"][1][0], {"Crypto": {"offset": 32, "len": 32}})
        self.assertEqual(flight["chosen_version"], 1)
        self.assertEqual(flight["available_versions"], [1, 0x1A1A1A1A])
        with self.assertRaisesRegex(ValueError, "no complete"):
            first_flights(document(complete=False), 443)

    def test_version_two_uses_its_own_initial_packet_type(self):
        version_one = scalar("quic.version", b"\x00\x00\x00\x01").encode()
        version_two = scalar("quic.version", bytes.fromhex("6b3343cf")).encode()
        data = (
            document()
            .replace(version_one, version_two)
            .replace(
                computed("quic.long.packet_type", 0).encode(),
                computed("quic.long.packet_type", 1).encode(),
            )
        )
        self.assertEqual(first_flights(data, 443)[0].flight["version"], 0x6B3343CF)
        unknown = data.replace(
            version_two, scalar("quic.version", bytes.fromhex("ffffffff")).encode()
        )
        with self.assertRaisesRegex(ValueError, "unsupported QUIC wire version"):
            first_flights(unknown, 443)

    def test_retransmitted_packet_numbers_retain_evidence_without_duplicate_frames(
        self,
    ):
        repeated = document().replace(datagram(1).encode(), (datagram(1) * 2).encode())
        flight = first_flights(repeated, 443)[0].flight
        self.assertEqual(flight["packet_numbers"], [1, 1, 2])
        self.assertEqual(len(flight["frames"]), 2)
        for budget in ("MAX_FRAMES", "MAX_PACKETS", "MAX_DATAGRAMS"):
            with self.subTest(budget=budget), patch("quic_wire." + budget, 1):
                with self.assertRaisesRegex(ValueError, "limit"):
                    first_flights(document(), 443)

    def test_raw_varints_and_frame_extents_must_agree(self):
        self.assertEqual(varint(Reader(b"\x40\x25")), 37)
        with self.assertRaises(ValueError):
            varint(Reader(b"\x80"))
        malformed = ET.fromstring(
            "<field>" + scalar("test", b"\x40", show=0) + "</field>"
        )
        with self.assertRaises(ValueError):
            varint_field(malformed, "test")
        damaged = document().replace(b'show="1232"', b'show="1233"')
        with self.assertRaisesRegex(ValueError, "display/raw mismatch"):
            first_flights(damaged, 443)
        damaged = document().replace(
            b'name="quic.frame" size="35"', b'name="quic.frame" size="36"'
        )
        with self.assertRaisesRegex(ValueError, "CRYPTO extent"):
            first_flights(damaged, 443)
        damaged = document().replace(
            b'name="quic.packet_number" pos="0" size="1"',
            b'name="quic.packet_number" pos="0" size="2"',
        )
        with self.assertRaisesRegex(ValueError, "packet-number extent"):
            first_flights(damaged, 443)

    def test_parameters_preserve_order_literals_and_only_redacted_lengths(self):
        archive, observed, _hello, _request = comparison_fixture()
        captured = archive["profiles"][0]["scopes"][0]["variants"][0]["capture"][
            "slots"
        ][1]["capture"]
        self.assertTrue(parameters_match(captured, observed.parameters))
        self.assertNotIn("private-id", repr(observed))
        changed = list(observed.parameters)
        changed[1] = (15, b"other--id!")
        self.assertTrue(parameters_match(captured, changed))
        changed[1] = (15, b"short")
        self.assertFalse(parameters_match(captured, changed))
        changed = list(observed.parameters)
        changed[0] = (4, b"\x40\x65")
        self.assertFalse(parameters_match(captured, changed))
        self.assertFalse(
            parameters_match(captured, tuple(reversed(observed.parameters)))
        )
        raw = ET.fromstring(parameter_extension())
        self.assertEqual(parameters(raw), observed.parameters)

    def test_transport_and_tls_components_cannot_be_stitched_between_joints(self):
        archive, observed, hello, request = comparison_fixture()
        report = compare_quic_captures(
            archive,
            [observed],
            [hello],
            client_settings(settings_document(), 443),
            [request],
        )
        self.assertEqual(
            report["verified_slots"],
            ["QuicTls", "QuicParameters", "QuicFirstFlight", "Http3Settings"],
        )
        self.assertEqual(report["unverified_slots"], ["Http3Sequence"])
        with self.assertRaisesRegex(ValueError, "matching retained joint"):
            compare_quic_captures(
                archive,
                [observed],
                [replace(hello, capture={"transport": "Quic", "ciphers": [4866]})],
                client_settings(settings_document(), 443),
                [request],
            )
        settings = client_settings(settings_document(), 443)
        wrong_settings = deepcopy(settings)
        wrong_settings[7]["fields"][0]["value"]["Literal"][-1] += 1
        with self.assertRaisesRegex(ValueError, "matching retained joint"):
            compare_quic_captures(
                archive, [observed], [hello], wrong_settings, [request]
            )
        missing_fragment = first_flights(
            ("<pdml>" + datagram(2, complete=True) + "</pdml>").encode(), 443
        )
        with self.assertRaisesRegex(ValueError, "matching retained joint"):
            compare_quic_captures(
                archive, missing_fragment, [hello], settings, [request]
            )
        variants = archive["profiles"][0]["scopes"][0]["variants"]
        other = deepcopy(variants[0])
        other["capture"]["slots"][0]["capture"]["ciphers"] = [4866]
        other["capture"]["slots"][1]["capture"]["fields"][0]["value"]["Literal"] = [
            64,
            101,
        ]
        variants.append(other)
        changed = replace(
            observed, parameters=((4, b"\x40\x65"), *observed.parameters[1:])
        )
        with self.assertRaisesRegex(ValueError, "matching retained joint"):
            compare_quic_captures(
                archive,
                [changed],
                [hello],
                client_settings(settings_document(), 443),
                [request],
            )
        with self.assertRaisesRegex(ValueError, "no wire observation"):
            compare_quic_captures(
                archive,
                [observed],
                [hello],
                client_settings(settings_document(), 443),
                [request],
            )

    def test_settings_use_raw_ordered_values_and_complete_framing(self):
        settings = client_settings(settings_document(), 443)[7]
        self.assertEqual([entry["id"] for entry in settings["fields"]], [1, 33])
        self.assertEqual(
            int.from_bytes(bytes(settings["fields"][0]["value"]["Literal"]), "big"), 100
        )
        duplicated = settings_document().replace(
            b'value="0140642107"', b'value="0140640107"'
        )
        with self.assertRaisesRegex(ValueError, "duplicate"):
            client_settings(duplicated, 443)
        for before, after in [
            (b'http3.frame" size="7"', b'http3.frame" size="8"'),
            (b'value="0140642107"', b'value="014064"'),
        ]:
            with self.subTest(before=before), self.assertRaises(ValueError):
                client_settings(settings_document().replace(before, after), 443)

    def test_same_verified_projection_cannot_credit_multiple_joint_ids(self):
        archive, observed, hello, request = comparison_fixture()
        variants = archive["profiles"][0]["scopes"][0]["variants"]
        variants.append(deepcopy(variants[0]))
        with self.assertRaisesRegex(ValueError, "ambiguous retained QUIC"):
            compare_quic_captures(
                archive,
                [observed],
                [hello],
                client_settings(settings_document(), 443),
                [request],
            )

    def test_filter_keeps_fragment_only_packets_for_downstream_verification(self):
        def decode(command, *, stdout, **_kwargs):
            display_filter = command[command.index("-Y") + 1]
            # Model packet membership, not an assertion on a command constant:
            # protocol-wide selection includes the first fragment-only packet.
            selected = (
                document()
                if display_filter == "quic"
                else ("<pdml>" + datagram(2, complete=True) + "</pdml>").encode()
            )
            stdout.write(selected)

        with TemporaryDirectory() as directory:
            root = Path(directory)
            capture, keys, output = (
                root / name for name in ("capture", "keys", "decoded")
            )
            capture.touch()
            keys.touch()
            with patch("wire.subprocess.run", side_effect=decode), patch(
                "wire.parse_pdml", return_value=[]
            ):
                read_header_blocks(capture, keys, "h3", 443, output)
            flight = first_flights(output.read_bytes(), 443)[0].flight
            self.assertEqual(flight["packet_numbers"], [1, 2])


if __name__ == "__main__":
    unittest.main()
