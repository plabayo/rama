"""QUIC fragments, raw extents, bindings and correlated capture regressions."""

import unittest
import xml.etree.ElementTree as ET
from copy import deepcopy
from dataclasses import replace
from pathlib import Path
from quic_stream_wire import varint, varint_field
from quic_wire import (
    client_settings,
    compare_quic_captures,
    first_flights,
    parameters,
    parameters_match,
)
from tempfile import TemporaryDirectory
from tls_wire import Reader
from unittest.mock import patch
from wire import read_header_blocks
from wire_fixtures import (
    comparison_fixture,
    computed,
    datagram,
    flow_fixture as flow_fixture,
    initial_document as document,
    padded_document,
    parameter_extension,
    scalar,
    sequence_fixture,
    settings_document,
)


class QuicWireTests(unittest.TestCase):
    def test_packet_number_widths_come_from_each_authenticated_extent(self):
        data = (
            "<pdml>"
            + datagram(1)
            + datagram(2, complete=True, number_width=2)
            + "</pdml>"
        ).encode()
        flight = first_flights(data, 443)[0].flight
        self.assertEqual(flight["packet_number_lengths"], [1, 2])

    def test_unattributed_short_header_packets_are_not_part_of_a_first_flight(self):
        short = (
            "<packet>"
            + computed("frame.number", 3)
            + scalar("udp.srcport", (10000).to_bytes(2, "big"))
            + scalar("udp.dstport", (443).to_bytes(2, "big"))
            + scalar("udp.length", (60).to_bytes(2, "big"))
            + '<proto name="quic" pos="32" size="52"></proto></packet>'
        )
        data = ("<pdml>" + datagram(1) + short + datagram(2, complete=True) + "</pdml>").encode()
        self.assertEqual(first_flights(data, 443)[0].flight["packet_numbers"], [1, 2])
        unattributed = datagram(1).replace(computed("quic.connection.number", 7), "")
        data = ("<pdml>" + unattributed + datagram(2, complete=True) + "</pdml>").encode()
        with self.assertRaisesRegex(ValueError, "quic.connection.number"):
            first_flights(data, 443)

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

    def test_explicit_padding_diagnostics_preserve_native_datagram_tails(self):
        root = padded_document()
        flight = first_flights(ET.tostring(root), 443)[0].flight
        self.assertEqual(flight["datagram_sizes"], [1252, 1252])
        self.assertEqual(flight["trailing_bytes"], [258, 261])
        self.assertEqual(flight["padding"], "DatagramTail")
        self.assertFalse(flight["coalesced"])
        self.assertEqual(flight["packet_numbers"], [1, 2])

    def test_missing_real_packet_length_cannot_masquerade_as_padding(self):
        root = padded_document()
        proto = root.find("packet/proto")
        proto.remove(proto.find("field[@name='quic.packet_length']"))
        with self.assertRaisesRegex(ValueError, "quic.packet_length"):
            first_flights(ET.tostring(root), 443)

    def test_padding_needs_positive_expert_only_terminal_extent(self):
        alternatives = []
        root = padded_document()
        tail = root.findall("packet")[0].findall("proto")[-1]
        tail.find(".//field[@name='quic.coalesced_padding_data']").set(
            "name", "unknown"
        )
        alternatives.append(root)
        root = padded_document()
        tail = root.findall("packet")[0].findall("proto")[-1]
        ET.SubElement(tail, "field", name="quic.version", show="1")
        alternatives.append(root)
        root = padded_document()
        root.find(".//field[@name='_ws.expert.message']").set(
            "show", "undecoded packet"
        )
        alternatives.append(root)
        for attribute, value in (("pos", "1025"), ("size", "257")):
            root = padded_document()
            root.findall("packet")[0].findall("proto")[-1].set(attribute, value)
            alternatives.append(root)
        root = padded_document()
        packet = root.findall("packet")[0]
        packet.insert(0, packet.findall("proto")[-1])
        alternatives.append(root)
        for root in alternatives:
            with self.subTest(document=ET.tostring(root)), self.assertRaises(
                ValueError
            ):
                first_flights(ET.tostring(root), 443)

    def test_version_two_uses_its_own_initial_packet_type(self):
        version_one = scalar("quic.version", b"\x00\x00\x00\x01").encode()
        version_two = scalar("quic.version", bytes.fromhex("6b3343cf")).encode()
        data = (
            document()
            .replace(version_one, version_two)
            .replace(
                computed("quic.long.packet_type", 0).encode(),
                computed("quic.long.packet_type_v2", 1).encode(),
            )
        )
        self.assertEqual(first_flights(data, 443)[0].flight["version"], 0x6B3343CF)
        # A v1 display field must not silently override or masquerade as v2.
        for malformed in (
            data.replace(b"quic.long.packet_type_v2", b"quic.long.packet_type"),
            data.replace(
                computed("quic.long.packet_type_v2", 1).encode(),
                (
                    computed("quic.long.packet_type_v2", 1)
                    + computed("quic.long.packet_type", 1)
                ).encode(),
            ),
            document().replace(b"quic.long.packet_type", b"quic.long.packet_type_v2"),
        ):
            with self.subTest(malformed=malformed), self.assertRaises(ValueError):
                first_flights(malformed, 443)
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
        self.assertEqual(flight["packet_number_lengths"], [1, 1, 1])
        self.assertEqual(len(flight["frames"]), 2)

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

    def test_replay_requires_every_flow_on_the_matched_connection_variant(self):
        archive, observed, hello, _request = comparison_fixture()
        requests = [
            replace(row, connection=7)
            for row in flow_fixture("h3")
            if row.headers and not row.from_server
        ]

        def compare(rows):
            return compare_quic_captures(
                archive,
                [observed],
                [hello],
                client_settings(settings_document(), 443),
                rows,
                sequence_fixture(),
                expected_per_variant_flow=1,
            )

        report = compare(requests)
        self.assertEqual(set(report["variant_flow_counts"]["01" * 32].values()), {1})
        for changed in [requests[:-1], requests + [requests[0]]]:
            with self.assertRaisesRegex(ValueError, "variant/flow matrix"):
                compare(changed)

    def test_transport_and_tls_components_cannot_be_stitched_between_joints(self):
        archive, observed, hello, request = comparison_fixture()
        report = compare_quic_captures(
            archive,
            [observed],
            [hello],
            client_settings(settings_document(), 443),
            [request],
            sequence_fixture(),
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
                sequence_fixture(),
            )
        settings = client_settings(settings_document(), 443)
        wrong_settings = deepcopy(settings)
        wrong_settings[7]["fields"][0]["value"]["Literal"][-1] += 1
        with self.assertRaisesRegex(ValueError, "matching retained joint"):
            compare_quic_captures(
                archive,
                [observed],
                [hello],
                wrong_settings,
                [request],
                sequence_fixture(),
            )
        missing_fragment = first_flights(
            ("<pdml>" + datagram(2, complete=True) + "</pdml>").encode(), 443
        )
        with self.assertRaisesRegex(ValueError, "matching retained joint"):
            compare_quic_captures(
                archive,
                missing_fragment,
                [hello],
                settings,
                [request],
                sequence_fixture(),
            )
        variants = archive["profiles"][0]["scopes"][0]["variants"]
        other = deepcopy(variants[0])
        other["id"] = [2] * 32
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
                sequence_fixture(),
            )
        with self.assertRaisesRegex(ValueError, "no wire observation"):
            compare_quic_captures(
                archive,
                [observed],
                [hello],
                client_settings(settings_document(), 443),
                [request],
                sequence_fixture(),
            )

    def test_settings_use_raw_ordered_values_and_complete_framing(self):
        settings = client_settings(settings_document(), 443)[7]
        self.assertEqual([entry["id"] for entry in settings["fields"]], [1, 33])
        self.assertEqual(
            int.from_bytes(bytes(settings["fields"][0]["value"]["Literal"]), "big"), 100
        )
        duplicated = settings_document().replace(b"0140642107", b"0140640107")
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
                sequence_fixture(),
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
