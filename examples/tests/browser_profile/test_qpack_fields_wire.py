"""Wire-prefix fixtures and joint-membership regressions for QPACK metadata."""

import copy
import unittest
import xml.etree.ElementTree as ET
from dataclasses import asdict, replace
from qpack_fields_wire import (
    Representation,
    compare_field_metadata,
    compare_replay_policy,
    decode_section,
    sections_from_wire,
)
from unittest.mock import patch
from wire import HeaderBlock
from wire_fixtures import (
    QPACK_FIELDS_WIRE_HEADERS as HEADERS,
    QPACK_FIELDS_WIRE_METADATA as METADATA,
    QPACK_FIELDS_WIRE_PAYLOAD as PAYLOAD,
    qpack_fields_wire_document as document,
    qpack_fields_wire_field_slots as field_slots,
    qpack_fields_wire_fixture_variants as fixture_variants,
    qpack_fields_wire_inspected as inspected,
)

# GET, literal :path=/report, and literal user-agent=fixture.


class QpackFieldWireTests(unittest.TestCase):
    def policy_report(self, archive, blocks, sections):
        try:
            return compare_replay_policy(archive, blocks, sections)
        except ValueError as error:
            self.fail(f"valid replay policy was rejected: {error}")

    def test_all_field_families_and_huffman_never_index_flags(self):
        cases = [
            (b"\xc1", Representation("StaticIndex", 1)),
            (b"\x80", Representation("DynamicIndex", 0)),
            (b"\x10", Representation("DynamicPostBaseIndex", 0)),
            (b"\x50\x01x", Representation("LiteralStaticName", 0)),
            (b"\x40\x01x", Representation("LiteralDynamicName", 0)),
            (b"\x00\x01x", Representation("LiteralPostBaseName", 0)),
            (b"\x21x\x01y", Representation("LiteralName")),
            (b"\x39\xf3\x81\xf3", Representation(
                "LiteralName", name_huffman=True, value_huffman=True, never_index=True,
            )),
            (b"\x60\x81\xf3", Representation(
                "LiteralDynamicName", 0, value_huffman=True, never_index=True,
            )),
            (b"\x70\x81\xf3", Representation(
                "LiteralStaticName", 0, value_huffman=True, never_index=True,
            )),
            (b"\x08\x81\xf3", Representation(
                "LiteralPostBaseName", 0, value_huffman=True, never_index=True,
            )),
            (b"\xff\x1f", Representation("StaticIndex", 94)),
        ]
        for encoded, expected in cases:
            with self.subTest(expected=expected):
                self.assertEqual(decode_section(b"\x02\x80" + encoded), (2, True, 0, (expected,)))
        self.assertEqual(decode_section(PAYLOAD), (0, False, 0, METADATA))

    def test_truncation_and_limits_fail_before_accepting_partial_metadata(self):
        for payload in [b"", b"\x00", b"\x00\x00\xff", b"\x00\x00\x25x"]:
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                decode_section(payload)

    def test_frame_extents_counts_roles_and_identity_are_required(self):
        self.assertEqual(sections_from_wire(ET.tostring(document()), 443)[(1, 0, 0)].fields, METADATA)
        changes = [
            ("http3.frame_payload", "size", "1"),
            ("http3.frame", "size", "1"),
            ("http3.frame_length", "show", "1"),
            ("http3.headers.count", "show", "2"),
            ("http3.frame_streamid", "show", "2"),
            ("http3.frame_streamid", "show", "-4"),
            ("http3.frame_streamid", "show", str(1 << 62)),
            ("udp.srcport", "show", "443"),
        ]
        for name, attribute, value in changes:
            root = document()
            root.find(f".//field[@name='{name}']").set(attribute, value)
            with self.subTest(name=name), self.assertRaises(ValueError):
                sections_from_wire(ET.tostring(root), 443)
        root = document()
        packet = root.find("packet")
        packet.append(copy.deepcopy(packet.find("field[@name='http3.frame']")))
        with self.assertRaisesRegex(ValueError, "ambiguous HEADERS"):
            sections_from_wire(ET.tostring(root), 443)

    @patch("qpack_fields_wire.FLOW_NAMES", {"navigate"})
    def test_metadata_requires_the_same_joint_scope_and_client(self):
        sections = sections_from_wire(ET.tostring(document()), 443)
        blocks = [HeaderBlock("h3", 1, 0, 0, False, HEADERS)]
        self.assertEqual(compare_field_metadata(inspected(), blocks, sections)["fields_checked"], 3)
        archive = inspected()
        variants = fixture_variants(archive)
        wrong_regular = copy.deepcopy(variants[0])
        regular = wrong_regular["capture"]["slots"][0]["capture"]["fields"][0]
        regular["representation"]["never_index"] = True
        wrong_pseudo = copy.deepcopy(variants[0])
        pseudo = wrong_pseudo["capture"]["slots"][1]["capture"]["fields"][0]
        pseudo["representation"]["index"] = 0
        variants[:] = [wrong_regular, wrong_pseudo]
        with self.assertRaisesRegex(ValueError, "no matching request joint"):
            compare_field_metadata(archive, blocks, sections)
        archive = inspected()
        archive["profiles"][0]["key"]["user_agent"] = "another client"
        with self.assertRaisesRegex(ValueError, "no matching request joint"):
            compare_field_metadata(archive, blocks, sections)
        archive = inspected()
        archive["profiles"][0]["scopes"][0]["flow"]["Http"]["version"] = "HTTP/2.0"
        with self.assertRaisesRegex(ValueError, "no matching request joint"):
            compare_field_metadata(archive, blocks, sections)
        with self.assertRaisesRegex(ValueError, "incomplete QPACK"):
            compare_field_metadata(inspected(), [], sections)
        with self.assertRaisesRegex(ValueError, "lacks raw QPACK"):
            compare_field_metadata(inspected(), blocks, {})

    @patch("qpack_fields_wire.FLOW_NAMES", {"navigate"})
    def test_replay_policy_keeps_flags_static_indexes_and_one_joint(self):
        blocks = [HeaderBlock("h3", 1, 0, 0, False, HEADERS)]
        original = sections_from_wire(ET.tostring(document()), 443)[(1, 0, 0)]
        self.policy_report(inspected(), blocks, {(1, 0, 0): original})
        changed = [
            replace(original, fields=(*METADATA[:2], replace(METADATA[2], **{flag: True})))
            for flag in ("name_huffman", "value_huffman", "never_index")
        ]
        changed.append(
            replace(original, fields=(Representation("StaticIndex", 18), *original.fields[1:]))
        )
        for section in changed:
            with (
                self.subTest(fields=section.fields),
                self.assertRaisesRegex(ValueError, "no matching request joint"),
            ):
                compare_replay_policy(inspected(), blocks, {(1, 0, 0): section})
        kinds = (
            "DynamicIndex", "DynamicPostBaseIndex",
            "LiteralDynamicName", "LiteralPostBaseName",
        )
        for kind in kinds:
            with self.subTest(kind=kind):
                archive = inspected()
                capture = fixture_variants(archive)[0]["capture"]
                regular = field_slots(capture)["Headers"][0]
                regular["representation"] = asdict(Representation(kind, 7))
                section = replace(original, fields=(*METADATA[:2], Representation(kind, 0)))
                report = self.policy_report(archive, blocks, {(1, 0, 0): section})
                self.assertEqual(report["fields_checked"], 3)
                # Capture accuracy never adopts the cross-connection projection.
                with self.assertRaisesRegex(ValueError, "no matching request joint"):
                    compare_field_metadata(archive, blocks, {(1, 0, 0): section})
                for metadata in (
                    Representation(kind, 0, value_huffman=True),
                    Representation(kind, 0, never_index=True),
                    Representation("LiteralName"),
                ):
                    different = replace(section, fields=(*METADATA[:2], metadata))
                    with (
                        self.subTest(metadata=metadata),
                        self.assertRaisesRegex(ValueError, "no matching request joint"),
                    ):
                        compare_replay_policy(archive, blocks, {(1, 0, 0): different})
        archive = inspected()
        variants = fixture_variants(archive)
        wrong_regular = copy.deepcopy(variants[0])
        regular = field_slots(wrong_regular["capture"])["Headers"][0]
        regular["representation"]["never_index"] = True
        wrong_pseudo = copy.deepcopy(variants[0])
        pseudo = field_slots(wrong_pseudo["capture"])["PseudoHeaders"][0]
        pseudo["representation"]["index"] = 18
        variants[:] = [wrong_regular, wrong_pseudo]
        with self.assertRaisesRegex(ValueError, "no matching request joint"):
            compare_replay_policy(archive, blocks, {(1, 0, 0): original})
        for index in (None, -1, 1 << 62, True):
            archive = inspected()
            capture = fixture_variants(archive)[0]["capture"]
            regular = field_slots(capture)["Headers"][0]
            regular["representation"] = asdict(Representation("DynamicIndex", index))
            actual = replace(original, fields=(*METADATA[:2], Representation("DynamicIndex", 0)))
            with (
                self.subTest(index=index),
                self.assertRaisesRegex(ValueError, "invalid dynamic reference index"),
            ):
                compare_replay_policy(archive, blocks, {(1, 0, 0): actual})

    @patch("qpack_fields_wire.FLOW_NAMES", {"navigate"})
    def test_replay_policy_checks_nonidentity_header_values(self):
        archive = inspected()
        capture = fixture_variants(archive)[0]["capture"]
        field_slots(capture)["Headers"].append({
            "name": "x-probe",
            "occurrence": 0,
            "value": {"Profile": list(b"kept")},
            "representation": asdict(Representation("LiteralName")),
        })
        headers = (*HEADERS, ("x-probe", "kept"))
        blocks = [HeaderBlock("h3", 1, 0, 0, False, headers)]
        original = sections_from_wire(ET.tostring(document()), 443)[(1, 0, 0)]
        section = replace(original, fields=(*METADATA, Representation("LiteralName")))
        self.assertEqual(
            self.policy_report(archive, blocks, {(1, 0, 0): section})["fields_checked"],
            4,
        )
        changed = [replace(blocks[0], headers=(*HEADERS, ("x-probe", "changed")))]
        with self.assertRaisesRegex(ValueError, "no matching request joint"):
            compare_replay_policy(archive, changed, {(1, 0, 0): section})


if __name__ == "__main__":
    unittest.main()
