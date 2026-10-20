"""Raw QPACK instruction coverage, metadata and redaction regressions."""

from dataclasses import replace
import json
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

import qpack_wire as qpack
from h3_sequence_wire import sequence_matches, stream_prefixes
from test_h3_sequence_wire import capture, document, evidence, stream_packet
from test_quic_wire import scalar

CAPACITY = "http3.qpack.encoder.opcode.dtable_cap"
REFERENCE = "http3.qpack.encoder.opcode.insert_indexed"
LITERAL = "http3.qpack.encoder.opcode.insert"
DUPLICATE = "http3.qpack.encoder.opcode.duplicate"


def instruction(kind, raw, *, name=None):
    children = (
        "" if name is None else scalar(LITERAL + ".name", name, show="decoded name")
    )
    return (
        f'<field name="{kind}" size="{len(raw)}" value="{raw.hex()}">'
        + children
        + "</field>"
    )


def fixture(*nodes, raw=b"\x20", server=False):
    packet = stream_packet(7 if server else 6, b"\x02" + raw, server=server)
    packet = packet.replace("</packet>", "".join(nodes) + "</packet>")
    data = document(packet)
    return data, stream_prefixes(data, 443)


class QpackWireTests(unittest.TestCase):
    def test_capacity_reference_literal_and_duplicate_metadata(self):
        # Inserted values are parsed for framing/flags and immediately discarded.
        cases = [
            (CAPACITY, b"\x20", None, {"Capacity": {"capacity": 0}}),
            (CAPACITY, b"\x3f\x00", None, {"Capacity": {"capacity": 31}}),
            (DUPLICATE, b"\x05", None, {"Duplicate": {"index": 5}}),
            (
                REFERENCE,
                b"\xc0\x81\x1f",
                None,
                {
                    "InsertNameReference": dict(
                        is_static=True, index=0, value_bytes=0, value_huffman=True
                    )
                },
            ),
            (
                REFERENCE,
                b"\x82\x01z",
                None,
                {
                    "InsertNameReference": dict(
                        is_static=False, index=2, value_bytes=0, value_huffman=False
                    )
                },
            ),
            (
                LITERAL,
                b"\x41a\x01b",
                b"a",
                {
                    "InsertLiteral": dict(
                        name_bytes=1,
                        value_bytes=0,
                        name_huffman=False,
                        value_huffman=False,
                    )
                },
            ),
            # HPACK Huffman 'a' (00011 + EOS padding), decoded by tshark.
            (
                LITERAL,
                b"\x61\x1f\x00",
                b"a",
                {
                    "InsertLiteral": dict(
                        name_bytes=1,
                        value_bytes=0,
                        name_huffman=True,
                        value_huffman=False,
                    )
                },
            ),
        ]
        for kind, raw, name, expected in cases:
            with self.subTest(kind=kind, raw=raw):
                encoded, observed = qpack.decode_instruction(
                    ET.fromstring(instruction(kind, raw, name=name))
                )
                self.assertEqual(encoded, raw)
                self.assertEqual(observed, expected)

    def test_truncated_overflowing_and_wrong_opcode_reject(self):
        for kind, raw in [
            (CAPACITY, b"\x3f"),
            (DUPLICATE, b"\x1f" + b"\xff" * 10),
            (REFERENCE, b"\xc0\x04x"),
            (CAPACITY, b"\x05"),
            (DUPLICATE, b"\x00\x00"),
        ]:
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                qpack.decode_instruction(ET.fromstring(instruction(kind, raw)))

    def test_decoded_literal_name_is_bounded_and_agrees_when_not_huffman(self):
        raw = b"\x41a\x00"
        for node in [
            instruction(LITERAL, raw, name=b"b"),
            instruction(LITERAL, raw),
            instruction(LITERAL, raw, name=b"a").replace('size="1"', 'size="2"'),
        ]:
            with self.subTest(node=node), self.assertRaises(ValueError):
                qpack.decode_instruction(ET.fromstring(node))
        with patch.object(qpack, "MAX_STRING_BYTES", 0), self.assertRaisesRegex(
            ValueError, "limit"
        ):
            qpack.decode_instruction(
                ET.fromstring(instruction(LITERAL, raw, name=b"a"))
            )

    def test_raw_instruction_extent_must_be_complete(self):
        node = ET.fromstring(instruction(CAPACITY, b"\x20"))
        node.set("size", "2")
        with self.assertRaisesRegex(ValueError, "extent"):
            qpack.decode_instruction(node)

    def test_instructions_reconstruct_encoder_stream_and_ignore_server_direction(self):
        raw = b"\x20\x05"
        data, streams = fixture(
            instruction(CAPACITY, b"\x20"), instruction(DUPLICATE, b"\x05"), raw=raw
        )
        observed = qpack.encoder_instructions(data, 443, streams)
        self.assertEqual(
            observed[7], ({"Capacity": {"capacity": 0}}, {"Duplicate": {"index": 5}})
        )
        data, streams = fixture(instruction(CAPACITY, b"\x20"), server=True)
        self.assertEqual(qpack.encoder_instructions(data, 443, streams), {})

    def test_missing_reordered_or_duplicate_dissection_cannot_prove_coverage(self):
        for nodes in [
            [],
            [instruction(DUPLICATE, b"\x05"), instruction(CAPACITY, b"\x20")],
            [
                instruction(CAPACITY, b"\x20"),
                instruction(DUPLICATE, b"\x05"),
                instruction(DUPLICATE, b"\x05"),
            ],
        ]:
            data, streams = fixture(*nodes, raw=b"\x20\x05")
            with self.subTest(nodes=nodes), self.assertRaisesRegex(
                ValueError, "cover encoder"
            ):
                qpack.encoder_instructions(data, 443, streams)
        data, _ = fixture(instruction(CAPACITY, b"\x20"))
        with self.assertRaisesRegex(ValueError, "lack their encoder"):
            qpack.encoder_instructions(data, 443, {})

    def test_instruction_count_and_byte_budgets(self):
        data, streams = fixture(instruction(CAPACITY, b"\x20"))
        for bound in ["MAX_INSTRUCTIONS", "MAX_STRING_BYTES"]:
            with self.subTest(bound=bound), patch.object(
                qpack, bound, 0
            ), self.assertRaisesRegex(ValueError, "limit"):
                qpack.encoder_instructions(data, 443, streams)

    def test_values_are_not_retained_in_metadata(self):
        value = b"private-test-value"
        raw = b"\xc0" + bytes([len(value)]) + value
        data, streams = fixture(instruction(REFERENCE, raw), raw=raw)
        observed = qpack.encoder_instructions(data, 443, streams)
        self.assertNotIn(value.decode(), json.dumps(observed))
        self.assertEqual(observed[7][0]["InsertNameReference"]["value_bytes"], 0)

    def test_selected_instruction_prefix_and_stream_must_agree(self):
        retained, observed = capture(), evidence()
        instructions = ({"Capacity": {"capacity": 4096}}, {"Duplicate": {"index": 5}})
        observed = replace(observed, encoder_instructions=instructions)
        retained["encoder_instructions"] = list(instructions[:1])
        self.assertFalse(sequence_matches(retained, observed))
        retained["events"].append({"Stream": {"stream_id": 6, "stream_type": 2}})
        self.assertTrue(sequence_matches(retained, observed))
        retained["encoder_instructions"][0] = {"Capacity": {"capacity": 4095}}
        self.assertFalse(sequence_matches(retained, observed))


if __name__ == "__main__":
    unittest.main()
