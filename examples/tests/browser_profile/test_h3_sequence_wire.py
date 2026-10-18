"""Independent H3 stream reassembly and recorder-prefix content regressions."""

from copy import deepcopy
import unittest
from unittest.mock import patch

import h3_sequence_wire as sequence
from quic_wire import compare_quic_captures, client_settings
from test_quic_wire import (
    comparison_fixture,
    computed,
    scalar,
    sequence_fixture,
    settings_document,
)


def number(value):
    width = next(size for size in (1, 2, 4, 8) if value < 1 << (8 * size - 2))
    return (value | ({1: 0, 2: 1, 4: 2, 8: 3}[width] << (8 * width - 2))).to_bytes(
        width, "big"
    )


def frame(kind, payload):
    return number(kind) + number(len(payload)) + payload


def stream_packet(stream_id, payload, *, offset=0, server=False, connection=7):
    fields = scalar("quic.frame_type", b"\x0e")
    fields += scalar("quic.stream.stream_id", number(stream_id), show=stream_id)
    fields += scalar("quic.stream.offset", number(offset), show=offset)
    fields += scalar("quic.stream.length", number(len(payload)), show=len(payload))
    fields += scalar("quic.stream_data", payload, show="payload")
    size = (
        1
        + len(number(stream_id))
        + len(number(offset))
        + len(number(len(payload)))
        + len(payload)
    )
    return (
        "<packet>"
        + computed("quic.connection.number", connection)
        + scalar("udp.srcport", (443 if server else 10000).to_bytes(2, "big"))
        + scalar("udp.dstport", (10000 if server else 443).to_bytes(2, "big"))
        + f'<field name="quic.frame" size="{size}">'
        + fields
        + "</field></packet>"
    )


def document(*packets):
    return ("<pdml>" + "".join(packets) + "</pdml>").encode()


def evidence():
    settings = dict(completeness="Complete", namespace="Http3Setting", fields=[])
    payload = frame(4, b"") + frame(0xF0700, b"\x00u=1, i") + frame(33, b"ignored")
    stream = sequence.StreamPrefix(2, 0, payload)
    return sequence.SequenceEvidence(
        (stream, sequence.StreamPrefix(6, 2, b"")),
        tuple(sequence.control_frames(stream)),
        settings,
    )


def capture():
    observed = evidence()
    return dict(
        completeness="Complete",
        local_settings=observed.local_settings,
        events=[{"Stream": {"stream_id": 2, "stream_type": 0}}]
        + [{"Control": item} for item in observed.controls],
        encoder_instructions=[],
    )


class H3SequenceWireTests(unittest.TestCase):
    def test_stream_count_is_per_connection_with_a_separate_capture_budget(self):
        packets = [stream_packet(2, b"\x00", connection=index) for index in range(33)]
        self.assertEqual(len(sequence.stream_prefixes(document(*packets), 443)), 33)

        overloaded = [stream_packet(2 + 4 * index, b"\x00") for index in range(33)]
        with self.assertRaisesRegex(ValueError, "connection stream count limit"):
            sequence.stream_prefixes(document(*overloaded), 443)
        with patch.object(sequence, "MAX_CAPTURE_STREAMS", 1):
            with self.assertRaisesRegex(ValueError, "capture stream count limit"):
                sequence.stream_prefixes(document(*packets[:2]), 443)

    def test_out_of_order_fragments_and_partial_retransmission_reassemble_once(self):
        payload = b"\x00" + frame(4, b"\x01\x10")
        decoded = sequence.stream_prefixes(
            document(
                stream_packet(2, payload[2:], offset=2),
                stream_packet(2, payload[:4]),
                stream_packet(2, payload[:4]),
                stream_packet(3, b"\x00" + frame(4, b""), server=True),
            ),
            443,
        )
        self.assertEqual(
            decoded[(7, False)], [sequence.StreamPrefix(2, 0, payload[1:])]
        )
        self.assertEqual(decoded[(7, True)][0].payload, frame(4, b""))

    def test_gaps_and_conflicting_overlap_cannot_create_a_prefix(self):
        for packets in [
            [stream_packet(2, b"\x04\x00", offset=1)],
            [stream_packet(2, b"\x00\x04"), stream_packet(2, b"\x05", offset=1)],
        ]:
            with self.subTest(packets=packets), self.assertRaises(ValueError):
                sequence.stream_prefixes(document(*packets), 443)

    def test_empty_stream_fin_without_data_field_preserves_existing_prefix(self):
        prefix = b"\x00" + frame(4, b"")
        empty = stream_packet(2, b"", offset=len(prefix))
        empty = empty.replace(scalar("quic.stream_data", b"", show="payload"), "")
        empty = empty.replace('value="0e" show="14"', 'value="0f" show="15"')
        try:
            decoded = sequence.stream_prefixes(
                document(stream_packet(2, prefix), empty), 443
            )
        except ValueError:
            decoded = None
        self.assertIsNotNone(
            decoded, "a valid empty FIN must not erase or reject its stream prefix"
        )
        self.assertEqual(decoded[(7, False)][0].payload, frame(4, b""))

    def test_missing_nonempty_or_duplicated_stream_payload_rejects(self):
        prefix = b"\x00" + frame(4, b"")
        raw = scalar("quic.stream_data", prefix, show="payload")
        packet = stream_packet(2, prefix)
        for changed in [packet.replace(raw, ""), packet.replace(raw, raw + raw)]:
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                sequence.stream_prefixes(document(changed), 443)

    def test_direction_and_connection_ids_do_not_share_reassembly(self):
        with self.assertRaisesRegex(ValueError, "wrong endpoint"):
            sequence.stream_prefixes(
                document(stream_packet(2, b"\x00", server=True)), 443
            )
        decoded = sequence.stream_prefixes(
            document(
                stream_packet(2, b"\x00"), stream_packet(2, b"\x02", connection=8)
            ),
            443,
        )
        self.assertEqual(decoded[(7, False)][0].stream_type, 0)
        self.assertEqual(decoded[(8, False)][0].stream_type, 2)

    def test_raw_stream_extent_and_length_are_checked(self):
        good = document(stream_packet(2, b"\x00\x04\x00"))
        for before, after in [
            (b'quic.frame" size="7"', b'quic.frame" size="8"'),
            (
                b'quic.stream.length" pos="0" size="1" value="03" show="3"',
                b'quic.stream.length" pos="0" size="1" value="04" show="4"',
            ),
        ]:
            changed = good.replace(before, after)
            self.assertNotEqual(changed, good)
            with self.assertRaises(ValueError):
                sequence.stream_prefixes(changed, 443)

    def test_stream_and_aggregate_budgets_include_retransmitted_bytes(self):
        data = document(
            stream_packet(2, b"\x00\x04\x00"), stream_packet(2, b"\x00\x04\x00")
        )
        for name, limit in [
            ("MAX_TOTAL_BYTES", 5),
            ("MAX_STREAM_BYTES", 2),
            ("MAX_STREAMS", 0),
        ]:
            with self.subTest(name=name), patch.object(
                sequence, name, limit
            ), self.assertRaisesRegex(ValueError, "limit"):
                sequence.stream_prefixes(data, 443)

    def test_control_values_preserve_priority_and_reserved_payload(self):
        observed = evidence()
        self.assertEqual(
            observed.controls[1],
            dict(frame_type=0xF0700, length=7, element_id=0, value=list(b"u=1, i")),
        )
        self.assertEqual(
            observed.controls[2],
            dict(frame_type=33, length=7, element_id=None, value=list(b"ignored")),
        )
        self.assertNotIn("ignored", repr(observed))
        self.assertNotIn("ignored", repr(observed.streams[0]))

    def test_control_framing_and_id_extents_must_be_complete(self):
        for payload in [
            frame(4, b"") + b"\x07\x02\x00",
            frame(4, b"") + frame(7, b"\x00\x00"),
            frame(4, b"") + frame(0xF0700, b""),
        ]:
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                sequence.control_frames(sequence.StreamPrefix(2, 0, payload))
        with patch.object(sequence, "MAX_CONTROL_FRAMES", 1), self.assertRaisesRegex(
            ValueError, "limit"
        ):
            sequence.control_frames(evidence().streams[0])

    def test_control_settings_are_first_and_unique(self):
        for payload in [
            frame(33, b"") + frame(4, b""),
            frame(4, b"") + frame(4, b""),
            b"",
        ]:
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                sequence.control_frames(sequence.StreamPrefix(2, 0, payload))

    def test_prefix_contents_match_without_inventing_cross_stream_schedule(self):
        retained = capture()
        self.assertTrue(sequence.sequence_matches(retained, evidence()))
        # A shorter recorder prefix can be valid: later control/QPACK bytes do
        # not prove when the application froze its first-request observation.
        retained["events"] = retained["events"][:2]
        self.assertTrue(sequence.sequence_matches(retained, evidence()))
        retained["events"].insert(0, {"Stream": {"stream_id": 6, "stream_type": 2}})
        self.assertTrue(sequence.sequence_matches(retained, evidence()))

    def test_context_stream_and_control_changes_cannot_match(self):
        cases = []
        for change in (
            "context",
            "stream",
            "duplicate",
            "priority",
            "order",
            "missing",
            "before-open",
        ):
            retained = deepcopy(capture())
            if change == "context":
                retained["local_settings"]["fields"] = [
                    {"id": 1, "value": {"Literal": [1]}}
                ]
            elif change == "stream":
                retained["events"][0]["Stream"]["stream_type"] = 2
            elif change == "duplicate":
                retained["events"].insert(1, deepcopy(retained["events"][0]))
            elif change == "priority":
                retained["events"][2]["Control"]["value"] = list(b"u=0, i")
            elif change == "order":
                retained["events"][1:3] = reversed(retained["events"][1:3])
            elif change == "missing":
                retained["events"] = retained["events"][:1]
            else:
                retained["events"] = retained["events"][1:]
            cases.append((change, retained))
        for label, retained in cases:
            with self.subTest(label=label):
                self.assertFalse(sequence.sequence_matches(retained, evidence()))

    def test_nonempty_qpack_needs_matching_instruction_evidence(self):
        retained = capture()
        retained["encoder_instructions"] = [{"Capacity": {"capacity": 4096}}]
        self.assertFalse(sequence.sequence_matches(retained, evidence()))

    def test_server_settings_supply_decoder_context_without_role_capabilities(self):
        # The browser's own capacity is 100; the receiving server's is 4096.
        # Confusing their directions would incorrectly accept a different QPACK
        # context. Capability advertisements are not recorder context settings.
        payload = b"".join(
            number(key) + number(value)
            for key, value in [(1, 4096), (7, 16), (6, 65536), (8, 1), (51, 1)]
        )
        settings = (
            '<field name="http3.frame" size="'
            + str(2 + len(payload))
            + '">'
            + scalar("http3.frame_type", b"\x04")
            + scalar("http3.frame_length", number(len(payload)), show=len(payload))
            + scalar("http3.frame_payload", payload, show="settings")
            + "</field>"
        )
        server = stream_packet(3, b"\x00" + frame(4, payload), server=True)
        server = server.replace("</packet>", settings + "</packet>")
        original = (
            settings_document().decode().removeprefix("<pdml>").removesuffix("</pdml>")
        )
        data = document(stream_packet(2, b"\x00" + frame(4, b"")), server, original)
        observed = sequence.sequence_evidence(data, 443)[7]
        self.assertEqual(
            [entry["id"] for entry in observed.local_settings["fields"]], [1, 7, 6]
        )
        self.assertEqual(
            [
                int.from_bytes(bytes(entry["value"]["Literal"]), "big")
                for entry in observed.local_settings["fields"]
            ],
            [4096, 16, 65536],
        )

    def test_sequence_must_match_the_same_tls_parameter_and_flight_joint(self):
        archive, flight, hello, request = comparison_fixture()
        slots = archive["profiles"][0]["scopes"][0]["variants"][0]["capture"]["slots"]
        slots[-1]["capture"]["local_settings"] = {"different": True}
        with self.assertRaisesRegex(ValueError, "matching retained joint"):
            compare_quic_captures(
                archive,
                [flight],
                [hello],
                client_settings(settings_document(), 443),
                [request],
                sequence_fixture(),
            )


if __name__ == "__main__":
    unittest.main()
