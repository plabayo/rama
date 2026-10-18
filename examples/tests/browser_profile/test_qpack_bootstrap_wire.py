"""Independent insertion decoding and exact initial-request reference guards."""

from copy import deepcopy
from dataclasses import replace
import json
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

import qpack_bootstrap_wire as bootstrap
from h3_sequence_wire import StreamPrefix
from qpack_wire import decode_instruction, encoder_instruction_evidence
from quic_wire import client_settings, compare_quic_captures
from test_qpack_fields_wire import inspected
from test_qpack_wire import (
    CAPACITY,
    DUPLICATE,
    LITERAL,
    REFERENCE,
    fixture,
    instruction,
)
from test_quic_wire import comparison_fixture, sequence_fixture, settings_document


def bootstrap_fixture():
    archive, flight, hello, _request = comparison_fixture()
    profile = archive["profiles"][0]
    connection_scope = profile["scopes"][0]
    slots = connection_scope["variants"][0]["capture"]["slots"]
    sequence = slots[-1]["capture"]
    sequence["events"].append({"Stream": {"stream_id": 6, "stream_type": 2}})

    # Capacity4096; static :authority name with a current connection-owned value;
    # then Huffman literal a:b. The independent decoder must resolve both forms.
    secret = b"private-current-origin"
    raw = (
        b"\x3f\xe1\x1f",
        b"\xc0" + bytes([len(secret)]) + secret,
        b"\x61\x1f\x81\x8f",
    )
    data, streams = fixture(
        instruction(CAPACITY, raw[0]),
        instruction(REFERENCE, raw[1]),
        instruction(LITERAL, raw[2], name=b"a"),
        raw=b"".join(raw),
    )
    metadata, encoded = encoder_instruction_evidence(data, 443, streams)[7]
    sequence["encoder_instructions"] = list(metadata)
    observed = sequence_fixture()[7]
    observed = replace(
        observed,
        streams=(*observed.streams, StreamPrefix(6, 2, b"".join(raw))),
        encoder_instructions=metadata,
        encoder_bytes=encoded,
    )
    headers = (
        (":method", "GET"),
        (":path", "/report"),
        (":authority", secret.decode()),
        ("user-agent", "fixture"),
        ("a", "b"),
    )
    request = SimpleNamespace(
        protocol="h3",
        connection=7,
        stream=0,
        packet=10,
        from_server=False,
        headers=headers,
    )
    request_scope = inspected()["profiles"][0]["scopes"][0]
    request_scope["variants"][0]["id"] = [2] * 32
    capture = request_scope["variants"][0]["capture"]
    capture["level"] = "Request"
    capture["slots"][0]["capture"]["fields"].append(
        {
            "name": "a",
            "occurrence": 0,
            "value": {"Profile": list(b"b")},
        }
    )
    capture["slots"][1]["capture"]["fields"].append({"name": ":authority"})
    profile["scopes"].append(request_scope)
    binding = {
        "request": [2] * 32,
        "method": "GET",
        "fields": len(headers),
        "bindings": {
            "stream_id": 0,
            "complete": True,
            "insertions": [
                {
                    "instruction_index": 1,
                    "insertion_index": 0,
                    "field": {"Unique": {"field_index": 2}},
                },
                {
                    "instruction_index": 2,
                    "insertion_index": 1,
                    "field": {"Unique": {"field_index": 4}},
                },
            ],
        },
    }
    slots.append({"kind": "Http3Bootstrap", "capture": binding})
    return archive, flight, hello, request, observed, binding


def compare_fixture(archive, flight, hello, request, observed, _binding):
    return compare_quic_captures(
        archive,
        [flight],
        [hello],
        client_settings(settings_document(), 443),
        [request],
        {7: observed},
    )


class QpackBootstrapWireTests(unittest.TestCase):
    def test_actual_raw_insertions_bind_to_one_initial_request_and_scoped_joint(self):
        rows = bootstrap_fixture()
        report = compare_fixture(*rows)
        self.assertEqual(report["bootstrap_connections_checked"], 1)
        self.assertEqual(report["bootstrap_insertions_checked"], 2)
        self.assertIn("Http3Bootstrap", report["verified_slots"])
        self.assertIn("freeze", report["sequence_limits"])
        self.assertNotIn("private-current-origin", json.dumps(report))
        self.assertNotIn("private-current-origin", repr(rows[4]))

    def test_empty_bootstrap_still_requires_its_scoped_initial_request(self):
        rows = list(bootstrap_fixture())
        sequence = rows[0]["profiles"][0]["scopes"][0]["variants"][0]["capture"][
            "slots"
        ][4]["capture"]
        sequence["encoder_instructions"] = []
        rows[-1]["bindings"]["insertions"] = []
        rows[4] = replace(rows[4], encoder_instructions=(), encoder_bytes=())
        report = compare_fixture(*rows)
        self.assertEqual(report["bootstrap_connections_checked"], 1)
        self.assertEqual(report["bootstrap_insertions_checked"], 0)
        rows[-1]["request"] = [9] * 32
        with self.assertRaisesRegex(ValueError, "scoped request joint"):
            compare_fixture(*rows)

    def test_absent_and_ambiguous_are_observations_not_replay_permissions(self):
        for ambiguous in (False, True):
            rows = list(bootstrap_fixture())
            headers = list(rows[3].headers)
            regular = rows[0]["profiles"][0]["scopes"][1]["variants"][0]["capture"][
                "slots"
            ][0]["capture"]["fields"]
            if ambiguous:
                headers.append(("a", "b"))
                regular.append(
                    {"name": "a", "occurrence": 1, "value": {"Profile": list(b"b")}}
                )
                rows[-1]["fields"] = len(headers)
                state = "Ambiguous"
            else:
                headers[-1] = ("a", "c")
                regular[-1]["value"] = {"Profile": list(b"c")}
                state = "Absent"
            rows[3] = SimpleNamespace(**{**vars(rows[3]), "headers": tuple(headers)})
            rows[-1]["bindings"]["insertions"][-1]["field"] = state
            self.assertEqual(compare_fixture(*rows)["bootstrap_insertions_checked"], 2)
            rows[-1]["bindings"]["insertions"][-1]["field"] = "Unavailable"
            with self.assertRaisesRegex(ValueError, "unverified H3 bootstrap"):
                compare_fixture(*rows)

    def test_explicit_navigation_warmup_keeps_its_fresh_path(self):
        rows = list(bootstrap_fixture())
        headers = list(rows[3].headers)
        headers[1] = (":path", "/")
        headers += [("sec-fetch-mode", "navigate"), ("sec-fetch-dest", "document")]
        rows[3] = SimpleNamespace(**{**vars(rows[3]), "headers": tuple(headers)})
        rows[-1]["fields"] = len(headers)
        request_scope = rows[0]["profiles"][0]["scopes"][1]
        request_scope["flow"]["Http"]["fetch"] = {
            "mode": "navigate",
            "destination": "document",
        }
        regular = request_scope["variants"][0]["capture"]["slots"][0]["capture"][
            "fields"
        ]
        regular.extend(
            {"name": name, "occurrence": 0, "value": {"Profile": list(value.encode())}}
            for name, value in headers[-2:]
        )
        try:
            report = compare_fixture(*rows)
        except ValueError as error:
            self.fail(f"valid current navigation warmup was rejected: {error}")
        self.assertEqual(report["bootstrap_insertions_checked"], 2)
        headers[-1] = ("sec-fetch-dest", "empty")
        rows[3] = SimpleNamespace(**{**vars(rows[3]), "headers": tuple(headers)})
        with self.assertRaisesRegex(ValueError, "scoped request joint"):
            compare_fixture(*rows)

    def test_inserted_values_are_resolved_independently_not_by_name_or_length(self):
        rows = list(bootstrap_fixture())
        raw = list(rows[4].encoder_bytes)
        raw[1] = raw[1][:-1] + b"x"  # Same name, value length and metadata.
        rows[4] = replace(rows[4], encoder_bytes=tuple(raw))
        with self.assertRaisesRegex(ValueError, "field association"):
            compare_fixture(*rows)
        rows = list(bootstrap_fixture())
        raw = list(rows[4].encoder_bytes)
        raw[2] = raw[2][:-1] + b"\x1f"  # Huffman 'a', rather than 'b'.
        rows[4] = replace(rows[4], encoder_bytes=tuple(raw))
        with self.assertRaisesRegex(ValueError, "field association"):
            compare_fixture(*rows)

    def test_independent_table_resolves_dynamic_names_duplicates_and_count_wrap(self):
        rows = bootstrap_fixture()
        sequence = rows[0]["profiles"][0]["scopes"][0]["variants"][0]["capture"][
            "slots"
        ][4]["capture"]
        observed = rows[4]
        metadata, raw = (
            list(observed.encoder_instructions),
            list(observed.encoder_bytes),
        )
        for kind, encoded in [(REFERENCE, b"\x80\x01c"), (DUPLICATE, b"\x00")]:
            encoded, decoded = decode_instruction(
                ET.fromstring(instruction(kind, encoded))
            )
            metadata.append(decoded)
            raw.append(encoded)
        sequence["encoder_instructions"] = metadata
        result = bootstrap.inserted_fields(
            sequence,
            replace(
                observed, encoder_instructions=tuple(metadata), encoder_bytes=tuple(raw)
            ),
        )
        self.assertEqual(result[3], (2, b"a", b"c"))
        self.assertEqual(result[4], (3, b"a", b"c"))

        # A tiny table repeatedly evicts entries and wraps Required Insert Count.
        # Queries still resolve each new entry from the independent table.
        capacity = {"Capacity": {"capacity": 128}}
        entry = {
            "InsertNameReference": {
                "is_static": True,
                "index": 0,
                "value_bytes": 0,
                "value_huffman": False,
            }
        }
        metadata = [capacity] + [entry] * 130
        raw = (b"\x3f\x61",) + (b"\xc0\x01a",) * 130
        sequence["encoder_instructions"] = metadata
        result = bootstrap.inserted_fields(
            sequence,
            replace(observed, encoder_instructions=tuple(metadata), encoder_bytes=raw),
        )
        self.assertEqual(len(result), 130)
        self.assertEqual(result[130], (129, b":authority", b"a"))

    def test_every_binding_coordinate_and_field_association_is_required(self):
        changes = [
            lambda b: b.update(method="POST"),
            lambda b: b.update(fields=4),
            lambda b: b["bindings"].update(stream_id=4),
            lambda b: b["bindings"].update(complete=False),
            lambda b: b["bindings"]["insertions"].pop(),
            lambda b: b["bindings"]["insertions"][0].update(instruction_index=2),
            lambda b: b["bindings"]["insertions"][0].update(insertion_index=1),
            lambda b: b["bindings"]["insertions"][0].update(
                field={"Unique": {"field_index": 4}}
            ),
            lambda b: b["bindings"]["insertions"][0].update(field="Absent"),
            lambda b: b["bindings"]["insertions"].reverse(),
            lambda b: b.update(request=[9] * 32),
        ]
        for change in changes:
            rows = bootstrap_fixture()
            change(rows[-1])
            with (
                self.subTest(change=changes.index(change)),
                self.assertRaises(ValueError),
            ):
                compare_fixture(*rows)

    def test_reference_cannot_cross_profile_connection_flow_or_request_joint(self):
        for change in ("profile", "connection", "flow", "fields", "duplicate"):
            rows = bootstrap_fixture()
            profile = rows[0]["profiles"][0]
            request_scope = profile["scopes"][1]
            if change == "profile":
                profile["scopes"].remove(request_scope)
                rows[0]["profiles"].append(
                    {"key": {"user_agent": "other"}, "scopes": [request_scope]}
                )
            elif change == "connection":
                request_scope["context"] = {"connection": {"resumption": "Resumed"}}
                profile["scopes"][0]["context"] = {"connection": {"resumption": "Full"}}
            elif change == "flow":
                request_scope["flow"]["Http"]["initiator"] = "fetch"
            elif change == "fields":
                request_scope["variants"][0]["capture"]["slots"][0]["capture"][
                    "fields"
                ][0]["value"] = {"Profile": list(b"other")}
            else:
                profile["scopes"].append(deepcopy(request_scope))
            with (
                self.subTest(change=change),
                self.assertRaisesRegex(ValueError, "scoped request joint"),
            ):
                compare_fixture(*rows)

    def test_bootstrap_cannot_select_a_later_head_or_incomplete_instruction_bytes(self):
        rows = list(bootstrap_fixture())
        rows[3] = SimpleNamespace(**{**vars(rows[3]), "stream": 4})
        with self.assertRaisesRegex(ValueError, "initial H3 request"):
            compare_fixture(*rows)
        rows = list(bootstrap_fixture())
        rows[4] = replace(rows[4], encoder_bytes=rows[4].encoder_bytes[:-1])
        with self.assertRaisesRegex(ValueError, "instruction evidence"):
            compare_fixture(*rows)

    def test_duplicate_slots_and_unknown_slots_do_not_escape_verification(self):
        for kind in ("Http3Bootstrap", "Unknown"):
            rows = bootstrap_fixture()
            rows[0]["profiles"][0]["scopes"][0]["variants"][0]["capture"][
                "slots"
            ].append({"kind": kind, "capture": rows[-1]})
            with (
                self.subTest(kind=kind),
                self.assertRaisesRegex(ValueError, "unverified QUIC"),
            ):
                compare_fixture(*rows)

    def test_bounded_decoder_failures_never_expose_inserted_values(self):
        for limit in ("MAX_CAPACITY", "MAX_INSTRUCTIONS", "MAX_BYTES", "MAX_FIELDS"):
            with self.subTest(limit=limit):
                with (
                    patch.object(bootstrap, limit, 0),
                    self.assertRaises(ValueError) as caught,
                ):
                    compare_fixture(*bootstrap_fixture())
                self.assertNotIn("private-current-origin", str(caught.exception))
        rows = list(bootstrap_fixture())
        rows[4] = replace(rows[4], encoder_bytes=(b"\x3f", *rows[4].encoder_bytes[1:]))
        with self.assertRaises(ValueError) as caught:
            compare_fixture(*rows)
        self.assertNotIn("private-current-origin", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
