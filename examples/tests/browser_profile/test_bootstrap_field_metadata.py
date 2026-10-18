"""Bootstrap raw HEADERS are checked separately from ordinary journey coverage."""

from copy import deepcopy
from dataclasses import asdict, replace
import unittest

from flows import FLOWS
from qpack_bootstrap_wire import prefixed
from qpack_fields_wire import (
    Representation,
    Section,
    compare_field_metadata,
    compare_replay_policy,
    decode_section,
)
from test_qpack_bootstrap_wire import bootstrap_fixture
from wire import HeaderBlock


def literal(name, value):
    name, value = name.encode(), value.encode()
    return prefixed(len(name), 3, 0x20) + name + prefixed(len(value), 7) + value


def request_capture(headers, representations):
    slots = []
    for kind, pseudo in (("Headers", False), ("PseudoHeaders", True)):
        fields = []
        for (name, value), metadata in zip(headers, representations):
            if name.startswith(":") != pseudo:
                continue
            field = {"name": name, "representation": asdict(metadata)}
            if not pseudo:
                field.update(occurrence=0, value={"Profile": list(value.encode())})
            fields.append(field)
        slots.append({"kind": kind, "capture": {"fields": fields}})
    return {"level": "Request", "slots": slots}


def field_fixture():
    archive, _flight, _hello, original, _evidence, binding = bootstrap_fixture()
    profile = archive["profiles"][0]
    native = profile["scopes"][0]["variants"][0]
    initial = HeaderBlock(
        "h3",
        10,
        7,
        0,
        False,
        tuple(
            (name, "/report?h3_probe=1" if name == ":path" else value)
            for name, value in original.headers
        )
        + (("sec-fetch-mode", "navigate"), ("sec-fetch-dest", "document")),
    )
    # The fixture's raw bytes are decoded by the real field-line decoder. This
    # lets mutations alter metadata without changing the resolved HTTP fields.
    count, negative, delta, representations = decode_section(
        b"\x00\x00" + b"".join(literal(name, value) for name, value in initial.headers)
    )
    section = Section(10, 7, 0, count, negative, delta, representations)
    scope = profile["scopes"][1]
    scope["flow"]["Http"]["fetch"] = {"mode": "navigate", "destination": "document"}
    scope["variants"][0]["capture"] = request_capture(initial.headers, representations)
    binding["fields"] = len(initial.headers)
    blocks, sections = [initial], {(10, 7, 0): section}

    operations = (
        ("GET", "/report"),
        ("POST", "/api/fetch/number/1"),
        ("POST", "/api/xml/number/2"),
        ("CONNECT", "/api/ws"),
        ("POST", "/form"),
        ("GET", "/form?source=web&turtles=yes"),
    )
    for index, (flow, (method, path)) in enumerate(zip(FLOWS, operations), 1):
        headers = ((":method", method), (":path", path), ("user-agent", "fixture"))
        if flow == "ws":
            headers += ((":protocol", "websocket"),)
        _count, _negative, _delta, metadata = decode_section(
            b"\x00\x00" + b"".join(literal(name, value) for name, value in headers)
        )
        block = HeaderBlock("h3", 10 + index, 7, index * 4, False, headers)
        blocks.append(block)
        sections[block.packet, block.connection, block.stream] = Section(
            block.packet,
            block.connection,
            block.stream,
            0,
            False,
            0,
            metadata,
        )
        profile["scopes"].append(
            {
                "flow": {
                    "Http": {
                        "version": "HTTP/3.0",
                        "method": method,
                        "initiator": "form" if flow == "form_get" else flow,
                        "fetch": None,
                    }
                },
                "variants": [
                    {
                        "id": [10 + index] * 32,
                        "capture": request_capture(headers, metadata),
                    }
                ],
            }
        )
    return archive, blocks, sections, {7: bytes(native["id"]).hex()}


class BootstrapFieldMetadataTests(unittest.TestCase):
    def compare(self, rows, function=compare_field_metadata):
        archive, blocks, sections, joints = rows
        return function(archive, blocks, sections, connection_joints=joints)

    def test_internal_initial_head_is_checked_without_becoming_navigation(self):
        report = self.compare(field_fixture())
        self.assertEqual(report["requests_checked"], 6)
        self.assertEqual(report["flows"], sorted(FLOWS))
        self.assertEqual(report["bootstrap_requests_checked"], 1)
        self.assertEqual(report["bootstrap_fields_checked"], 7)
        subset = field_fixture()
        subset[1][:] = [
            block
            for block in subset[1]
            if dict(block.headers).get(":protocol") != "websocket"
        ]
        report = compare_field_metadata(
            subset[0],
            subset[1],
            subset[2],
            connection_joints=subset[3],
            expected_flows=set(FLOWS) - {"ws"},
        )
        self.assertEqual(
            (report["requests_checked"], report["bootstrap_requests_checked"]), (5, 1)
        )
        rows = field_fixture()
        # The real profiled navigation cannot be replaced by the auxiliary head.
        rows[1].pop(1)
        with self.assertRaisesRegex(ValueError, "incomplete QPACK field flow"):
            self.compare(rows)

    def test_initial_families_static_indexes_and_flags_are_not_skipped(self):
        for metadata in (
            Representation("StaticIndex", 17),
            Representation("LiteralStaticName", 1),
            Representation("LiteralName", name_huffman=True),
            Representation("LiteralName", value_huffman=True),
            Representation("LiteralName", never_index=True),
        ):
            rows = field_fixture()
            original = rows[2][10, 7, 0]
            rows[2][10, 7, 0] = replace(
                original, fields=(metadata, *original.fields[1:])
            )
            for function in (compare_field_metadata, compare_replay_policy):
                with self.subTest(
                    metadata=metadata, function=function.__name__
                ), self.assertRaisesRegex(
                    ValueError, "Bootstrap raw QPACK metadata differs"
                ):
                    self.compare(rows, function)

    def test_initial_static_index_cannot_change_within_the_same_family(self):
        rows = field_fixture()
        pseudo = rows[0]["profiles"][0]["scopes"][1]["variants"][0]["capture"]["slots"][
            1
        ]["capture"]["fields"]
        pseudo[0]["representation"] = asdict(Representation("StaticIndex", 17))
        original = rows[2][10, 7, 0]
        rows[2][10, 7, 0] = replace(
            original, fields=(Representation("StaticIndex", 17), *original.fields[1:])
        )
        self.assertEqual(self.compare(rows)["bootstrap_requests_checked"], 1)
        rows[2][10, 7, 0] = replace(
            original, fields=(Representation("StaticIndex", 18), *original.fields[1:])
        )
        for function in (compare_field_metadata, compare_replay_policy):
            with self.subTest(function=function.__name__), self.assertRaisesRegex(
                ValueError, "Bootstrap raw QPACK metadata differs"
            ):
                self.compare(rows, function)

    def test_missing_raw_initial_head_and_native_joint_are_rejected(self):
        rows = field_fixture()
        del rows[2][10, 7, 0]
        with self.assertRaisesRegex(ValueError, "Bootstrap request lacks raw"):
            self.compare(rows)
        rows = field_fixture()
        for joints in (None, {}, {7: "ff" * 32}):
            with self.subTest(joints=joints), self.assertRaisesRegex(
                ValueError, "Bootstrap"
            ):
                compare_field_metadata(
                    rows[0], rows[1], rows[2], connection_joints=joints
                )

    def test_another_request_joint_cannot_supply_initial_metadata(self):
        rows = field_fixture()
        scope = rows[0]["profiles"][0]["scopes"][1]
        other = deepcopy(scope["variants"][0])
        other["id"] = [99] * 32
        scope["variants"].append(other)
        referenced = scope["variants"][0]["capture"]["slots"][1]["capture"]["fields"][0]
        referenced["representation"]["value_huffman"] = True
        with self.assertRaisesRegex(ValueError, "Bootstrap raw QPACK metadata differs"):
            self.compare(rows)

    def test_capture_keeps_exact_dynamic_index_while_replay_keeps_its_policy(self):
        rows = field_fixture()
        capture = rows[0]["profiles"][0]["scopes"][1]["variants"][0]["capture"]
        capture["slots"][0]["capture"]["fields"][0]["representation"] = asdict(
            Representation("DynamicIndex", 0)
        )
        original = rows[2][10, 7, 0]
        metadata = list(original.fields)
        metadata[3] = Representation("DynamicIndex", 3)
        rows[2][10, 7, 0] = replace(original, fields=tuple(metadata))
        with self.assertRaisesRegex(ValueError, "Bootstrap raw QPACK metadata differs"):
            self.compare(rows)
        self.assertEqual(
            self.compare(rows, compare_replay_policy)["bootstrap_requests_checked"], 1
        )
