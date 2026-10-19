"""Every startup exchange is recounted without receiving measured-flow credit."""

from dataclasses import replace
import json
import html
from pathlib import Path
import tempfile
import unittest
import xml.etree.ElementTree as ET
from unittest.mock import patch

import zstandard

from preliminary_inventory import main_head
from remote.admission import complete_responses, packet_peers

from operations_tests.fixtures import JOINTS, reports
from operations_tests.preliminary_fixtures import (
    client_packet,
    inventory_fixture,
    post_source,
    replace_main_body,
)


def encoded_main_fixture(directory, *, compressed=True):
    raw, frames, inventory, _sections, _rows, _source, previous = inventory_fixture(
        directory
    )
    head = frames[2]
    headers = tuple(
        (name, "GET" if name == ":method" else "/report" if name == ":path" else value)
        for name, value in head.headers
    )
    head = replace(head, headers=headers, data=b"")
    frames[2] = head
    regular = tuple(pair for pair in headers if not pair[0].startswith(":"))
    info = [
        ("Version", "HTTP/3.0"),
        ("Method", "GET"),
        ("Scheme", "https"),
        ("Authority", "capture.test:443"),
        ("Path", "/report"),
        ("Socket Address", "127.0.0.1:10000"),
    ]

    def table(rows):
        return (
            "<table>"
            + "".join(
                "<tr><td>"
                + html.escape(name)
                + "</td><td>"
                + html.escape(value)
                + "</td></tr>"
                for name, value in rows
            )
            + "</table>"
        )

    body = (
        "<h2>Request Info</h2>"
        + table(info)
        + "<h2>🚗 Http Headers</h2>"
        + table(regular)
        + "<h2>HTTP/3</h2>"
        + table(
            (("HTTP/3 observation", json.dumps(dict(request_stream_id=head.stream))),)
        )
    ).encode()
    encoded = zstandard.ZstdCompressor().compress(body) if compressed else body
    raw = replace_main_body(raw, frames, previous, encoded)
    response_headers = (
        (":status", "200"),
        ("content-type", "text/html; charset=utf-8"),
    )
    if compressed:
        response_headers += (("content-encoding", "zstd"),)
    frames[3] = replace(frames[3], headers=response_headers)
    run = dict(
        inventory.runs[0],
        flow="navigate",
        reference=replace(
            inventory.runs[0]["reference"], method="GET", uri="/report", body=b""
        ),
    )
    run["output"].write_bytes(encoded)
    return raw, frames, run, body, encoded


class PreliminaryInventoryTests(unittest.TestCase):
    def test_raw_zstd_get_output_is_bound_before_decoding_its_own_native_headers(self):
        for compressed in (False, True):
            with self.subTest(
                compressed=compressed
            ), tempfile.TemporaryDirectory() as directory:
                raw, frames, run, body, encoded = encoded_main_fixture(
                    Path(directory), compressed=compressed
                )
                if compressed:
                    self.assertNotEqual(body, encoded)
                    self.assertEqual(
                        zstandard.ZstdDecompressor().decompress(encoded), body
                    )
                try:
                    actual = main_head(
                        run,
                        frames,
                        packet_peers(raw, 443),
                        complete_responses(raw, 443),
                        "probe",
                    )
                except ValueError as error:
                    self.fail(
                        "raw encoded response must bind using its own headers: "
                        + str(error)
                    )
                self.assertEqual(
                    (actual.packet, actual.connection, actual.stream),
                    (20, 7, frames[2].stream),
                )
                self.assertEqual(run["output"].read_bytes(), encoded)

    def test_wrong_or_ambiguous_coding_cannot_select_a_decoder_from_the_output(self):
        for coding in (None, "gzip", "identity", "duplicate"):
            with self.subTest(
                coding=coding
            ), tempfile.TemporaryDirectory() as directory:
                raw, frames, run, _body, _encoded = encoded_main_fixture(
                    Path(directory)
                )
                headers = tuple(
                    pair for pair in frames[3].headers if pair[0] != "content-encoding"
                )
                if coding is not None:
                    headers += (
                        (
                            "content-encoding",
                            "zstd" if coding == "duplicate" else coding,
                        ),
                    )
                if coding == "duplicate":
                    headers += (("content-encoding", "zstd"),)
                frames[3] = replace(frames[3], headers=headers)
                with self.assertRaises(ValueError):
                    main_head(
                        run,
                        frames,
                        packet_peers(raw, 443),
                        complete_responses(raw, 443),
                        "probe",
                    )

    def test_raw_output_full_uri_authority_and_unique_candidate_stay_mandatory(self):
        for mutation in (
            "changed-output",
            "decoded-only",
            "duplicate",
            "authority",
            "query",
            "incomplete",
        ):
            with self.subTest(
                mutation=mutation
            ), tempfile.TemporaryDirectory() as directory:
                raw, frames, run, body, encoded = encoded_main_fixture(Path(directory))
                if mutation == "changed-output":
                    run["output"].write_bytes(encoded + b"x")
                elif mutation == "decoded-only":
                    run["output"].write_bytes(body)
                elif mutation == "incomplete":
                    document = ET.fromstring(raw)
                    response = next(
                        packet
                        for packet in document
                        if packet.find("field[@name='frame.number'][@show='21']")
                        is not None
                    )
                    kind = response.find(".//field[@name='quic.frame_type']")
                    kind.set("value", "0e")
                    kind.set("show", "14")
                    raw = ET.tostring(document)
                elif mutation == "duplicate":
                    frames.append(replace(frames[2], packet=19))
                    raw = raw.replace(
                        client_packet(20, frames[2].stream).encode(),
                        (
                            client_packet(19, frames[2].stream)
                            + client_packet(20, frames[2].stream)
                        ).encode(),
                    )
                else:
                    name, value = (
                        (":authority", "other.test:443")
                        if mutation == "authority"
                        else (":path", "/report?other=1")
                    )
                    frames[2] = replace(
                        frames[2],
                        headers=tuple(
                            (field, value if field == name else content)
                            for field, content in frames[2].headers
                        ),
                    )
                with self.assertRaisesRegex(ValueError, "unique"):
                    main_head(
                        run,
                        frames,
                        packet_peers(raw, 443),
                        complete_responses(raw, 443),
                        "probe",
                    )

    def test_native_main_binding_inventory_and_no_measured_flow_substitution(self):
        with tempfile.TemporaryDirectory() as directory:
            raw, frames, inventory, sections, source_rows, source, _body = (
                inventory_fixture(Path(directory))
            )
            with patch(
                "preliminary_inventory.sections_from_wire", return_value=sections
            ):
                bound, report = inventory.bind(raw, frames)
            self.assertEqual(report["requests"], 1)
            self.assertEqual(report["observations"][0]["complete_packet"], 12)
            self.assertEqual(
                bound.preliminary[0]["request"],
                inventory.runs[0]["preliminary"][0].request_pin,
            )
            self.assertIsNone(bound.name(frames[0]))
            # Repeating the initial fetch as a prelude cannot supply the absent measured fetch.
            other = [
                row
                for row in source_rows
                if not row.from_server and source.name(row) != "fetch"
            ]
            with self.assertRaisesRegex(ValueError, "missing or duplicated"):
                bound.validate_heads(other + [frames[0]])

    def test_main_echo_headers_stream_peer_and_multiple_compatible_outputs_are_fatal(
        self,
    ):
        for mutation in ("echo", "stream", "peer", "duplicate"):
            with self.subTest(
                mutation=mutation
            ), tempfile.TemporaryDirectory() as directory:
                raw, frames, inventory, sections, _rows, _source, body = (
                    inventory_fixture(Path(directory))
                )
                value = json.loads(body)
                if mutation == "echo":
                    value["fp"]["http_info"]["headers"].append(["x-unobserved", "x"])
                elif mutation == "stream":
                    value["fp"]["http_info"]["h3"]["request_stream_id"] += 4
                elif mutation == "peer":
                    value["fp"]["request_info"]["peer_addr"] = "127.0.0.1:10001"
                else:
                    # Identical compatible native bodies must not be picked arbitrarily.
                    frames.append(replace(frames[2], packet=19))
                    raw = raw.replace(
                        client_packet(20, frames[2].stream).encode(),
                        (
                            client_packet(19, frames[2].stream)
                            + client_packet(20, frames[2].stream)
                        ).encode(),
                    )
                current = json.dumps(value).encode()
                raw = replace_main_body(raw, frames, body, current)
                inventory.runs[0]["output"].write_bytes(current)
                with patch(
                    "preliminary_inventory.sections_from_wire", return_value=sections
                ), self.assertRaisesRegex(ValueError, "unique"):
                    inventory.bind(raw, frames)

    def test_missing_late_fin_wrong_body_policy_and_extra_requests_are_fatal(self):
        for mutation in ("missing", "late-fin", "body", "policy", "extra"):
            with self.subTest(
                mutation=mutation
            ), tempfile.TemporaryDirectory() as directory:
                raw, frames, inventory, sections, _rows, _source, _body = (
                    inventory_fixture(Path(directory))
                )
                if mutation == "missing":
                    frames = frames[2:]
                elif mutation == "late-fin":
                    document = ET.fromstring(raw)
                    ending = next(
                        packet
                        for packet in document
                        if packet.find("field[@name='frame.number'][@show='12']")
                        is not None
                    )
                    document.remove(ending)
                    ending.find("field[@name='frame.number']").set("show", "25")
                    document.append(ending)
                    raw = ET.tostring(document)
                elif mutation == "body":
                    frames[0] = replace(frames[0], data=b"wrong-body")
                elif mutation == "policy":
                    section = sections[10, 7, 0]
                    sections[10, 7, 0] = replace(
                        section,
                        fields=(replace(section.fields[0], value_huffman=True),)
                        + section.fields[1:],
                    )
                else:
                    frames.append(replace(frames[2], packet=30, stream=40))
                with patch(
                    "preliminary_inventory.sections_from_wire", return_value=sections
                ), self.assertRaises(ValueError):
                    inventory.bind(raw, frames)

    def test_preliminary_native_joint_is_checked_even_without_measured_flow_credit(
        self,
    ):
        rows, source, _value, _sections = post_source()
        head = next(row for row in rows if source.name(row) == "fetch")
        auxiliary = replace(head, connection=9, packet=100)
        ledger = source.for_replay().with_preliminary(
            (dict(key=("h3", 9, head.stream), joint=JOINTS["h3"]),)
        )
        native = reports()
        native["h3"]["connection_joints"][9] = "99" * 32
        with self.assertRaisesRegex(ValueError, "preliminary operation changed"):
            ledger.check_matrix(rows + [auxiliary], native)
