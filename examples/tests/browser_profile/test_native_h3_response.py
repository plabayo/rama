"""Native snapshot attribution remains separate from independent wire checks."""

from copy import deepcopy
from dataclasses import replace
import html
import json
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import zstandard

import native_h3_response as native
from h3_sequence_wire import StreamPrefix
from quic_wire import compare_quic_captures
from test_h3_sequence_wire import frame, number
from test_quic_wire import (
    comparison_fixture,
    computed,
    scalar,
    sequence_fixture,
    settings_document,
)
from quic_wire import client_settings
from wire import HeaderBlock


def view():
    return dict(
        request_stream_id=4,
        connection_revision=8,
        settings_status="received",
        completeness={
            name: True
            for name in (
                "snapshot",
                "streams",
                "control",
                "qpack",
                "settings",
                "local_settings",
                "fields",
            )
        },
        local_settings=[dict(id=1, value=4096, grease=False)],
        streams=[dict(sequence=2, stream_id=2, stream_type=0, grease=False)],
        control=[dict(sequence=3, frame_type=4, length=0, element_id=None, value=[])],
        qpack=[],
    )


def encoded_view(value=None):
    return json.dumps(
        {"fp": {"http_info": {"h3": view() if value is None else value}}}
    ).encode()


def packet(payload, *, offset=0, fin=True, connection=7, stream=4):
    kind = 15 if fin else 14
    fields = scalar("quic.frame_type", bytes([kind]))
    fields += scalar("quic.stream.stream_id", number(stream), show=stream)
    fields += scalar("quic.stream.offset", number(offset), show=offset)
    fields += scalar("quic.stream.length", number(len(payload)), show=len(payload))
    fields += scalar("quic.stream_data", payload)
    size = (
        1
        + len(number(stream))
        + len(number(offset))
        + len(number(len(payload)))
        + len(payload)
    )
    return (
        "<packet>"
        + computed("quic.connection.number", connection)
        + scalar("udp.srcport", (443).to_bytes(2, "big"))
        + scalar("udp.dstport", (10000).to_bytes(2, "big"))
        + f'<field name="quic.frame" size="{size}">'
        + fields
        + "</field></packet>"
    )


def document(*packets):
    return ("<pdml>" + "".join(packets) + "</pdml>").encode()


def blocks(payload, *, connection=7, stream=4, response_headers=()):
    return [
        HeaderBlock(
            "h3",
            1,
            connection,
            stream,
            False,
            ((":method", "GET"), (":path", "/report")),
        ),
        HeaderBlock(
            "h3",
            2,
            connection,
            stream,
            True,
            ((":status", "200"), ("content-type", "application/json"))
            + response_headers,
            data=payload,
        ),
    ]


class NativeH3ResponseTests(unittest.TestCase):
    def test_complete_stream_data_reassembles_and_checks_retransmissions(self):
        payload = frame(1, b"head") + frame(0, b"body")
        data = document(packet(payload[3:], offset=3), packet(payload[:5], fin=False))
        self.assertEqual(native.response_data(data, 443), {(7, 4): b"body"})
        self.assertEqual(
            native.response_data(document(packet(payload, fin=False)), 443), {}
        )
        for data in (
            document(packet(payload[3:], offset=3)),
            document(packet(payload), packet(b"x", offset=2, fin=False)),
            document(packet(payload), packet(b"", offset=1)),
            document(packet(payload), packet(b"x", offset=len(payload), fin=False)),
            document(packet(payload[:-1])),
        ):
            with self.subTest(data=data), self.assertRaises(ValueError):
                native.response_data(data, 443)

    def test_response_stream_identity_and_resource_limits_are_not_inferred(self):
        payload = frame(0, b"body")
        self.assertEqual(
            native.response_data(document(packet(payload, stream=6)), 443), {}
        )
        for constant, value in (
            ("MAX_RESPONSE_BYTES", 3),
            ("MAX_CAPTURE_BYTES", 1),
            ("MAX_RESPONSES", 0),
        ):
            with self.subTest(constant=constant), patch.object(
                native, constant, value
            ), self.assertRaisesRegex(ValueError, "limit"):
                native.response_data(document(packet(payload)), 443)
        wrong_extent = document(packet(payload)).replace(b'size="10"', b'size="9"')
        with self.assertRaises(ValueError):
            native.response_data(wrong_extent, 443)

    def test_real_zstd_frames_require_one_complete_bounded_representation(self):
        body = encoded_view()
        compressor = zstandard.ZstdCompressor(write_content_size=False)
        encoded = compressor.compress(body)
        self.assertEqual(native.decoded_body(encoded, "zstd"), body)
        self.assertEqual(native.decoded_body(body, None), body)
        for malformed in (encoded[:-1], encoded + b"trailing", encoded + encoded):
            with self.subTest(malformed=malformed), self.assertRaises(ValueError):
                native.decoded_body(malformed, "zstd")
        for constant, value in (
            ("MAX_RESPONSE_BYTES", len(encoded) - 1),
            ("MAX_RESPONSE_BYTES", len(body) - 1),
            ("MAX_WINDOW_BYTES", 1),
        ):
            with self.subTest(constant=constant, value=value), patch.object(
                native, constant, value
            ), self.assertRaises(ValueError):
                native.decoded_body(encoded, "zstd")
        known_size = zstandard.ZstdCompressor().compress(body)
        with patch.object(
            native, "MAX_RESPONSE_BYTES", len(body) - 1
        ), self.assertRaises(ValueError):
            native.decoded_body(known_size, "zstd")
        with self.assertRaisesRegex(ValueError, "encoding"):
            native.decoded_body(encoded, "br")

    def test_existing_json_and_html_surfaces_have_the_same_native_view(self):
        value = view()
        page = (
            '<html><table><tr><td>Other</td><td><a href="/">link</a></td></tr><tr><td>HTTP/3 observation</td><td><code>'
            + html.escape(json.dumps(value))
            + "</code></td></tr></table></html>"
        )
        self.assertEqual(
            native.native_view(encoded_view(value), "application/json"), value
        )
        self.assertEqual(
            native.native_view(page.encode(), "text/html; charset=utf-8"), value
        )
        for body, content_type in (
            (encoded_view().replace(b'"h3":', b'"h3": {}, "h3":'), "application/json"),
            (b"{}", "application/json"),
            (
                page.replace(
                    "</table>",
                    page[page.index("<tr><td>HTTP/3") : page.index("</table>")]
                    + "</table>",
                ).encode(),
                "text/html; charset=utf-8",
            ),
            (
                b"<table><tr><td>HTTP/3 observation</td><td>{}</td></tr>",
                "text/html; charset=utf-8",
            ),
            (b"{}", "text/plain"),
        ):
            with self.subTest(body=body), self.assertRaises(ValueError):
                native.native_view(body, content_type)

    def test_native_sequence_preserves_order_and_applies_existing_privacy_policy(self):
        value = view()
        value["streams"].append(
            dict(sequence=7, stream_id=6, stream_type=2, grease=False)
        )
        value["control"].append(
            dict(sequence=5, frame_type=33, length=2, element_id=None, value=[1, 2])
        )
        value["qpack"] = [
            {
                "InsertLiteral": dict(
                    name_bytes=8, value_bytes=47, name_huffman=True, value_huffman=False
                )
            }
        ]
        sequence = native.native_sequence(value, 4)
        self.assertEqual(
            [next(iter(event)) for event in sequence["events"]],
            ["Stream", "Control", "Control", "Stream"],
        )
        self.assertEqual(sequence["events"][2]["Control"]["value"], [1, 2])
        self.assertEqual(
            sequence["encoder_instructions"][0]["InsertLiteral"]["value_bytes"], 0
        )
        self.assertEqual(value["qpack"][0]["InsertLiteral"]["value_bytes"], 47)
        self.assertEqual(
            sequence["local_settings"]["fields"][0]["value"]["Literal"],
            list((4096).to_bytes(8, "big")),
        )

    def test_native_flags_ordinals_streams_and_qpack_are_typed(self):
        changes = [
            lambda x: x.update(request_stream_id=8),
            lambda x: x.update(request_stream_id=True),
            lambda x: x.update(settings_status="timed_out"),
            lambda x: x["completeness"].update(streams=1),
            lambda x: x["completeness"].update(qpack=False),
            lambda x: x["streams"][0].update(sequence=0),
            lambda x: x["streams"][0].update(sequence=9),
            lambda x: x["control"][0].update(sequence=2),
            lambda x: x["control"][0].pop("element_id"),
            lambda x: x["streams"][0].update(stream_id=3),
            lambda x: x["streams"][0].update(grease=0),
            lambda x: x["local_settings"].append(deepcopy(x["local_settings"][0])),
            lambda x: x.update(qpack=[{"Capacity": {"capacity": True}}]),
            lambda x: x.update(qpack=[{"Unknown": {}}]),
            lambda x: x.update(qpack=[{"InsertLiteral": {"name_bytes": 1}}]),
        ]
        for change in changes:
            value = view()
            change(value)
            with self.subTest(change=change), self.assertRaises(ValueError):
                native.native_sequence(value, 4)

    def test_response_view_is_bound_to_complete_same_stream_wire_data(self):
        payload = encoded_view()
        data = document(packet(frame(1, b"head") + frame(0, payload)))
        with patch.object(native, "parse_pdml", return_value=blocks(payload)):
            result = native.response_sequences(data, 443)
        self.assertEqual(result, {7: native.native_sequence(view(), 4)})
        for malformed_blocks in (
            blocks(payload, stream=8),
            blocks(payload, connection=8),
            blocks(payload + b"x"),
        ):
            with patch.object(
                native, "parse_pdml", return_value=malformed_blocks
            ), self.assertRaises(ValueError):
                native.response_sequences(data, 443)
        with patch.object(
            native, "parse_pdml", return_value=blocks(payload)
        ), self.assertRaisesRegex(ValueError, "complete"):
            native.response_sequences(
                document(packet(frame(0, payload), fin=False)), 443
            )
        duplicate = blocks(
            payload, response_headers=(("content-type", "application/json"),)
        )
        with patch.object(
            native, "parse_pdml", return_value=duplicate
        ), self.assertRaisesRegex(ValueError, "duplicate"):
            native.response_sequences(data, 443)

    def test_conflicting_native_views_on_one_connection_fail(self):
        first = encoded_view()
        changed = view()
        changed["request_stream_id"] = 8
        changed["streams"].append(
            dict(sequence=7, stream_id=6, stream_type=2, grease=False)
        )
        second = encoded_view(changed)
        data = document(packet(frame(0, first)), packet(frame(0, second), stream=8))
        observed = blocks(first) + blocks(second, stream=8)
        with patch.object(
            native, "parse_pdml", return_value=observed
        ), self.assertRaisesRegex(ValueError, "conflicting"):
            native.response_sequences(data, 443)

    def test_ws_has_no_invented_native_view_and_redirect_is_explicit(self):
        request = HeaderBlock(
            "h3",
            1,
            7,
            4,
            False,
            ((":method", "CONNECT"), (":path", "/api/ws"), (":protocol", "websocket")),
        )
        with patch.object(native, "parse_pdml", return_value=[request]):
            self.assertEqual(native.response_sequences(b"<pdml/>", 443), {})
        request = replace(request, headers=((":method", "GET"), (":path", "/")))
        response = HeaderBlock("h3", 2, 7, 4, True, ((":status", "307"),))
        data = document(packet(frame(1, b"head")))
        with patch.object(native, "parse_pdml", return_value=[request, response]):
            self.assertEqual(native.response_sequences(data, 443), {})
        with patch.object(
            native,
            "parse_pdml",
            return_value=[request, replace(response, headers=((":status", "500"),))],
        ), self.assertRaisesRegex(ValueError, "startup redirect"):
            native.response_sequences(data, 443)

    def test_same_traffic_mode_is_explicit_and_never_implicit_in_replay(self):
        import replay

        with patch.object(replay, "client_hellos", return_value=[]), patch.object(
            replay, "first_flights", return_value=[]
        ), patch.object(replay, "client_settings", return_value={}), patch.object(
            replay, "sequence_evidence", return_value={}
        ), patch.object(
            replay, "compare_quic_captures", return_value={}
        ) as compare, patch.object(
            replay, "response_sequences", return_value={7: {"witness": True}}
        ) as witness:
            replay.compare_native_connections(
                {}, b"wire", 443, [], {flow: "h3" for flow in replay.FLOWS}, replay=True
            )
            witness.assert_not_called()
            self.assertIsNone(compare.call_args.kwargs["native_sequences"])
            replay.compare_native_connections(
                {},
                b"wire",
                443,
                [],
                {flow: "h3" for flow in replay.FLOWS},
                same_traffic_native=True,
            )
            self.assertEqual(
                compare.call_args.kwargs["native_sequences"], {7: {"witness": True}}
            )
            witness.assert_called_once_with(b"wire", 443)
            with self.assertRaisesRegex(ValueError, "new native freeze"):
                replay.compare_native_connections(
                    {},
                    b"wire",
                    443,
                    [],
                    {flow: "h3" for flow in replay.FLOWS},
                    replay=True,
                    same_traffic_native=True,
                )

    def test_exact_native_witness_is_required_even_for_a_unique_wire_candidate(self):
        archive, flight, hello, request = comparison_fixture()
        wrong = deepcopy(
            archive["profiles"][0]["scopes"][0]["variants"][0]["capture"]["slots"][-1][
                "capture"
            ]
        )
        wrong["events"][0]["Stream"]["stream_id"] = 6
        with self.assertRaisesRegex(ValueError, "no matching retained"):
            compare_quic_captures(
                archive,
                [flight],
                [hello],
                client_settings(settings_document(), 443),
                [request],
                sequence_fixture(),
                native_sequences={7: wrong},
            )
        result = compare_quic_captures(
            archive,
            [flight],
            [hello],
            client_settings(settings_document(), 443),
            [request],
            sequence_fixture(),
            native_sequences={},
        )
        self.assertEqual(
            result["native_attribution"]["response_snapshot_connections"], 0
        )
        self.assertEqual(result["native_attribution"]["wire_only_connections"], 1)

    def test_valid_but_different_decoded_data_cannot_replace_raw_stream_body(self):
        raw = encoded_view()
        changed = view()
        changed["connection_revision"] = 9
        other = encoded_view(changed)
        data = document(packet(frame(0, raw)))
        with patch.object(
            native, "parse_pdml", return_value=blocks(other)
        ), self.assertRaisesRegex(ValueError, "DATA differs"):
            native.response_sequences(data, 443)

    def test_native_witness_never_combines_candidates_or_replaces_wire_facts(self):
        archive, flight, hello, request = comparison_fixture()
        variants = archive["profiles"][0]["scopes"][0]["variants"]
        longer = deepcopy(variants[0])
        longer["id"] = [2] * 32
        longer["capture"]["slots"][-1]["capture"]["events"].append(
            {"Stream": {"stream_id": 6, "stream_type": 2}}
        )
        variants.append(longer)
        seq = sequence_fixture()[7]
        seq = replace(seq, streams=seq.streams + (StreamPrefix(6, 2, b""),))
        arguments = [
            archive,
            [flight, replace(flight, connection=8)],
            [hello, replace(hello, connection=8)],
            {
                7: client_settings(settings_document(), 443)[7],
                8: client_settings(settings_document(), 443)[7],
            },
            [request, SimpleNamespace(**{**vars(request), "connection": 8})],
            {7: seq, 8: seq},
        ]
        with self.assertRaisesRegex(ValueError, "ambiguous retained"):
            compare_quic_captures(*arguments)
        with self.assertRaisesRegex(ValueError, "ambiguous retained"):
            compare_quic_captures(*arguments, native_sequences={})
        witnesses = {
            7: variants[0]["capture"]["slots"][-1]["capture"],
            8: longer["capture"]["slots"][-1]["capture"],
        }
        result = compare_quic_captures(*arguments, native_sequences=witnesses)
        self.assertEqual(result["connection_joints"], {7: "01" * 32, 8: "02" * 32})
        self.assertEqual(result["retained_joints_checked"], 2)
        with self.assertRaisesRegex(ValueError, "unknown connection"):
            compare_quic_captures(*arguments, native_sequences={9: witnesses[7]})
        with self.assertRaisesRegex(ValueError, "no wire observation"):
            compare_quic_captures(
                *arguments, native_sequences={7: witnesses[7], 8: witnesses[7]}
            )
        arguments[2][0] = replace(
            hello, capture={"transport": "Quic", "ciphers": [999]}
        )
        with self.assertRaisesRegex(ValueError, "no matching retained"):
            compare_quic_captures(*arguments, native_sequences=witnesses)


if __name__ == "__main__":
    unittest.main()
