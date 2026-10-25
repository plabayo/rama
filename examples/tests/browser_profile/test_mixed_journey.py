"""Keep a standard browser's actual per-operation protocols through replay."""

import unittest
import xml.etree.ElementTree as ET
from collections import Counter
from connection_fields import check_variant_flow_matrix, compare_h1_connections
from dataclasses import replace
from flow_bodies import WEBSOCKET_PROBE
from flows import FLOWS, compare_requests, flow_protocols
from replay import requests_from_wire
from tls_wire import client_hellos
from wire import check_flow_bodies, parse_pdml
from wire_fixtures import (
    flow_fixture as fixture,
    mixed_connections_hello_packet as hello_packet,
    mixed_journey_h1_document as h1_document,
    mixed_journey_mixed_frames as mixed_frames,
    wire_streams_packet as packet,
)


class MixedJourneyTests(unittest.TestCase):
    def test_page_known_probe_survives_the_mixed_h1_fallback_decoder(self):
        root = h1_document()
        probe = WEBSOCKET_PROBE + " #" + "34" * 16
        for field in root.iter("field"):
            if (
                field.get("name") == "websocket.payload.text"
                and field.get("show") == WEBSOCKET_PROBE
            ):
                field.set("show", probe)
        data = ET.tostring(root)
        frames = parse_pdml(
            data, "mixed", 65320, include_data=True, websocket_probe=probe
        )
        sent = [
            text
            for frame in frames
            if not frame.from_server
            for text in frame.websocket_text
        ]
        self.assertEqual(sent, [probe])
        with self.assertRaisesRegex(ValueError, "round trip"):
            parse_pdml(
                data, "mixed", 65320, include_data=True, websocket_probe=probe + "wrong"
            )

    def test_standard_fallback_keeps_all_six_flows_and_native_protocols(self):
        frames = mixed_frames("h2")
        self.assertEqual(check_flow_bodies(frames)["flows"], sorted(FLOWS))
        plan = flow_protocols(frames)
        self.assertEqual(plan["ws"], "h2")
        self.assertEqual({plan[flow] for flow in FLOWS if flow != "ws"}, {"h3"})
        reference = requests_from_wire(frames)
        self.assertEqual(reference["ws"][0].protocol, "h2")
        altered = dict(reference, ws=[replace(reference["ws"][0], protocol="h3")])
        self.assertFalse(
            next(
                row
                for row in compare_requests(reference, altered)
                if row["flow"] == "ws"
            )["match"]
        )
        with self.assertRaisesRegex(ValueError, "unambiguous protocol"):
            flow_protocols([frame for frame in frames if frame.stream != 3])
        with self.assertRaisesRegex(ValueError, "unambiguous protocol"):
            flow_protocols(frames + fixture("h2"))

    def test_h1_upgrade_in_mixed_pdml_verifies_nonce_response_and_text(self):
        root = h1_document()
        root.extend(
            ET.fromstring(
                packet("h3", [(0, [(":method", "GET"), (":path", "/report")])]).replace(
                    b'show="443"', b'show="65320"'
                )
            )
        )
        blocks = parse_pdml(ET.tostring(root), "mixed", 65320, include_data=True)
        h1 = [block for block in blocks if block.protocol == "h1"]
        self.assertEqual([block.connection for block in h1], [4] * 5)
        self.assertEqual({block.stream for block in h1}, {56})
        self.assertEqual(dict(h1[0].headers)["User-Agent"], "fixture")
        self.assertEqual(len([block for block in blocks if block.protocol == "h3"]), 1)
        # The same frame representation feeds body checks and CLI inputs; H1
        # keeps GET/Upgrade while H3 keeps its five actual HTTP operations.
        frames = [frame for frame in fixture("h3") if frame.stream != 3] + h1
        self.assertEqual(check_flow_bodies(frames)["flows"], sorted(FLOWS))
        self.assertEqual(flow_protocols(frames)["ws"], "h1")
        request = requests_from_wire(frames)["ws"][0]
        self.assertEqual((request.protocol, request.method), ("h1", "GET"))
        self.assertEqual(dict(request.headers)["Sec-WebSocket-Key"], "<websocket-key>")
        self.assertEqual(request.bindings["sec-websocket-protocol"], "a, b")
        # Wrong accept and cross-connection responses must fail before replay.
        for name, change, error in (
            ("http.response.line", "value", "accept binding"),
            ("tcp.stream", "show", "connection mismatch"),
        ):
            document = h1_document()
            reply = document.findall("packet")[1]
            field = next(
                node for node in reply.iter("field") if node.get("name") == name
            )
            field.set(
                change,
                (
                    "Sec-WebSocket-Accept: wrong\r\n".encode().hex()
                    if change == "value"
                    else "9"
                ),
            )
            if change == "value":
                field.set("size", str(len(bytes.fromhex(field.get("value")))))
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, error):
                parse_pdml(ET.tostring(document), "mixed", 65320, include_data=True)

    def test_h1_fallback_cannot_borrow_another_connections_tls_joint(self):
        document = ("<pdml>" + hello_packet("Tcp", 4865, 1) + "</pdml>").encode()
        hellos = client_hellos(document, "Tcp")
        archive = {
            "format_version": 1,
            "profiles": [
                {
                    "key": {"user_agent": "fixture"},
                    "scopes": [
                        {
                            "variants": [
                                {
                                    "id": [1] * 32,
                                    "capture": {
                                        "level": "Connection",
                                        "slots": [
                                            {
                                                "kind": "TcpTls",
                                                "capture": hellos[0].capture,
                                            }
                                        ],
                                    },
                                }
                            ]
                        }
                    ],
                }
            ],
        }
        request = replace(
            parse_pdml(ET.tostring(h1_document()), "mixed", 65320)[0], connection=7
        )
        arguments = dict(expected_per_variant_flow=1, expected_flows={"ws"})
        report = compare_h1_connections(archive, hellos, [request], **arguments)
        self.assertEqual(report["variant_flow_counts"]["01" * 32], {"ws": 1})
        with self.assertRaisesRegex(ValueError, "incomplete or ambiguous H1 TLS"):
            compare_h1_connections(
                archive, hellos, [replace(request, connection=8)], **arguments
            )
        unrelated = client_hellos(
            ("<pdml>" + hello_packet("Tcp", 4866, 1) + "</pdml>").encode(), "Tcp"
        )
        with self.assertRaisesRegex(ValueError, "no unique retained connection"):
            compare_h1_connections(archive, unrelated, [request], **arguments)

    def test_protocol_variant_matrix_keeps_the_exact_subset(self):
        matrix = Counter({("variant", "ws"): 1})
        check_variant_flow_matrix(matrix, {"variant"}, 1, flows={"ws"})
        with self.assertRaisesRegex(ValueError, "incomplete"):
            check_variant_flow_matrix(matrix, {"variant"}, 1)
        with self.assertRaisesRegex(ValueError, "outside replay plan"):
            check_variant_flow_matrix(matrix, {"variant"}, 1, flows={"navigate"})
        matrix["variant", "ws"] = 2
        with self.assertRaisesRegex(ValueError, "duplicated"):
            check_variant_flow_matrix(matrix, {"variant"}, 1, flows={"ws"})
