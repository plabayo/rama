"""Keep a standard browser's actual per-operation protocols through strict replay."""

import base64
from collections import Counter
from contextlib import contextmanager
from dataclasses import replace
import hashlib
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

from capture import fixture_http_versions
from connection_fields import check_variant_flow_matrix, compare_h1_connections
from flows import FLOWS, compare_requests, flow_name, flow_protocols
from replay import connection_variants, requests_from_wire, verify_tls_replay
from test_flow_bodies import fixture
from flow_bodies import WEBSOCKET_PROBE
from test_mixed_connections import hello_packet
from tls_wire import client_hellos
from test_wire_streams import packet
from wire import GUID, check_flow_bodies, parse_pdml

HERE = Path(__file__).parent


def mixed_frames(websocket_protocol):
    """A real six-flow body fixture, with only WS using the browser's fallback."""
    frames = [frame for frame in fixture("h3") if frame.stream != 3]
    for frame in fixture("h2"):
        if frame.stream != 3:
            continue
        headers = frame.headers
        if not frame.from_server:
            headers += (("sec-websocket-protocol", "a,b"),)
        frames.append(replace(frame, protocol=websocket_protocol, headers=headers))
    return frames


def h1_document():
    """Credential-free Upgrade plus retained independently decoded text frames."""
    root = ET.Element("pdml")
    key = base64.b64encode(b"0123456789abcdef").decode()
    accept = base64.b64encode(hashlib.sha1((key + GUID).encode()).digest()).decode()
    for number, response in ((56, False), (58, True)):
        packet = ET.SubElement(root, "packet")
        for name, value in (
            ("frame.number", number),
            ("tcp.stream", 4),
            ("tcp.srcport", 65320 if response else 65345),
            ("tcp.dstport", 65345 if response else 65320),
        ):
            ET.SubElement(packet, "field", name=name, show=str(value))
        http = ET.SubElement(packet, "proto", name="http")
        fields = (
            {"http.request_in": "56", "http.response.code": "101"}
            if response
            else {
                "http.request.method": "GET",
                "http.request.uri": "/api/ws",
                "http.request.version": "HTTP/1.1",
                "http.host": "localhost:65320",
            }
        )
        for name, value in fields.items():
            ET.SubElement(http, "field", name=name, show=value)
        lines = (
            ["Sec-WebSocket-Accept: " + accept]
            if response
            else [
                "Host: localhost:65320",
                "User-Agent: fixture",
                "Connection: Upgrade",
                "Upgrade: websocket",
                "Origin: https://localhost:65320",
                "Sec-WebSocket-Key: " + key,
                "Sec-WebSocket-Protocol: a, b",
            ]
        )
        for line in lines:
            raw = (line + "\r\n").encode()
            ET.SubElement(
                http,
                "field",
                name="http.response.line" if response else "http.request.line",
                value=raw.hex(),
                size=str(len(raw)),
            )
    root.extend(ET.fromstring((HERE / "tests/fixtures/websocket.pdml").read_bytes()))
    return root


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

    def test_shared_replay_sends_only_each_protocols_observed_operations(self):
        class CaptureReached(Exception):
            pass

        @contextmanager
        def process(*_args, **_kwargs):
            yield SimpleNamespace(returncode=0)

        def variant(identifier, kind):
            return {
                "id": [identifier] * 32,
                "capture": {
                    "level": "Connection",
                    "slots": [{"kind": kind, "capture": {"extensions": []}}],
                },
            }

        archive = {
            "profiles": [
                {
                    "scopes": [
                        {
                            "variants": [
                                variant(1, "QuicTls"),
                                variant(2, "TcpTls"),
                                variant(3, "TcpTls"),
                            ]
                        }
                    ]
                }
            ]
        }
        # Add native H2 prefix to classify the TCP recipe, rather than sharing
        # all connection IDs across the H3 and WebSocket protocol flows.
        for variant in archive["profiles"][0]["scopes"][0]["variants"][1:]:
            variant["capture"]["slots"].append(
                {"kind": "Http2EarlyFrames", "capture": {}}
            )
        self.assertEqual(connection_variants(archive, "h3"), ["01" * 32])
        self.assertEqual(connection_variants(archive, "h2"), ["02" * 32, "03" * 32])
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "headers.pdml").write_text("<pdml/>")
            commands, probes = [], []
            with patch.multiple(
                "replay",
                client_hellos=lambda *_args: [],
                replay_environment=lambda _parent: {},
                running=process,
                wait_ready=lambda *_args, **_kwargs: None,
                check_missing_tls_bindings=lambda command, *_args, **_kwargs: probes.append(
                    command
                ),
                run_replay=lambda command, **_kwargs: commands.append(command),
            ), patch("replay.drain_capture", side_effect=CaptureReached) as drain:
                with self.assertRaises(CaptureReached):
                    verify_tls_replay(
                        SimpleNamespace(
                            output=root,
                            rama=Path("rama"),
                            protocol="h3",
                            interface="lo",
                        ),
                        traffic=SimpleNamespace(frames=mixed_frames("h2")),
                        inspected=archive,
                        server_command=[],
                        environment={},
                        certificate=root / "cert.pem",
                        port=443,
                    )
            self.assertEqual(len(probes), 2)
            self.assertEqual(sum("--http3" in command for command in commands), 5)
            self.assertEqual(sum("--http2" in command for command in commands), 2)
            self.assertTrue(
                all(
                    ("--http2" in command) == command[-1].startswith("wss:")
                    for command in commands
                )
            )
            self.assertEqual(
                drain.call_args.kwargs["expected_per_flow"],
                {**dict.fromkeys(FLOWS, 1), "ws": 2},
            )
            self.assertEqual(drain.call_args.kwargs["expected_warmups"], 5)

    def test_internal_protocol_probe_is_not_a_profiled_navigation(self):
        self.assertEqual(
            flow_name(((":method", "GET"), (":path", "/report"))), "navigate"
        )
        self.assertIsNone(
            flow_name(((":method", "GET"), (":path", "/report?h3_probe=1")))
        )

    def test_fixture_retains_standard_websocket_fallback(self):
        self.assertEqual(fixture_http_versions("h3"), "auto")
        self.assertEqual(fixture_http_versions("h2"), "h1,h2")
