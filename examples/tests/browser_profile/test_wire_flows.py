import base64
import csv
import io
import hashlib
import tempfile
import unittest
from copy import deepcopy
from dataclasses import replace
from flows import ReplayTarget, compare_requests as compare, replay_args
from pathlib import Path
from unittest.mock import patch
from wire import (
    GUID,
    decode_rows,
    field_rows,
    h1_header_blocks,
    h1_tls_evidence,
    http_decode_args,
)
from wire_fixtures import wire_flows_fixture as fixture


class FlowWireTests(unittest.TestCase):
    def test_h1_custom_marker_reaches_the_replay_command(self):
        requests, responses = fixture()
        for row in requests:
            row["http.request.line"] += "\x1fx-RAMA-custom-header-marker: current-marker"
        captured = decode_rows(requests, responses, 1234, True)
        for flow in ("fetch", "xhr"):
            command = replay_args(
                "rama", "archive", "output",
                ReplayTarget("h1", "http://127.0.0.1:5678"),
                flow, captured[flow][0],
            )
            self.assertIn(
                "--header=x-rama-custom-header-marker: current-marker", command
            )

    def test_six_operations_and_request_owned_replay_inputs(self):
        requests, responses = fixture()
        flows = decode_rows(requests, responses, 1234, True)
        self.assertTrue(all(row["match"] for row in compare(flows, flows)))
        args = replay_args(
            Path("rama"),
            Path("archive"),
            Path("output"),
            ReplayTarget("h1", "http://127.0.0.1:5678"),
            "fetch",
            flows["fetch"][0],
        )
        for value in (
            "fetch",
            "POST",
            "--data=hello",
            "--header=content-type: text/plain;charset=UTF-8",
            "--header=origin: http://127.0.0.1:5678",
            "--header=content-length: 5",
        ):
            self.assertIn(value, args)
        self.assertEqual(args[-1], "http://127.0.0.1:5678/api/fetch/number/1")
        ws_args = replay_args(
            Path("rama"),
            Path("archive"),
            Path("output"),
            ReplayTarget("h1", "http://127.0.0.1:5678"),
            "ws",
            flows["ws"][0],
        )
        self.assertIn(
            "--header=sec-websocket-extensions: permessage-deflate; client_max_window_bits",
            ws_args,
        )
        self.assertIn("a,b", ws_args)

    def test_https_uses_its_owned_authority_origin_and_wss_replay(self):
        requests, responses = fixture()
        for row in requests:
            row["http.host"] = "localhost:1234"
            row["http.request.line"] = row["http.request.line"].replace(
                "http://127.0.0.1", "https://localhost"
            ).replace("127.0.0.1", "localhost")
        captured = decode_rows(requests, responses, 1234, True, secure=True)
        target = ReplayTarget("h1", "https://localhost:5678", Path("fixture.pem"))
        command = replay_args(
            "rama", "archive", "output", target, "ws", captured["ws"][0],
            connection_variant="ab" * 32,
        )
        self.assertEqual(command[-1], "wss://localhost:5678/api/ws")
        self.assertIn("--cacert", command)
        self.assertIn("--emulate-connection-variant", command)
        self.assertEqual(
            captured["fetch"][0].bindings["origin"], "https://localhost:1234"
        )
        requests[1]["http.request.line"] = requests[1]["http.request.line"].replace(
            "https://", "http://"
        )
        with self.assertRaisesRegex(ValueError, "Origin binding"):
            decode_rows(requests, responses, 1234, True, secure=True)

    def test_replay_requires_the_exact_number_of_pinned_variants_per_flow(self):
        requests, responses = fixture()
        repeated = requests + [dict(row) for row in requests]
        result = decode_rows(repeated, responses, 1234, False, expected_per_flow=2)
        self.assertTrue(all(len(rows) == 2 for rows in result.values()))
        for count in (1, 3):
            with self.subTest(count=count), self.assertRaisesRegex(
                ValueError, "ambiguous repeated flow"
            ):
                decode_rows(repeated, responses, 1234, False, expected_per_flow=count)

    def test_tls_field_decode_requires_a_keylog_and_selects_tls(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            capture, keylog = root / "wire.pcapng", root / "fixture.keys"
            capture.touch()
            with self.assertRaisesRegex(ValueError, "missing TLS key log"):
                field_rows(capture, 24443, "http.request", [], keylog=keylog)
            keylog.touch()
            decoded = "frame.number\n2\n"
            output = root / "requests.tsv"
            with patch("wire.subprocess.check_output", return_value=decoded) as decode:
                self.assertEqual(
                    field_rows(
                        capture, 24443, "http.request", ["frame.number"],
                        keylog=keylog, output=output,
                    ),
                    [{"frame.number": "2"}],
                )
            self.assertEqual(output.read_text(), decoded)
            command = decode.call_args.args[0]
            self.assertIn("tcp.port==24443,tls", command)
            self.assertIn("tls.keylog_file:" + str(keylog), command)
            self.assertNotIn("tcp.port==24443,http", command)
            self.assertEqual(http_decode_args(24443), ["-d", "tcp.port==24443,http"])

    def test_tls_evidence_binds_decoded_requests_to_their_own_client_hello(self):
        from wire_fixtures import tls_wire_comparison_fixture as comparison_fixture, tls_wire_vector as vector

        archive, _, _ = comparison_fixture()
        body = (b"\x03\x03" + bytes(32) + b"\x00" + vector(b"\x13\x01")
                + b"\x01\x00" + vector(b""))
        raw = b"\x01" + vector(body, 3)
        pdml = (
            '<pdml><packet><field name="frame.number" show="1"/>'
            '<field name="tcp.stream" show="7"/>'
            f'<field name="tls.handshake" pos="0" size="{len(raw)}" value="{raw.hex()}">'
            '<field name="tls.handshake.type" show="1" pos="0" size="1" value="01"/>'
            '</field></packet></pdml>'
        ).encode()
        row = {
            "frame.number": "2", "tcp.stream": "7", "http.user_agent": "fixture",
            "http.request.uri": "/report",
        }
        asset = dict(row, **{"tcp.stream": "99", "http.request.uri": "/assets/script.js"})
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            capture, keylog = root / "wire.pcapng", root / "fixture.keys"
            capture.touch()
            keylog.touch()

            def decode(command, **kwargs):
                self.assertIn("tcp.port==24443,tls", command)
                kwargs["stdout"].write(pdml)

            def decode_fields(command, **kwargs):
                output = io.StringIO()
                fields = [command[i + 1] for i, arg in enumerate(command) if arg == "-e"]
                writer = csv.DictWriter(output, fieldnames=fields, delimiter="\t", quoting=csv.QUOTE_ALL)
                writer.writeheader()
                writer.writerows([row, asset])
                return output.getvalue()

            with patch("wire.subprocess.run", side_effect=decode), patch(
                "wire.subprocess.check_output", side_effect=decode_fields
            ):
                result = h1_tls_evidence(
                    capture, keylog, 24443, root / "valid.pdml", archive
                )
                self.assertEqual(result["connections_checked"], 1)
                self.assertEqual(result["unprofiled_asset_requests"], 1)
                row["tcp.stream"] = "8"
                with self.assertRaisesRegex(ValueError, "incomplete request-bearing"):
                    h1_tls_evidence(
                        capture, keylog, 24443, root / "wrong-stream.pdml", archive
                    )
                row["tcp.stream"] = "7"
                row["http.user_agent"] = "other"
                with self.assertRaisesRegex(ValueError, "no matching TLS capture"):
                    h1_tls_evidence(
                        capture, keylog, 24443, root / "wrong-agent.pdml", archive
                    )

    def test_h1_header_blocks_preserve_wire_case_order_and_transport_identity(self):
        rows, _ = fixture()
        for index, row in enumerate(rows):
            row["tcp.stream"] = str(index % 2)
        blocks = h1_header_blocks(rows)
        self.assertEqual(len(blocks), 6)
        self.assertEqual(blocks[0].connection, 0)
        self.assertEqual(blocks[1].connection, 1)
        self.assertEqual(blocks[0].stream, 1)
        self.assertEqual(blocks[0].headers[:4], (
            (":method", "GET"), (":path", "/report"),
            ("Host", "127.0.0.1:1234"), ("Connection", "keep-alive"),
        ))
        for field, value in (
            ("tcp.stream", "0\x1f1"), ("frame.number", "1\x1f2"),
            ("http.request.version", "HTTP/2.0"),
        ):
            bad = deepcopy(rows)
            bad[0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                h1_header_blocks(bad)

    def test_invalid_bindings_status_and_missing_flow_are_rejected(self):
        for field, value in [
            ("http.host", "example.com"),
            ("http.request.version", "HTTP/2"),
            ("http.file_data", b"wrong length".hex()),
            ("http.request.line", "Host: 127.0.0.1:1234\x1fOrigin: http://example.com"),
        ]:
            with self.subTest(field=field):
                requests, responses = fixture()
                requests[1][field] = value
                with self.assertRaises(ValueError):
                    decode_rows(requests, responses, 1234, True)
        for change in ("status", "accept", "missing", "duplicate"):
            with self.subTest(change=change):
                requests, responses = fixture()
                if change == "status":
                    responses[0]["http.response.code"] = "500"
                if change == "accept":
                    responses[3]["http.response.line"] = "Sec-WebSocket-Accept: wrong"
                if change == "missing":
                    requests.pop()
                if change == "duplicate":
                    requests.append(deepcopy(requests[1]))
                with self.assertRaises(ValueError):
                    decode_rows(requests, responses, 1234, True)

    def test_wire_checks_body_header_value_case_and_order(self):
        flows = decode_rows(*fixture(), 1234, True)
        original = flows["fetch"][0]
        for altered in (
            replace(original, body=b"other"),
            replace(original, headers=tuple(reversed(original.headers))),
            replace(
                original,
                headers=tuple(
                    line.replace("text/plain", "application/json")
                    for line in original.headers
                ),
            ),
            replace(original, headers=tuple(line.lower() for line in original.headers)),
            replace(original, headers=original.headers + ("X-Extra: no",)),
        ):
            replay = dict(flows, fetch=[altered])
            self.assertFalse(
                next(row for row in compare(flows, replay) if row["flow"] == "fetch")[
                    "match"
                ]
            )

    def test_authority_and_nonce_normalization_remains_bound_to_wire(self):
        requests, responses = fixture()
        baseline = decode_rows(requests, responses, 1234, True)
        for row in requests:
            row["http.host"] = "127.0.0.1:5678"
            row["http.request.line"] = row["http.request.line"].replace(
                ":1234", ":5678"
            )
        key = base64.b64encode(b"fedcba9876543210").decode()
        requests[3]["http.request.line"] = requests[3]["http.request.line"].replace(
            base64.b64encode(b"0123456789abcdef").decode(), key
        )
        responses[3]["http.response.line"] = (
            "Sec-WebSocket-Accept: "
            + base64.b64encode(hashlib.sha1((key + GUID).encode()).digest()).decode()
        )
        replay = decode_rows(requests, responses, 5678, False)
        self.assertTrue(all(row["match"] for row in compare(baseline, replay)))

    def test_unsupported_or_ambiguous_framing_is_rejected(self):
        for extra in (
            "Host: 127.0.0.1:1234",
            "Content-Length: 5",
            "Transfer-Encoding: chunked",
            "Cookie: private",
            "Authorization: private",
            "Proxy-Authorization: private",
        ):
            with self.subTest(extra=extra):
                requests, responses = fixture()
                requests[1]["http.request.line"] += "\x1f" + extra
                with self.assertRaises(ValueError):
                    decode_rows(requests, responses, 1234, True)

    def test_variants_cannot_mix_independently_matching_fields(self):
        flows = decode_rows(*fixture(), 1234, True)
        first = flows["navigate"][0]
        second = replace(
            first, headers=first.headers + ("X-Variant: two",), body=b"two"
        )
        reference = dict(flows, navigate=[first, second])
        replay = dict(flows, navigate=[replace(first, body=b"two")])
        self.assertFalse(compare(reference, replay)[0]["match"])


if __name__ == "__main__":
    unittest.main()
