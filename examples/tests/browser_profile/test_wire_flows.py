import base64
from copy import deepcopy
from dataclasses import replace
import hashlib
from pathlib import Path
import unittest

from wire import FLOWS, GUID, decode_rows
from flows import ReplayTarget, compare_requests as compare, replay_args


def fixture():
    requests, responses = [], []
    key = base64.b64encode(b"0123456789abcdef").decode()
    for index, (flow, uri) in enumerate(
        zip(
            FLOWS,
            (
                "/report",
                "/api/fetch/number/1",
                "/api/xml/number/2",
                "/api/ws",
                "/form",
                "/form?source=web&turtles=yes",
            ),
        ),
        1,
    ):
        body = b"hello" if flow in ("fetch", "xhr", "form") else b""
        headers = ["Host: 127.0.0.1:1234", "Connection: keep-alive"]
        if body:
            headers += [
                "Content-Type: text/plain;charset=UTF-8",
                "Content-Length: 5",
                "Origin: http://127.0.0.1:1234",
            ]
        if flow == "ws":
            headers += [
                "Sec-WebSocket-Key: " + key,
                "Sec-WebSocket-Protocol: a, b",
                "Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits",
            ]
        requests.append(
            {
                "frame.number": str(index),
                "http.request.method": "POST" if body else "GET",
                "http.request.uri": uri,
                "http.request.version": "HTTP/1.1",
                "http.host": "127.0.0.1:1234",
                "http.request.line": "\x1f".join(headers),
                "http.file_data": body.hex(),
            }
        )
        accept = base64.b64encode(hashlib.sha1((key + GUID).encode()).digest()).decode()
        responses.append(
            {
                "http.request_in": str(index),
                "http.response.code": "101" if flow == "ws" else "200",
                "http.response.line": (
                    "Sec-WebSocket-Accept: " + accept if flow == "ws" else ""
                ),
            }
        )
    return requests, responses


class FlowWireTests(unittest.TestCase):
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
            "hello",
            "content-type: text/plain;charset=UTF-8",
            "origin: http://127.0.0.1:5678",
            "content-length: 5",
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
            "sec-websocket-extensions: permessage-deflate; client_max_window_bits",
            ws_args,
        )
        self.assertIn("a,b", ws_args)

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
