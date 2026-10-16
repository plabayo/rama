from dataclasses import replace
import json
import unittest

from flow_bodies import check_original_bodies
from wire import HeaderBlock


def fixture(protocol):
    rows = []
    for stream, (method, path, body) in enumerate(
        [
            ("GET", "/report", b""),
            (
                "POST",
                "/api/fetch/number/7",
                b'{"number":7,"jsWebApis":{"navigator":{"userAgent":"fixture"}}}',
            ),
            ("POST", "/api/xml/number/8", b'{"number":8}'),
            ("CONNECT", "/api/ws", b""),
            ("POST", "/form", b"source=web&rating=3"),
            ("GET", "/form?source=web&turtles=yes", b""),
        ]
    ):
        headers = ((":method", method), (":path", path), ("user-agent", "fixture"))
        greeting = ()
        if method == "CONNECT":
            headers += ((":protocol", "websocket"),)
            greeting = (
                json.dumps(
                    {
                        "initiator": "ws",
                        "version": {"h2": "HTTP/2.0", "h3": "HTTP/3.0"}[protocol],
                    }
                ),
            )
        rows += [
            HeaderBlock(protocol, stream + 1, 0, stream, False, headers, body),
            HeaderBlock(
                protocol,
                stream + 1,
                0,
                stream,
                True,
                ((":status", "200"),),
                websocket_text=greeting,
            ),
        ]
    return rows


class FlowBodyTests(unittest.TestCase):
    def test_all_operations_and_greeting(self):
        for protocol in ("h2", "h3"):
            self.assertEqual(len(check_original_bodies(fixture(protocol))["flows"]), 6)

    def test_wrong_body_response_or_greeting_cannot_pass(self):
        mutations = [
            (4, {"data": b'{"number":9}'}),
            (
                2,
                {
                    "data": b'{"number":7,"jsWebApis":{"navigator":{"userAgent":"wrong"}}}'
                },
            ),
            (4, {"data": b'{"number":8,"extra":true}'}),
            (8, {"data": b"source=web&rating=2"}),
            (0, {"data": b"unexpected"}),
            (1, {"headers": ((":status", "500"),)}),
            (7, {"websocket_text": ()}),
            (7, {"websocket_text": ('{"initiator":"ws","version":"HTTP/1.1"}',)}),
        ]
        for protocol in ("h2", "h3"):
            for index, changes in mutations:
                rows = fixture(protocol)
                rows[index] = replace(rows[index], **changes)
                with self.subTest(
                    protocol=protocol, index=index, changes=changes
                ), self.assertRaises(ValueError):
                    check_original_bodies(rows)
        with self.assertRaisesRegex(ValueError, "coverage"):
            check_original_bodies(fixture("h3")[:-2])


if __name__ == "__main__":
    unittest.main()
