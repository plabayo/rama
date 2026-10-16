from dataclasses import replace
import json
import unittest

from flow_bodies import check_original_bodies, json_object
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
    def test_non_json_numeric_constants_are_rejected_recursively(self):
        for token in ("NaN", "Infinity", "-Infinity"):
            with self.subTest(token=token), self.assertRaisesRegex(
                ValueError, "non-finite"
            ):
                json_object('{"nested":{"value":' + token + "}}")

    def test_all_operations_and_greeting(self):
        for protocol in ("h2", "h3"):
            self.assertEqual(len(check_original_bodies(fixture(protocol))["flows"]), 6)

    def test_invalid_json_number_and_duplicate_members_are_rejected(self):
        # Keep every other flow valid so no later coverage check masks failure.
        for protocol in ("h2", "h3"):
            for index, initiator in ((2, "fetch"), (4, "xml")):
                for literal, number in (
                    ("true", 1),
                    ("false", 0),
                    ("1.0", 1),
                    ('1,"number":1', 1),
                    ("-1", -1),
                    (str(1 << 64), 1 << 64),
                ):
                    rows = fixture(protocol)
                    body = '{"number":' + literal
                    if initiator == "fetch":
                        body += ',"jsWebApis":{"navigator":{"userAgent":"fixture"}}'
                    body += "}"
                    headers = tuple(
                        (
                            name,
                            (
                                f"/api/{initiator}/number/{number}"
                                if name == ":path"
                                else value
                            ),
                        )
                        for name, value in rows[index].headers
                    )
                    rows[index] = replace(
                        rows[index], headers=headers, data=body.encode()
                    )
                    with self.subTest(
                        protocol=protocol, initiator=initiator, literal=literal
                    ), self.assertRaises(ValueError):
                        check_original_bodies(rows)

    def test_json_objects_and_nested_members_are_unambiguous(self):
        for protocol in ("h2", "h3"):
            for body in (b"[]", b"null", b"8", b'{"number":8,"extra":{"a":1,"a":2}}'):
                rows = fixture(protocol)
                rows[4] = replace(rows[4], data=body)
                with self.subTest(protocol=protocol, body=body), self.assertRaises(
                    ValueError
                ):
                    check_original_bodies(rows)
            rows = fixture(protocol)
            version = {"h2": "HTTP/2.0", "h3": "HTTP/3.0"}[protocol]
            greeting = (
                '{"initiator":"wrong","initiator":"ws","version":"' + version + '"}'
            )
            rows[7] = replace(rows[7], websocket_text=(greeting,))
            with self.assertRaisesRegex(ValueError, "duplicate"):
                check_original_bodies(rows)

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
