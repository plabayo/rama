import copy
import unittest
from capture_fields import compare_capture_fields, matching_fields
from flows import FLOWS
from types import SimpleNamespace
from wire import h1_header_blocks
from wire_fixtures import wire_flows_fixture as h1_fixture


def joint():
    return {
        "slots": [
            {
                "kind": "Headers",
                "capture": {
                    "fields": [
                        {
                            "name": "accept",
                            "occurrence": 0,
                            "value": {"Profile": list(b"first")},
                        },
                        {
                            "name": "accept",
                            "occurrence": 1,
                            "value": {"Profile": list(b"second")},
                        },
                        {
                            "name": "content-length",
                            "occurrence": 0,
                            "value": {"Request": "Framing"},
                        },
                    ]
                },
            },
            {
                "kind": "PseudoHeaders",
                "capture": {"fields": [{"name": ":method"}, {"name": ":path"}]},
            },
        ]
    }


WIRE = (
    (":method", "POST"),
    (":path", "/form"),
    ("accept", "first"),
    ("accept", "second"),
    ("content-length", "12"),
)


class CaptureFieldTests(unittest.TestCase):
    def test_retained_values_and_request_bindings_are_reported_separately(self):
        self.assertEqual(matching_fields(joint(), WIRE), (2, 1))

    def test_different_literal_duplicate_order_or_pseudo_order_fails(self):
        for wire in [
            WIRE[:3] + (("accept", "wrong"),) + WIRE[4:],
            WIRE[:2] + (WIRE[3], WIRE[2]) + WIRE[4:],
            (WIRE[1], WIRE[0]) + WIRE[2:],
            WIRE[:-1],
        ]:
            with self.subTest(wire=wire):
                self.assertIsNone(matching_fields(joint(), wire))

    def test_occurrence_number_and_joint_membership_are_required(self):
        capture = joint()
        capture["slots"][0]["capture"]["fields"][1]["occurrence"] = 0
        self.assertIsNone(matching_fields(capture, WIRE))
        capture = joint()
        capture["slots"].pop()
        self.assertIsNone(matching_fields(capture, WIRE))

    def test_full_comparison_requires_every_flow_and_matching_client(self):
        operations = [
            ("navigate", "GET", "/report"),
            ("fetch", "POST", "/api/fetch/number/1"),
            ("xhr", "POST", "/api/xml/number/1"),
            ("ws", "CONNECT", "/api/ws"),
            ("form", "POST", "/form"),
            ("form_get", "GET", "/form?source=web&turtles=yes"),
        ]
        scopes, blocks = [], []
        for flow, method, path in operations:
            headers = [(":method", method), (":path", path), ("user-agent", "fixture")]
            if flow == "ws":
                headers.insert(2, (":protocol", "websocket"))
            capture = {
                "slots": [
                    {
                        "kind": "Headers",
                        "capture": {
                            "fields": [
                                {
                                    "name": "user-agent",
                                    "occurrence": 0,
                                    "value": {"Profile": list(b"fixture")},
                                }
                            ]
                        },
                    },
                    {
                        "kind": "PseudoHeaders",
                        "capture": {
                            "fields": [
                                {"name": name}
                                for name, _ in headers
                                if name.startswith(":")
                            ]
                        },
                    },
                ]
            }
            scopes.append(
                {
                    "flow": {
                        "Http": {
                            "version": "HTTP/3.0",
                            "method": method,
                            "initiator": "form" if flow == "form_get" else flow,
                            "fetch": None,
                        }
                    },
                    "variants": [{"capture": capture}],
                }
            )
            blocks.append(
                SimpleNamespace(
                    protocol="h3",
                    from_server=False,
                    connection=0,
                    stream=len(blocks) * 4,
                    headers=tuple(headers),
                )
            )
        inspected = {
            "format_version": 1,
            "profiles": [{"key": {"user_agent": "fixture"}, "scopes": scopes}],
        }
        self.assertEqual(
            compare_capture_fields(inspected, blocks)["requests_checked"], 6
        )
        with self.assertRaisesRegex(ValueError, "incomplete"):
            compare_capture_fields(inspected, blocks[:-1])
        inspected["profiles"][0]["key"]["user_agent"] = "other-client"
        with self.assertRaisesRegex(ValueError, "no matching scoped"):
            compare_capture_fields(inspected, blocks)

    def test_h1_keeps_field_spelling_but_counts_duplicate_names_without_case(self):
        capture = {
            "version": "HTTP/1.1",
            "fields": [
                {"name": "Accept", "occurrence": 0, "value": {"Profile": list(b"first")}},
                {"name": "aCcEpT", "occurrence": 1, "value": {"Profile": list(b"second")}},
                {"name": "Host", "occurrence": 0, "value": {"Request": "Authority"}},
            ],
        }
        headers = (
            (":method", "GET"), (":path", "/report"),
            ("Accept", "first"), ("aCcEpT", "second"), ("Host", "owned:443"),
        )
        self.assertEqual(matching_fields(capture, headers, protocol="h1"), (2, 1))
        for altered in (
            headers[:2] + (headers[3], headers[2], headers[4]),
            headers[:2] + (("accept", "first"),) + headers[3:],
            headers[:3] + (("aCcEpT", "wrong"),) + headers[4:],
            headers[:-1],
        ):
            with self.subTest(altered=altered):
                self.assertIsNone(matching_fields(capture, altered, protocol="h1"))
        capture["fields"][1]["occurrence"] = 0
        self.assertIsNone(matching_fields(capture, headers, protocol="h1"))
        self.assertIsNone(matching_fields(capture, headers, protocol="h2"))

    def test_h1_six_flows_require_their_own_browser_scope_and_observation(self):
        rows, _ = h1_fixture()
        for row in rows:
            row["tcp.stream"] = "7"
            row["http.request.line"] += "\x1fUser-Agent: fixture"
        blocks = h1_header_blocks(rows)
        scopes = []
        for flow, block in zip(FLOWS, blocks):
            fields = []
            for name, value in block.headers:
                if name.startswith(":"):
                    continue
                fields.append({
                    "name": name, "occurrence": 0,
                    "value": {"Request": "Authority"} if name == "Host" else {
                        "Profile": list(value.encode("latin-1"))
                    },
                })
            scopes.append({
                "flow": {"Http": {
                    "version": "HTTP/1.1", "method": dict(block.headers)[":method"],
                    "initiator": "form" if flow == "form_get" else flow, "fetch": None,
                }},
                "variants": [{"capture": {"version": "HTTP/1.1", "fields": fields}}],
            })
        inspected = {
            "format_version": 1,
            "profiles": [{"key": {"user_agent": "fixture"}, "scopes": scopes}],
        }
        report = compare_capture_fields(inspected, blocks)
        self.assertEqual(report["requests_checked"], 6)
        self.assertEqual(report["request_bound_values_not_retained"], 6)
        self.assertEqual(set(report["flows"]), set(FLOWS))
        for change in ("agent", "version", "initiator", "literal"):
            bad = copy.deepcopy(inspected)
            if change == "agent":
                bad["profiles"][0]["key"]["user_agent"] = "other"
            elif change == "literal":
                fields = bad["profiles"][0]["scopes"][1]["variants"][0]["capture"]["fields"]
                fields[-1]["value"] = {"Profile": list(b"wrong")}
            else:
                bad["profiles"][0]["scopes"][1]["flow"]["Http"][change] = (
                    "HTTP/2.0" if change == "version" else "xhr"
                )
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, "no matching"):
                compare_capture_fields(bad, blocks)
        with self.assertRaisesRegex(ValueError, "incomplete"):
            compare_capture_fields(inspected, blocks[:-1])

    def test_unknown_value_ownership_fails_closed(self):
        capture = copy.deepcopy(joint())
        capture["slots"][0]["capture"]["fields"][0]["value"] = {"Unknown": []}
        with self.assertRaisesRegex(ValueError, "unknown"):
            matching_fields(capture, WIRE)


if __name__ == "__main__":
    unittest.main()
