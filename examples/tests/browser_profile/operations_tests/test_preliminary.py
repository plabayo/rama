"""Caller-owned initial POSTs remain coupled to actual source fields and pins."""

from copy import deepcopy
from dataclasses import replace
import unittest

from flows import ReplayTarget, replay_args, request_segments
from operations_tests.fixtures import JOINTS, bound
from operations_tests.preliminary_fixtures import post_source, segment_fields
from preliminary import plan_preliminary, preliminary_arguments, source_preliminary
from request_wire import request_from_stream


class PreliminaryPlanningTests(unittest.TestCase):
    def test_actual_initial_post_uses_current_caller_body_context_and_exact_pins(self):
        rows, source, value, sections = post_source()
        later = next(
            operation for operation in source.operations if operation.name == "xhr"
        )
        requests = plan_preliminary(
            value, rows, sections, source, later, (JOINTS["h3"],)
        )
        self.assertEqual(len(requests), 1)
        request = requests[0]
        self.assertEqual(request.request.method, "POST")
        self.assertEqual(request.flow, "fetch")
        self.assertEqual(request.source_key, ("h3", 7, 0))
        target = ReplayTarget("h3", "https://[::1]:28443")
        segments = preliminary_arguments(requests, target)
        actual = segment_fields(segments[0])
        self.assertEqual(actual["method"], "POST")
        self.assertEqual(actual["uri"], target.origin + request.request.uri)
        self.assertEqual(actual["data"].encode(), request.request.body)
        self.assertEqual(actual["request"], request.request_pin)
        self.assertEqual(actual["connection"], JOINTS["h3"])
        self.assertFalse(actual["bootstrap"])
        main = next(row for row in rows if source.name(row) == "xhr")
        reference = request_from_stream(
            [
                row
                for row in rows
                if (row.protocol, row.connection, row.stream)
                == (main.protocol, main.connection, main.stream)
            ],
            flow="xhr",
        )
        args = replay_args(
            "rama",
            "archive",
            "response",
            target,
            "xhr",
            reference,
            preliminary_requests=segments,
        )
        # Preliminary first, the operation last, and only its response is kept.
        first, last = request_segments(args)
        self.assertEqual(first[-len(segments[0]) :], list(segments[0]))
        self.assertIn("--last-response-only", first)
        self.assertEqual(last[-1], target.origin + reference.uri)
        self.assertEqual(segment_fields(last)["method"], reference.method)
        self.assertNotIn("--emulate-connection-bootstrap", args)
        with self.assertRaisesRegex(ValueError, "cannot mix"):
            replay_args(
                "rama",
                "archive",
                "response",
                target,
                "xhr",
                reference,
                preliminary_requests=segments,
                warmup_variants=(JOINTS["h3"],),
            )

    def test_preliminary_body_must_be_literal_utf8_data(self):
        rows, source, value, sections = post_source()
        request = source_preliminary(
            value, rows, sections, source, JOINTS["h3"], connection=7
        )
        target = ReplayTarget("h3", "https://[::1]:28443")
        for body in (b"\xff\xfe", b"a\0b", b"@secret"):
            with (
                self.subTest(body=body),
                self.assertRaisesRegex(ValueError, "literal UTF-8"),
            ):
                replace(request, request=replace(request.request, body=body)).arguments(
                    target
                )

    def test_bodyless_get_does_not_request_an_explicit_empty_entity(self):
        rows, source, value, sections = bound(bootstrap=True)
        request = source_preliminary(
            value, rows, sections, source, JOINTS["h3"], connection=7
        )
        value = segment_fields(
            request.arguments(ReplayTarget("h3", "https://capture.test:443"))
        )
        self.assertEqual(value["method"], "GET")
        self.assertNotIn("data", value)
        self.assertFalse(
            any(name.lower() == "content-length" for name, _value in value["headers"])
        )

    def test_missing_or_crossed_source_pin_body_and_raw_metadata_fail_closed(self):
        rows, source, value, sections = post_source()
        first = source_preliminary(
            value, rows, sections, source, JOINTS["h3"], connection=7
        )
        missing = dict(sections)
        missing.pop((first.source_packet, 7, 0))
        with self.assertRaisesRegex(ValueError, "raw QPACK"):
            source_preliminary(value, rows, missing, source, JOINTS["h3"], connection=7)
        changed = dict(sections)
        section = changed[first.source_packet, 7, 0]
        changed[first.source_packet, 7, 0] = replace(
            section,
            fields=(replace(section.fields[0], value_huffman=True),)
            + section.fields[1:],
        )
        with self.assertRaisesRegex(ValueError, "raw QPACK"):
            source_preliminary(value, rows, changed, source, JOINTS["h3"], connection=7)
        with self.assertRaisesRegex(ValueError, "native joint"):
            source_preliminary(
                value, rows, sections, source, JOINTS["h3"], connection=99
            )
        altered = deepcopy(value)
        altered["profiles"][0]["scopes"][1]["variants"][0]["capture"]["slots"][-1][
            "capture"
        ]["request"] = [0] * 32
        with self.assertRaisesRegex(ValueError, "scoped request joint"):
            source_preliminary(
                altered, rows, sections, source, JOINTS["h3"], connection=7
            )
        credentialed = [
            (
                replace(row, headers=row.headers + (("authorization", "never-copy"),))
                if row.protocol == "h3" and row.stream == 0 and not row.from_server
                else row
            )
            for row in rows
        ]
        with self.assertRaises(ValueError):
            source_preliminary(
                value, credentialed, sections, source, JOINTS["h3"], connection=7
            )

    def test_source_preliminary_count_and_input_byte_bounds_are_explicit(self):
        rows, source, value, sections = post_source()
        operation = next(
            operation for operation in source.operations if operation.name == "xhr"
        )
        with self.assertRaisesRegex(ValueError, "count limit"):
            plan_preliminary(
                value, rows, sections, source, operation, (JOINTS["h3"],) * 17
            )
        requests = plan_preliminary(
            value, rows, sections, source, operation, (JOINTS["h3"],)
        )
        target = ReplayTarget("h3", "https://capture.test:443")
        with self.assertRaisesRegex(ValueError, "count limit"):
            preliminary_arguments(requests * 17, target)
        large = replace(
            requests[0],
            request=replace(requests[0].request, body=b"x" * (1024 * 1024)),
        )
        with self.assertRaisesRegex(ValueError, "byte budget"):
            preliminary_arguments((large,), target)
