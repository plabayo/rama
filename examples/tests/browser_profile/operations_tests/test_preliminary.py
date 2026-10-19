"""Caller-owned initial POSTs remain coupled to actual source fields and pins."""

import base64
from copy import deepcopy
from dataclasses import replace
import json
from pathlib import Path
import tempfile
import unittest

from flows import ReplayTarget, replay_args
from operations_tests.fixtures import JOINTS, bound
from operations_tests.preliminary_fixtures import post_source
from preliminary import plan_preliminary, source_preliminary, write_preliminary
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
        with tempfile.TemporaryDirectory() as directory:
            target = ReplayTarget("h3", "https://[::1]:28443")
            files = write_preliminary(Path(directory) / "plans", requests, target)
            actual = json.loads(files[0].read_bytes())
            self.assertEqual(actual["method"], "POST")
            self.assertEqual(actual["uri"], target.origin + request.request.uri)
            self.assertEqual(
                base64.b64decode(actual["body_base64"]), request.request.body
            )
            self.assertEqual(actual["emulate_request_variant"], request.request_pin)
            self.assertEqual(actual["emulate_connection_variant"], JOINTS["h3"])
            self.assertEqual(files[0].stat().st_mode & 0o777, 0o600)
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
                preliminary_files=files,
            )
            self.assertIn("--pre-request", args)
            self.assertNotIn("--emulate-warmup-connection-variant", args)
            with self.assertRaisesRegex(ValueError, "cannot mix"):
                replay_args(
                    "rama",
                    "archive",
                    "response",
                    target,
                    "xhr",
                    reference,
                    preliminary_files=files,
                    warmup_variants=(JOINTS["h3"],),
                )
            with self.assertRaises(FileExistsError):
                write_preliminary(Path(directory) / "plans", requests, target)

    def test_bodyless_get_does_not_request_an_explicit_empty_entity(self):
        rows, source, value, sections = bound(bootstrap=True)
        request = source_preliminary(
            value, rows, sections, source, JOINTS["h3"], connection=7
        )
        value = request.input(ReplayTarget("h3", "https://capture.test:443"))
        self.assertEqual(value["method"], "GET")
        self.assertNotIn("body_base64", value)
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
