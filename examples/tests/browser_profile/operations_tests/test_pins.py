"""Request recipes and startup plans remain coupled to actual source heads."""

from copy import deepcopy
from dataclasses import replace
import unittest

from operations_tests.fixtures import JOINTS, bound, frames, inspected, ledger, reports
from replay import connection_warmups


class OperationPinTests(unittest.TestCase):
    def test_exact_request_joint_and_initial_query_remove_only_its_own_warmup(self):
        rows, planned, value, _sections = bound(bootstrap=True)
        plans = planned.schedule(value, rows, connection_warmups(value, "h3"))
        self.assertEqual(len(plans), 7)
        for row in plans:
            operation = row["operation"]
            self.assertEqual(len(operation.request), 64)
            if operation.name == "navigate":
                self.assertTrue(row["initial"])
                self.assertEqual(row["warmups"], ())
            else:
                self.assertFalse(row["initial"])
                self.assertEqual(
                    row["warmups"],
                    (JOINTS["h3"],) if operation.protocol == "h3" else (),
                )

    def test_resumed_initial_operation_keeps_full_handshake_ticket_priming(self):
        rows, planned, value, _sections = bound(bootstrap=True)
        full = "11" * 32
        original = value["profiles"][0]["scopes"][1]["variants"][0]
        original["capture"]["slots"][0]["capture"]["extensions"] = [{"id": 41}]
        first = deepcopy(original)
        first["id"] = list(bytes.fromhex(full))
        first["capture"]["slots"] = first["capture"]["slots"][:1]
        first["capture"]["slots"][0]["capture"]["extensions"] = []
        value["profiles"][0]["scopes"][1]["variants"].append(first)
        plans = planned.schedule(value, rows, connection_warmups(value, "h3"))
        initial = next(row for row in plans if row["operation"].name == "navigate")
        later = next(row for row in plans if row["operation"].name == "fetch")
        self.assertEqual(initial["warmups"], (full,))
        self.assertEqual(later["warmups"], (full, JOINTS["h3"]))

    def test_missing_raw_section_or_changed_huffman_flags_cannot_select_request(self):
        rows = frames()
        value, sections = inspected(rows)
        source = ledger(rows).with_joints(reports())
        key = next(iter(sections))
        missing = dict(sections)
        missing.pop(key)
        with self.assertRaisesRegex(ValueError, "raw QPACK"):
            source.with_requests(value, rows, missing)
        section = sections[key]
        sections[key] = replace(
            section,
            fields=(replace(section.fields[0], name_huffman=True),)
            + section.fields[1:],
        )
        with self.assertRaisesRegex(ValueError, "request joint is missing"):
            source.with_requests(value, rows, sections)

    def test_same_fields_in_another_connection_context_do_not_supply_the_pin(self):
        rows = frames()
        value, sections = inspected(rows)
        scope = value["profiles"][0]["scopes"][3]
        scope["context"]["connection"]["resumption"] = "Resumed"
        with self.assertRaisesRegex(ValueError, "request joint is missing"):
            ledger(rows).with_joints(reports()).with_requests(value, rows, sections)

    def test_ambiguous_request_ids_and_malformed_connection_ids_fail_closed(self):
        rows = frames()
        value, sections = inspected(rows)
        scopes = value["profiles"][0]["scopes"]
        other = deepcopy(scopes[3]["variants"][0])
        other["id"] = [99] * 32
        scopes[3]["variants"].append(other)
        with self.assertRaisesRegex(ValueError, "ambiguous"):
            ledger(rows).with_joints(reports()).with_requests(value, rows, sections)
        for raw in ([True] * 32, [256] * 32, "x" * 32, [0] * 31):
            value, sections = inspected(rows)
            value["profiles"][0]["scopes"][0]["variants"][0]["id"] = raw
            with self.subTest(raw=raw), self.assertRaisesRegex(
                ValueError, "connection recipe"
            ):
                ledger(rows).with_joints(reports()).with_requests(value, rows, sections)

    def test_initial_operation_must_own_the_bootstrap_reference_and_startup_plan(self):
        rows, planned, value, _sections = bound(bootstrap=True)
        bootstrap = value["profiles"][0]["scopes"][1]["variants"][0]["capture"][
            "slots"
        ][1]["capture"]
        bootstrap["request"] = [0] * 32
        with self.assertRaisesRegex(ValueError, "reference"):
            planned.schedule(value, rows, connection_warmups(value, "h3"))
        rows, planned, value, _sections = bound(bootstrap=True)
        with self.assertRaisesRegex(ValueError, "startup plan"):
            planned.schedule(value, rows, {})
