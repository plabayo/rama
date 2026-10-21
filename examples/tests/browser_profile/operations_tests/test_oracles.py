"""A declared probe goes through the existing field, body and native oracles."""

from dataclasses import replace
import unittest

from capture_fields import compare_capture_fields
from flow_bodies import check_flow_bodies
from operations_tests.fixtures import JOINTS, bound
from qpack_fields_wire import compare_field_metadata


class OperationOracleTests(unittest.TestCase):
    def test_query_and_discovery_are_checked_without_replacing_six_flow_coverage(self):
        rows, planned, value, sections = bound(bootstrap=True)
        self.assertEqual(
            compare_capture_fields(value, rows, operations=planned)["requests_checked"],
            7,
        )
        self.assertEqual(len(check_flow_bodies(rows, operations=planned)["flows"]), 6)
        result = compare_field_metadata(
            value,
            rows,
            sections,
            expected_flows=planned.roles("h3"),
            connection_joints={7: JOINTS["h3"]},
            operations=planned,
        )
        self.assertEqual(result["requests_checked"], 5)
        self.assertEqual(result["bootstrap_requests_checked"], 1)
        broken = [
            (
                replace(block, headers=((":status", "500"),))
                if block.from_server and block.protocol == "h3" and block.stream == 0
                else block
            )
            for block in rows
        ]
        with self.assertRaisesRegex(ValueError, "successful final response"):
            check_flow_bodies(broken, operations=planned)
        broken = [
            (
                replace(block, data=b"unexpected")
                if not block.from_server
                and block.protocol == "h2"
                and block.stream == 1
                else block
            )
            for block in rows
        ]
        with self.assertRaisesRegex(ValueError, "unexpectedly has a body"):
            check_flow_bodies(broken, operations=planned)
        no_ws = [
            block
            for block in rows
            if not (block.protocol == "h2" and block.stream == 11)
        ]
        with self.assertRaisesRegex(ValueError, "missing or duplicated"):
            check_flow_bodies(no_ws, operations=planned)
