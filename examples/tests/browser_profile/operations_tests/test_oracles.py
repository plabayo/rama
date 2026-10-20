"""A declared probe goes through the existing field, body and native oracles."""

from dataclasses import replace
import unittest
from unittest.mock import patch

from capture_fields import compare_capture_fields
from flow_bodies import check_flow_bodies
from native_h3_response import response_sequences
from operations_tests.fixtures import JOINTS, bound
from qpack_fields_wire import compare_field_metadata
from replay import compare_native_connections


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

    def test_query_requires_its_own_complete_native_response_witness(self):
        rows, planned, _value, _sections = bound()
        with patch(
            "native_h3_response.parse_pdml",
            return_value=[
                block for block in rows if block.protocol == "h3" and block.stream == 0
            ],
        ), patch("native_h3_response.response_data", return_value={}):
            with self.assertRaisesRegex(ValueError, "complete native response"):
                response_sequences(b"", 18443, operations=planned)

    def test_original_policy_cannot_use_replay_native_freeze_and_matrix_is_mandatory(
        self,
    ):
        rows, planned, value, _sections = bound()
        replay = planned.for_replay()
        with self.assertRaisesRegex(ValueError, "new native freeze"):
            compare_native_connections(
                value,
                b"",
                18443,
                rows,
                planned.protocols,
                replay=True,
                same_traffic_native=True,
                operations=replay,
            )
        h2 = {"connection_joints": {3: JOINTS["h2"]}}
        wrong_h3 = {"connection_joints": {7: "56" * 32}}
        with patch.multiple(
            "replay",
            client_hellos=lambda *_a: [],
            first_flights=lambda *_a: [],
            client_settings=lambda *_a: [],
            sequence_evidence=lambda *_a: {},
            h2_prefixes=lambda *_a, **_k: [],
            compare_connection_fields=lambda *_a, **_k: h2,
            compare_quic_captures=lambda *_a, **_k: wrong_h3,
        ):
            with self.assertRaisesRegex(ValueError, "swapped"):
                compare_native_connections(
                    value,
                    b"",
                    18443,
                    rows,
                    planned.protocols,
                    replay=True,
                    operations=replay,
                )
