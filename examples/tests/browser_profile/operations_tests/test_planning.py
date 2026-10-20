"""Driver identity and exact source operations must agree."""

from dataclasses import replace
import unittest

from flows import FLOWS, compare_requests, flow_protocols
from operations import DISCOVERY, OperationLedger
from operations_tests.fixtures import FINAL, ORIGIN, bound, frames, ledger, reports
from replay import requests_from_wire


class OperationPlanningTests(unittest.TestCase):
    def test_original_and_final_navigation_keep_their_actual_protocol_and_uri(self):
        rows, planned, _inspected, _sections = bound()
        self.assertEqual(set(planned.names), set(FLOWS) | {DISCOVERY})
        self.assertEqual(planned.protocols[DISCOVERY], "h2")
        self.assertEqual(planned.measured_protocols["navigate"], "h3")
        self.assertEqual(flow_protocols(rows, operations=planned), planned.protocols)
        requests = requests_from_wire(rows, operations=planned)
        self.assertEqual(requests[DISCOVERY][0].uri, "/report")
        self.assertEqual(requests["navigate"][0].uri, "/report?h3_probe=1")
        self.assertEqual(len(planned.check_matrix(rows, reports())), 7)

    def test_driver_final_url_cannot_be_guessed_or_normalized(self):
        planned = ledger()
        for url in (
            None,
            ORIGIN + "/form",
            FINAL + "&extra=1",
            FINAL.replace("capture.test", "other.test"),
        ):
            with self.subTest(url=url), self.assertRaisesRegex(
                ValueError, "actual final report URL"
            ):
                OperationLedger.from_driver(
                    frames(), planned.measured_protocols, ORIGIN, url
                )
        with self.assertRaisesRegex(ValueError, "no unique source stream"):
            OperationLedger.from_driver(
                frames(), planned.measured_protocols, ORIGIN, ORIGIN + "/report"
            )

    def test_missing_or_duplicate_discovery_and_measured_heads_fail(self):
        rows = frames()
        for changed in (rows[2:], rows + [rows[0]], rows[:2] + rows[4:]):
            with self.subTest(size=len(changed)), self.assertRaises(ValueError):
                ledger(changed)

    def test_stream_packet_or_method_changes_do_not_borrow_an_operation(self):
        rows, planned, _value, _sections = bound()
        head = rows[2]
        for changed in (
            replace(head, packet=999),
            replace(head, stream=999),
            replace(head, protocol="h2"),
            replace(
                head,
                headers=tuple(
                    (name, "HEAD" if name == ":method" else value)
                    for name, value in head.headers
                ),
            ),
        ):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                planned.validate_heads(rows[:2] + [changed] + rows[3:])

    def test_every_retained_joint_needs_an_actual_declared_operation(self):
        for changed in (
            {"h3": reports()["h3"]},
            {**reports(), "h2": {"connection_joints": {3: "12" * 32, 8: "56" * 32}}},
        ):
            with self.subTest(changed=changed), self.assertRaises(
                (ValueError, KeyError)
            ):
                ledger().with_joints(changed)

    def test_replay_requires_exact_joint_operation_pairs_after_stream_renumbering(self):
        rows, planned, _value, _sections = bound()
        replay = planned.for_replay()
        actual = [
            replace(
                block,
                packet=block.packet + 100,
                connection=block.connection + 100,
                stream=block.stream + 100,
            )
            for block in rows
        ]
        actual_reports = {
            protocol: {
                "connection_joints": {
                    number + 100: joint
                    for number, joint in report["connection_joints"].items()
                }
            }
            for protocol, report in reports().items()
        }
        self.assertEqual(len(replay.check_matrix(actual, actual_reports)), 7)
        actual_reports["h2"]["connection_joints"][103] = "34" * 32
        with self.assertRaisesRegex(ValueError, "swapped"):
            replay.check_matrix(actual, actual_reports)

    def test_root_warmup_never_substitutes_for_measured_query(self):
        rows, planned, _value, _sections = bound()
        changed = [
            (
                replace(
                    block,
                    headers=tuple(
                        (name, "/" if name == ":path" else value)
                        for name, value in block.headers
                    ),
                )
                if block.protocol == "h3" and block.stream == 0
                else block
            )
            for block in rows
        ]
        with self.assertRaisesRegex(ValueError, "missing or duplicated"):
            planned.for_replay().validate_heads(changed)
        requests = requests_from_wire(rows, operations=planned)
        replay_requests = dict(requests)
        replay_requests["navigate"] = [replace(requests["navigate"][0], uri="/")]
        matches = compare_requests(
            requests, replay_requests, operations=planned.for_replay()
        )
        self.assertFalse(
            next(item["match"] for item in matches if item["flow"] == "navigate")
        )
