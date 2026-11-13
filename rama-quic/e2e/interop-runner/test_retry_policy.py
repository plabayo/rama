"""A second run is for one isolated cell, never for a wider or repeated failure."""
import unittest

from check_results import InvalidResults, gate
from retry_policy import decide, failed_cells, previous_first_failures

CELL = ("quic-go", "rama", "handshakeloss")
OTHER = ("ngtcp2", "rama", "handshakeloss")
NO_HISTORY = (None, set())


def decided(failures, previous=NO_HISTORY, group="loss"):
    return decide(group=group, retried_groups=["loss"], failures=failures, previous=previous)


class RetryPolicyTests(unittest.TestCase):
    def test_one_failed_cell_in_one_role_is_run_again(self):
        self.assertEqual(decided({"server": [CELL]}), ("server", CELL, None))

    def test_anything_wider_than_one_cell_is_refused(self):
        for failures in ({"server": [CELL, OTHER]}, {"server": [CELL], "client": [OTHER]},
                         {"server": [CELL], "client": []}, {"server": [CELL], "client": None},
                         {"server": []}, {"server": None}):
            with self.subTest(failures=failures):
                role, cell, refusal = decided(failures)
                self.assertEqual((role, cell), (None, None))
                self.assertIn("exactly one cell", refusal)

    def test_a_group_that_is_not_retried_is_refused(self):
        for group in ("core", "paths", None):
            with self.subTest(group=group):
                self.assertIn("only the loss", decided({"server": [CELL]}, group=group)[2])

    def test_nothing_is_retried_without_the_previous_run_record(self):
        self.assertIn("no record", decided({"server": [CELL]}, previous=None)[2])

    def test_a_cell_that_failed_first_in_the_previous_run_is_refused_and_says_so(self):
        refusal = decided({"server": [CELL]}, previous=("https://example.test/run/7", {CELL}))[2]
        self.assertIn("same cell also failed first in the previous workflow run", refusal)
        self.assertIn("https://example.test/run/7", refusal)
        self.assertEqual(decided({"server": [CELL]}, previous=("run", {OTHER}))[1], CELL)

    def test_previous_run_record_is_read_strictly(self):
        cell = dict(zip(("client", "server", "case"), CELL))
        self.assertEqual(previous_first_failures({"run": "url", "first_failures": [cell]}),
                         ("url", {CELL}))
        self.assertEqual(previous_first_failures({"run": None, "first_failures": []}), NO_HISTORY)
        for record in ([], {"run": None}, {"run": 1, "first_failures": []},
                       {"run": None, "first_failures": [{"client": "quic-go"}]},
                       {"run": None, "first_failures": [{**cell, "case": ""}]},
                       {"run": None, "first_failures": [], "extra": 1}):
            with self.subTest(record=record), self.assertRaises(InvalidResults):
                previous_first_failures(record)


class ExcusedCellTests(unittest.TestCase):
    def setUp(self):
        self.expected = dict(clients=["quic-go", "ngtcp2"], servers=["rama"], cases=["handshakeloss"])
        self.report = {
            "clients": ["quic-go", "ngtcp2"], "servers": ["rama"],
            "tests": {"L1": {"name": "handshakeloss"}},
            "results": [[{"name": "handshakeloss", "abbr": "L1", "result": "failed"}],
                        [{"name": "handshakeloss", "abbr": "L1", "result": "succeeded"}]],
        }

    def test_failed_cells_are_read_from_the_report(self):
        self.assertEqual(failed_cells(self.report), [CELL])
        with self.assertRaises(InvalidResults):
            failed_cells({"clients": ["quic-go"], "servers": ["rama"], "results": []})

    def test_only_the_excused_cell_may_have_failed(self):
        with self.assertRaises(InvalidResults):
            gate(self.report, **self.expected)
        self.assertEqual(gate(self.report, **self.expected, excused={CELL}), 2)
        self.report["results"][1][0]["result"] = "failed"
        with self.assertRaisesRegex(InvalidResults, "client=ngtcp2 server=rama"):
            gate(self.report, **self.expected, excused={CELL})

    def test_an_excused_cell_must_have_failed_not_gone_unsupported(self):
        self.report["results"][0][0]["result"] = "unsupported"
        with self.assertRaises(InvalidResults):
            gate(self.report, **self.expected, excused={CELL})


if __name__ == "__main__":
    unittest.main()
