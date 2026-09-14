"""Adversarial fixtures: an empty or partially successful run must never pass."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

from check_results import InvalidResults, gate, load_report


class ResultGateTests(unittest.TestCase):
    def setUp(self):
        self.expected = dict(clients=["rama"], servers=["quic-go", "ngtcp2"],
                             cases=["handshake", "transfer", "retry"])
        self.report = {
            "clients": ["rama"], "servers": ["ngtcp2", "quic-go"],
            "tests": {abbr: {"name": name} for abbr, name in
                      zip(["H", "DC", "S"], self.expected["cases"])},
            "results": [[{"name": name, "abbr": abbr, "result": "succeeded"}
                         for abbr, name in zip(["H", "DC", "S"], self.expected["cases"])]
                        for _ in range(2)],
        }

    def test_complete_success_and_axis_order(self):
        self.assertEqual(gate(self.report, **self.expected), 6)

    def test_both_roles_client_major_order(self):
        self.report["clients"], self.report["servers"] = ["ngtcp2", "quic-go"], ["rama"]
        self.expected.update(clients=["quic-go", "ngtcp2"], servers=["rama"])
        self.assertEqual(gate(self.report, **self.expected), 6)
        self.report["results"][1][2]["result"] = "failed"
        with self.assertRaisesRegex(InvalidResults, "client=quic-go server=rama case=retry"):
            gate(self.report, **self.expected)

    def test_missing_unsupported_and_wrong_success_values(self):
        for value in [None, "unsupported", "failed", "success", "SUCCEEDED", True, 0, {}, []]:
            with self.subTest(value=value):
                report = copy.deepcopy(self.report)
                report["results"][1][0]["result"] = value
                with self.assertRaises(InvalidResults):
                    gate(report, **self.expected)

    def test_malformed_and_incomplete_fixtures(self):
        mutations = [
            lambda r: r.clear(),
            lambda r: r.update(results=[]),
            lambda r: r["results"].pop(),
            lambda r: r["results"].append(r["results"][0]),
            lambda r: r["results"][0].pop(),
            lambda r: r["results"][0].append(r["results"][0][0]),
            lambda r: r["results"][0][0].pop("result"),
            lambda r: r["results"][0][0].update(name="unknown"),
            lambda r: r["results"][0][0].update(abbr="DC"),
            lambda r: r["results"][0][0].update(name=[]),
            lambda r: r.update(servers=["ngtcp2", "ngtcp2"]),
            lambda r: r.update(servers=["rama", "quic-go"]),
            lambda r: r.update(clients=[]),
            lambda r: r["tests"].pop("S"),
            lambda r: r["tests"].update(OTHER={"name": "retry"}),
        ]
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                report = copy.deepcopy(self.report)
                mutate(report)
                with self.assertRaises(InvalidResults):
                    gate(report, **self.expected)

    def test_empty_or_duplicate_expected_scope(self):
        for axis in self.expected:
            for value in ([], [""], ["rama", "rama"]):
                with self.subTest(axis=axis, value=value):
                    expected = dict(self.expected, **{axis: value})
                    with self.assertRaises(InvalidResults):
                        gate(self.report, **expected)

    def test_reject_duplicate_json_keys(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "report.json"
            path.write_text('{"results": [], "results": []}')
            with self.assertRaises(InvalidResults):
                load_report(path)
            path.write_text('{"results":')
            with self.assertRaises(json.JSONDecodeError):
                load_report(path)
            path.unlink()
            with self.assertRaises(OSError):
                load_report(path)


if __name__ == "__main__":
    unittest.main()
