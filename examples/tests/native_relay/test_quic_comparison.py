"""Compare real first-flight/settings traces and reject false identity/version proof."""

import json
from pathlib import Path
import sys
import unittest

sys.path.append(str(Path(__file__).parents[1] / "browser_profile"))
from quic_comparison import compare_quic_legs, observe, require_no_retry

FIXTURES = Path(__file__).parent / "tests/fixtures"


def inputs(version):
    ports = json.loads((FIXTURES / "quic-metadata.json").read_text())[str(version)]
    return (
        (FIXTURES / f"quic-v{version}-ingress.pdml").read_bytes(),
        (FIXTURES / f"quic-v{version}-egress.pdml").read_bytes(),
        ports["ingress"],
        ports["egress"],
    )


class QuicComparisonTests(unittest.TestCase):
    def test_both_wire_versions_report_real_native_differences(self):
        for version in (1, 2):
            with self.subTest(version=version):
                report = compare_quic_legs(*inputs(version), version)
                self.assertTrue(report["fresh_connection_ids"])
                self.assertFalse(report["fingerprint_match"])
                self.assertFalse(report["matches"]["parameters"])
                self.assertFalse(report["matches"]["first_flight"])
                self.assertFalse(report["matches"]["settings"])

    def test_a_v1_capture_cannot_be_called_v2(self):
        with self.assertRaisesRegex(ValueError, "QUIC version differs"):
            compare_quic_legs(*inputs(1), 2)

    def test_reusing_the_ingress_capture_cannot_prove_fresh_egress(self):
        ingress, _, port, _ = inputs(1)
        with self.assertRaisesRegex(ValueError, "reused ingress QUIC identity"):
            compare_quic_legs(ingress, ingress, port, port, 1)

    def test_connection_ids_are_bound_by_length_and_checked_separately(self):
        ingress, egress, port, other = inputs(1)
        before, ids = observe(ingress, port)
        after, other_ids = observe(egress, other)
        self.assertTrue(ids and other_ids and ids.isdisjoint(other_ids))
        for observation in (before, after):
            connection_values = [
                field["value"]
                for field in observation["parameters"]
                if "ConnectionLength" in field["value"]
            ]
            self.assertTrue(connection_values)
            self.assertTrue(
                all(value["ConnectionLength"] > 0 for value in connection_values)
            )


class RetryScopeTests(unittest.TestCase):
    def test_legitimate_retry_is_explicitly_outside_initial_only_scope(self):
        data = (FIXTURES / "quic-retry-v2-ingress.pdml").read_bytes()
        port = json.loads((FIXTURES / "quic-metadata.json").read_text())[
            "retry_v2_ingress"
        ]
        for check in (require_no_retry, observe):
            with self.subTest(check=check.__name__):
                with self.assertRaisesRegex(ValueError, "excludes QUIC Retry"):
                    check(data, port)
