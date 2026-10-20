"""Exercise all HTTP contracts from actual independently decoded relay traffic."""

from dataclasses import replace
import json
from pathlib import Path
import unittest

from comparison import compare_legs, http1_exchanges, multiplexed_exchanges
from http_contract import expected_exchanges, verify_exchange

FIXTURES = Path(__file__).parent / "tests/fixtures"
CAPTURES = json.loads((FIXTURES / "http-contract-captures.json").read_text())
BODY = b"external-relay-body"


def exchanges(label, side):
    capture = CAPTURES[label]
    data = (FIXTURES / (label + "-" + side + ".pdml")).read_bytes()
    port = capture["ports"][side]
    if capture["protocol"] == "h1":
        parsed = http1_exchanges(data, port)
    else:
        parsed = multiplexed_exchanges(data, capture["protocol"], port)
    return {exchange.path: exchange for exchange in parsed}


class HttpContractTests(unittest.TestCase):
    def test_all_protocol_versions_recount_all_nine_real_contracts(self):
        for label, capture in CAPTURES.items():
            with self.subTest(label=label):
                report = compare_legs(
                    (FIXTURES / (label + "-ingress.pdml")).read_bytes(),
                    (FIXTURES / (label + "-egress.pdml")).read_bytes(),
                    capture["protocol"],
                    capture["ports"]["ingress"],
                    capture["ports"]["egress"],
                    BODY,
                    quic_version=capture["quic_version"],
                )
                expected = json.loads(
                    (FIXTURES / (label + "-expected.json")).read_text()
                )
                self.assertEqual(json.loads(json.dumps(report)), expected)
                self.assertEqual(report["exchanges_checked"], 9)
                self.assertFalse(report["fingerprint_match"])

    def test_head_and_bodyless_statuses_reject_an_actual_response_body(self):
        expected = expected_exchanges(BODY)
        for label, capture in CAPTURES.items():
            for side in ("ingress", "egress"):
                actual = exchanges(label, side)
                for path in ("/head", "/no-content", "/not-modified"):
                    altered = replace(actual[path], response_body=b"unexpected payload")
                    with self.subTest(label=label, side=side, path=path):
                        with self.assertRaisesRegex(ValueError, "body differs"):
                            verify_exchange(
                                altered, expected[path], capture["protocol"]
                            )

    def test_bodyless_status_is_part_of_the_contract(self):
        expected = expected_exchanges(BODY)
        for label, capture in CAPTURES.items():
            actual = exchanges(label, "egress")
            for path in ("/no-content", "/not-modified"):
                with self.subTest(label=label, path=path):
                    with self.assertRaisesRegex(ValueError, "response status differs"):
                        verify_exchange(
                            replace(actual[path], status=200),
                            expected[path],
                            capture["protocol"],
                        )

    def test_fixed_lengths_and_empty_streams_cannot_be_conflated(self):
        expected = expected_exchanges(BODY)
        for label, capture in CAPTURES.items():
            actual = exchanges(label, "egress")
            for path, headers_name in (
                ("/fixed", "request_headers"),
                ("/fixed", "response_headers"),
                ("/head", "response_headers"),
                ("/empty", "request_headers"),
                ("/empty", "response_headers"),
            ):
                headers = tuple(
                    pair
                    for pair in getattr(actual[path], headers_name)
                    if pair[0].lower() != "content-length"
                )
                altered = replace(actual[path], **{headers_name: headers})
                with self.subTest(label=label, path=path, section=headers_name):
                    with self.assertRaisesRegex(ValueError, "Content-Length contract"):
                        verify_exchange(altered, expected[path], capture["protocol"])
            for path in ("/POST", "/empty-stream", "/stream"):
                headers = actual[path].response_headers + (("content-length", "0"),)
                with self.subTest(label=label, path=path):
                    with self.assertRaisesRegex(ValueError, "Content-Length contract"):
                        verify_exchange(
                            replace(actual[path], response_headers=headers),
                            expected[path],
                            capture["protocol"],
                        )

    def test_streaming_h1_and_multiplexed_transfer_codings_are_distinct(self):
        expected = expected_exchanges(BODY)["/POST"]
        for label, capture in CAPTURES.items():
            actual = exchanges(label, "egress")["/POST"]
            for section in ("request_headers", "response_headers"):
                headers = tuple(
                    pair
                    for pair in getattr(actual, section)
                    if pair[0].lower() != "transfer-encoding"
                )
                if capture["protocol"] != "h1":
                    headers += (("transfer-encoding", "chunked"),)
                with self.subTest(label=label, section=section):
                    with self.assertRaisesRegex(
                        ValueError, "transfer framing contract"
                    ):
                        verify_exchange(
                            replace(actual, **{section: headers}),
                            expected,
                            capture["protocol"],
                        )

    def test_empty_stream_still_requires_its_request_trailer(self):
        expected = expected_exchanges(BODY)["/empty-stream"]
        for label, capture in CAPTURES.items():
            for side in ("ingress", "egress"):
                actual = exchanges(label, side)["/empty-stream"]
                with self.subTest(label=label, side=side):
                    with self.assertRaisesRegex(ValueError, "request trailer differs"):
                        verify_exchange(
                            replace(actual, request_trailers=()),
                            expected,
                            capture["protocol"],
                        )

    def test_exotic_h1_reference_and_egress_are_both_required(self):
        expected = expected_exchanges(BODY)
        for side in ("ingress", "egress"):
            actual = exchanges("h1", side)["/fixed"]
            for section in ("request_headers", "response_headers"):
                for mutation in ("canonicalize", "drop-repeat"):
                    headers = []
                    for name, value in getattr(actual, section):
                        if name.lower().startswith("x-exotic-"):
                            if mutation == "drop-repeat" and value == "second":
                                continue
                            if mutation == "canonicalize":
                                name = name.title()
                        headers.append((name, value))
                    altered = replace(actual, **{section: tuple(headers)})
                    with self.subTest(side=side, section=section, mutation=mutation):
                        with self.assertRaisesRegex(ValueError, "exotic field"):
                            verify_exchange(altered, expected["/fixed"], "h1")
