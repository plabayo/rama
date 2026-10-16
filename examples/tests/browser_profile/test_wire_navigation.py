import csv
import io
import unittest

from wire import compare_navigation as compare, decode_requests


def wire(headers, host="127.0.0.1:8000", version="HTTP/1.1"):
    text = io.StringIO()
    writer = csv.writer(text, delimiter="\t")
    writer.writerow(
        [
            "http.request.method",
            "http.request.uri",
            "http.request.version",
            "http.host",
            "http.request.line",
        ]
    )
    writer.writerow(["GET", "/report", version, host, "\x1f".join(headers)])
    return text.getvalue()


class WireTests(unittest.TestCase):
    def setUp(self):
        self.headers = [
            "Host: 127.0.0.1:8000",
            "User-Agent: test",
            "Accept: */*",
            "Connection: keep-alive",
        ]
        self.reference = decode_requests(wire(self.headers), 8000)

    def test_only_destination_value_is_normalized(self):
        headers = self.headers.copy()
        headers[0] = "Host: 127.0.0.1:9000"
        self.assertEqual(
            compare(
                self.reference,
                decode_requests(wire(headers, host="127.0.0.1:9000"), 9000),
            ),
            4,
        )
        for host, version in [
            ("other.test:8000", "HTTP/1.1"),
            ("127.0.0.1:8000", "HTTP/2"),
        ]:
            with self.subTest(host=host, version=version), self.assertRaises(
                ValueError
            ):
                decode_requests(wire(self.headers, host=host, version=version), 8000)

    def test_changed_case_value_order_and_cardinality_fail(self):
        mutations = [
            list(reversed(self.reference[0])),
            [line.lower() for line in self.reference[0]],
            self.reference[0][:-1],
            self.reference[0][:-1] + ["Connection: close"],
        ]
        for headers in mutations:
            with self.subTest(headers=headers), self.assertRaises(ValueError):
                compare(self.reference, [headers])
        for replay in [[], self.reference * 2]:
            with self.assertRaises(ValueError):
                compare(self.reference, replay)

    def test_tuple_membership_cannot_mix_requests(self):
        other = self.reference[0].copy()
        other[1] = "User-Agent: second"
        other[2] = "Accept: text/plain"
        mixed = self.reference[0].copy()
        mixed[1] = other[1]
        with self.assertRaises(ValueError):
            compare(self.reference + [other], [mixed])

    def test_missing_wire_evidence_fails(self):
        for text in [
            "",
            wire(self.headers[:2]),
            wire(self.headers).replace("GET", "POST"),
        ]:
            with self.assertRaises(ValueError):
                decode_requests(text, 8000)


if __name__ == "__main__":
    unittest.main()
