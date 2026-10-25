"""Client Hints retries need advertisement, native response and driver evidence."""

from dataclasses import replace
from html import escape
import unittest

from flows import FLOWS
from operations import HINT_DISCOVERY, OperationLedger
from page_info import request_headers
from operations_tests.admission_fixtures import ORIGIN, admission_fixture


def header_page(headers):
    return (
        "<h2>🚗 Http Headers</h2><table>"
        + "".join(
            "<tr><td>" + escape(name) + "</td><td>" + escape(value) + "</td></tr>"
            for name, value in headers
            if not name.startswith(":")
        )
        + "</table>"
    )


def hint_fixture():
    _raw, rows, page = admission_fixture()
    rows = [replace(row, packet=row.packet + 20) for row in rows]
    first = next(
        row
        for row in rows
        if row.headers
        and not row.from_server
        and dict(row.headers).get(":path") == "/report"
    )
    rows = [row for row in rows if row.stream != first.stream]
    original = first.headers + (
        ("sec-fetch-mode", "navigate"),
        ("sec-fetch-dest", "document"),
    )
    first = replace(first, packet=1, headers=original)
    final = replace(
        first, packet=3, stream=21, headers=original + (("sec-ch-ua-arch", '"arm"'),)
    )
    advertisement = (
        (":status", "200"),
        ("Accept-CH", "sec-ch-ua-arch"),
        ("Critical-CH", "sec-ch-ua-arch"),
    )
    responses = [
        replace(
            head,
            from_server=True,
            packet=head.packet + 1,
            headers=advertisement,
            data=header_page(head.headers).encode(),
        )
        for head in (first, final)
    ]
    rows = [first, responses[0], final, responses[1]] + rows
    # The shared admission fixture omits WS authority, which the operation ledger requires.
    rows = [
        (
            replace(
                row,
                headers=row.headers + ((":authority", "h3.fp.ramaproxy.org:32543"),),
            )
            if row.headers
            and not row.from_server
            and dict(row.headers).get(":path") == "/api/ws"
            else row
        )
        for row in rows
    ]
    page["report_url"] = ORIGIN + "/report"
    page["report_html"] = header_page(final.headers)
    complete = {
        (row.protocol, row.connection, row.stream) for row in rows if row.from_server
    }
    return rows, page, complete


def planned(rows, page, complete):
    return OperationLedger.from_driver(
        rows,
        page["protocols"],
        ORIGIN,
        page["report_url"],
        report_html=page["report_html"],
        completed=complete,
    )


class ClientHintNavigationTests(unittest.TestCase):
    def test_final_native_headers_select_the_retry_and_preserve_both_operations(self):
        rows, page, complete = hint_fixture()
        ledger = planned(rows, page, complete)
        self.assertEqual(set(ledger.names), set(FLOWS) | {HINT_DISCOVERY})
        self.assertEqual(ledger.operations[0].packet, 1)
        self.assertEqual(
            next(op.packet for op in ledger.operations if op.name == "navigate"), 3
        )
        self.assertEqual(ledger.measured_protocols, page["protocols"])
        self.assertEqual(ledger.name(rows[0]), HINT_DISCOVERY)
        self.assertEqual(ledger.name(rows[2]), "navigate")

    def test_missing_changed_or_late_advertisement_cannot_explain_a_retry(self):
        for mutation in (
            "accept",
            "critical",
            "unadvertised",
            "late",
            "ordinary",
            "response-echo",
            "no-new-critical",
        ):
            rows, page, complete = hint_fixture()
            if mutation in ("accept", "critical"):
                rows[1] = replace(
                    rows[1],
                    headers=tuple(
                        pair
                        for pair in rows[1].headers
                        if pair[0].lower() != mutation + "-ch"
                    ),
                )
            elif mutation == "late":
                rows[1] = replace(rows[1], packet=9)
            elif mutation == "response-echo":
                rows[1] = replace(rows[1], data=header_page(rows[2].headers).encode())
            elif mutation == "no-new-critical":
                rows[0] = replace(
                    rows[0], headers=rows[0].headers + (("sec-ch-ua-arch", '"x86"'),)
                )
                rows[1] = replace(rows[1], data=header_page(rows[0].headers).encode())
            else:
                name = "sec-ch-other" if mutation == "unadvertised" else "x-ordinary"
                rows[2] = replace(
                    rows[2], headers=rows[2].headers + ((name, "changed"),)
                )
                rows[3] = replace(rows[3], data=header_page(rows[2].headers).encode())
                page["report_html"] = header_page(rows[2].headers)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                planned(rows, page, complete)

    def test_missing_completion_wrong_driver_or_third_navigation_fail_closed(self):
        rows, page, complete = hint_fixture()
        for key in (("h2", 0, 1), ("h2", 0, 21)):
            with self.subTest(key=key), self.assertRaisesRegex(
                ValueError, "completion"
            ):
                planned(rows, page, complete - {key})
        for document in (None, header_page(rows[0].headers), page["report_html"] * 2):
            changed = dict(page, report_html=document)
            with self.subTest(document=document), self.assertRaises(ValueError):
                planned(rows, changed, complete)
        with self.assertRaises(ValueError):
            planned(rows + [replace(rows[2], packet=9, stream=25)], page, complete)

    def test_native_header_table_requires_one_bounded_unambiguous_table(self):
        rows, page, _complete = hint_fixture()
        self.assertEqual(
            request_headers(page["report_html"]),
            tuple(pair for pair in rows[2].headers if not pair[0].startswith(":")),
        )
        for html in (
            page["report_html"] * 2,
            page["report_html"].replace("🚗 Http Headers", "Other"),
            page["report_html"].replace("user-agent", "bad name"),
        ):
            with self.subTest(html=html), self.assertRaises(ValueError):
                request_headers(html)
