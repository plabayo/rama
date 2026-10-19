"""Client Hints retries need advertisement, native response and driver evidence."""

from dataclasses import replace
from html import escape
import unittest

from flows import FLOWS, FETCH_CONTEXT_FIELDS
from operations import HINT_DISCOVERY, OperationLedger
from operations_tests.fixtures import request_capture
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


def pinned(rows, ledger):
    joint = "11" * 32
    ledger = ledger.with_joints({"h2": {"connection_joints": {0: joint}}})
    scopes = [
        {
            "context": {"connection": {}},
            "variants": [
                {
                    "id": list(bytes.fromhex(joint)),
                    "capture": {"level": "Connection", "slots": []},
                }
            ],
        }
    ]
    for index, operation in enumerate(ledger.operations):
        block = next(row for row in rows if ledger.name(row) == operation.name)
        fields = dict(block.headers)
        capture, _metadata = request_capture(block)
        scopes.append(
            dict(
                context={"connection": {}},
                flow={
                    "Http": dict(
                        version="HTTP/2.0",
                        method=operation.method,
                        initiator=(
                            "form" if operation.flow == "form_get" else operation.flow
                        ),
                        fetch={
                            key: fields[name]
                            for key, name in FETCH_CONTEXT_FIELDS
                            if name in fields
                        },
                    )
                },
                variants=[dict(id=[index + 40] * 32, capture=capture)],
            )
        )
    return ledger.with_requests(
        {"profiles": [{"key": {"user_agent": "ordinary-browser"}, "scopes": scopes}]},
        rows,
        {},
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

    def test_replay_duplicate_uris_need_their_exact_coupled_request_fields(self):
        rows, page, complete = hint_fixture()
        ledger = pinned(rows, planned(rows, page, complete))
        replay = ledger.for_replay()
        changed = [
            replace(
                row,
                packet=row.packet + 100,
                connection=row.connection + 100,
                stream=row.stream + 100,
            )
            for row in rows
        ]
        replay.validate_heads(changed)
        self.assertEqual(replay.name(changed[0]), HINT_DISCOVERY)
        self.assertEqual(replay.name(changed[2]), "navigate")
        unpinned = replace(
            ledger,
            operations=tuple(replace(op, capture=None) for op in ledger.operations),
        ).for_replay()
        with self.assertRaisesRegex(ValueError, "ambiguous"):
            unpinned.name(changed[0])
        self.assertNotEqual(ledger.operations[0].request, ledger.operations[1].request)

    def test_client_hints_retry_and_h3_discovery_remain_distinct_operations(self):
        rows, page, complete = hint_fixture()
        original = rows[:4]
        query = replace(
            rows[2],
            protocol="h3",
            connection=2,
            stream=0,
            packet=10,
            headers=tuple(
                (name, "/report?h3_probe=1" if name == ":path" else value)
                for name, value in rows[2].headers
            ),
        )
        others = [
            replace(
                row,
                protocol=(
                    "h2"
                    if dict(row.headers).get(":path") == "/api/ws" or row.stream == 11
                    else "h3"
                ),
                packet=row.packet + 50,
                connection=2 if row.stream != 11 else 0,
            )
            for row in rows[4:]
        ]
        page = dict(
            page,
            report_url=ORIGIN + "/report?h3_probe=1",
            report_html=header_page(query.headers),
            protocols={flow: "h2" if flow == "ws" else "h3" for flow in FLOWS},
        )
        ledger = planned(original + [query] + others, page, complete)
        self.assertEqual(
            set(ledger.names), set(FLOWS) | {HINT_DISCOVERY, "discover_h3"}
        )
        self.assertEqual(
            [(op.name, op.protocol, op.packet) for op in ledger.operations[:3]],
            [
                (HINT_DISCOVERY, "h2", 1),
                ("discover_h3", "h2", 3),
                ("navigate", "h3", 10),
            ],
        )

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
