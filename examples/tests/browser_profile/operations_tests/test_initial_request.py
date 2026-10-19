"""Unclassified first requests need an exact retained recipe and current input."""

from copy import deepcopy
from dataclasses import replace
import unittest

from flows import ReplayTarget
from operations_tests.fixtures import CONTEXT, JOINTS, bound, request_capture
from preliminary import source_preliminary
from qpack_fields_wire import Section
from qpack_bootstrap_wire import bootstrap_request


def source_asset():
    rows, ledger, inspected, sections = bound()
    # All declared HTTP3 operations follow the native first asset stream.
    rows = [
        replace(row, stream=row.stream + 4) if row.protocol == "h3" else row
        for row in rows
    ]
    ledger = replace(
        ledger,
        operations=tuple(
            replace(op, stream=op.stream + 4) if op.protocol == "h3" else op
            for op in ledger.operations
        ),
    )
    sections = {
        (p, c, s + 4): replace(section, stream=s + 4)
        for (p, c, s), section in sections.items()
    }
    original = next(
        row
        for row in rows
        if row.protocol == "h3" and row.headers and not row.from_server
    )
    head = replace(
        original,
        packet=5,
        stream=0,
        headers=(
            (":method", "GET"),
            (":path", "/assets/first.css?owned=1"),
            (":authority", "capture.test:18443"),
            (":scheme", "https"),
            ("user-agent", "fixture"),
            ("sec-fetch-mode", "no-cors"),
            ("sec-fetch-dest", "style"),
            ("sec-fetch-site", "same-origin"),
        ),
    )
    rows.append(head)
    captured, metadata = request_capture(head)
    identifier = [99] * 32
    profile = inspected["profiles"][0]
    profile["scopes"].append(
        {
            "context": {"connection": dict(CONTEXT)},
            "flow": {
                "Http": {
                    "version": "HTTP/3.0",
                    "method": "GET",
                    "initiator": None,
                    "fetch": {
                        "mode": "no-cors",
                        "destination": "style",
                        "site": "same-origin",
                    },
                }
            },
            "variants": [{"id": identifier, "capture": captured}],
        }
    )
    profile["scopes"][1]["variants"][0]["capture"]["slots"].append(
        {
            "kind": "Http3Bootstrap",
            "capture": {
                "request": identifier,
                "method": "GET",
                "fields": len(head.headers),
                "bindings": {"stream_id": 0, "complete": True, "insertions": []},
            },
        }
    )
    sections[5, 7, 0] = Section(5, 7, 0, 0, False, 0, metadata)
    return rows, ledger, inspected, sections, head


class InitialRequestPlanningTests(unittest.TestCase):
    def test_actual_first_asset_keeps_none_initiator_and_exact_recipe(self):
        rows, ledger, archive, sections, head = source_asset()
        request = source_preliminary(
            archive, rows, sections, ledger, JOINTS["h3"], connection=7
        )
        value = request.input(ReplayTarget("h3", "https://[::1]:3443"))
        self.assertEqual(request.source_key, ("h3", 7, 0))
        self.assertIsNone(request.flow)
        self.assertEqual(request.request_pin, "63" * 32)
        self.assertEqual(value["method"], "GET")
        self.assertEqual(value["uri"], "https://[::1]:3443/assets/first.css?owned=1")
        self.assertNotIn("emulate_initiator", value)
        self.assertNotIn("body_base64", value)
        self.assertIn(("sec-fetch-mode", "no-cors"), value["headers"])
        self.assertIn(("sec-fetch-dest", "style"), value["headers"])
        self.assertIsNone(ledger.name(head))
        self.assertEqual(
            set(ledger.measured_protocols),
            {"navigate", "fetch", "xhr", "ws", "form", "form_get"},
        )

    def test_missing_reference_or_missing_recipe_never_falls_back_to_declared_request(
        self,
    ):
        for change in ["bootstrap", "recipe", "reference"]:
            rows, ledger, archive, sections, _head = source_asset()
            scopes = archive["profiles"][0]["scopes"]
            slots = scopes[1]["variants"][0]["capture"]["slots"]
            if change == "bootstrap":
                slots[:] = [slot for slot in slots if slot["kind"] != "Http3Bootstrap"]
            elif change == "recipe":
                scopes.pop()
            else:
                slots[-1]["capture"]["request"] = [88] * 32
            with self.subTest(change=change), self.assertRaises(ValueError):
                source_preliminary(
                    archive, rows, sections, ledger, JOINTS["h3"], connection=7
                )

    def test_first_native_stream_context_and_raw_metadata_remain_exact(self):
        for change in ["stream", "initiator", "fetch", "metadata", "raw_metadata"]:
            rows, ledger, archive, sections, head = source_asset()
            if change == "stream":
                archive["profiles"][0]["scopes"][1]["variants"][0]["capture"]["slots"][
                    -1
                ]["capture"]["bindings"]["stream_id"] = 4
            elif change == "initiator":
                archive["profiles"][0]["scopes"][-1]["flow"]["Http"][
                    "initiator"
                ] = "navigate"
            elif change == "fetch":
                archive["profiles"][0]["scopes"][-1]["flow"]["Http"]["fetch"][
                    "destination"
                ] = "script"
            elif change == "raw_metadata":
                section = sections[head.packet, head.connection, head.stream]
                sections[head.packet, head.connection, head.stream] = replace(
                    section,
                    fields=(
                        replace(section.fields[0], never_index=True),
                        *section.fields[1:],
                    ),
                )
            else:
                sections.pop((head.packet, head.connection, head.stream))
            with self.subTest(change=change), self.assertRaises(ValueError):
                source_preliminary(
                    archive, rows, sections, ledger, JOINTS["h3"], connection=7
                )

    def test_unclassified_websocket_cannot_be_an_http_preliminary(self):
        rows, ledger, archive, sections, head = source_asset()
        changed = replace(head, headers=head.headers + ((":protocol", "websocket"),))
        rows[rows.index(head)] = changed
        captured, metadata = request_capture(changed)
        archive["profiles"][0]["scopes"][-1]["variants"][0]["capture"] = captured
        archive["profiles"][0]["scopes"][1]["variants"][0]["capture"]["slots"][-1][
            "capture"
        ]["fields"] += 1
        sections[5, 7, 0] = Section(5, 7, 0, 0, False, 0, metadata)
        with self.assertRaisesRegex(ValueError, "WebSocket"):
            source_preliminary(
                archive, rows, sections, ledger, JOINTS["h3"], connection=7
            )
