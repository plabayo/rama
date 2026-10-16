"""Protocol/coverage regressions run identically with normal and optimized Python."""

import unittest
from unittest.mock import Mock
from browser_automation.workflow import (
    parse_protocol_report,
    verify_protocols,
    get_form_navigation_complete,
)


class FlowProtocolTests(unittest.TestCase):
    def test_get_form_wait_requires_new_query_and_loaded_document(self):
        browser = Mock()
        browser.execute_script.return_value = "complete"
        for url in (
            "https://fixture/form",
            "https://fixture/form?source=web",
            "https://fixture/report?source=web&turtles=yes",
        ):
            browser.current_url = url
            self.assertFalse(get_form_navigation_complete(browser))
        browser.current_url = "https://fixture/form?source=web&turtles=yes"
        browser.execute_script.return_value = "loading"
        self.assertFalse(get_form_navigation_complete(browser))
        browser.execute_script.return_value = "complete"
        self.assertTrue(get_form_navigation_complete(browser))

    def test_all_four_page_flows_have_an_observed_protocol(self):
        for wire, protocol in [
            ("HTTP/1.1", "h1"),
            ("HTTP/2.0", "h2"),
            ("HTTP/3.0", "h3"),
        ]:
            report = parse_protocol_report(
                [
                    f"{name}: {wire}"
                    for name in ["Navigation", "Fetch", "XMLHttpRequest", "WebSocket"]
                ]
            )
            self.assertEqual(
                report, dict.fromkeys(["navigate", "fetch", "xhr", "ws"], protocol)
            )
            verify_protocols(dict(report, form=protocol), protocol)

    def test_page_completion_cannot_hide_a_failed_websocket(self):
        with self.assertRaisesRegex(ValueError, "flow failed"):
            parse_protocol_report(
                [
                    "Navigation: h3",
                    "Fetch: HTTP/3.0",
                    "XMLHttpRequest: HTTP/3.0",
                    "WebSocket: unavailable (failed)",
                ]
            )

    def test_missing_or_duplicate_flow_fails(self):
        for lines in [[], ["Navigation: h2"], ["Navigation: h2", "Navigation: h2"]]:
            with self.subTest(lines=lines), self.assertRaises(ValueError):
                parse_protocol_report(lines)

    def test_each_flow_including_websocket_and_form_rejects_fallback(self):
        for failed in ["navigate", "fetch", "xhr", "ws", "form", "form_get"]:
            protocols = dict.fromkeys(
                ["navigate", "fetch", "xhr", "ws", "form", "form_get"], "h3"
            )
            protocols[failed] = "h2"
            with self.subTest(flow=failed), self.assertRaisesRegex(
                ValueError, "fallback"
            ):
                verify_protocols(protocols, "h3")

    def test_unknown_expected_protocol_is_not_an_auto_mode(self):
        with self.assertRaises(ValueError):
            verify_protocols({"navigate": "h1"}, "http3")


if __name__ == "__main__":
    unittest.main()
