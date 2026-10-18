"""Protocol/coverage regressions run identically with normal and optimized Python."""

import unittest
from unittest.mock import Mock, patch

from browser_automation import workflow
from browser_automation.workflow import (
    parse_protocol_report,
    verify_protocols,
    get_form_navigation_complete,
    checked_page_results,
)


def page_results(*, fetch="h3", xhr="h3", websocket="h2", probe="owned page echo"):
    return {
        "fetch": {"fp": {"request_info": {"version": fetch}}},
        "xhr": {"fp": {"request_info": {"version": xhr}}},
        "websocket": {
            "greeting": {"initiator": "ws", "version": websocket},
            "probe": probe,
        },
    }


class PageResultTests(unittest.TestCase):
    def test_result_keeps_existing_response_objects_and_exact_probe(self):
        value = page_results(probe="per-page echo 🐢")
        self.assertIs(
            checked_page_results(value, dict(fetch="h3", xhr="h3", ws="h2")), value
        )
        self.assertEqual(value["websocket"]["probe"], "per-page echo 🐢")

    def test_missing_or_inconsistent_response_never_becomes_evidence(self):
        protocols = dict(fetch="h3", xhr="h3", ws="h2")
        for value in (
            None,
            {},
            {"fetch": None},
            page_results(fetch="h2"),
            page_results(xhr="h1"),
            page_results(websocket="h3"),
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                checked_page_results(value, protocols)
        for key in ("fetch", "xhr", "websocket"):
            value = page_results()
            value[key] = None
            with self.subTest(key=key), self.assertRaises(ValueError):
                checked_page_results(value, protocols)

    def test_probe_is_bounded_and_cannot_change_cli_line_framing(self):
        for probe in (None, "", "a\nb", "a\rb", "a\0b", "a" * 1025, "🐢" * 257):
            with self.subTest(probe=probe), self.assertRaisesRegex(
                ValueError, "invalid WebSocket probe"
            ):
                checked_page_results(
                    page_results(probe=probe), dict(fetch="h3", xhr="h3", ws="h2")
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

    def test_visible_protocol_cards_accept_layout_whitespace(self):
        lines = [
            "Navigation:\nHTTP/3",
            "  Fetch:\nHTTP/3  ",
            "XMLHttpRequest:\tHTTP/3",
            "WebSocket:\nHTTP/2",
        ]
        self.assertEqual(
            parse_protocol_report(lines),
            {"navigate": "h3", "fetch": "h3", "xhr": "h3", "ws": "h2"},
        )
        with self.assertRaisesRegex(ValueError, "ambiguous"):
            parse_protocol_report(lines + ["Navigation: HTTP/3"])
        with self.assertRaisesRegex(ValueError, "flow failed"):
            parse_protocol_report(lines[:-1] + ["WebSocket:\nunavailable"])

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

    def test_duplicate_flow_with_complete_coverage_is_rejected(self):
        lines = [
            f"{name}: h3"
            for name in ("Navigation", "Fetch", "XMLHttpRequest", "WebSocket")
        ]
        for duplicate in lines:
            with self.subTest(duplicate=duplicate), self.assertRaisesRegex(
                ValueError, "ambiguous"
            ):
                parse_protocol_report(lines + [duplicate])

    def test_each_http_flow_and_form_rejects_fallback(self):
        for failed in ["navigate", "fetch", "xhr", "form", "form_get"]:
            protocols = dict.fromkeys(
                ["navigate", "fetch", "xhr", "ws", "form", "form_get"], "h3"
            )
            protocols[failed] = "h2"
            with self.subTest(flow=failed), self.assertRaisesRegex(
                ValueError, "fallback"
            ):
                verify_protocols(protocols, "h3")

    def test_websocket_uses_its_actual_protocol_independently_of_http(self):
        for websocket in ("h1", "h2", "h3"):
            protocols = dict.fromkeys(
                ["navigate", "fetch", "xhr", "form", "form_get"], "h3"
            )
            protocols["ws"] = websocket
            original = dict(protocols)
            with self.subTest(websocket=websocket):
                verify_protocols(protocols, "h3")
                self.assertEqual(protocols, original)

    def test_unknown_websocket_protocol_is_not_an_accepted_fallback(self):
        for expected in (None, "h3"):
            with self.subTest(expected=expected), self.assertRaisesRegex(
                ValueError, "unknown observed"
            ):
                verify_protocols({"navigate": "h3", "ws": "unavailable"}, expected)

    def test_unknown_expected_protocol_is_not_an_auto_mode(self):
        with self.assertRaises(ValueError):
            verify_protocols({"navigate": "h1"}, "http3")


class CollectAllJourneyTests(unittest.TestCase):
    def run_journey(
        self,
        page_lines,
        *,
        post="h3",
        get="h3",
        events=None,
        results=None,
        observed=None,
    ):
        events = [] if events is None else events
        browser = Mock()
        browser.capabilities = {"browserName": "fixture", "browserVersion": "1"}
        browser.page_source = "owned fixture page"
        websocket = next(
            (
                line.partition(": ")[2]
                for line in page_lines
                if line.startswith("WebSocket: ")
            ),
            "h2",
        )
        browser.execute_async_script.return_value = (
            page_results(websocket=websocket) if results is None else results
        )
        if observed is not None:
            observed["browser"] = browser
        browser.get.side_effect = lambda url: setattr(browser, "current_url", url)

        def script(value):
            if value == "return navigator.userAgent":
                return "fixture user agent"
            if value == "return document.readyState":
                return "complete"
            return get if "?" in browser.current_url else post

        browser.execute_script.side_effect = script
        form, get_form = Mock(), Mock()
        form.is_displayed.return_value = get_form.is_displayed.return_value = True

        def submit(method):
            events.append(method)
            browser.current_url = "https://fixture/form" + (
                "?source=web&turtles=yes" if method == "GET" else ""
            )

        form.find_element.return_value.click.side_effect = lambda: submit("POST")
        get_form.find_element.return_value.click.side_effect = lambda: submit("GET")
        browser.find_element.side_effect = lambda _by, selector: (
            get_form if 'method="GET"' in selector else form
        )

        def report(*_args):
            events.append("report")
            return [Mock(text=line) for line in page_lines]

        browser.find_elements.side_effect = report

        class ImmediateWait:
            def __init__(self, driver, _timeout):
                self.driver = driver

            def until(self, condition):
                value = condition(self.driver)
                if not value:
                    raise RuntimeError("fixture navigation did not complete")
                return value

        original = workflow.parse_protocol_report

        def validate(lines):
            events.append("validate")
            return original(lines)

        with patch.object(workflow, "WebDriverWait", ImmediateWait), patch.object(
            workflow, "parse_protocol_report", side_effect=validate
        ):
            return workflow.run_capture_flow(
                browser, "https://fixture/", expected_protocol="h3"
            )

    def test_existing_page_promise_is_read_once_without_reissuing_requests(self):
        observed = {}
        value = page_results(probe="known cell echo")
        result = self.run_journey(
            ["Navigation: h3", "Fetch: h3", "XMLHttpRequest: h3", "WebSocket: h2"],
            results=value,
            observed=observed,
        )
        browser = observed["browser"]
        browser.execute_async_script.assert_called_once()
        script = browser.execute_async_script.call_args.args[0]
        self.assertIn("window.ramaFpFlow", script)
        for duplicate in (
            "main(",
            "fetch(",
            "connectWebSocket(",
            "makeRequestWithXHR(",
        ):
            self.assertNotIn(duplicate, script)
        browser.set_script_timeout.assert_called_once_with(30)
        self.assertIs(result.page_results, value)
        self.assertEqual(result.websocket_probe, "known cell echo")
        self.assertEqual(browser.get.call_count, 1)

    def test_invalid_page_result_does_not_skip_forms_or_become_success(self):
        events = []
        with self.assertRaisesRegex(ValueError, "page response unavailable"):
            self.run_journey(
                ["Navigation: h3", "Fetch: h3", "XMLHttpRequest: h3", "WebSocket: h2"],
                events=events,
                results={},
            )
        self.assertEqual(events, ["report", "POST", "GET", "validate"])

    def test_unavailable_websocket_does_not_hide_forms_or_become_success(self):
        events = []
        with self.assertRaisesRegex(ValueError, "flow failed") as failure:
            self.run_journey(
                [
                    "Navigation: h3",
                    "Fetch: h3",
                    "XMLHttpRequest: h3",
                    "WebSocket: unavailable (unsupported or connection failed)",
                ],
                events=events,
            )
        self.assertEqual(events, ["report", "POST", "GET", "validate"])
        self.assertIn("POST=h3, GET=h3", failure.exception.__notes__[0])
        self.assertIn("not successful coverage", failure.exception.__notes__[0])

    def test_http_fallback_still_fails_after_both_forms(self):
        events = []
        with self.assertRaisesRegex(ValueError, "fallback"):
            self.run_journey(
                ["Navigation: h3", "Fetch: h2", "XMLHttpRequest: h3", "WebSocket: h2"],
                events=events,
            )
        self.assertEqual(events, ["report", "POST", "GET", "validate"])

    def test_unknown_form_protocol_stays_failure_after_both_submissions(self):
        lines = ["Navigation: h3", "Fetch: h3", "XMLHttpRequest: h3", "WebSocket: h2"]
        for post, get in (("unknown", "h3"), ("h3", "unknown")):
            events = []
            with self.subTest(post=post, get=get), self.assertRaisesRegex(
                ValueError, "form navigation protocol unavailable"
            ) as failure:
                self.run_journey(lines, post=post, get=get, events=events)
            self.assertEqual(events, ["report", "POST", "GET", "validate"])
            self.assertIn("unavailable", failure.exception.__notes__[0])

    def test_success_retains_all_six_actual_protocols(self):
        for websocket, label in (("h1", "HTTP/1.1"), ("h2", "h2"), ("h3", "h3")):
            result = self.run_journey(
                [
                    "Navigation: h3",
                    "Fetch: h3",
                    "XMLHttpRequest: h3",
                    "WebSocket: " + label,
                ]
            )
            self.assertEqual(
                result.protocols,
                dict(
                    navigate="h3",
                    fetch="h3",
                    xhr="h3",
                    ws=websocket,
                    form="h3",
                    form_get="h3",
                ),
            )


if __name__ == "__main__":
    unittest.main()
