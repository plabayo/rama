"""Protocol/coverage regressions run identically with normal and optimized Python."""

import json
import unittest
from unittest.mock import Mock, patch

from selenium.common.exceptions import StaleElementReferenceException, TimeoutException

from browser_automation import workflow
from browser_automation.workflow import (
    parse_protocol_report,
    verify_protocols,
    get_form_navigation_complete,
    submit_form,
    checked_page_results,
    websocket_over_h2_unsupported,
    websocket_over_h3_unsupported,
    UnsupportedFlow,
)

SAFARI_18 = (
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15"
    " (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1"
)
SAFARI_26 = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15"
    " (KHTML, like Gecko) Version/26.0 Safari/605.1.15"
)
CHROME = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
    " (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"
)
FIREFOX = (
    "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0"
)
ANDROID_CHROME = (
    "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko)"
    " Chrome/152.0.0.0 Mobile Safari/537.36"
)
CHROME_IOS = (
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15"
    " (KHTML, like Gecko) CriOS/140.0.0.0 Mobile/15E148 Safari/604.1"
)


def page_results(*, fetch="h3", xhr="h3", websocket="h2", probe="owned page echo"):
    return {
        "fetch": json.dumps({"fp": {"request_info": {"version": fetch}}}),
        "xhr": json.dumps({"fp": {"request_info": {"version": xhr}}}),
        "websocket": {
            "greeting": {"initiator": "ws", "version": websocket},
            "probe": probe,
        },
    }


class PageResultTests(unittest.TestCase):
    def test_result_decodes_original_response_text_and_keeps_exact_probe(self):
        value = page_results(probe="per-page echo 🐢")
        result = checked_page_results(value, dict(fetch="h3", xhr="h3", ws="h2"))
        for flow in ("fetch", "xhr"):
            self.assertIsInstance(value[flow], str)
            self.assertEqual(result[flow], json.loads(value[flow]))
        self.assertIs(result["websocket"], value["websocket"])
        self.assertEqual(result["websocket"]["probe"], "per-page echo 🐢")


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
        browser.execute_script.return_value = True
        for url in (
            "https://fixture/form",
            "https://fixture/form?source=web",
            "https://fixture/report?source=web&turtles=yes",
        ):
            browser.current_url = url
            self.assertFalse(get_form_navigation_complete(browser))
        browser.current_url = "https://fixture/form?source=web&turtles=yes"
        browser.execute_script.return_value = False
        self.assertFalse(get_form_navigation_complete(browser))
        browser.execute_script.return_value = True
        self.assertTrue(get_form_navigation_complete(browser))

    def test_submit_relocates_a_form_the_page_re_rendered(self):
        stale = Mock()
        stale.send_keys.side_effect = StaleElementReferenceException("re-rendered")
        fresh = Mock()
        browser = Mock()
        browser.find_element.side_effect = [stale, fresh]
        submit_form(browser, 'form[action="/form"]')
        fresh.send_keys.assert_called_once()
        self.assertEqual(
            browser.find_element.call_args.args[1], 'form[action="/form"] button[type="submit"]'
        )

        browser.find_element.side_effect = None
        browser.find_element.return_value = stale
        with self.assertRaises(StaleElementReferenceException):
            submit_form(browser, 'form[action="/form"]')

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


class SafariWebSocketOverH2Tests(unittest.TestCase):
    def test_predicate_matches_only_safari_before_26_on_h2(self):
        self.assertTrue(websocket_over_h2_unsupported(SAFARI_18, "h2"))
        for user_agent, expected in (
            (SAFARI_18, "h1"),
            (SAFARI_18, "h3"),
            (SAFARI_18, None),
            (SAFARI_26, "h2"),
            (CHROME, "h2"),
            (CHROME_IOS, "h2"),
            ("fixture user agent", "h2"),
            (None, "h2"),
        ):
            with self.subTest(user_agent=user_agent, expected=expected):
                self.assertFalse(websocket_over_h2_unsupported(user_agent, expected))


class WebSocketOverH3Tests(unittest.TestCase):
    def test_predicate_matches_every_browser_but_safari_26_on_h3(self):
        for user_agent in (CHROME, CHROME_IOS, SAFARI_18, "fixture user agent", None):
            with self.subTest(user_agent=user_agent):
                self.assertTrue(websocket_over_h3_unsupported(user_agent, "h3"))
        self.assertFalse(websocket_over_h3_unsupported(SAFARI_26, "h3"))
        for expected in ("h1", "h2", None):
            with self.subTest(expected=expected):
                self.assertFalse(websocket_over_h3_unsupported(CHROME, expected))


SWITCHING = ("ラマ | HTTP/3", "ラマ | Switching to HTTP/3…")
STAYED = ("ラマ | HTTP/3", "ラマ\n | This browser did not switch to HTTP/3")
REPORT = ("ラマ | FP", "ラマ | FP")


class H3BootstrapTests(unittest.TestCase):
    def capture(
        self,
        page,
        *,
        expected="h3",
        form_visible=False,
        load_error=None,
        probe=None,
        user_agent=SAFARI_18,
        user_agents=None,
        capabilities=None,
    ):
        browser = Mock()
        browser.current_url = "https://fixture/report"
        browser.capabilities = capabilities or {}
        agents = iter(user_agents) if user_agents is not None else None
        if load_error is not None:
            browser.get.side_effect = load_error

        def script(value, *_args):
            if "document.title" in value:
                if probe is not None:
                    raise probe
                return list(page)
            if value == "return navigator.userAgent":
                if agents is not None:
                    agent = next(agents, None)
                    if isinstance(agent, Exception):
                        raise agent
                    return agent
                return user_agent
            return None

        browser.execute_script.side_effect = script
        browser.find_elements.return_value = []

        class Wait:
            calls = 0

            def __init__(self, _driver, _timeout, **_options):
                pass

            def until(self, _condition):
                Wait.calls += 1
                if form_visible and Wait.calls == 1:
                    return Mock()
                raise TimeoutException("fixture timeout")

        with patch.object(workflow, "WebDriverWait", Wait), patch.object(
            workflow.time, "sleep"
        ):
            return workflow.run_capture_flow(
                browser, "https://fixture/", expected_protocol=expected
            )

    def test_timeout_on_bootstrap_door_is_unsupported_with_precise_reason(self):
        for page, reason in (
            (SWITCHING, "h3: browser did not leave the HTTP/3 bootstrap"),
            (STAYED, "h3: browser stayed on TCP: did not switch to HTTP/3"),
            (("ラマ | HTTP/3", ""), "h3: browser did not leave the HTTP/3 bootstrap"),
        ):
            with self.subTest(page=page):
                with self.assertRaises(UnsupportedFlow) as failure:
                    self.capture(page)
                self.assertEqual(str(failure.exception), reason)
                self.assertIsInstance(failure.exception.__cause__, TimeoutException)

    def test_only_browsers_known_to_stay_on_tcp_may_be_stuck_on_the_door(self):
        for user_agent in (SAFARI_18, SAFARI_26, CHROME_IOS, ANDROID_CHROME):
            with self.subTest(user_agent=user_agent):
                with self.assertRaises(UnsupportedFlow):
                    self.capture(STAYED, user_agent=user_agent)
        for user_agent in (CHROME, FIREFOX, None):
            with self.subTest(user_agent=user_agent):
                with self.assertRaisesRegex(RuntimeError, "must switch") as failure:
                    self.capture(SWITCHING, user_agent=user_agent)
                self.assertNotIsInstance(failure.exception, UnsupportedFlow)
                self.assertIsInstance(failure.exception.__cause__, TimeoutException)

    def test_user_agent_read_mid_reload_is_retried(self):
        navigating = RuntimeError("navigation in progress")
        with self.assertRaises(UnsupportedFlow):
            self.capture(SWITCHING, user_agents=[navigating, None, ANDROID_CHROME])

    def test_mobile_session_platform_covers_an_unreadable_user_agent(self):
        for platform in ("android", "iOS"):
            with self.subTest(platform=platform), self.assertRaises(UnsupportedFlow):
                self.capture(
                    SWITCHING, user_agent=None, capabilities={"platformName": platform}
                )
        with self.assertRaisesRegex(RuntimeError, "must switch"):
            self.capture(
                SWITCHING, user_agent=None, capabilities={"platformName": "windows"}
            )

    def test_page_load_timeout_on_bootstrap_door_is_unsupported(self):
        with self.assertRaisesRegex(UnsupportedFlow, "did not leave"):
            self.capture(SWITCHING, load_error=TimeoutException("page load"))

    def test_timeout_on_real_report_stays_failure(self):
        for page in (REPORT, ("", ""), ("ラマ | HTTP/3 report", "ラマ | FP")):
            with self.subTest(page=page), self.assertRaises(TimeoutException):
                self.capture(page)

    def test_bootstrap_door_outside_h3_stays_failure(self):
        for expected in ("h2", None):
            with self.subTest(expected=expected), self.assertRaises(TimeoutException):
                self.capture(STAYED, expected=expected)

    def test_unreadable_page_keeps_the_original_failure(self):
        with self.assertRaises(TimeoutException):
            self.capture(SWITCHING, probe=RuntimeError("driver gone"))

    def test_failure_after_report_loaded_is_never_reclassified(self):
        with self.assertRaises(TimeoutException) as failure:
            self.capture(STAYED, form_visible=True)
        self.assertNotIsInstance(failure.exception, UnsupportedFlow)


class ChromeWebSocketOverH2Tests(unittest.TestCase):
    def test_only_chrome_114_and_older_lack_websocket_over_h2(self):
        old = "Mozilla/5.0 (Linux; Android 12; SM-S908B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Mobile Safari/537.36"
        current = "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Mobile Safari/537.36"
        self.assertTrue(websocket_over_h2_unsupported(old, "h2"))
        self.assertFalse(websocket_over_h2_unsupported(current, "h2"))
        self.assertFalse(websocket_over_h2_unsupported(old, "h1"))
        self.assertFalse(websocket_over_h2_unsupported(None, "h2"))


if __name__ == "__main__":
    unittest.main()
