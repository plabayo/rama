import unittest
from types import SimpleNamespace
from flows import (
    ASSET_FLOWS,
    ReplayTarget,
    flow_initiator,
    flow_name,
    replay_args,
    scope_matches,
)
from wire import Request


class FlowContextTests(unittest.TestCase):
    def test_link_and_measured_subresources_are_operations_without_new_initiators(self):
        self.assertEqual(flow_name(((":method", "GET"), (":path", "/landing"))), "link")
        self.assertEqual(flow_initiator("link"), "navigate")
        for flow, path in ASSET_FLOWS.items():
            with self.subTest(flow=flow):
                self.assertEqual(flow_name(((":method", "GET"), (":path", path))), flow)
                self.assertIsNone(flow_name(((":method", "POST"), (":path", path))))
                self.assertIsNone(flow_initiator(flow))
        # Other subresources stay outside the measured journey.
        self.assertIsNone(
            flow_name(((":method", "GET"), (":path", "/assets/banner.jpeg")))
        )

    def test_subresource_replay_has_no_initiator_and_a_current_referer(self):
        request = Request(
            "GET",
            "/assets/style.css",
            (),
            b"",
            {"referer": "https://localhost:1111/form?source=web&turtles=yes"},
        )
        target = ReplayTarget("h1", "https://localhost:2222")
        args = replay_args("rama", "archive", "output", target, "style", request)
        self.assertNotIn("--emulate-initiator", args)
        self.assertIn(
            "--header=referer: https://localhost:2222/form?source=web&turtles=yes", args
        )
        link = replay_args("rama", "archive", "output", target, "link", request)
        self.assertEqual(link[link.index("--emulate-initiator") + 1], "navigate")
        outside = Request("GET", "/landing", (), b"", {"referer": "about:blank"})
        with self.assertRaisesRegex(ValueError, "Referer"):
            replay_args("rama", "archive", "output", target, "link", outside)

    def test_post_and_get_forms_are_distinct_operations(self):
        self.assertEqual(flow_name(((":method", "POST"), (":path", "/form"))), "form")
        self.assertEqual(
            flow_name(((":method", "GET"), (":path", "/form?source=web&turtles=yes"))),
            "form_get",
        )
        self.assertIsNone(flow_name(((":method", "GET"), (":path", "/api/ws"))))

    def test_other_method_initiator_protocol_or_fetch_context_cannot_match(self):
        context = dict(
            version="HTTP/3.0",
            method="POST",
            initiator="fetch",
            fetch={"mode": "cors", "site": "same-origin", "destination": "empty"},
        )
        block = SimpleNamespace(
            protocol="h3",
            headers=(
                (":method", "POST"),
                ("sec-fetch-mode", "cors"),
                ("sec-fetch-site", "same-origin"),
                ("sec-fetch-dest", "empty"),
            ),
        )
        self.assertTrue(scope_matches({"flow": {"Http": context}}, block, "fetch"))
        for key, value in [
            ("version", "HTTP/2.0"),
            ("method", "GET"),
            ("initiator", "xhr"),
            (
                "fetch",
                {"mode": "navigate", "site": "same-origin", "destination": "empty"},
            ),
        ]:
            with self.subTest(key=key):
                self.assertFalse(
                    scope_matches(
                        {"flow": {"Http": dict(context, **{key: value})}},
                        block,
                        "fetch",
                    )
                )

    def test_h1_upgrade_is_a_get_only_in_an_explicit_h1_context(self):
        headers = ((":method", "GET"), (":path", "/api/ws"))
        self.assertEqual(flow_name(headers, protocol="h1"), "ws")
        for protocol in (None, "h2", "h3"):
            with self.subTest(protocol=protocol):
                self.assertIsNone(flow_name(headers, protocol=protocol))

    def test_websocket_without_fetch_metadata_matches(self):
        context = dict(version="HTTP/3.0", method="CONNECT", initiator="ws", fetch=None)
        block = SimpleNamespace(protocol="h3", headers=((":method", "CONNECT"),))
        self.assertTrue(scope_matches({"flow": {"Http": context}}, block, "ws"))


if __name__ == "__main__":
    unittest.main()
