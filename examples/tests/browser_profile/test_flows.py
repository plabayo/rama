import unittest
from types import SimpleNamespace
from flows import scope_matches, flow_name


class FlowContextTests(unittest.TestCase):
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

    def test_websocket_without_fetch_metadata_matches(self):
        context = dict(version="HTTP/3.0", method="CONNECT", initiator="ws", fetch=None)
        block = SimpleNamespace(protocol="h3", headers=((":method", "CONNECT"),))
        self.assertTrue(scope_matches({"flow": {"Http": context}}, block, "ws"))


if __name__ == "__main__":
    unittest.main()
