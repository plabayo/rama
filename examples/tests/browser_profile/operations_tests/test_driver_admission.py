"""Driver/native/wire attribution must fail closed."""

from copy import deepcopy
from dataclasses import replace
import unittest
import xml.etree.ElementTree as ET

from flows import FLOWS
from admission import admit, complete_responses, peer_socket, request_info
from operations_tests.admission_fixtures import ORIGIN, admission_fixture


class DriverAdmissionTests(unittest.TestCase):
    def test_driver_native_peer_response_completion_and_probe_bind_all_six(self):
        raw, frames, page = admission_fixture()
        result = admit(raw, frames, page, ORIGIN)
        self.assertEqual(set(result["flows"]), set(FLOWS))
        self.assertIn("redacted", result["limits"])
        for change in (
            lambda p: p["page_results"]["fetch"]["fp"]["request_info"].update(
                peer_addr="198.51.100.8:52442"
            ),
            lambda p: p["page_results"]["fetch"].update(number=44),
            lambda p: p["page_results"]["websocket"].update(probe="other"),
        ):
            changed = deepcopy(page)
            change(changed)
            with self.assertRaises(ValueError):
                admit(raw, frames, changed, ORIGIN)
        with self.assertRaises(ValueError):
            admit(raw.replace(b"198.51.100.7", b"198.51.100.8"), frames, page, ORIGIN)
        with self.assertRaises(ValueError):
            admit(raw.replace(b'value="01"', b'value="00"'), frames, page, ORIGIN)
        with self.assertRaises(ValueError):
            admit(raw, frames + [frames[0]], page, ORIGIN)
        altered = list(frames)
        altered[0] = replace(
            altered[0], headers=altered[0].headers + (("authorization", "secret"),)
        )
        with self.assertRaises(ValueError):
            admit(raw, altered, page, ORIGIN)
        with self.assertRaises(ValueError):
            admit(
                raw,
                frames
                + [
                    replace(
                        frames[0],
                        stream=99,
                        headers=((":method", "GET"), (":path", "/unowned")),
                    )
                ],
                page,
                ORIGIN,
            )

    def test_admission_rejects_other_user_agents_connections_and_greetings(self):
        raw, frames, page = admission_fixture()
        changed = list(frames)
        changed[0] = replace(
            changed[0],
            headers=tuple(
                (name, "foreign-browser" if name == "user-agent" else value)
                for name, value in changed[0].headers
            ),
        )
        with self.assertRaises(ValueError):
            admit(raw, changed, page, ORIGIN)
        other = replace(
            frames[0],
            connection=99,
            stream=99,
            headers=(
                (":method", "GET"),
                (":path", "/assets/style.css"),
                ("user-agent", "ordinary-browser"),
            ),
        )
        with self.assertRaises(ValueError):
            admit(raw, frames + [other], page, ORIGIN)
        extra = ET.fromstring(raw)
        packet = ET.SubElement(extra, "packet")
        for name, value in (
            ("frame.number", 900),
            ("tcp.dstport", 32543),
            ("tcp.srcport", 53456),
            ("tcp.stream", 99),
            ("ip.src", "198.51.100.7"),
        ):
            ET.SubElement(packet, "field", name=name, show=str(value))
        with self.assertRaises(ValueError):
            admit(ET.tostring(extra), frames, page, ORIGIN)
        changed_page = deepcopy(page)
        changed_page["page_results"]["websocket"]["greeting"]["message"] = "other"
        with self.assertRaises(ValueError):
            admit(raw, frames, changed_page, ORIGIN)

    def test_native_socket_and_html_ambiguity_fail_closed(self):
        self.assertEqual(peer_socket("[2001:db8::1]:52442"), ("2001:db8::1", 52442))
        for value in (
            "example.org:3",
            "127.0.0.1",
            "127.0.0.1:4/path",
            "user@127.0.0.1:4",
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                peer_socket(value)
        raw, _, page = admission_fixture()
        document = page["report_html"]
        with self.assertRaises(ValueError):
            request_info(document + document)
        with self.assertRaises(ValueError):
            request_info(
                document.replace(
                    "<table>", "<table><tr><td>Version</td><td>HTTP/2.0</td></tr>"
                )
            )

    def test_h2_completion_uses_exact_parent_flags_not_masked_children_or_display(self):
        raw, _frames, _page = admission_fixture()
        document = ET.fromstring(raw)
        flags = document.findall(".//field[@name='http2.flags']")
        self.assertTrue(flags)
        expected = complete_responses(raw, 32543)
        self.assertTrue(expected)
        for node in flags:
            ET.SubElement(
                node,
                "field",
                name="http2.flags.unused_settings",
                value="0",
                unmaskedvalue=node.get("value"),
                size="1",
                pos=node.get("pos"),
            )
        self.assertEqual(complete_responses(ET.tostring(document), 32543), expected)
        for node in flags:
            node.set("value", "00")
            node.set("show", "0x01")
        self.assertEqual(complete_responses(ET.tostring(document), 32543), set())
        flags[0].set("size", "2")
        with self.assertRaisesRegex(ValueError, "flags"):
            complete_responses(ET.tostring(document), 32543)


if __name__ == "__main__":
    unittest.main()
