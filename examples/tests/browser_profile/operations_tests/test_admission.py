"""Discovery keeps its own response completion and native peer binding."""

from dataclasses import replace
import unittest
import xml.etree.ElementTree as ET

from operations import DISCOVERY, OperationLedger
from admission import admit
from operations_tests.admission_fixtures import ORIGIN, admission_fixture


def discovery_fixture():
    raw, frames, page = admission_fixture()
    tree = ET.fromstring(raw)
    frames = [
        replace(
            block,
            packet=block.packet + 2,
            headers=tuple(
                (
                    name,
                    (
                        "/report?h3_probe=1"
                        if name == ":path" and value == "/report"
                        else value
                    ),
                )
                for name, value in block.headers
            )
            + (
                ((":authority", "h3.fp.ramaproxy.org:32543"),)
                if not block.from_server and block.stream == 11
                else ()
            ),
        )
        for block in frames
    ]
    for packet in tree:
        number = packet.find("field[@name='frame.number']")
        number.set("show", str(int(number.get("show")) + 2))
    discovery_head = replace(
        frames[0],
        packet=1,
        stream=13,
        headers=tuple(
            (name, "/report" if name == ":path" else value)
            for name, value in frames[0].headers
        ),
    )
    discovery_response = replace(frames[1], packet=2, stream=13)
    frames = [discovery_head, discovery_response] + frames
    for number, outbound in ((1, True), (2, False)):
        packet = ET.SubElement(tree, "packet")
        for name, value in (
            ("frame.number", number),
            ("tcp.stream", 0),
            ("tcp.dstport", 32543 if outbound else 52442),
            ("tcp.srcport", 52442 if outbound else 32543),
            ("ip.src", "198.51.100.7"),
        ):
            ET.SubElement(packet, "field", name=name, show=str(value))
        if not outbound:
            stream = ET.SubElement(packet, "field", name="http2.stream")
            ET.SubElement(
                stream, "field", name="http2.flags", value="01", size="1", pos="0"
            )
            ET.SubElement(stream, "field", name="http2.streamid", show="13")
    page["report_url"] = ORIGIN + "/report?h3_probe=1"
    planned = OperationLedger.from_driver(
        frames, page["protocols"], ORIGIN, page["report_url"]
    )
    return ET.tostring(tree), frames, page, planned


class DiscoveryAdmissionTests(unittest.TestCase):
    def test_discovery_response_is_independently_admitted(self):
        raw, frames, page, planned = discovery_fixture()
        result = admit(raw, frames, page, ORIGIN, operations=planned)
        self.assertEqual(set(result["flows"]), set(page["protocols"]))
        self.assertEqual(set(result["declared_operations"]), set(planned.names))
        self.assertIn(DISCOVERY, result["declared_operations"])
        changed = list(frames)
        changed[1] = replace(
            changed[1], data=changed[1].data.replace(b"198.51.100.7", b"198.51.100.8")
        )
        with self.assertRaisesRegex(ValueError, "discovery native response"):
            admit(raw, changed, page, ORIGIN, operations=planned)

    def test_missing_discovery_completion_and_late_discovery_cannot_pass(self):
        raw, frames, page, planned = discovery_fixture()
        tree = ET.fromstring(raw)
        tree.remove(
            next(
                packet
                for packet in tree
                if packet.find("field[@name='frame.number']").get("show") == "2"
            )
        )
        with self.assertRaisesRegex(
            ValueError, "discovery navigation response missing"
        ):
            admit(ET.tostring(tree), frames, page, ORIGIN, operations=planned)
        changed = [
            (
                replace(block, packet=500)
                if not block.from_server and block.stream == 13
                else block
            )
            for block in frames
        ]
        with self.assertRaisesRegex(ValueError, "precede"):
            OperationLedger.from_driver(
                changed, page["protocols"], ORIGIN, page["report_url"]
            )
