"""Independent traffic cannot borrow driver attribution or retained profile credit."""

from copy import deepcopy
from dataclasses import replace
import hashlib
import unittest
import xml.etree.ElementTree as ET

from remote.admission import admit
from remote.background import MAX_INDEPENDENT_BYTES, partition
from remote.tests.fixtures import ORIGIN, admission_fixture
from wire import HeaderBlock


def background_fixture():
    raw, rows, page = admission_fixture()
    document = ET.fromstring(raw)

    def packet(number, source, destination, stream, address):
        node = ET.SubElement(document, "packet")
        for name, value in (
            ("frame.number", number),
            ("tcp.srcport", source),
            ("tcp.dstport", destination),
            ("tcp.stream", stream),
            ("ip.src", address),
        ):
            ET.SubElement(node, "field", name=name, show=str(value))
        return node

    # The shared body fixture represents WS frames separately; add its source socket.
    packet(10, 52442, 32543, 0, "198.51.100.7")
    packet(200, 53123, 32543, 9, "203.0.113.9")
    final = packet(201, 32543, 53123, 9, "203.0.113.7")
    stream = ET.SubElement(final, "field", name="http2.stream")
    ET.SubElement(stream, "field", name="http2.flags", value="01", size="1", pos="0")
    ET.SubElement(stream, "field", name="http2.streamid", show="1")
    foreign = HeaderBlock(
        "h2",
        200,
        9,
        1,
        False,
        (
            (":method", "HEAD"),
            (":path", "/report"),
            (":scheme", "https"),
            (":authority", "h3.fp.ramaproxy.org:32543"),
            ("user-agent", "independent-claim"),
        ),
    )
    rows += [
        foreign,
        replace(foreign, packet=201, from_server=True, headers=((":status", "200"),)),
    ]
    inspected = {"profiles": [{"key": {"user_agent": page["user_agent"]}}]}
    return ET.tostring(document), rows, page, inspected


class IndependentObservationTests(unittest.TestCase):
    def test_explicit_independent_inventory_preserves_default_failure_and_owned_checks(
        self,
    ):
        raw, frames, page, inspected = background_fixture()
        with self.assertRaisesRegex(ValueError, "User-Agent"):
            admit(raw, frames, page, ORIGIN)
        owned, report, inventory = partition(raw, frames, page, ORIGIN, inspected)
        self.assertEqual(inventory, frozenset({("tcp", 9)}))
        self.assertEqual(
            len(
                admit(raw, owned, page, ORIGIN, independent_connections=inventory)[
                    "flows"
                ]
            ),
            6,
        )
        self.assertEqual(report["independent_requests"], 1)
        self.assertEqual(report["source_pdml_sha256"], hashlib.sha256(raw).hexdigest())
        observed = report["observations"][0]
        self.assertEqual(observed["classification"], "unattributed_independent")
        self.assertEqual(observed["provider_provenance"], "unknown")
        self.assertEqual(
            (
                observed["protocol"],
                observed["packet"],
                observed["stream"],
                observed["method"],
            ),
            ("h2", 200, 1, "HEAD"),
        )
        self.assertTrue(observed["response_complete"])
        self.assertEqual(
            observed["response_body_sha256"], hashlib.sha256(b"").hexdigest()
        )
        self.assertFalse(any(row.connection == 9 for row in owned))
        with self.assertRaisesRegex(ValueError, "undecoded"):
            admit(raw, owned, page, ORIGIN)

    def test_shared_connection_peer_or_retained_foreign_profile_cannot_be_partitioned(
        self,
    ):
        raw, frames, page, inspected = background_fixture()
        wrong = list(frames)
        wrong[-2] = replace(wrong[-2], connection=0)
        with self.assertRaisesRegex(ValueError, "connection"):
            partition(raw, wrong, page, ORIGIN, inspected)
        changed = ET.fromstring(raw)
        packet = next(
            p
            for p in changed
            if p.find("field[@name='frame.number'][@show='200']") is not None
        )
        packet.find("field[@name='ip.src']").set("show", "198.51.100.7")
        packet.find("field[@name='tcp.srcport']").set("show", "52442")
        with self.assertRaisesRegex(ValueError, "peer"):
            partition(ET.tostring(changed), frames, page, ORIGIN, inspected)
        foreign = deepcopy(inspected)
        foreign["profiles"].append({"key": {"user_agent": "independent-claim"}})
        with self.assertRaisesRegex(ValueError, "foreign profile"):
            partition(raw, frames, page, ORIGIN, foreign)

    def test_same_agent_extra_connection_never_becomes_independent_success(self):
        raw, frames, page, inspected = background_fixture()
        frames[-2] = replace(
            frames[-2],
            headers=tuple(
                (name, page["user_agent"] if name == "user-agent" else value)
                for name, value in frames[-2].headers
            ),
        )
        owned, report, inventory = partition(raw, frames, page, ORIGIN, inspected)
        self.assertIsNone(report)
        self.assertFalse(inventory)
        with self.assertRaisesRegex(ValueError, "additional source connection"):
            admit(raw, owned, page, ORIGIN, independent_connections=inventory)

    def test_incomplete_ambiguous_credentialed_or_unresolved_traffic_is_fatal(self):
        for mutation in (
            "end-stream",
            "duplicate-response",
            "credential",
            "requestless",
            "missing-agent",
        ):
            raw, frames, page, inspected = background_fixture()
            document = ET.fromstring(raw)
            if mutation == "end-stream":
                # Only alter the actual independent response's END_STREAM byte.
                response = next(
                    p
                    for p in document
                    if p.find("field[@name='frame.number'][@show='201']") is not None
                )
                response.find("field/field[@name='http2.flags']").set("value", "00")
            elif mutation == "duplicate-response":
                frames.append(frames[-1])
            elif mutation == "credential":
                frames[-2] = replace(
                    frames[-2],
                    headers=frames[-2].headers + (("authorization", "foreign"),),
                )
            elif mutation == "missing-agent":
                frames[-2] = replace(
                    frames[-2],
                    headers=tuple(
                        pair for pair in frames[-2].headers if pair[0] != "user-agent"
                    ),
                )
            else:
                extra = ET.SubElement(document, "packet")
                for name, value in (
                    ("frame.number", 300),
                    ("tcp.stream", 15),
                    ("tcp.dstport", 32543),
                    ("tcp.srcport", 54000),
                    ("ip.src", "203.0.113.15"),
                ):
                    ET.SubElement(extra, "field", name=name, show=str(value))
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                partition(ET.tostring(document), frames, page, ORIGIN, inspected)

    def test_independent_body_budget_is_not_a_way_to_hide_extra_bytes(self):
        raw, frames, page, inspected = background_fixture()
        frames[-1] = replace(frames[-1], data=b"x" * (MAX_INDEPENDENT_BYTES + 1))
        with self.assertRaisesRegex(ValueError, "byte budget"):
            partition(raw, frames, page, ORIGIN, inspected)
