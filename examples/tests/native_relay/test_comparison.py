"""Use actual decoded Go/Rama legs to test preservation and honest mismatch reports."""

from copy import deepcopy
from dataclasses import replace
import json
from pathlib import Path
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

from comparison import compare_connection_facts, compare_legs, h2_settings
from tls_wire import client_hellos

FIXTURES = Path(__file__).parent / "tests/fixtures"
CAPTURES = json.loads((FIXTURES / "http-contract-captures.json").read_text())
PORTS = {
    protocol: (
        CAPTURES[protocol]["ports"]["ingress"],
        CAPTURES[protocol]["ports"]["egress"],
    )
    for protocol in ("h1", "h2")
}
BODY = b"external-relay-body"


def inputs(protocol):
    return tuple(
        (FIXTURES / (protocol + "-" + side + ".pdml")).read_bytes()
        for side in ("ingress", "egress")
    )


def compare(protocol, ingress, egress):
    return compare_legs(ingress, egress, protocol, *PORTS[protocol], BODY)


def changed_bytes(field, data):
    field.set("value", data.hex())
    field.set("size", str(len(data)))


class NativeComparisonTests(unittest.TestCase):
    def test_actual_packets_match_the_reviewable_native_snapshots(self):
        for protocol in PORTS:
            with self.subTest(protocol=protocol):
                report = compare(protocol, *inputs(protocol))
                expected = json.loads(
                    (FIXTURES / (protocol + "-expected.json")).read_text()
                )
                self.assertEqual(json.loads(json.dumps(report)), expected)
                self.assertTrue(report["supported_tls_facts_match"])
                self.assertTrue(report["bodies_and_trailers_match"])
                self.assertTrue(report["end_to_end_headers_match"])
                self.assertEqual(report["exchanges_checked"], 9)
                # The raw TLS/hop framing/SETTINGS differences are real. A
                # functional round trip must never turn them into fidelity PASS.
                self.assertFalse(report["fingerprint_match"])
                self.assertFalse(report["tls_fingerprint_match"])
                self.assertFalse(report["exact_header_wire_match"])

    def test_shared_connection_facts_preserve_http_results(self):
        for protocol in PORTS:
            with self.subTest(protocol=protocol):
                facts = compare_connection_facts(
                    *inputs(protocol), protocol, *PORTS[protocol]
                )
                expected = json.loads(
                    (FIXTURES / (protocol + "-expected.json")).read_text()
                )
                for name, value in facts.items():
                    if name != "fingerprint_match":
                        self.assertEqual(
                            json.loads(json.dumps(value)), expected[name], name
                        )
                self.assertFalse(facts["fingerprint_match"])
                self.assertNotIn("exchanges", facts)

    def test_reduced_websocket_traces_cannot_supply_connection_facts(self):
        metadata = json.loads((FIXTURES / "websocket-metadata.json").read_text())
        # H1's reduced tunnel fixtures are plain text, not PDML. The existing
        # H1/H2 actual HTTP snapshots exercise their shared TCP TLS path above.
        for protocol in ("h2", "h3"):
            with self.subTest(protocol=protocol), self.assertRaisesRegex(
                ValueError, "ClientHello"
            ):
                compare_connection_facts(
                    *[
                        (FIXTURES / f"websocket-{protocol}-{side}.pdml").read_bytes()
                        for side in ("ingress", "egress")
                    ],
                    protocol,
                    metadata[protocol]["ingress"],
                    metadata[protocol]["egress"],
                )

    def test_shared_connection_facts_recount_both_quic_wire_versions(self):
        metadata = json.loads((FIXTURES / "quic-metadata.json").read_text())
        for version in (1, 2):
            with self.subTest(version=version):
                facts = compare_connection_facts(
                    *[
                        (FIXTURES / f"quic-v{version}-{side}.pdml").read_bytes()
                        for side in ("ingress", "egress")
                    ],
                    "h3",
                    metadata[str(version)]["ingress"],
                    metadata[str(version)]["egress"],
                    quic_version=version,
                )
                self.assertTrue(facts["supported_tls_facts_match"])
                self.assertIn("quic", facts)
                self.assertTrue(facts["quic"]["fresh_connection_ids"])
                self.assertEqual(facts["quic"]["version"], version)
                self.assertFalse(facts["fingerprint_match"])

    def test_changed_native_tls_offer_is_not_accepted_as_a_partial_match(self):
        for protocol in PORTS:
            ingress, egress = inputs(protocol)
            left, right = client_hellos(ingress, "Tcp"), client_hellos(egress, "Tcp")
            altered = deepcopy(right[0].capture)
            altered["ciphers"] = altered["ciphers"][1:]
            changed = [replace(right[0], capture=altered)]
            with self.subTest(protocol=protocol):
                with patch("comparison.client_hellos", side_effect=[left, changed]):
                    with self.assertRaisesRegex(ValueError, "TLS ciphers differs"):
                        compare(protocol, ingress, egress)

    def test_changed_supported_extension_is_not_hidden_by_other_tls_differences(self):
        ingress, egress = inputs("h2")
        left, right = client_hellos(ingress, "Tcp"), client_hellos(egress, "Tcp")
        altered = deepcopy(right[0].capture)
        altered["extensions"] = [
            field for field in altered["extensions"] if field["id"] != 16
        ]
        with patch(
            "comparison.client_hellos",
            side_effect=[left, [replace(right[0], capture=altered)]],
        ):
            with self.assertRaisesRegex(ValueError, "ALPN offer differs"):
                compare("h2", ingress, egress)

    def test_changed_application_body_is_rejected_on_either_protocol(self):
        for protocol in PORTS:
            ingress, egress = inputs(protocol)
            root = ET.fromstring(egress)
            name = "http.file_data" if protocol == "h1" else "http2.data.data"
            body = next(
                field
                for field in root.iter("field")
                if field.get("name") == name and field.get("value") == BODY.hex()
            )
            changed_bytes(body, b"wrong")
            with self.subTest(protocol=protocol):
                with self.assertRaisesRegex(ValueError, "body differs"):
                    compare(protocol, ingress, ET.tostring(root))

    def test_changed_trailer_is_rejected(self):
        for protocol in PORTS:
            ingress, egress = inputs(protocol)
            root = ET.fromstring(egress)
            if protocol == "h1":
                trailer = next(
                    field
                    for field in root.iter("field")
                    if field.get("name") == "http.chunked_trailer_part"
                )
                changed_bytes(trailer, b"X-Interop-End: wrong\r\n")
            else:
                trailer = next(
                    field
                    for field in root.iter("field")
                    if field.get("name") == "http2.header"
                    and any(
                        child.get("name") == "http2.header.name"
                        and child.get("show") == "x-interop-end"
                        for child in field
                    )
                )
                value = next(
                    child
                    for child in trailer
                    if child.get("name") == "http2.header.value"
                )
                value.set("show", "wrong")
                changed_bytes(value, b"wrong")
            with self.subTest(protocol=protocol):
                with self.assertRaisesRegex(ValueError, "response trailer differs"):
                    compare(protocol, ingress, ET.tostring(root))

    def test_duplicate_field_multiplicity_cannot_be_lost(self):
        for protocol in PORTS:
            ingress, egress = inputs(protocol)
            root = ET.fromstring(egress)
            parents = {child: parent for parent in root.iter() for child in parent}
            if protocol == "h1":
                field = next(
                    field
                    for field in root.iter("field")
                    if field.get("name") == "http.request.line"
                    and bytes.fromhex(field.get("value", "")).startswith(
                        b"X-Interop-Repeat:"
                    )
                )
            else:
                field = next(
                    field
                    for field in root.iter("field")
                    if field.get("name") == "http2.header"
                    and any(
                        child.get("name") == "http2.header.name"
                        and child.get("show") == "x-interop-repeat"
                        for child in field
                    )
                )
            parents[field].remove(field)
            with self.subTest(protocol=protocol):
                with self.assertRaisesRegex(ValueError, "field spelling/order/values"):
                    compare(protocol, ingress, ET.tostring(root))

    def test_ingress_random_or_public_share_cannot_be_reused_on_egress(self):
        for name in ("randoms", "shares"):
            first = {"randoms": {"client-random"}, "shares": {"client-public"}}
            second = {"randoms": {"relay-random"}, "shares": {"relay-public"}}
            second[name] = first[name]
            with self.subTest(name=name), patch(
                "comparison.fresh_values", side_effect=[first, second]
            ):
                with self.assertRaisesRegex(ValueError, "reused ingress"):
                    compare("h1", *inputs("h1"))

    def test_h1_response_association_is_checked(self):
        ingress, egress = inputs("h1")
        root = ET.fromstring(egress)
        field = next(
            field
            for field in root.iter("field")
            if field.get("name") == "http.request_in"
        )
        field.set("show", "99999")
        with self.assertRaisesRegex(ValueError, "response association"):
            compare("h1", ingress, ET.tostring(root))

    def test_h2_settings_use_literal_wire_bytes_and_keep_order(self):
        ingress, _ = inputs("h2")
        original = h2_settings(ingress, PORTS["h2"][0])
        root = ET.fromstring(ingress)
        value = next(
            field
            for field in root.iter("field")
            if field.get("name") == "http2.settings.initial_window_size"
        )
        value.set("show", "99999")
        self.assertEqual(h2_settings(ET.tostring(root), PORTS["h2"][0]), original)
        changed_bytes(value, (123).to_bytes(4, "big"))
        self.assertNotEqual(h2_settings(ET.tostring(root), PORTS["h2"][0]), original)

    def test_h3_cannot_receive_an_unmeasured_tcp_fidelity_claim(self):
        with self.assertRaisesRegex(ValueError, "no complete ClientHello"):
            compare_legs(*inputs("h1"), "h3", *PORTS["h1"], BODY)


class RetryAdmissionTests(unittest.TestCase):
    def test_retry_is_rejected_before_tls_connection_counting(self):
        fixtures = Path(__file__).parent / "tests/fixtures"
        data = (fixtures / "quic-retry-v2-ingress.pdml").read_bytes()
        port = json.loads((fixtures / "quic-metadata.json").read_text())[
            "retry_v2_ingress"
        ]
        with self.assertRaisesRegex(ValueError, "excludes QUIC Retry"):
            compare_legs(
                data, data, "h3", port, port, "external-relay-body", quic_version=2
            )

    def test_unrelated_connections_are_not_merged_from_equal_hellos(self):
        metadata = json.loads((FIXTURES / "quic-metadata.json").read_text())["1"]
        tree = ET.fromstring((FIXTURES / "quic-v1-ingress.pdml").read_bytes())
        packet = next(
            packet
            for packet in tree.findall("packet")
            if any(
                field.get("name") == "tls.handshake.type" and field.get("show") == "1"
                for field in packet.iter("field")
            )
        )
        unrelated = deepcopy(packet)
        for field in unrelated.iter("field"):
            if field.get("name") == "quic.connection.number":
                field.set("show", "99")
            if field.get("name") == "quic.scid":
                field.set("value", "ff" * int(field.get("size")))
        tree.append(unrelated)
        data = ET.tostring(tree)
        with self.assertRaisesRegex(ValueError, "more than one TLS connection"):
            compare_legs(
                data,
                data,
                "h3",
                metadata["ingress"],
                metadata["ingress"],
                "external-relay-body",
            )
