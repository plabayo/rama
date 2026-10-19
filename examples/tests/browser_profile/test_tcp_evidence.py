"""Synthetic native-format accounting controls; real decryption is checked offline."""

from copy import deepcopy
import hashlib
from pathlib import Path
import tempfile
import unittest
import xml.etree.ElementTree as ET

from tcp_evidence import (
    PREFACE,
    account_tcp,
    h2_frame_bytes,
    tls_follow,
    write_tcp_evidence,
)
from source_evidence import source_evidence
from tls_wire import byte_span

PORT = 4433
SETTINGS = b"\0\0\0\4\0\0\0\0\0"


def field(node, name, show=None, raw=None, *, pos=0, size=None):
    attributes = dict(
        name=name,
        pos=str(pos),
        size=str(len(raw) if size is None and raw is not None else size or 0),
    )
    if show is not None:
        attributes["show"] = str(show)
    if raw is not None:
        attributes["value"] = raw.hex()
    return ET.SubElement(node, "field", attributes)


def fixture():
    """Minimal native-shaped closed TLS1.3/H2 record inventory, not a handshake oracle."""
    root = ET.Element("pdml")
    sequences = {False: 0, True: 0}
    apps = {False: PREFACE + SETTINGS, True: SETTINGS}

    def packet(side, flags, raw=b"", *, inner=None, app=None, hello=False):
        node = ET.SubElement(root, "packet")
        number = len(root)
        for name, value in {
            "frame.number": number,
            "frame.cap_len": 54 + len(raw),
            "frame.len": 54 + len(raw),
            "tcp.stream": 0,
            "tcp.srcport": PORT if side else 50000,
            "tcp.dstport": 50000 if side else PORT,
            "tcp.len": len(raw),
            "tcp.seq": sequences[side],
            "tcp.ack": sequences[not side],
            "tcp.flags": hex(flags),
            "ip.src": "127.0.0.1",
            "ip.dst": "127.0.0.1",
        }.items():
            field(node, name, value)
        if raw:
            field(node, "tcp.payload", raw=raw, pos=54)
        sequences[side] += len(raw) + bool(flags & 3)
        if inner is not None:
            proto = ET.SubElement(
                node, "proto", name="tls", pos="54", size=str(len(raw))
            )
            field(proto, "tls.stream", 0)
            record = field(proto, "tls.record", pos=54, size=len(raw))
            field(record, "tls.record.length", len(raw) - 5)
            field(record, "tls.record.content_type", inner)
            if raw[0] == 23:
                field(record, "tls.record.opaque_type", 23)
                field(record, "tls.record.sequence_number", 0)
            if hello:
                handshake = field(record, "tls.handshake", size=len(raw) - 5)
                field(handshake, "tls.handshake.type", 2)
                field(handshake, "tls.handshake.ciphersuite", "0x1301", b"\x13\1")
        if app is not None:
            proto = ET.SubElement(node, "proto", name="http2")
            offset = 0
            if app.startswith(PREFACE):
                frame = field(proto, "http2.stream", pos=0, size=24)
                field(frame, "http2.magic", raw=PREFACE)
                offset = 24
            frame = field(proto, "http2.stream", raw=app[offset:], pos=offset)
            field(frame, "http2.length", 0, b"\0\0\0", pos=offset)
            field(frame, "http2.type", 4, b"\4", pos=offset + 3)
            field(frame, "http2.flags", "0x00", b"\0", pos=offset + 4)
            field(frame, "http2.streamid", 0, b"\0" * 4, pos=offset + 5)
        return node

    packet(False, 2)
    packet(True, 0x12)
    packet(False, 0x10)
    packet(False, 0x18, b"\x16\3\1\0\4\1\0\0\0", inner=22)
    packet(True, 0x18, b"\x16\3\3\0\4\2\0\0\0", inner=22, hello=True)
    for side in (False, True):
        body = b"z" * (len(apps[side]) + 17)
        packet(
            side,
            0x18,
            b"\x17\3\3" + len(body).to_bytes(2, "big") + body,
            inner=23,
            app=apps[side],
        )
    packet(False, 0x11)
    packet(True, 0x11)
    evidence = dict(
        revision=1,
        connections=[
            dict(
                connection=0,
                **{
                    name: dict(
                        bytes=len(apps[side]),
                        sha256=hashlib.sha256(apps[side]).hexdigest(),
                    )
                    for side, name in ((False, "client"), (True, "server"))
                }
            )
        ],
    )
    return root, evidence


def empty_fixture():
    """Closed TLS1.3 connection whose records carry no application byte."""
    root, evidence = fixture()
    for _ in range(2):
        root.remove(root[5])
    for number, packet in enumerate(root, 1):
        packet.find("field[@name='frame.number']").set("show", str(number))
    for packet in root[-2:]:
        # Both FINs directly follow the nine-byte handshake record.
        packet.find("field[@name='tcp.seq']").set("show", "10")
    for name in ("client", "server"):
        evidence["connections"][0][name] = dict(
            bytes=0, sha256=hashlib.sha256(b"").hexdigest()
        )
    return root, evidence


def refused_fixture():
    """A client SYN answered by the server's RST/ACK, as captured natively."""
    root, evidence = fixture()
    del root[2:]
    root[1].find("field[@name='tcp.flags']").set("show", "0x14")
    root[1].find("field[@name='tcp.seq']").set("show", "1")
    empty = dict(bytes=0, sha256=hashlib.sha256(b"").hexdigest())
    evidence["connections"][0].update(client=empty, server=dict(empty))
    return root, evidence


def account(root, evidence):
    data = ET.tostring(root)
    evidence = deepcopy(evidence)
    evidence["source_pdml_sha256"] = hashlib.sha256(data).hexdigest()
    return account_tcp(data, PORT, evidence)


class CaptureAccounting(unittest.TestCase):
    def test_fresh_cell_cannot_omit_completeness_witness(self):
        with self.assertRaisesRegex(ValueError, "fresh capture requires"):
            source_evidence(
                b"<pdml/>",
                {},
                {},
                "https://localhost:4433",
                PORT,
                require_complete_tcp=True,
            )

    def test_generated_hpack_fields_cannot_replace_original_compressed_bytes(self):
        node = ET.fromstring(
            '<field name="http2.stream" pos="0" size="2"><field name="http2.headers" pos="0" size="2" value="8284"/><field name="http2.header" pos="0" size="2"><field name="http2.header.value" pos="0" size="2" value="4142"/></field></field>'
        )
        self.assertEqual(h2_frame_bytes(node), b"\x82\x84")
        node.remove(node[0])
        with self.assertRaisesRegex(ValueError, "incomplete"):
            h2_frame_bytes(node)

    def test_reassembled_body_source_is_not_the_current_data_frame_source(self):
        node = ET.fromstring(
            '<field name="http2.stream" pos="0" size="1"><field name="http2.type" pos="0" size="1" value="00"/><field name="http2.body.fragments" pos="0" size="1" value="ff"/><field name="json" pos="0" size="1" value="ff"/></field>'
        )
        self.assertEqual(h2_frame_bytes(node), b"\0")

    def test_unknown_stream_zero_frame_never_grants_requestless_admission(self):
        root, evidence = fixture()
        frame = root[5].find("proto[@name='http2']/field[2]")
        kind = frame.find("field[@name='http2.type']")
        kind.set("show", "99")
        kind.set("value", "63")
        with self.assertRaisesRegex(ValueError, "unsupported stream-zero"):
            account(root, evidence)

    def test_tcp_payload_outside_fin_and_missing_syn_refuse(self):
        for kind in ("fin", "syn"):
            root, evidence = fixture()
            if kind == "fin":
                root[-1].find("field[@name='tcp.seq']").set("show", "2")
            else:
                root.remove(root[0])
            with self.subTest(kind=kind), self.assertRaisesRegex(
                ValueError, "FIN extent|initial SYN"
            ):
                account(root, evidence)

    def test_complete_native_controls_are_requestless_without_browser_attribution(self):
        root, evidence = fixture()
        result = account(root, evidence)
        self.assertTrue(result["complete"])
        connection = result["connections"][0]
        self.assertTrue(connection["requestless_h2"])
        self.assertTrue(connection["native_h2_frames_complete"])
        self.assertEqual(connection["application_bytes"], 42)

    def test_closed_connection_without_application_bytes_is_unattributed(self):
        root, evidence = empty_fixture()
        connection = account(root, evidence)["connections"][0]
        self.assertEqual(
            connection["classification"], "unattributed_no_application_data"
        )
        self.assertEqual(connection["provider_provenance"], "unknown")
        self.assertTrue(connection["no_application_data"])
        self.assertFalse(connection["requestless_h2"])
        self.assertEqual(connection["application_bytes"], 0)
        self.assertFalse(account(*fixture())["connections"][0]["no_application_data"])

    def test_open_empty_connection_is_not_classified_as_requestless(self):
        for removed in (-2, -1):
            root, evidence = empty_fixture()
            root.remove(root[removed])
            with self.subTest(removed=removed):
                connection = account(root, evidence)["connections"][0]
                self.assertFalse(connection["no_application_data"])
                self.assertEqual(
                    connection["provider_provenance"],
                    "not_attributed_by_tcp_accounting",
                )

    def test_empty_connection_requires_an_empty_witness(self):
        for name in ("bytes", "digest"):
            root, evidence = empty_fixture()
            if name == "bytes":
                evidence["connections"][0]["server"]["bytes"] = 1
            else:
                evidence["connections"][0]["client"]["sha256"] = "0" * 64
            with self.subTest(name=name), self.assertRaisesRegex(
                ValueError, "incomplete or padded"
            ):
                account(root, evidence)

    def test_refused_handshake_is_an_unattributed_payload_free_connection(self):
        root, evidence = refused_fixture()
        connection = account(root, evidence)["connections"][0]
        self.assertEqual(
            connection["classification"], "unattributed_refused_connection"
        )
        self.assertTrue(connection["no_application_data"])
        self.assertEqual(connection["application_bytes"], 0)
        with tempfile.TemporaryDirectory() as directory:
            data = ET.tostring(root)
            written = write_tcp_evidence(
                None, None, PORT, data, Path(directory) / "tls-accounting.json"
            )
        self.assertEqual(written["connections"], evidence["connections"])

    def test_refused_handshake_shape_is_exact(self):
        for name in (
            "payload",
            "witness",
            "reset first",
            "client ack",
            "server data",
            "no reset",
        ):
            root, evidence = refused_fixture()
            if name == "payload":
                field(root[0], "tcp.payload", raw=b"x", pos=54)
                root[0].find("field[@name='tcp.len']").set("show", "1")
            elif name == "witness":
                evidence["connections"][0]["server"]["bytes"] = 1
            elif name == "reset first":
                root[0].find("field[@name='frame.number']").set("show", "3")
            elif name == "client ack":
                root[0].find("field[@name='tcp.flags']").set("show", "0x10")
            elif name == "server data":
                root[1].find("field[@name='tcp.flags']").set("show", "0x10")
            else:
                root.remove(root[1])
            with self.subTest(name=name), self.assertRaises(ValueError):
                account(root, evidence)

    def test_same_bytes_retransmission_does_not_create_more_application_data(self):
        root, evidence = fixture()
        repeated = deepcopy(root[5])
        repeated.find("field[@name='frame.number']").set("show", "10")
        repeated.remove(repeated.find("proto[@name='tls']"))
        repeated.remove(repeated.find("proto[@name='http2']"))
        root.append(repeated)
        self.assertTrue(account(root, evidence)["complete"])

    def test_filtered_missing_packet_is_a_gap_not_a_requestless_exception(self):
        root, evidence = fixture()
        root.remove(root[3])
        with self.assertRaisesRegex(ValueError, "sequence gap"):
            account(root, evidence)

    def test_conflicting_retransmission_refuses(self):
        root, evidence = fixture()
        repeated = deepcopy(root[5])
        repeated.find("field[@name='frame.number']").set("show", "10")
        repeated.remove(repeated.find("proto[@name='tls']"))
        repeated.remove(repeated.find("proto[@name='http2']"))
        payload = repeated.find("field[@name='tcp.payload']")
        payload.set("value", "00" + payload.get("value")[2:])
        root.append(repeated)
        with self.assertRaisesRegex(ValueError, "conflicting TCP"):
            account(root, evidence)

    def test_opaque_protected_record_on_otherwise_owned_stream_refuses(self):
        root, evidence = fixture()
        record = root[5].find("proto/field[@name='tls.record']")
        record.remove(record.find("field[@name='tls.record.content_type']"))
        with self.assertRaisesRegex(ValueError, "content_type"):
            account(root, evidence)

    def test_decryption_marker_without_sequence_refuses(self):
        root, evidence = fixture()
        record = root[5].find("proto/field[@name='tls.record']")
        record.remove(record.find("field[@name='tls.record.sequence_number']"))
        with self.assertRaisesRegex(ValueError, "decryption sequence"):
            account(root, evidence)

    def test_decoded_record_omission_on_existing_connection_refuses(self):
        root, evidence = fixture()
        root[5].remove(root[5].find("proto[@name='tls']"))
        with self.assertRaisesRegex(ValueError, "lack native decoded record"):
            account(root, evidence)

    def test_undecoded_h2_bytes_cannot_hide_behind_other_control_frames(self):
        root, evidence = fixture()
        root[5].remove(root[5].find("proto[@name='http2']"))
        with self.assertRaisesRegex(ValueError, "frames do not cover"):
            account(root, evidence)

    def test_follow_missing_bytes_or_padding_are_inconclusive(self):
        for delta in (-1, 1):
            root, evidence = fixture()
            evidence["connections"][0]["client"]["bytes"] += delta
            with self.subTest(delta=delta), self.assertRaisesRegex(
                ValueError, "incomplete or padded"
            ):
                account(root, evidence)

    def test_follow_same_length_different_payload_refuses(self):
        root, evidence = fixture()
        evidence["connections"][0]["client"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "frames do not cover"):
            account(root, evidence)

    def test_nonzero_stream_is_never_requestless_even_without_headers(self):
        root, evidence = fixture()
        frame = root[5].find("proto[@name='http2']/field[2]")
        raw = bytes.fromhex(frame.get("value"))[:-4] + b"\0\0\0\x63"
        frame.set("value", raw.hex())
        stream = frame.find("field[@name='http2.streamid']")
        stream.set("show", "99")
        stream.set("value", "00000063")
        evidence["connections"][0]["client"]["sha256"] = hashlib.sha256(
            PREFACE + raw
        ).hexdigest()
        self.assertFalse(account(root, evidence)["connections"][0]["requestless_h2"])

    def test_requestless_unclosed_connection_refuses(self):
        root, evidence = fixture()
        root.remove(root[-1])
        with self.assertRaisesRegex(ValueError, "lifetime is incomplete"):
            account(root, evidence)

    def test_snapshot_truncation_refuses_even_with_decoded_frames(self):
        root, evidence = fixture()
        root[5].find("field[@name='frame.cap_len']").set("show", "54")
        with self.assertRaisesRegex(ValueError, "truncated captured"):
            account(root, evidence)

    def test_wrong_record_extent_refuses(self):
        root, evidence = fixture()
        root[5].find("proto/field[@name='tls.record']").set("pos", "55")
        with self.assertRaises(ValueError):
            account(root, evidence)

    def test_witness_cannot_be_rebound_to_other_pdml_or_connection(self):
        root, evidence = fixture()
        evidence["source_pdml_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "source differs"):
            account_tcp(ET.tostring(root), PORT, evidence)
        evidence["connections"][0]["connection"] = 99
        with self.assertRaisesRegex(ValueError, "ambiguous TCP witness"):
            account(root, evidence)

    def test_native_follow_handles_ipv6_direction_without_loopback_assumption(self):
        text = (
            "\n"
            + "=" * 67
            + "\nFollow: tls,raw\nFilter: tls.stream eq 7\nNode 0: [2001:db8::1]:4433\nNode 1: [2001:db8::2]:50000\n\t0102\n0304\n"
            + "=" * 67
            + "\n"
        )
        self.assertEqual(
            tls_follow(text, (("2001:db8::2", 50000), ("2001:db8::1", 4433)), 7),
            {False: b"\1\2", True: b"\3\4"},
        )
        with self.assertRaisesRegex(ValueError, "endpoints differ"):
            tls_follow(text, (("2001:db8::2", 50001), ("2001:db8::1", 4433)), 7)

    def test_physical_spans_use_native_unmasked_values_and_ignore_generated_widths(
        self,
    ):
        frame = ET.fromstring(
            '<field pos="4" size="2"><field pos="4" size="2" value="f" unmaskedvalue="010f"/><field pos="4" size="2" value="f"/></field>'
        )
        self.assertEqual(byte_span(frame), b"\1\x0f")
        frame[0].set("value", "zzzz")
        with self.assertRaises(ValueError):
            byte_span(frame)
        frame[0].set("value", "f")
        frame[0].set("unmaskedvalue", "zzzz")
        with self.assertRaises(ValueError):
            byte_span(frame)

    def test_conflicting_and_missing_physical_span_bytes_still_refuse(self):
        for extra in ('<field pos="4" size="2" value="020e"/>', ""):
            raw = (
                '<field pos="4" size="2"><field pos="4" size="1" value="01"/>'
                + extra
                + "</field>"
            )
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                byte_span(ET.fromstring(raw))


class TerminalControls(unittest.TestCase):
    def add_reset(self, root, *, side=False, delta=0, flags=4, payload=b"", ack=None):
        previous = next(
            packet
            for packet in reversed(root)
            if packet.find("field[@name='tcp.srcport']").get("show")
            == str(PORT if side else 50000)
        )
        node = deepcopy(previous)
        for proto in list(node.findall("proto")):
            node.remove(proto)
        node.find("field[@name='frame.number']").set(
            "show",
            str(
                max(
                    int(p.find("field[@name='frame.number']").get("show")) for p in root
                )
                + 1
            ),
        )
        sequence = (
            int(previous.find("field[@name='tcp.seq']").get("show"))
            + int(previous.find("field[@name='tcp.len']").get("show"))
            + bool(int(previous.find("field[@name='tcp.flags']").get("show"), 0) & 3)
        )
        node.find("field[@name='tcp.seq']").set("show", str(sequence + delta))
        node.find("field[@name='tcp.flags']").set("show", hex(flags))
        if ack is not None:
            node.find("field[@name='tcp.ack']").set("show", str(ack))
        node.find("field[@name='tcp.len']").set("show", str(len(payload)))
        for old in list(node.findall("field[@name='tcp.payload']")):
            node.remove(old)
        if payload:
            field(node, "tcp.payload", raw=payload, pos=54)
        for name in ("frame.len", "frame.cap_len"):
            node.find("field[@name='" + name + "']").set("show", str(54 + len(payload)))
        root.append(node)

    def fin_sequence(self, root, side):
        return next(
            int(packet.find("field[@name='tcp.seq']").get("show"))
            for packet in root
            if packet.find("field[@name='tcp.srcport']").get("show")
            == str(PORT if side else 50000)
            and int(packet.find("field[@name='tcp.flags']").get("show"), 0) & 1
        )

    def late_ack_reset(self, root, *, side=False, ack, sequence=None, flags=4):
        # The peer acknowledges stale data after our FIN; our closed endpoint
        # answers with RST.SEQ = SEG.ACK.
        self.add_reset(root, side=not side, flags=0x10, ack=ack)
        own = [
            packet
            for packet in root
            if packet.find("field[@name='tcp.srcport']").get("show")
            == str(PORT if side else 50000)
        ][-1]
        end = (
            int(own.find("field[@name='tcp.seq']").get("show"))
            + int(own.find("field[@name='tcp.len']").get("show"))
            + bool(int(own.find("field[@name='tcp.flags']").get("show"), 0) & 3)
        )
        self.add_reset(
            root,
            side=side,
            flags=flags,
            delta=(ack if sequence is None else sequence) - end,
        )

    def nonzero_stream(self, root, evidence):
        # A native nonzero DATA stream defeats requestless classification even
        # without decoded request headers; ordinary stream admission still applies.
        frame = root[5].find("proto[@name='http2']/field[2]")
        raw = b"\0\0\0\0\0\0\0\0\x63"
        frame.set("value", raw.hex())
        kind = frame.find("field[@name='http2.type']")
        kind.set("value", "00")
        kind.set("show", "0")
        stream = frame.find("field[@name='http2.streamid']")
        stream.set("value", "00000063")
        stream.set("show", "99")
        evidence["connections"][0]["client"]["sha256"] = hashlib.sha256(
            PREFACE + raw
        ).hexdigest()

    def test_zero_payload_resets_after_both_fins_preserve_requestless_accounting(self):
        root, evidence = fixture()
        self.add_reset(root)
        self.add_reset(root, side=True)
        result = account(root, evidence)["connections"][0]
        self.assertTrue(result["requestless_h2"])
        self.assertTrue(result["closed_both_directions"])
        self.assertEqual(result["application_bytes"], 42)

    def test_reset_after_peer_fin_accounts_nonzero_stream_without_tls_closure_claim(
        self,
    ):
        root, evidence = fixture()
        self.nonzero_stream(root, evidence)
        root.remove(root[-2])
        self.add_reset(root, flags=20)
        result = account(root, evidence)["connections"][0]
        self.assertFalse(result["requestless_h2"])
        self.assertFalse(result["closed_both_directions"])

    def test_reset_sequence_includes_its_own_fin_increment(self):
        for delta in (-2, -1, 1):
            root, evidence = fixture()
            self.add_reset(root, delta=delta)
            with self.subTest(delta=delta), self.assertRaisesRegex(
                ValueError, "terminal sequence extent"
            ):
                account(root, evidence)

    def test_reset_before_any_fin_is_not_proven_terminal(self):
        root, evidence = fixture()
        self.nonzero_stream(root, evidence)
        root.remove(root[-1])
        root.remove(root[-1])
        self.add_reset(root)
        with self.assertRaisesRegex(ValueError, "before an observed terminal FIN"):
            account(root, evidence)

    def test_reset_with_payload_or_nonterminal_flags_refuses(self):
        for flags, payload in ((4, b"x"), (12, b""), (6, b"")):
            root, evidence = fixture()
            self.add_reset(root, flags=flags, payload=payload)
            with self.subTest(flags=flags, payload=payload), self.assertRaises(
                ValueError
            ):
                account(root, evidence)

    def test_payload_after_reset_cannot_hide_as_an_identical_retransmission(self):
        root, evidence = fixture()
        self.add_reset(root)
        repeated = deepcopy(root[5])
        repeated.remove(repeated.find("proto[@name='tls']"))
        repeated.remove(repeated.find("proto[@name='http2']"))
        repeated.find("field[@name='frame.number']").set("show", "11")
        root.append(repeated)
        with self.assertRaisesRegex(ValueError, "payload follows terminal reset"):
            account(root, evidence)

    def test_reset_sequenced_from_late_peer_ack_after_own_fin_is_terminal(self):
        for side in (False, True):
            for back in (0, 1, 7):
                root, evidence = fixture()
                ack = self.fin_sequence(root, side) - back
                self.late_ack_reset(root, side=side, ack=ack)
                with self.subTest(side=side, back=back):
                    result = account(root, evidence)["connections"][0]
                    self.assertTrue(result["closed_both_directions"])
                    self.assertEqual(result["application_bytes"], 42)

    def test_late_ack_reset_requires_the_exact_captured_peer_ack(self):
        for name, ack, sequence in (
            ("wrong", -3, -4),
            ("future", 4, None),
            ("beyond fin", 2, None),
            ("zero", None, 0),
        ):
            root, evidence = fixture()
            end = self.fin_sequence(root, False)
            self.late_ack_reset(
                root,
                ack=end + ack if ack is not None else end - 3,
                sequence=None if sequence is None else end + sequence,
            )
            with self.subTest(name=name), self.assertRaisesRegex(
                ValueError, "terminal sequence extent"
            ):
                account(root, evidence)

    def test_late_ack_reset_refuses_missing_ack_or_ack_before_own_fin(self):
        for name in ("missing", "before fin", "rst ack", "reset flags"):
            root, evidence = fixture()
            end = self.fin_sequence(root, False)
            if name == "missing":
                self.add_reset(root, delta=end - 3 - (end + 1))
            elif name == "before fin":
                # The peer's stale ACK precedes our FIN, so it cannot sequence it.
                ack = deepcopy(root[-1])
                ack.find("field[@name='tcp.flags']").set("show", "0x10")
                ack.find("field[@name='tcp.ack']").set("show", str(end - 3))
                root.insert(len(root) - 2, ack)
                for number, packet in enumerate(root, 1):
                    packet.find("field[@name='frame.number']").set("show", str(number))
                self.add_reset(root, delta=-4)
            elif name == "rst ack":
                self.add_reset(root, side=True, flags=0x14, ack=end - 3)
                self.add_reset(root, delta=-4)
            else:
                self.late_ack_reset(root, ack=end - 3, flags=20)
            with self.subTest(name=name), self.assertRaisesRegex(
                ValueError, "terminal sequence extent"
            ):
                account(root, evidence)

    def test_late_ack_reset_refuses_ambiguous_ack(self):
        root, evidence = fixture()
        end = self.fin_sequence(root, False)
        self.late_ack_reset(root, ack=end - 3)
        field(root[-2], "tcp.ack", end)
        with self.assertRaisesRegex(ValueError, "tcp.ack|ambiguous"):
            account(root, evidence)

    def test_late_ack_reset_does_not_replace_missing_bytes_fin_or_later_payload(self):
        for name in ("gap", "no fin", "later payload"):
            root, evidence = fixture()
            end = self.fin_sequence(root, False)
            if name == "gap":
                root.remove(root[5])
            if name == "no fin":
                root.remove(root[-2])
            self.late_ack_reset(root, ack=end - 3)
            if name == "later payload":
                repeated = deepcopy(root[5])
                repeated.remove(repeated.find("proto[@name='tls']"))
                repeated.remove(repeated.find("proto[@name='http2']"))
                repeated.find("field[@name='frame.number']").set("show", "99")
                root.append(repeated)
            with self.subTest(name=name), self.assertRaises(ValueError):
                account(root, evidence)

    def test_requestless_reset_does_not_replace_missing_fin_closure(self):
        root, evidence = fixture()
        root.remove(root[-2])
        self.add_reset(root)
        with self.assertRaisesRegex(ValueError, "lifetime is incomplete"):
            account(root, evidence)


if __name__ == "__main__":
    unittest.main()
