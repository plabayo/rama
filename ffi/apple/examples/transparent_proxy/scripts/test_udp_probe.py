#!/usr/bin/env python3
"""DNS wire validation regression tests for the standalone UDP probe."""

import json
from pathlib import Path
import struct
import tempfile
import unittest

import modern_udp_e2e_probe as udp_probe

class DnsWireValidationTests(unittest.TestCase):
    question = b"\x07example\x03com\x00\x00\x01\x00\x01"
    query = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + question
    address = bytes((93, 184, 216, 34))

    @staticmethod
    def record(owner, data, kind=1, record_class=1, ttl=60):
        return owner + struct.pack("!HHIH", kind, record_class, ttl, len(data)) + data

    def response(self, answers, authority=(), additional=(), *, flags=0x8180, question=None):
        return (struct.pack("!HHHHHH", 0x1234, flags, 1, len(answers), len(authority), len(additional))
                + (self.question if question is None else question)
                + b"".join((*answers, *authority, *additional)))

    def validate(self, response):
        udp_probe.validate_dns_response(self.query, response, ("8.8.8.8", 53), "8.8.8.8")

    def test_accepts_complete_compressed_uncompressed_and_case_insensitive_answers(self):
        for owner, question in ((b"\xc0\x0c", self.question),
                                (b"\x07example\x03com\0", self.question),
                                (b"\x07EXAMPLE\x03COM\0", self.question.upper())):
            with self.subTest(owner=owner, question=question):
                self.validate(self.response([self.record(owner, self.address)], question=question))

    def test_accepts_cname_chain_and_pointer_to_prior_compressed_rdata(self):
        alias = b"\x05alias\xc0\x0c"
        alias_offset = len(self.query) + 12  # first answer's CNAME RDATA
        alias_pointer = struct.pack("!H", 0xC000 | alias_offset)
        self.validate(self.response([
            self.record(b"\xc0\x0c", alias, kind=5),
            self.record(alias_pointer, self.address),
        ]))
        first = b"\x05first\x07example\x03com\0"
        second = b"\x06second\x07example\x03com\0"
        # Record ordering is immaterial to the answer's CNAME chain.
        self.validate(self.response([
            self.record(second, self.address),
            self.record(first, second, kind=5),
            self.record(b"\xc0\x0c", first, kind=5),
        ]))

    def test_accepts_protocol_name_bound_and_long_prior_pointer_chain(self):
        longest_name = (b"\x3f" + b"a" * 63) * 3 + b"\x3d" + b"b" * 61 + b"\0"
        self.assertEqual(len(longest_name), 255)
        target = struct.pack("!H", 0xC000 | (len(self.query) + 12))
        self.validate(self.response([
            self.record(b"\xc0\x0c", longest_name, 5),
            self.record(target, self.address),
        ]))
        records = []
        previous, offset = 12, len(self.query)
        for _ in range(1000):
            record = self.record(struct.pack("!H", 0xC000 | previous), self.address)
            records.append(record)
            previous, offset = offset, offset + len(record)
        self.validate(self.response(records))

    def test_accepts_opaque_authority_additional_and_bounded_edns_options(self):
        opt = self.record(b"\0", struct.pack("!HH", 65001, 3) + b"abc", 41, 1232, 0)
        unknown = self.record(b"\0", bytes(600), 65280)
        response = self.response([self.record(b"\xc0\x0c", self.address)],
                                 [self.record(b"\xc0\x0c", b"\x02ns\xc0\x0c", 2)],
                                 [unknown, opt])
        self.assertGreater(len(response), 512)
        self.validate(response)

    def test_rejects_every_truncated_prefix_and_unframed_trailing_bytes(self):
        response = self.response([self.record(b"\xc0\x0c", self.address)])
        for length in range(len(response)):
            with self.subTest(length=length), self.assertRaises(RuntimeError):
                self.validate(response[:length])
        with self.assertRaisesRegex(RuntimeError, "trailing"):
            self.validate(response + b"\0")

    def test_rejects_opcode_tc_and_mismatched_question_or_answer(self):
        answer = self.record(b"\xc0\x0c", self.address)
        cases = {
            "opcode": self.response([answer], flags=0x8980),
            "TC": self.response([answer], flags=0x8380),
            "question-name": self.response([answer], question=b"\x07invalid" + self.question[8:]),
            "question-type": self.response([answer], question=self.question[:-4] + b"\0\x1c\0\x01"),
            "question-class": self.response([answer], question=self.question[:-2] + b"\0\x03"),
            "answer-name": self.response([self.record(b"\x07invalid\x03com\0", self.address)]),
            "answer-class": self.response([self.record(b"\xc0\x0c", self.address, record_class=3)]),
            "only-additional-A": self.response([self.record(b"\xc0\x0c", b"\x01x", 16)], additional=[answer]),
            "CNAME-without-A": self.response([self.record(b"\xc0\x0c", b"\x05alias\xc0\x0c", 5)]),
            "CNAME-cycle": self.response([self.record(b"\xc0\x0c", b"\xc0\x0c", 5)]),
        }
        for case, response in cases.items():
            with self.subTest(case=case), self.assertRaises(RuntimeError):
                self.validate(response)

    def test_rejects_invalid_record_lengths_and_name_compression(self):
        answer = self.record(b"\xc0\x0c", self.address)
        start = len(self.query)
        cases = {
            "A-length": self.response([self.record(b"\xc0\x0c", self.address[:3])]),
            "CNAME-length": self.response([self.record(b"\xc0\x0c", b"\xc0\x0c\0", 5)]),
            "CNAME-label-crosses-rdata": self.response([
                self.record(b"\xc0\x0c", b"\x05abc", 5), answer]),
            "CNAME-pointer-crosses-rdata": self.response([
                self.record(b"\xc0\x0c", b"\xc0", 5), answer]),
            "self-pointer": self.response([self.record(struct.pack("!H", 0xC000 | start), self.address)]),
            "label-pointer-loop": self.response([
                self.record(b"\x01x" + struct.pack("!H", 0xC000 | start), self.address)]),
            "forward-pointer": self.response([self.record(b"\xff\xff", self.address)]),
            "header-pointer": self.response([self.record(b"\xc0\0", self.address)]),
            "reserved-label": self.response([self.record(b"\x40" + bytes(64) + b"\0", self.address)]),
            "oversized-name": self.response([self.record(
                (b"\x3f" + b"a" * 63) * 3 + b"\x3e" + b"b" * 62 + b"\0", self.address)]),
            "authority-overrun": self.response([answer], authority=[self.record(b"\0", b"abcd", 65280)[:-1]]),
            "additional-overrun": self.response([answer], additional=[self.record(b"\0", b"abcd", 65280)[:-1]]),
        }
        for case, response in cases.items():
            with self.subTest(case=case), self.assertRaises(RuntimeError):
                self.validate(response)

    def test_rejects_malformed_edns_and_extended_error(self):
        answer = self.record(b"\xc0\x0c", self.address)
        opt = self.record(b"\0", b"", 41, 1232, 0)
        cases = (
            [self.record(b"\0", b"", 41, 1232, 1 << 24)],
            [self.record(b"\0", b"\x00", 41, 1232, 0)],
            [self.record(b"\0", struct.pack("!HH", 65001, 4) + b"abc", 41, 1232, 0)],
            [self.record(b"\xc0\x0c", b"", 41, 1232, 0)],
            [opt, opt],
        )
        for records in cases:
            with self.subTest(records=records), self.assertRaises(RuntimeError):
                self.validate(self.response([answer], additional=records))

class ReceiptFileTests(unittest.TestCase):
    def test_bounded_files_and_no_replace_publication(self):
        receipt = dict.fromkeys(udp_probe.HTTP3_RECEIPT_KEYS, 0)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            body = root / 'body'
            body.write_bytes(b'http=http/3\n')
            self.assertEqual(udp_probe.read_http3_body(body), b'http=http/3\n')
            valid = root / 'valid.json'
            valid.write_text(json.dumps(receipt))
            self.assertEqual(udp_probe.read_http3_receipt(valid), receipt)
            duplicate = root / 'duplicate.json'
            duplicate.write_text(json.dumps(receipt)[:-1] + ',"exit_code":0}')
            with self.assertRaises(ValueError): udp_probe.read_http3_receipt(duplicate)
            symlink = root / 'symlink'
            symlink.symlink_to(body)
            with self.assertRaises(OSError): udp_probe.read_http3_body(symlink)
            oversized = root / 'oversized'
            oversized.write_bytes(b'x' * (udp_probe.HTTP3_BODY_MAX_BYTES + 1))
            with self.assertRaises(ValueError): udp_probe.read_http3_body(oversized)
            udp_probe._publish_http3_file(root / 'fresh', b'published')
            self.assertEqual((root / 'fresh').read_bytes(), b'published')
            with self.assertRaises(FileExistsError): udp_probe._publish_http3_file(body, b'overwrite')
            self.assertEqual(body.read_bytes(), b'http=http/3\n')
            self.assertFalse(list(root.glob('.http3-probe-*')))

    def test_receipt_reader_rejects_incomplete_duplicate_and_oversized_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "receipt.json"
            with self.assertRaises(OSError):
                udp_probe.read_probe_receipt(path)
            value = dict.fromkeys(udp_probe.PROBE_RECEIPT_KEYS, 0)
            content = json.dumps(value)
            path.write_text(content)
            self.assertEqual(udp_probe.read_probe_receipt(path), value)
            for raw in ("", content[:-1], content[:-1] + ',"exit_code":0}',
                        content.ljust(udp_probe.PROBE_RECEIPT_MAX_BYTES + 1)):
                with self.subTest(length=len(raw)):
                    path.write_text(raw)
                    with self.assertRaises(ValueError):
                        udp_probe.read_probe_receipt(path)

if __name__ == "__main__":
    unittest.main()
