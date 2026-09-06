#!/usr/bin/env python3
"""Protocol and pacing regression tests for the standalone UDP probe."""

import contextlib
import ctypes as C
import hashlib
import io
import json
import os
from pathlib import Path
import socket
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import modern_udp_e2e_probe as udp_probe
from modern_udp_e2e_probe import ProductViolation, pressure_burst

RUN_UUID = "12345678-1234-4234-8234-123456789abc"

def probe_receipt_fixture(label, source_pid, endpoint, *, start_epoch_ms=1100, run_uuid=RUN_UUID):
    """An ordinary captured request/response, independent of the replay helper."""
    protocol = "ntp" if label in ("ntp", "recovery") else "dns"
    if protocol == "dns":
        question = b"\x07example\x03com\x00\x00\x01\x00\x01"
        request = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + question
        response = struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0) + question
        response += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + bytes((93, 184, 216, 34))
    else:
        request = bytes((0x23,)) + bytes(39) + struct.pack("!II", 2_208_988_801, 0)
        response = bytes((0x24, 1)) + bytes(22) + request[40:48] + bytes(16)
    start = start_epoch_ms * 1_000_000 + 1_000_000_000
    timeout = label == "blocked"
    elapsed_ms = 4002 if timeout else 3
    server, port = endpoint.rsplit(":", 1)
    return {
        "schema_version": 1, "kind": "udp_protocol_probe", "run_uuid": run_uuid,
        "probe_label": label, "source_pid": source_pid, "protocol": protocol,
        "endpoint": endpoint, "dns_name": "example.com" if protocol == "dns" else None,
        "expect_no_response": timeout, "timeout_ns": (4 if timeout else 8) * 1_000_000_000,
        "request_hex": request.hex(), "sent_bytes": len(request),
        "response_hex": None if timeout else response.hex(),
        "response_peer": None if timeout else [server, int(port)],
        "receive_outcome": "timeout" if timeout else "response",
        "start_epoch_ms": start_epoch_ms, "end_epoch_ms": start_epoch_ms + elapsed_ms,
        "start_monotonic_ns": start, "receive_started_monotonic_ns": start + 1_000_000,
        "receive_completed_monotonic_ns": start + (elapsed_ms - 1) * 1_000_000,
        "end_monotonic_ns": start + elapsed_ms * 1_000_000,
        "close_error": False, "exit_code": 0, "schema_complete": True,
    }

def http3_receipt_fixture():
    body = b"fl=fixture\nhttp=http/3\ntls=TLSv1.3\n"
    return {
        "schema_version": 1, "kind": "bound_http3_client", "schema_complete": True,
        "run_uuid": RUN_UUID, "source_pid": 3500,
        "url": "https://cloudflare.com/cdn-cgi/trace",
        "library_path": "/opt/homebrew/Cellar/curl/8.20.0/lib/libcurl.4.dylib",
        "library_sha256": "30011f4f6bb8db9f151673d9c2327eb7f81b24f3e3a6e201d0a27bfb31773a14",
        "libcurl_version": "libcurl/8.20.0 OpenSSL/3.6.0 ngtcp2/1.22.1 nghttp3/1.15.0",
        "requested_local_port": 54000, "http_version": 30, "response_code": 200,
        "local_endpoint": "192.0.2.1:54000", "remote_endpoint": "1.1.1.1:443",
        "monotonic_clock": "CLOCK_MONOTONIC",
        "start_epoch_ms": 8600, "end_epoch_ms": 8700,
        "start_monotonic_ns": 9_600_000_000, "end_monotonic_ns": 9_700_000_000,
        "response_body_bytes": len(body), "response_body_sha256": hashlib.sha256(body).hexdigest(),
        "passed": True, "exit_code": 0, "error": None,
    }, body

HTTP3_FIXTURE_RECEIPT, HTTP3_FIXTURE_BODY = http3_receipt_fixture()

class BoundHttp3ReceiptTests(unittest.TestCase):
    def replay(self, value, body=HTTP3_FIXTURE_BODY):
        expected = HTTP3_FIXTURE_RECEIPT
        return udp_probe.replay_http3_receipt(
            value, body, expected['run_uuid'], expected['source_pid'], expected['url'])

    def test_offline_receipt_and_rejection_boundaries(self):
        receipt = dict(HTTP3_FIXTURE_RECEIPT)
        # Replay must remain offline even when the claimed library is absent.
        with mock.patch.object(C, 'CDLL', side_effect=AssertionError('native load in replay')):
            self.assertEqual(self.replay(receipt), 0)
        integer_fields = ('schema_version', 'source_pid', 'requested_local_port',
                          'http_version', 'response_code', 'start_epoch_ms', 'end_epoch_ms',
                          'start_monotonic_ns', 'end_monotonic_ns', 'response_body_bytes', 'exit_code')
        mutations = [(key, True) for key in integer_fields]
        mutations += [
            ('run_uuid', 'bad'), ('source_pid', receipt['source_pid'] + 1),
            ('url', receipt['url'] + 'x'), ('kind', 'udp_protocol_probe'),
            ('monotonic_clock', 'mach_absolute_time'), ('schema_complete', 1),
            ('passed', 1), ('passed', False), ('error', ''), ('exit_code', 20),
            ('library_path', '/'), ('library_path', 'relative'), ('library_path', '/a/../b'),
            ('library_path', '/a\nb'), ('library_sha256', 'A' * 64),
            ('libcurl_version', 'notcurl'), ('libcurl_version', 'libcurl/8.20.0wrong'),
            ('requested_local_port', 0), ('requested_local_port', 1),
            ('local_endpoint', '0.0.0.0:54000'), ('local_endpoint', '192.0.2.1:054000'),
            ('local_endpoint', 'unavailable'), ('local_endpoint', '[::1]:54000'),
            ('remote_endpoint', '1.1.1.1:53'), ('remote_endpoint', '0.0.0.0:443'),
            ('http_version', 3), ('response_code', 204),
            ('response_body_bytes', len(HTTP3_FIXTURE_BODY) + 1), ('response_body_sha256', '0' * 64),
            ('start_monotonic_ns', 0), ('end_monotonic_ns', receipt['start_monotonic_ns'] - 1),
            ('end_monotonic_ns', receipt['start_monotonic_ns'] + 30_000_000_001),
            ('end_epoch_ms', receipt['end_epoch_ms'] + 3000),
        ]
        for key, value in mutations:
            with self.subTest(field=key, value=value), self.assertRaises(ValueError):
                self.replay(dict(receipt, **{key: value}))
        for body in (b'', bytearray(HTTP3_FIXTURE_BODY), b'http=http/30\n',
                     b'http=http/3\nhttp=http/3\n', b'x' * (udp_probe.HTTP3_BODY_MAX_BYTES + 1)):
            with self.subTest(body_size=len(body)), self.assertRaises(ValueError):
                self.replay(dict(receipt, response_body_bytes=len(body),
                                 response_body_sha256=hashlib.sha256(body).hexdigest()), body)
        for changed in (dict(receipt, extra=1),
                        {key: value for key, value in receipt.items() if key != 'error'}):
            with self.subTest(keys=set(changed)), self.assertRaises(ValueError):
                self.replay(changed)
        with self.assertRaises(ValueError):
            self.replay(receipt, HTTP3_FIXTURE_BODY + b'x')

    def test_bounded_client_lifecycle(self):
        modes = ('success', 'global_init_error', 'handle_error', 'bind_error',
                 'setopt_error', 'perform_error', 'oversized_body', 'callback_error',
                 'wrong_protocol', 'cleanup_error')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / 'libcurl.dylib'
            path.write_bytes(b'mock library: never loaded')
            for mode in modes:
                with self.subTest(mode=mode):
                    options = {}
                    library = SimpleNamespace()
                    for name, result in (
                        ('curl_global_init', 0), ('curl_global_cleanup', None),
                        ('curl_easy_init', 123), ('curl_easy_cleanup', None),
                        ('curl_easy_setopt', 0), ('curl_easy_getinfo', 0),
                        ('curl_easy_perform', 0), ('curl_version', b'libcurl/8.20.0 mock'),
                    ):
                        setattr(library, name, mock.Mock(return_value=result))
                    selection = mock.MagicMock()
                    selection.__enter__.return_value = selection
                    selection.getsockname.return_value = ('0.0.0.0', 54000)
                    if mode == 'global_init_error': library.curl_global_init.return_value = 2
                    if mode == 'handle_error': library.curl_easy_init.return_value = None
                    if mode == 'bind_error': selection.bind.side_effect = OSError('mock bind failure')
                    if mode == 'cleanup_error':
                        library.curl_easy_cleanup.side_effect = RuntimeError('mock cleanup failure')

                    def setopt(handle, option, value):
                        options[option] = value
                        return 48 if mode == 'setopt_error' else 0
                    library.curl_easy_setopt.side_effect = setopt

                    def perform(handle):
                        # The selection socket must close before traffic, and the
                        # transfer must use that one port with no HTTP fallback.
                        self.assertEqual(selection.__exit__.call_count, 1)
                        selection.bind.assert_called_once_with(('0.0.0.0', 0))
                        self.assertEqual({key: options[key].value for key in (84, 139, 140, 113, 155, 156)},
                                         {84: 31, 139: 54000, 140: 1, 113: 1, 155: 15000, 156: 10000})
                        self.assertEqual(options[10004].value, b'')
                        self.assertEqual(options[10177].value, b'*')
                        self.assertEqual(library.curl_easy_setopt.argtypes, [C.c_void_p, C.c_int])
                        self.assertEqual(library.curl_easy_getinfo.argtypes, [C.c_void_p, C.c_int])
                        if mode == 'perform_error': return 28
                        if mode == 'oversized_body':
                            self.assertEqual(options[20011](None, 1, udp_probe.HTTP3_BODY_MAX_BYTES + 1, None), 0)
                            return 23
                        if mode == 'callback_error':
                            with mock.patch.object(C, 'string_at', side_effect=ValueError('mock read failure')):
                                self.assertEqual(options[20011](None, 1, 1, None), 0)
                            return 23
                        buffer = C.create_string_buffer(HTTP3_FIXTURE_BODY)
                        self.assertEqual(options[20011](C.addressof(buffer), 1, len(HTTP3_FIXTURE_BODY), None),
                                         len(HTTP3_FIXTURE_BODY))
                        return 0
                    library.curl_easy_perform.side_effect = perform

                    def getinfo(handle, info, pointer):
                        pointer._obj.value = {
                            0x200000 + 46: 2 if mode == 'wrong_protocol' else 30,
                            0x200000 + 2: 200, 0x200000 + 42: 54000, 0x200000 + 40: 443,
                            0x100000 + 41: b'192.0.2.1', 0x100000 + 32: b'1.1.1.1',
                        }[info]
                        return 0
                    library.curl_easy_getinfo.side_effect = getinfo
                    receipt_path, body_path = root / (mode + '.json'), root / (mode + '.body')
                    with mock.patch.object(C, 'CDLL', return_value=library), \
                            mock.patch.object(udp_probe.socket, 'socket', return_value=selection), \
                            contextlib.redirect_stdout(io.StringIO()):
                        if mode == 'success':
                            udp_probe.http3_probe(path, HTTP3_FIXTURE_RECEIPT['url'],
                                                  HTTP3_FIXTURE_RECEIPT['run_uuid'], receipt_path, body_path)
                        else:
                            with self.assertRaises(RuntimeError):
                                udp_probe.http3_probe(path, HTTP3_FIXTURE_RECEIPT['url'],
                                                      HTTP3_FIXTURE_RECEIPT['run_uuid'], receipt_path, body_path)
                    receipt = udp_probe.read_http3_receipt(receipt_path)
                    body = udp_probe.read_http3_body(body_path)
                    self.assertEqual(set(receipt), udp_probe.HTTP3_RECEIPT_KEYS)
                    self.assertEqual(receipt['passed'], mode == 'success')
                    self.assertEqual(receipt['exit_code'], 0 if mode == 'success' else 20)
                    self.assertEqual(receipt['response_body_bytes'], len(body))
                    self.assertEqual(receipt['response_body_sha256'], hashlib.sha256(body).hexdigest())
                    self.assertLessEqual(len(body), udp_probe.HTTP3_BODY_MAX_BYTES)
                    self.assertEqual(library.curl_easy_cleanup.call_count,
                                     0 if mode in ('global_init_error', 'handle_error') else 1)
                    self.assertEqual(library.curl_global_cleanup.call_count, 0 if mode == 'global_init_error' else 1)
                    if mode in ('global_init_error', 'handle_error', 'bind_error', 'setopt_error'):
                        library.curl_easy_perform.assert_not_called()
                    if mode == 'success':
                        self.assertEqual(udp_probe.replay_http3_receipt(
                            receipt, body, receipt['run_uuid'], os.getpid(), receipt['url']), 0)

    def test_bounded_files_and_no_replace_publication(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            body = root / 'body'
            body.write_bytes(HTTP3_FIXTURE_BODY)
            duplicate = root / 'duplicate.json'
            duplicate.write_text(json.dumps(HTTP3_FIXTURE_RECEIPT)[:-1] + ',"exit_code":0}')
            with self.assertRaises(ValueError): udp_probe.read_http3_receipt(duplicate)
            symlink = root / 'symlink'
            symlink.symlink_to(body)
            with self.assertRaises(OSError): udp_probe.read_http3_body(symlink)
            oversized = root / 'oversized'
            oversized.write_bytes(b'x' * (udp_probe.HTTP3_BODY_MAX_BYTES + 1))
            with self.assertRaises(ValueError): udp_probe.read_http3_body(oversized)
            with self.assertRaises(FileExistsError): udp_probe._publish_http3_file(body, b'overwrite')
            self.assertEqual(body.read_bytes(), HTTP3_FIXTURE_BODY)
            self.assertFalse(list(root.glob('.http3-probe-*')))

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

class ProtocolProbeReceiptTests(unittest.TestCase):
    def capture(self, root, label, *, outcome="response", mutate=None, close_error=False,
                partial_send=False, early_timeout=False, bind_error=False):
        """Mock only our socket and clock; never contact a protocol endpoint."""
        protocol = "ntp" if label in ("ntp", "recovery") else "dns"
        server, port = ("162.159.200.1", 123) if protocol == "ntp" else ("8.8.8.8", 53)
        now = [10_000_000_000]
        sent = []
        received = []
        binds = []
        closes = []
        timeout = 4 if label == "blocked" else 8
        path = root / f"udp-probe-{label}.json"

        class MockSocket:
            def bind(self, endpoint):
                binds.append(endpoint)
                if bind_error:
                    raise OSError("ordinary mocked bind error")

            def settimeout(self, seconds):
                self.timeout = seconds

            def sendto(self, packet, endpoint):
                if binds != [("0.0.0.0", 0)]:
                    raise AssertionError("probe sent before ephemeral bind")
                sent.append((bytes(packet), endpoint))
                now[0] += 1_000_000
                return len(packet) - int(partial_send)

            def recvfrom(self, maximum):
                received.append(maximum)
                now[0] += 1_000_000 if outcome != "timeout" or early_timeout else timeout * 1_000_000_000
                if outcome == "timeout":
                    raise socket.timeout("ordinary mocked timeout")
                if outcome == "error":
                    raise OSError("ordinary mocked socket error")
                packet = sent[0][0]
                if protocol == "dns":
                    response = packet[:2] + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0) + packet[12:]
                    response += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + bytes((93, 184, 216, 34))
                else:
                    response = bytes((0x24, 1)) + bytes(22) + packet[40:48] + bytes(16)
                pair = (response, (server, port))
                return mutate(*pair) if mutate else pair

            def close(self):
                closes.append(True)
                if close_error:
                    raise OSError("ordinary mocked close error")

        error = None
        with mock.patch.object(udp_probe.socket, "socket", return_value=MockSocket()), \
                mock.patch.object(udp_probe.time, "clock_gettime_ns", side_effect=lambda _: now[0]), \
                mock.patch.object(udp_probe.time, "time_ns", side_effect=lambda: now[0] + 1_000_000_000_000), \
                mock.patch.object(udp_probe.time, "time", side_effect=lambda: 1000 + now[0] / 1e9), \
                mock.patch("builtins.print"):
            try:
                keywords = dict(run_uuid=RUN_UUID, probe_label=label, result_file=str(path))
                if protocol == "dns":
                    udp_probe.dns_query(server, "example.com", timeout, label == "blocked", **keywords)
                else:
                    udp_probe.ntp_query(server, timeout, **keywords)
            except Exception as caught:
                error = caught
        self.assertEqual(binds, [("0.0.0.0", 0)])
        self.assertEqual(closes, [True])
        self.assertEqual(len(sent), 0 if bind_error else 1)
        if sent:
            self.assertEqual(sent[0][1], (server, port))
        self.assertEqual(received, [] if partial_send or bind_error else [65_535])
        self.assertFalse(list(root.glob(".udp-probe-*.tmp")))
        return path, error

    def replay(self, value):
        return udp_probe.replay_probe_receipt(
            value, RUN_UUID, value["probe_label"], os.getpid(), value["endpoint"]
        )

    def test_all_five_canaries_publish_raw_receipts_and_replay(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for label in udp_probe.PROBE_LABELS:
                with self.subTest(label=label):
                    path, error = self.capture(root, label, outcome="timeout" if label == "blocked" else "response")
                    self.assertIsNone(error)
                    value = udp_probe.read_probe_receipt(path)
                    self.assertEqual(self.replay(value), 0)
                    self.assertEqual(len(bytes.fromhex(value["request_hex"])), value["sent_bytes"])
                    self.assertEqual(value["response_hex"] is None, label == "blocked")
                    self.assertEqual(path.stat().st_nlink, 1)

    def test_bind_failure_closes_without_traffic_and_publishes_failure(self):
        for label in udp_probe.PROBE_LABELS:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                path, error = self.capture(Path(temporary), label, bind_error=True)
                self.assertIsInstance(error, OSError)
                value = udp_probe.read_probe_receipt(path)
                self.assertEqual(value["sent_bytes"], 0)
                self.assertEqual(value["receive_outcome"], "not_started")
                self.assertEqual(self.replay(value), udp_probe.PROBE_ERROR_EXIT)

    def test_malformed_packets_and_wrong_peers_preserve_raw_failed_outcomes(self):
        mutations = (
            ("control", "truncated", lambda response, peer: (b"short", peer)),
            ("control", "transaction", lambda response, peer: (bytes((response[0] ^ 1,)) + response[1:], peer)),
            ("control", "response", lambda response, peer: (response[:2] + b"\x01" + response[3:], peer)),
            ("control", "rcode", lambda response, peer: (response[:3] + b"\x83" + response[4:], peer)),
            ("control", "answer", lambda response, peer: (response[:6] + bytes(2) + response[8:], peer)),
            ("control", "peer", lambda response, peer: (response, ("8.8.4.4", peer[1]))),
            ("ntp", "truncated", lambda response, peer: (response[:47], peer)),
            ("ntp", "mode", lambda response, peer: (b"\x23" + response[1:], peer)),
            ("ntp", "stratum", lambda response, peer: (response[:1] + b"\x00" + response[2:], peer)),
            ("recovery", "originate", lambda response, peer: (response[:24] + bytes(8) + response[32:], peer)),
            ("recovery", "peer", lambda response, peer: (response, (peer[0], 124))),
            ("blocked", "malformed", lambda response, peer: (b"short", peer)),
        )
        for label, name, mutation in mutations:
            with self.subTest(label=label, mutation=name), tempfile.TemporaryDirectory() as temporary:
                path, error = self.capture(Path(temporary), label, mutate=mutation)
                self.assertIsInstance(error, RuntimeError)
                self.assertNotIsInstance(error, ProductViolation)
                value = udp_probe.read_probe_receipt(path)
                self.assertEqual(value["receive_outcome"], "response")
                self.assertEqual(self.replay(value), udp_probe.PROBE_ERROR_EXIT)
                value["exit_code"] = 0
                with self.assertRaisesRegex(ValueError, "raw protocol evidence"):
                    self.replay(value)

    def test_timeout_socket_failure_and_block_violation_remain_distinct(self):
        cases = (
            ("control", "timeout", False, False, socket.timeout, 20),
            ("ntp", "error", False, False, OSError, 20),
            ("blocked", "error", True, False, OSError, 20),
            ("ntp", "response", True, False, OSError, 20),
            ("ntp", "response", False, True, RuntimeError, 20),
            ("blocked", "response", False, False, ProductViolation, 10),
            ("blocked", "response", True, False, ProductViolation, 10),
            ("blocked", "timeout", True, False, None, 0),
        )
        for label, outcome, close_error, partial_send, expected_error, expected in cases:
            with self.subTest(case=(label, outcome, close_error, partial_send)), tempfile.TemporaryDirectory() as temporary:
                path, error = self.capture(Path(temporary), label, outcome=outcome,
                                           close_error=close_error, partial_send=partial_send)
                if expected_error is None:
                    self.assertIsNone(error)
                else:
                    self.assertIsInstance(error, expected_error)
                value = udp_probe.read_probe_receipt(path)
                self.assertEqual(self.replay(value), expected)

    def test_incomplete_dns_wire_data_cannot_claim_pass_or_a_block_violation(self):
        cases = (
            ("header-only", lambda response: response[:12]),
            ("truncated-question", lambda response: response[:28]),
            ("truncated-A", lambda response: response[:-1]),
            ("mismatched-question", lambda response: response[:13] + b"invalid" + response[20:]),
        )
        for label in ("passthrough", "control", "blocked"):
            for case, response_fixture in cases:
                with self.subTest(label=label, case=case), tempfile.TemporaryDirectory() as temporary:
                    path, error = self.capture(Path(temporary), label,
                                               mutate=lambda response, peer: (response_fixture(response), peer))
                    self.assertIsInstance(error, RuntimeError)
                    self.assertNotIsInstance(error, ProductViolation)
                    value = udp_probe.read_probe_receipt(path)
                    self.assertEqual(self.replay(value), udp_probe.PROBE_ERROR_EXIT)
                    for claim in (0, udp_probe.PRODUCT_VIOLATION_EXIT):
                        value["exit_code"] = claim
                        with self.assertRaisesRegex(ValueError, "raw protocol evidence"):
                            self.replay(value)

    def test_early_timeout_cannot_supply_block_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            path, _ = self.capture(Path(temporary), "blocked", outcome="timeout", early_timeout=True)
            with self.assertRaisesRegex(ValueError, "full timeout"):
                self.replay(udp_probe.read_probe_receipt(path))

    def test_publication_failure_and_duplicate_publication_never_replace_a_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with mock.patch.object(udp_probe.os, "link", side_effect=OSError("fixture publication failure")):
                path, error = self.capture(root, "ntp")
            self.assertIsInstance(error, OSError)
            self.assertFalse(path.exists())
            path, error = self.capture(root, "ntp")
            self.assertIsNone(error)
            original = path.read_bytes()
            _, error = self.capture(root, "ntp")
            self.assertIsInstance(error, FileExistsError)
            self.assertEqual(path.read_bytes(), original)

    def test_receipt_reader_rejects_incomplete_duplicate_and_oversized_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "receipt.json"
            with self.assertRaises(OSError):
                udp_probe.read_probe_receipt(path)
            value = probe_receipt_fixture("ntp", os.getpid(), "162.159.200.1:123")
            content = json.dumps(value)
            for raw in ("", content[:-1], content[:-1] + ',"exit_code":0}',
                        " " * (udp_probe.PROBE_RECEIPT_MAX_BYTES + 1)):
                with self.subTest(length=len(raw)):
                    path.write_text(raw)
                    with self.assertRaises(ValueError):
                        udp_probe.read_probe_receipt(path)

class PressureProbePacingTests(unittest.TestCase):
    class Clock:
        def __init__(self):
            self.now = 100.0
            self.sleeps = []
            self.oversleep = {}

        def monotonic(self):
            return self.now

        def sleep(self, seconds):
            self.sleeps.append((self.now, seconds))
            self.now += seconds + self.oversleep.get(len(self.sleeps), 0.0)

    class Socket:
        def __init__(self, clock):
            self.clock = clock
            self.attempts = []
            self.delays = {}
            self.errors = {}
            self.partial = set()
            self.timeout = None
            self.closes = 0
            self.binds = []
            self.bind_error = None

        def bind(self, endpoint):
            self.binds.append(endpoint)
            if self.bind_error is not None:
                raise self.bind_error

        def settimeout(self, seconds):
            self.timeout = seconds

        def sendto(self, packet, peer):
            if self.binds != [("0.0.0.0", 0)]:
                raise AssertionError("pressure probe sent before ephemeral bind")
            sequence = len(self.attempts)
            started = self.clock.now
            self.clock.now += self.delays.get(sequence, 0.0)
            self.attempts.append((
                bytes(packet), peer, started, self.clock.now, self.timeout,
            ))
            if sequence in self.errors:
                raise self.errors[sequence]
            return len(packet) - int(sequence in self.partial)

        def close(self):
            self.closes += 1

    def setUp(self):
        self.clock = self.Clock()
        self.socket = self.Socket(self.clock)
        self.factory = mock.Mock(return_value=self.socket)
        self.output = mock.Mock()

    def run_probe(self, *, count=512, payload_bytes=4096, deadline=120.0):
        with mock.patch.object(udp_probe.time, "monotonic", self.clock.monotonic), \
                mock.patch.object(udp_probe.time, "sleep", self.clock.sleep), \
                mock.patch.object(udp_probe.socket, "socket", self.factory), \
                mock.patch.object(udp_probe, "print", self.output, create=True), \
                mock.patch.object(udp_probe, "PRESSURE_DEADLINE_SECONDS", deadline):
            pressure_burst("162.159.200.1", count, payload_bytes, 4.0)

    def assert_once_only_sequences(self):
        marker = b"rama-udp-e2e-pressure-v1 162.159.200.1:123\0"
        for sequence, (packet, peer, _, _, _) in enumerate(self.socket.attempts):
            self.assertEqual(len(packet), 4096)
            self.assertEqual(packet[:len(marker)], marker)
            self.assertEqual(int.from_bytes(packet[len(marker):len(marker) + 8], "big"), sequence)
            self.assertEqual(peer, ("162.159.200.1", 123))

    def test_canonical_workload_primes_recovers_and_sends_every_packet_once(self):
        self.run_probe()
        self.assertEqual(len(self.socket.attempts), 512)
        self.assert_once_only_sequences()
        self.factory.assert_called_once_with(socket.AF_INET, socket.SOCK_DGRAM)
        self.assertEqual(self.socket.binds, [("0.0.0.0", 0)])
        self.assertEqual(self.socket.closes, 1)
        self.output.assert_called_once()
        self.assertLess(self.socket.attempts[65][3] - 100, 2.0)
        for sequence in range(1, 512):
            previous = self.socket.attempts[sequence - 1]
            current = self.socket.attempts[sequence]
            self.assertAlmostEqual(current[2] - previous[3], 2.5 if sequence == 66 else 0.02)
        self.assertEqual(self.clock.sleeps[-1][1], 4.0)
        self.assertAlmostEqual(self.clock.now - 100, 16.7)
        self.assertTrue(all(row[4] == 5.0 for row in self.socket.attempts))

    def test_bind_failure_closes_without_sending_or_pacing(self):
        self.socket.bind_error = OSError("ordinary mocked bind error")
        with self.assertRaisesRegex(OSError, "bind error"):
            self.run_probe()
        self.assertEqual(self.socket.binds, [("0.0.0.0", 0)])
        self.assertEqual(self.socket.attempts, [])
        self.assertEqual(self.socket.closes, 1)
        self.assertEqual(self.clock.sleeps, [])
        self.output.assert_not_called()

    def test_scheduler_and_send_delays_do_not_compress_later_intervals(self):
        self.clock.oversleep[40] = 0.7
        self.socket.delays[45] = 0.3
        self.run_probe()
        self.assert_once_only_sequences()
        for sequence in range(1, 512):
            previous = self.socket.attempts[sequence - 1]
            current = self.socket.attempts[sequence]
            self.assertGreaterEqual(current[2] - previous[3], 0.02 - 1e-9)
        self.assertAlmostEqual(self.socket.attempts[40][2] - self.socket.attempts[39][3], 0.72)
        self.assertAlmostEqual(self.clock.now - 100, 17.7)

    def test_socket_errors_and_partial_datagrams_never_retry(self):
        for sequence, error in (
            (0, socket.timeout("blocked send")),
            (65, socket.timeout("blocked send")),
            (66, socket.timeout("blocked send")),
            (511, OSError("socket unavailable")),
            (66, None),
        ):
            with self.subTest(sequence=sequence, error=error):
                self.setUp()
                if error is None:
                    self.socket.partial.add(sequence)
                else:
                    self.socket.errors[sequence] = error
                with self.assertRaises(RuntimeError if error is None else OSError):
                    self.run_probe()
                self.assertEqual(len(self.socket.attempts), sequence + 1)
                self.assert_once_only_sequences()
                self.assertEqual(self.socket.closes, 1)
                self.output.assert_not_called()

    def test_unschedulable_load_is_rejected_before_socket_creation(self):
        # This byte product is admissible, but its pacing cannot fit in 120s.
        with self.assertRaisesRegex(ValueError, "schedule exceeds"):
            self.run_probe(count=100_000, payload_bytes=64)
        self.factory.assert_not_called()
        self.output.assert_not_called()

    def test_short_load_deadline_omits_a_recovery_pause_that_is_never_reached(self):
        for count in (64, 65, 66):
            with self.subTest(count=count):
                self.setUp()
                self.run_probe(count=count, deadline=5.5)
                self.assertEqual(len(self.socket.attempts), count)
                self.assert_once_only_sequences()
                self.assertAlmostEqual(self.clock.now - 100, (count - 1) * 0.02 + 4.0)
                self.assertTrue(all(seconds == 0.02 for _, seconds in self.clock.sleeps[:-1]))
                self.output.assert_called_once()

    def test_whole_deadline_rejects_late_sleep_or_send_completion(self):
        for late_operation in ("sleep", "send"):
            with self.subTest(late_operation=late_operation):
                self.setUp()
                if late_operation == "sleep":
                    self.clock.oversleep[1] = 120.0
                else:
                    # Even an unexpectedly late successful syscall cannot
                    # bypass the total deadline when it returns to Python.
                    self.socket.delays[0] = 120.0
                with self.assertRaisesRegex(TimeoutError, "deadline expired"):
                    self.run_probe()
                self.assertEqual(len(self.socket.attempts), 1)
                self.assertEqual(self.socket.closes, 1)
                self.output.assert_not_called()

    def test_send_timeout_uses_remaining_deadline_and_settle_is_bounded(self):
        self.run_probe(deadline=17.0)
        self.assertAlmostEqual(self.socket.attempts[-1][4], 4.3)
        self.assertTrue(all(0 < row[4] <= 5.0 for row in self.socket.attempts))
        self.setUp()
        self.socket.delays[50] = 0.5
        with self.assertRaisesRegex(TimeoutError, "cannot finish its pause after 512 sends"):
            self.run_probe(deadline=17.0)
        self.assertEqual(len(self.socket.attempts), 512)
        self.assertEqual(self.socket.closes, 1)
        self.output.assert_not_called()

if __name__ == "__main__":
    unittest.main()
