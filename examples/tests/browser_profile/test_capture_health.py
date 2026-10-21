"""Unreadable QUIC is capture evidence failure, not an unsupported browser flow."""

import json
from pathlib import Path
import tempfile
import unittest

from capture_health import decoding_health, require_quic_decoding


def packet(number=1, issue="quic.decryption_failed"):
    return f'''<packet><proto name="quic"/><field name="frame.number" show="{number}"/>
    <field name="udp.length" show="8217"/><field name="{issue}"/>
    <field name="_ws.expert.message" show="secret-cookie-and-header"/>
    <field name="http3.header.header.name" show="authorization"/>
    <field name="http3.headers.header.value" show="private-token"/></packet>'''


class HealthTests(unittest.TestCase):
    def test_real_failure_shapes_are_classified_without_leaking_values(self):
        data = ("<pdml>" + packet() + packet(2, "quic.connection.unknown") + "</pdml>").encode()
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "headers.diagnostics.json"
            with self.assertRaisesRegex(ValueError, "undecodable QUIC packet evidence.*decryption_failed=1.*unknown_connection=1"):
                require_quic_decoding(data, report)
            text = report.read_text()
            for private in ("secret-cookie", "authorization", "private-token"):
                self.assertNotIn(private, text)
            health = json.loads(text)
            self.assertFalse(health["no_reported_quic_errors"])
            self.assertEqual(health["samples"][0]["udp_lengths"], [8217])

    def test_no_false_failure_for_qpack_blocking_or_non_quic_experts(self):
        for issue in ("http3.header.qpack.blocked", "tcp.analysis.retransmission", "quic.coalesced_padding_data"):
            with self.subTest(issue=issue):
                self.assertTrue(decoding_health(("<pdml>" + packet(issue=issue) + "</pdml>").encode())["no_reported_quic_errors"])

    def test_sample_limit_does_not_hide_total_errors(self):
        health = decoding_health(("<pdml>" + "".join(packet(i) for i in range(100)) + "</pdml>").encode())
        self.assertEqual(health["issues"]["decryption_failed"], 100)
        self.assertEqual(len(health["samples"]), 16)

    def test_numeric_fields_cannot_smuggle_arbitrary_text(self):
        health = decoding_health(("<pdml>" + packet('secret-token') + "</pdml>").encode())
        self.assertEqual(health["samples"][0]["packet"], [])
        self.assertNotIn("secret-token", json.dumps(health))

    def test_drain_keeps_decoder_failure_as_cause(self):
        from unittest.mock import MagicMock, patch
        from wire import drain_capture
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            capture, key = root/'wire.pcapng', root/'tls.keys'
            capture.write_bytes(b'')
            key.write_text('synthetic')
            process = MagicMock()
            process.poll.return_value = 0
            data = ('<pdml>' + packet() + '</pdml>').encode()
            def decode(*args, **kwargs):
                kwargs['stdout'].write(data)
            with patch('wire.subprocess.run', side_effect=decode), self.assertRaisesRegex(
                RuntimeError, 'incomplete independently decoded capture'
            ) as caught:
                drain_capture(process, capture=capture, keylog=key, protocol='h3',
                              server_port=443, output=root/'headers.pdml')
            self.assertIn('undecodable QUIC', str(caught.exception.__cause__))
            self.assertTrue((root/'headers.diagnostics.json').exists())

    def test_admission_status_is_bounded_and_reported(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'capture-environment.json').write_text('{"status":"passed"}')
            with self.assertRaisesRegex(ValueError, 'admission=passed'):
                require_quic_decoding(('<pdml>' + packet() + '</pdml>').encode(), root/'health.json')
