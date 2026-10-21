"""Regression checks for capture decoding and ephemeral-key cleanup."""
import csv
import io
import subprocess
import sys
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import quic_relay


class WireOracleTests(unittest.TestCase):
    def rows(self):
        common = {
            'udp.srcport': '1234', 'udp.payload': 'origin-initial',
            'tls.handshake.type': '1', 'tls.handshake.extensions_alpn_str': 'h3',
            'http3.headers.status': '200', 'http3.settings.id': '1',
            'http3.header.header.name': 'x-rama-mitm',
            'http3.headers.header.value': 'h3',
        }
        return [dict(common, **{'udp.dstport': '40000'}),
                dict(common, **{'udp.dstport': '40001', 'udp.payload': 'client-initial',
                                'http3.header.header.name': '', 'http3.headers.header.value': ''})]

    def test_comma_in_preceding_header_value_does_not_shift_marker(self):
        rows = self.rows()
        delimiter = quic_relay.OCCURRENCE_SEPARATOR
        rows[0]['http3.header.header.name'] = delimiter.join(['alt-svc', 'x-rama-mitm'])
        rows[0]['http3.headers.header.value'] = delimiter.join(['h3=":443", h3-29=":443"', 'h3'])
        self.assertTrue(quic_relay.check(rows, 'terminated', 40000, 40001)['passed'])

    def test_quoted_fields_preserve_occurrences_and_embedded_separators(self):
        rows = self.rows()
        delimiter = quic_relay.OCCURRENCE_SEPARATOR
        rows[0]['http3.header.header.name'] = delimiter.join(['alt-svc', 'x-rama-mitm'])
        rows[0]['http3.headers.header.value'] = delimiter.join(['h3=":443",\th3-29=":443"', 'h3'])
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=list(rows[0]), delimiter='\t', quoting=csv.QUOTE_ALL)
        writer.writeheader()
        writer.writerows(rows)
        decoded = quic_relay.decode_rows(output.getvalue())
        self.assertEqual(decoded, rows)
        self.assertTrue(quic_relay.check(decoded, 'terminated', 40000, 40001)['passed'])

    def test_unrelated_h3_value_cannot_supply_marker(self):
        rows = self.rows()
        rows[0]['http3.header.header.name'] = 'alt-svc'
        with self.assertRaisesRegex(AssertionError, 'no relay marker'):
            quic_relay.check(rows, 'terminated', 40000, 40001)

    def test_origin_private_key_is_removed_when_openssl_fails(self):
        with tempfile.TemporaryDirectory() as root:
            output = Path(root)/'capture'
            def failing_run(command, **_kwargs):
                key = Path(command[command.index('-keyout') + 1])
                key.write_text('synthetic private key')
                raise subprocess.CalledProcessError(1, command)
            with mock.patch.object(sys, 'argv', ['quic_relay.py', '--bin-dir', root, '--output', str(output)]), \
                    mock.patch.object(quic_relay, 'require_capture_environment') as admit, \
                    mock.patch.object(quic_relay, 'run', side_effect=failing_run):
                with self.assertRaises(subprocess.CalledProcessError):
                    quic_relay.main()
            admit.assert_called_once_with('lo0' if sys.platform == 'darwin' else 'lo', output.resolve())
            self.assertFalse((output/'origin-key.pem').exists())

    def test_failed_capture_admission_prevents_key_and_process_creation(self):
        with tempfile.TemporaryDirectory() as root:
            output = Path(root)/'capture'
            with mock.patch.object(sys, 'argv', ['quic_relay.py', '--bin-dir', root, '--output', str(output)]), \
                    mock.patch.object(quic_relay, 'require_capture_environment', side_effect=RuntimeError('unsafe capture')), \
                    mock.patch.object(quic_relay, 'run') as run:
                with self.assertRaisesRegex(RuntimeError, 'unsafe capture'):
                    quic_relay.main()
            run.assert_not_called()
            self.assertFalse((output/'origin-key.pem').exists())


if __name__ == '__main__':
    unittest.main()
