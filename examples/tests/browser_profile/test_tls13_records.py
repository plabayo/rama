"""Published TLS1.3 vector plus authenticated padding and capture-binding controls."""

from copy import deepcopy
import hashlib
from pathlib import Path
import tempfile
import unittest

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from tls13_records import decrypt_record, application_witness
from tcp_evidence import inventory, reassemble, decoded_records
from test_tcp_evidence import fixture, field, account, PORT
import xml.etree.ElementTree as ET

# RFC 8448 section 3 client application traffic secret, key, IV and first record.
SECRET = bytes.fromhex('9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5')
KEY = bytes.fromhex('17422dda596ed5d9acd890e3c63f5051')
IV = bytes.fromhex('5b78923dee08579033e523d9')
RECORD = bytes.fromhex('1703030043a23f7054b62c94d0affafe8228ba55cbefacea42f914aa66bcab3f2b9819a8a5b46b395bd54a9a20441e2b62974e1f5a6292a2977014bd1e3deae63aeebb21694915e4')


def encrypted(content, padding, sequence=0, kind=23):
    inner = content + bytes([kind]) + bytes(padding)
    header = b'\x17\x03\x03' + (len(inner) + 16).to_bytes(2, 'big')
    nonce = bytes(a ^ b for a, b in zip(IV, sequence.to_bytes(12, 'big')))
    return header + AESGCM(KEY).encrypt(nonce, inner, header)


class RecordTests(unittest.TestCase):
    def test_rfc8448_client_application_record(self):
        self.assertEqual(decrypt_record(RECORD, SECRET, 0x1301, 0), (bytes(range(50)), 0))

    def test_padding_does_not_consume_application_zero_bytes(self):
        for content in (b'', b'payload\0\0', bytes(range(255))):
            for padding in (0, 1, 255, 1024):
                raw = encrypted(content, padding, 257)
                self.assertEqual(decrypt_record(raw, SECRET, 0x1301, 257), (content, padding))

    def test_authenticated_inner_plaintext_limit_includes_padding(self):
        for content, padding in ((b"x" * (1 << 14), 0), (b"x", (1 << 14) - 1)):
            self.assertEqual(decrypt_record(encrypted(content, padding), SECRET, 0x1301, 0), (content, padding))
            with self.assertRaisesRegex(ValueError, "inner plaintext exceeds"):
                decrypt_record(encrypted(content, padding + 1), SECRET, 0x1301, 0)

    def test_ciphertext_key_sequence_and_inner_type_are_authenticated(self):
        raw = encrypted(b'payload', 128)
        for changed, secret, sequence in (
            (raw[:-1] + bytes([raw[-1] ^ 1]), SECRET, 0),
            (raw, bytes(32), 0), (raw, SECRET, 1),
            (encrypted(b'payload', 1, kind=22), SECRET, 0),
            (raw[:-1], SECRET, 0),
        ):
            with self.assertRaises(ValueError):
                decrypt_record(changed, secret, 0x1301, sequence)

    def padded_capture(self):
        root, evidence = fixture()
        record = root[3].find("proto/field[@name='tls.record']")
        hello = field(record, 'tls.handshake')
        field(hello, 'tls.handshake.type', 1)
        field(hello, 'tls.handshake.random', raw=bytes(32))
        for index, padding in ((5, 71), (6, 93)):
            packet = root[index]
            app = b''.join(bytes.fromhex(node.get('value')) for node in packet.findall("proto[@name='http2']/field") if node.get('value'))
            # The preface is represented by a child field in the native fixture.
            if index == 5:
                from tcp_evidence import PREFACE
                app = PREFACE + app
            raw = encrypted(app, padding)
            for name, size in [('tcp.len', len(raw)), ('frame.cap_len', 54 + len(raw)), ('frame.len', 54 + len(raw))]:
                packet.find(f"field[@name='{name}']").set('show', str(size))
            payload = packet.find("field[@name='tcp.payload']")
            payload.set('value', raw.hex())
            payload.set('size', str(len(raw)))
            proto = packet.find("proto[@name='tls']")
            proto.set('size', str(len(raw)))
            record = proto.find("field[@name='tls.record']")
            record.set('size', str(len(raw)))
            record.find("field[@name='tls.record.length']").set('show', str(len(raw) - 5))
            final = root[index + 2].find("field[@name='tcp.seq']")
            final.set('show', str(int(final.get('show')) + padding))
        rows = inventory(ET.tostring(root), PORT)[0]
        bodies = {side: reassemble(rows, side)[0] for side in (False, True)}
        with tempfile.TemporaryDirectory() as temporary:
            keylog = Path(temporary) / 'keys'
            keylog.write_text(''.join(f'{side}_TRAFFIC_SECRET_0 {bytes(32).hex()} {SECRET.hex()}\n' for side in ('CLIENT', 'SERVER')))
            witness = application_witness(rows, bodies, decoded_records(rows, bodies), keylog)
        evidence['revision'] = 2
        evidence['connections'][0]['authenticated_application'] = witness
        return root, evidence

    def test_padded_capture_preserves_exhaustive_h2_accounting(self):
        root, evidence = self.padded_capture()
        result = account(root, evidence)['connections'][0]
        self.assertTrue(result['native_h2_frames_complete'])
        self.assertEqual(result['application_padding_bytes'], 164)

    def test_witness_cannot_hide_missing_records_or_changed_follow_bytes(self):
        root, original = self.padded_capture()
        for change in ('missing', 'extra', 'padding', 'ciphertext', 'sequence', 'follow'):
            evidence = deepcopy(original)
            item = evidence['connections'][0]
            records = item['authenticated_application']['records']
            if change == 'missing':
                records.pop()
            elif change == 'extra':
                records.append(dict(records[0]))
            elif change == 'padding':
                records[0]['padding_bytes'] += 1
            elif change == 'ciphertext':
                records[0]['ciphertext_sha256'] = '0' * 64
            elif change == 'sequence':
                records[0]['sequence'] += 1
            else:
                item['client']['sha256'] = hashlib.sha256(b'wrong').hexdigest()
            with self.subTest(change=change), self.assertRaises(ValueError):
                account(root, evidence)
