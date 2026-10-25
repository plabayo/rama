import struct
import tempfile
from pathlib import Path
import unittest

from capture_drops import capture_drops
from capture_health import require_quic_decoding


def block(kind, body, endian='<'):
    size = len(body) + 12
    return struct.pack(endian + 'II', kind, size) + body + struct.pack(endian + 'I', size)


def section(endian='<'):
    return block(0x0a0d0d0a, struct.pack(endian + 'IHHq', 0x1a2b3c4d, 1, 0, -1), endian)


def statistics(count, endian='<', interface=0):
    body = struct.pack(endian + 'IIIHHQHH', interface, 0, 0, 5, 8, count, 0, 0)
    return block(5, body, endian)


class DropTests(unittest.TestCase):
    def read(self, data):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'capture.pcapng'
            path.write_bytes(data)
            return capture_drops(path)

    def test_unavailable_is_not_zero(self):
        for data in (b'', b'legacy pcap header', section(), section() + statistics(4)[:16]):
            self.assertEqual(self.read(data)['reported_drops'], None)
        self.assertEqual(self.read(section() + statistics(0))['reported_drops'], 0)

    def test_cumulative_interfaces_and_sections_in_both_byte_orders(self):
        data = section() + statistics(3) + statistics(3) + statistics(1, interface=1)
        data += section('>') + statistics(2, '>')
        self.assertEqual(self.read(data)['reported_drops'], 6)

    def test_drop_is_rejected_even_when_remaining_packets_decode(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            capture = root / 'wire.pcapng'
            capture.write_bytes(section() + statistics(2))
            with self.assertRaisesRegex(ValueError, 'capture dropped packets'):
                require_quic_decoding(b'<pdml/>', root/'health.json', capture=capture)
            self.assertIn('"reported_drops": 2', (root/'health.json').read_text())

    def test_oversized_blocks_fail_without_allocation(self):
        with self.assertRaisesRegex(ValueError, 'oversized'):
            self.read(section() + struct.pack('<III', 5, 0xfffffff0, 0))
