"""Read only pcapng interface statistics; never expose packet contents."""

import struct

from pdml import MAX_CAPTURE_BYTES


def capture_drops(path):
    """Return observed cumulative if_drop counters, or explicitly unavailable.

    Live captures may end in an incomplete block and may not yet contain ISBs.
    Each section has its own interface IDs. Repeated ISBs are cumulative, so
    retain the maximum per interface instead of summing repeated snapshots.
    """
    counters = {}
    section = -1
    endian = None
    consumed = 0
    with path.open('rb') as stream:
        while True:
            header = stream.read(12)
            if len(header) < 12:
                break
            if header[:4] == b'\x0a\x0d\x0d\x0a':
                magic = header[8:12]
                if magic not in (b'\x4d\x3c\x2b\x1a', b'\x1a\x2b\x3c\x4d'):
                    raise ValueError('invalid pcapng byte order')
                endian = '<' if magic[0] == 0x4d else '>'
                section += 1
            elif endian is None:
                # Older pcap has no interface statistics blocks.
                return dict(status='unavailable', reported_drops=None)
            kind, size = struct.unpack(endian + 'II', header[:8])
            if size < 16 or size % 4 or consumed + size > MAX_CAPTURE_BYTES:
                raise ValueError('invalid or oversized pcapng block')
            consumed += size
            if kind != 5:  # Interface Statistics Block
                stream.seek(size - 12, 1)
                continue
            # An ISB has interface ID and timestamp, then padded options.
            if size > 65536:
                raise ValueError('pcapng statistics block limit exceeded')
            tail = stream.read(size - 12)
            if len(tail) != size - 12:
                break
            block = header + tail
            if size < 24 or struct.unpack(endian + 'I', block[-4:])[0] != size:
                raise ValueError('invalid pcapng statistics block')
            interface = struct.unpack(endian + 'I', block[8:12])[0]
            offset = 20
            while offset + 4 <= size - 4:
                code, length = struct.unpack(endian + 'HH', block[offset:offset + 4])
                offset += 4
                if code == 0:
                    break
                if offset + length > size - 4:
                    raise ValueError('invalid pcapng statistics option')
                if code == 5:  # isb_ifdrop: unsigned 64-bit counter
                    if length != 8:
                        raise ValueError('invalid pcapng drop counter')
                    count = struct.unpack(endian + 'Q', block[offset:offset + 8])[0]
                    key = (section, interface)
                    counters[key] = max(counters.get(key, 0), count)
                offset += (length + 3) & ~3
    return dict(status='reported' if counters else 'unavailable',
                reported_drops=sum(counters.values()) if counters else None)
