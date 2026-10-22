"""Regression from Safari's real H2 DATA chunks (no mocked browser or decoder)."""
import unittest
from websocket_tunnel import decode

# Safari 26.5.2, local credential-free echo fixture: compressed text, followed
# by a masked close split into header, mask, and payload DATA chunks.
CHUNKS = tuple(bytes.fromhex(value) for value in (
    'c1b902ef243928a5e874d6a20f694aa2eaf1b5bddc097d2d86b8c6e5ee7f14c6adf02b46b22f6b6932df14a9e2106b89c2df4b29ad50a46602bf64a6b23902',
    '888a', '3bea651c', '38020375558316745e8e',
))


class WebSocketTunnelTests(unittest.TestCase):
    def test_captured_safari_exchange(self):
        self.assertEqual(decode(b''.join(CHUNKS), False, ['permessage-deflate']),
                         ('rama-fp echo: ' + '🐢' * 32 + ' #28dacde98f187823df677b3af5a416b9',))

    def test_missing_close_bytes_wrong_mask_direction_and_extra_bytes_reject(self):
        complete = b''.join(CHUNKS)
        for data, side in ((complete[:-1], False), (complete, True), (complete + b'\0', False)):
            with self.subTest(side=side, length=len(data)), self.assertRaises(ValueError):
                decode(data, side, ['permessage-deflate'])
