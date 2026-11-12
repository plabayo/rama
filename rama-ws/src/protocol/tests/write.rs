use crate::{
    Message,
    protocol::{Role, WebSocket, WebSocketConfig, error::ProtocolError},
};
use std::assert_matches;
use std::io::{self, Cursor, Read, Write};

#[cfg(feature = "compression")]
use {
    crate::protocol::PerMessageDeflateConfig, rama_core::telemetry::tracing,
    tracing_test::traced_test,
};

pin_project_lite::pin_project! {
    struct WriteMoc<Stream> {
        #[pin]
        stream: Stream,
        written_bytes: usize,
        write_count: usize,
        flush_count: usize,
    }
}

impl<Stream> WriteMoc<Stream> {
    fn new(stream: Stream) -> Self {
        Self {
            stream,
            written_bytes: 0,
            write_count: 0,
            flush_count: 0,
        }
    }
}

impl<Stream: Read> Read for WriteMoc<Stream> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.stream.read(buf)
    }
}

impl<Stream> Write for WriteMoc<Stream> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = buf.len();
        self.written_bytes += n;
        self.write_count += 1;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.flush_count += 1;
        Ok(())
    }
}

#[test]
fn receive_messages() {
    let incoming = Cursor::new(vec![
        0x89, 0x02, 0x01, 0x02, 0x8a, 0x01, 0x03, 0x01, 0x07, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x2c,
        0x20, 0x80, 0x06, 0x57, 0x6f, 0x72, 0x6c, 0x64, 0x21, 0x82, 0x03, 0x01, 0x02, 0x03,
    ]);
    let mut socket = WebSocket::from_raw_socket(WriteMoc::new(incoming), Role::Client, None);
    assert_eq!(socket.read().unwrap(), Message::Ping(vec![1, 2].into()));
    assert_eq!(socket.read().unwrap(), Message::Pong(vec![3].into()));
    assert_eq!(
        socket.read().unwrap(),
        Message::Text("Hello, World!".into())
    );
    assert_eq!(
        socket.read().unwrap(),
        Message::Binary(vec![0x01, 0x02, 0x03].into())
    );
}

#[cfg(feature = "compression")]
#[test]
#[traced_test]
fn receive_compressed_hello_text_msg_rfc7692_example_compression_1() {
    let incoming = Cursor::new(vec![0xc1, 0x07, 0xf2, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00]);

    let mut socket = WebSocket::from_raw_socket(
        WriteMoc::new(incoming),
        Role::Client,
        Some(WebSocketConfig {
            per_message_deflate: Some(PerMessageDeflateConfig::default()),
            ..Default::default()
        }),
    );

    assert_eq!(socket.read().unwrap(), Message::Text("Hello".into()));
}

#[cfg(feature = "compression")]
#[test]
#[traced_test]
fn receive_compressed_hello_text_msg_rfc7692_example_compression_2() {
    #[rustfmt::skip]
    let incoming = Cursor::new(vec![
        0x41, 0x03, 0xf2, 0x48, 0xcd,       // fragment #1
        0x80, 0x04, 0xc9, 0xc9, 0x07, 0x00, // fragment #2
    ]);

    let mut socket = WebSocket::from_raw_socket(
        WriteMoc::new(incoming),
        Role::Client,
        Some(WebSocketConfig {
            per_message_deflate: Some(PerMessageDeflateConfig::default()),
            ..Default::default()
        }),
    );

    assert_eq!(socket.read().unwrap(), Message::Text("Hello".into()));
}

#[test]
fn size_limiting_text_fragmented() {
    let incoming = Cursor::new(vec![
        0x01, 0x07, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x2c, 0x20, 0x80, 0x06, 0x57, 0x6f, 0x72, 0x6c,
        0x64, 0x21,
    ]);
    let limit = WebSocketConfig {
        max_message_size: Some(10),
        ..WebSocketConfig::default()
    };
    let mut socket = WebSocket::from_raw_socket(WriteMoc::new(incoming), Role::Client, Some(limit));

    assert_matches!(
        socket.read(),
        Err(ProtocolError::MessageTooLong {
            size: 13,
            max_size: 10
        }),
    );
}

#[test]
fn size_limiting_binary() {
    let incoming = Cursor::new(vec![0x82, 0x03, 0x01, 0x02, 0x03]);
    let limit = WebSocketConfig {
        max_message_size: Some(2),
        ..WebSocketConfig::default()
    };
    let mut socket = WebSocket::from_raw_socket(WriteMoc::new(incoming), Role::Client, Some(limit));

    assert_matches!(
        socket.read(),
        Err(ProtocolError::MessageTooLong {
            size: 3,
            max_size: 2
        }),
    );
}

#[test]
fn server_write_flush_behaviour() {
    const SEND_ME_LEN: usize = 10;
    const BATCH_ME_LEN: usize = 11;
    const WRITE_BUFFER_SIZE: usize = 600;

    let mut ws = WebSocket::from_raw_socket(
        WriteMoc::new(Cursor::new(Vec::default())),
        Role::Server,
        Some(WebSocketConfig::default().with_write_buffer_size(WRITE_BUFFER_SIZE)),
    );

    assert_eq!(ws.get_ref().written_bytes, 0);
    assert_eq!(ws.get_ref().write_count, 0);
    assert_eq!(ws.get_ref().flush_count, 0);

    // `send` writes & flushes immediately
    ws.send(Message::Text("Send me!".into())).unwrap();
    assert_eq!(ws.get_ref().written_bytes, SEND_ME_LEN);
    assert_eq!(ws.get_ref().write_count, 1);
    assert_eq!(ws.get_ref().flush_count, 1);

    // send a batch of messages
    for msg in (0..100).map(|_| Message::Text("Batch me!".into())) {
        ws.write(msg).unwrap();
    }
    // after 55 writes the out_buffer will exceed write_buffer_size=600
    // and so do a single underlying write (not flushing).
    assert_eq!(ws.get_ref().written_bytes, 55 * BATCH_ME_LEN + SEND_ME_LEN);
    assert_eq!(ws.get_ref().write_count, 2);
    assert_eq!(ws.get_ref().flush_count, 1);

    // flushing will perform a single write for the remaining out_buffer & flush.
    ws.flush().unwrap();
    assert_eq!(ws.get_ref().written_bytes, 100 * BATCH_ME_LEN + SEND_ME_LEN);
    assert_eq!(ws.get_ref().write_count, 3);
    assert_eq!(ws.get_ref().flush_count, 2);
}

// Deflate bomb: the compressed payload is small but decompresses to far more
// than max_message_size.  Both code paths (single-frame and fragmented) must
// check the *decompressed* length, not the wire length.

/// Compress `data` using raw DEFLATE + SYNC_FLUSH, stripping the 4-byte
/// sync-flush trailer, exactly as the per_message_deflate encoder does.
#[cfg(feature = "compression")]
fn raw_deflate_compress(data: &[u8]) -> Vec<u8> {
    use flate2::{Compress, Compression, FlushCompress, Status};
    let mut c = Compress::new_with_window_bits(Compression::default(), false, 15);
    let mut buf: Vec<u8> = Vec::with_capacity(data.len());
    let before = c.total_in();
    // Process all input bytes.
    while c.total_in() - before < data.len() as u64 {
        buf.reserve(128);
        match c
            .compress_vec(
                &data[(c.total_in() - before) as usize..],
                &mut buf,
                FlushCompress::Sync,
            )
            .unwrap()
        {
            Status::BufError => buf.reserve(buf.len()),
            Status::Ok | Status::StreamEnd => {}
        }
    }
    // Flush until the sync-flush trailer appears.
    while !buf.ends_with(&[0x00, 0x00, 0xff, 0xff]) {
        buf.reserve(8);
        match c.compress_vec(&[], &mut buf, FlushCompress::Sync).unwrap() {
            Status::BufError => buf.reserve(buf.len()),
            Status::Ok | Status::StreamEnd => {}
        }
    }
    buf.truncate(buf.len() - 4); // strip trailer
    buf
}

/// Build a single-frame WebSocket binary message with RSV1=1 (compressed).
#[cfg(feature = "compression")]
fn ws_frame_compressed_binary(payload: &[u8]) -> Vec<u8> {
    assert!(payload.len() < 126, "test helper only handles short frames");
    let mut frame = vec![
        0xC2, // FIN=1, RSV1=1, opcode=2 (binary)
        payload.len() as u8,
    ];
    frame.extend_from_slice(payload);
    frame
}

#[cfg(feature = "compression")]
#[test]
fn deflate_bomb_single_frame_rejected() {
    // 500 identical bytes compress to ~20 bytes but decompress back to 500.
    const PLAIN_LEN: usize = 500;
    let compressed = raw_deflate_compress(&vec![b'A'; PLAIN_LEN]);
    // max_size is above the wire payload (no false positive from the compressed-length
    // pre-check) but well below the decompressed length.
    let max_size = compressed.len() + 50;
    assert!(
        max_size < PLAIN_LEN,
        "test invariant: max_size must be less than decompressed size"
    );

    let incoming = Cursor::new(ws_frame_compressed_binary(&compressed));
    let limit = WebSocketConfig {
        per_message_deflate: Some(PerMessageDeflateConfig::default()),
        max_message_size: Some(max_size),
        ..Default::default()
    };
    let mut socket = WebSocket::from_raw_socket(WriteMoc::new(incoming), Role::Client, Some(limit));
    match socket.read() {
        Err(ProtocolError::MessageTooLong {
            size,
            max_size: reported_max,
        }) => {
            assert_eq!(reported_max, max_size);
            assert!(size > reported_max);
            assert!(size < PLAIN_LEN);
        }
        result => panic!("expected compressed payload to exceed decoded size limit: {result:?}"),
    }
}

#[cfg(feature = "compression")]
#[test]
fn deflate_bomb_fragmented_rejected() {
    // Same 500-byte bomb, split into two compressed fragments.
    const PLAIN_LEN: usize = 500;
    let compressed = raw_deflate_compress(&vec![b'A'; PLAIN_LEN]);
    let max_size = compressed.len() + 50;
    assert!(
        max_size < PLAIN_LEN,
        "test invariant: max_size must be less than decompressed size"
    );

    let mid = compressed.len() / 2;
    let (frag1, frag2) = compressed.split_at(mid);

    let mut frame_bytes = Vec::new();
    // Fragment 1: FIN=0, RSV1=1, opcode=2 (binary)
    frame_bytes.push(0x42);
    frame_bytes.push(frag1.len() as u8);
    frame_bytes.extend_from_slice(frag1);
    // Fragment 2: FIN=1, RSV1=0, opcode=0 (continuation)
    frame_bytes.push(0x80);
    frame_bytes.push(frag2.len() as u8);
    frame_bytes.extend_from_slice(frag2);

    let incoming = Cursor::new(frame_bytes);
    let limit = WebSocketConfig {
        per_message_deflate: Some(PerMessageDeflateConfig::default()),
        max_message_size: Some(max_size),
        ..Default::default()
    };
    let mut socket = WebSocket::from_raw_socket(WriteMoc::new(incoming), Role::Client, Some(limit));
    match socket.read() {
        Err(ProtocolError::MessageTooLong {
            size,
            max_size: reported_max,
        }) => {
            assert_eq!(reported_max, max_size);
            assert!(size > reported_max);
            assert!(size < PLAIN_LEN);
        }
        result => panic!("expected compressed payload to exceed decoded size limit: {result:?}"),
    }
}

/// Frames as a server sends them: `first` is the byte holding FIN, RSV1 and the opcode.
#[cfg(feature = "compression")]
fn server_frames(frames: &[(u8, &[u8])]) -> Cursor<Vec<u8>> {
    let mut wire = Vec::new();
    for (first, payload) in frames {
        wire.push(*first);
        wire.push(payload.len() as u8);
        wire.extend_from_slice(payload);
    }
    Cursor::new(wire)
}

#[cfg(feature = "compression")]
fn deflate_reader(incoming: Cursor<Vec<u8>>) -> WebSocket<WriteMoc<Cursor<Vec<u8>>>> {
    let config = WebSocketConfig {
        per_message_deflate: Some(PerMessageDeflateConfig::default()),
        ..Default::default()
    };
    WebSocket::from_raw_socket(WriteMoc::new(incoming), Role::Client, Some(config))
}

/// A data frame may not start while a compressed message is still being continued, whether
/// the newcomer is compressed or not: neither is delivered inside the other, nor replaces it.
#[cfg(feature = "compression")]
#[test]
fn a_data_frame_inside_a_compressed_fragmented_message_is_refused() {
    let compressed = raw_deflate_compress(b"compressed");
    let (head, tail) = compressed.split_at(compressed.len() / 2);
    // FIN text, then non-final compressed text, then a final continuation.
    for interloper in [(0x81, b"plain".as_slice()), (0x41, head)] {
        let mut socket = deflate_reader(server_frames(&[(0x41, head), interloper, (0x80, tail)]));
        assert!(matches!(
            socket.read(),
            Err(ProtocolError::ExpectedFragment(_))
        ));
    }
}

/// A continuation with no message to continue is refused when it arrives, not once it ends.
#[cfg(feature = "compression")]
#[test]
fn a_continuation_of_nothing_is_refused_before_it_is_buffered() {
    for first in [0x00, 0x80] {
        let mut socket = deflate_reader(server_frames(&[(first, b"orphan")]));
        assert!(matches!(
            socket.read(),
            Err(ProtocolError::UnexpectedContinueFrame)
        ));
    }
}

/// RSV2 and RSV3 stay reserved on a compressed frame: only RSV1 was negotiated.
#[cfg(feature = "compression")]
#[test]
fn reserved_bits_beside_the_compression_bit_are_refused() {
    let compressed = raw_deflate_compress(b"compressed");
    // FIN and RSV1 with RSV2, with RSV3, and without either.
    for (first, refused) in [(0xE1, true), (0xD1, true), (0xC1, false)] {
        let mut socket = deflate_reader(server_frames(&[(first, &compressed)]));
        assert_eq!(
            matches!(socket.read(), Err(ProtocolError::NonZeroReservedBits)),
            refused,
            "{first:#x}"
        );
    }
}
