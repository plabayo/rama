use crate::{
    Message,
    protocol::{Role, WebSocket, WebSocketConfig, error::ProtocolError},
};
use std::io::{self, Cursor, Read, Write};

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

    assert!(matches!(
        socket.read(),
        Err(ProtocolError::MessageTooLong {
            size: 13,
            max_size: 10
        })
    ));
}

#[test]
fn size_limiting_binary() {
    let incoming = Cursor::new(vec![0x82, 0x03, 0x01, 0x02, 0x03]);
    let limit = WebSocketConfig {
        max_message_size: Some(2),
        ..WebSocketConfig::default()
    };
    let mut socket = WebSocket::from_raw_socket(WriteMoc::new(incoming), Role::Client, Some(limit));

    assert!(matches!(
        socket.read(),
        Err(ProtocolError::MessageTooLong {
            size: 3,
            max_size: 2
        })
    ));
}

#[test]
fn server_write_flush_behaviour() {
    const SEND_ME_LEN: usize = 10;
    const BATCH_ME_LEN: usize = 11;
    const WRITE_BUFFER_SIZE: usize = 600;

    let mut ws = WebSocket::from_raw_socket(
        WriteMoc::new(Cursor::new(Vec::default())),
        Role::Server,
        Some(WebSocketConfig::default().write_buffer_size(WRITE_BUFFER_SIZE)),
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
