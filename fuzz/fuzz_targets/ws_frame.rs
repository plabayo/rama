//! WebSocket frame and message decoding fuzz target.
//!
//! Goals: arbitrary bytes never panic the frame reader or the message
//! assembly of either role, with tight and default size limits.
//!
//! Run with:
//!     cargo +nightly fuzz run ws_frame -- -max_len=65536
#![no_main]

use libfuzzer_sys::fuzz_target;
use rama::http::ws::protocol::{Role, WebSocket, WebSocketConfig, frame::FrameSocket};
use std::io::{self, Cursor, Read, Write};

/// Reads the fuzz input in chunks sized by its first byte and discards writes.
struct Wire<'a> {
    input: Cursor<&'a [u8]>,
    step: usize,
}

impl Read for Wire<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let len = buf.len().min(self.step);
        self.input.read(&mut buf[..len])
    }
}

impl Write for Wire<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&step, input)) = data.split_first() else {
        return;
    };
    let wire = || Wire {
        input: Cursor::new(input),
        step: usize::from(step).max(1),
    };

    let mut frames = FrameSocket::new(wire());
    for _ in 0..1024 {
        match frames.read(Some(4096)) {
            Ok(Some(_frame)) => {}
            Ok(None) | Err(_) => break,
        }
    }

    for role in [Role::Server, Role::Client] {
        for config in [
            None,
            Some(
                WebSocketConfig::default()
                    .with_read_buffer_size(16)
                    .with_max_message_size(1024)
                    .with_max_frame_size(256),
            ),
        ] {
            let mut ws = WebSocket::from_raw_socket(wire(), role, config);
            for _ in 0..1024 {
                if ws.read().is_err() {
                    break;
                }
            }
        }
    }
});
