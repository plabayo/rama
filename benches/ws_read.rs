#![expect(clippy::unwrap_used, reason = "bench: fail on setup or frame errors")]

//! Adaptive reads with alternating small/large frames and slow consumers.
//! Compare 4 KiB and the former 128 KiB initial read buffer, including allocation
//! counts. Frames are received through 1 KiB reads or an unconstrained cursor.

use divan::{black_box, counter::BytesCount};
use rama::http::ws::{
    Message,
    protocol::{Role, WebSocket, WebSocketConfig},
};
use std::io::{self, Cursor, Read, Write};

mod bench_alloc;

struct Chunked {
    wire: Cursor<Vec<u8>>,
    chunk: usize,
}
impl Read for Chunked {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let len = self.chunk.min(buf.len());
        self.wire.read(&mut buf[..len])
    }
}
impl Write for Chunked {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::ErrorKind::WouldBlock.into())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn main() {
    divan::main();
}

const CASES: &[(usize, usize, bool)] = &[
    (4096, 1024, false),
    (131_072, 1024, false),
    (4096, usize::MAX, false),
    (131_072, usize::MAX, false),
    (4096, 1024, true),
    (131_072, 1024, true),
    (4096, usize::MAX, true),
    (131_072, usize::MAX, true),
];

#[divan::bench(args = CASES, sample_count = 30)]
fn alternating_frames(bencher: divan::Bencher, (initial, chunk, retain): (usize, usize, bool)) {
    const PAIRS: usize = 8;
    const SMALL: usize = 1024;
    const LARGE: usize = 256 * 1024;
    let mut writer = WebSocket::from_raw_socket(Cursor::new(Vec::new()), Role::Server, None);
    for _ in 0..PAIRS {
        for len in [SMALL, LARGE] {
            writer
                .send(Message::Binary(vec![0x5a; len].into()))
                .unwrap();
        }
    }
    let wire = writer.get_ref().get_ref();
    bencher
        .counter(BytesCount::new(PAIRS * (SMALL + LARGE)))
        .with_inputs(|| {
            WebSocket::from_raw_socket(
                Chunked {
                    wire: Cursor::new(wire.clone()),
                    chunk,
                },
                Role::Client,
                Some(WebSocketConfig::default().with_read_buffer_size(initial)),
            )
        })
        .bench_local_values(|mut socket| {
            let mut held = Vec::new();
            for _ in 0..PAIRS {
                for len in [SMALL, LARGE] {
                    let frame = socket.read().unwrap();
                    assert_eq!(frame.len(), len);
                    if retain {
                        held.push(frame);
                    } else {
                        black_box(frame);
                    }
                }
            }
            black_box(held);
        });
}
