#![expect(
    clippy::expect_used,
    reason = "example/test/bench: panic-on-error is the standard pattern for harnesses"
)]

//! In-memory benchmark for the NDJSON read stream, decoupled from any
//! transport: lines of one JSON string each, short (100 bytes) and long
//! (10 KiB), fed at various chunk sizes. Items deserialize into
//! [`IgnoredAny`] so line splitting is not hidden behind value construction.

use divan::black_box;
use divan::counter::BytesCount;
use rama::bytes::Bytes;
use rama::futures::StreamExt as _;
use rama::futures::stream;
use rama::stream::json::JsonReadStream;
use serde::de::IgnoredAny;
use std::convert::Infallible;
use std::task::{Context, Poll, Waker};

mod bench_alloc;

const TOTAL_BYTES: usize = 8 * 1024 * 1024;
const LINE_LENS: &[usize] = &[100, 10 * 1024];
const CHUNK_SIZES: &[usize] = &[1024, 16 * 1024, 64 * 1024];

fn encoded(line_len: usize) -> (Vec<u8>, usize) {
    let mut line = Vec::with_capacity(line_len + 1);
    line.push(b'"');
    for i in 0..line_len - 2 {
        line.push(b'a' + ((i * 7) % 26) as u8);
    }
    line.extend_from_slice(b"\"\n");
    let lines = TOTAL_BYTES / line.len();
    (line.repeat(lines), lines)
}

fn chunks_for(encoded: &[u8], chunk_size: usize) -> Vec<Bytes> {
    encoded
        .chunks(chunk_size)
        .map(Bytes::copy_from_slice)
        .collect()
}

async fn decode(chunks: &[Bytes]) -> usize {
    let mut stream = std::pin::pin!(JsonReadStream::<IgnoredAny, _>::new(stream::iter(
        chunks.iter().cloned().map(Ok::<_, Infallible>),
    )));
    let mut count = 0;
    while let Some(item) = stream.next().await {
        black_box(item.expect("valid ndjson line"));
        count += 1;
    }
    count
}

/// Minimal single-future block-on: the in-memory stream never waits on I/O.
fn block_on<F: Future>(fut: F) -> F::Output {
    let mut fut = std::pin::pin!(fut);
    let mut cx = Context::from_waker(Waker::noop());
    loop {
        if let Poll::Ready(out) = fut.as_mut().poll(&mut cx) {
            return out;
        }
        std::hint::spin_loop();
    }
}

fn main() {
    // correctness preflight, outside any timing
    for line_len in LINE_LENS {
        let (encoded, lines) = encoded(*line_len);
        assert_eq!(lines, block_on(decode(&chunks_for(&encoded, 1024))));
    }

    divan::main();
}

#[divan::bench(args = CHUNK_SIZES, consts = [100, 10240], sample_count = 30)]
fn ndjson_decode<const LINE_LEN: usize>(bencher: divan::Bencher, chunk_size: usize) {
    let (encoded, _) = encoded(LINE_LEN);
    let chunks = chunks_for(&encoded, chunk_size);
    bencher
        .counter(BytesCount::new(encoded.len()))
        .bench_local(|| block_on(decode(black_box(&chunks))));
}
