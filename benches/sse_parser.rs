#![expect(
    clippy::expect_used,
    clippy::unreachable,
    reason = "example/test/bench: panic-on-error is the standard pattern for harnesses"
)]

//! In-memory benchmark for the client-side SSE decoder ([`EventStream`]),
//! decoupled from HTTP transport: the `rust-sse-bench` "gigantic" workload
//! (100 events x 3,000 `data:` lines x 153 bytes = 46,199,900 payload bytes)
//! fed at various body-chunk sizes, measuring decoding plus full payload
//! materialization as `String`.

use divan::counter::BytesCount;
use divan::{AllocProfiler, black_box};
use rama::bytes::Bytes;
use rama::futures::StreamExt as _;
use rama::futures::stream;
use rama::http::sse::EventStream;
use std::convert::Infallible;
use std::sync::OnceLock;

#[global_allocator]
static ALLOC: AllocProfiler = AllocProfiler::system();

const EVENTS: usize = 100;
const LINES: usize = 3_000;
const LINE_LEN: usize = 153;
const TOTAL_PAYLOAD: usize = EVENTS * (LINES * (LINE_LEN + 1) - 1);

/// `0` stands for "the entire stream as a single chunk"
const CHUNK_SIZES: &[usize] = &[
    512,
    4 * 1024,
    16 * 1024,
    64 * 1024,
    128 * 1024,
    256 * 1024,
    512 * 1024,
    1024 * 1024,
    0,
];

fn encoded_stream() -> &'static [u8] {
    static ENCODED: OnceLock<Vec<u8>> = OnceLock::new();
    ENCODED.get_or_init(|| {
        let mut line = String::new();
        for i in 0..LINE_LEN {
            line.push(char::from(b'a' + ((i * 7) % 26) as u8));
        }
        let mut encoded = Vec::new();
        for _ in 0..EVENTS {
            for _ in 0..LINES {
                encoded.extend_from_slice(b"data: ");
                encoded.extend_from_slice(line.as_bytes());
                encoded.push(b'\n');
            }
            encoded.push(b'\n');
        }
        encoded
    })
}

fn chunks_for(chunk_size: usize) -> Vec<Bytes> {
    let encoded = encoded_stream();
    let chunk_size = if chunk_size == 0 {
        encoded.len()
    } else {
        chunk_size
    };
    encoded
        .chunks(chunk_size)
        .map(Bytes::copy_from_slice)
        .collect()
}

async fn decode(chunks: &[Bytes]) -> usize {
    let mut stream = EventStream::<_, String>::new(stream::iter(
        chunks.iter().cloned().map(Ok::<_, Infallible>),
    ));
    let mut total = 0;
    let mut count = 0;
    while let Some(event) = stream.next().await {
        let event = event.expect("valid sse event");
        if let Some(data) = event.data() {
            total += black_box(data.len());
        }
        count += 1;
    }
    assert_eq!(EVENTS, count);
    total
}

fn main() {
    // correctness preflight, outside any timing: exact reconstruction
    let chunks = chunks_for(64 * 1024);
    let total = pollster_block_on(decode(&chunks));
    assert_eq!(TOTAL_PAYLOAD, total);
    assert_eq!(46_199_900, total);

    divan::main();
}

/// minimal single-future block-on: the in-memory stream never returns
/// `Poll::Pending`, so no reactor or waker infrastructure is needed
fn pollster_block_on<F: Future>(fut: F) -> F::Output {
    use std::task::{Context, Poll, Waker};
    let mut fut = std::pin::pin!(fut);
    let mut cx = Context::from_waker(Waker::noop());
    // a single poll completes: the future never awaits anything that pends
    match fut.as_mut().poll(&mut cx) {
        Poll::Ready(out) => out,
        Poll::Pending => unreachable!("in-memory sse stream never pends"),
    }
}

#[divan::bench(args = CHUNK_SIZES, sample_count = 30)]
fn sse_decode(bencher: divan::Bencher, chunk_size: usize) {
    let chunks = chunks_for(chunk_size);
    bencher
        .counter(BytesCount::new(encoded_stream().len()))
        .bench_local(|| pollster_block_on(decode(black_box(&chunks))));
}
