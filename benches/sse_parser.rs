#![expect(
    clippy::expect_used,
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
const CRLF_CHUNK_SIZES: &[usize] = &[512, 64 * 1024, 0];

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

fn encoded_stream_crlf() -> &'static [u8] {
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
                encoded.extend_from_slice(b"\r\n");
            }
            encoded.extend_from_slice(b"\r\n");
        }
        encoded
    })
}

fn chunks_for(chunk_size: usize) -> Vec<Bytes> {
    chunks_for_encoded(encoded_stream(), chunk_size)
}

fn chunks_for_encoded(encoded: &[u8], chunk_size: usize) -> Vec<Bytes> {
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

/// Minimal single-future block-on. The in-memory decoder can cooperatively
/// yield between bounded batches, but never waits on external I/O.
fn pollster_block_on<F: Future>(fut: F) -> F::Output {
    use std::task::{Context, Poll, Waker};
    let mut fut = std::pin::pin!(fut);
    let mut cx = Context::from_waker(Waker::noop());
    loop {
        if let Poll::Ready(out) = fut.as_mut().poll(&mut cx) {
            return out;
        }
        std::hint::spin_loop();
    }
}

#[divan::bench(args = CHUNK_SIZES, sample_count = 30)]
fn sse_decode(bencher: divan::Bencher, chunk_size: usize) {
    let chunks = chunks_for(chunk_size);
    bencher
        .counter(BytesCount::new(encoded_stream().len()))
        .bench_local(|| pollster_block_on(decode(black_box(&chunks))));
}

/// CRLF coverage for the branch that handles split and paired terminators.
#[divan::bench(args = CRLF_CHUNK_SIZES, sample_count = 30)]
fn sse_decode_crlf(bencher: divan::Bencher, chunk_size: usize) {
    let encoded = encoded_stream_crlf();
    let chunks = chunks_for_encoded(encoded, chunk_size);
    bencher
        .counter(BytesCount::new(encoded.len()))
        .bench_local(|| pollster_block_on(decode(black_box(&chunks))));
}

/// the server-side counterpart: serialize (encode) events, measuring
/// `Event::serialize` incl. the `data: ` line-prefix writer
mod encode {
    use super::*;
    use rama::http::StreamingBody as _;
    use rama::http::sse::Event;
    use rama::http::sse::server::SseResponseBody;
    use std::pin::Pin;
    use std::task::{Context, Poll, Waker};

    fn event_multiline() -> Event<String> {
        let mut line = String::new();
        for i in 0..LINE_LEN {
            line.push(char::from(b'a' + ((i * 7) % 26) as u8));
        }
        Event::new().with_data(vec![line.as_str(); LINES].join("\n"))
    }

    fn event_single_line() -> Event<String> {
        let mut data = String::new();
        for i in 0..(LINES * (LINE_LEN + 1) - 1) {
            data.push(char::from(b'a' + ((i * 7) % 26) as u8));
        }
        Event::new().with_data(data)
    }

    fn serialize(
        body: &mut SseResponseBody<
            impl rama::futures::Stream<Item = Result<Event<String>, Infallible>> + Unpin,
        >,
    ) -> usize {
        let mut cx = Context::from_waker(Waker::noop());
        let mut total = 0;
        while let Poll::Ready(Some(frame)) = Pin::new(&mut *body).poll_frame(&mut cx) {
            total += frame
                .expect("serialize event")
                .into_data()
                .expect("data frame")
                .len();
        }
        total
    }

    fn encoded_len(event: &Event<String>) -> usize {
        let mut body = SseResponseBody::new(stream::iter([Ok::<_, Infallible>(event.clone())]));
        serialize(&mut body)
    }

    /// 100 gigantic events with 3,000-line payloads (the decoder workload,
    /// reversed): stresses the per-line `data: ` prefix insertion
    #[divan::bench(sample_count = 30)]
    fn sse_encode_multiline(bencher: divan::Bencher) {
        let event = event_multiline();
        let total: usize = EVENTS * encoded_len(&event);
        bencher.counter(BytesCount::new(total)).bench_local(|| {
            let mut body = SseResponseBody::new(stream::iter(
                std::iter::repeat_n(event.clone(), EVENTS).map(Ok::<_, Infallible>),
            ));
            black_box(serialize(black_box(&mut body)))
        });
    }

    /// 100 events carrying the same bytes as one single-line payload:
    /// stresses the raw copy path without prefix insertions
    #[divan::bench(sample_count = 30)]
    fn sse_encode_single_line(bencher: divan::Bencher) {
        let event = event_single_line();
        let total: usize = EVENTS * encoded_len(&event);
        bencher.counter(BytesCount::new(total)).bench_local(|| {
            let mut body = SseResponseBody::new(stream::iter(
                std::iter::repeat_n(event.clone(), EVENTS).map(Ok::<_, Infallible>),
            ));
            black_box(serialize(black_box(&mut body)))
        });
    }
}
