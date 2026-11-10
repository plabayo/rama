#![expect(
    clippy::expect_used,
    clippy::print_stderr,
    reason = "bench: panic-on-error and print-for-output are the standard patterns for harnesses"
)]

//! In-memory benchmark for streamed response compression, decoupled from any
//! transport: text bodies go through the stream compression service, once as
//! a single data frame of various sizes and once as many small frames, back
//! to back or with the inner body pending between them.
//!
//! Before the timed runs, a `RESULT` line on stderr reports per case the
//! compressed size, the number of data frames, the largest data frame and
//! the longest single poll (the lowest of a few runs).

use divan::black_box;
use divan::counter::BytesCount;
use rama::Service;
use rama::bytes::Bytes;
use rama::http::body::{Frame, StreamingBody};
use rama::http::layer::compression::stream::StreamCompression;
use rama::http::{Body, Request, Response, header};
use rama::service::service_fn;
use rama::utils::octets::{kib, mib};
use std::collections::VecDeque;
use std::convert::Infallible;
use std::fmt;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

mod bench_alloc;

const SMALL_FRAMES: usize = 1000;
const SMALL_FRAME_LEN: usize = 256;

#[derive(Debug, Clone, Copy)]
enum Codec {
    Gzip,
    Deflate,
    Brotli,
    Zstd,
}

impl Codec {
    const ALL: [Self; 4] = [Self::Gzip, Self::Deflate, Self::Brotli, Self::Zstd];

    fn accept_encoding(self) -> &'static str {
        match self {
            Self::Gzip => "gzip",
            Self::Deflate => "deflate",
            Self::Brotli => "br",
            Self::Zstd => "zstd",
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct FullBody {
    codec: Codec,
    len: usize,
}

impl fmt::Display for FullBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.codec.accept_encoding(), self.len)
    }
}

#[derive(Debug, Clone, Copy)]
struct SmallFrames {
    codec: Codec,
    /// The inner body is pending once before every frame.
    paced: bool,
    /// The response carries a `content-length`, the one case without a flush per frame.
    sized: bool,
}

impl fmt::Display for SmallFrames {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}/{}/{}",
            self.codec.accept_encoding(),
            if self.paced { "paced" } else { "back_to_back" },
            if self.sized { "sized" } else { "unsized" },
        )
    }
}

fn full_body_cases() -> Vec<FullBody> {
    let mut cases = Vec::new();
    for codec in Codec::ALL {
        for len in [kib(64), mib(1), mib(8)] {
            cases.push(FullBody { codec, len });
        }
    }
    cases
}

fn small_frames_cases() -> Vec<SmallFrames> {
    let mut cases = Vec::new();
    for codec in Codec::ALL {
        for paced in [false, true] {
            for sized in [false, true] {
                cases.push(SmallFrames {
                    codec,
                    paced,
                    sized,
                });
            }
        }
    }
    cases
}

/// Text of `len` bytes drawn from a small vocabulary, about as compressible as markup.
fn text(len: usize) -> Bytes {
    const WORDS: &[&str] = &[
        "the",
        "response",
        "body",
        "stream",
        "frame",
        "header",
        "value",
        "request",
        "<div>",
        "</div>",
        "class=\"row\"",
        "id",
        "true",
        "false",
        "null",
        "{\"name\":",
        "\"status\":",
        "2026-11-10",
        "error",
        "ok",
        "42",
        "3.14159",
        "compression",
        "window",
        "\n",
    ];
    let mut state = 0x9e37_79b9_u32;
    let mut out = Vec::with_capacity(len + 16);
    while out.len() < len {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        out.extend_from_slice(WORDS[state as usize % WORDS.len()].as_bytes());
        out.push(b' ');
    }
    out.truncate(len);
    out.into()
}

/// Body that yields its frames one per poll, optionally pending once before each.
struct FramesBody {
    frames: VecDeque<Bytes>,
    paced: bool,
    pending_next: bool,
}

impl StreamingBody for FramesBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if self.paced && self.pending_next && !self.frames.is_empty() {
            self.pending_next = false;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        self.pending_next = true;
        Poll::Ready(self.frames.pop_front().map(|data| Ok(Frame::data(data))))
    }
}

/// Minimal single-future block-on: nothing here waits on I/O.
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

#[derive(Debug, Default, Clone, Copy)]
struct Outcome {
    compressed_len: usize,
    data_frames: usize,
    largest_frame: usize,
    longest_poll: Duration,
}

fn compress(
    codec: Codec,
    frames: &Arc<[Bytes]>,
    paced: bool,
    sized: bool,
    time_polls: bool,
) -> Outcome {
    let frames = frames.clone();
    let service = StreamCompression::new(service_fn(move |_req: Request| {
        let frames = frames.clone();
        async move {
            let mut response = Response::builder().header(header::CONTENT_TYPE, "text/plain");
            if sized {
                let len: usize = frames.iter().map(Bytes::len).sum();
                response = response.header(header::CONTENT_LENGTH, len);
            }
            Ok::<_, Infallible>(
                response
                    .body(FramesBody {
                        frames: frames.iter().cloned().collect(),
                        paced,
                        pending_next: true,
                    })
                    .expect("valid response"),
            )
        }
    }));
    let request = Request::builder()
        .header(header::ACCEPT_ENCODING, codec.accept_encoding())
        .body(Body::empty())
        .expect("valid request");
    let response = block_on(service.serve(request)).expect("infallible service");
    assert_eq!(
        response
            .headers()
            .get(header::CONTENT_ENCODING)
            .and_then(|value| value.to_str().ok()),
        Some(codec.accept_encoding()),
    );

    let mut body = std::pin::pin!(response.into_body());
    let mut cx = Context::from_waker(Waker::noop());
    let mut outcome = Outcome::default();
    loop {
        let start = time_polls.then(Instant::now);
        let polled = body.as_mut().poll_frame(&mut cx);
        if let Some(start) = start {
            outcome.longest_poll = outcome.longest_poll.max(start.elapsed());
        }
        match polled {
            Poll::Pending => {}
            Poll::Ready(None) => return outcome,
            Poll::Ready(Some(frame)) => {
                if let Ok(data) = frame.expect("compressed frame").into_data() {
                    outcome.compressed_len += data.len();
                    outcome.data_frames += 1;
                    outcome.largest_frame = outcome.largest_frame.max(data.len());
                    black_box(data);
                }
            }
        }
    }
}

fn small_frames() -> Arc<[Bytes]> {
    let text = text(SMALL_FRAMES * SMALL_FRAME_LEN);
    (0..SMALL_FRAMES)
        .map(|i| text.slice(i * SMALL_FRAME_LEN..(i + 1) * SMALL_FRAME_LEN))
        .collect()
}

fn report(case: &dyn fmt::Display, frames: &Arc<[Bytes]>, codec: Codec, paced: bool, sized: bool) {
    let mut outcome = compress(codec, frames, paced, sized, true);
    for _ in 0..4 {
        let again = compress(codec, frames, paced, sized, true);
        outcome.longest_poll = outcome.longest_poll.min(again.longest_poll);
    }
    eprintln!(
        "RESULT {case}: compressed={} data_frames={} largest_frame={} longest_poll={:?}",
        outcome.compressed_len, outcome.data_frames, outcome.largest_frame, outcome.longest_poll,
    );
}

fn main() {
    for case in full_body_cases() {
        report(&case, &[text(case.len)].into(), case.codec, false, true);
    }
    let frames = small_frames();
    for case in small_frames_cases() {
        report(&case, &frames, case.codec, case.paced, case.sized);
    }

    divan::main();
}

#[divan::bench(args = full_body_cases(), sample_count = 10, sample_size = 1)]
fn full_body(bencher: divan::Bencher, case: FullBody) {
    let frames: Arc<[Bytes]> = [text(case.len)].into();
    bencher
        .counter(BytesCount::new(case.len))
        .bench_local(|| compress(case.codec, black_box(&frames), false, true, false));
}

#[divan::bench(args = small_frames_cases(), sample_count = 20, sample_size = 1)]
fn many_small_frames(bencher: divan::Bencher, case: SmallFrames) {
    let frames = small_frames();
    bencher
        .counter(BytesCount::new(SMALL_FRAMES * SMALL_FRAME_LEN))
        .bench_local(|| {
            compress(
                case.codec,
                black_box(&frames),
                case.paced,
                case.sized,
                false,
            )
        });
}
