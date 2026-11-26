//! Request-body replay through the real retry service, including its request
//! extension forks. Divan reports allocations alongside latency; `max alloc`
//! is the peak live heap during one request, which includes the replay copy.
//!
//! ```sh
//! cargo bench -p rama --bench http_retry_body --features http
//! ```

#![allow(clippy::expect_used, reason = "benchmark fixtures fail fast")]

use std::{
    collections::VecDeque,
    convert::Infallible,
    future::ready,
    pin::Pin,
    sync::atomic::{AtomicBool, Ordering},
    task::{Context, Poll},
};

use divan::Bencher;
use rama::{
    Service,
    bytes::Bytes,
    futures::stream,
    http::{
        Body, Request, Response, StatusCode, StreamingBody,
        body::{Frame, SizeHint, util::BodyExt as _},
        layer::retry::{ManagedPolicy, Policy, Retry, RetryBody, storage::FsReplayStore},
    },
    service::service_fn,
    utils::octets::{kib, mib_u64},
};

mod bench_alloc;

fn main() {
    divan::main();
}

/// How the bench hands the payload to the retry layer.
#[derive(Clone, Copy)]
enum Upload {
    /// Buffered bodies up to 16 KiB, larger ones as unsized 16 KiB stream frames.
    Default,
    /// Fixed-size frames that report an exact length, as a content-length upload does.
    Sized(usize),
    /// Fixed-size frames without a length hint, as a chunked upload does.
    Unsized(usize),
}

/// Frames that report a size hint like a transport body with a known length.
struct Frames {
    frames: VecDeque<Bytes>,
    remaining: u64,
    sized: bool,
}

impl StreamingBody for Frames {
    type Data = Bytes;

    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        let frame = self.frames.pop_front();
        if let Some(data) = &frame {
            self.remaining -= data.len() as u64;
        }
        Poll::Ready(frame.map(|data| Ok(Frame::data(data))))
    }

    fn is_end_stream(&self) -> bool {
        self.frames.is_empty()
    }

    fn size_hint(&self) -> SizeHint {
        if self.sized {
            SizeHint::with_exact(self.remaining)
        } else {
            SizeHint::default()
        }
    }
}

fn upload(payload: &Bytes, shape: Upload) -> Body {
    let len = payload.len();
    let (frame, sized) = match shape {
        Upload::Default if len > kib(16) => {
            let payload = payload.clone();
            return Body::from_stream(stream::iter(
                (0..len)
                    .step_by(kib(16))
                    .map(move |i| Ok::<_, Infallible>(payload.slice(i..(i + kib(16)).min(len)))),
            ));
        }
        Upload::Default => return Body::from(payload.clone()),
        Upload::Sized(frame) => (frame, true),
        Upload::Unsized(frame) => (frame, false),
    };
    Body::new(Frames {
        frames: (0..len)
            .step_by(frame)
            .map(|i| payload.slice(i..(i + frame).min(len)))
            .collect(),
        remaining: len as u64,
        sized,
    })
}

fn measure<P: Policy<Response<()>, Infallible>>(
    bencher: Bencher<'_, '_>,
    policy: impl Future<Output = P>,
    len: usize,
    shape: Upload,
    retry_once: bool,
) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("benchmark runtime");
    let payload = Bytes::from(vec![42; len]);
    let first_attempt = AtomicBool::new(true);
    let retry = Retry::new(
        rt.block_on(policy),
        service_fn(move |request: Request<RetryBody>| {
            // Simulate an early retryable response before the upload is read.
            let reject = retry_once && first_attempt.fetch_xor(true, Ordering::Relaxed);
            async move {
                let mut response = Response::new(());
                if reject {
                    *response.status_mut() = StatusCode::SERVICE_UNAVAILABLE;
                } else {
                    let mut body = request.into_body();
                    let mut received = 0;
                    while let Some(frame) = body.frame().await {
                        if let Ok(data) = frame.expect("read upload").into_data() {
                            received += data.len();
                        }
                    }
                    assert_eq!(received, len);
                }
                Ok::<_, Infallible>(response)
            }
        }),
    );

    bencher.bench_local(|| {
        let request = Request::new(upload(&payload, shape));
        let response = rt.block_on(retry.serve(request)).expect("serve request");
        assert_eq!(response.status(), StatusCode::OK);
    });
}

#[divan::bench(args = [0, kib(1), kib(64)])]
fn memory_success(bencher: Bencher<'_, '_>, len: usize) {
    measure(
        bencher,
        std::future::ready(ManagedPolicy::default()),
        len,
        Upload::Default,
        false,
    );
}

#[divan::bench(args = [0, kib(1), kib(64)])]
fn memory_retry(bencher: Bencher<'_, '_>, len: usize) {
    measure(
        bencher,
        std::future::ready(ManagedPolicy::default()),
        len,
        Upload::Default,
        true,
    );
}

/// One streamed frame goes through the capture writer instead of the buffered shortcut.
#[divan::bench(args = [kib(1), kib(4), kib(16)])]
fn memory_retry_single_frame(bencher: Bencher<'_, '_>, len: usize) {
    measure(
        bencher,
        ready(ManagedPolicy::default()),
        len,
        Upload::Sized(len),
        true,
    );
}

/// 1 KiB frames, with and without an exact length, well below and at the 64 KiB limit.
#[divan::bench(args = [kib(40), kib(64)])]
fn memory_retry_fragmented_sized(bencher: Bencher<'_, '_>, len: usize) {
    measure(
        bencher,
        ready(ManagedPolicy::default()),
        len,
        Upload::Sized(kib(1)),
        true,
    );
}

#[divan::bench(args = [kib(40), kib(56), kib(64)])]
fn memory_retry_fragmented_unsized(bencher: Bencher<'_, '_>, len: usize) {
    measure(
        bencher,
        ready(ManagedPolicy::default()),
        len,
        Upload::Unsized(kib(1)),
        true,
    );
}

#[divan::bench(args = [false, true])]
fn filesystem_spill(bencher: Bencher<'_, '_>, retry_once: bool) {
    let policy = async {
        let store = FsReplayStore::new(std::env::temp_dir(), kib(16), kib(64), mib_u64(64))
            .await
            .expect("create spill store");
        ManagedPolicy::default().with_replay_store(store)
    };
    measure(bencher, policy, kib(64), Upload::Default, retry_once);
}
