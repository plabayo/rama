//! Request-body replay through the real retry service, including its request
//! extension forks. Divan reports allocations alongside latency.
//!
//! ```sh
//! cargo bench -p rama --bench http_retry_body --features http
//! ```

#![allow(clippy::expect_used, reason = "benchmark fixtures fail fast")]

use divan::Bencher;
use rama::{
    Service,
    bytes::Bytes,
    futures::stream,
    http::{
        Body, Request, Response, StatusCode,
        body::util::BodyExt as _,
        layer::retry::{ManagedPolicy, Policy, Retry, RetryBody, storage::FsReplayStore},
    },
    service::service_fn,
    utils::octets::{kib, mib_u64},
};
use std::{
    convert::Infallible,
    sync::atomic::{AtomicBool, Ordering},
};

mod bench_alloc;

fn main() {
    divan::main();
}

fn measure<P: Policy<Response<()>, Infallible>>(
    bencher: Bencher<'_, '_>,
    policy: impl Future<Output = P>,
    len: usize,
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
        // Preserve the normal empty and single-frame fast paths. The larger
        // input crosses the filesystem spill threshold over several frames.
        let body = if len > kib(16) {
            let payload = payload.clone();
            Body::from_stream(stream::iter((0..len).step_by(kib(16)).map(move |i| {
                Ok::<_, Infallible>(payload.slice(i..(i + kib(16)).min(len)))
            })))
        } else {
            Body::from(payload.clone())
        };
        let request = Request::new(body);
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
        false,
    );
}

#[divan::bench(args = [0, kib(1), kib(64)])]
fn memory_retry(bencher: Bencher<'_, '_>, len: usize) {
    measure(
        bencher,
        std::future::ready(ManagedPolicy::default()),
        len,
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
    measure(bencher, policy, kib(64), retry_once);
}
