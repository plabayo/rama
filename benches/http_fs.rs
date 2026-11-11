#![expect(
    clippy::unwrap_used,
    reason = "bench: fail on setup or response errors"
)]

//! Warm-cache whole-file and tiny-range requests around the small-file cutoff.
//! Includes opening and consuming each response, but excludes fixture creation.
//! The profiler counts only the benchmark thread: allocations on Tokio blocking
//! threads are excluded, so its counters are not total request-memory figures.

use divan::{black_box, counter::BytesCount};
use rama::{
    Service,
    http::{Body, Request, StatusCode, body::util::BodyExt, header, service::fs::ServeDir},
};

mod bench_alloc;

fn main() {
    divan::main();
}

const SIZES: &[usize] = &[4096, 131_071, 131_072, 131_073];

fn serve(bencher: divan::Bencher, len: usize, ranged: bool) {
    let dir = rama::utils::fs::tempdir().unwrap();
    std::fs::write(dir.path().join("file.bin"), vec![0x5a; len]).unwrap();
    let service = ServeDir::new(dir.path());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let expected = if ranged { 1024 } else { len };
    let request = || {
        let mut request = Request::builder().uri("/file.bin");
        if ranged {
            request = request.header(header::RANGE, "bytes=0-1023");
        }
        request.body(Body::empty()).unwrap()
    };
    runtime.block_on(async {
        let response = service.serve(request()).await.unwrap();
        assert_eq!(
            response.status(),
            if ranged {
                StatusCode::PARTIAL_CONTENT
            } else {
                StatusCode::OK
            }
        );
        assert_eq!(
            response
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .as_ref(),
            vec![0x5a; expected]
        );
    });
    bencher.counter(BytesCount::new(expected)).bench_local(|| {
        runtime.block_on(async {
            let response = service.serve(request()).await.unwrap();
            black_box(response.into_body().collect().await.unwrap().to_bytes());
        });
    });
}

#[divan::bench(args = SIZES, sample_count = 30)]
fn whole_file(bencher: divan::Bencher, len: usize) {
    serve(bencher, len, false);
}

#[divan::bench(args = SIZES, sample_count = 30)]
fn tiny_range(bencher: divan::Bencher, len: usize) {
    serve(bencher, len, true);
}
