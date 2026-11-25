//! A gRPC `Status` written as response headers: the trailers of a failed call.

#![expect(clippy::unwrap_used, reason = "benchmark fixtures must be valid")]

use divan::black_box;
use rama::http::{
    HeaderMap,
    grpc::{
        Code, Status,
        metadata::{MetadataMap, MetadataValue},
    },
};

mod bench_alloc;

fn main() {
    divan::main();
}

const METADATA: [&str; 8] = [
    "x-request-id",
    "x-trace-id",
    "x-tenant",
    "x-region",
    "x-retry-after",
    "x-quota-remaining",
    "x-shard",
    "x-backend",
];

/// A status with eight metadata entries and `message`.
fn status(message: &'static str) -> Status {
    let mut metadata = MetadataMap::new();
    for name in METADATA {
        metadata.insert(name, MetadataValue::from_static("0123456789abcdef"));
    }
    Status::with_metadata(Code::Unavailable, message, metadata)
}

/// Into a reused header map, as a server writes trailers.
#[divan::bench(args = ["backend unavailable", "backend unavailable: 100% busy"])]
fn add_header(bencher: divan::Bencher, message: &'static str) {
    let status = status(message);
    let mut headers = HeaderMap::with_capacity(16);
    bencher.bench_local(|| {
        headers.clear();
        status.add_header(&mut headers).unwrap();
        black_box(&mut headers);
    });
}

/// Into a fresh response, as a handler returns its error.
#[divan::bench(args = ["backend unavailable", "backend unavailable: 100% busy"])]
fn into_http(bencher: divan::Bencher, message: &'static str) {
    let status = status(message);
    bencher
        .with_inputs(|| status.clone())
        .bench_local_values(|status| black_box(status.try_into_http::<()>().unwrap()));
}
