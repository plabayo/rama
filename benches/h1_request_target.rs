//! HTTP/1 request-target encoding into the head buffer, as the
//! `rama-http-core` client encoder does for every outgoing request.

#![expect(
    clippy::unwrap_used,
    reason = "bench: panic-on-error is the standard pattern for harnesses"
)]

use divan::black_box;
use rama::{
    bytes::BytesMut,
    extensions::Extensions,
    http::{Method, proto::h1::head::encode_request_target},
    net::{address::ProxyAddress, client::EstablishedProxyRoute, uri::Uri},
};

fn main() {
    divan::main();
}

const ITEMS: &str = "http://origin.example/api/v1/items/123?include=metadata&format=json";

/// `(uri, via forward proxy)`: origin-form direct, absolute-form proxied.
const CASES: &[(&str, bool)] = &[
    (ITEMS, false),
    (ITEMS, true),
    ("http://[2001:db8::8]:8080/resource?q=1", true),
];

fn case(index: usize) -> (Uri, Extensions) {
    let (uri, via_proxy) = CASES[index];
    let extensions = Extensions::new();
    if via_proxy {
        let proxy: ProxyAddress = "http://proxy.example:8080".parse().unwrap();
        extensions.insert(EstablishedProxyRoute::Forward(proxy));
    }
    (uri.parse().unwrap(), extensions)
}

/// The target is written straight into the head buffer.
#[divan::bench(args = [0_usize, 1, 2], sample_count = 100)]
fn direct_into_head(bencher: divan::Bencher, case_index: usize) {
    let (uri, extensions) = case(case_index);
    let mut head = Vec::with_capacity(256);
    bencher.bench_local(|| {
        head.clear();
        encode_request_target(&Method::GET, black_box(&uri), &extensions, &mut head).unwrap();
        black_box(head.as_slice());
        head.len()
    });
}

/// The previous encoder path: render into a fresh scratch `BytesMut`, then
/// copy it into the head buffer.
#[divan::bench(args = [0_usize, 1, 2], sample_count = 100)]
fn scratch_then_copy(bencher: divan::Bencher, case_index: usize) {
    let (uri, extensions) = case(case_index);
    let mut head = Vec::with_capacity(256);
    bencher.bench_local(|| {
        head.clear();
        let mut scratch = BytesMut::new();
        encode_request_target(&Method::GET, black_box(&uri), &extensions, &mut scratch).unwrap();
        head.extend_from_slice(&scratch);
        black_box(head.as_slice());
        head.len()
    });
}
