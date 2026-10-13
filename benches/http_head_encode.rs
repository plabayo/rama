//! Request head encoding: the HTTP/1 request line and head, the HTTP/2
//! pseudo-header fields, and numeric header values, as clients and proxies
//! build them for every outgoing request.

#![expect(
    clippy::unwrap_used,
    reason = "bench: panic-on-error is the standard pattern for harnesses"
)]

use divan::black_box;
use rama::{
    extensions::ExtensionsRef as _,
    http::{
        HeaderMap, HeaderName, HeaderValue, Method, Request,
        proto::{h1::head::encode_request, h2::frame::Pseudo},
    },
    net::{address::ProxyAddress, client::EstablishedProxyRoute, uri::Uri},
};
use std::hash::{Hash, Hasher};

mod bench_alloc;

fn main() {
    divan::main();
}

const ITEMS: &str = "http://origin.example/api/v1/items/123?include=metadata&format=json";

/// `(uri, via forward proxy)`: origin-form direct, absolute-form proxied.
const TARGETS: &[(&str, bool)] = &[
    (ITEMS, false),
    (ITEMS, true),
    ("http://[2001:db8::8]:8080/resource?q=1", true),
    (
        "https://origin.example/a%2Fb/caf%C3%A9?next=%2Fhome&q=a b",
        false,
    ),
];

fn request(index: usize) -> Request<()> {
    let (uri, via_proxy) = TARGETS[index];
    let request = Request::builder()
        .uri(uri.parse::<Uri>().unwrap())
        .header("host", "origin.example")
        .header("user-agent", "rama-bench/1.0")
        .header("Accept", "application/json")
        .header("accept-encoding", "gzip, br")
        .header("X-Request-Id", "5f0c6a3e-1d2b-4c8f-9a7e-0b1c2d3e4f50")
        .body(())
        .unwrap();
    if via_proxy {
        let proxy: ProxyAddress = "http://proxy.example:8080".parse().unwrap();
        request
            .extensions()
            .insert(EstablishedProxyRoute::Forward(proxy));
    }
    request
}

/// A standalone HTTP/1 request head: request line and five header fields.
#[divan::bench(args = [0_usize, 1, 2, 3], sample_count = 100)]
fn h1_request_head(bencher: divan::Bencher, index: usize) {
    let request = request(index);
    bencher.bench_local(|| encode_request(black_box(&request)).unwrap());
}

/// The HTTP/2 (and HTTP/3) pseudo-header fields of a request.
#[divan::bench(args = [0_usize, 3], sample_count = 100)]
fn h2_pseudo_request(bencher: divan::Bencher, index: usize) {
    let uri: Uri = TARGETS[index].0.parse().unwrap();
    bencher.bench_local(|| Pseudo::request(Method::GET, black_box(&uri), None));
}

/// A `Content-Length` value.
#[divan::bench(sample_count = 100)]
fn content_length_value(bencher: divan::Bencher) {
    bencher.bench_local(|| HeaderValue::from(black_box(1_048_576_u64)));
}

/// Common unique fields and repeated Set-Cookie / cookie-crumb traffic.
#[divan::bench(args = [false, true])]
fn header_map_build(bencher: divan::Bencher, repeated: bool) {
    let names: Vec<_> = (0..32)
        .map(|i| HeaderName::from_bytes(format!("x-field-{i}").as_bytes()).unwrap())
        .collect();
    bencher.bench_local(|| {
        let mut map = HeaderMap::with_capacity(32);
        for name in &names {
            map.append(name, HeaderValue::from_static("value"));
            if repeated {
                map.append(
                    "set-cookie",
                    HeaderValue::from_static("session=abc; Secure"),
                );
                map.append("cookie", HeaderValue::from_static("a=b"));
            }
        }
        black_box(map)
    });
}

#[divan::bench(args = [false, true])]
fn header_map_lookup(bencher: divan::Bencher, repeated: bool) {
    let mut map = HeaderMap::new();
    for i in 0..32 {
        map.insert(
            HeaderName::from_bytes(format!("x-field-{i}").as_bytes()).unwrap(),
            HeaderValue::from_static("value"),
        );
        if repeated {
            map.append("cookie", HeaderValue::from_static("a=b"));
        }
    }
    bencher.bench_local(|| {
        black_box(map.get(black_box("x-field-17")));
        black_box(map.get_all(black_box("cookie")).iter().count());
    });
}

struct CollisionHash(u64);

impl Hasher for CollisionHash {
    fn finish(&self) -> u64 {
        self.0
    }
    fn write(&mut self, bytes: &[u8]) {
        for byte in bytes {
            self.0 = (self.0 ^ u64::from(*byte)).wrapping_mul(0x100000001b3);
        }
    }
}

/// Names colliding under the fast hash force the randomized-hasher fallback.
#[divan::bench]
fn header_map_hash_flood(bencher: divan::Bencher) {
    let names: Vec<_> = (0..)
        .map(|i| HeaderName::from_bytes(format!("x-collision-{i}").as_bytes()).unwrap())
        .filter(|name| {
            let mut hasher = CollisionHash(0xcbf29ce484222325);
            name.hash(&mut hasher);
            hasher.finish() & 32767 == 0
        })
        .take(600)
        .collect();
    bencher.bench_local(|| {
        let mut map = HeaderMap::new();
        for name in &names {
            map.insert(name, HeaderValue::from_static("value"));
        }
        black_box(map)
    });
}
