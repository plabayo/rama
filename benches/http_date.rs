#![expect(clippy::unwrap_used, reason = "benchmark fixtures must be valid")]

use rama::{
    http::{
        HeaderMap, HeaderValue,
        headers::{Date, DateNow, HeaderMapExt, util::HttpDate},
    },
    utils::time::now_system_time,
};
use std::{
    hint::black_box,
    time::{Duration, UNIX_EPOCH},
};

mod bench_alloc;

fn main() {
    divan::main();
}

/// The `Date` response field as `AddRequiredResponseHeadersLayer` writes it.
#[divan::bench(sample_size = 1000)]
fn date_now_insert(bencher: divan::Bencher) {
    let mut headers = HeaderMap::with_capacity(4);
    bencher.bench_local(|| {
        headers.typed_insert(DateNow::new());
        black_box(&mut headers);
    });
}

/// The typed `Date` header from a `SystemTime` of the current time.
#[divan::bench(sample_size = 1000)]
fn date_now_typed_insert(bencher: divan::Bencher) {
    let mut headers = HeaderMap::with_capacity(4);
    bencher.bench_local(|| {
        headers.typed_insert(Date::from(now_system_time()));
        black_box(&mut headers);
    });
}

#[divan::bench]
fn http_date_to_header_value() -> HeaderValue {
    let date = HttpDate::from(UNIX_EPOCH + Duration::from_secs(1_763_000_000));
    HeaderValue::from(black_box(date))
}

#[divan::bench]
fn http_date_display() -> String {
    let date = HttpDate::from(UNIX_EPOCH + Duration::from_secs(1_763_000_000));
    black_box(date).to_string()
}

#[divan::bench(args = [
    "Sun, 06 Nov 1994 08:49:37 GMT",
    "Sunday, 06-Nov-94 08:49:37 GMT",
    "Sun Nov  6 08:49:37 1994",
])]
fn http_date_parse(value: &str) -> HttpDate {
    black_box(value).parse().unwrap()
}

mod required_headers {
    use super::*;
    use rama::{
        Layer, Service,
        futures::FutureExt as _,
        http::{
            Body, Request, Response,
            layer::required_header::{
                AddRequiredRequestHeadersLayer, AddRequiredResponseHeadersLayer,
            },
        },
        service::service_fn,
    };

    #[divan::bench(sample_size = 128)]
    fn request(b: divan::Bencher) {
        let svc =
            AddRequiredRequestHeadersLayer::new().into_layer(service_fn(async |req: Request| {
                black_box(req.headers());
                Ok::<_, std::convert::Infallible>(Response::new(()))
            }));
        b.with_inputs(|| {
            Request::builder()
                .uri("https://example.com/")
                .body(Body::empty())
                .unwrap()
        })
        .bench_local_values(|req| svc.serve(req).now_or_never().unwrap().unwrap());
    }

    #[divan::bench(sample_size = 128)]
    fn response(b: divan::Bencher) {
        let svc =
            AddRequiredResponseHeadersLayer::new().into_layer(service_fn(async |_: Request| {
                Ok::<_, std::convert::Infallible>(Response::new(()))
            }));
        b.with_inputs(|| Request::new(Body::empty()))
            .bench_local_values(|req| svc.serve(req).now_or_never().unwrap().unwrap());
    }
}
