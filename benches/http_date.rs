#![expect(clippy::unwrap_used, reason = "benchmark fixtures must be valid")]

use rama::{
    http::{
        HeaderMap, HeaderValue,
        header::DATE,
        headers::{Date, HeaderMapExt, util::HttpDate},
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
        headers.insert(DATE, HeaderValue::http_date_now());
        black_box(&mut headers);
    });
}

/// The typed `Date` header from the current time: formatted on every call.
#[divan::bench(sample_size = 1000)]
fn date_now_typed_insert(bencher: divan::Bencher) {
    let mut headers = HeaderMap::with_capacity(4);
    bencher.bench_local(|| {
        headers.typed_insert(Date::from(now_system_time()));
        black_box(&mut headers);
    });
}

#[divan::bench]
fn header_value_http_date_now() -> HeaderValue {
    HeaderValue::http_date_now()
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
