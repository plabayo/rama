#![expect(clippy::unwrap_used, reason = "benchmark fixtures must be valid")]

//! Decode, query and encode costs of commonly received typed headers.
//!
//! Compare runs with fixed sampling, e.g. `-- --sample-count 100 --sample-size 1000`.

use rama::http::{
    HeaderMap, HeaderValue,
    headers::{
        Accept, Authorization, CacheControl, Connection, ContentLength, ContentRange, ContentType,
        Cookie, CrossOriginOpenerPolicy, ETag, HeaderDecode, HeaderEncode, HeaderMapExt, Host,
        IfMatch, IfModifiedSince, IfNoneMatch, IfRange, Origin, Priority, Range,
        SecWebSocketExtensions, StrictTransportSecurity, Te, UserAgent, Vary, XRobotsTag,
        encoding::{AcceptEncoding, parse_accept_encoding_headers},
        forwarded::{Forwarded, Via, XForwardedFor},
    },
};
use rama::net::user::{Basic, Bearer};
use std::{
    hint::black_box,
    time::{Duration, UNIX_EPOCH},
};

#[global_allocator]
static ALLOC: divan::AllocProfiler = divan::AllocProfiler::system();

fn main() {
    divan::main();
}

fn values(raw: &[&'static str]) -> Vec<HeaderValue> {
    raw.iter().map(|v| HeaderValue::from_static(v)).collect()
}

fn decode<H: HeaderDecode>(values: &[HeaderValue]) -> H {
    H::decode(&mut black_box(values).iter()).unwrap()
}

mod decode {
    use super::*;

    macro_rules! decode_bench {
        ($name:ident, $ty:ty, $($raw:literal),+ $(,)?) => {
            #[divan::bench]
            fn $name(b: divan::Bencher) {
                let values = values(&[$($raw),+]);
                b.bench_local(|| black_box(decode::<$ty>(&values)));
            }
        };
    }

    decode_bench!(etag, ETag, "\"33a64df551425fcc55e4d42a148795d9f25f89d4\"");
    decode_bench!(
        if_none_match_single,
        IfNoneMatch,
        "\"33a64df551425fcc55e4d42a148795d9f25f89d4\""
    );
    decode_bench!(
        if_none_match_list,
        IfNoneMatch,
        "\"a1\", W/\"b2\", \"c3\", W/\"d4\", \"33a64df551425fcc55e4d42a148795d9f25f89d4\""
    );
    decode_bench!(if_none_match_any, IfNoneMatch, "*");
    decode_bench!(if_match, IfMatch, "\"xyzzy\", \"r2d2xxxx\", \"c3piozzzz\"");
    decode_bench!(if_range_etag, IfRange, "\"xyzzy\"");
    decode_bench!(
        if_modified_since,
        IfModifiedSince,
        "Sun, 06 Nov 1994 08:49:37 GMT"
    );
    decode_bench!(
        accept_browser,
        Accept,
        "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
    );
    decode_bench!(content_type, ContentType, "text/html; charset=utf-8");
    decode_bench!(
        cache_control_immutable,
        CacheControl,
        "public, max-age=31536000, immutable"
    );
    decode_bench!(
        cache_control_no_store,
        CacheControl,
        "no-cache, no-store, must-revalidate, private, max-age=0"
    );
    decode_bench!(range, Range, "bytes=0-1023");
    decode_bench!(content_range, ContentRange, "bytes 0-1023/146515");
    decode_bench!(content_length, ContentLength, "3495");
    decode_bench!(
        cookie,
        Cookie,
        "session=38afes7a8; theme=dark; lang=en-US; _ga=GA1.2.1234567890.1234567890; csrftoken=abcdef0123456789"
    );
    decode_bench!(connection, Connection, "keep-alive, Upgrade");
    decode_bench!(te, Te, "trailers, deflate;q=0.5");
    decode_bench!(te_weight_then_param, Te, "trailers, deflate;q=0.5;foo=bar");
    decode_bench!(vary, Vary, "Accept-Encoding, Origin, Accept-Language");
    decode_bench!(host, Host, "example.com:8443");
    decode_bench!(origin, Origin, "https://example.com:8443");
    decode_bench!(
        user_agent,
        UserAgent,
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36"
    );
    decode_bench!(
        authorization_basic,
        Authorization<Basic>,
        "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="
    );
    decode_bench!(
        authorization_bearer,
        Authorization<Bearer>,
        "Bearer mF_9.B5f-4.1JqM"
    );
    decode_bench!(
        x_forwarded_for,
        XForwardedFor,
        "203.0.113.195, 2001:db8:85a3:8d3:1319:8a2e:370:7348, 198.51.100.178"
    );
    decode_bench!(
        forwarded,
        Forwarded,
        "for=192.0.2.60;proto=http;by=203.0.113.43, for=\"[2001:db8:cafe::17]:4711\""
    );
    decode_bench!(via, Via, "1.1 vegur, HTTP/1.0 fred, 1.1 p.example.net");
    decode_bench!(
        cross_origin_opener_policy,
        CrossOriginOpenerPolicy,
        "same-origin; report-to=\"coop-endpoint\""
    );
    decode_bench!(
        sec_websocket_extensions,
        SecWebSocketExtensions,
        "permessage-deflate; client_max_window_bits"
    );
    decode_bench!(priority, Priority, "u=3, i");
    decode_bench!(
        strict_transport_security,
        StrictTransportSecurity,
        "max-age=63072000; includeSubDomains; preload"
    );
    decode_bench!(
        x_robots_tag,
        XRobotsTag,
        "googlebot: noindex, nofollow, max-snippet: 20"
    );
}

mod query {
    use super::*;

    #[divan::bench]
    fn if_none_match_precondition(b: divan::Bencher) {
        let header = decode::<IfNoneMatch>(&values(&[
            "\"a1\", W/\"b2\", \"c3\", W/\"d4\", \"33a64df551425fcc55e4d42a148795d9f25f89d4\"",
        ]));
        let etag: ETag = "\"33a64df551425fcc55e4d42a148795d9f25f89d4\""
            .parse()
            .unwrap();
        b.bench_local(|| black_box(header.precondition_passes(black_box(&etag))));
    }

    #[divan::bench]
    fn if_match_precondition(b: divan::Bencher) {
        let header = decode::<IfMatch>(&values(&["\"xyzzy\", \"r2d2xxxx\", \"c3piozzzz\""]));
        let etag: ETag = "\"c3piozzzz\"".parse().unwrap();
        b.bench_local(|| black_box(header.precondition_passes(black_box(&etag))));
    }

    #[divan::bench]
    fn if_modified_since(b: divan::Bencher) {
        let header = decode::<IfModifiedSince>(&values(&["Sun, 06 Nov 1994 08:49:37 GMT"]));
        let modified = UNIX_EPOCH
            .checked_add(Duration::from_secs(784_111_777))
            .unwrap();
        b.bench_local(|| black_box(header.is_modified(black_box(modified))));
    }

    #[divan::bench]
    fn range_satisfiable(b: divan::Bencher) {
        let header = decode::<Range>(&values(&["bytes=0-1023"]));
        b.bench_local(|| black_box(header.satisfiable_ranges(black_box(146_515)).count()));
    }

    #[divan::bench]
    fn cookie_get(b: divan::Bencher) {
        let header = decode::<Cookie>(&values(&[
            "session=38afes7a8; theme=dark; lang=en-US; _ga=GA1.2.1234567890.1234567890; csrftoken=abcdef0123456789",
        ]));
        b.bench_local(|| black_box(header.get(black_box("csrftoken"))));
    }

    #[divan::bench]
    fn accept_encoding_preference(b: divan::Bencher) {
        let mut map = HeaderMap::new();
        map.insert(
            rama::http::header::ACCEPT_ENCODING,
            HeaderValue::from_static("gzip, deflate, br, zstd"),
        );
        b.bench_local(|| {
            black_box(
                parse_accept_encoding_headers(black_box(&map), AcceptEncoding::default()).count(),
            )
        });
    }
}

mod encode {
    use super::*;

    #[divan::bench]
    fn cache_control(b: divan::Bencher) {
        let header = decode::<CacheControl>(&values(&["public, max-age=31536000, immutable"]));
        b.bench_local(|| black_box(black_box(&header).encode_to_value()));
    }

    #[divan::bench]
    fn if_none_match(b: divan::Bencher) {
        let header = decode::<IfNoneMatch>(&values(&["\"a1\", W/\"b2\", \"c3\""]));
        b.bench_local(|| black_box(black_box(&header).encode_to_value()));
    }

    #[divan::bench]
    fn typed_insert_replace(b: divan::Bencher) {
        let mut map = HeaderMap::new();
        map.typed_insert(ContentLength(1));
        b.bench_local(|| map.typed_insert(black_box(ContentLength(3495))));
    }
}
