//! Fuzz target for the [`rama_net::uri::Uri`] parser.
//!
//! Goals: never panic on any byte sequence; never read out of bounds;
//! never overflow; never UB. The parser is graceful by default and
//! returns typed [`rama_net::uri::ParseError`] for invalid input.
//!
//! When a graceful parse succeeds and the URI has a query, also exercise
//! the [`QueryRef::pairs`] iterator and read decoded views on each pair.
//! That routes fuzzer-discovered inputs through the private
//! `form_decode` / `hex_val` helpers — catching panics, OOB reads, or
//! overflow there for free.
//!
//! Run with:
//!     cargo +nightly fuzz run uri_parse
//!
//! The deterministic structured smoke corpus in
//! `rama-net/src/uri/parser/tests/smoke.rs` covers the cheap pre-fuzz
//! shape; this target picks up the long tail.
#![no_main]

use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher as _},
    hint::black_box,
};

use libfuzzer_sys::fuzz_target;
use rama::net::uri::{FragmentRef, PathRef, QueryRef, Uri};

fn hash<T: Hash>(value: T) -> u64 {
    let mut h = DefaultHasher::new();
    value.hash(&mut h);
    h.finish()
}

fuzz_target!(|data: &[u8]| {
    // Both parsers must terminate cleanly (Ok or typed Err — no panic).
    // `Uri::parse` accepts `&[u8]` directly via the `IntoUriInput` trait.
    drop(Uri::parse_strict(data));

    if let Ok(uri) = Uri::parse(data) {
        if let Some(path) = uri.path() {
            let encoded = path.as_encoded_str();
            let roundtrip = PathRef::from_raw_str(encoded.as_ref());
            black_box(path == roundtrip);
            black_box(path.cmp(&roundtrip));
            black_box((hash(path), hash(roundtrip)));
            drop(path.trimmed_slashes().as_encoded_str());
            black_box((
                path.segment_count(),
                path.first_segment(),
                path.last_segment(),
            ));
            for segment in path.segments() {
                drop(segment.as_encoded_str());
                drop(segment.as_decoded_str());
                black_box((segment.is_empty(), hash(segment)));
            }
        }

        if let Some(query) = uri.query() {
            let encoded = query.as_encoded_str();
            let roundtrip = QueryRef::from_raw_str(encoded.as_ref());
            black_box(query == roundtrip);
            black_box(query.cmp(&roundtrip));
            black_box((hash(query), hash(roundtrip)));
            drop(query.as_decoded_str());

            // Iteration walks the query bytes; encoded/decoded calls route
            // every structural and `%XX` edge through pair rendering and
            // form_decode / hex_val.
            for pair in query.pairs() {
                black_box(format!("{pair}"));
                drop(pair.name_encoded());
                drop(pair.value_encoded());
                drop(pair.name_decoded());
                drop(pair.value_decoded());
                black_box(pair.has_value());
            }
        }

        if let Some(fragment) = uri.fragment() {
            let encoded = fragment.as_encoded_str();
            let roundtrip = FragmentRef::from_raw_str(encoded.as_ref());
            black_box(fragment == roundtrip);
            black_box(fragment.cmp(&roundtrip));
            black_box((hash(fragment), hash(roundtrip)));
            drop(fragment.as_decoded_str());
        }
    }
});
