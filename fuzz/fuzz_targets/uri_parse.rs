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

use libfuzzer_sys::fuzz_target;
use rama::net::uri::Uri;

fuzz_target!(|data: &[u8]| {
    // Both parsers must terminate cleanly (Ok or typed Err — no panic).
    // `Uri::parse` accepts `&[u8]` directly via the `IntoUriInput` trait.
    drop(Uri::parse_strict(data));

    if let Ok(uri) = Uri::parse(data)
        && let Some(query) = uri.query()
    {
        // Iteration walks the raw query bytes; the `_decoded` calls
        // route every `%XX` through `form_decode` and (transitively)
        // `hex_val`. Both return non-`Copy` `Cow<str>` (or `Option`
        // thereof), so `drop` keeps the calls live under
        // dead-code-elimination.
        for pair in query.pairs() {
            drop(pair.name_decoded());
            drop(pair.value_decoded());
        }
    }
});
