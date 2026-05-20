//! Fuzz target for the [`rama_net::uri::Uri`] parser.
//!
//! Goals: never panic on any byte sequence; never read out of bounds;
//! never overflow; never UB. The parser is graceful by default and
//! returns typed [`rama_net::uri::ParseError`] for invalid input.
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
    drop(Uri::parse(data));
    drop(Uri::parse_strict(data));
});
