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
use rama::bytes::Bytes;
use rama::net::uri::Uri;

fuzz_target!(|data: &[u8]| {
    let buf = Bytes::copy_from_slice(data);
    // Both parsers must terminate cleanly (Ok or typed Err — no panic).
    drop(Uri::parse_bytes(buf.clone()));
    drop(Uri::parse_bytes_strict(buf));
});
