//! Fuzz target for [`rama_net::uri::Uri::resolve`] /
//! [`rama_net::uri::Uri::resolve_strict`].
//!
//! Splits the fuzzer input into two halves, parses each as a URI / URI-reference,
//! and runs both resolve modes. Goal: never panic, never UB, never OOB.
//!
//! Run with:
//!     cargo +nightly fuzz run uri_resolve
#![no_main]

use libfuzzer_sys::fuzz_target;
use rama::net::uri::Uri;

fuzz_target!(|data: &[u8]| {
    // Split input into base + reference. NUL byte = separator if present;
    // otherwise split at the midpoint.
    let split = data.iter().position(|&b| b == 0).unwrap_or(data.len() / 2);
    let base_bytes = &data[..split];
    let ref_bytes = data.get(split + 1..).unwrap_or(&[]);

    // Parse base as a URI (absolute) and reference as a URI-reference.
    if let (Ok(base), Ok(reference)) = (Uri::parse(base_bytes), Uri::parse_reference(ref_bytes)) {
        // Both resolve modes must terminate cleanly (Ok or typed Err — no panic).
        drop(base.resolve(&reference));
        drop(base.resolve_strict(&reference));
    }
});
