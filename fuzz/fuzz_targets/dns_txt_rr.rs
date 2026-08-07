//! Fuzz target for the systemd-resolved varlink backend's raw RR parser
//! (`rama-dns/src/client/systemd_resolved_wire.rs`).
//!
//! `ResolveRecord` replies carry each resource record as RFC 1035 wire bytes
//! (the base64 `raw` field). The parser walks the owner name, the
//! type/class/TTL/rdlen header and the TXT character-string segments. On any
//! malformed input it must return a typed `Malformed` verdict (mapped to a
//! transport failure upstream) — never panic, never read out of bounds,
//! never hang. The hook additionally asserts that every yielded TXT segment
//! derives from within the input buffer.
//!
//! Run with:
//!     cargo +nightly fuzz run dns_txt_rr -- -max_len=4096
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    rama::dns::client::fuzzing::parse_txt_rr(data);
});
