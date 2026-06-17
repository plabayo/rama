//! Fuzz target for the MaxMind DB reader
//! ([`rama_net::address::ip::geo::mmdb::MmdbReader`]).
//!
//! `MmdbReader::from_bytes` parses an *untrusted* binary blob (the `.mmdb`
//! format) and `try_lookup` walks the search tree and lazily decodes a record
//! out of the same buffer. Both paths are designed to be panic-free: on any
//! malformed input they must return a typed [`GeoIpError`] (or `Ok(None)`),
//! never panic, never read out of bounds, never overflow, never UB, never hang.
//!
//! This target feeds the fuzzer's arbitrary bytes straight into `from_bytes`
//! and, on the rare successful parse, exercises `try_lookup` for a handful of
//! IPv4 and IPv6 addresses. The lookups route fuzzer-controlled tree bytes
//! through `find` / `read_record` and the lazy field [`Decoder`], so pointer
//! cycles, bogus offsets and truncated fields surface here too. We also touch
//! the parsed metadata. The invariant is purely "no panic / no UB"; the
//! returned values are intentionally discarded.
//!
//! Run with:
//!     cargo +nightly fuzz run mmdb_reader
//!
//! The deterministic `malformed_inputs_error_not_panic` unit test in
//! `rama-net/src/address/ip/geo/mmdb/mod.rs` covers the cheap pre-fuzz shapes;
//! this target picks up the long tail of structurally-valid-looking garbage.
#![no_main]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use libfuzzer_sys::fuzz_target;
use rama::net::address::ip::geo::mmdb::MmdbReader;

// A spread of addresses: an IPv4-only tree, an IPv6 tree, the ::/96 IPv4-in-v6
// path, and an IPv4-mapped IPv6 input that canonicalises back to IPv4.
const LOOKUP_IPS: [IpAddr; 5] = [
    IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
    IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
    IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
    IpAddr::V6(Ipv6Addr::LOCALHOST),
    // ::ffff:9.9.9.9 — IPv4-mapped, canonicalised to IPv4 before the walk.
    IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0x0909, 0x0909)),
];

fuzz_target!(|data: &[u8]| {
    // `from_bytes` takes anything `Into<Bytes>`; an owned `Vec<u8>` converts
    // without copying the slice's backing store more than once.
    let Ok(reader) = MmdbReader::from_bytes(data.to_vec()) else {
        // Parse rejected the blob with a typed error — exactly the contract.
        return;
    };

    // Each lookup must terminate cleanly: Ok(Some) / Ok(None) / typed Err.
    // `try_lookup` is the corruption-observing variant, so it exercises the
    // most error paths in the tree walk and the lazy record decoder.
    for ip in LOOKUP_IPS {
        if let Ok(Some(loc)) = reader.try_lookup(ip) {
            // Drive the lazy decoder over a successfully matched record so
            // field decoding (pointers, string lengths, map walks) is fuzzed
            // too. `to_owned` forces every field to be decoded eagerly.
            drop(loc.to_owned());
        }
    }
});
