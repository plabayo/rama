//! Fuzz target for the MaxMind DB reader
//! ([`rama_net::address::ip::geo::mmdb::MmdbReader`]).
//!
//! `MmdbReader::from_bytes` parses an *untrusted* binary blob (the `.mmdb`
//! format) and `try_lookup` walks the search tree and lazily decodes a record
//! out of the same buffer. Both paths are designed to be panic-free: on any
//! malformed input they must return a typed [`GeoIpError`] (or `Ok(None)`),
//! never panic, never read out of bounds, never overflow, never UB, never hang.
//!
//! This target feeds the fuzzer's arbitrary bytes into `from_bytes` and, on
//! the rare successful parse, exercises `try_lookup` for a handful of IPv4 and
//! IPv6 addresses. The lookups route fuzzer-controlled tree bytes through the
//! tree walk (with and without the 16-bit jump table) and the lazy field
//! [`Decoder`], so pointer cycles, bogus offsets and truncated fields surface
//! here too.
//!
//! It is also differential: the same bytes go through
//! [`MmdbFileReader::from_read_at`], which reads them through positional
//! reads (uncached, and through a small block cache so fields straddle
//! blocks). Both readers must agree on every open error and every lookup
//! result, compared through `Debug` so a NaN coordinate compares equal.
//!
//! Run with:
//!     cargo +nightly fuzz run mmdb_reader
//!
//! The deterministic `malformed_inputs_error_not_panic` unit test in
//! `rama-net/src/address/ip/geo/mmdb/mod.rs` covers the cheap pre-fuzz shapes;
//! this target picks up the long tail of structurally-valid-looking garbage.
#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "fuzz harness: a panic is how a disagreement is reported"
)]
#![no_main]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::num::NonZeroUsize;

use libfuzzer_sys::fuzz_target;
use rama::io::BlockCacheConfig;
use rama::net::address::ip::geo::mmdb::{MmdbFileConfig, MmdbFileReader, MmdbReader};
use rama::utils::octets::kib;

// A spread of addresses: an IPv4-only tree, an IPv6 tree, the ::/96 IPv4-in-v6
// path, and an IPv4-mapped IPv6 input that canonicalises back to IPv4.
const LOOKUP_IPS: [IpAddr; 6] = [
    IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
    IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
    IpAddr::V4(Ipv4Addr::new(200, 100, 50, 25)),
    IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
    IpAddr::V6(Ipv6Addr::LOCALHOST),
    // ::ffff:9.9.9.9 — IPv4-mapped, canonicalised to IPv4 before the walk.
    IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0x0909, 0x0909)),
];

fn positional(data: &[u8], config: MmdbFileConfig) -> Result<MmdbFileReader, String> {
    MmdbFileReader::from_read_at(data.to_vec(), config).map_err(|err| err.to_string())
}

fuzz_target!(|data: &[u8]| {
    let slice = MmdbReader::from_bytes(data.to_vec()).map_err(|err| err.to_string());
    let small_blocks =
        BlockCacheConfig::new(kib(4)).with_block_size(NonZeroUsize::new(64).unwrap());
    let others = [
        positional(data, MmdbFileConfig::default()),
        positional(data, MmdbFileConfig::default().with_jump_table(false)),
        positional(data, MmdbFileConfig::default().with_cache(small_blocks)),
    ];

    let reader = match slice {
        Ok(reader) => reader,
        Err(err) => {
            // a rejected blob is rejected the same way by every reader
            for other in others {
                assert_eq!(other.err(), Some(err.clone()));
            }
            return;
        }
    };
    let others: Vec<MmdbFileReader> = others
        .into_iter()
        .map(|other| other.expect("positional reader rejects what the slice reader accepts"))
        .collect();
    let plain = reader.clone().without_jump_table();

    for ip in LOOKUP_IPS {
        // `to_owned` decodes every field, so the lazy decoder is fuzzed too
        let expected = format!(
            "{:?}",
            reader
                .try_lookup(ip)
                .map(|found| found.map(|view| view.to_owned()))
                .map_err(|err| err.to_string())
        );
        let without_jump = format!(
            "{:?}",
            plain
                .try_lookup(ip)
                .map(|found| found.map(|view| view.to_owned()))
                .map_err(|err| err.to_string())
        );
        assert_eq!(
            without_jump, expected,
            "jump table changed the result for {ip}"
        );
        for other in &others {
            let got = format!("{:?}", other.try_lookup(ip).map_err(|err| err.to_string()));
            assert_eq!(got, expected, "positional reader disagrees for {ip}");
        }
    }
});
