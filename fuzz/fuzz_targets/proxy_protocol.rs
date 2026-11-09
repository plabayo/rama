//! PROXY protocol v1/v2 header parsing fuzz target.
//!
//! Goals: arbitrary bytes never panic, a parsed header only covers bytes of its
//! input, and re-parsing those bytes yields the same header.
//!
//! Run with:
//!     cargo +nightly fuzz run proxy_protocol -- -max_len=1024
#![expect(
    clippy::panic,
    reason = "a violated fuzz invariant must produce a crash artifact"
)]
#![no_main]

use libfuzzer_sys::fuzz_target;
use rama::proxy::haproxy::protocol::{HeaderResult, PartialResult as _};

fuzz_target!(|data: &[u8]| {
    let result = HeaderResult::parse(data);
    let _incomplete = std::hint::black_box(result.is_incomplete());
    match result {
        HeaderResult::V2(Ok(header)) => {
            let bytes = header.as_bytes();
            if !data.starts_with(bytes) {
                panic!("a v2 header covers bytes outside its input");
            }
            _ = std::hint::black_box((header.address_family(), header.verify_crc32c()));
            for tlv in header.tlvs() {
                _ = std::hint::black_box(tlv);
            }
            match HeaderResult::parse(bytes) {
                HeaderResult::V2(Ok(again)) if again.as_bytes() == bytes => {}
                other => panic!("a v2 header re-parses differently: {other:?}"),
            }
        }
        HeaderResult::V1(Ok(header)) => {
            _ = std::hint::black_box((header.protocol(), header.addresses_str()));
            if !data.starts_with(header.header.as_bytes()) {
                panic!("a v1 header covers bytes outside its input");
            }
            match HeaderResult::parse(header.header.as_bytes()) {
                HeaderResult::V1(Ok(again)) if again == header => {}
                other => panic!("a v1 header re-parses differently: {other:?}"),
            }
        }
        HeaderResult::V1(Err(_)) | HeaderResult::V2(Err(_)) => {}
    }
});
