#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data_: &[u8]| {
    let _decoder_ = rama_http_core::h2::fuzz_bridge::fuzz_logic::fuzz_hpack(data_);
});
