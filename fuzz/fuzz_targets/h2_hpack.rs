#![no_main]

#[cfg(fuzzing)]
use libfuzzer_sys::fuzz_target;

#[cfg(fuzzing)]
fuzz_target!(|data_: &[u8]| {
    let _decoder_ = rama_http_core::h2::fuzz_bridge::fuzz_logic::fuzz_hpack(data_);
});
