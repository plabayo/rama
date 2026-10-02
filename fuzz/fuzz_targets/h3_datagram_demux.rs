#![no_main]
#![cfg(fuzzing)]

use libfuzzer_sys::fuzz_target;
fuzz_target!(|input: &[u8]| {
    _ = rama::http::core::h3::fuzz::datagram_demux(input);
});
