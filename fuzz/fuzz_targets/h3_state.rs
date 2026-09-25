#![no_main]
#![cfg(fuzzing)]

use libfuzzer_sys::fuzz_target;
fuzz_target!(|input: &[u8]| rama::http::core::h3::fuzz::state(input));
