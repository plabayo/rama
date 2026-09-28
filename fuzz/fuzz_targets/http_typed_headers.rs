#![no_main]
#![cfg(fuzzing)]

use libfuzzer_sys::fuzz_target;

// Newline-separated header values decoded as every typed header, then driven through their API.
fuzz_target!(|data: &[u8]| rama::http::headers::fuzz::exercise_bytes(data));
