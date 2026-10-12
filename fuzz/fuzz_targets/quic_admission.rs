#![no_main]
#![cfg(fuzzing)]

use libfuzzer_sys::fuzz_target;
use rama::quic::fuzzing::fuzz_admission;

fuzz_target!(|data: &[u8]| fuzz_admission(data));
