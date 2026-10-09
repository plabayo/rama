#![no_main]
#![cfg(fuzzing)]

use libfuzzer_sys::fuzz_target;
use rama::quic::fuzzing::token_sequence;

fuzz_target!(|input: &[u8]| token_sequence(input));
