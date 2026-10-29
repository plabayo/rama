#![no_main]
#![cfg(fuzzing)]

use libfuzzer_sys::fuzz_target;
use rama::quic::fuzzing::datagram_sequence;

fuzz_target!(|input: &[u8]| datagram_sequence(input));
