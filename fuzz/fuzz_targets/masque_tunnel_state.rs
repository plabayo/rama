#![no_main]
#![cfg(fuzzing)]

use libfuzzer_sys::fuzz_target;
use rama::proxy::masque::connect_udp::fuzzing::tunnel_state;

fuzz_target!(|input: &[u8]| tunnel_state(input));
