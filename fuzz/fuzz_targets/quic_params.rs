#![no_main]
#![cfg(fuzzing)]

use libfuzzer_sys::fuzz_target;
use rama_quic_proto::{Side, transport_parameters::TransportParameters};

fuzz_target!(|data: &[u8]| {
    let mut data = data;
    let _ = TransportParameters::read(Side::Client, &mut data);
});
