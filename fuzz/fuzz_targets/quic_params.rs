#![no_main]

use libfuzzer_sys::fuzz_target;
use rama_quic::{Side, fuzzing::TransportParameters};

fuzz_target!(|data: &[u8]| {
    let mut data = data;
    let _ = TransportParameters::read(Side::Client, &mut data);
});
