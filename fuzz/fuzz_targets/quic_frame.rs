#![no_main]
#![cfg(fuzzing)]

use libfuzzer_sys::fuzz_target;
use rama_quic::fuzzing::{Bytes, decode_frames};

fuzz_target!(|data: &[u8]| {
    let _ = decode_frames(Bytes::copy_from_slice(data));
});
