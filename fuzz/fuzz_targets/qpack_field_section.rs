#![no_main]
#![cfg(fuzzing)]

use libfuzzer_sys::fuzz_target;
use rama_core::bytes::Bytes;
use rama_http_core::h3::qpack::{Decoder, DecoderConfig};

// Decode an arbitrary encoded field section against a fresh decoder. With no dynamic inserts, any
// dynamic reference or bad prefix must be a clean error, never a panic or unbounded allocation.
fuzz_target!(|data: &[u8]| {
    let mut dec = Decoder::new(DecoderConfig::default());
    let _ = dec.decode_field_section(0, Bytes::copy_from_slice(data));
});
