#![no_main]
#![cfg(fuzzing)]

use libfuzzer_sys::fuzz_target;
use rama::http::core::h3::qpack::{Decoder, DecoderConfig};

// Feed arbitrary bytes to the QPACK encoder-stream processor in small chunks. The dynamic table
// must stay bounded by the advertised capacity, and malformed instructions must be a clean error.
fuzz_target!(|data: &[u8]| {
    let mut dec = Decoder::new(DecoderConfig::default());
    for chunk in data.chunks(5) {
        if dec.feed_encoder_stream(chunk).is_err() {
            return;
        }
    }
    let _ = dec.resume_blocked();
});
