#![no_main]
#![cfg(fuzzing)]

use libfuzzer_sys::fuzz_target;
use rama::bytes::Bytes;
use rama::http::core::h3::qpack::{Decoder, DecoderConfig};

// Decode an arbitrary field section after an arbitrary peer encoder stream. Bad input must be a
// clean error, and every decoded section must fit both limits whatever its representations.
fuzz_target!(|data: &[u8]| {
    let [split, limits, rest @ ..] = data else {
        return;
    };
    let config = DecoderConfig {
        max_field_section_size: 32 * (1 + usize::from(limits & 0x1f)),
        max_field_lines: 1 + usize::from(limits >> 5),
        ..DecoderConfig::default()
    };
    let (instructions, section) = rest.split_at(usize::from(*split).min(rest.len()));
    let mut dec = Decoder::new(config);
    if dec.feed_encoder_stream(instructions).is_err() {
        return;
    }
    if let Ok(Some(fields)) = dec.decode_field_section(0, Bytes::copy_from_slice(section)) {
        assert!(fields.len() <= config.max_field_lines);
        let size: usize = fields
            .iter()
            .map(|field| field.name.len() + field.value.len() + 32)
            .sum();
        assert!(size <= config.max_field_section_size);
    }
});
