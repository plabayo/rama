#![no_main]
#![cfg(fuzzing)]

use std::collections::BTreeMap;

use libfuzzer_sys::fuzz_target;
use rama_core::bytes::{Bytes, BytesMut};
use rama_http_core::h3::qpack::{
    Decoder, DecoderConfig, EncodeField, Encoder, EncoderConfig, FieldPair,
};

fn check_fields(actual: &[FieldPair], expected: &FieldPair) {
    assert_eq!(actual.len(), 1);
    assert_eq!(actual[0].name, expected.name);
    assert_eq!(actual[0].value, expected.value);
    assert_eq!(actual[0].never_index, expected.never_index);
}

// Correlated endpoints with independently scheduled streams. Small tables cause repeated RIC
// wraps; delayed acknowledgments and cancellations keep eviction/reference accounting live.
// Stream identifiers exceed 127 so feedback also exercises fragmented prefixed integers.
fuzz_target!(|data: &[u8]| {
    // Invalid feedback must be rejected independently of fragmentation, with no advance in the
    // known-received count. A fresh encoder has no insertions or outstanding acknowledgments.
    let mut whole = Encoder::new(EncoderConfig::default());
    let mut fragmented = Encoder::new(EncoderConfig::default());
    let whole_result = whole.feed_decoder_stream(data);
    let fragmented_result = data
        .iter()
        .try_for_each(|byte| fragmented.feed_decoder_stream(&[*byte]));
    assert_eq!(whole_result.is_err(), fragmented_result.is_err());
    assert_eq!(
        whole.known_received_count(),
        fragmented.known_received_count()
    );

    let Some((&setup, operations)) = data.split_first() else {
        return;
    };
    let capacity = [0, 64, 128, 256][usize::from(setup & 3)];
    let max_sections = 1 + usize::from(setup >> 6);
    let max_references = 1 + usize::from((setup >> 3) & 7);
    let max_output = 4 + usize::from(setup >> 3);
    let mut encoder = Encoder::new(EncoderConfig {
        max_table_capacity: capacity,
        target_capacity: capacity,
        max_blocked_streams: 4,
        huffman: setup & 4 != 0,
        max_outstanding_sections: max_sections,
        max_outstanding_references: max_references,
        max_encoder_stream_bytes: max_output,
        ..Default::default()
    });
    let mut decoder = Decoder::new(DecoderConfig {
        max_table_capacity: capacity,
        max_blocked_streams: 4,
        ..Default::default()
    });
    let mut forward = BytesMut::new();
    let mut feedback = BytesMut::new();
    let mut blocked = BTreeMap::new();
    let mut streams = [128, 132, 136, 140];
    for &operation in operations.iter().take(256) {
        let slot = usize::from((operation >> 3) & 3);
        let stream = streams[slot];
        match operation & 7 {
            0 | 1 => {
                if !blocked.contains_key(&stream) {
                    let field = FieldPair {
                        name: Bytes::from(vec![b'a' + (operation >> 5)]),
                        value: Bytes::from(vec![b'0' + ((operation >> 3) & 7)]),
                        never_index: operation & 1 != 0,
                    };
                    let section = encoder
                        .encode(
                            stream,
                            [EncodeField {
                                name: &field.name,
                                value: &field.value,
                                never_index: field.never_index,
                            }],
                        )
                        .unwrap();
                    match decoder.decode_field_section(stream, section).unwrap() {
                        Some(fields) => check_fields(&fields, &field),
                        None => {
                            blocked.insert(stream, field);
                        }
                    }
                }
            }
            2 | 3 => {
                forward.extend_from_slice(&encoder.take_encoder_stream());
                let count = forward.len().min(1 + usize::from(operation >> 3));
                decoder
                    .feed_encoder_stream(&forward.split_to(count))
                    .unwrap();
            }
            4 => {
                feedback.extend_from_slice(&decoder.take_decoder_stream());
                let count = feedback.len().min(1 + usize::from(operation >> 3));
                encoder
                    .feed_decoder_stream(&feedback.split_to(count))
                    .unwrap();
            }
            5 => {
                for (stream, fields) in decoder.resume_blocked() {
                    check_fields(&fields.unwrap(), &blocked.remove(&stream).unwrap());
                }
            }
            6 => {
                if blocked.remove(&stream).is_some() {
                    decoder.cancel_stream(stream).unwrap();
                    streams[slot] += 16;
                }
            }
            _ => {
                // Drain feedback bytewise, including the continuation of a previous instruction.
                feedback.extend_from_slice(&decoder.take_decoder_stream());
                while !feedback.is_empty() {
                    encoder.feed_decoder_stream(&feedback.split_to(1)).unwrap();
                }
            }
        }
        assert!(encoder.tracked_section_count() <= max_sections);
        assert!(encoder.tracked_reference_count() <= max_references);
        assert!(encoder.encoder_stream_len() <= max_output);
        assert!(decoder.blocked_stream_count() <= blocked.len());
        assert!(blocked.len() <= 4);
        assert!(encoder.known_received_count() <= decoder.insert_count());
        assert!(decoder.insert_count() <= encoder.insert_count());
    }
    // Every successfully emitted section must decode correctly or have been explicitly canceled.
    forward.extend_from_slice(&encoder.take_encoder_stream());
    decoder.feed_encoder_stream(&forward).unwrap();
    for (stream, fields) in decoder.resume_blocked() {
        check_fields(&fields.unwrap(), &blocked.remove(&stream).unwrap());
    }
    assert!(blocked.is_empty());
    feedback.extend_from_slice(&decoder.take_decoder_stream());
    for byte in feedback {
        encoder.feed_decoder_stream(&[byte]).unwrap();
    }
    assert_eq!(encoder.known_received_count(), encoder.insert_count());
});
