use super::{EncodeField, Encoder, EncoderConfig};
use crate::h3::qpack::{Decoder, DecoderConfig, QpackError};
use rama_core::bytes::{Bytes, BytesMut};
use rama_http_types::proto::h3::qpack::{DecoderInstruction, FieldLine, HeaderPrefix};

fn feedback(inst: DecoderInstruction) -> Bytes {
    let mut b = BytesMut::new();
    inst.encode(&mut b);
    b.freeze()
}

#[test]
fn decoder_feedback_every_split_and_bytewise() {
    for stream_id in [0, 4, 64, 128, 16384, (1u64 << 62) - 4] {
        for cancel in [false, true] {
            let inst = if cancel {
                DecoderInstruction::StreamCancellation { stream_id }
            } else {
                DecoderInstruction::SectionAcknowledgment { stream_id }
            };
            let wire = feedback(inst);
            for split in 0..=wire.len() {
                let mut enc = Encoder::new(EncoderConfig::default());
                enc.encode(stream_id, [(b"custom", b"value")]).unwrap();
                enc.feed_decoder_stream(&wire[..split]).unwrap();
                enc.feed_decoder_stream(&wire[split..]).unwrap();
                assert!(enc.is_at_decoder_instruction_boundary());
                assert_eq!(enc.tracked_section_count(), 0);
                assert_eq!(enc.tracked_reference_count(), 0);
                assert_eq!(enc.known_received_count(), u64::from(!cancel));
            }
            let mut enc = Encoder::new(EncoderConfig::default());
            enc.encode(stream_id, [(b"custom", b"value")]).unwrap();
            for byte in wire {
                enc.feed_decoder_stream(&[byte]).unwrap();
            }
            assert_eq!(enc.tracked_section_count(), 0);
        }
    }
}

#[test]
fn increments_zero_excess_and_overflow_are_rejected_without_changing_state() {
    let mut enc = Encoder::new(EncoderConfig::default());
    enc.encode(0, [(b"a", b"b")]).unwrap();
    for increment in [0, 2, u64::MAX] {
        assert!(matches!(
            enc.on_decoder_instruction(DecoderInstruction::InsertCountIncrement { increment }),
            Err(QpackError::DecoderStreamError(_))
        ));
        assert_eq!(enc.known_received_count(), 0);
    }
    enc.on_decoder_instruction(DecoderInstruction::SectionAcknowledgment { stream_id: 0 })
        .unwrap();
    assert!(enc.feed_decoder_stream(&[1]).is_err());
    assert_eq!(enc.known_received_count(), 1);
}

#[test]
fn fragmented_increment_and_truncated_overflow() {
    let mut enc = Encoder::new(EncoderConfig {
        target_capacity: 8192,
        max_table_capacity: 8192,
        ..EncoderConfig::default()
    });
    for n in 0..64 {
        enc.encode(0, [(format!("x-{n}"), "y")]).unwrap();
    }
    let wire = feedback(DecoderInstruction::InsertCountIncrement { increment: 64 });
    assert_eq!(wire.len(), 2);
    enc.feed_decoder_stream(&wire[..1]).unwrap();
    assert!(!enc.is_at_decoder_instruction_boundary());
    assert_eq!(enc.known_received_count(), 0);
    enc.feed_decoder_stream(&wire[1..]).unwrap();
    assert_eq!(enc.known_received_count(), 64);
    let mut enc = Encoder::new(EncoderConfig::default());
    for _ in 0..10 {
        enc.feed_decoder_stream(&[0xff]).unwrap();
    }
    assert!(enc.feed_decoder_stream(&[0xff]).is_err());
}

#[test]
fn cancellation_does_not_acknowledge_insert_or_allow_eviction() {
    let mut enc = Encoder::new(EncoderConfig {
        max_table_capacity: 34,
        target_capacity: 34,
        huffman: false,
        ..EncoderConfig::default()
    });
    enc.encode(0, [(b"a", b"b")]).unwrap();
    let first_insert = enc.take_encoder_stream();
    enc.on_decoder_instruction(DecoderInstruction::StreamCancellation { stream_id: 0 })
        .unwrap();
    enc.encode(4, [(b"c", b"d")]).unwrap();
    enc.on_decoder_instruction(DecoderInstruction::StreamCancellation { stream_id: 4 })
        .unwrap();
    let last = enc.encode(8, [(b"e", b"f")]).unwrap();
    assert_eq!(enc.insert_count(), 1);
    assert_eq!(enc.known_received_count(), 0);
    let mut dec = Decoder::new(DecoderConfig {
        max_table_capacity: 34,
        ..DecoderConfig::default()
    });
    let fields = dec.decode_field_section(8, last).unwrap().unwrap();
    assert_eq!(&fields[0].name[..], b"e");
    assert_eq!(&fields[0].value[..], b"f");
    dec.feed_encoder_stream(&first_insert).unwrap();
    enc.feed_decoder_stream(&dec.take_decoder_stream()).unwrap();
    enc.encode(12, [(b"g", b"h")]).unwrap();
    assert_eq!(
        enc.insert_count(),
        2,
        "acknowledgment makes the old entry evictable"
    );
}

#[test]
fn sensitive_fields_survive_forwarding_and_static_or_dynamic_matches() {
    let mut dec = Decoder::new(DecoderConfig::default());
    let fields = dec
        .decode_field_section(0, Bytes::from_static(&[0, 0, 0x31, b'x', 1, b'y']))
        .unwrap()
        .unwrap();
    let mut enc = Encoder::new(EncoderConfig::default());
    let forwarded = enc.encode(0, fields).unwrap();
    let mut cursor = &forwarded[..];
    HeaderPrefix::decode(&mut cursor, 128, 0).unwrap();
    assert!(matches!(
        FieldLine::decode(&mut cursor, 4096).unwrap(),
        FieldLine::LiteralWithLiteralName {
            never_index: true,
            ..
        }
    ));
    assert_eq!(enc.insert_count(), 0);
    enc.encode(4, [(b"x", b"y")]).unwrap();
    let insert_count = enc.insert_count();
    let wire = enc
        .encode(
            8,
            [
                EncodeField {
                    name: &b"x"[..],
                    value: &b"y"[..],
                    never_index: true,
                },
                EncodeField {
                    name: b":method",
                    value: b"GET",
                    never_index: true,
                },
            ],
        )
        .unwrap();
    let mut cursor = &wire[..];
    HeaderPrefix::decode(&mut cursor, 128, insert_count).unwrap();
    for _ in 0..2 {
        assert!(matches!(
            FieldLine::decode(&mut cursor, 4096).unwrap(),
            FieldLine::LiteralWithNameRef {
                never_index: true,
                ..
            } | FieldLine::LiteralWithPostBaseNameRef {
                never_index: true,
                ..
            }
        ));
    }
    assert_eq!(enc.insert_count(), insert_count);
}

#[test]
fn tracking_budgets_fall_back_and_recover_after_acknowledgment() {
    let mut enc = Encoder::new(EncoderConfig {
        max_outstanding_sections: 1,
        max_outstanding_references: 1,
        ..EncoderConfig::default()
    });
    let mut dec = Decoder::new(DecoderConfig::default());
    let first = enc.encode(0, [(b"a", b"b"), (b"a", b"b")]).unwrap();
    assert_eq!(enc.tracked_reference_count(), 1);
    dec.feed_encoder_stream(&enc.take_encoder_stream()).unwrap();
    // Acknowledging the insertion alone removes blocking, but must not bypass tracking budgets.
    enc.feed_decoder_stream(&dec.take_decoder_stream()).unwrap();
    for stream in 1..100 {
        let section = enc.encode(stream * 4, [(b"a", b"b")]).unwrap();
        let prefix = HeaderPrefix::decode(&mut &section[..], 128, 1).unwrap();
        assert_eq!(prefix.required_insert_count, 0);
        assert_eq!(enc.tracked_section_count(), 1);
        assert_eq!(enc.tracked_reference_count(), 1);
    }
    dec.decode_field_section(0, first).unwrap().unwrap();
    enc.feed_decoder_stream(&dec.take_decoder_stream()).unwrap();
    assert_eq!(enc.tracked_reference_count(), 0);
    enc.encode(400, [(b"a", b"b")]).unwrap();
    assert_eq!(enc.tracked_section_count(), 1);
}

#[test]
fn output_budget_falls_back_without_partial_instructions() {
    for limit in 0..40 {
        let mut enc = Encoder::new(EncoderConfig {
            max_encoder_stream_bytes: limit,
            huffman: false,
            ..EncoderConfig::default()
        });
        let mut dec = Decoder::new(DecoderConfig::default());
        for stream in 0..10 {
            let value = format!("{stream}");
            let section = enc.encode(stream * 4, [("x", value.as_str())]).unwrap();
            assert!(enc.encoder_stream_len() <= limit);
            dec.feed_encoder_stream(&enc.take_encoder_stream()).unwrap();
            let fields = dec
                .decode_field_section(stream * 4, section)
                .unwrap()
                .unwrap();
            assert_eq!(&fields[0].value[..], value.as_bytes());
            enc.feed_decoder_stream(&dec.take_decoder_stream()).unwrap();
        }
    }
}

#[test]
fn input_rejection_is_transactional_and_exact_limit_works() {
    let mut enc = Encoder::new(EncoderConfig {
        max_field_section_size: 34,
        ..EncoderConfig::default()
    });
    enc.encode(0, [(b"a", b"b"), (b"c", b"d")]).unwrap_err();
    assert_eq!(enc.insert_count(), 0);
    assert_eq!(enc.encoder_stream_len(), 0);
    enc.encode(u64::MAX, [(b"a", b"b")]).unwrap_err();
    assert_eq!(enc.encoder_stream_len(), 0);
    enc.encode(0, [(b"a", b"b")]).unwrap();
    assert_eq!(enc.insert_count(), 1);
}

#[test]
fn blocking_budget_and_same_stream_multiple_sections() {
    let mut enc = Encoder::new(EncoderConfig {
        max_blocked_streams: 1,
        ..EncoderConfig::default()
    });
    enc.encode(0, [(b"a", b"b")]).unwrap();
    enc.encode(0, [(b"c", b"d")]).unwrap();
    assert_eq!(enc.blocking_streams, 1);
    let other = enc.encode(4, [(b"e", b"f")]).unwrap();
    assert_eq!(
        HeaderPrefix::decode(&mut &other[..], 128, 2)
            .unwrap()
            .required_insert_count,
        0
    );
    enc.on_decoder_instruction(DecoderInstruction::SectionAcknowledgment { stream_id: 0 })
        .unwrap();
    assert_eq!(enc.blocking_streams, 1);
    enc.on_decoder_instruction(DecoderInstruction::SectionAcknowledgment { stream_id: 0 })
        .unwrap();
    assert_eq!(enc.blocking_streams, 0);
    assert!(
        enc.on_decoder_instruction(DecoderInstruction::SectionAcknowledgment { stream_id: 0 })
            .is_err()
    );
}

#[test]
fn native_header_sensitivity_is_preserved() {
    let name = rama_http_types::header::AUTHORIZATION;
    let mut value = rama_http_types::HeaderValue::from_static("secret");
    value.set_sensitive(true);
    let mut enc = Encoder::new(EncoderConfig::default());
    let bytes = enc
        .encode(0, [EncodeField::from_header(&name, &value)])
        .unwrap();
    assert_eq!(enc.insert_count(), 0);
    let mut dec = Decoder::new(DecoderConfig::default());
    let fields = dec.decode_field_section(0, bytes).unwrap().unwrap();
    assert!(fields[0].never_index);
}
