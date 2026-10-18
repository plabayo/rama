//! Encoder-stream insertion and field-line representation are independent choices.

use super::*;
use rama_http_types::proto::h3::qpack::{
    encoding::{InsertionNameEncoding, InsertionPreferences},
    static_table,
};

fn insertion_preferences() -> FieldPreferences {
    FieldPreferences {
        representation: Representation::LiteralName,
        insertion: Some(InsertionPreferences {
            name_encoding: InsertionNameEncoding::Literal,
            name_huffman: Some(true),
            value_huffman: Some(true),
        }),
        name_huffman: Some(false),
        value_huffman: Some(false),
        ..FieldPreferences::default()
    }
}

fn field<'a>(
    name: &'a str,
    value: &'a str,
    preferences: &'a FieldPreferences,
) -> EncodeField<'a, &'a str, &'a str> {
    EncodeField {
        name,
        value,
        never_index: false,
        preferences: Some(preferences),
    }
}

fn deferred() -> EncoderConfig {
    EncoderConfig {
        defer_dynamic_first_section: true,
        max_blocked_streams: 0,
        ..EncoderConfig::default()
    }
}

#[test]
fn explicit_insertions_use_current_values_while_the_first_field_section_stays_literal() {
    for (representation, blocked) in [
        (Representation::LiteralName, 0),
        (Representation::Automatic, 0),
        (Representation::Automatic, 4),
    ] {
        for value in ["first-current-value", "second-current-value"] {
            let mut config = deferred();
            config.max_blocked_streams = blocked;
            let mut encoder = Encoder::new(config);
            let mut preferences = insertion_preferences();
            preferences.representation = representation;
            let section = encoder
                .encode(0, [field("x-current", value, &preferences)])
                .unwrap();
            let instructions = encoder.take_encoder_stream();
            let mut decoder = Decoder::new(DecoderConfig::default());
            // Literal HEADERS decode before the independently ordered encoder stream.
            let decoded = decoder
                .decode_field_section(0, section.clone())
                .unwrap()
                .unwrap();
            assert_eq!(decoded[0].value.as_ref(), value.as_bytes());
            assert_eq!(encoder.insert_count(), 1);
            let mut cursor = instructions.as_ref();
            assert_matches!(
                EncoderInstruction::decode(&mut cursor, 4096).unwrap(),
                EncoderInstruction::SetDynamicTableCapacity { .. }
            );
            match EncoderInstruction::decode(&mut cursor, 4096).unwrap() {
                EncoderInstruction::InsertWithLiteralName {
                    name,
                    value: inserted,
                    name_huffman,
                    value_huffman,
                } => {
                    assert_eq!(name.as_ref(), b"x-current");
                    assert_eq!(inserted.as_ref(), value.as_bytes());
                    assert!(name_huffman && value_huffman);
                }
                other => panic!("expected current-field insertion, got {other:?}"),
            }
            assert!(cursor.is_empty());
            let mut cursor = section.as_ref();
            assert_eq!(
                HeaderPrefix::decode(&mut cursor, 128, 0)
                    .unwrap()
                    .required_insert_count,
                0
            );
            assert_matches!(
                FieldLine::decode(&mut cursor, 4096).unwrap(),
                FieldLine::LiteralWithLiteralName {
                    name_huffman: false,
                    value_huffman: false,
                    ..
                }
            );
            decoder.feed_encoder_stream(&instructions).unwrap();
            encoder
                .feed_decoder_stream(&decoder.take_decoder_stream())
                .unwrap();
            // Normal later compression can reference the acknowledged fresh entry.
            let later = encoder.encode(4, [("x-current", value)]).unwrap();
            assert!(
                HeaderPrefix::decode(&mut later.as_ref(), 128, 1)
                    .unwrap()
                    .required_insert_count
                    > 0
            );
            let decoded = decoder.decode_field_section(4, later).unwrap().unwrap();
            assert_eq!(decoded[0].value.as_ref(), value.as_bytes());
        }
    }
}

#[test]
fn explicit_static_name_encoding_is_independent_and_invalid_names_are_transactional() {
    let mut encoder = Encoder::new(deferred());
    let mut preferences = insertion_preferences();
    preferences.insertion.as_mut().unwrap().name_encoding = InsertionNameEncoding::StaticName(17);
    // The first field in the input would insert; the second has an invalid name
    // reference. Neither capacity nor the first insertion may escape preflight.
    let ordinary = insertion_preferences();
    let error = encoder
        .encode(
            0,
            [
                field("x-first", "one", &ordinary),
                field("x-wrong", "two", &preferences),
            ],
        )
        .unwrap_err();
    assert_eq!(error.scope(), Some(ErrorScope::Stream));
    assert_eq!(encoder.insert_count(), 0);
    assert!(encoder.take_encoder_stream().is_empty());
    assert!(encoder.defer_dynamic_first_section);
    let section = encoder
        .encode(0, [field(":method", "POST", &preferences)])
        .unwrap();
    let instructions = encoder.take_encoder_stream();
    let mut cursor = instructions.as_ref();
    EncoderInstruction::decode(&mut cursor, 4096).unwrap();
    assert_matches!(
        EncoderInstruction::decode(&mut cursor, 4096).unwrap(),
        EncoderInstruction::InsertWithNameRef {
            is_static: true,
            name_index: 17,
            ..
        }
    );
    let mut decoder = Decoder::new(DecoderConfig::default());
    decoder.feed_encoder_stream(&instructions).unwrap();
    assert_eq!(
        decoder.decode_field_section(0, section).unwrap().unwrap()[0]
            .value
            .as_ref(),
        b"POST"
    );
}

#[test]
fn explicit_insertions_cannot_override_caller_or_preference_sensitivity() {
    for caller in [false, true] {
        let mut encoder = Encoder::new(deferred());
        let mut preferences = insertion_preferences();
        preferences.never_index = !caller;
        let mut sensitive = field("authorization", "current secret", &preferences);
        sensitive.never_index = caller;
        encoder.encode(0, [sensitive]).unwrap_err();
        assert_eq!(encoder.insert_count(), 0);
        assert!(encoder.take_encoder_stream().is_empty());
        assert!(encoder.defer_dynamic_first_section);
        assert_eq!(encoder.tracked_section_count(), 0);
    }
}

#[test]
fn explicit_batch_capacity_and_output_credit_rejections_leave_no_partial_prefix() {
    let preferences = insertion_preferences();
    let mut reference = Encoder::new(deferred());
    reference
        .encode(
            0,
            [
                field("x-a", "one", &preferences),
                field("x-b", "two", &preferences),
            ],
        )
        .unwrap();
    let exact_wire = reference.take_encoder_stream().len();
    for case in 0..4 {
        let mut config = deferred();
        match case {
            0 => {
                config.max_table_capacity = 0;
                config.target_capacity = 0;
            }
            1 => {
                config.target_capacity = 40;
            }
            2 => {
                config.max_encoder_stream_bytes = exact_wire - 1;
            }
            3 => (),
            _ => unreachable!(),
        }
        let mut encoder = Encoder::new(config);
        let input = [
            field("x-a", "one", &preferences),
            field("x-b", "two", &preferences),
        ];
        let result = if case == 3 {
            encoder.encode_with_credit(0, input, exact_wire - 1, None)
        } else {
            encoder.encode(0, input)
        };
        result.unwrap_err();
        assert_eq!(encoder.insert_count(), 0);
        assert!(encoder.take_encoder_stream().is_empty());
        assert!(encoder.defer_dynamic_first_section);
    }
    let mut encoder = Encoder::new(deferred());
    encoder
        .encode_with_credit(
            0,
            [
                field("x-a", "one", &preferences),
                field("x-b", "two", &preferences),
            ],
            exact_wire,
            None,
        )
        .unwrap();
    assert_eq!(encoder.insert_count(), 2);
}

#[test]
fn explicit_batch_respects_outstanding_references_before_any_insertion() {
    let mut encoder = Encoder::new(EncoderConfig {
        target_capacity: 80,
        ..EncoderConfig::default()
    });
    let first = encoder.encode(0, [("x", "old")]).unwrap();
    let first_instructions = encoder.take_encoder_stream();
    let preferences = insertion_preferences();
    encoder
        .encode(
            4,
            [
                field("a", "one", &preferences),
                field("b", "two", &preferences),
            ],
        )
        .unwrap_err();
    assert_eq!(encoder.insert_count(), 1);
    assert!(encoder.take_encoder_stream().is_empty());
    let mut decoder = Decoder::new(DecoderConfig::default());
    decoder.feed_encoder_stream(&first_instructions).unwrap();
    decoder.decode_field_section(0, first).unwrap().unwrap();
    encoder
        .feed_decoder_stream(&decoder.take_decoder_stream())
        .unwrap();
    let next = encoder
        .encode(
            4,
            [
                field("a", "one", &preferences),
                field("b", "two", &preferences),
            ],
        )
        .unwrap();
    decoder
        .feed_encoder_stream(&encoder.take_encoder_stream())
        .unwrap();
    let fields = decoder.decode_field_section(4, next).unwrap().unwrap();
    assert_eq!(fields[0].name.as_ref(), b"a");
    assert_eq!(fields[1].value.as_ref(), b"two");
    assert_eq!(encoder.insert_count(), 3);
}

#[test]
fn automatic_insertion_name_encoding_uses_the_protocol_static_table() {
    let mut encoder = Encoder::new(deferred());
    let mut preferences = insertion_preferences();
    preferences.insertion = Some(InsertionPreferences::default());
    let section = encoder
        .encode(0, [field(":method", "POST", &preferences)])
        .unwrap();
    let instructions = encoder.take_encoder_stream();
    let mut cursor = instructions.as_ref();
    EncoderInstruction::decode(&mut cursor, 4096).unwrap();
    let index = match EncoderInstruction::decode(&mut cursor, 4096).unwrap() {
        EncoderInstruction::InsertWithNameRef {
            is_static: true,
            name_index,
            ..
        } => name_index,
        other => panic!("expected static insertion name, got {other:?}"),
    };
    assert_eq!(static_table::get(index as usize).unwrap().0, b":method");
    let mut decoder = Decoder::new(DecoderConfig::default());
    decoder.feed_encoder_stream(&instructions).unwrap();
    assert_eq!(
        decoder.decode_field_section(0, section).unwrap().unwrap()[0]
            .value
            .as_ref(),
        b"POST"
    );
}
