use super::*;
use crate::profile::{
    capture::joint::{
        CaptureLevel, CapturedSlot, CapturedSlotKind, JointCapture, JointCaptureLimits,
    },
    format::canonical::ValueId,
};
use ahash::HashSet;
use rama_http::proto::h3::observation::{
    ObservationCompleteness, ObservedSetting, ObservedUniStream,
};
use sha2::{Digest as _, Sha256};

#[test]
fn compact_local_settings_accept_exact_budget_with_settings_prefix() {
    for count in [0, 1, 2, 3, 16, 256] {
        let mut source = source();
        source.streams.retain(|stream| stream.stream_type == 0);
        source.control.retain(|frame| frame.frame_type == 4);
        source.encoder_instructions.clear();
        source.local_settings = (0..count)
            .map(|index| ObservedSetting {
                id: 0x21 + 31 * index,
                value: index,
                grease: true,
            })
            .collect();
        let limits = H3SequenceCaptureLimits::default();
        let capture = H3ClientSequenceCapture::capture_at_request_head(&source, limits).unwrap();
        for value in [
            capture.canonical(limits).unwrap(),
            capture.structural(limits).unwrap(),
        ] {
            let exact = H3SequenceCaptureLimits {
                bytes: value.bytes.len(),
                ..limits
            };
            value.validated_domain(exact.bytes).unwrap();
            value.validated_domain(exact.bytes - 1).unwrap_err();
            // Structural encoding omits per-request details; its budget
            // does not substitute for the raw capture's input budget.
            value.validated_domain(exact.bytes).unwrap();
        }
    }
}

fn source() -> H3ObservationSnapshot {
    H3ObservationSnapshot {
        revision: 10,
        settings_received: true,
        settings: Some(vec![]),
        local_settings: vec![ObservedSetting {
            id: 1,
            value: 4096,
            grease: false,
        }],
        streams: vec![
            ObservedUniStream {
                sequence: 2,
                stream_id: 2,
                stream_type: 0,
                grease: false,
            },
            ObservedUniStream {
                sequence: 5,
                stream_id: 10,
                stream_type: 0x21,
                grease: true,
            },
            ObservedUniStream {
                sequence: 3,
                stream_id: 18,
                stream_type: 2,
                grease: false,
            },
        ],
        control: vec![
            ObservedControlFrame {
                sequence: 4,
                frame_type: 4,
                length: 0,
                element_id: None,
                value: Box::default(),
            },
            ObservedControlFrame {
                sequence: 9,
                frame_type: 0xf0700,
                length: 4,
                element_id: Some(0),
                value: b"u=1".as_slice().into(),
            },
            ObservedControlFrame {
                sequence: 10,
                frame_type: 0x21,
                length: 13,
                element_id: None,
                value: Box::default(),
            },
        ],
        encoder_instructions: vec![
            ObservedEncoderInstruction::Capacity { capacity: 4096 },
            ObservedEncoderInstruction::InsertLiteral {
                name_bytes: 4,
                value_bytes: 12,
                name_huffman: false,
                value_huffman: true,
            },
        ],
        completeness: ObservationCompleteness {
            snapshot: true,
            settings: true,
            local_settings: true,
            streams: true,
            control: true,
            qpack: true,
            fields: true,
        },
        connection_error: None,
    }
}

fn capture() -> H3ClientSequenceCapture {
    H3ClientSequenceCapture::capture_at_request_head(&source(), H3SequenceCaptureLimits::default())
        .unwrap()
}

fn resign(bytes: Vec<u8>) -> CanonicalValue {
    CanonicalValue {
        id: ValueId(Sha256::digest(&bytes).into()),
        bytes: bytes.into(),
    }
}

#[test]
fn h3_sequence_preserves_merged_relative_order_and_independent_qpack_order() {
    let limits = H3SequenceCaptureLimits::default();
    let capture = capture();
    let encoded = capture.canonical(limits).unwrap();
    let restored = H3ClientSequenceCapture::from_canonical(&encoded, limits).unwrap();
    assert_eq!(
        serde_json::to_value(&capture).unwrap(),
        serde_json::to_value(&restored).unwrap()
    );
    assert!(matches!(
        restored.events[0],
        H3CapturedEvent::Stream { stream_type: 0, .. }
    ));
    assert!(matches!(
        restored.events[2],
        H3CapturedEvent::Control { frame_type: 4, .. }
    ));
    assert!(matches!(
        restored.events[3],
        H3CapturedEvent::Stream {
            stream_type: 0x21,
            ..
        }
    ));
    let mut later = source();
    later.revision = 100;
    for stream in &mut later.streams {
        stream.sequence += 20;
    }
    for frame in &mut later.control {
        frame.sequence += 20;
    }
    assert_eq!(
        encoded.id,
        H3ClientSequenceCapture::capture_at_request_head(&later, limits)
            .unwrap()
            .canonical(limits)
            .unwrap()
            .id
    );
    later.streams[1].sequence = 21;
    assert_ne!(
        encoded.id,
        H3ClientSequenceCapture::capture_at_request_head(&later, limits)
            .unwrap()
            .canonical(limits)
            .unwrap()
            .id
    );
}

#[test]
fn h3_sequence_requires_complete_component_prefixes_and_valid_revisions() {
    let limits = H3SequenceCaptureLimits::default();
    for case in 0..9 {
        let mut source = source();
        match case {
            0 => source.completeness.snapshot = false,
            1 => source.completeness.local_settings = false,
            2 => source.completeness.streams = false,
            3 => source.completeness.control = false,
            4 => source.completeness.qpack = false,
            5 => source.connection_error = Some(0x100),
            6 => source.control[0].sequence = 2,
            7 => source.revision = 9,
            _ => source.settings_received = false,
        }
        H3ClientSequenceCapture::capture_at_request_head(&source, limits).unwrap_err();
    }
    let mut source = source();
    source.settings_received = false;
    source.settings = None;
    source.completeness.settings = false;
    source.streams.clear();
    source.control.clear();
    source.encoder_instructions.clear();
    H3ClientSequenceCapture::capture_at_request_head(&source, limits).unwrap_err();
}

#[test]
fn h3_sequence_budget_precedes_owned_capture_and_bounds_all_arrays() {
    let source = source();
    let limits = H3SequenceCaptureLimits::default();
    let size = capture().canonical(limits).unwrap().bytes.len();
    for limits in [
        H3SequenceCaptureLimits {
            events: 4,
            ..limits
        },
        H3SequenceCaptureLimits {
            instructions: 1,
            ..limits
        },
        H3SequenceCaptureLimits {
            settings: 0,
            ..limits
        },
        H3SequenceCaptureLimits {
            bytes: size - 1,
            ..limits
        },
    ] {
        H3ClientSequenceCapture::capture_at_request_head(&source, limits).unwrap_err();
    }
    H3ClientSequenceCapture::capture_at_request_head(
        &source,
        H3SequenceCaptureLimits {
            bytes: size,
            ..limits
        },
    )
    .unwrap();
}

#[test]
fn h3_sequence_import_enforces_stream_roles_control_order_and_instruction_shapes() {
    let limits = H3SequenceCaptureLimits::default();
    for case in 0..10 {
        let mut value = capture();
        match case {
            0 => {
                value.events[0] = H3CapturedEvent::Stream {
                    stream_id: 3,
                    stream_type: 0,
                }
            }
            1 => {
                value.events[3] = H3CapturedEvent::Stream {
                    stream_id: 2,
                    stream_type: 0x21,
                }
            }
            2 => {
                value.events[3] = H3CapturedEvent::Stream {
                    stream_id: 10,
                    stream_type: 0,
                }
            }
            3 => value.events.swap(0, 2),
            4 => {
                value.events[4] = H3CapturedEvent::Control {
                    frame_type: 4,
                    length: 0,
                    element_id: None,
                    value: Box::default(),
                }
            }
            5 => {
                value.events[4] = H3CapturedEvent::Control {
                    frame_type: 0,
                    length: 0,
                    element_id: None,
                    value: Box::default(),
                }
            }
            6 => {
                value.encoder_instructions[1] = ObservedEncoderInstruction::InsertNameReference {
                    is_static: true,
                    index: 99,
                    value_bytes: 0,
                    value_huffman: false,
                }
            }
            7 => {
                value.events[5] = H3CapturedEvent::Control {
                    frame_type: 0x21,
                    length: 2,
                    element_id: None,
                    value: Box::new([7]),
                }
            }
            8 => {
                value.encoder_instructions[0] =
                    ObservedEncoderInstruction::Capacity { capacity: 4097 }
            }
            _ => {
                value.events[1] = H3CapturedEvent::Stream {
                    stream_id: 18,
                    stream_type: 0x40,
                }
            }
        }
        value.canonical(limits).unwrap_err();
    }
}

#[test]
fn reserved_control_bodies_roundtrip_without_splitting_structural_shapes() {
    let limits = H3SequenceCaptureLimits::default();
    let mut structural = None;
    let mut literals = HashSet::default();
    for byte in [7, 19] {
        let mut source = source();
        source.control[2].value = vec![byte; 13].into();
        let captured = H3ClientSequenceCapture::capture_at_request_head(&source, limits).unwrap();
        let encoded = captured.canonical(limits).unwrap();
        literals.insert(encoded.id);
        let restored = H3ClientSequenceCapture::from_canonical(&encoded, limits).unwrap();
        assert!(
            matches!(&restored.events[5], H3CapturedEvent::Control { value, .. } if value.as_ref() == [byte; 13])
        );
        let shape = captured.structural(limits).unwrap();
        assert_eq!(*structural.get_or_insert(shape.id), shape.id);
        let bounded = H3SequenceCaptureLimits {
            bytes: encoded.bytes.len() - 1,
            ..limits
        };
        H3ClientSequenceCapture::capture_at_request_head(&source, bounded).unwrap_err();

        // Ordinary unknown bodies remain metadata-only, even when supplied by a producer.
        source.control[2].frame_type = 0x22;
        let redacted = H3ClientSequenceCapture::capture_at_request_head(&source, limits).unwrap();
        assert!(
            matches!(&redacted.events[5], H3CapturedEvent::Control { value, .. } if value.is_empty())
        );
    }
    assert_eq!(literals.len(), 2);
}

#[test]
fn h3_sequence_structures_group_reserved_draws_and_connection_references() {
    let limits = H3SequenceCaptureLimits::default();
    let mut key = None;
    for sequence in 0..10_000u64 {
        let mut value = capture();
        value.events[3] = H3CapturedEvent::Stream {
            stream_id: 22 + 4 * sequence,
            stream_type: 0x21 + 31 * sequence,
        };
        value.events[5] = H3CapturedEvent::Control {
            frame_type: 0x21 + 31 * sequence,
            length: sequence % 17,
            element_id: None,
            value: Box::default(),
        };
        value.encoder_instructions[1] = ObservedEncoderInstruction::InsertLiteral {
            name_bytes: 3,
            value_bytes: sequence as usize % 256,
            name_huffman: false,
            value_huffman: true,
        };
        let structure = value.structural(limits).unwrap();
        assert_eq!(*key.get_or_insert(structure.id), structure.id);
        structure.validated_domain(limits.bytes).unwrap();
    }
    let mut value = capture();
    value.encoder_instructions[0] = ObservedEncoderInstruction::Capacity { capacity: 1024 };
    assert_eq!(key.unwrap(), value.structural(limits).unwrap().id);
}

#[test]
fn h3_sequence_import_rejects_bad_envelopes_trailers_and_noncanonical_structure() {
    let limits = H3SequenceCaptureLimits::default();
    let value = capture().canonical(limits).unwrap();
    for size in 0..value.bytes.len() {
        H3ClientSequenceCapture::from_canonical(&resign(value.bytes[..size].to_vec()), limits)
            .unwrap_err();
    }
    let mut bad = value.clone();
    bad.id.0[0] ^= 1;
    bad.validated_domain(limits.bytes).unwrap_err();
    let mut bytes = value.bytes.to_vec();
    bytes.push(0);
    resign(bytes).validated_domain(limits.bytes).unwrap_err();
    let mut bytes = value.bytes.to_vec();
    bytes[16] = 20;
    resign(bytes).validated_domain(limits.bytes).unwrap_err();
}

#[test]
fn h3_sequence_is_quic_connection_owned_in_joint_captures() {
    let value = capture()
        .canonical(H3SequenceCaptureLimits::default())
        .unwrap();
    let mut joint = JointCapture {
        completeness: ProfileCaptureCompleteness::Complete,
        level: CaptureLevel::Connection,
        slots: Box::new([CapturedSlot {
            kind: CapturedSlotKind::Http3Sequence,
            value,
        }]),
    };
    let limits = JointCaptureLimits::default();
    joint.canonical(limits).unwrap();
    joint
        .structural(limits)
        .unwrap()
        .validated_domain(limits.bytes)
        .unwrap();
    joint.level = CaptureLevel::Request;
    joint.canonical(limits).unwrap_err();
}

#[test]
fn qpack_shape_lengths_have_separate_observed_and_encoded_budgets() {
    for instruction in [
        ObservedEncoderInstruction::InsertNameReference {
            is_static: true,
            index: 0,
            value_bytes: 4096,
            value_huffman: false,
        },
        ObservedEncoderInstruction::InsertLiteral {
            name_bytes: 512,
            value_bytes: 4096,
            name_huffman: false,
            value_huffman: true,
        },
    ] {
        let mut capture = capture();
        capture.encoder_instructions = Box::new([instruction]);
        let value = capture
            .canonical(H3SequenceCaptureLimits::default())
            .unwrap();
        assert!(value.bytes.len() < 512);
        let limits = H3SequenceCaptureLimits {
            bytes: value.bytes.len(),
            ..H3SequenceCaptureLimits::default()
        };
        capture.canonical(limits).unwrap();
        H3ClientSequenceCapture::from_canonical(&value, limits).unwrap();
        value.validated_domain(value.bytes.len()).unwrap();
        capture
            .canonical(H3SequenceCaptureLimits {
                observed_field_bytes: 511,
                ..limits
            })
            .unwrap_err();
        let decoded = H3ClientSequenceCapture::from_canonical(
            &value,
            H3SequenceCaptureLimits {
                observed_field_bytes: 511,
                ..limits
            },
        );
        if matches!(
            capture.encoder_instructions[0],
            ObservedEncoderInstruction::InsertLiteral { .. }
        ) {
            decoded.unwrap_err();
        } else {
            // The inserted value length is deliberately not retained.
            decoded.unwrap();
        }
        capture
            .canonical(H3SequenceCaptureLimits {
                bytes: value.bytes.len() - 1,
                ..limits
            })
            .unwrap_err();
    }
}

#[test]
fn h3_structure_ignores_request_qpack_priority_and_control_arrival() {
    let limits = H3SequenceCaptureLimits::default();
    let original = capture();
    let structure = original.structural(limits).unwrap();
    let sample = original.canonical(limits).unwrap();
    for static_index in [5, 84] {
        // cookie and authorization
        let mut different = capture();
        different.encoder_instructions = Box::new([
            ObservedEncoderInstruction::Capacity { capacity: 1024 },
            ObservedEncoderInstruction::InsertNameReference {
                is_static: true,
                index: static_index,
                value_bytes: 37,
                value_huffman: false,
            },
            ObservedEncoderInstruction::Duplicate { index: 0 },
        ]);
        different.events[4] = H3CapturedEvent::Control {
            frame_type: 0xf0700,
            length: 9,
            element_id: Some(12),
            value: b"u=7, i".as_slice().into(),
        };
        // SETTINGS arrives before the independent encoder stream.
        different.events.swap(1, 2);
        assert_eq!(different.structural(limits).unwrap().id, structure.id);
        assert_ne!(different.canonical(limits).unwrap().id, sample.id);
        different.encoder_instructions = Box::default();
        assert_eq!(different.structural(limits).unwrap().id, structure.id);
    }
    let mut before_settings = source();
    before_settings.settings_received = false;
    before_settings.settings = None;
    before_settings.control.clear();
    H3ClientSequenceCapture::capture_at_request_head(&before_settings, limits).unwrap_err();
}

#[test]
fn h3_sequence_has_independent_canonical_goldens() {
    let capture = capture();
    let limits = H3SequenceCaptureLimits::default();
    for (value, expected, digest) in [
        (
            capture.canonical(limits).unwrap(),
            "72616d612d70726f66696c65000001001301000000000000001000000000000000010000000000001000000000000000000600000000000000000200000000000000000000000000000000120000000000000002010000000000000004000000000000000000000000000000000000000000000000000a00000000000000210100000000000f070000000000000000040100000000000000000000000000000003753d31010000000000000021000000000000000d000000000000000000000000000000000200000000000000100002000000000000000400000000000000000001",
            "17dafb08287c4f1b63cef92932102914dd0d2363ef485fac1410a047b8fce619",
        ),
        (
            capture.structural(limits).unwrap(),
            "72616d612d70726f66696c6500000100140100000000000000100000000000000001000000000000100000000000000000040000000000000000020000000000000000000000000000000006000000000000000200000000000000000a000000000000002101000000000000000400000000000000000000000000000000000000000000000000",
            "7a3a2c785c879a0190c797ec5552ede85cfa5c54a28969960966ec4a13067974",
        ),
    ] {
        let bytes = value
            .bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let hash = value
            .id
            .0
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        assert_eq!(bytes, expected);
        assert_eq!(hash, digest);
    }
}

#[test]
fn h3_sequence_rejects_out_of_range_wire_integers() {
    let limits = H3SequenceCaptureLimits::default();
    for case in 0..6 {
        let mut capture = capture();
        match case {
            0 => {
                capture.events[3] = H3CapturedEvent::Stream {
                    stream_id: (1_u64 << 62) + 2,
                    stream_type: 33,
                }
            }
            1 => {
                capture.events[3] = H3CapturedEvent::Stream {
                    stream_id: 10,
                    stream_type: 1_u64 << 62,
                }
            }
            2 => {
                capture.events[5] = H3CapturedEvent::Control {
                    frame_type: 1_u64 << 62,
                    length: 0,
                    element_id: None,
                    value: Box::default(),
                }
            }
            3 => {
                capture.events[5] = H3CapturedEvent::Control {
                    frame_type: 33,
                    length: 1_u64 << 62,
                    element_id: None,
                    value: Box::default(),
                }
            }
            4 => {
                capture.events[4] = H3CapturedEvent::Control {
                    frame_type: 0xf0700,
                    length: 12,
                    element_id: Some(1_u64 << 62),
                    value: b"u=1".as_slice().into(),
                }
            }
            _ => {
                capture.encoder_instructions[1] =
                    ObservedEncoderInstruction::Duplicate { index: 1_u64 << 62 }
            }
        }
        capture.canonical(limits).unwrap_err();
        capture.structural(limits).unwrap_err();
    }
    let mut capture = capture();
    capture.encoder_instructions[1] = ObservedEncoderInstruction::Duplicate {
        index: (1_u64 << 62) - 1,
    };
    capture.canonical(limits).unwrap();
}

#[test]
fn qpack_samples_do_not_retain_request_value_lengths() {
    let limits = H3SequenceCaptureLimits::default();
    for reference in [false, true] {
        let mut sample_id = None;
        for length in [1, 8, 128, kib(8)] {
            let mut source = source();
            source.encoder_instructions = vec![if reference {
                ObservedEncoderInstruction::InsertNameReference {
                    is_static: true,
                    index: 5,
                    value_bytes: length,
                    value_huffman: true,
                }
            } else {
                ObservedEncoderInstruction::InsertLiteral {
                    name_bytes: 6,
                    value_bytes: length,
                    name_huffman: false,
                    value_huffman: true,
                }
            }];
            let captured =
                H3ClientSequenceCapture::capture_at_request_head(&source, limits).unwrap();
            assert!(matches!(
                captured.encoder_instructions[0],
                ObservedEncoderInstruction::InsertNameReference { value_bytes: 0, .. }
                    | ObservedEncoderInstruction::InsertLiteral { value_bytes: 0, .. }
            ));
            let encoded = captured.canonical(limits).unwrap();
            assert_eq!(*sample_id.get_or_insert(encoded.id), encoded.id);
        }
    }
}
