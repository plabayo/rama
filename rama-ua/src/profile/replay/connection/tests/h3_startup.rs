use super::*;
use crate::profile::{
    capture::http3::{H3CapturedEvent, H3ClientSequenceCapture, bootstrap::H3BootstrapCapture},
    format::canonical::ValueId,
    replay::{connection::h3_startup, request::LoweredProfileItem},
};
use rama_core::extensions::Extensions;
use rama_http::{
    Method,
    proto::h3::{
        control::ClientControlPreferences,
        critical_streams::{Order, Preferences, Startup},
        observation::{
            InsertionFieldMatch, ObservedEncoderBindings, ObservedEncoderInstruction,
            ObservedInsertionBinding,
        },
        qpack::EncoderPreferences,
    },
};

fn lowered(
    extensions: &Extensions,
    sequence: &H3ClientSequenceCapture,
    bootstrap: Option<&H3BootstrapCapture>,
    initial: bool,
) -> Vec<LoweredProfileItem> {
    let mut report = ProfilePreservationReport::default();
    h3_startup::prepare(extensions, Some(sequence), bootstrap, initial, &mut report)
        .unwrap()
        .unwrap();
    report
        .differences
        .iter()
        .filter_map(|difference| match difference {
            ProfilePreservationDifference::LoweredProfileItem { item } => Some(*item),
            _ => None,
        })
        .collect()
}

fn priority_prefix(target: u64, length: u64) -> H3ClientSequenceCapture {
    H3ClientSequenceCapture {
        completeness: ProfileCaptureCompleteness::Complete,
        local_settings: OrderedProtocolCapture {
            completeness: ProfileCaptureCompleteness::Complete,
            namespace: OrderNamespace::Http3Setting,
            fields: Box::default(),
        },
        events: vec![
            H3CapturedEvent::Stream {
                stream_id: 2,
                stream_type: 0,
            },
            H3CapturedEvent::Control {
                frame_type: 4,
                length: 0,
                element_id: None,
                value: Box::default(),
            },
            H3CapturedEvent::Control {
                frame_type: 0xf0700,
                length,
                element_id: Some(target),
                value: b"u=0".to_vec().into(),
            },
        ]
        .into(),
        encoder_instructions: Box::default(),
    }
}

#[test]
fn client_priority_targets_survive_compilation_into_native_wire_preferences() {
    for (target, encoded_target) in [(0, vec![0]), (4, vec![4]), (64, vec![0x40, 0x40])] {
        let capture = priority_prefix(target, 3 + encoded_target.len() as u64);
        let extensions = Extensions::new();
        h3_startup::prepare(
            &extensions,
            Some(&capture),
            None,
            false,
            &mut ProfilePreservationReport::default(),
        )
        .unwrap()
        .unwrap()
        .apply(&extensions);
        let controls = extensions.get_ref::<ClientControlPreferences>().unwrap();
        assert_eq!(controls.frames.len(), 1);
        let mut actual = Vec::new();
        controls.frames[0].encode(&mut actual).unwrap();
        // Independent RFC9218 frame bytes: type, length, target varint, Priority field.
        let mut expected = vec![0x80, 0x0f, 0x07, 0x00, 3 + encoded_target.len() as u8];
        expected.extend_from_slice(&encoded_target);
        expected.extend_from_slice(b"u=0");
        assert_eq!(actual, expected);
    }
}

#[test]
fn priority_replay_refuses_invalid_stream_roles_and_inconsistent_lengths() {
    for target in [1, 2, 3, 1 << 62] {
        assert!(!h3_startup::supports(
            Some(&priority_prefix(target, 4)),
            None
        ));
    }
    assert!(!h3_startup::supports(Some(&priority_prefix(4, 5)), None));
}

#[test]
fn dynamic_startup_preserves_encoder_allocation_and_capacity() {
    let mut sequence = priority_prefix(0, 4);
    let mut events = sequence.events.into_vec();
    events.push(H3CapturedEvent::Stream {
        stream_id: 10,
        stream_type: 2,
    });
    sequence.events = events.into();
    sequence.encoder_instructions = vec![
        ObservedEncoderInstruction::Capacity { capacity: 4096 },
        ObservedEncoderInstruction::InsertLiteral {
            name_bytes: 6,
            value_bytes: 9,
            name_huffman: true,
            value_huffman: false,
        },
    ]
    .into();
    let bootstrap = H3BootstrapCapture {
        request: ValueId([3; 32]),
        method: Method::GET,
        fields: 1,
        bindings: ObservedEncoderBindings {
            stream_id: 0,
            complete: true,
            insertions: vec![ObservedInsertionBinding {
                instruction_index: 1,
                insertion_index: 0,
                field: InsertionFieldMatch::Unique { field_index: 0 },
            }],
        },
    };
    assert!(!h3_startup::supports(Some(&sequence), None));
    // Without its bootstrap the prefix is lowered to native stream and control startup.
    let native = Extensions::new();
    h3_startup::prepare(
        &native,
        Some(&sequence),
        None,
        false,
        &mut ProfilePreservationReport::default(),
    )
    .unwrap()
    .unwrap()
    .apply(&native);
    assert_eq!(
        native.get_ref::<Preferences>(),
        Some(&Preferences {
            order: Order::DecoderFirst,
            encoder: Startup::Immediate,
            decoder: Startup::OnDemand,
            ..Preferences::default()
        })
    );
    let encoding = native.get_ref::<EncoderPreferences>().unwrap();
    assert_eq!(encoding.target_capacity, None);
    assert_eq!(encoding.defer_dynamic_first_section, Some(true));
    let extensions = Extensions::new();
    h3_startup::prepare(
        &extensions,
        Some(&sequence),
        Some(&bootstrap),
        false,
        &mut ProfilePreservationReport::default(),
    )
    .unwrap()
    .unwrap()
    .apply(&extensions);
    assert_eq!(
        extensions.get_ref::<Preferences>(),
        Some(&Preferences {
            order: Order::DecoderFirst,
            encoder: Startup::OnDemand,
            decoder: Startup::OnDemand,
            ..Preferences::default()
        })
    );
    let encoding = extensions.get_ref::<EncoderPreferences>().unwrap();
    assert_eq!(encoding.target_capacity, Some(4096));
    assert_eq!(encoding.defer_dynamic_first_section, Some(true));
    assert_eq!(
        extensions
            .get_ref::<ClientControlPreferences>()
            .unwrap()
            .frames
            .len(),
        1
    );

    // Only request-owned insertion validation authorizes eager ordered startup.
    let initial = Extensions::new();
    h3_startup::prepare(
        &initial,
        Some(&sequence),
        Some(&bootstrap),
        true,
        &mut ProfilePreservationReport::default(),
    )
    .unwrap()
    .unwrap()
    .apply(&initial);
    assert_eq!(
        initial.get_ref::<Preferences>(),
        Some(&Preferences {
            order: Order::DecoderFirst,
            encoder: Startup::Immediate,
            decoder: Startup::OnDemand,
            ordered_startup: true,
        })
    );
    assert_eq!(
        initial
            .get_ref::<EncoderPreferences>()
            .unwrap()
            .defer_dynamic_first_section,
        Some(false)
    );
    let mut incompatible = sequence.clone();
    let mut events = incompatible.events.into_vec();
    events.push(H3CapturedEvent::Stream {
        stream_id: 6,
        stream_type: 3,
    });
    incompatible.events = events.into();
    assert_eq!(
        lowered(&Extensions::new(), &incompatible, Some(&bootstrap), true),
        [LoweredProfileItem::Http3StartupOrder],
        "recorded descending prefix order is not represented by allocated-ID startup"
    );
    let mut trailing_control = sequence.clone();
    let mut events = trailing_control.events.into_vec();
    events.swap(2, 3);
    trailing_control.events = events.into();
    assert_eq!(
        lowered(
            &Extensions::new(),
            &trailing_control,
            Some(&bootstrap),
            true
        ),
        [LoweredProfileItem::Http3StartupOrder],
        "initial CONTROL cannot move silently before recorded QPACK"
    );
    let caller = Extensions::new();
    caller.insert(Preferences {
        order: Order::DecoderFirst,
        encoder: Startup::OnDemand,
        decoder: Startup::OnDemand,
        ..Preferences::default()
    });
    assert_eq!(
        lowered(&caller, &sequence, Some(&bootstrap), true),
        [LoweredProfileItem::CallerHttp3Startup],
        "caller startup conflict stays explicit"
    );

    for case in 0..5 {
        let mut invalid = sequence.clone();
        match case {
            0 => {
                invalid.events[3] = H3CapturedEvent::Stream {
                    stream_id: 14,
                    stream_type: 2,
                }
            }
            1 => {
                invalid.events[3] = H3CapturedEvent::Stream {
                    stream_id: 10,
                    stream_type: 0,
                }
            }
            2 => {
                invalid.encoder_instructions[0] =
                    ObservedEncoderInstruction::Capacity { capacity: 0 }
            }
            3 => {
                invalid.encoder_instructions[1] = ObservedEncoderInstruction::Duplicate { index: 0 }
            }
            _ => {
                invalid.encoder_instructions =
                    vec![ObservedEncoderInstruction::Capacity { capacity: 4096 }].into()
            }
        }
        assert!(
            !h3_startup::supports(Some(&invalid), Some(&bootstrap)),
            "case {case}"
        );
    }
    let conflict = Extensions::new();
    conflict.insert(EncoderPreferences {
        target_capacity: Some(1024),
        ..EncoderPreferences::default()
    });
    assert_eq!(
        lowered(&conflict, &sequence, Some(&bootstrap), false),
        [LoweredProfileItem::CallerQpackEncoding]
    );
}

#[test]
fn empty_instruction_startup_uses_observed_types_without_initial_bindings() {
    for (order, streams) in [
        (Order::EncoderFirst, vec![(6, 2), (10, 3)]),
        (Order::DecoderFirst, vec![(6, 3), (10, 2)]),
    ] {
        let mut sequence = priority_prefix(0, 4);
        let mut events = sequence.events.into_vec();
        events.extend(streams.into_iter().map(|(stream_id, stream_type)| {
            H3CapturedEvent::Stream {
                stream_id,
                stream_type,
            }
        }));
        sequence.events = events.into();
        let extensions = Extensions::new();
        assert!(h3_startup::supports(Some(&sequence), None));
        h3_startup::prepare(
            &extensions,
            Some(&sequence),
            None,
            false,
            &mut ProfilePreservationReport::default(),
        )
        .unwrap()
        .unwrap()
        .apply(&extensions);
        assert_eq!(
            extensions.get_ref::<Preferences>(),
            Some(&Preferences {
                order,
                encoder: Startup::Immediate,
                decoder: Startup::Immediate,
                ordered_startup: true
            })
        );
        assert!(
            extensions
                .get_ref::<EncoderPreferences>()
                .unwrap()
                .defer_dynamic_first_section
                .unwrap()
        );
        let mut invalid = sequence.clone();
        invalid.events.swap(3, 4);
        assert_eq!(
            lowered(&Extensions::new(), &invalid, None, false),
            [LoweredProfileItem::Http3StartupOrder],
            "descending static prefix order cannot be silently rearranged"
        );
    }
    let extensions = Extensions::new();
    let control_only = priority_prefix(0, 4);
    h3_startup::prepare(
        &extensions,
        Some(&control_only),
        None,
        false,
        &mut ProfilePreservationReport::default(),
    )
    .unwrap()
    .unwrap()
    .apply(&extensions);
    assert_eq!(
        extensions.get_ref::<Preferences>(),
        Some(&Preferences {
            encoder: Startup::OnDemand,
            decoder: Startup::OnDemand,
            ordered_startup: true,
            ..Preferences::default()
        })
    );
    assert!(
        h3_startup::prepare(
            &Extensions::new(),
            None,
            None,
            false,
            &mut ProfilePreservationReport::default()
        )
        .unwrap()
        .is_none(),
        "absence never invents a capture"
    );
}
