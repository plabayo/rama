use super::*;
use crate::profile::{
    CanonicalValue, CapturedSlot, ConnectionContext, DrawKey, H2CapturedFrame, H2CapturedSetting,
    PreparedConnectionProfile, ProfileCaptureCompleteness, ProfileObservationScope, ValueId,
};
use rama_http::proto::h2::frame::EarlyFrame;

fn order_slot(kind: CapturedSlotKind, namespace: OrderNamespace, id: u64) -> CapturedSlot {
    let value = match namespace {
        OrderNamespace::Http3Setting => 0u64.to_be_bytes().to_vec(),
        OrderNamespace::QuicParameter | OrderNamespace::QuicVersion => Vec::new(),
    };
    let value = OrderedProtocolCapture::capture(
        ProfileCaptureCompleteness::Complete,
        namespace,
        [(id, value)],
        OrderCaptureLimits::default(),
    )
    .unwrap()
    .canonical(OrderCaptureLimits::default())
    .unwrap();
    CapturedSlot { kind, value }
}

fn selection(capture: CanonicalValue) -> ConnectionSelection {
    let joint = JointCapture::from_canonical(&capture, JointCaptureLimits::default()).unwrap();
    let h3_settings_evidence = joint
        .slots
        .iter()
        .find(|slot| slot.kind == CapturedSlotKind::Http3Settings)
        .map(|slot| settings_evidence(&vec![slot.value.clone(); 64], &slot.value));
    ConnectionSelection {
        profile: ValueId([1; 32]),
        variant: capture.id,
        draw: DrawKey([2; 32]),
        analysis_revision: 2,
        effective: PreparedConnectionProfile {
            h3_settings_evidence,
            scope: ValueId([3; 32]),
            capture,
            context: ProfileObservationScope {
                authorized: false,
                profile: ValueId([1; 32]),
                flow: None,
                connection: ConnectionContext::default(),
                structure: ValueId([4; 32]),
            },
        },
    }
}

#[test]
fn tcp_connection_components_decode_h2_frames() {
    let h2 = H2Capture {
        completeness: ProfileCaptureCompleteness::Complete,
        frames: vec![H2CapturedFrame::Settings {
            ack: false,
            entries: vec![H2CapturedSetting { id: 1, value: 4096 }].into(),
        }]
        .into(),
    }
    .canonical(H2CaptureLimits::default())
    .unwrap();
    let capture = JointCapture {
        completeness: ProfileCaptureCompleteness::Complete,
        level: CaptureLevel::Connection,
        slots: vec![CapturedSlot {
            kind: CapturedSlotKind::Http2EarlyFrames,
            value: h2,
        }]
        .into(),
    }
    .canonical(JointCaptureLimits::default())
    .unwrap();

    let prepared = selection(capture).prepare_components().unwrap();
    let replay = prepared.h2_early_frames.unwrap();
    let EarlyFrame::Settings(settings) = &replay[0] else {
        panic!("initial replay frame must be SETTINGS");
    };
    assert_eq!(settings.config.header_table_size, Some(4_096));
}

#[test]
fn h2_settings_ack_is_regenerated_during_component_preparation() {
    let h2 = H2Capture {
        completeness: ProfileCaptureCompleteness::Complete,
        frames: vec![
            H2CapturedFrame::Settings {
                ack: false,
                entries: Box::default(),
            },
            H2CapturedFrame::Settings {
                ack: true,
                entries: Box::default(),
            },
        ]
        .into(),
    }
    .canonical(H2CaptureLimits::default())
    .unwrap();
    let capture = JointCapture {
        completeness: ProfileCaptureCompleteness::Complete,
        level: CaptureLevel::Connection,
        slots: vec![CapturedSlot {
            kind: CapturedSlotKind::Http2EarlyFrames,
            value: h2,
        }]
        .into(),
    }
    .canonical(JointCaptureLimits::default())
    .unwrap();

    let prepared = selection(capture).prepare_components().unwrap();
    assert_eq!(prepared.h2_early_frames.unwrap().len(), 1);
    assert!(prepared.preservation_report.is_exact());
}

#[test]
fn quic_connection_components_keep_each_order_namespace_separate() {
    let capture = JointCapture {
        completeness: ProfileCaptureCompleteness::Complete,
        level: CaptureLevel::Connection,
        slots: vec![
            order_slot(
                CapturedSlotKind::QuicParameters,
                OrderNamespace::QuicParameter,
                0x04,
            ),
            order_slot(
                CapturedSlotKind::Http3Settings,
                OrderNamespace::Http3Setting,
                0x06,
            ),
            order_slot(
                CapturedSlotKind::QuicVersions,
                OrderNamespace::QuicVersion,
                1,
            ),
        ]
        .into(),
    }
    .canonical(JointCaptureLimits::default())
    .unwrap();

    let prepared = selection(capture).prepare_components().unwrap();
    assert_eq!(prepared.quic_parameters.unwrap().fields[0].id, 0x04);
    assert_eq!(prepared.h3_peer_settings.unwrap().fields[0].id, 0x06);
    assert_eq!(prepared.quic_versions.unwrap().fields[0].id, 1);
    assert!(prepared.h2_early_frames.is_none());
}

#[test]
fn request_capture_cannot_be_prepared_as_connection_components() {
    let capture = JointCapture {
        completeness: ProfileCaptureCompleteness::Complete,
        level: CaptureLevel::Request,
        slots: Box::default(),
    }
    .canonical(JointCaptureLimits::default())
    .unwrap();

    assert!(matches!(
        selection(capture).prepare_components(),
        Err(ProfileDataError::Invalid(
            "connection profile capture level"
        ))
    ));
}

#[test]
fn selected_h3_settings_keep_reserved_literals_and_order() {
    let fields = [
        (SettingId::FIRST_RESERVED.value(), 17u64),
        (SettingId::QPACK_BLOCKED_STREAMS.value(), 0),
        (0xface, 29),
    ];
    let capture = OrderedProtocolCapture::capture(
        ProfileCaptureCompleteness::Complete,
        OrderNamespace::Http3Setting,
        fields.map(|(id, value)| (id, value.to_be_bytes())),
        OrderCaptureLimits::default(),
    )
    .unwrap()
    .canonical(OrderCaptureLimits::default())
    .unwrap();
    let joint = JointCapture {
        completeness: ProfileCaptureCompleteness::Complete,
        level: CaptureLevel::Connection,
        slots: vec![CapturedSlot {
            kind: CapturedSlotKind::Http3Settings,
            value: capture,
        }]
        .into(),
    }
    .canonical(JointCaptureLimits::default())
    .unwrap();
    let mut selection = selection(joint);
    let prepared = selection.prepare_components().unwrap();
    let source = prepared
        .h3_peer_settings
        .as_ref()
        .unwrap()
        .canonical(OrderCaptureLimits::default())
        .unwrap();
    let settings = prepared
        .h3_client_settings(&mut test_draw())
        .unwrap()
        .unwrap();
    assert_eq!(
        settings,
        prepared
            .h3_client_settings(&mut test_draw())
            .unwrap()
            .unwrap()
    );
    selection.draw = DrawKey([9; 32]);
    let second = selection
        .prepare_components()
        .unwrap()
        .h3_client_settings(&mut test_draw())
        .unwrap()
        .unwrap();
    assert_eq!(settings.0.entries()[0].id, second.0.entries()[0].id);
    assert_eq!(settings.0.entries()[0].value, second.0.entries()[0].value);
    assert_eq!(settings.0.entries()[1..], second.0.entries()[1..]);
    let unchanged = prepared
        .h3_peer_settings
        .as_ref()
        .unwrap()
        .canonical(OrderCaptureLimits::default())
        .unwrap();
    assert_eq!(source.id, unchanged.id);
    assert_eq!(source.bytes, unchanged.bytes);
    let actual: Vec<_> = settings
        .0
        .entries()
        .iter()
        .map(|s| (s.id.value(), s.value))
        .collect();
    assert!(SettingId::new(actual[0].0).is_reserved());
    assert_eq!(actual[0], fields[0]);
    assert_eq!(&actual[1..], &fields[1..]);
    assert_eq!(settings.0.qpack_max_table_capacity(), 0);
}

#[test]
fn unsupported_connection_components_never_certify_exact_replay() {
    for component in [
        CapturedSlotKind::TcpTls,
        CapturedSlotKind::QuicTls,
        CapturedSlotKind::QuicParameters,
        CapturedSlotKind::QuicVersions,
        CapturedSlotKind::QuicFirstFlight,
        CapturedSlotKind::Http3Sequence,
    ] {
        let mut strict = ProfilePreservationReport::default();
        assert!(matches!(
            check_connection_component(component, ProfilePreservationMode::Strict, &mut strict),
            Err(ProfileReplayError::UnsupportedConnectionComponent(actual)) if actual == component
        ));
        let mut best_effort = ProfilePreservationReport::default();
        check_connection_component(
            component,
            ProfilePreservationMode::BestEffort,
            &mut best_effort,
        )
        .unwrap();
        assert_eq!(
            best_effort.differences.as_ref(),
            &[ProfilePreservationDifference::UnsupportedConnectionComponent { component }]
        );
        assert!(!best_effort.is_exact());
    }
}

#[test]
fn replay_preparation_reports_every_unconsumed_selected_component() {
    let capture = JointCapture {
        completeness: ProfileCaptureCompleteness::Complete,
        level: CaptureLevel::Connection,
        slots: vec![
            order_slot(
                CapturedSlotKind::QuicParameters,
                OrderNamespace::QuicParameter,
                4,
            ),
            order_slot(
                CapturedSlotKind::QuicVersions,
                OrderNamespace::QuicVersion,
                1,
            ),
        ]
        .into(),
    }
    .canonical(JointCaptureLimits::default())
    .unwrap();
    let selected = selection(capture);
    // Inspection remains available without making a runtime replay claim.
    assert!(
        selected
            .prepare_components()
            .unwrap()
            .quic_parameters
            .is_some()
    );
    assert!(matches!(
        selected.prepare_for_replay(ProfilePreservationMode::Strict),
        Err(ProfileReplayError::UnsupportedConnectionComponent(
            CapturedSlotKind::QuicParameters
        ))
    ));
    let prepared = selected
        .prepare_for_replay(ProfilePreservationMode::BestEffort)
        .unwrap();
    assert!(prepared.quic_parameters.is_some());
    assert!(prepared.quic_versions.is_some());
    assert_eq!(
        prepared.preservation_report.differences.as_ref(),
        &[
            ProfilePreservationDifference::UnsupportedConnectionComponent {
                component: CapturedSlotKind::QuicParameters
            },
            ProfilePreservationDifference::UnsupportedConnectionComponent {
                component: CapturedSlotKind::QuicVersions
            },
        ]
    );
}

#[test]
fn literal_h3_reserved_settings_keep_full_varint_ids_and_values() {
    let maximum = (1_u64 << 62) - 1;
    let highest_reserved = 33 + 31 * ((maximum - 33) / 31);
    for (id, value) in [(33, 17), (64, 29), (highest_reserved, maximum)] {
        assert!(SettingId::new(id).is_reserved());
        let capture = OrderedProtocolCapture::capture(
            ProfileCaptureCompleteness::Complete,
            OrderNamespace::Http3Setting,
            [(id, value.to_be_bytes())],
            OrderCaptureLimits::default(),
        )
        .unwrap()
        .canonical(OrderCaptureLimits::default())
        .unwrap();
        let selected = selection(
            JointCapture {
                completeness: ProfileCaptureCompleteness::Complete,
                level: CaptureLevel::Connection,
                slots: vec![CapturedSlot {
                    kind: CapturedSlotKind::Http3Settings,
                    value: capture,
                }]
                .into(),
            }
            .canonical(JointCaptureLimits::default())
            .unwrap(),
        );
        for mode in [
            ProfilePreservationMode::Strict,
            ProfilePreservationMode::BestEffort,
        ] {
            let prepared = selected.prepare_for_replay(mode).unwrap();
            let compiled = prepared
                .h3_client_settings(&mut test_draw())
                .unwrap()
                .unwrap();
            assert_eq!(compiled.0.entries().len(), 1);
            assert_eq!(compiled.0.entries()[0].id.value(), id);
            assert_eq!(compiled.0.entries()[0].value, value);
            assert!(prepared.preservation_report.is_exact());
        }
    }
}

fn test_draw() -> ProfileDraw {
    ProfileDraw::new(
        ProfileSeed([7; 32]),
        ProfileDrawContext {
            profile: ValueId([1; 32]),
            analysis_revision: 2,
            scope: ValueId([3; 32]),
            key: DrawKey([2; 32]),
            domain: DrawDomain::Http3Settings,
            slot: 0,
        },
    )
}
fn settings_evidence(
    values: &[CanonicalValue],
    selected: &CanonicalValue,
) -> H3SettingsReplayEvidence {
    use crate::profile::{
        CanonicalDomain, CountedObservationBucket, ObservationId, OrderAnalysisConfig,
        ProfileBucketLimits, analyze_capture_bucket,
    };
    let mut bucket = CountedObservationBucket::new(
        CanonicalDomain::Order,
        ValueId([4; 32]),
        [3; 32],
        ProfileBucketLimits::default(),
    )
    .unwrap();
    for (index, value) in values.iter().enumerate() {
        bucket
            .observe(
                ObservationId {
                    run: [1; 16],
                    sequence: index as u64 + 1,
                },
                value,
            )
            .unwrap();
    }
    H3SettingsReplayEvidence::from_analysis(
        &analyze_capture_bucket(&bucket, OrderAnalysisConfig::default()).unwrap(),
        selected,
    )
    .unwrap()
    .unwrap()
}

#[test]
fn varying_h3_settings_generate_only_evidenced_slots_and_values() {
    for value_mode in [0, 1, 2] {
        let values: Vec<_> = (0..64_u64)
            .map(|index| {
                let mut fields = vec![
                    (7, 0_u64),
                    (90, 29),
                    (33, 23),
                    (
                        64 + 31 * (u64::from(u32::MAX) / 64 * index),
                        if value_mode == 1 && index > 0 {
                            u64::from(u32::MAX) / 64 * index
                        } else if value_mode == 2 {
                            17 + index % 2
                        } else {
                            17
                        },
                    ),
                ];
                fields.sort_unstable_by_key(|(id, _)| *id);
                OrderedProtocolCapture::capture(
                    ProfileCaptureCompleteness::Complete,
                    OrderNamespace::Http3Setting,
                    fields
                        .into_iter()
                        .map(|(id, value)| (id, value.to_be_bytes())),
                    OrderCaptureLimits::default(),
                )
                .unwrap()
                .canonical(OrderCaptureLimits::default())
                .unwrap()
            })
            .collect();
        let evidence = settings_evidence(&values, &values[0]);
        let mut selected = selection(
            JointCapture {
                completeness: ProfileCaptureCompleteness::Complete,
                level: CaptureLevel::Connection,
                slots: vec![CapturedSlot {
                    kind: CapturedSlotKind::Http3Settings,
                    value: values[0].clone(),
                }]
                .into(),
            }
            .canonical(JointCaptureLimits::default())
            .unwrap(),
        );
        selected.effective.h3_settings_evidence = Some(evidence);
        let prepared = selected
            .prepare_for_replay(ProfilePreservationMode::Strict)
            .unwrap();
        let first = prepared
            .h3_client_settings(&mut selected.h3_settings_draw(ProfileSeed([7; 32])))
            .unwrap()
            .unwrap();
        selected.draw = DrawKey([9; 32]);
        let second = prepared
            .h3_client_settings(&mut selected.h3_settings_draw(ProfileSeed([7; 32])))
            .unwrap()
            .unwrap();
        let reserved = |settings: &ClientSettingsProfile| {
            *settings
                .0
                .entries()
                .iter()
                .find(|entry| entry.id.is_reserved() && entry.id != SettingId::FIRST_RESERVED)
                .unwrap()
        };
        assert_ne!(reserved(&first).id, reserved(&second).id);
        if value_mode == 1 {
            assert_ne!(reserved(&first).value, reserved(&second).value);
        } else {
            assert_eq!(reserved(&first).value, 17);
            assert_eq!(reserved(&second).value, 17);
        }
        for settings in [&first, &second] {
            assert_eq!(settings.0.get(SettingId::FIRST_RESERVED), Some(23));
            assert!(
                settings
                    .0
                    .entries()
                    .windows(2)
                    .all(|pair| pair[0].id.value() < pair[1].id.value())
            );
            let literal: Vec<_> = settings
                .0
                .entries()
                .iter()
                .filter(|entry| !entry.id.is_reserved())
                .map(|entry| (entry.id.value(), entry.value))
                .collect();
            assert_eq!(literal, [(7, 0), (90, 29)]);
        }
    }
}

#[test]
fn missing_h3_settings_evidence_is_strictly_rejected_or_reported() {
    let mut selected = selection(
        JointCapture {
            completeness: ProfileCaptureCompleteness::Complete,
            level: CaptureLevel::Connection,
            slots: vec![order_slot(
                CapturedSlotKind::Http3Settings,
                OrderNamespace::Http3Setting,
                33,
            )]
            .into(),
        }
        .canonical(JointCaptureLimits::default())
        .unwrap(),
    );
    selected.effective.h3_settings_evidence = None;
    selected
        .prepare_for_replay(ProfilePreservationMode::Strict)
        .unwrap_err();
    selected
        .prepare_components()
        .unwrap()
        .h3_client_settings(&mut test_draw())
        .unwrap_err();
    let prepared = selected
        .prepare_for_replay(ProfilePreservationMode::BestEffort)
        .unwrap();
    assert_eq!(
        prepared.preservation_report.differences.as_ref(),
        [ProfilePreservationDifference::UnanalyzedHttp3ReservedSettings]
    );
    assert_eq!(
        prepared
            .h3_client_settings(&mut test_draw())
            .unwrap()
            .unwrap()
            .0
            .entries()[0]
            .id
            .value(),
        33
    );
}

#[test]
fn h3_settings_generation_requires_enough_samples_and_exact_binding() {
    let values: Vec<_> = [(33, 17_u64), (64, 29)]
        .into_iter()
        .map(|(id, value)| {
            OrderedProtocolCapture::capture(
                ProfileCaptureCompleteness::Complete,
                OrderNamespace::Http3Setting,
                [(id, value.to_be_bytes())],
                OrderCaptureLimits::default(),
            )
            .unwrap()
            .canonical(OrderCaptureLimits::default())
            .unwrap()
        })
        .collect();
    let evidence = settings_evidence(&values, &values[0]);
    let first =
        OrderedProtocolCapture::from_canonical(&values[0], OrderCaptureLimits::default()).unwrap();
    assert_eq!(
        evidence.compile(&first, &mut test_draw()).unwrap(),
        [(33, 17)]
    );
    let second =
        OrderedProtocolCapture::from_canonical(&values[1], OrderCaptureLimits::default()).unwrap();
    evidence.compile(&second, &mut test_draw()).unwrap_err();
}
