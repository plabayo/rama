//! Initial recipes bind native insertion preferences to current request fields.

use super::*;
use crate::profile::capture::{
    headers::header_request_binding,
    http3::H3CapturedEvent,
    joint::CapturedSlot,
    order::{OrderNamespace, OrderedProtocolCapture},
    pseudo_headers::PseudoHeaderOccurrence,
};
use rama_http::proto::{
    h2::PseudoHeader,
    h3::{
        observation::{
            FieldRepresentation, InsertionFieldMatch, ObservedEncoderBindings,
            ObservedEncoderInstruction, ObservedInsertionBinding,
        },
        qpack::encoding::{InsertionNameEncoding, InsertionScope, Representation},
    },
};

fn initial_recipe() -> (
    RequestSelection,
    H3BootstrapCapture,
    H3ClientSequenceCapture,
) {
    let literal = ObservedFieldRepresentation::from(&FieldLine::LiteralWithLiteralName {
        name: Bytes::from_static(b"x-live"),
        value: Bytes::from_static(b"discarded"),
        name_huffman: false,
        value_huffman: false,
        never_index: false,
    });
    let mut fields = vec![
        field(
            "x-live",
            0,
            HeaderValueSource::Request(RequestBinding::Custom),
        ),
        field(
            "x-live",
            1,
            HeaderValueSource::Request(RequestBinding::Custom),
        ),
    ];
    for field in &mut fields {
        field.representation = Some(literal);
    }
    let mut selection = selection_for_version(fields, Version::HTTP_3);
    let mut joint =
        JointCapture::from_canonical(&selection.effective.capture, JointCaptureLimits::default())
            .unwrap();
    let pseudo = PseudoHeaderCapture {
        completeness: ProfileCaptureCompleteness::Complete,
        version: Version::HTTP_3,
        fields: [
            PseudoHeader::Method,
            PseudoHeader::Scheme,
            PseudoHeader::Authority,
            PseudoHeader::Path,
        ]
        .into_iter()
        .map(|name| PseudoHeaderOccurrence {
            name,
            representation: Some(literal),
        })
        .collect(),
    }
    .canonical(4096)
    .unwrap();
    let mut slots = joint.slots.into_vec();
    slots.push(CapturedSlot {
        kind: CapturedSlotKind::PseudoHeaders,
        value: pseudo,
    });
    joint.slots = slots.into();
    selection
        .effective
        .set_capture(joint.canonical(JointCaptureLimits::default()).unwrap());
    selection.variant = selection.effective.capture.id;
    let bootstrap = H3BootstrapCapture {
        request: selection.variant,
        method: Method::GET,
        fields: 6,
        bindings: ObservedEncoderBindings {
            stream_id: 0,
            complete: true,
            insertions: (3..6)
                .enumerate()
                .map(|(index, field_index)| ObservedInsertionBinding {
                    instruction_index: index + 1,
                    insertion_index: index as u64,
                    field: InsertionFieldMatch::Unique { field_index },
                })
                .collect(),
        },
    };
    let sequence =
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
                H3CapturedEvent::Stream {
                    stream_id: 10,
                    stream_type: 2,
                },
            ]
            .into(),
            encoder_instructions: std::iter::once(ObservedEncoderInstruction::Capacity {
                capacity: 4096,
            })
            .chain([5, 6, 6].into_iter().map(|name_bytes| {
                ObservedEncoderInstruction::InsertLiteral {
                    name_bytes,
                    value_bytes: 9,
                    name_huffman: true,
                    value_huffman: false,
                }
            }))
            .collect(),
        };
    (selection, bootstrap, sequence)
}

#[test]
fn initial_mapping_keeps_duplicate_current_values_and_exact_field_associations() {
    let (selection, bootstrap, sequence) = initial_recipe();
    let mut original = HeaderMap::new();
    original.append("x-live", HeaderValue::from_static("current-first"));
    original.append("x-live", HeaderValue::from_static("current-second"));
    let replayed = selection
        .replay_initial_request(&original, &bootstrap, &sequence)
        .unwrap();
    let headers = replayed.headers.unwrap();
    assert_eq!(
        headers
            .get_all("x-live")
            .iter()
            .map(|value| value.to_str().unwrap())
            .collect::<Vec<_>>(),
        ["current-first", "current-second"]
    );
    let choices = replayed.qpack_headers.unwrap();
    for preference in choices
        .headers
        .get_all("x-live")
        .iter()
        .chain(std::iter::once(
            &choices.pseudo_headers[&PseudoHeader::Path],
        ))
    {
        let insertion = preference.insertion.unwrap();
        assert_eq!(insertion.scope, InsertionScope::InitialSection);
        assert_eq!(insertion.name_encoding, InsertionNameEncoding::Literal);
        assert_eq!(insertion.name_huffman, Some(true));
        assert_eq!(insertion.value_huffman, Some(false));
    }
    assert!(
        choices.pseudo_headers[&PseudoHeader::Method]
            .insertion
            .is_none()
    );
    let ordinary = selection.replay_request(&original).unwrap();
    assert!(
        ordinary
            .qpack_headers
            .unwrap()
            .headers
            .get_all("x-live")
            .iter()
            .all(|field| field.insertion.is_none())
    );
}

#[test]
fn initial_mapping_rejects_malformed_and_lowers_unusable_associations() {
    let (selection, bootstrap, sequence) = initial_recipe();
    let mut original = HeaderMap::new();
    original.append("x-live", HeaderValue::from_static("first"));
    original.append("x-live", HeaderValue::from_static("second"));
    for case in 0..7 {
        let mut bootstrap = bootstrap.clone();
        let mut sequence = sequence.clone();
        match case {
            0 => bootstrap.request = ValueId([9; 32]),
            1 => bootstrap.method = Method::POST,
            2 => bootstrap.fields += 1,
            3 => bootstrap.bindings.insertions[0].field = InsertionFieldMatch::Absent,
            4 => {
                bootstrap.bindings.insertions[0].field =
                    InsertionFieldMatch::Unique { field_index: 4 }
            }
            5 => {
                sequence.encoder_instructions[1] =
                    ObservedEncoderInstruction::Duplicate { index: 0 }
            }
            _ => bootstrap.bindings.complete = false,
        }
        let result = selection.replay_initial_request(&original, &bootstrap, &sequence);
        if case < 3 {
            // Malformed identity or shape: the capture itself is invalid.
            assert!(
                matches!(
                    result,
                    Err(ProfileReplayError::Data(ProfileDataError::Invalid(_)))
                ),
                "case {case}: {result:?}"
            );
            continue;
        }
        // An association native replay cannot reproduce drops the insertions.
        let replayed = result.unwrap();
        assert!(
            replayed.report.differences.contains(
                &ProfilePreservationDifference::LoweredProfileItem {
                    item: LoweredProfileItem::Http3InitialInsertions
                }
            ),
            "case {case}"
        );
        let choices = replayed.qpack_headers.unwrap();
        assert!(
            choices
                .headers
                .iter()
                .map(|(_, field)| field)
                .chain(choices.pseudo_headers.values())
                .all(|field| field.insertion.is_none()),
            "case {case}"
        );
    }
}

#[test]
fn initial_mapping_resolves_static_names_against_the_actual_field() {
    let (selection, bootstrap, mut sequence) = initial_recipe();
    let mut original = HeaderMap::new();
    original.append("x-live", HeaderValue::from_static("current-first"));
    original.append("x-live", HeaderValue::from_static("current-second"));
    sequence.encoder_instructions[1] = ObservedEncoderInstruction::InsertNameReference {
        is_static: true,
        index: 1,
        value_bytes: 1,
        value_huffman: true,
    };
    let replayed = selection
        .replay_initial_request(&original, &bootstrap, &sequence)
        .unwrap();
    let choices = replayed.qpack_headers.unwrap();
    let insertion = choices.pseudo_headers[&PseudoHeader::Path]
        .insertion
        .unwrap();
    assert_eq!(
        insertion.name_encoding,
        InsertionNameEncoding::StaticName(1)
    );
    assert_eq!(insertion.value_huffman, Some(true));

    // RFC9204 static entry zero is :authority, which cannot insert :path.
    sequence.encoder_instructions[1] = ObservedEncoderInstruction::InsertNameReference {
        is_static: true,
        index: 0,
        value_bytes: 1,
        value_huffman: true,
    };
    selection
        .replay_initial_request(&original, &bootstrap, &sequence)
        .unwrap_err();
}

fn dynamic_initial_recipe() -> (
    RequestSelection,
    H3BootstrapCapture,
    H3ClientSequenceCapture,
) {
    let (mut selection, mut bootstrap, sequence) = initial_recipe();
    let limits = JointCaptureLimits::default();
    let mut joint = JointCapture::from_canonical(&selection.effective.capture, limits).unwrap();
    for slot in &mut joint.slots {
        match slot.kind {
            CapturedSlotKind::Headers => {
                let policy = HeaderCapturePolicy::default();
                let mut capture = HeaderCapture::from_canonical(&slot.value, &policy).unwrap();
                for (index, field) in capture.fields.iter_mut().enumerate() {
                    field.representation =
                        Some(ObservedFieldRepresentation::from(&FieldLine::Indexed {
                            is_static: false,
                            index: 1 - index as u64,
                        }));
                }
                slot.value = capture.canonical(&policy).unwrap();
            }
            CapturedSlotKind::PseudoHeaders => {
                let mut capture =
                    PseudoHeaderCapture::from_canonical(&slot.value, limits.value_bytes).unwrap();
                capture.fields[3].representation =
                    Some(ObservedFieldRepresentation::from(&FieldLine::Indexed {
                        is_static: false,
                        index: 2,
                    }));
                slot.value = capture.canonical(limits.value_bytes).unwrap();
            }
            _ => (),
        }
    }
    selection
        .effective
        .set_capture(joint.canonical(limits).unwrap());
    selection.variant = selection.effective.capture.id;
    bootstrap.request = selection.variant;
    (selection, bootstrap, sequence)
}

#[test]
fn initial_dynamic_references_bind_only_to_their_own_fresh_insertions() {
    let (selection, bootstrap, sequence) = dynamic_initial_recipe();
    let mut original = HeaderMap::new();
    original.append("x-live", HeaderValue::from_static("new-first"));
    original.append("x-live", HeaderValue::from_static("new-second"));
    let replayed = selection
        .replay_initial_request(&original, &bootstrap, &sequence)
        .unwrap();
    let choices = replayed.qpack_headers.unwrap();
    for preference in choices
        .headers
        .get_all("x-live")
        .iter()
        .chain(std::iter::once(
            &choices.pseudo_headers[&PseudoHeader::Path],
        ))
    {
        assert_eq!(
            preference.representation,
            Representation::DynamicIndexBeforeBase
        );
        assert_eq!(
            preference.insertion.unwrap().scope,
            InsertionScope::InitialSection
        );
    }
    assert_eq!(
        replayed.qpack_base,
        Some(FieldSectionBase::FromFieldPreferences)
    );
}

#[test]
fn initial_dynamic_references_reject_foreign_relative_indexes_and_unproved_bases() {
    let (selection, bootstrap, sequence) = dynamic_initial_recipe();
    let limits = JointCaptureLimits::default();

    #[derive(Debug, Clone, Copy)]
    enum InvalidReference {
        ForeignRelativeIndex,
        ConflictingPostBase,
        DynamicName,
        PostBaseName,
        UnprovedBase,
        UnboundField,
    }

    for case in [
        InvalidReference::ForeignRelativeIndex,
        InvalidReference::ConflictingPostBase,
        InvalidReference::DynamicName,
        InvalidReference::PostBaseName,
        InvalidReference::UnprovedBase,
        InvalidReference::UnboundField,
    ] {
        let mut selection = selection.clone();
        let mut bootstrap = bootstrap.clone();
        let mut joint = JointCapture::from_canonical(&selection.effective.capture, limits).unwrap();
        let slot = joint
            .slots
            .iter_mut()
            .find(|slot| slot.kind == CapturedSlotKind::Headers)
            .unwrap();
        let policy = HeaderCapturePolicy::default();
        let mut captured = HeaderCapture::from_canonical(&slot.value, &policy).unwrap();
        // Keep the final reference valid when isolating the relative-index check.
        let field_index = match case {
            InvalidReference::ForeignRelativeIndex => 0,
            _ => 1,
        };
        let metadata = captured.fields[field_index]
            .representation
            .as_mut()
            .unwrap();
        match case {
            InvalidReference::ForeignRelativeIndex => metadata.index = Some(0),
            InvalidReference::ConflictingPostBase => {
                metadata.representation = FieldRepresentation::DynamicPostBaseIndex
            }
            InvalidReference::DynamicName => {
                metadata.representation = FieldRepresentation::LiteralDynamicName
            }
            InvalidReference::PostBaseName => {
                metadata.representation = FieldRepresentation::LiteralPostBaseName
            }
            InvalidReference::UnprovedBase => {
                metadata.representation = FieldRepresentation::LiteralName;
                metadata.index = None;
            }
            InvalidReference::UnboundField => (),
        }
        slot.value = captured.canonical(&policy).unwrap();
        if matches!(case, InvalidReference::UnboundField) {
            let slot = joint
                .slots
                .iter_mut()
                .find(|slot| slot.kind == CapturedSlotKind::PseudoHeaders)
                .unwrap();
            let mut captured =
                PseudoHeaderCapture::from_canonical(&slot.value, limits.value_bytes).unwrap();
            captured.fields[0].representation =
                Some(ObservedFieldRepresentation::from(&FieldLine::Indexed {
                    is_static: false,
                    index: 0,
                }));
            slot.value = captured.canonical(limits.value_bytes).unwrap();
        }
        selection
            .effective
            .set_capture(joint.canonical(limits).unwrap());
        selection.variant = selection.effective.capture.id;
        bootstrap.request = selection.variant;
        let insertions =
            Insertions::new(&bootstrap, &sequence, selection.variant, &Method::GET).unwrap();
        assert!(
            insertions
                .validate_request(&selection.effective.capture)
                .is_err(),
            "case {case:?}"
        );
    }
}

/// Reconstruct the observed Firefox first-head coordinates with synthetic values.
fn post_base_initial_recipe() -> (
    RequestSelection,
    H3BootstrapCapture,
    H3ClientSequenceCapture,
) {
    let (mut selection, mut bootstrap, mut sequence) = initial_recipe();
    let limits = JointCaptureLimits::default();
    let mut joint = JointCapture::from_canonical(&selection.effective.capture, limits).unwrap();
    let policy = HeaderCapturePolicy::default();
    let names = [
        "user-agent",
        "accept",
        "accept-language",
        "accept-encoding",
        "alt-used",
        "upgrade-insecure-requests",
        "sec-fetch-dest",
        "sec-fetch-mode",
        "sec-fetch-site",
        "sec-fetch-user",
        "priority",
    ];
    let dynamic = [4usize, 6, 7, 8, 9, 10];
    for slot in &mut joint.slots {
        match slot.kind {
            CapturedSlotKind::Headers => {
                let mut capture = HeaderCapture::from_canonical(&slot.value, &policy).unwrap();
                capture.fields = names
                    .into_iter()
                    .enumerate()
                    .map(|(ordinal, name)| {
                        let mut field = field(
                            name,
                            0,
                            HeaderValueSource::Request(
                                header_request_binding(&HeaderName::from_static(name))
                                    .unwrap_or(RequestBinding::Custom),
                            ),
                        );
                        let line = if let Some(index) = dynamic.iter().position(|i| *i == ordinal) {
                            FieldLine::IndexedPostBase {
                                index: index as u64,
                            }
                        } else if ordinal == 5 {
                            FieldLine::Indexed {
                                is_static: true,
                                index: 94,
                            }
                        } else {
                            FieldLine::LiteralWithNameRef {
                                is_static: true,
                                name_index: [95, 29, 72, 31][ordinal],
                                value: Bytes::new(),
                                value_huffman: true,
                                never_index: false,
                            }
                        };
                        field.representation = Some(ObservedFieldRepresentation::from(&line));
                        field
                    })
                    .collect();
                slot.value = capture.canonical(&policy).unwrap();
            }
            CapturedSlotKind::PseudoHeaders => {
                let mut capture =
                    PseudoHeaderCapture::from_canonical(&slot.value, limits.value_bytes).unwrap();
                for (ordinal, field) in capture.fields.iter_mut().enumerate() {
                    let line = if ordinal < 2 {
                        FieldLine::Indexed {
                            is_static: true,
                            index: [17, 23][ordinal],
                        }
                    } else {
                        FieldLine::LiteralWithNameRef {
                            is_static: true,
                            name_index: (ordinal - 2) as u64,
                            value: Bytes::new(),
                            value_huffman: true,
                            never_index: false,
                        }
                    };
                    field.representation = Some(ObservedFieldRepresentation::from(&line));
                }
                slot.value = capture.canonical(limits.value_bytes).unwrap();
            }
            _ => (),
        }
    }
    selection
        .effective
        .set_capture(joint.canonical(limits).unwrap());
    selection.variant = selection.effective.capture.id;
    bootstrap.request = selection.variant;
    bootstrap.fields = 15;
    bootstrap.bindings.insertions = dynamic
        .iter()
        .enumerate()
        .map(|(index, ordinal)| ObservedInsertionBinding {
            instruction_index: index + 1,
            insertion_index: index as u64,
            field: InsertionFieldMatch::Unique {
                field_index: ordinal + 4,
            },
        })
        .collect();
    sequence.encoder_instructions =
        std::iter::once(ObservedEncoderInstruction::Capacity { capacity: 4096 })
            .chain(
                dynamic
                    .into_iter()
                    .map(|ordinal| ObservedEncoderInstruction::InsertLiteral {
                        name_bytes: names[ordinal].len(),
                        value_bytes: 0,
                        name_huffman: true,
                        value_huffman: true,
                    }),
            )
            .collect();
    (selection, bootstrap, sequence)
}

#[test]
fn initial_post_base_references_keep_all_six_first_head_bindings() {
    let (selection, bootstrap, sequence) = post_base_initial_recipe();
    let insertions =
        Insertions::new(&bootstrap, &sequence, selection.variant, &Method::GET).unwrap();
    assert!(
        insertions
            .validate_request(&selection.effective.capture)
            .unwrap()
    );
    let mut current = HeaderMap::new();
    for (name, value) in [
        ("user-agent", "current-browser"),
        ("accept", "current-accept"),
        ("accept-language", "current-language"),
        ("accept-encoding", "current-encoding"),
        ("alt-used", "current-authority"),
        ("upgrade-insecure-requests", "1"),
        ("sec-fetch-dest", "document"),
        ("sec-fetch-mode", "navigate"),
        ("sec-fetch-site", "none"),
        ("sec-fetch-user", "?1"),
        ("priority", "u=1"),
    ] {
        current.append(name, HeaderValue::from_static(value));
    }
    let replayed = selection
        .replay_initial_request(&current, &bootstrap, &sequence)
        .unwrap();
    assert_eq!(
        replayed.qpack_base,
        Some(FieldSectionBase::FromFieldPreferences)
    );
    let headers = replayed.headers.unwrap();
    let preferences = replayed.qpack_headers.unwrap();
    for (instruction, field_index) in [(1, 8), (2, 10), (3, 11), (4, 12), (5, 13), (6, 14)] {
        let name = [
            "alt-used",
            "sec-fetch-dest",
            "sec-fetch-mode",
            "sec-fetch-site",
            "sec-fetch-user",
            "priority",
        ][instruction - 1];
        assert_eq!(headers[name], current[name]);
        let preference = &preferences.headers[name];
        assert_eq!(
            preference.representation,
            Representation::DynamicIndexAfterBase
        );
        let insertion = preference.insertion.unwrap();
        assert_eq!(insertion.scope, InsertionScope::InitialSection);
        assert_eq!(insertion.name_huffman, Some(true));
        assert_eq!(insertion.value_huffman, Some(true));
        assert_eq!(
            bootstrap.bindings.insertions[instruction - 1].field,
            InsertionFieldMatch::Unique { field_index }
        );
    }
    assert!(
        preferences
            .pseudo_headers
            .values()
            .all(|field| field.insertion.is_none())
    );
}

#[test]
fn initial_pre_and_post_base_references_require_one_proved_base() {
    let (mut selection, mut bootstrap, sequence) = dynamic_initial_recipe();
    let limits = JointCaptureLimits::default();
    let mut joint = JointCapture::from_canonical(&selection.effective.capture, limits).unwrap();
    for slot in &mut joint.slots {
        match slot.kind {
            CapturedSlotKind::Headers => {
                let policy = HeaderCapturePolicy::default();
                let mut capture = HeaderCapture::from_canonical(&slot.value, &policy).unwrap();
                for (index, field) in capture.fields.iter_mut().enumerate() {
                    field.representation = Some(ObservedFieldRepresentation::from(
                        &FieldLine::IndexedPostBase {
                            index: index as u64,
                        },
                    ));
                }
                slot.value = capture.canonical(&policy).unwrap();
            }
            CapturedSlotKind::PseudoHeaders => {
                let mut capture =
                    PseudoHeaderCapture::from_canonical(&slot.value, limits.value_bytes).unwrap();
                capture.fields[3].representation =
                    Some(ObservedFieldRepresentation::from(&FieldLine::Indexed {
                        is_static: false,
                        index: 0,
                    }));
                slot.value = capture.canonical(limits.value_bytes).unwrap();
            }
            _ => (),
        }
    }
    selection
        .effective
        .set_capture(joint.canonical(limits).unwrap());
    selection.variant = selection.effective.capture.id;
    bootstrap.request = selection.variant;
    let insertions =
        Insertions::new(&bootstrap, &sequence, selection.variant, &Method::GET).unwrap();
    assert!(
        insertions
            .validate_request(&selection.effective.capture)
            .unwrap()
    );

    let policy = HeaderCapturePolicy::default();
    let headers = joint
        .slots
        .iter_mut()
        .find(|slot| slot.kind == CapturedSlotKind::Headers)
        .unwrap();
    let mut captured = HeaderCapture::from_canonical(&headers.value, &policy).unwrap();
    captured.fields[0].representation.as_mut().unwrap().index = Some(1);
    headers.value = captured.canonical(&policy).unwrap();
    let contradictory = joint.canonical(limits).unwrap();
    let error = insertions.validate_request(&contradictory).unwrap_err();
    assert!(matches!(
        error,
        ProfileDataError::Invalid("captured initial QPACK references disagree on Base")
    ));
}

#[test]
fn initial_post_base_reference_without_its_own_binding_is_rejected() {
    let (mut selection, mut bootstrap, sequence) = post_base_initial_recipe();
    let limits = JointCaptureLimits::default();
    let mut joint = JointCapture::from_canonical(&selection.effective.capture, limits).unwrap();
    let slot = joint
        .slots
        .iter_mut()
        .find(|slot| slot.kind == CapturedSlotKind::PseudoHeaders)
        .unwrap();
    let mut captured =
        PseudoHeaderCapture::from_canonical(&slot.value, limits.value_bytes).unwrap();
    captured.fields[0].representation = Some(ObservedFieldRepresentation::from(
        &FieldLine::IndexedPostBase { index: 0 },
    ));
    slot.value = captured.canonical(limits.value_bytes).unwrap();
    selection
        .effective
        .set_capture(joint.canonical(limits).unwrap());
    selection.variant = selection.effective.capture.id;
    bootstrap.request = selection.variant;
    let insertions =
        Insertions::new(&bootstrap, &sequence, selection.variant, &Method::GET).unwrap();
    assert!(matches!(
        insertions
            .validate_request(&selection.effective.capture)
            .unwrap_err(),
        ProfileDataError::Unsupported("initial QPACK dynamic reference lacks its own insertion")
    ));
}
