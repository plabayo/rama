//! Initial recipes bind native insertion preferences to current request fields.

use super::*;
use crate::profile::capture::{
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
    selection.effective.capture = joint.canonical(JointCaptureLimits::default()).unwrap();
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
        .replay_initial_request(
            &original,
            ProfilePreservationMode::Strict,
            &bootstrap,
            &sequence,
        )
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
    let ordinary = selection
        .replay_request(&original, ProfilePreservationMode::Strict)
        .unwrap();
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
fn initial_mapping_rejects_missing_foreign_and_sensitive_associations() {
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
        assert!(
            selection
                .replay_initial_request(
                    &original,
                    ProfilePreservationMode::Strict,
                    &bootstrap,
                    &sequence
                )
                .is_err(),
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
        .replay_initial_request(
            &original,
            ProfilePreservationMode::Strict,
            &bootstrap,
            &sequence,
        )
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
        .replay_initial_request(
            &original,
            ProfilePreservationMode::Strict,
            &bootstrap,
            &sequence,
        )
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
    selection.effective.capture = joint.canonical(limits).unwrap();
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
        .replay_initial_request(
            &original,
            ProfilePreservationMode::Strict,
            &bootstrap,
            &sequence,
        )
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
        PostBase,
        DynamicName,
        UnprovedBase,
        UnboundField,
    }

    for case in [
        InvalidReference::ForeignRelativeIndex,
        InvalidReference::PostBase,
        InvalidReference::DynamicName,
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
            InvalidReference::PostBase => {
                metadata.representation = FieldRepresentation::DynamicPostBaseIndex
            }
            InvalidReference::DynamicName => {
                metadata.representation = FieldRepresentation::LiteralDynamicName
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
        selection.effective.capture = joint.canonical(limits).unwrap();
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
