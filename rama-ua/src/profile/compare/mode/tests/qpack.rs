use super::*;
use crate::profile::capture::{
    headers::{
        HeaderCapture, HeaderCapturePolicy, HeaderOccurrence, HeaderValueSource, RequestBinding,
    },
    joint::{CaptureLevel, CapturedSlot, JointCapture},
    pseudo_headers::{PseudoHeaderCapture, PseudoHeaderOccurrence},
};
use rama_http::{
    HeaderName, Version,
    proto::h3::{PseudoHeader, qpack::static_table},
};

fn metadata(kind: FieldRepresentation, index: u64) -> ObservedFieldRepresentation {
    ObservedFieldRepresentation {
        representation: kind,
        index: Some(index),
        name_huffman: false,
        value_huffman: false,
        never_index: false,
    }
}

fn headers(metadata: ObservedFieldRepresentation, value: &'static [u8]) -> CanonicalValue {
    HeaderCapture {
        completeness: ProfileCaptureCompleteness::Complete,
        version: Version::HTTP_3,
        fields: vec![HeaderOccurrence {
            name: HeaderName::from_static("accept"),
            occurrence: 0,
            sensitive: false,
            representation: Some(metadata),
            value: HeaderValueSource::Profile(value.into()),
        }]
        .into(),
    }
    .canonical(&HeaderCapturePolicy::default())
    .unwrap()
}

fn pseudo(index: u64, reverse: bool) -> CanonicalValue {
    let mut fields = [
        PseudoHeader::Method,
        PseudoHeader::Scheme,
        PseudoHeader::Path,
    ]
    .map(|name| PseudoHeaderOccurrence {
        name,
        representation: Some(metadata(FieldRepresentation::DynamicIndex, index)),
    });
    if reverse {
        fields.reverse();
    }
    PseudoHeaderCapture {
        completeness: ProfileCaptureCompleteness::Complete,
        version: Version::HTTP_3,
        fields: fields.into(),
    }
    .canonical(65536)
    .unwrap()
}

fn joint_request(index: u64, value: &'static [u8], reverse: bool) -> CanonicalValue {
    JointCapture {
        completeness: ProfileCaptureCompleteness::Complete,
        level: CaptureLevel::Request,
        slots: vec![
            CapturedSlot {
                kind: CapturedSlotKind::Headers,
                value: headers(metadata(FieldRepresentation::DynamicIndex, index), value),
            },
            CapturedSlot {
                kind: CapturedSlotKind::PseudoHeaders,
                value: pseudo(index, reverse),
            },
        ]
        .into(),
    }
    .canonical(JointCaptureLimits::default())
    .unwrap()
}

#[test]
fn replay_compares_dynamic_reference_policy_without_rewriting_wire_evidence() {
    for kind in [
        FieldRepresentation::DynamicIndex,
        FieldRepresentation::DynamicPostBaseIndex,
        FieldRepresentation::LiteralDynamicName,
        FieldRepresentation::LiteralPostBaseName,
    ] {
        let reference = headers(metadata(kind, 7), b"value");
        let original = reference.clone();
        for index in [0, 1, 31, (1 << 62) - 1] {
            let actual = headers(metadata(kind, index), b"value");
            assert!(!matches(
                std::slice::from_ref(&reference),
                &actual,
                ComparisonMode::Literal
            ));
            let report = compare_retained_captures(
                std::slice::from_ref(&reference),
                &actual,
                ComparisonMode::Replay,
                CaptureComparisonLimits::default(),
            )
            .unwrap();
            assert!(report.matched);
            assert_eq!(report.reference, reference.id);
            assert_eq!(report.observed, actual.id);
            assert_eq!(reference.bytes, original.bytes);
            assert_eq!(reference.id, original.id);
        }
    }
}

#[test]
fn replay_preserves_static_indexes_field_families_flags_and_values() {
    let first = static_table::find_name(b"accept").unwrap() as u64;
    let reference = headers(
        metadata(FieldRepresentation::LiteralStaticName, first),
        b"value",
    );
    let actual = headers(
        metadata(FieldRepresentation::LiteralStaticName, first + 1),
        b"value",
    );
    assert!(!matches(
        std::slice::from_ref(&reference),
        &actual,
        ComparisonMode::Replay
    ));

    let base = metadata(FieldRepresentation::LiteralDynamicName, 7);
    let reference = headers(base, b"value");
    for actual in [
        headers(
            metadata(FieldRepresentation::LiteralPostBaseName, 9),
            b"value",
        ),
        headers(
            ObservedFieldRepresentation {
                value_huffman: true,
                ..base
            },
            b"value",
        ),
        headers(base, b"other"),
    ] {
        assert!(!matches(
            std::slice::from_ref(&reference),
            &actual,
            ComparisonMode::Replay
        ));
    }
    // Keep privacy ownership and sensitivity identical, so only the N flag differs.
    let sensitive = |never_index| {
        HeaderCapture {
            completeness: ProfileCaptureCompleteness::Complete,
            version: Version::HTTP_3,
            fields: vec![HeaderOccurrence {
                name: HeaderName::from_static("accept"),
                occurrence: 0,
                sensitive: true,
                representation: Some(ObservedFieldRepresentation {
                    never_index,
                    ..base
                }),
                value: HeaderValueSource::Request(RequestBinding::Sensitive),
            }]
            .into(),
        }
        .canonical(&HeaderCapturePolicy::default())
        .unwrap()
    };
    assert!(!matches(
        &[sensitive(false)],
        &sensitive(true),
        ComparisonMode::Replay
    ));
}

#[test]
fn replay_projects_pseudo_and_joint_indexes_without_combining_variants() {
    let reference = [
        joint_request(7, b"first", false),
        joint_request(9, b"second", true),
    ];
    assert!(matches(
        &reference,
        &joint_request(31, b"first", false),
        ComparisonMode::Replay
    ));
    assert!(!matches(
        &reference,
        &joint_request(31, b"first", true),
        ComparisonMode::Replay
    ));
    assert!(!matches(
        &reference,
        &joint_request(31, b"first", false),
        ComparisonMode::Literal
    ));
    assert!(!matches(
        &[pseudo(7, false)],
        &pseudo(31, true),
        ComparisonMode::Replay
    ));
}
