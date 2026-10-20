use super::*;
use crate::profile::{
    capture::{
        headers::HeaderCapturePolicy,
        joint::{CaptureLevel, CapturedSlot, CapturedSlotKind, JointCapture, JointCaptureLimits},
        observation::ProfileCapture,
    },
    format::canonical::ValueId,
    model::identity::{ConnectionContext, FetchContext, FlowKey, ProfileKey},
};
use rama_http::{HeaderMap, HeaderValue, proto::h3::observation::FieldRepresentation};
use sha2::{Digest as _, Sha256};

fn capture(version: Version) -> PseudoHeaderCapture {
    PseudoHeaderCapture::capture(
        ProfileCaptureCompleteness::Complete,
        version,
        &[
            PseudoHeader::Method,
            PseudoHeader::Authority,
            PseudoHeader::Scheme,
            PseudoHeader::Path,
        ]
        .into_iter()
        .collect(),
        None,
        1024,
    )
    .unwrap()
}
fn value(bytes: Vec<u8>) -> CanonicalValue {
    CanonicalValue {
        id: ValueId(Sha256::digest(&bytes).into()),
        bytes: bytes.into(),
    }
}
fn indexed(index: u64) -> ObservedFieldRepresentation {
    ObservedFieldRepresentation {
        representation: FieldRepresentation::StaticIndex,
        index: Some(index),
        name_huffman: false,
        value_huffman: false,
        never_index: false,
    }
}

#[test]
fn pseudo_order_has_stable_identity_and_request_values_have_no_storage_field() {
    let capture = capture(Version::HTTP_3);
    let value = capture.canonical(1024).unwrap();
    assert_eq!(value.bytes.len(), 35);
    assert_eq!(
        value.id.0,
        [
            16, 218, 251, 180, 181, 46, 93, 22, 30, 156, 73, 182, 252, 28, 238, 86, 40, 187, 23,
            240, 90, 171, 253, 192, 43, 158, 230, 222, 179, 128, 47, 181
        ]
    );
    assert_eq!(
        capture.structural(1024).unwrap().id.0,
        [
            177, 225, 71, 249, 40, 22, 105, 8, 132, 169, 20, 224, 94, 240, 47, 245, 239, 50, 113,
            44, 14, 66, 111, 44, 100, 170, 78, 160, 17, 54, 229, 221
        ]
    );
    let restored = PseudoHeaderCapture::from_canonical(&value, 1024).unwrap();
    assert_eq!(
        restored
            .fields
            .iter()
            .map(|field| field.name)
            .collect::<Vec<_>>(),
        [
            PseudoHeader::Method,
            PseudoHeader::Authority,
            PseudoHeader::Scheme,
            PseudoHeader::Path
        ]
    );
    assert_ne!(
        value.id,
        crate::profile::capture::pseudo_headers::tests::capture(Version::HTTP_2)
            .canonical(1024)
            .unwrap()
            .id
    );
    for domain in [
        CanonicalDomain::PseudoHeaders,
        CanonicalDomain::PseudoHeaderStructure,
    ] {
        let value = if domain == CanonicalDomain::PseudoHeaders {
            capture.canonical(1024).unwrap()
        } else {
            capture.structural(1024).unwrap()
        };
        assert_eq!(value.validated_domain(1024).unwrap(), domain);
    }
}

#[test]
fn pseudo_incomplete_legacy_versions_and_small_budgets_do_not_gain_capability() {
    let mut capture = capture(Version::HTTP_2);
    let order = capture.fields.iter().map(|field| field.name).collect();
    PseudoHeaderCapture::capture(
        ProfileCaptureCompleteness::Incomplete,
        Version::HTTP_2,
        &order,
        None,
        1024,
    )
    .unwrap_err();
    capture.completeness = ProfileCaptureCompleteness::Incomplete;
    capture.canonical(1024).unwrap_err();
    capture.structural(1024).unwrap_err();
    capture.completeness = ProfileCaptureCompleteness::Complete;
    for version in [Version::HTTP_09, Version::HTTP_10, Version::HTTP_11] {
        capture.version = version;
        capture.canonical(1024).unwrap_err();
        capture.structural(1024).unwrap_err();
    }
    capture.version = Version::HTTP_2;
    for maximum in [0, 1, 4, 26, 34] {
        capture.canonical(maximum).unwrap_err();
        capture.structural(maximum).unwrap_err();
        PseudoHeaderCapture::capture(
            ProfileCaptureCompleteness::Complete,
            Version::HTTP_2,
            &order,
            None,
            maximum,
        )
        .unwrap_err();
    }
}

#[test]
fn pseudo_import_rejects_duplicates_response_names_and_missing_request_shapes() {
    for names in [
        vec![],
        vec![PseudoHeader::Method],
        vec![PseudoHeader::Method, PseudoHeader::Status],
        vec![
            PseudoHeader::Method,
            PseudoHeader::Authority,
            PseudoHeader::Method,
        ],
        vec![PseudoHeader::Method, PseudoHeader::Scheme],
        vec![
            PseudoHeader::Method,
            PseudoHeader::Authority,
            PseudoHeader::Protocol,
        ],
    ] {
        let capture = PseudoHeaderCapture {
            completeness: ProfileCaptureCompleteness::Complete,
            version: Version::HTTP_3,
            fields: names
                .into_iter()
                .map(|name| PseudoHeaderOccurrence {
                    name,
                    representation: None,
                })
                .collect(),
        };
        capture.canonical(1024).unwrap_err();
        capture.structural(1024).unwrap_err();
    }
    for names in [
        vec![PseudoHeader::Method, PseudoHeader::Authority],
        vec![
            PseudoHeader::Method,
            PseudoHeader::Scheme,
            PseudoHeader::Path,
        ],
        vec![
            PseudoHeader::Method,
            PseudoHeader::Authority,
            PseudoHeader::Scheme,
            PseudoHeader::Path,
            PseudoHeader::Protocol,
        ],
    ] {
        let order = names.into_iter().collect();
        PseudoHeaderCapture::capture(
            ProfileCaptureCompleteness::Complete,
            Version::HTTP_3,
            &order,
            None,
            1024,
        )
        .unwrap();
    }
}

#[test]
fn pseudo_compression_metadata_is_aligned_validated_and_not_structural() {
    let mut capture = capture(Version::HTTP_3);
    let base = capture.canonical(1024).unwrap();
    let structure = capture.structural(1024).unwrap();
    let order = capture.fields.iter().map(|field| field.name).collect();
    for size in [0, 3, 5] {
        PseudoHeaderCapture::capture(
            ProfileCaptureCompleteness::Complete,
            Version::HTTP_3,
            &order,
            Some(&vec![indexed(17); size]),
            1024,
        )
        .unwrap_err();
    }
    // QPACK index 17 is :method GET. Its value is still a request binding.
    capture.fields[0].representation = Some(indexed(17));
    let observed = capture.canonical(1024).unwrap();
    assert_ne!(base.id, observed.id);
    assert_eq!(structure.id, capture.structural(1024).unwrap().id);
    assert_eq!(
        PseudoHeaderCapture::from_canonical(&observed, 1024)
            .unwrap()
            .fields[0]
            .representation
            .unwrap()
            .index,
        Some(17)
    );
    capture.fields.swap(0, 3);
    assert_eq!(structure.id, capture.structural(1024).unwrap().id);
    assert_ne!(observed.id, capture.canonical(1024).unwrap().id);
    capture.version = Version::HTTP_2;
    capture.canonical(1024).unwrap_err();
    capture.version = Version::HTTP_3;
    capture.fields[3].representation = Some(indexed(0)); // :authority, not :method.
    capture.canonical(1024).unwrap_err();
    capture.structural(1024).unwrap_err();
}

#[test]
fn static_qpack_index_bounds_apply_to_regular_and_pseudo_fields() {
    let policy = HeaderCapturePolicy::default();
    let mut headers = HeaderMap::new();
    headers.insert("accept", HeaderValue::from_static("text/plain"));
    for kind in [
        FieldRepresentation::StaticIndex,
        FieldRepresentation::LiteralStaticName,
    ] {
        for index in [99, u64::MAX] {
            let metadata = ObservedFieldRepresentation {
                representation: kind,
                ..indexed(index)
            };
            policy
                .capture(
                    ProfileCaptureCompleteness::Complete,
                    Version::HTTP_3,
                    &headers,
                    Some(&[metadata]),
                )
                .unwrap_err();
            let mut capture = capture(Version::HTTP_3);
            capture.fields[0].representation = Some(metadata);
            capture.canonical(1024).unwrap_err();
            capture.structural(1024).unwrap_err();
        }
    }
    let mut capture = capture(Version::HTTP_3);
    for metadata in [
        ObservedFieldRepresentation {
            index: None,
            ..indexed(17)
        },
        ObservedFieldRepresentation {
            never_index: true,
            ..indexed(17)
        },
        ObservedFieldRepresentation {
            value_huffman: true,
            ..indexed(17)
        },
        ObservedFieldRepresentation {
            name_huffman: true,
            ..indexed(17)
        },
    ] {
        capture.fields[0].representation = Some(metadata);
        capture.canonical(1024).unwrap_err();
    }
}

#[test]
fn pseudo_decode_checks_digest_tags_trailing_data_and_structural_canonicality() {
    let capture = capture(Version::HTTP_3);
    let original = capture.canonical(1024).unwrap();
    let mut bad = original.clone();
    bad.id.0[0] ^= 1;
    PseudoHeaderCapture::from_canonical(&bad, 1024).unwrap_err();
    for (index, byte) in [
        (14, 2),
        (17, 1),
        (18, 0),
        (18, 2),
        (26, 6),
        (27, 5),
        (28, 2),
    ] {
        let mut bytes = original.bytes.to_vec();
        bytes[index] = byte;
        value(bytes).validated_domain(1024).unwrap_err();
    }
    let mut bytes = original.bytes.to_vec();
    bytes.push(0);
    value(bytes).validated_domain(1024).unwrap_err();
    let mut bytes = original.bytes.to_vec();
    bytes[16] = 15; // Order is not sorted in the structural domain.
    value(bytes).validated_domain(1024).unwrap_err();
    for length in 0..original.bytes.len() {
        value(original.bytes[..length].to_vec())
            .validated_domain(1024)
            .unwrap_err();
    }
}

#[test]
fn pseudo_joint_ownership_and_flow_version_are_enforced() {
    let limits = JointCaptureLimits::default();
    let mut profile = ProfileCapture {
        profile: ProfileKey::new("test"),
        flow: Some(FlowKey::Http {
            version: Version::HTTP_3,
            method: Method::GET,
            initiator: None,
            fetch: Some(FetchContext::default()),
            connection: ConnectionContext::default(),
        }),
        connection: ConnectionContext::default(),
        joint: JointCapture {
            completeness: ProfileCaptureCompleteness::Complete,
            level: CaptureLevel::Request,
            slots: Box::new([CapturedSlot {
                kind: CapturedSlotKind::PseudoHeaders,
                value: capture(Version::HTTP_3).canonical(1024).unwrap(),
            }]),
        },
    };
    profile.prepare(false, limits).unwrap();
    profile.joint.level = CaptureLevel::Connection;
    profile.joint.canonical(limits).unwrap_err();
    profile.joint.structural(limits).unwrap_err();
    profile.joint.level = CaptureLevel::Request;
    profile.joint.slots[0].value = capture(Version::HTTP_2).canonical(1024).unwrap();
    profile.prepare(false, limits).unwrap_err();
}

#[test]
fn pseudo_method_bindings_reject_connect_and_static_value_mismatches() {
    let limits = JointCaptureLimits::default();
    for names in [
        vec![PseudoHeader::Method, PseudoHeader::Authority],
        vec![
            PseudoHeader::Method,
            PseudoHeader::Scheme,
            PseudoHeader::Path,
        ],
        vec![
            PseudoHeader::Method,
            PseudoHeader::Authority,
            PseudoHeader::Scheme,
            PseudoHeader::Path,
        ],
        vec![
            PseudoHeader::Method,
            PseudoHeader::Authority,
            PseudoHeader::Scheme,
            PseudoHeader::Path,
            PseudoHeader::Protocol,
        ],
    ] {
        for method in [Method::GET, Method::POST, Method::CONNECT] {
            let valid = (method == Method::CONNECT) == matches!(names.len(), 2 | 5);
            let order = names.iter().collect();
            let pseudo = PseudoHeaderCapture::capture(
                ProfileCaptureCompleteness::Complete,
                Version::HTTP_3,
                &order,
                None,
                1024,
            )
            .unwrap();
            let mut profile = ProfileCapture {
                profile: ProfileKey::new("test"),
                flow: Some(FlowKey::Http {
                    version: Version::HTTP_3,
                    method: method.clone(),
                    initiator: None,
                    fetch: None,
                    connection: ConnectionContext::default(),
                }),
                connection: ConnectionContext::default(),
                joint: JointCapture {
                    completeness: ProfileCaptureCompleteness::Complete,
                    level: CaptureLevel::Request,
                    slots: Box::new([CapturedSlot {
                        kind: CapturedSlotKind::PseudoHeaders,
                        value: pseudo.canonical(1024).unwrap(),
                    }]),
                },
            };
            assert_eq!(
                profile.prepare(false, limits).is_ok(),
                valid,
                "{names:?} {method}"
            );
            if valid {
                let mut with_static = pseudo;
                with_static.fields[0].representation =
                    Some(indexed(if method == Method::GET { 20 } else { 17 }));
                profile.joint.slots[0].value = with_static.canonical(1024).unwrap();
                profile.prepare(false, limits).unwrap_err();
            }
        }
    }
}

#[test]
fn static_qpack_name_and_value_bindings_reject_forged_regular_headers() {
    let policy = HeaderCapturePolicy::default();
    let mut headers = HeaderMap::new();
    headers.insert("accept", HeaderValue::from_static("*/*"));
    let original = policy
        .capture(
            ProfileCaptureCompleteness::Complete,
            Version::HTTP_3,
            &headers,
            Some(&[indexed(29)]),
        )
        .unwrap();
    for metadata in [
        indexed(0),
        indexed(30),
        ObservedFieldRepresentation {
            representation: FieldRepresentation::LiteralStaticName,
            ..indexed(0)
        },
    ] {
        policy
            .capture(
                ProfileCaptureCompleteness::Complete,
                Version::HTTP_3,
                &headers,
                Some(&[metadata]),
            )
            .unwrap_err();
        let mut forged = original.clone();
        forged.fields[0].representation = Some(metadata);
        forged.canonical(&policy).unwrap_err();
        forged.structural(&policy).unwrap_err();
    }
    let literal = ObservedFieldRepresentation {
        representation: FieldRepresentation::LiteralStaticName,
        ..indexed(30)
    };
    policy
        .capture(
            ProfileCaptureCompleteness::Complete,
            Version::HTTP_3,
            &headers,
            Some(&[literal]),
        )
        .unwrap();
}
