use super::*;

#[test]
fn header_canonical_identity_preserves_order_spelling_duplicates_and_representation() {
    let policy = HeaderCapturePolicy::default();
    let a = headers(&[("X-One", "a"), ("X-Two", "b"), ("x-one", "c")]);
    let b = headers(&[("x-one", "a"), ("X-Two", "b"), ("X-One", "c")]);
    assert_ne!(encode(&a).id, encode(&b).id);
    let a = policy
        .capture(
            ProfileCaptureCompleteness::Complete,
            Version::HTTP_3,
            &a,
            None,
        )
        .unwrap();
    let b = policy
        .capture(
            ProfileCaptureCompleteness::Complete,
            Version::HTTP_3,
            &b,
            None,
        )
        .unwrap();
    assert_eq!(
        a.canonical(&policy).unwrap().id,
        b.canonical(&policy).unwrap().id
    );
    assert_eq!(a.fields[2].occurrence, 1);
    let original = a.canonical(&policy).unwrap();
    let mut changed = a.clone();
    changed.fields.swap(0, 1);
    assert_ne!(original.id, changed.canonical(&policy).unwrap().id);
    let mut changed = a;
    changed.fields[0].representation = Some(ObservedFieldRepresentation {
        representation: FieldRepresentation::LiteralName,
        index: None,
        name_huffman: true,
        value_huffman: false,
        never_index: false,
    });
    let represented = changed.canonical(&policy).unwrap();
    assert_ne!(original.id, represented.id);
    assert_eq!(
        HeaderCapture::from_canonical(&represented, &policy)
            .unwrap()
            .canonical(&policy)
            .unwrap()
            .id,
        represented.id
    );
}

#[test]
fn representation_metadata_is_validated_on_capture_and_import() {
    let policy = HeaderCapturePolicy::default();
    let input = headers(&[("accept", "*/*")]);
    for kind in [
        FieldRepresentation::StaticIndex,
        FieldRepresentation::DynamicIndex,
        FieldRepresentation::DynamicPostBaseIndex,
        FieldRepresentation::LiteralStaticName,
        FieldRepresentation::LiteralDynamicName,
        FieldRepresentation::LiteralPostBaseName,
        FieldRepresentation::LiteralName,
    ] {
        let valid = ObservedFieldRepresentation {
            representation: kind,
            index: (kind != FieldRepresentation::LiteralName).then_some(29),
            name_huffman: false,
            value_huffman: false,
            never_index: false,
        };
        let captured = policy
            .capture(
                ProfileCaptureCompleteness::Complete,
                Version::HTTP_3,
                &input,
                Some(&[valid]),
            )
            .unwrap();
        let value = captured.canonical(&policy).unwrap();
        HeaderCapture::from_canonical(&value, &policy).unwrap();
        for version in [Version::HTTP_11, Version::HTTP_2] {
            policy
                .capture(
                    ProfileCaptureCompleteness::Complete,
                    version,
                    &input,
                    Some(&[valid]),
                )
                .unwrap_err();
            let mut wrong_version = captured.clone();
            wrong_version.version = version;
            wrong_version.canonical(&policy).unwrap_err();
        }
        if matches!(
            kind,
            FieldRepresentation::DynamicIndex
                | FieldRepresentation::DynamicPostBaseIndex
                | FieldRepresentation::LiteralDynamicName
                | FieldRepresentation::LiteralPostBaseName
        ) {
            for index in [1 << 62, u64::MAX] {
                let invalid = ObservedFieldRepresentation {
                    index: Some(index),
                    ..valid
                };
                policy
                    .capture(
                        ProfileCaptureCompleteness::Complete,
                        Version::HTTP_3,
                        &input,
                        Some(&[invalid]),
                    )
                    .unwrap_err();
                let mut forged = captured.clone();
                forged.fields[0].representation = Some(invalid);
                forged.canonical(&policy).unwrap_err();
            }
        }
        let mut invalid = valid;
        invalid.index = if valid.index.is_some() { None } else { Some(0) };
        policy
            .capture(
                ProfileCaptureCompleteness::Complete,
                Version::HTTP_3,
                &input,
                Some(&[invalid]),
            )
            .unwrap_err();
        let mut forged = captured;
        forged.fields[0].representation = Some(invalid);
        forged.canonical(&policy).unwrap_err();
        if kind != FieldRepresentation::LiteralName {
            invalid = valid;
            invalid.name_huffman = true;
            policy
                .capture(
                    ProfileCaptureCompleteness::Complete,
                    Version::HTTP_3,
                    &input,
                    Some(&[invalid]),
                )
                .unwrap_err();
        }
        if matches!(
            kind,
            FieldRepresentation::StaticIndex
                | FieldRepresentation::DynamicIndex
                | FieldRepresentation::DynamicPostBaseIndex
        ) {
            for flag in 0..2 {
                invalid = valid;
                invalid.value_huffman = flag == 0;
                invalid.never_index = flag == 1;
                policy
                    .capture(
                        ProfileCaptureCompleteness::Complete,
                        Version::HTTP_3,
                        &input,
                        Some(&[invalid]),
                    )
                    .unwrap_err();
            }
        }
    }
}

#[test]
fn bound_header_qpack_and_lowercase_encoding_has_a_fixed_vector() {
    let policy = HeaderCapturePolicy::default();
    let representation = ObservedFieldRepresentation {
        representation: FieldRepresentation::LiteralName,
        index: None,
        name_huffman: true,
        value_huffman: true,
        never_index: true,
    };
    let capture = policy
        .capture(
            ProfileCaptureCompleteness::Complete,
            Version::HTTP_3,
            &headers(&[("X-Request-ID", "excluded-canary")]),
            Some(&[representation]),
        )
        .unwrap();
    let value = capture.canonical(&policy).unwrap();
    assert_eq!(
        value.bytes.as_ref(),
        &[
            114, 97, 109, 97, 45, 112, 114, 111, 102, 105, 108, 101, 0, 0, 2, 0, 1, 4, 1, 0, 0, 0,
            0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 12, 120, 45, 114, 101, 113, 117, 101, 115, 116, 45,
            105, 100, 0, 0, 0, 0, 1, 1, 6, 0, 1, 1, 1, 1, 15
        ]
    );
    assert_eq!(
        value.id.0,
        [
            222, 44, 164, 165, 174, 125, 99, 210, 100, 170, 69, 108, 221, 187, 98, 83, 22, 27, 170,
            133, 244, 96, 123, 23, 178, 252, 9, 241, 152, 135, 22, 20
        ]
    );
    assert_eq!(
        HeaderCapture::from_canonical(&value, &policy)
            .unwrap()
            .canonical(&policy)
            .unwrap()
            .bytes,
        value.bytes
    );
}
