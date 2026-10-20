use super::*;

#[test]
fn header_import_rejects_conflicting_framing_and_incomplete_metadata() {
    let policy = HeaderCapturePolicy::default();
    for input in [
        headers(&[("Content-Length", "1"), ("Content-Length", "2")]),
        headers(&[("Content-Length", "+1")]),
        headers(&[("Content-Length", "1"), ("Transfer-Encoding", "chunked")]),
        headers(&[("Host", "a.example"), ("Host", "a.example")]),
    ] {
        for version in [Version::HTTP_11, Version::HTTP_2, Version::HTTP_3] {
            policy
                .capture(ProfileCaptureCompleteness::Complete, version, &input, None)
                .unwrap_err();
        }
    }
    for version in [Version::HTTP_11, Version::HTTP_2, Version::HTTP_3] {
        policy
            .capture(
                ProfileCaptureCompleteness::Complete,
                version,
                &headers(&[("Content-Length", "1, 1"), ("Content-Length", "1")]),
                None,
            )
            .unwrap();
        policy
            .capture(
                ProfileCaptureCompleteness::Complete,
                version,
                &headers(&[("x-app", "a")]),
                Some(&[]),
            )
            .unwrap_err();
    }
    for version in [Version::HTTP_2, Version::HTTP_3] {
        for input in [
            headers(&[("Connection", "close")]),
            headers(&[("TE", "gzip")]),
        ] {
            policy
                .capture(ProfileCaptureCompleteness::Complete, version, &input, None)
                .unwrap_err();
        }
        policy
            .capture(
                ProfileCaptureCompleteness::Complete,
                version,
                &headers(&[("TE", "trailers")]),
                None,
            )
            .unwrap();
    }
}

#[test]
fn header_canonical_golden_vector_and_hostile_decode_bounds() {
    let policy = HeaderCapturePolicy::default();
    let value = encode(&headers(&[("X-Test", "a")]));
    assert_eq!(value.bytes.as_ref(), b"\x72\x61\x6d\x61\x2d\x70\x72\x6f\x66\x69\x6c\x65\x00\x00\x02\x00\x01\x02\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x06\x58\x2d\x54\x65\x73\x74\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x61");
    assert_eq!(
        value.id.0,
        [
            6, 191, 188, 221, 22, 21, 89, 4, 144, 227, 168, 120, 26, 90, 180, 166, 162, 75, 47,
            134, 0, 122, 181, 23, 231, 55, 194, 205, 74, 242, 87, 223
        ]
    );
    for length in 0..value.bytes.len() {
        let bytes: Box<[u8]> = value.bytes[..length].into();
        let truncated = CanonicalValue {
            id: ValueId(Sha256::digest(&bytes).into()),
            bytes,
        };
        HeaderCapture::from_canonical(&truncated, &policy).unwrap_err();
    }
    let mut mismatched = value.clone();
    *mismatched.bytes.last_mut().unwrap() = b'b';
    HeaderCapture::from_canonical(&mismatched, &policy).unwrap_err();
    let mut tampered = value.clone();
    tampered.bytes[0] ^= 1;
    HeaderCapture::from_canonical(&tampered, &policy).unwrap_err();
    let mut oversized = value.clone();
    oversized.bytes[19..27].fill(255);
    oversized.id.0 = Sha256::digest(&oversized.bytes).into();
    HeaderCapture::from_canonical(&oversized, &policy).unwrap_err();
    let mut limited = policy;
    limited.fields = 0;
    HeaderCapture::from_canonical(&value, &limited).unwrap_err();
    limited.fields = 1;
    limited.bytes = value.bytes.len() - 1;
    HeaderCapture::from_canonical(&value, &limited).unwrap_err();
    limited.bytes += 1;
    HeaderCapture::from_canonical(&value, &limited).unwrap();
}

#[test]
fn header_capture_input_bounds_and_direct_secret_forgery_are_rejected() {
    let mut policy = HeaderCapturePolicy {
        fields: 1,
        bytes: 3,
        overrides: Box::default(),
    };
    let input = headers(&[("x", "ab")]);
    policy
        .capture(
            ProfileCaptureCompleteness::Complete,
            Version::HTTP_11,
            &input,
            None,
        )
        .unwrap();
    policy.bytes = 2;
    policy
        .capture(
            ProfileCaptureCompleteness::Complete,
            Version::HTTP_11,
            &input,
            None,
        )
        .unwrap_err();
    policy.bytes = 3;
    policy.fields = 0;
    policy
        .capture(
            ProfileCaptureCompleteness::Complete,
            Version::HTTP_11,
            &input,
            None,
        )
        .unwrap_err();
    let policy = HeaderCapturePolicy::default();
    let mut captured = policy
        .capture(
            ProfileCaptureCompleteness::Complete,
            Version::HTTP_11,
            &headers(&[("Cookie", "canary")]),
            None,
        )
        .unwrap();
    captured.fields[0].value = HeaderValueSource::Profile(b"canary".to_vec().into());
    captured.canonical(&policy).unwrap_err();
    let mut captured = policy
        .capture(
            ProfileCaptureCompleteness::Complete,
            Version::HTTP_11,
            &headers(&[("x-app", "a")]),
            None,
        )
        .unwrap();
    for binding in [
        RequestBinding::Authority,
        RequestBinding::Framing,
        RequestBinding::Cookie,
        RequestBinding::Authorization,
        RequestBinding::WebSocketKey,
        RequestBinding::Origin,
    ] {
        captured.fields[0].value = HeaderValueSource::Request(binding);
        captured.canonical(&policy).unwrap_err();
    }
}

#[test]
fn canonical_import_cannot_bypass_header_shape_validation() {
    let policy = HeaderCapturePolicy::default();
    let host = policy
        .capture(
            ProfileCaptureCompleteness::Complete,
            Version::HTTP_11,
            &headers(&[("Host", "a")]),
            None,
        )
        .unwrap();
    let mut duplicated = host;
    let mut fields = duplicated.fields.to_vec();
    let mut duplicate = fields[0].clone();
    duplicate.occurrence = 1;
    fields.push(duplicate);
    duplicated.fields = fields.into();
    duplicated.canonical(&policy).unwrap_err();
    let mut framing = policy
        .capture(
            ProfileCaptureCompleteness::Complete,
            Version::HTTP_11,
            &headers(&[("Content-Length", "1")]),
            None,
        )
        .unwrap();
    let transfer = policy
        .capture(
            ProfileCaptureCompleteness::Complete,
            Version::HTTP_11,
            &headers(&[("Transfer-Encoding", "chunked")]),
            None,
        )
        .unwrap();
    let mut fields = framing.fields.to_vec();
    fields.extend_from_slice(&transfer.fields);
    framing.fields = fields.into();
    framing.canonical(&policy).unwrap_err();
    for name in [
        "connection",
        "keep-alive",
        "proxy-connection",
        "transfer-encoding",
        "upgrade",
    ] {
        let mut captured = policy
            .capture(
                ProfileCaptureCompleteness::Complete,
                Version::HTTP_11,
                &headers(&[(name, "close")]),
                None,
            )
            .unwrap();
        for version in [Version::HTTP_2, Version::HTTP_3] {
            captured.version = version;
            captured.canonical(&policy).unwrap_err();
        }
    }
}

#[test]
fn never_index_metadata_prevents_literal_retention_even_without_header_flag() {
    let input = headers(&[("x-private", "private-value-canary")]);
    let mut policy = HeaderCapturePolicy::default();
    let representation = ObservedFieldRepresentation {
        representation: FieldRepresentation::LiteralName,
        index: None,
        name_huffman: false,
        value_huffman: false,
        never_index: true,
    };
    let mut capture = policy
        .capture(
            ProfileCaptureCompleteness::Complete,
            Version::HTTP_3,
            &input,
            Some(&[representation]),
        )
        .unwrap();
    assert!(capture.fields[0].sensitive);
    assert!(matches!(
        capture.fields[0].value,
        HeaderValueSource::Request(RequestBinding::Sensitive)
    ));
    let value = capture.canonical(&policy).unwrap();
    assert!(
        !value
            .bytes
            .windows(b"private-value-canary".len())
            .any(|v| v == b"private-value-canary")
    );
    HeaderCapture::from_canonical(&value, &policy).unwrap();
    capture.fields[0].sensitive = false;
    capture.canonical(&policy).unwrap_err();
    capture.fields[0].value = HeaderValueSource::Profile(b"private-value-canary".to_vec().into());
    capture.canonical(&policy).unwrap_err();
    policy.overrides = vec![HeaderOwnershipOverride {
        name: HeaderName::from_static("x-private"),
        ownership: HeaderOwnership::Profile,
    }]
    .into();
    policy
        .capture(
            ProfileCaptureCompleteness::Complete,
            Version::HTTP_3,
            &input,
            Some(&[representation]),
        )
        .unwrap_err();
}

#[test]
fn header_ordinals_reject_nonzero_duplicate_and_gapped_occurrences() {
    let policy = HeaderCapturePolicy::default();
    for version in [Version::HTTP_11, Version::HTTP_2, Version::HTTP_3] {
        let fields = ["X-Ordinal", "x-ORDINAL", "X-ordinal"]
            .into_iter()
            .enumerate()
            .map(|(occurrence, name)| HeaderOccurrence {
                name: HeaderName::from_bytes(name.as_bytes()).unwrap(),
                occurrence: occurrence as u32,
                sensitive: false,
                representation: None,
                value: HeaderValueSource::Profile(b"value".as_slice().into()),
            })
            .collect();
        let valid = HeaderCapture {
            completeness: ProfileCaptureCompleteness::Complete,
            version,
            fields,
        };
        let canonical = valid.canonical(&policy).unwrap();
        HeaderCapture::from_canonical(&canonical, &policy).unwrap();

        // Locate each encoded name, whose next four bytes are its ordinal.
        // Case-insensitive names must share one sequence for every HTTP version.
        let offsets: Vec<_> = canonical
            .bytes
            .windows(b"x-ordinal".len())
            .enumerate()
            .filter_map(|(offset, name)| {
                name.eq_ignore_ascii_case(b"x-ordinal")
                    .then_some(offset + name.len())
            })
            .collect();
        assert_eq!(offsets.len(), 3);
        for ordinals in [[1_u32, 1, 2], [0, 0, 2], [0, 2, 2], [0, 1, 1], [0, 1, 3]] {
            let mut invalid = valid.clone();
            let mut forged = canonical.clone();
            for ((field, offset), ordinal) in invalid.fields.iter_mut().zip(&offsets).zip(ordinals)
            {
                field.occurrence = ordinal;
                forged.bytes[*offset..*offset + 4].copy_from_slice(&ordinal.to_be_bytes());
            }
            invalid.canonical(&policy).unwrap_err();
            invalid.structural(&policy).unwrap_err();

            // Recompute identity so rejection proves semantic validation, not a
            // digest mismatch or a truncated envelope.
            forged.id.0 = Sha256::digest(&forged.bytes).into();
            forged.verify(HEADER_DOMAIN, policy.bytes).unwrap();
            HeaderCapture::from_canonical(&forged, &policy).unwrap_err();
        }
    }
}
