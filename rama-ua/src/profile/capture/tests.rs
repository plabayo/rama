use crate::profile::CanonicalDomain;
use crate::profile::ProfileCaptureCompleteness;
use std::collections::BTreeSet;

use super::*;
use crate::profile::{CountedObservationBucket, ObservationId, ProfileBucketLimits, ValueId};
use sha2::{Digest as _, Sha256};

fn headers(values: &[(&str, &str)]) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for (name, value) in values {
        headers.append(
            HeaderName::from_bytes(name.as_bytes()).unwrap(),
            HeaderValue::from_bytes(value.as_bytes()).unwrap(),
        );
    }
    headers
}

fn encode(headers: &HeaderMap) -> CanonicalValue {
    let policy = HeaderCapturePolicy::default();
    policy
        .capture(
            ProfileCaptureCompleteness::Complete,
            Version::HTTP_11,
            headers,
            None,
        )
        .unwrap()
        .canonical(&policy)
        .unwrap()
}

#[test]
fn header_ownership_preserves_browser_fields_and_binds_message_values() {
    let mut input = headers(&[
        ("User-Agent", "reference/1"),
        ("Accept", "text/html"),
        ("Accept-Language", "en"),
        ("Accept-Encoding", "gzip"),
        ("Sec-CH-UA", "reference"),
        ("Upgrade-Insecure-Requests", "1"),
        ("Priority", "u=1"),
        ("DNT", "1"),
        ("Sec-Fetch-User", "?1"),
        ("Sec-Fetch-Mode", "navigate"),
        ("X-App-Mode", "full"),
        ("Cookie", "cookie-canary"),
        ("Authorization", "auth-canary"),
        ("Proxy-Authorization", "proxy-canary"),
        ("Host", "private.example"),
        ("Sec-WebSocket-Key", "nonce-canary"),
        ("Origin", "https://private.example"),
        ("Referer", "https://private.example/account"),
        ("Content-Length", "18"),
        (
            "Content-Type",
            "multipart/form-data; boundary=boundary-canary",
        ),
        ("If-None-Match", "validator-canary"),
        ("Range", "bytes=0-1"),
    ]);
    let mut secret = HeaderValue::from_static("custom-canary");
    secret.set_sensitive(true);
    input.append("x-secret", secret);
    let policy = HeaderCapturePolicy::default();
    let capture = policy
        .capture(
            ProfileCaptureCompleteness::Complete,
            Version::HTTP_11,
            &input,
            None,
        )
        .unwrap();
    for (index, field) in capture.fields.iter().enumerate() {
        assert_eq!(
            matches!(field.value, HeaderValueSource::Profile(_)),
            index < 11,
            "{}",
            field.name
        );
    }
    let value = capture.canonical(&policy).unwrap();
    for canary in [
        "cookie-canary",
        "auth-canary",
        "proxy-canary",
        "private.example",
        "nonce-canary",
        "boundary-canary",
        "validator-canary",
        "custom-canary",
    ] {
        assert!(
            !value
                .bytes
                .windows(canary.len())
                .any(|v| v == canary.as_bytes()),
            "{canary}"
        );
    }
    let decoded = HeaderCapture::from_canonical(&value, &policy).unwrap();
    assert_eq!(decoded.canonical(&policy).unwrap().id, value.id);
}

#[test]
fn request_nonces_and_body_lengths_do_not_create_profile_variants() {
    let mut ids = BTreeSet::new();
    for number in 0..1000 {
        ids.insert(
            encode(&headers(&[
                ("User-Agent", "reference/1"),
                ("Sec-WebSocket-Key", &format!("key-{number}")),
                ("Content-Length", &number.to_string()),
                (
                    "Content-Type",
                    &format!("multipart/form-data; boundary=nonce-{number}"),
                ),
            ]))
            .id,
        );
    }
    assert_eq!(ids.len(), 1);
    let absent = encode(&headers(&[("User-Agent", "reference/1")]));
    let present = encode(&headers(&[
        ("User-Agent", "reference/1"),
        ("Cookie", "secret"),
    ]));
    let changed = encode(&headers(&[
        ("User-Agent", "reference/1"),
        ("Cookie", "another"),
    ]));
    assert_ne!(absent.id, present.id);
    assert_eq!(present.id, changed.id);
}

#[test]
fn header_import_overrides_cannot_retain_protocol_or_sensitive_values() {
    let mut policy = HeaderCapturePolicy::default();
    for name in [
        "cookie",
        "authorization",
        "content-length",
        "content-type",
        "sec-websocket-key",
        "host",
        "origin",
        "referer",
    ] {
        policy.overrides = vec![HeaderOwnershipOverride {
            name: HeaderName::from_bytes(name.as_bytes()).unwrap(),
            ownership: HeaderOwnership::Profile,
        }]
        .into();
        policy
            .capture(
                ProfileCaptureCompleteness::Complete,
                Version::HTTP_11,
                &headers(&[(name, "1")]),
                None,
            )
            .unwrap_err();
    }
    policy.overrides = vec![HeaderOwnershipOverride {
        name: HeaderName::from_static("x-app"),
        ownership: HeaderOwnership::Profile,
    }]
    .into();
    let input = headers(&[("X-App", "capture-safe")]);
    let capture = policy
        .capture(
            ProfileCaptureCompleteness::Complete,
            Version::HTTP_11,
            &input,
            None,
        )
        .unwrap();
    assert!(
        matches!(&capture.fields[0].value, HeaderValueSource::Profile(value) if &**value == b"capture-safe")
    );
    policy.overrides[0].ownership = HeaderOwnership::Request;
    assert!(matches!(
        policy
            .capture(
                ProfileCaptureCompleteness::Complete,
                Version::HTTP_11,
                &input,
                None
            )
            .unwrap()
            .fields[0]
            .value,
        HeaderValueSource::Request(RequestBinding::Custom)
    ));
    policy.overrides[0].ownership = HeaderOwnership::Profile;
    let mut input = input;
    input.get_mut("x-app").unwrap().set_sensitive(true);
    policy
        .capture(
            ProfileCaptureCompleteness::Complete,
            Version::HTTP_11,
            &input,
            None,
        )
        .unwrap_err();
    let input = headers(&[("Connection", "x-app"), ("X-App", "connection-secret")]);
    policy
        .capture(
            ProfileCaptureCompleteness::Complete,
            Version::HTTP_11,
            &input,
            None,
        )
        .unwrap_err();
    policy.overrides = Box::default();
    let capture = policy
        .capture(
            ProfileCaptureCompleteness::Complete,
            Version::HTTP_11,
            &input,
            None,
        )
        .unwrap();
    assert!(matches!(
        capture.fields[1].value,
        HeaderValueSource::Request(RequestBinding::Connection)
    ));
}

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
fn representation_metadata_is_validated_on_capture_and_import() {
    let policy = HeaderCapturePolicy::default();
    let input = headers(&[("X-Test", "a")]);
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
            index: (kind != FieldRepresentation::LiteralName).then_some(0),
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
        let mut forged = captured.clone();
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
fn forwarding_identifiers_proofs_and_body_fields_never_become_profile_values() {
    let names = [
        ("forwarded", RequestBinding::Forwarding),
        ("x-forwarded-for", RequestBinding::Forwarding),
        ("x-forwarded-host", RequestBinding::Forwarding),
        ("x-forwarded-proto", RequestBinding::Forwarding),
        ("x-forwarded-port", RequestBinding::Forwarding),
        ("x-real-ip", RequestBinding::Forwarding),
        ("via", RequestBinding::Forwarding),
        ("alt-used", RequestBinding::Authority),
        ("traceparent", RequestBinding::PerRequestId),
        ("tracestate", RequestBinding::PerRequestId),
        ("baggage", RequestBinding::PerRequestId),
        ("x-request-id", RequestBinding::PerRequestId),
        ("request-id", RequestBinding::PerRequestId),
        ("x-correlation-id", RequestBinding::PerRequestId),
        ("correlation-id", RequestBinding::PerRequestId),
        ("idempotency-key", RequestBinding::PerRequestId),
        ("dpop", RequestBinding::Proof),
        ("sec-websocket-protocol", RequestBinding::WebSocketProtocol),
        ("expect", RequestBinding::BodyMetadata),
        ("signature", RequestBinding::Proof),
        ("signature-input", RequestBinding::Proof),
        ("last-event-id", RequestBinding::PerRequestId),
        ("ping-from", RequestBinding::Referer),
        ("ping-to", RequestBinding::Referer),
        ("cdn-loop", RequestBinding::Forwarding),
        ("max-forwards", RequestBinding::Forwarding),
        ("early-data", RequestBinding::Connection),
        ("http2-settings", RequestBinding::Connection),
        ("content-language", RequestBinding::BodyMetadata),
        ("content-location", RequestBinding::BodyMetadata),
        ("content-custom", RequestBinding::BodyMetadata),
    ];
    let secret = "private-binding-canary";
    let policy = HeaderCapturePolicy::default();
    for version in [Version::HTTP_11, Version::HTTP_2, Version::HTTP_3] {
        for (name, binding) in names {
            let captured = policy
                .capture(
                    ProfileCaptureCompleteness::Complete,
                    version,
                    &headers(&[(name, secret)]),
                    None,
                )
                .unwrap();
            assert!(
                matches!(captured.fields[0].value, HeaderValueSource::Request(value) if value == binding)
            );
            let value = captured.canonical(&policy).unwrap();
            assert!(
                !value
                    .bytes
                    .windows(secret.len())
                    .any(|bytes| bytes == secret.as_bytes())
            );
            let changed = policy
                .capture(
                    ProfileCaptureCompleteness::Complete,
                    version,
                    &headers(&[(name, "another-request")]),
                    None,
                )
                .unwrap()
                .canonical(&policy)
                .unwrap();
            assert_eq!(changed.id, value.id);
            assert_eq!(
                HeaderCapture::from_canonical(&value, &policy)
                    .unwrap()
                    .canonical(&policy)
                    .unwrap()
                    .id,
                value.id
            );
            let mut bucket = CountedObservationBucket::new(
                CanonicalDomain::Headers,
                ValueId([2; 32]),
                [3; 32],
                ProfileBucketLimits::default(),
            )
            .unwrap();
            bucket
                .observe(
                    ObservationId {
                        run: [1; 16],
                        sequence: 1,
                    },
                    &value,
                )
                .unwrap();
            let numeric = serde_json::to_string(secret.as_bytes()).unwrap();
            let debug_numeric = format!("{:?}", secret.as_bytes());
            for output in [
                serde_json::to_string(&captured).unwrap(),
                serde_json::to_string(&bucket.snapshot()).unwrap(),
            ] {
                assert!(!output.contains(secret));
                assert!(!output.contains(&numeric[1..numeric.len() - 1]));
            }
            for output in [format!("{captured:?}"), format!("{:?}", bucket.snapshot())] {
                assert!(!output.contains(secret));
                assert!(!output.contains(&debug_numeric[1..debug_numeric.len() - 1]));
            }
            let mut forged = captured;
            forged.fields[0].value = HeaderValueSource::Profile(secret.as_bytes().into());
            forged.canonical(&policy).unwrap_err();
            let mut override_policy = policy.clone();
            override_policy.overrides = vec![HeaderOwnershipOverride {
                name: HeaderName::from_bytes(name.as_bytes()).unwrap(),
                ownership: HeaderOwnership::Profile,
            }]
            .into();
            override_policy
                .capture(
                    ProfileCaptureCompleteness::Complete,
                    version,
                    &headers(&[(name, secret)]),
                    None,
                )
                .unwrap_err();
        }
    }
}

#[test]
fn canonical_and_decoded_imports_enforce_explicit_ownership_overrides() {
    let mut policy = HeaderCapturePolicy::default();
    let input = headers(&[("x-app", "capture-safe")]);
    let captured = policy
        .capture(
            ProfileCaptureCompleteness::Complete,
            Version::HTTP_11,
            &input,
            None,
        )
        .unwrap();
    let encoded = captured.canonical(&policy).unwrap();
    policy.overrides = vec![HeaderOwnershipOverride {
        name: HeaderName::from_static("x-app"),
        ownership: HeaderOwnership::Request,
    }]
    .into();
    captured.canonical(&policy).unwrap_err();
    HeaderCapture::from_canonical(&encoded, &policy).unwrap_err();
    let safe = policy
        .capture(
            ProfileCaptureCompleteness::Complete,
            Version::HTTP_11,
            &input,
            None,
        )
        .unwrap();
    safe.canonical(&policy).unwrap();
    policy.overrides[0].ownership = HeaderOwnership::Profile;
    assert_eq!(captured.canonical(&policy).unwrap().id, encoded.id);
    policy.overrides = vec![policy.overrides[0].clone(); 2].into();
    captured.canonical(&policy).unwrap_err();
    HeaderCapture::from_canonical(&encoded, &policy).unwrap_err();
    policy.overrides = vec![HeaderOwnershipOverride {
        name: HeaderName::from_static("cookie"),
        ownership: HeaderOwnership::Profile,
    }]
    .into();
    let cookies = HeaderCapturePolicy::default()
        .capture(
            ProfileCaptureCompleteness::Complete,
            Version::HTTP_11,
            &headers(&[("cookie", "excluded")]),
            None,
        )
        .unwrap();
    cookies.canonical(&policy).unwrap_err();
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

#[test]
fn custom_credential_and_trace_defaults_require_explicit_capture_safe_values() {
    let names = [
        "sentry-trace",
        "b3",
        "x-b3-traceid",
        "x-amzn-trace-id",
        "x-cloud-trace-context",
        "x-datadog-parent-id",
        "uber-trace-id",
        "newrelic",
        "true-client-ip",
        "x-client-ip",
        "client-ip",
        "x-cluster-client-ip",
        "cf-connecting-ip",
        "fastly-client-ip",
        "x-csrf-token",
        "x-xsrf-token",
        "x-api-key",
        "api-key",
        "x-apikey",
        "x-auth",
        "x-authorization",
        "password",
        "x-credential",
        "x-bearer",
        "x-jwt",
        "sec-private-state-token-crypto-version",
        "x-auth-token",
        "x-access-token",
        "x-amz-security-token",
        "my-secret",
        "session-key",
        "request-signature",
    ];
    let secret = "custom-private-canary";
    for version in [Version::HTTP_11, Version::HTTP_2, Version::HTTP_3] {
        for name in names {
            let mut policy = HeaderCapturePolicy::default();
            let input = headers(&[(name, secret)]);
            let captured = policy
                .capture(ProfileCaptureCompleteness::Complete, version, &input, None)
                .unwrap();
            assert!(matches!(
                captured.fields[0].value,
                HeaderValueSource::Request(_)
            ));
            let canonical = captured.canonical(&policy).unwrap();
            assert!(
                !canonical
                    .bytes
                    .windows(secret.len())
                    .any(|part| part == secret.as_bytes())
            );
            let mut bucket = CountedObservationBucket::new(
                CanonicalDomain::Headers,
                ValueId([2; 32]),
                [3; 32],
                ProfileBucketLimits::default(),
            )
            .unwrap();
            bucket
                .observe(
                    ObservationId {
                        run: [1; 16],
                        sequence: 1,
                    },
                    &canonical,
                )
                .unwrap();
            let numeric = serde_json::to_string(secret.as_bytes()).unwrap();
            let debug_numeric = format!("{:?}", secret.as_bytes());
            for output in [
                serde_json::to_string(&captured).unwrap(),
                serde_json::to_string(&bucket.snapshot()).unwrap(),
                format!("{captured:?}"),
                format!("{:?}", bucket.snapshot()),
            ] {
                assert!(!output.contains(secret));
                assert!(!output.contains(&numeric[1..numeric.len() - 1]));
                assert!(!output.contains(&debug_numeric[1..debug_numeric.len() - 1]));
            }
            let mut forged = captured;
            forged.fields[0].value = HeaderValueSource::Profile(secret.as_bytes().into());
            forged.canonical(&policy).unwrap_err();
            policy.overrides = vec![HeaderOwnershipOverride {
                name: HeaderName::from_bytes(name.as_bytes()).unwrap(),
                ownership: HeaderOwnership::Profile,
            }]
            .into();
            let safe = policy
                .capture(
                    ProfileCaptureCompleteness::Complete,
                    version,
                    &headers(&[(name, "fixed-safe-mode")]),
                    None,
                )
                .unwrap();
            assert!(matches!(
                safe.fields[0].value,
                HeaderValueSource::CaptureSafeProfile(_)
            ));
            let value = safe.canonical(&policy).unwrap();
            // The explicit importer assertion survives storage/structural validation.
            value.validated_domain(policy.bytes).unwrap();
            safe.structural(&HeaderCapturePolicy::default()).unwrap();
            assert_eq!(
                HeaderCapture::from_canonical(&value, &HeaderCapturePolicy::default())
                    .unwrap()
                    .canonical(&HeaderCapturePolicy::default())
                    .unwrap()
                    .id,
                value.id
            );
            let mut flagged = HeaderValue::from_static("never-safe");
            flagged.set_sensitive(true);
            let mut sensitive = HeaderMap::new();
            sensitive.insert(HeaderName::from_bytes(name.as_bytes()).unwrap(), flagged);
            policy
                .capture(
                    ProfileCaptureCompleteness::Complete,
                    version,
                    &sensitive,
                    None,
                )
                .unwrap_err();
        }
    }
}

#[test]
fn explicit_capture_safe_literals_cannot_override_protocol_or_sensitive_bindings() {
    let policy = HeaderCapturePolicy::default();
    for name in [
        "authorization",
        "cookie",
        "signature",
        "content-location",
        "forwarded",
    ] {
        let mut captured = policy
            .capture(
                ProfileCaptureCompleteness::Complete,
                Version::HTTP_11,
                &headers(&[(name, "private-canary")]),
                None,
            )
            .unwrap();
        captured.fields[0].value =
            HeaderValueSource::CaptureSafeProfile(b"private-canary".as_slice().into());
        captured.canonical(&policy).unwrap_err();
    }
}
