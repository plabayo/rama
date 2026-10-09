use std::collections::BTreeSet;

use super::*;
use crate::profile::ValueId;
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
        .capture(Version::HTTP_11, headers, None)
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
    let capture = policy.capture(Version::HTTP_11, &input, None).unwrap();
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
            .capture(Version::HTTP_11, &headers(&[(name, "1")]), None)
            .unwrap_err();
    }
    policy.overrides = vec![HeaderOwnershipOverride {
        name: HeaderName::from_static("x-app"),
        ownership: HeaderOwnership::Profile,
    }]
    .into();
    let input = headers(&[("X-App", "capture-safe")]);
    let capture = policy.capture(Version::HTTP_11, &input, None).unwrap();
    assert!(
        matches!(&capture.fields[0].value, HeaderValueSource::Profile(value) if &**value == b"capture-safe")
    );
    policy.overrides[0].ownership = HeaderOwnership::Request;
    assert!(matches!(
        policy
            .capture(Version::HTTP_11, &input, None)
            .unwrap()
            .fields[0]
            .value,
        HeaderValueSource::Request(RequestBinding::Custom)
    ));
    policy.overrides[0].ownership = HeaderOwnership::Profile;
    let mut input = input;
    input.get_mut("x-app").unwrap().set_sensitive(true);
    policy.capture(Version::HTTP_11, &input, None).unwrap_err();
    let input = headers(&[("Connection", "x-app"), ("X-App", "connection-secret")]);
    policy.capture(Version::HTTP_11, &input, None).unwrap_err();
    policy.overrides = Box::default();
    let capture = policy.capture(Version::HTTP_11, &input, None).unwrap();
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
    let a = policy.capture(Version::HTTP_3, &a, None).unwrap();
    let b = policy.capture(Version::HTTP_3, &b, None).unwrap();
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
            policy.capture(version, &input, None).unwrap_err();
        }
    }
    for version in [Version::HTTP_11, Version::HTTP_2, Version::HTTP_3] {
        policy
            .capture(
                version,
                &headers(&[("Content-Length", "1, 1"), ("Content-Length", "1")]),
                None,
            )
            .unwrap();
        policy
            .capture(version, &headers(&[("x-app", "a")]), Some(&[]))
            .unwrap_err();
    }
    for version in [Version::HTTP_2, Version::HTTP_3] {
        for input in [
            headers(&[("Connection", "close")]),
            headers(&[("TE", "gzip")]),
        ] {
            policy.capture(version, &input, None).unwrap_err();
        }
        policy
            .capture(version, &headers(&[("TE", "trailers")]), None)
            .unwrap();
    }
}

#[test]
fn header_canonical_golden_vector_and_hostile_decode_bounds() {
    let policy = HeaderCapturePolicy::default();
    let value = encode(&headers(&[("X-Test", "a")]));
    assert_eq!(value.bytes.as_ref(), b"rama-profile\0\0\x01\0\x01\x02\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\x06X-Test\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01a");
    assert_eq!(
        value.id.0,
        [
            237, 224, 138, 195, 5, 237, 113, 7, 35, 144, 154, 242, 45, 248, 38, 40, 172, 119, 254,
            14, 35, 202, 12, 95, 94, 73, 128, 48, 173, 101, 120, 3
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
    oversized.bytes[18..26].fill(255);
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
    policy.capture(Version::HTTP_11, &input, None).unwrap();
    policy.bytes = 2;
    policy.capture(Version::HTTP_11, &input, None).unwrap_err();
    policy.bytes = 3;
    policy.fields = 0;
    policy.capture(Version::HTTP_11, &input, None).unwrap_err();
    let policy = HeaderCapturePolicy::default();
    let mut captured = policy
        .capture(Version::HTTP_11, &headers(&[("Cookie", "canary")]), None)
        .unwrap();
    captured.fields[0].value = HeaderValueSource::Profile(b"canary".to_vec().into());
    captured.canonical(&policy).unwrap_err();
    let mut captured = policy
        .capture(Version::HTTP_11, &headers(&[("x-app", "a")]), None)
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
        .capture(Version::HTTP_11, &headers(&[("Host", "a")]), None)
        .unwrap();
    let mut duplicated = host;
    let mut fields = duplicated.fields.to_vec();
    let mut duplicate = fields[0].clone();
    duplicate.occurrence = 1;
    fields.push(duplicate);
    duplicated.fields = fields.into();
    duplicated.canonical(&policy).unwrap_err();
    let mut framing = policy
        .capture(Version::HTTP_11, &headers(&[("Content-Length", "1")]), None)
        .unwrap();
    let transfer = policy
        .capture(
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
            .capture(Version::HTTP_11, &headers(&[(name, "close")]), None)
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
            .capture(Version::HTTP_3, &input, Some(&[valid]))
            .unwrap();
        let value = captured.canonical(&policy).unwrap();
        HeaderCapture::from_canonical(&value, &policy).unwrap();
        for version in [Version::HTTP_11, Version::HTTP_2] {
            policy.capture(version, &input, Some(&[valid])).unwrap_err();
            let mut wrong_version = captured.clone();
            wrong_version.version = version;
            wrong_version.canonical(&policy).unwrap_err();
        }
        let mut invalid = valid;
        invalid.index = if valid.index.is_some() { None } else { Some(0) };
        policy
            .capture(Version::HTTP_3, &input, Some(&[invalid]))
            .unwrap_err();
        let mut forged = captured.clone();
        forged.fields[0].representation = Some(invalid);
        forged.canonical(&policy).unwrap_err();
        if kind != FieldRepresentation::LiteralName {
            invalid = valid;
            invalid.name_huffman = true;
            policy
                .capture(Version::HTTP_3, &input, Some(&[invalid]))
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
                    .capture(Version::HTTP_3, &input, Some(&[invalid]))
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
        .capture(Version::HTTP_3, &input, Some(&[representation]))
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
        .capture(Version::HTTP_3, &input, Some(&[representation]))
        .unwrap_err();
}
