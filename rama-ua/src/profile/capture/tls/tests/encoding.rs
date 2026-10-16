use super::*;

#[test]
fn incomplete_oversized_and_malformed_tls_sources_do_not_acquire_capture_data() {
    let good = hello(vec![opaque(51, vec![0, 5, 0, 29, 0, 1, 1])]);
    TlsCapture::capture(
        ProfileCaptureCompleteness::Incomplete,
        TlsCaptureTransport::Tcp,
        &good,
        TlsCaptureLimits::default(),
    )
    .unwrap_err();
    for limits in [
        TlsCaptureLimits {
            elements: 0,
            bytes: kib(64),
        },
        TlsCaptureLimits {
            elements: 256,
            bytes: 0,
        },
    ] {
        TlsCapture::capture(
            ProfileCaptureCompleteness::Complete,
            TlsCaptureTransport::Tcp,
            &good,
            limits,
        )
        .unwrap_err();
    }
    for extension in [
        opaque(51, vec![0, 1, 0]),
        opaque(51, vec![0, 4, 0, 29, 0, 0]),
        opaque(41, vec![0, 0, 0, 0]),
        opaque(0, b"private".to_vec()),
        opaque(65037, b"private".to_vec()),
    ] {
        TlsCapture::capture(
            ProfileCaptureCompleteness::Complete,
            TlsCaptureTransport::Tcp,
            &hello(vec![extension]),
            TlsCaptureLimits::default(),
        )
        .unwrap_err();
    }
    TlsCapture::capture(
        ProfileCaptureCompleteness::Complete,
        TlsCaptureTransport::Tcp,
        &hello(vec![opaque(21, vec![]), opaque(21, vec![])]),
        TlsCaptureLimits::default(),
    )
    .unwrap_err();
}

#[test]
fn nested_protocol_candidates_remain_literal_and_malformed_vectors_fail() {
    let captured = capture(&hello(vec![
        opaque(45, vec![3, 0, 11, 228]),
        opaque(50, vec![0, 4, 0x1a, 0x1a, 0x08, 0x04]),
    ]));
    assert!(
        matches!(&captured.extensions[0].value,TlsCapturedExtensionValue::U8List(values) if values.as_ref()==[0,11,228])
    );
    assert!(
        matches!(&captured.extensions[1].value,TlsCapturedExtensionValue::U16List(values) if values.as_ref()==[0x1a1a,0x0804])
    );
    for extension in [
        opaque(45, vec![0]),
        opaque(45, vec![2, 1]),
        opaque(50, vec![0, 0]),
        opaque(50, vec![0, 1, 1]),
        opaque(50, vec![0, 2, 8, 4, 0]),
        opaque(51, vec![0, 10, 0, 29, 0, 1, 1, 0, 29, 0, 1, 2]),
    ] {
        TlsCapture::capture(
            ProfileCaptureCompleteness::Complete,
            TlsCaptureTransport::Tcp,
            &hello(vec![extension]),
            TlsCaptureLimits::default(),
        )
        .unwrap_err();
    }
}

#[test]
fn tls_canonical_roundtrip_preserves_shapes_and_rejects_literal_secret_imports() {
    let limits = TlsCaptureLimits::default();
    let observed = capture(&hello(vec![
        opaque(35, b"private-canary".to_vec()),
        opaque(45, vec![2, 1, 11]),
    ]));
    let canonical = observed.canonical(limits).unwrap();
    assert!(
        !canonical
            .bytes
            .windows(b"private-canary".len())
            .any(|bytes| bytes == b"private-canary")
    );
    assert_eq!(
        serde_json::to_string(&TlsCapture::from_canonical(&canonical, limits).unwrap()).unwrap(),
        serde_json::to_string(&observed).unwrap()
    );
    for id in [
        0, 2, 3, 5, 6, 7, 8, 12, 17, 25, 29, 30, 31, 32, 33, 35, 36, 37, 38, 41, 44, 47, 48, 51,
        54, 55, 56, 57, 59, 51764, 65037, 65281,
    ] {
        let mut invalid = capture(&hello(vec![]));
        invalid.extensions = vec![TlsCapturedExtension {
            id,
            value: TlsCapturedExtensionValue::Literal(Box::from(*b"private-canary")),
        }]
        .into();
        invalid.canonical(limits).unwrap_err();
    }
}

#[test]
fn tls_extension_wire_lengths_include_vector_and_entry_overhead() {
    let limits = TlsCaptureLimits {
        elements: 100_000,
        bytes: kib(256),
    };
    let mut capture = TlsCapture {
        completeness: ProfileCaptureCompleteness::Complete,
        transport: TlsCaptureTransport::Tcp,
        protocol_version: 0x0303,
        ciphers: Box::new([0x1301]),
        compression: Box::new([0]),
        extensions: Box::default(),
    };
    for extension in [
        TlsCapturedExtension {
            id: 65037,
            value: TlsCapturedExtensionValue::EchOuter {
                kdf: 1,
                aead: 1,
                enc: 0,
                payload: u16::MAX,
            },
        },
        TlsCapturedExtension {
            id: 51,
            value: TlsCapturedExtensionValue::KeyShares(Box::new([TlsKeyShareShape {
                group: 29,
                length: u16::MAX - 4,
            }])),
        },
        TlsCapturedExtension {
            id: 41,
            value: TlsCapturedExtensionValue::PreSharedKeys {
                identities: Box::new([u16::MAX - 6]),
                binders: Box::new([32]),
            },
        },
    ] {
        capture.extensions = Box::new([extension]);
        capture.canonical(limits).unwrap_err();
    }
    capture.extensions = Box::new([
        TlsCapturedExtension {
            id: 100,
            value: TlsCapturedExtensionValue::Literal(vec![0; 32764].into()),
        },
        TlsCapturedExtension {
            id: 101,
            value: TlsCapturedExtensionValue::Literal(vec![0; 32764].into()),
        },
    ]);
    capture.canonical(limits).unwrap_err();
    if let TlsCapturedExtensionValue::Literal(bytes) = &mut capture.extensions[1].value {
        *bytes = vec![0; 32763].into();
    }
    capture.canonical(limits).unwrap();
}

#[test]
fn psk_and_key_share_nested_lengths_and_order_are_enforced() {
    let limits = TlsCaptureLimits::default();
    let mut psk = vec![0, 7, 0, 1, 42, 0, 0, 0, 1, 0, 33, 32];
    psk.extend_from_slice(&[7; 32]);
    let shares = vec![0, 5, 0, 29, 0, 1, 42];
    for (id, data) in [(41, &psk), (51, &shares)] {
        capture(&hello(vec![opaque(id, data.clone())]));
        for end in 0..data.len() {
            TlsCapture::capture(
                ProfileCaptureCompleteness::Complete,
                TlsCaptureTransport::Tcp,
                &hello(vec![opaque(id, data[..end].to_vec())]),
                limits,
            )
            .unwrap_err();
        }
    }
    TlsCapture::capture(
        ProfileCaptureCompleteness::Complete,
        TlsCaptureTransport::Tcp,
        &hello(vec![opaque(41, psk), opaque(21, vec![])]),
        limits,
    )
    .unwrap_err();
    let mut value = capture(&hello(vec![]));
    for extension in [
        TlsCapturedExtension {
            id: 51,
            value: TlsCapturedExtensionValue::KeyShares(Box::new([TlsKeyShareShape {
                group: 29,
                length: 0,
            }])),
        },
        TlsCapturedExtension {
            id: 51,
            value: TlsCapturedExtensionValue::KeyShares(Box::new([
                TlsKeyShareShape {
                    group: 29,
                    length: 1,
                },
                TlsKeyShareShape {
                    group: 29,
                    length: 1,
                },
            ])),
        },
        TlsCapturedExtension {
            id: 41,
            value: TlsCapturedExtensionValue::PreSharedKeys {
                identities: Box::new([1]),
                binders: Box::new([31]),
            },
        },
        TlsCapturedExtension {
            id: 41,
            value: TlsCapturedExtensionValue::PreSharedKeys {
                identities: Box::new([1, 1]),
                binders: Box::new([32]),
            },
        },
        TlsCapturedExtension {
            id: 16,
            value: TlsCapturedExtensionValue::Protocols(Box::new([Box::default()])),
        },
        TlsCapturedExtension {
            id: 21,
            value: TlsCapturedExtensionValue::Literal(Box::new([1])),
        },
        TlsCapturedExtension {
            id: 42,
            value: TlsCapturedExtensionValue::Literal(Box::new([1])),
        },
    ] {
        value.extensions = Box::new([extension]);
        value.canonical(limits).unwrap_err();
    }
    value.extensions = Box::default();
    value.completeness = ProfileCaptureCompleteness::Incomplete;
    value.canonical(limits).unwrap_err();
    value.structural(limits).unwrap_err();
}

#[test]
fn historical_secret_extensions_never_retain_literal_values_or_connection_lengths_in_keys() {
    let limits = TlsCaptureLimits::default();
    for id in [
        40, 53, 0xffce, 0xffa5, 0xfe08, 0xfe09, 0xfe0a, 0xfe0b, 0xfe0c,
    ] {
        let first = capture(&hello(vec![opaque(id, b"private-canary".to_vec())]));
        let other = capture(&hello(vec![opaque(
            id,
            b"different-private-secret".to_vec(),
        )]));
        let encoded = first.canonical(limits).unwrap();
        assert!(!encoded.bytes.windows(7).any(|bytes| bytes == b"private"));
        assert_eq!(
            first.structural(limits).unwrap().id,
            other.structural(limits).unwrap().id
        );
        let mut forged = first;
        forged.extensions[0].value =
            TlsCapturedExtensionValue::Literal(b"private-canary".as_slice().into());
        forged.canonical(limits).unwrap_err();
    }
}

#[test]
fn canonical_tls_budgets_charge_retained_shapes_not_discarded_payloads() {
    for extension in [
        TlsCapturedExtension {
            id: 51,
            value: TlsCapturedExtensionValue::KeyShares(Box::new([TlsKeyShareShape {
                group: 0x1234,
                length: 4096,
            }])),
        },
        TlsCapturedExtension {
            id: 41,
            value: TlsCapturedExtensionValue::PreSharedKeys {
                identities: Box::new([1000]),
                binders: Box::new([255]),
            },
        },
        TlsCapturedExtension {
            id: 65037,
            value: TlsCapturedExtensionValue::EchOuter {
                kdf: 1,
                aead: 1,
                enc: 512,
                payload: 2048,
            },
        },
        TlsCapturedExtension {
            id: 35,
            value: TlsCapturedExtensionValue::ConnectionLength(4096),
        },
    ] {
        let capture = TlsCapture {
            completeness: ProfileCaptureCompleteness::Complete,
            transport: TlsCaptureTransport::Quic,
            protocol_version: 0x0303,
            ciphers: Box::new([0x1301]),
            compression: Box::new([0]),
            extensions: Box::new([extension]),
        };
        let value = capture.canonical(TlsCaptureLimits::default()).unwrap();
        let size = value.bytes.len();
        let limits = TlsCaptureLimits {
            bytes: size,
            ..TlsCaptureLimits::default()
        };
        assert_eq!(capture.canonical(limits).unwrap().id, value.id);
        TlsCapture::from_canonical(&value, limits).unwrap();
        value.validated_domain(size).unwrap();
        let mut bucket = CountedObservationBucket::new(
            CanonicalDomain::Tls,
            ValueId([1; 32]),
            [2; 32],
            ProfileBucketLimits {
                literal_values: 1,
                samples: 1,
                value_bytes: size,
                input_bytes: size,
                retained_bytes: size,
            },
        )
        .unwrap();
        bucket
            .observe(
                ObservationId {
                    run: [3; 16],
                    sequence: 1,
                },
                &value,
            )
            .unwrap();
        assert_eq!(bucket.snapshot().counts.total, 1);
        capture
            .canonical(TlsCaptureLimits {
                bytes: size - 1,
                ..limits
            })
            .unwrap_err();
    }
}
