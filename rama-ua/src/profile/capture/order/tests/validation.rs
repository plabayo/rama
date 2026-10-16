use super::*;

#[test]
fn protocol_bindings_do_not_retain_connection_identifiers_or_tokens() {
    let limits = OrderCaptureLimits::default();
    let mut first = None;
    for sequence in 0..1000 {
        let secret = format!("nonce-{sequence:010}");
        let captured = capture(
            OrderNamespace::QuicParameter,
            &[
                (0, secret.as_bytes()),
                (2, secret.as_bytes()),
                (0x0d, secret.as_bytes()),
                (0x0f, secret.as_bytes()),
                (0x10, secret.as_bytes()),
                (0x26ab, secret.as_bytes()),
                (0x4751, secret.as_bytes()),
                (0x219bbcd0, secret.as_bytes()),
            ],
        );
        let canonical = captured.canonical(limits).unwrap();
        assert!(!canonical.bytes.windows(6).any(|part| part == b"nonce-"));
        assert!(
            captured
                .fields
                .iter()
                .all(|field| matches!(field.value, ProtocolValue::ConnectionLength(16)))
        );
        assert_eq!(*first.get_or_insert(canonical.id), canonical.id);
    }
    let malformed = OrderedProtocolCapture {
        completeness: ProfileCaptureCompleteness::Complete,
        namespace: OrderNamespace::QuicParameter,
        fields: vec![OrderedProtocolField {
            id: 0x0f,
            value: ProtocolValue::Literal(b"connection-secret".as_slice().into()),
        }]
        .into(),
    };
    malformed.canonical(limits).unwrap_err();
    let oversized_shape = OrderedProtocolCapture {
        completeness: ProfileCaptureCompleteness::Complete,
        namespace: OrderNamespace::QuicParameter,
        fields: vec![OrderedProtocolField {
            id: 0x0f,
            value: ProtocolValue::ConnectionLength(usize::from(u16::MAX) + 1),
        }]
        .into(),
    };
    oversized_shape.canonical(limits).unwrap_err();
    // A valid digest does not grant literal ownership to a connection-bound field.
    for id in [0x0f, 0x26ab, 0x4751, 0x219bbcd0] {
        for domain in [ORDER_DOMAIN, ORDER_STRUCTURE_DOMAIN] {
            let mut writer = CanonicalWriter::new(domain, limits.bytes).unwrap();
            writer.u8(0).unwrap();
            if domain == ORDER_DOMAIN {
                writer.u8(1).unwrap();
            }
            writer.u64(1).unwrap();
            if domain == ORDER_STRUCTURE_DOMAIN {
                writer.u8(0).unwrap();
            }
            writer.u64(id).unwrap();
            writer.u8(0).unwrap();
            writer.bytes(b"connection-secret").unwrap();
            let forged = writer.finish();
            forged.verify(domain, limits.bytes).unwrap();
            let mut bucket = CountedObservationBucket::new(
                domain,
                ValueId([1; 32]),
                [2; 32],
                ProfileBucketLimits::default(),
            )
            .unwrap();
            bucket
                .observe(
                    ObservationId {
                        run: [1; 16],
                        sequence: 1,
                    },
                    &forged,
                )
                .unwrap_err();
            assert_eq!(bucket.snapshot().counts.total, 0);
        }
    }
}

#[test]
fn nested_versions_retain_semantics_and_reject_malformed_values() {
    let limits = OrderCaptureLimits::default();
    for bytes in [
        vec![],
        vec![0; 3],
        vec![0; 4],
        vec![0, 0, 0, 1],
        vec![0, 0, 0, 1, 0, 0, 0, 0],
        vec![0, 0, 0, 1, 0, 0, 0, 2],
        vec![0, 0, 0, 1, 0],
    ] {
        OrderedProtocolCapture::capture(
            ProfileCaptureCompleteness::Complete,
            OrderNamespace::QuicParameter,
            [(0x11, bytes)],
            limits,
        )
        .unwrap_err();
    }
    let mut first = Vec::new();
    VersionInformation::new(Version::V1, vec![Version::V1, Version::V2]).write(&mut first);
    let mut other = Vec::new();
    VersionInformation::new(Version::V1, vec![Version::V1, Version::from_u32(7)]).write(&mut other);
    let mut reversed = Vec::new();
    VersionInformation::new(Version::V1, vec![Version::V2, Version::V1]).write(&mut reversed);
    let reversed = capture(OrderNamespace::QuicParameter, &[(0x11, &reversed)]);
    let first = capture(OrderNamespace::QuicParameter, &[(0x11, &first)]);
    assert_ne!(
        first.structural(limits).unwrap().id,
        reversed.structural(limits).unwrap().id
    );

    let other = capture(OrderNamespace::QuicParameter, &[(0x11, &other)]);
    assert_ne!(
        first.structural(limits).unwrap().id,
        other.structural(limits).unwrap().id
    );
    first
        .canonical(OrderCaptureLimits {
            elements: 1,
            ..limits
        })
        .unwrap_err();
}

#[test]
fn redacted_transport_shape_uses_encoded_budget_without_recharging_wire_bytes() {
    let limits = OrderCaptureLimits::default();
    let mut preferred = [0_u8; 61];
    preferred[24] = 20;
    let capture = capture(OrderNamespace::QuicParameter, &[(0x0d, &preferred)]);
    let value = capture.canonical(limits).unwrap();
    assert!(value.bytes.len() < preferred.len());
    let exact = OrderCaptureLimits {
        bytes: value.bytes.len(),
        ..limits
    };
    capture.canonical(exact).unwrap();
    OrderedProtocolCapture::from_canonical(&value, exact).unwrap();
    value.validated_domain(value.bytes.len()).unwrap();
    OrderedProtocolCapture::capture(
        ProfileCaptureCompleteness::Complete,
        OrderNamespace::QuicParameter,
        [(0x0d, preferred)],
        exact,
    )
    .unwrap_err();
}
