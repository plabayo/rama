use std::cell::Cell;

use super::*;
use crate::profile::{CountedObservationBucket, ObservationId, ProfileBucketLimits, ValueId};

fn capture(namespace: OrderNamespace, fields: &[(u64, &[u8])]) -> OrderedProtocolCapture {
    OrderedProtocolCapture::capture(
        namespace,
        fields.iter().copied(),
        OrderCaptureLimits::default(),
    )
    .unwrap()
}

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
        namespace: OrderNamespace::QuicParameter,
        fields: vec![OrderedProtocolField {
            id: 0x0f,
            value: ProtocolValue::Literal(b"connection-secret".as_slice().into()),
        }]
        .into(),
    };
    malformed.canonical(limits).unwrap_err();
    let oversized_shape = OrderedProtocolCapture {
        namespace: OrderNamespace::QuicParameter,
        fields: vec![OrderedProtocolField {
            id: 0x0f,
            value: ProtocolValue::ConnectionLength(limits.bytes + 1),
        }]
        .into(),
    };
    oversized_shape.canonical(limits).unwrap_err();
    // A valid digest does not grant literal ownership to a connection-bound field.
    for domain in [ORDER_DOMAIN, ORDER_STRUCTURE_DOMAIN] {
        let mut writer = CanonicalWriter::new(domain, limits.bytes).unwrap();
        writer.u8(0).unwrap();
        writer.u64(1).unwrap();
        if domain == ORDER_STRUCTURE_DOMAIN {
            writer.u8(0).unwrap();
        }
        writer.u64(0x0f).unwrap();
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

#[test]
fn ten_thousand_orders_keep_one_structure_and_exact_total() {
    let limits = OrderCaptureLimits::default();
    let bucket_limits = ProfileBucketLimits {
        literal_values: 8,
        samples: 32,
        ..ProfileBucketLimits::default()
    };
    let mut structure = None;
    let mut bucket =
        CountedObservationBucket::new(ORDER_DOMAIN, ValueId([1; 32]), [2; 32], bucket_limits)
            .unwrap();
    for sequence in 1..=10_000u64 {
        let payload = sequence.to_be_bytes();
        let mut fields = vec![
            (1, b"\x0a".as_slice()),
            (4, b"\x10".as_slice()),
            (31 * sequence + 27, payload.as_slice()),
            (0xff02de1a, b"constant".as_slice()),
        ];
        fields.rotate_left(sequence as usize % 4);
        if sequence % 2 == 0 {
            fields.reverse();
        }
        let captured = capture(OrderNamespace::QuicParameter, &fields);
        let key = captured.structural(limits).unwrap();
        validate_structure(&key, limits.bytes).unwrap();
        assert_eq!(*structure.get_or_insert(key.id), key.id);
        let canonical = captured.canonical(limits).unwrap();
        // A constant 31N+27 value remains literal evidence even beside a varying candidate.
        let constant = captured
            .fields
            .iter()
            .find(|field| field.id == 0xff02de1a)
            .unwrap();
        assert!(
            matches!(&constant.value, ProtocolValue::Literal(bytes) if bytes.as_ref() == b"constant")
        );
        bucket
            .observe(
                ObservationId {
                    run: [1; 16],
                    sequence,
                },
                &canonical,
            )
            .unwrap();
    }
    let snapshot = bucket.snapshot();
    assert_eq!(snapshot.counts.total, 10_000);
    assert_eq!(snapshot.counts.values.len(), 8);
    assert_eq!(snapshot.samples.len(), 32);
    assert!(snapshot.values.len() <= 40);
    let restored = CountedObservationBucket::from_snapshot(
        &snapshot,
        ORDER_DOMAIN,
        ValueId([1; 32]),
        [2; 32],
        bucket_limits,
    )
    .unwrap();
    assert_eq!(
        serde_json::to_vec(&snapshot).unwrap(),
        serde_json::to_vec(&restored.snapshot()).unwrap()
    );
}

#[test]
fn structure_preserves_semantic_values_multiplicity_namespace_and_candidate_shape() {
    let limits = OrderCaptureLimits::default();
    let base = capture(
        OrderNamespace::QuicParameter,
        &[(0xff04de1b, b"\x01"), (27, b"x"), (1, b"v"), (1, b"v")],
    );
    let key = base.structural(limits).unwrap();
    for fields in [
        vec![
            (0xff04de1b, b"\x02".as_slice()),
            (27, b"x"),
            (1, b"v"),
            (1, b"v"),
        ],
        vec![
            (0xff04de1b, b"\x01".as_slice()),
            (27, b"xx"),
            (1, b"v"),
            (1, b"v"),
        ],
        vec![(0xff04de1b, b"\x01".as_slice()), (27, b"x"), (1, b"v")],
        vec![(0xff04de1b, b"\x01".as_slice()), (1, b"v"), (1, b"v")],
    ] {
        assert_ne!(
            key.id,
            capture(OrderNamespace::QuicParameter, &fields)
                .structural(limits)
                .unwrap()
                .id
        );
    }
    let one = 1u64.to_be_bytes();
    let a = capture(OrderNamespace::Http3Setting, &[(1, &one), (0x21, &one)]);
    let b = capture(OrderNamespace::Http3Setting, &[(0x40, &one), (1, &one)]);
    assert_eq!(
        a.structural(limits).unwrap().id,
        b.structural(limits).unwrap().id
    );
    assert_ne!(
        a.canonical(limits).unwrap().id,
        b.canonical(limits).unwrap().id
    );
    let a = capture(OrderNamespace::QuicVersion, &[(1, b""), (0x0a1a2a3a, b"")]);
    let b = capture(OrderNamespace::QuicVersion, &[(0x4a5a6a7a, b""), (1, b"")]);
    assert_eq!(
        a.structural(limits).unwrap().id,
        b.structural(limits).unwrap().id
    );
    assert_ne!(
        capture(OrderNamespace::QuicVersion, &[(1, b"")])
            .structural(limits)
            .unwrap()
            .id,
        capture(OrderNamespace::QuicParameter, &[(1, b"")])
            .structural(limits)
            .unwrap()
            .id
    );
}

#[test]
fn order_capture_rejects_oversized_fields_invalid_values_and_forged_structure() {
    let limits = OrderCaptureLimits::default();
    let visited = Cell::new(0);
    OrderedProtocolCapture::capture(
        OrderNamespace::QuicParameter,
        std::iter::from_fn(|| {
            visited.set(visited.get() + 1);
            Some((1, []))
        }),
        OrderCaptureLimits {
            elements: 2,
            ..limits
        },
    )
    .unwrap_err();
    assert_eq!(visited.get(), 3);
    let bound = vec![0; limits.bytes / 2];
    OrderedProtocolCapture::capture(
        OrderNamespace::QuicParameter,
        [(0, bound.as_slice()), (0x0f, bound.as_slice())],
        limits,
    )
    .unwrap_err();
    OrderedProtocolCapture::capture(
        OrderNamespace::QuicParameter,
        [(1, vec![0; limits.bytes + 1])],
        limits,
    )
    .unwrap_err();
    for id in [1 << 62, u64::MAX] {
        OrderedProtocolCapture::capture(OrderNamespace::QuicParameter, [(id, [])], limits)
            .unwrap_err();
        OrderedProtocolCapture::capture(
            OrderNamespace::Http3Setting,
            [(id, 0u64.to_be_bytes())],
            limits,
        )
        .unwrap_err();
    }
    OrderedProtocolCapture::capture(
        OrderNamespace::Http3Setting,
        [(1, (1u64 << 62).to_be_bytes())],
        limits,
    )
    .unwrap_err();
    OrderedProtocolCapture::capture(OrderNamespace::Http3Setting, [(1, [0; 7])], limits)
        .unwrap_err();
    OrderedProtocolCapture::capture(OrderNamespace::QuicVersion, [(1u64 << 32, [])], limits)
        .unwrap_err();
    OrderedProtocolCapture::capture(OrderNamespace::QuicVersion, [(1, [0])], limits).unwrap_err();
    let original = capture(OrderNamespace::QuicParameter, &[(1, b"value")])
        .canonical(limits)
        .unwrap();
    for length in 0..original.bytes.len() {
        let mut truncated = original.clone();
        truncated.bytes = truncated.bytes[..length].into();
        OrderedProtocolCapture::from_canonical(&truncated, limits).unwrap_err();
    }
    let mut writer = CanonicalWriter::new(ORDER_STRUCTURE_DOMAIN, limits.bytes).unwrap();
    writer.u8(0).unwrap();
    writer.u64(2).unwrap();
    for id in [4, 1] {
        writer.u8(0).unwrap();
        writer.u64(id).unwrap();
        writer.u8(0).unwrap();
        writer.bytes(b"v").unwrap();
    }
    validate_structure(&writer.finish(), limits.bytes).unwrap_err();
    let mut writer = CanonicalWriter::new(ORDER_STRUCTURE_DOMAIN, limits.bytes).unwrap();
    writer.u8(1).unwrap();
    writer.u64(1).unwrap();
    writer.u8(1).unwrap();
    writer.u64(7).unwrap();
    validate_structure(&writer.finish(), limits.bytes).unwrap_err();
    let mut writer = CanonicalWriter::new(ORDER_STRUCTURE_DOMAIN, limits.bytes).unwrap();
    writer.u8(2).unwrap();
    writer.u64(1).unwrap();
    writer.u8(1).unwrap();
    writer.u64(1).unwrap();
    validate_structure(&writer.finish(), limits.bytes).unwrap_err();
}

#[test]
fn protocol_order_has_fixed_canonical_bytes_and_digest() {
    let limits = OrderCaptureLimits::default();
    let canonical = capture(
        OrderNamespace::QuicParameter,
        &[(1, b"\x0a"), (15, b"nonce")],
    )
    .canonical(limits)
    .unwrap();
    assert_eq!(
        canonical.id.0,
        [
            106, 167, 243, 167, 165, 213, 142, 99, 21, 243, 54, 195, 114, 109, 23, 3, 65, 197, 151,
            241, 190, 145, 101, 81, 208, 34, 114, 172, 145, 244, 207, 32
        ]
    );
    assert_eq!(canonical.bytes.as_ref(), b"rama-profile\0\0\x01\0\x04\0\0\0\0\0\0\0\0\x02\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\x01\x0a\0\0\0\0\0\0\0\x0f\x01\0\0\0\0\0\0\0\x05");
    let decoded = OrderedProtocolCapture::from_canonical(&canonical, limits).unwrap();
    assert_eq!(decoded.canonical(limits).unwrap().bytes, canonical.bytes);
}
