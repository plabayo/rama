use rama_utils::octets::kib_u64;

use super::*;
use crate::profile::{
    CountedObservationBucket, HeaderCapturePolicy, ObservationId, ProfileBucketLimits,
};
use rama_http::{HeaderMap, HeaderValue, Version};

fn order_slot(kind: CapturedSlotKind, fields: &[(u64, &[u8])]) -> CapturedSlot {
    let limits = OrderCaptureLimits::default();
    CapturedSlot {
        kind,
        value: OrderedProtocolCapture::capture(
            kind.namespace().unwrap(),
            fields.iter().copied(),
            limits,
        )
        .unwrap()
        .canonical(limits)
        .unwrap(),
    }
}
fn headers() -> CapturedSlot {
    let mut headers = HeaderMap::new();
    headers.insert("cookie", HeaderValue::from_static("private-cookie"));
    headers.insert("accept", HeaderValue::from_static("text/html"));
    let policy = HeaderCapturePolicy::default();
    CapturedSlot {
        kind: CapturedSlotKind::Headers,
        value: policy
            .capture(Version::HTTP_11, &headers, None)
            .unwrap()
            .canonical(&policy)
            .unwrap(),
    }
}

#[test]
fn complete_joint_samples_preserve_correlated_orders_with_varying_reserved_values() {
    let limits = JointCaptureLimits::default();
    let bucket_limits = ProfileBucketLimits {
        literal_values: 8,
        samples: 64,
        ..ProfileBucketLimits::default()
    };
    let mut bucket =
        CountedObservationBucket::new(JOINT_DOMAIN, ValueId([1; 32]), [2; 32], bucket_limits);
    let mut structure = None;
    let zero = 0u64.to_be_bytes();
    let size = kib_u64(8).to_be_bytes();
    for sequence in 1..=10_000u64 {
        let grease = sequence.to_be_bytes();
        let mut tp = vec![(1, b"a".as_slice()), (4, b"b".as_slice())];
        let mut h3 = vec![(1, zero.as_slice()), (6, size.as_slice())];
        if sequence % 2 == 1 {
            tp.reverse();
            h3.reverse();
        }
        tp.insert(
            sequence as usize % 3,
            (31 * sequence + 27, grease.as_slice()),
        );
        let mut slots = vec![
            order_slot(CapturedSlotKind::QuicParameters, &tp),
            order_slot(CapturedSlotKind::Http3Settings, &h3),
        ];
        if sequence % 3 == 0 {
            slots.reverse();
        }
        let joint = JointCapture {
            level: CaptureLevel::Connection,
            slots: slots.into(),
        };
        let canonical = joint.canonical(limits).unwrap();
        let key = joint.structural(limits).unwrap();
        validate_joint_structure(&key, limits.bytes).unwrap();
        assert_eq!(*structure.get_or_insert(key.id), key.id);
        bucket
            .observe(
                ObservationId {
                    run: [3; 16],
                    sequence,
                },
                &canonical,
            )
            .unwrap();
    }
    let snapshot = bucket.snapshot();
    assert_eq!(snapshot.counts.total, 10_000);
    assert_eq!(snapshot.samples.len(), 64);
    assert!(snapshot.values.len() <= 72);
    let restored =
        CountedObservationBucket::from_snapshot(&snapshot, [2; 32], bucket_limits).unwrap();
    for sample in restored.snapshot().samples {
        let canonical = snapshot
            .values
            .iter()
            .find(|value| value.id == sample.value)
            .unwrap();
        let joint = JointCapture::from_canonical(canonical, limits).unwrap();
        assert_eq!(joint.structural(limits).unwrap().id, structure.unwrap());
        let ids: Vec<Vec<u64>> = joint
            .slots
            .iter()
            .map(|slot| {
                let order = OrderedProtocolCapture::from_canonical(
                    &slot.value,
                    OrderCaptureLimits::default(),
                )
                .unwrap();
                order
                    .fields
                    .iter()
                    .filter(|field| !order.namespace.reserved_candidate(field.id))
                    .map(|field| field.id)
                    .collect()
            })
            .collect();
        assert!(
            matches!(ids.as_slice(), [a, x] if a == &[1,4] && x == &[1,6])
                || matches!(ids.as_slice(), [b, y] if b == &[4,1] && y == &[6,1])
        );
    }
}

#[test]
fn joint_import_revalidates_leaf_ownership_and_rejects_nested_tuples() {
    let limits = JointCaptureLimits::default();
    let request = JointCapture {
        level: CaptureLevel::Request,
        slots: vec![headers()].into(),
    };
    let canonical = request.canonical(limits).unwrap();
    assert!(
        !canonical
            .bytes
            .windows(14)
            .any(|bytes| bytes == b"private-cookie")
    );
    JointCapture::from_canonical(&canonical, limits).unwrap();
    // A leaf slot cannot contain another tuple, even with valid nested hashes.
    let nested = JointCapture {
        level: CaptureLevel::Connection,
        slots: vec![CapturedSlot {
            kind: CapturedSlotKind::QuicParameters,
            value: canonical,
        }]
        .into(),
    };
    nested.canonical(limits).unwrap_err();
    let mut leaf = CanonicalWriter::new(HEADER_DOMAIN, limits.value_bytes).unwrap();
    leaf.u8(2).unwrap();
    leaf.u64(1).unwrap();
    leaf.bytes(b"cookie").unwrap();
    leaf.u32(0).unwrap();
    leaf.u8(0).unwrap();
    leaf.u8(0).unwrap();
    leaf.u8(0).unwrap();
    leaf.bytes(b"private-cookie").unwrap();
    let leaf = leaf.finish();
    for domain in [JOINT_DOMAIN, JOINT_STRUCTURE_DOMAIN] {
        let mut writer = CanonicalWriter::new(domain, limits.bytes).unwrap();
        writer.u8(1).unwrap();
        writer.u64(1).unwrap();
        writer.u16(0).unwrap();
        writer.bytes(&leaf.bytes).unwrap();
        let forged = writer.finish();
        forged.verify(domain, limits.bytes).unwrap();
        let mut bucket = CountedObservationBucket::new(
            domain,
            ValueId([1; 32]),
            [2; 32],
            ProfileBucketLimits::default(),
        );
        bucket
            .observe(
                ObservationId {
                    run: [3; 16],
                    sequence: 1,
                },
                &forged,
            )
            .unwrap_err();
        assert_eq!(bucket.snapshot().counts.total, 0);
    }
}

#[test]
fn joint_level_namespace_duplicate_and_byte_guards_are_atomic() {
    let limits = JointCaptureLimits::default();
    let tp = order_slot(CapturedSlotKind::QuicParameters, &[(1, b"a")]);
    let mut joint = JointCapture {
        level: CaptureLevel::Connection,
        slots: vec![tp.clone()].into(),
    };
    let canonical = joint.canonical(limits).unwrap();
    joint
        .canonical(JointCaptureLimits { slots: 0, ..limits })
        .unwrap_err();
    joint
        .canonical(JointCaptureLimits {
            value_bytes: tp.value.bytes.len() - 1,
            ..limits
        })
        .unwrap_err();
    joint
        .canonical(JointCaptureLimits {
            bytes: canonical.bytes.len() - 1,
            ..limits
        })
        .unwrap_err();
    joint.level = CaptureLevel::Request;
    joint.canonical(limits).unwrap_err();
    joint.level = CaptureLevel::Connection;
    joint.slots = vec![headers()].into();
    joint.canonical(limits).unwrap_err();
    joint.slots = vec![tp.clone(), tp].into();
    joint.canonical(limits).unwrap_err();
    let mut wrong = order_slot(CapturedSlotKind::Http3Settings, &[(1, &0u64.to_be_bytes())]);
    wrong.kind = CapturedSlotKind::QuicParameters;
    joint.slots = vec![wrong].into();
    joint.canonical(limits).unwrap_err();
    let mut writer = CanonicalWriter::new(JOINT_DOMAIN, limits.bytes).unwrap();
    writer.u8(0).unwrap();
    writer.u64(2).unwrap();
    for slot in [
        order_slot(CapturedSlotKind::Http3Settings, &[(1, &0u64.to_be_bytes())]),
        order_slot(CapturedSlotKind::QuicParameters, &[(1, b"a")]),
    ] {
        writer.u16(slot.kind.tag()).unwrap();
        writer.bytes(&slot.value.bytes).unwrap();
    }
    JointCapture::from_canonical(&writer.finish(), limits).unwrap_err();
    let slot = order_slot(CapturedSlotKind::Http3Settings, &[(1, &0u64.to_be_bytes())]);
    let order_limits = OrderCaptureLimits::default();
    let structure = OrderedProtocolCapture::from_canonical(&slot.value, order_limits)
        .unwrap()
        .structural(order_limits)
        .unwrap();
    let mut writer = CanonicalWriter::new(JOINT_STRUCTURE_DOMAIN, limits.bytes).unwrap();
    writer.u8(0).unwrap();
    writer.u64(1).unwrap();
    writer.u16(CapturedSlotKind::QuicParameters.tag()).unwrap();
    writer.bytes(&structure.bytes).unwrap();
    validate_joint_structure(&writer.finish(), limits.bytes).unwrap_err();
}

#[test]
fn joint_canonical_identity_is_independent_of_input_component_order() {
    let limits = JointCaptureLimits::default();
    let joint = JointCapture {
        level: CaptureLevel::Connection,
        slots: vec![order_slot(
            CapturedSlotKind::QuicParameters,
            &[(1, b"\x0a"), (15, b"nonce")],
        )]
        .into(),
    };
    let canonical = joint.canonical(limits).unwrap();
    assert_eq!(canonical.bytes.len(), 97);
    assert_eq!(
        canonical.id.0,
        [
            239, 122, 117, 152, 71, 200, 108, 254, 182, 209, 236, 14, 219, 48, 62, 96, 86, 118,
            150, 25, 160, 95, 117, 231, 197, 111, 182, 22, 99, 91, 184, 147
        ]
    );
    let mut joint = JointCapture {
        level: CaptureLevel::Connection,
        slots: vec![
            order_slot(CapturedSlotKind::QuicVersions, &[(1, b"")]),
            joint.slots[0].clone(),
        ]
        .into(),
    };
    let id = joint.canonical(limits).unwrap().id;
    joint.slots.reverse();
    assert_eq!(joint.canonical(limits).unwrap().id, id);
    let structural = joint.structural(limits).unwrap();
    assert_ne!(structural.id, id);
    validate_joint_structure(&structural, limits.bytes).unwrap();
}
