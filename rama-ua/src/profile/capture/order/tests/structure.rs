use super::*;

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
fn structure_preserves_semantic_values_multiplicity_and_namespace() {
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
        ProfileCaptureCompleteness::Complete,
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
        ProfileCaptureCompleteness::Complete,
        OrderNamespace::QuicParameter,
        [(0, bound.as_slice()), (0x0f, bound.as_slice())],
        limits,
    )
    .unwrap_err();
    OrderedProtocolCapture::capture(
        ProfileCaptureCompleteness::Complete,
        OrderNamespace::QuicParameter,
        [(1, vec![0; limits.bytes + 1])],
        limits,
    )
    .unwrap_err();
    for id in [1 << 62, u64::MAX] {
        OrderedProtocolCapture::capture(
            ProfileCaptureCompleteness::Complete,
            OrderNamespace::QuicParameter,
            [(id, [])],
            limits,
        )
        .unwrap_err();
        OrderedProtocolCapture::capture(
            ProfileCaptureCompleteness::Complete,
            OrderNamespace::Http3Setting,
            [(id, 0u64.to_be_bytes())],
            limits,
        )
        .unwrap_err();
    }
    OrderedProtocolCapture::capture(
        ProfileCaptureCompleteness::Complete,
        OrderNamespace::Http3Setting,
        [(1, (1u64 << 62).to_be_bytes())],
        limits,
    )
    .unwrap_err();
    OrderedProtocolCapture::capture(
        ProfileCaptureCompleteness::Complete,
        OrderNamespace::Http3Setting,
        [(1, [0; 7])],
        limits,
    )
    .unwrap_err();
    OrderedProtocolCapture::capture(
        ProfileCaptureCompleteness::Complete,
        OrderNamespace::QuicVersion,
        [(1u64 << 32, [])],
        limits,
    )
    .unwrap_err();
    OrderedProtocolCapture::capture(
        ProfileCaptureCompleteness::Complete,
        OrderNamespace::QuicVersion,
        [(1, [0])],
        limits,
    )
    .unwrap_err();
    let original = capture(OrderNamespace::QuicParameter, &[(1, b"value")])
        .canonical(limits)
        .unwrap();
    for length in 0..original.bytes.len() {
        let mut truncated = original.clone();
        truncated.bytes = truncated.bytes.slice(..length);
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
fn ten_thousand_reserved_lengths_and_nested_versions_share_one_quic_structure() {
    let limits = OrderCaptureLimits::default();
    let mut key = None;
    let mut bucket = CountedObservationBucket::new(
        ORDER_DOMAIN,
        ValueId([7; 32]),
        [8; 32],
        ProfileBucketLimits::default(),
    )
    .unwrap();
    for sequence in 1..=10_000u64 {
        let reserved = 0x0a0a0a0a
            | (((sequence as u32) & 0xf) << 28)
            | ((((sequence as u32) >> 4) & 0xf) << 20);
        let mut versions = vec![Version::V1, Version::V2];
        versions.insert(sequence as usize % 3, Version::from_u32(reserved));
        let mut bytes = Vec::new();
        VersionInformation::new(Version::V1, versions).write(&mut bytes);
        let random = vec![sequence as u8; sequence as usize % 17];
        let connection = vec![b'c'; 8 + sequence as usize % 13];
        let mut fields = vec![
            (0x11, bytes.as_slice()),
            (31 * sequence + 27, random.as_slice()),
            (0x0f, connection.as_slice()),
            (1, b"choice"),
        ];
        fields.rotate_left(sequence as usize % 4);
        let captured = capture(OrderNamespace::QuicParameter, &fields);
        let structure = captured.structural(limits).unwrap();
        assert_eq!(*key.get_or_insert(structure.id), structure.id);
        validate_structure(&structure, limits.bytes).unwrap();
        let value = captured.canonical(limits).unwrap();
        bucket
            .observe(
                ObservationId {
                    run: [9; 16],
                    sequence,
                },
                &value,
            )
            .unwrap();
    }
    let snapshot = bucket.snapshot();
    assert_eq!(snapshot.counts.total, 10_000);
    assert!(snapshot.values.len() <= 272);
    for value in snapshot.values.iter() {
        OrderedProtocolCapture::from_canonical(value, limits).unwrap();
    }
}

#[test]
fn connection_parameter_values_do_not_multiply_structures() {
    let limits = OrderCaptureLimits::default();
    for id in [0x3127, 0x173e] {
        let first = capture(OrderNamespace::QuicParameter, &[(id, b"\x42\xf9")]);
        let other = capture(OrderNamespace::QuicParameter, &[(id, b"\x42\xb7")]);
        let wider = capture(OrderNamespace::QuicParameter, &[(id, b"\x80\x00\xff\xff")]);
        let structure = first.structural(limits).unwrap();
        validate_structure(&structure, limits.bytes).unwrap();
        for value in [&other, &wider] {
            assert_eq!(structure.id, value.structural(limits).unwrap().id);
            assert_ne!(
                first.canonical(limits).unwrap().id,
                value.canonical(limits).unwrap().id
            );
        }
        assert_ne!(
            structure.id,
            capture(OrderNamespace::QuicParameter, &[])
                .structural(limits)
                .unwrap()
                .id
        );
        assert_ne!(
            structure.id,
            capture(OrderNamespace::QuicParameter, &[(id, b"x"), (id, b"y")])
                .structural(limits)
                .unwrap()
                .id
        );
        assert!(
            matches!(&first.fields[0].value, ProtocolValue::Literal(bytes) if bytes.as_ref() == b"\x42\xf9")
        );
        // A canonical digest cannot disguise an unnormalized structural value.
        let mut writer = CanonicalWriter::new(ORDER_STRUCTURE_DOMAIN, limits.bytes).unwrap();
        writer.u8(OrderNamespace::QuicParameter.tag()).unwrap();
        writer.u64(1).unwrap();
        writer.u8(0).unwrap();
        writer.u64(id).unwrap();
        writer.u8(0).unwrap();
        writer.bytes(b"\x42\xf9").unwrap();
        validate_structure(&writer.finish(), limits.bytes).unwrap_err();
    }
    // Measured/padding ownership is specific to QUIC, not the numeric id alone.
    for id in [0x3127, 0x173e, 0x3128, 0xff04de1b, 0x219e, 0x17f7586d2cb571] {
        let a = capture(OrderNamespace::Http3Setting, &[(id, &1u64.to_be_bytes())]);
        let b = capture(OrderNamespace::Http3Setting, &[(id, &2u64.to_be_bytes())]);
        if !OrderNamespace::Http3Setting.reserved_candidate(id) {
            assert_ne!(
                a.structural(limits).unwrap().id,
                b.structural(limits).unwrap().id
            );
        }
    }
    for id in [0x3128, 0xff04de1b, 0x219e, 0x17f7586d2cb571, 0x1234] {
        let a = capture(OrderNamespace::QuicParameter, &[(id, b"a")]);
        let b = capture(OrderNamespace::QuicParameter, &[(id, b"b")]);
        assert_ne!(
            a.structural(limits).unwrap().id,
            b.structural(limits).unwrap().id
        );
    }
}

#[test]
fn chrome_repeat_visits_keep_rtt_presence_without_splitting_by_measurement() {
    // Task-owned Chrome 154 loopback captures: first and repeat visits from two
    // independent browser profiles. The repeat visits report 761 and 695 us.
    let limits = OrderCaptureLimits::default();
    let samples: Vec<Vec<(u64, Vec<u8>)>> =
        serde_json::from_str(include_str!("fixtures/chrome_repeat_parameters.json")).unwrap();
    assert_eq!(samples.len(), 4);
    let captures: Vec<_> = samples
        .iter()
        .map(|sample| {
            OrderedProtocolCapture::capture(
                ProfileCaptureCompleteness::Complete,
                OrderNamespace::QuicParameter,
                sample.iter().map(|(id, value)| (*id, value)),
                limits,
            )
            .unwrap()
        })
        .collect();
    assert_eq!(
        captures[0].structural(limits).unwrap().id,
        captures[2].structural(limits).unwrap().id
    );
    assert_eq!(
        captures[1].structural(limits).unwrap().id,
        captures[3].structural(limits).unwrap().id
    );
    assert_ne!(
        captures[0].structural(limits).unwrap().id,
        captures[1].structural(limits).unwrap().id
    );
    assert_ne!(
        captures[1].canonical(limits).unwrap().id,
        captures[3].canonical(limits).unwrap().id
    );
    let joint_limits = JointCaptureLimits::default();
    let joints: Vec<_> = captures
        .iter()
        .map(|capture| JointCapture {
            completeness: ProfileCaptureCompleteness::Complete,
            level: CaptureLevel::Connection,
            slots: vec![CapturedSlot {
                kind: CapturedSlotKind::QuicParameters,
                value: capture.canonical(limits).unwrap(),
            }]
            .into(),
        })
        .collect();
    assert_eq!(
        joints[0].structural(joint_limits).unwrap().id,
        joints[2].structural(joint_limits).unwrap().id
    );
    assert_eq!(
        joints[1].structural(joint_limits).unwrap().id,
        joints[3].structural(joint_limits).unwrap().id
    );
    assert_ne!(
        joints[0].structural(joint_limits).unwrap().id,
        joints[1].structural(joint_limits).unwrap().id
    );
    assert_ne!(
        joints[1].canonical(joint_limits).unwrap().id,
        joints[3].canonical(joint_limits).unwrap().id
    );
    for capture in captures {
        let value = capture.canonical(limits).unwrap();
        assert_eq!(
            OrderedProtocolCapture::from_canonical(&value, limits)
                .unwrap()
                .canonical(limits)
                .unwrap()
                .bytes,
            value.bytes
        );
    }
}
