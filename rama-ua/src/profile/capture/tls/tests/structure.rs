use super::*;

#[test]
fn tls_structure_bounds_ten_thousand_orders_without_changing_samples() {
    let limits = TlsCaptureLimits::default();
    let mut structure = None;
    let mut raw_ids = BTreeSet::new();
    let mut bucket = None;
    let mut state = 1u64;
    for sequence in 1..=10_000u64 {
        let grease = 0x0a0a + 0x1010 * (sequence % 16) as u16;
        let mut extensions: Vec<_> = (100..112)
            .map(|id| TlsCapturedExtension {
                id,
                value: TlsCapturedExtensionValue::Literal(Box::new([1, 2, 3])),
            })
            .collect();
        extensions.push(TlsCapturedExtension {
            id: grease,
            value: TlsCapturedExtensionValue::Literal(
                vec![sequence as u8; (sequence % 31) as usize].into(),
            ),
        });
        extensions.push(TlsCapturedExtension {
            id: 10,
            value: TlsCapturedExtensionValue::U16List(Box::new([grease, 29, 23])),
        });
        extensions.push(TlsCapturedExtension {
            id: 51,
            value: TlsCapturedExtensionValue::KeyShares(Box::new([
                TlsKeyShareShape {
                    group: grease,
                    length: (sequence % 31 + 1) as u16,
                },
                TlsKeyShareShape {
                    group: 29,
                    length: 32,
                },
            ])),
        });
        for index in (1..extensions.len()).rev() {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            extensions.swap(index, (state % (index as u64 + 1)) as usize);
        }
        let capture = TlsCapture {
            completeness: ProfileCaptureCompleteness::Complete,
            transport: TlsCaptureTransport::Tcp,
            protocol_version: 0x0303,
            ciphers: Box::new([grease, 0x1301, 0x1302]),
            compression: Box::new([0]),
            extensions: extensions.into(),
        };
        let raw = capture.canonical(limits).unwrap();
        let key = capture.structural(limits).unwrap();
        key.validated_domain(limits.bytes).unwrap();
        assert_eq!(*structure.get_or_insert(key.id), key.id);
        raw_ids.insert(raw.id);
        let bucket = bucket.get_or_insert_with(|| {
            CountedObservationBucket::new(
                CanonicalDomain::Tls,
                key.id,
                [7; 32],
                ProfileBucketLimits {
                    literal_values: 2,
                    samples: 4,
                    ..ProfileBucketLimits::default()
                },
            )
            .unwrap()
        });
        bucket
            .observe(
                ObservationId {
                    run: [1; 16],
                    sequence,
                },
                &raw,
            )
            .unwrap();
        assert!(bucket.snapshot().values.len() <= 6);
    }
    assert!(raw_ids.len() > 9_000);
    let snapshot = bucket.unwrap().snapshot();
    assert_eq!(snapshot.counts.total, 10_000);
    assert_eq!(snapshot.samples.len(), 4);
    for value in snapshot.values {
        assert!(raw_ids.contains(&value.id));
        let capture = TlsCapture::from_canonical(&value, limits).unwrap();
        assert_eq!(capture.extensions.len(), 15);
        assert_eq!(capture.structural(limits).unwrap().id, structure.unwrap());
    }
}

#[test]
fn tls_structure_preserves_multiplicity_semantics_and_unknown_values() {
    let limits = TlsCaptureLimits::default();
    let mut capture = TlsCapture {
        completeness: ProfileCaptureCompleteness::Complete,
        transport: TlsCaptureTransport::Tcp,
        protocol_version: 0x0303,
        ciphers: Box::new([0x0a0a, 0x1301]),
        compression: Box::new([0]),
        extensions: vec![
            TlsCapturedExtension {
                id: 0x1a1a,
                value: TlsCapturedExtensionValue::Literal(Box::new([1])),
            },
            TlsCapturedExtension {
                id: 0x2a2a,
                value: TlsCapturedExtensionValue::Literal(Box::new([2])),
            },
            TlsCapturedExtension {
                id: 16,
                value: TlsCapturedExtensionValue::Protocols(
                    vec![Box::from(b"h2".as_slice()), Box::from([0x3a, 0x3a])].into(),
                ),
            },
            TlsCapturedExtension {
                id: 45,
                value: TlsCapturedExtensionValue::U8List(Box::new([1, 0x2a])),
            },
            TlsCapturedExtension {
                id: u16::from(ExtensionId::SUPPORTED_GROUPS),
                value: TlsCapturedExtensionValue::U16List(Box::new([29, 0x3a3a])),
            },
            TlsCapturedExtension {
                id: u16::from(ExtensionId::SIGNATURE_ALGORITHMS),
                value: TlsCapturedExtensionValue::U16List(Box::new([0x0804, 0x4a4a])),
            },
            TlsCapturedExtension {
                id: u16::from(ExtensionId::SUPPORTED_VERSIONS),
                value: TlsCapturedExtensionValue::U16List(Box::new([0x0304, 0x5a5a])),
            },
        ]
        .into(),
    };
    let original = capture.structural(limits).unwrap();

    let mut equivalent = capture.clone();
    equivalent.ciphers[0] = 0xfafa;
    equivalent.extensions[0].id = 0x3a3a;
    equivalent.extensions[1].id = 0x4a4a;
    equivalent.extensions[2].value = TlsCapturedExtensionValue::Protocols(
        vec![Box::from(b"h2".as_slice()), Box::from([0xfa, 0xfa])].into(),
    );
    equivalent.extensions[3].value = TlsCapturedExtensionValue::U8List(Box::new([1, 0xe4]));
    equivalent.extensions[4].value = TlsCapturedExtensionValue::U16List(Box::new([29, 0x6a6a]));
    equivalent.extensions[5].value = TlsCapturedExtensionValue::U16List(Box::new([0x0804, 0x7a7a]));
    equivalent.extensions[6].value = TlsCapturedExtensionValue::U16List(Box::new([0x0304, 0x8a8a]));
    assert_eq!(original.id, equivalent.structural(limits).unwrap().id);

    capture.extensions.swap(0, 1);
    assert_eq!(original.id, capture.structural(limits).unwrap().id);
    let mut changed = capture.clone();
    changed.ciphers[0] = 0x1a2a;
    assert_ne!(original.id, changed.structural(limits).unwrap().id);
    changed = capture.clone();
    changed.extensions[0].id = 0x1a2a;
    assert_ne!(original.id, changed.structural(limits).unwrap().id);
    changed = capture.clone();
    changed.ciphers = Box::new([0x0a0a, 0x0a0a, 0x1301]);
    assert_ne!(original.id, changed.structural(limits).unwrap().id);
    changed = capture.clone();
    changed.transport = TlsCaptureTransport::Quic;
    assert_ne!(original.id, changed.structural(limits).unwrap().id);
    changed = capture.clone();
    changed.extensions[2].value = TlsCapturedExtensionValue::Protocols(
        vec![Box::from(b"h3".as_slice()), Box::from([0x3a, 0x3a])].into(),
    );
    assert_ne!(original.id, changed.structural(limits).unwrap().id);
    changed = capture;
    changed.extensions[3].value = TlsCapturedExtensionValue::U8List(Box::new([1, 0x2b]));
    assert_ne!(original.id, changed.structural(limits).unwrap().id);
}

#[test]
fn tls_canonical_import_rejects_truncation_and_structural_noncanonical_data() {
    let limits = TlsCaptureLimits::default();
    let capture = TlsCapture {
        completeness: ProfileCaptureCompleteness::Complete,
        transport: TlsCaptureTransport::Tcp,
        protocol_version: 0x0303,
        ciphers: Box::new([0x1302, 0x1301]),
        compression: Box::new([0]),
        extensions: Box::default(),
    };
    let raw = capture.canonical(limits).unwrap();
    let structural = capture.structural(limits).unwrap();
    for value in [&raw, &structural] {
        value.validated_domain(limits.bytes).unwrap();
        for end in 0..value.bytes.len() {
            let bytes: Box<[u8]> = value.bytes[..end].into();
            CanonicalValue {
                id: ValueId(Sha256::digest(&bytes).into()),
                bytes,
            }
            .validated_domain(limits.bytes)
            .unwrap_err();
        }
        let mut bytes = value.bytes.to_vec();
        bytes.push(0);
        CanonicalValue {
            id: ValueId(Sha256::digest(&bytes).into()),
            bytes: bytes.into(),
        }
        .validated_domain(limits.bytes)
        .unwrap_err();
        let mut wrong_digest = value.clone();
        wrong_digest.id.0[0] ^= 1;
        wrong_digest.validated_domain(limits.bytes).unwrap_err();
    }
    // A valid envelope and digest do not establish ownership of decoded payloads.
    let mut forged = CanonicalWriter::new(CanonicalDomain::Tls, limits.bytes).unwrap();
    forged.u8(0).unwrap();
    forged.u8(1).unwrap();
    forged.u16(0x0303).unwrap();
    forged.u64(1).unwrap();
    forged.u16(0x1301).unwrap();
    forged.bytes(&[0]).unwrap();
    forged.u64(1).unwrap();
    forged.u16(35).unwrap();
    forged.u8(0).unwrap();
    forged.bytes(b"private-canary").unwrap();
    TlsCapture::from_canonical(&forged.finish(), limits).unwrap_err();
    let mut writer = CanonicalWriter::new(CanonicalDomain::TlsStructure, limits.bytes).unwrap();
    writer.bytes(&raw.bytes).unwrap();
    writer.finish().validated_domain(limits.bytes).unwrap_err();
}

#[test]
fn tls_canonical_and_structural_encodings_match_independent_vectors() {
    let limits = TlsCaptureLimits::default();
    let capture = TlsCapture {
        completeness: ProfileCaptureCompleteness::Complete,
        transport: TlsCaptureTransport::Tcp,
        protocol_version: 0x0303,
        ciphers: Box::new([0x1a1a, 0x1302, 0x1301]),
        compression: Box::new([0]),
        extensions: Box::new([
            TlsCapturedExtension {
                id: 0x2a2a,
                value: TlsCapturedExtensionValue::Literal(Box::new([0xbe, 0xef])),
            },
            TlsCapturedExtension {
                id: 10,
                value: TlsCapturedExtensionValue::U16List(Box::new([29, 0x3a3a])),
            },
            TlsCapturedExtension {
                id: 0,
                value: TlsCapturedExtensionValue::ServerName { present: true },
            },
            TlsCapturedExtension {
                id: 16,
                value: TlsCapturedExtensionValue::Protocols(
                    vec![
                        Box::from(b"h2".as_slice()),
                        Box::from(b"http/1.1".as_slice()),
                    ]
                    .into(),
                ),
            },
            TlsCapturedExtension {
                id: 45,
                value: TlsCapturedExtensionValue::U8List(Box::new([1, 0x49])),
            },
        ]),
    };
    let value = capture.canonical(limits).unwrap();
    assert_eq!(
        value.bytes.as_ref(),
        &[
            114, 97, 109, 97, 45, 112, 114, 111, 102, 105, 108, 101, 0, 0, 2, 0, 10, 0, 1, 3, 3, 0,
            0, 0, 0, 0, 0, 0, 3, 26, 26, 19, 2, 19, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0,
            0, 5, 42, 42, 0, 0, 0, 0, 0, 0, 0, 0, 2, 190, 239, 0, 10, 1, 0, 0, 0, 0, 0, 0, 0, 2, 0,
            29, 58, 58, 0, 0, 4, 1, 0, 16, 3, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 2, 104,
            50, 0, 0, 0, 0, 0, 0, 0, 8, 104, 116, 116, 112, 47, 49, 46, 49, 0, 45, 2, 0, 0, 0, 0,
            0, 0, 0, 2, 1, 73
        ]
    );
    assert_eq!(
        value.id.0,
        [
            231, 164, 58, 150, 105, 13, 124, 43, 135, 189, 246, 41, 152, 23, 52, 247, 111, 85, 143,
            89, 89, 62, 175, 164, 209, 118, 34, 84, 151, 30, 102, 105
        ]
    );
    let value = capture.structural(limits).unwrap();
    assert_eq!(
        value.bytes.as_ref(),
        &[
            114, 97, 109, 97, 45, 112, 114, 111, 102, 105, 108, 101, 0, 0, 2, 0, 11, 0, 0, 0, 0, 0,
            0, 0, 132, 114, 97, 109, 97, 45, 112, 114, 111, 102, 105, 108, 101, 0, 0, 2, 0, 10, 0,
            1, 3, 3, 0, 0, 0, 0, 0, 0, 0, 3, 10, 10, 19, 1, 19, 2, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0,
            0, 0, 0, 0, 0, 5, 0, 0, 4, 1, 0, 10, 1, 0, 0, 0, 0, 0, 0, 0, 2, 0, 29, 10, 10, 0, 16,
            3, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 2, 104, 50, 0, 0, 0, 0, 0, 0, 0, 8,
            104, 116, 116, 112, 47, 49, 46, 49, 0, 45, 2, 0, 0, 0, 0, 0, 0, 0, 2, 1, 11, 10, 10, 0,
            0, 0, 0, 0, 0, 0, 0, 0
        ]
    );
    assert_eq!(
        value.id.0,
        [
            47, 171, 152, 190, 179, 159, 189, 113, 157, 206, 222, 237, 94, 90, 103, 65, 199, 28,
            224, 150, 145, 22, 170, 13, 46, 117, 8, 162, 17, 178, 217, 239
        ]
    );
}

#[test]
fn ten_thousand_connection_and_destination_lengths_share_one_tls_structure() {
    let limits = TlsCaptureLimits::default();
    let mut structure = None;
    let mut joint_structure = None;
    let mut bucket = CountedObservationBucket::new(
        CanonicalDomain::Tls,
        ValueId([4; 32]),
        [5; 32],
        ProfileBucketLimits::default(),
    )
    .unwrap();
    for sequence in 1..=10_000u64 {
        let size = 1 + sequence as usize % 63;
        let identity_length = 1 + sequence as usize % 1000;
        let mut psk = Vec::new();
        psk.extend_from_slice(&u16::try_from(identity_length + 6).unwrap().to_be_bytes());
        psk.extend_from_slice(&u16::try_from(identity_length).unwrap().to_be_bytes());
        psk.extend(vec![b'x'; identity_length]);
        psk.extend_from_slice(&[0; 4]);
        psk.extend_from_slice(&[0, 33, 32]);
        psk.extend_from_slice(&[b'p'; 32]);
        let observed = hello(vec![
            ClientHelloExtension::ServerName(Some(
                Domain::try_from(format!("{}.example", "x".repeat(size))).unwrap(),
            )),
            opaque(21, vec![0; sequence as usize % 512]),
            opaque(35, vec![b't'; identity_length]),
            ClientHelloExtension::EncryptedClientHello(
                serde_json::from_value(json!({"Outer": {
                    "cipher_suite": {"kdf_id":1,"aead_id":1}, "config_id": 7,
                    "enc":vec![b'e';32], "payload":vec![b'p'; 1 + sequence as usize % 511],
                }}))
                .unwrap(),
            ),
            opaque(41, psk),
        ]);
        let captured = capture(&observed);
        let key = captured.structural(limits).unwrap();
        assert_eq!(*structure.get_or_insert(key.id), key.id);
        key.validated_domain(limits.bytes).unwrap();
        let value = captured.canonical(limits).unwrap();
        let joint = JointCapture {
            completeness: ProfileCaptureCompleteness::Complete,
            level: CaptureLevel::Connection,
            slots: Box::new([CapturedSlot {
                kind: CapturedSlotKind::QuicTls,
                value: value.clone(),
            }]),
        };
        let joint = joint.structural(JointCaptureLimits::default()).unwrap();
        assert_eq!(*joint_structure.get_or_insert(joint.id), joint.id);
        bucket
            .observe(
                ObservationId {
                    run: [6; 16],
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
        TlsCapture::from_canonical(value, limits).unwrap();
    }
}
