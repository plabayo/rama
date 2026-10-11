use rama_net::address::Domain;
use rama_tls::{CipherSuite, CompressionAlgorithm, ExtensionId, ProtocolVersion};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeSet;

use super::*;
use crate::profile::{
    CanonicalDomain, CanonicalValue, CaptureLevel, CapturedSlot, CapturedSlotKind,
    CountedObservationBucket, JointCapture, JointCaptureLimits, ObservationId, ProfileBucketLimits,
    ValueId, canonical::CanonicalWriter,
};

fn hello(extensions: Vec<ClientHelloExtension>) -> ClientHello {
    ClientHello::new(
        ProtocolVersion::TLSv1_2,
        vec![CipherSuite::from(0x1301)],
        vec![CompressionAlgorithm::from(0)],
        extensions,
    )
}
fn opaque(id: u16, data: Vec<u8>) -> ClientHelloExtension {
    ClientHelloExtension::Opaque {
        id: ExtensionId::from(id),
        data,
    }
}
fn capture(hello: &ClientHello) -> TlsCapture {
    TlsCapture::capture(
        ProfileCaptureCompleteness::Complete,
        TlsCaptureTransport::Quic,
        hello,
        TlsCaptureLimits::default(),
    )
    .unwrap()
}

#[test]
fn tls_capture_discards_connection_secrets_while_retaining_shapes_and_order() {
    let secret = b"private!";
    let mut shares = vec![0, 12, 0x1a, 0x1a, 0, 8];
    shares.extend_from_slice(secret);
    let mut psk = vec![0, 14, 0, 8];
    psk.extend_from_slice(secret);
    psk.extend_from_slice(&[0, 0, 0, 1]);
    psk.extend_from_slice(&[0, 33, 32]);
    psk.extend_from_slice(&[b'p'; 32]);
    let observed = hello(vec![
        ClientHelloExtension::ServerName(Some(Domain::try_from("private.example").unwrap())),
        opaque(35, secret.to_vec()),
        opaque(51, shares),
        opaque(57, secret.to_vec()),
        opaque(41, psk),
    ]);
    let value = capture(&observed);
    let encoded = serde_json::to_string(&value).unwrap();
    assert!(!encoded.contains("private"));
    assert!(!format!("{value:?}").contains("private"));
    assert_eq!(
        value
            .extensions
            .iter()
            .map(|extension| extension.id)
            .collect::<Vec<_>>(),
        vec![0, 35, 51, 57, 41]
    );
    assert!(matches!(
        value.extensions[0].value,
        TlsCapturedExtensionValue::ServerName { present: true }
    ));
    assert!(
        matches!(&value.extensions[2].value,TlsCapturedExtensionValue::KeyShares(values) if values.len()==1 && values[0].group==0x1a1a && values[0].length==8)
    );
    assert!(
        matches!(&value.extensions[4].value,TlsCapturedExtensionValue::PreSharedKeys { identities,binders } if identities.as_ref()==[8] && binders.as_ref()==[32])
    );
    // Changing secret contents without changing their shape does not change capture data.
    let mut altered = serde_json::to_value(&observed).unwrap();
    fn replace(value: &mut Value) {
        match value {
            Value::Array(values) => {
                for value in values {
                    replace(value);
                }
            }
            Value::Object(values) => {
                for (key, value) in values {
                    if key == "data" {
                        if let Some(bytes) = value.as_array_mut() {
                            for byte in bytes {
                                if byte.as_u64() == Some(u64::from(b'p')) {
                                    *byte = Value::from(b'q');
                                }
                            }
                        }
                    } else {
                        replace(value);
                    }
                }
            }
            _ => (),
        }
    }
    replace(&mut altered);
    assert_eq!(
        encoded,
        serde_json::to_string(&capture(&serde_json::from_value(altered).unwrap())).unwrap()
    );
}

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
fn tls_joint_slots_bind_the_transport_and_capture_level() {
    let limits = TlsCaptureLimits::default();
    let joint_limits = JointCaptureLimits::default();
    for (transport, kind, other) in [
        (
            TlsCaptureTransport::Tcp,
            CapturedSlotKind::TcpTls,
            CapturedSlotKind::QuicTls,
        ),
        (
            TlsCaptureTransport::Quic,
            CapturedSlotKind::QuicTls,
            CapturedSlotKind::TcpTls,
        ),
    ] {
        let capture = TlsCapture {
            completeness: ProfileCaptureCompleteness::Complete,
            transport,
            protocol_version: 0x0303,
            ciphers: Box::new([0x1301]),
            compression: Box::new([0]),
            extensions: Box::default(),
        };
        let mut joint = JointCapture {
            completeness: ProfileCaptureCompleteness::Complete,
            level: CaptureLevel::Connection,
            slots: Box::new([CapturedSlot {
                kind,
                value: capture.canonical(limits).unwrap(),
            }]),
        };
        let raw = joint.canonical(joint_limits).unwrap();
        JointCapture::from_canonical(&raw, joint_limits).unwrap();
        joint
            .structural(joint_limits)
            .unwrap()
            .validated_domain(joint_limits.bytes)
            .unwrap();
        joint.slots[0].kind = other;
        joint.canonical(joint_limits).unwrap_err();
        joint.structural(joint_limits).unwrap_err();
        joint.slots[0].kind = kind;
        joint.level = CaptureLevel::Request;
        joint.canonical(joint_limits).unwrap_err();
        joint.level = CaptureLevel::Connection;
        joint.slots[0].value = capture.structural(limits).unwrap();
        let mut writer =
            CanonicalWriter::new(CanonicalDomain::JointStructure, joint_limits.bytes).unwrap();
        writer.u8(0).unwrap();
        writer.u8(1).unwrap();
        writer.u64(1).unwrap();
        writer
            .u16(if matches!(other, CapturedSlotKind::TcpTls) {
                4
            } else {
                5
            })
            .unwrap();
        writer.bytes(&joint.slots[0].value.bytes).unwrap();
        writer
            .finish()
            .validated_domain(joint_limits.bytes)
            .unwrap_err();
    }
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
fn ech_and_sni_secret_changes_keep_only_their_capture_shapes() {
    let limits = TlsCaptureLimits::default();
    let observed = |secret: &[u8], config_id, name: &str| {
        hello(vec![
            ClientHelloExtension::ServerName(Some(Domain::try_from(name.to_owned()).unwrap())),
            ClientHelloExtension::EncryptedClientHello(
                serde_json::from_value(json!({"Outer": {
                    "cipher_suite": { "kdf_id": 1, "aead_id": 1 }, "config_id": config_id,
                    "enc": secret, "payload": secret,
                }}))
                .unwrap(),
            ),
        ])
    };
    let first = capture(&observed(b"private-canary", 42, "private.example"));
    let other = capture(&observed(
        b"another-secret",
        19,
        "another.destination.example",
    ));
    assert_eq!(
        first.canonical(limits).unwrap().bytes,
        other.canonical(limits).unwrap().bytes
    );
    assert_eq!(
        first.structural(limits).unwrap().bytes,
        other.structural(limits).unwrap().bytes
    );
    let encoded = first.canonical(limits).unwrap();
    assert!(
        !encoded
            .bytes
            .windows(14)
            .any(|value| value == b"private-canary")
    );
    assert!(!format!("{first:?}").contains("private"));
    let changed = capture(&observed(b"short", 42, "private.example"));
    assert_ne!(encoded.id, changed.canonical(limits).unwrap().id);
    let changed = capture(&hello(vec![ClientHelloExtension::EncryptedClientHello(
        ECHClientHello::Inner,
    )]));
    assert!(matches!(
        changed.extensions[0].value,
        TlsCapturedExtensionValue::EchInner
    ));
}

#[test]
fn joint_capture_cannot_combine_tcp_and_quic_tls_connections() {
    let limits = TlsCaptureLimits::default();
    let slots = [
        (TlsCaptureTransport::Tcp, CapturedSlotKind::TcpTls),
        (TlsCaptureTransport::Quic, CapturedSlotKind::QuicTls),
    ]
    .into_iter()
    .map(|(transport, kind)| CapturedSlot {
        kind,
        value: TlsCapture {
            completeness: ProfileCaptureCompleteness::Complete,
            transport,
            protocol_version: 0x0303,
            ciphers: Box::new([0x1301]),
            compression: Box::new([0]),
            extensions: Box::default(),
        }
        .canonical(limits)
        .unwrap(),
    })
    .collect();
    let joint = JointCapture {
        completeness: ProfileCaptureCompleteness::Complete,
        level: CaptureLevel::Connection,
        slots,
    };
    joint.canonical(JointCaptureLimits::default()).unwrap_err();
    joint.structural(JointCaptureLimits::default()).unwrap_err();
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
fn destination_names_and_padding_do_not_become_profile_values() {
    let limits = TlsCaptureLimits::default();
    let mut identity = None;
    for size in 1..=63 {
        let observed = hello(vec![
            ClientHelloExtension::ServerName(Some(
                Domain::try_from(format!("{}.example", "x".repeat(size))).unwrap(),
            )),
            opaque(21, vec![0; size * 8]),
        ]);
        let captured = capture(&observed);
        let encoded = captured.canonical(limits).unwrap();
        assert_eq!(*identity.get_or_insert(encoded.id), encoded.id);
        assert!(matches!(
            captured.extensions[0].value,
            TlsCapturedExtensionValue::ServerName { present: true }
        ));
        assert!(matches!(
            captured.extensions[1].value,
            TlsCapturedExtensionValue::ConnectionLength(0)
        ));
    }
    TlsCapture::capture(
        ProfileCaptureCompleteness::Complete,
        TlsCaptureTransport::Tcp,
        &hello(vec![opaque(21, vec![1])]),
        limits,
    )
    .unwrap_err();
    let mut forged = capture(&hello(vec![opaque(21, vec![0; 5])]));
    forged.extensions[0].value = TlsCapturedExtensionValue::ConnectionLength(5);
    forged.canonical(limits).unwrap_err();
    forged.extensions[0].value = TlsCapturedExtensionValue::Literal(Box::new([0]));
    forged.canonical(limits).unwrap_err();
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

#[test]
fn borrowed_tls_budgets_still_bound_discarded_wire_payloads() {
    let source = hello(vec![opaque(35, vec![b'x'; 4096])]);
    let value = capture(&source)
        .canonical(TlsCaptureLimits::default())
        .unwrap();
    assert!(value.bytes.len() < 128);
    TlsCapture::capture(
        ProfileCaptureCompleteness::Complete,
        TlsCaptureTransport::Quic,
        &source,
        TlsCaptureLimits {
            bytes: 128,
            ..TlsCaptureLimits::default()
        },
    )
    .unwrap_err();
}
