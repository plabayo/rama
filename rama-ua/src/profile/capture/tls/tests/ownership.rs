use super::*;

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
