use super::*;
use rama_tls::{ExtensionId, ProtocolVersion, SupportedGroup};
use rama_ua::profile::capture::tls::TlsCapturedExtension;

#[test]
fn compiled_settings_reproduce_retained_tls_fields_with_fresh_crypto() {
    let capture = capture();
    let config = tls::compile(tls::TransportBinding::Tcp, &capture, None).unwrap();
    let mut observations = Vec::new();
    for _ in 0..2 {
        let hello = hello_from_data(TlsConnectorData::try_from(&config).unwrap());
        let actual = TlsCapture::capture(
            ProfileCaptureCompleteness::Complete,
            TlsCaptureTransport::Tcp,
            &hello,
            TlsCaptureLimits::default(),
        )
        .unwrap();
        assert_eq!(
            capture
                .canonical(TlsCaptureLimits::default())
                .unwrap()
                .bytes,
            actual.canonical(TlsCaptureLimits::default()).unwrap().bytes
        );
        observations.push(hello);
    }
    // Canonical equality above excludes cryptographic material, while the
    // original parsed key shares must differ across native sessions.
    let key_shares = |hello: &rama_tls::client::ClientHello| {
        format!(
            "{:?}",
            hello
                .extensions()
                .iter()
                .find(|extension| extension.id() == ExtensionId::KEY_SHARE)
        )
    };
    assert!(
        key_shares(&observations[0]) != key_shares(&observations[1]),
        "fresh sessions must generate different key shares"
    );
}

#[test]
fn unsupported_or_incomplete_native_shapes_reject() {
    let original = capture();
    let mut incomplete = original.clone();
    incomplete.completeness = ProfileCaptureCompleteness::Incomplete;
    tls::compile(tls::TransportBinding::Tcp, &incomplete, None).unwrap_err();

    let mut unknown_cipher = original.clone();
    unknown_cipher.ciphers[0] = 0xffff;
    tls::compile(tls::TransportBinding::Tcp, &unknown_cipher, None).unwrap_err();

    let mut unknown_share = original.clone();
    let share = unknown_share
        .extensions
        .iter_mut()
        .find_map(|extension| match &mut extension.value {
            TlsCapturedExtensionValue::KeyShares(shares) => Some(&mut shares[0]),
            _ => None,
        })
        .unwrap();
    share.length += 1;
    tls::compile(tls::TransportBinding::Tcp, &unknown_share, None).unwrap_err();

    let mut resumed = original;
    let mut extensions = resumed.extensions.into_vec();
    extensions.push(TlsCapturedExtension {
        id: ExtensionId::PRE_SHARED_KEY.into(),
        value: TlsCapturedExtensionValue::PreSharedKeys {
            identities: vec![12].into(),
            binders: vec![32].into(),
        },
    });
    resumed.extensions = extensions.into();
    tls::compile(tls::TransportBinding::Tcp, &resumed, None).unwrap_err();
}

#[test]
fn trust_advertisement_requires_a_current_binding_of_the_retained_length() {
    let mut captured = capture();
    let anchors = crate::client::BoringRequestedTrustAnchors::try_from_ids([vec![7; 13]]).unwrap();
    let length = anchors.extension_body().unwrap().len() as u16;
    let mut extensions = captured.extensions.into_vec();
    extensions.push(TlsCapturedExtension {
        id: 51764,
        value: TlsCapturedExtensionValue::ConnectionLength(length),
    });
    captured.extensions = extensions.into();
    tls::compile(tls::TransportBinding::Tcp, &captured, None).unwrap_err();
    let wrong = crate::client::BoringRequestedTrustAnchors::try_from_ids([vec![9; 8]]).unwrap();
    tls::compile(tls::TransportBinding::Tcp, &captured, Some(&wrong)).unwrap_err();
    tls::compile(tls::TransportBinding::Tcp, &captured, Some(&anchors)).unwrap();
}

#[test]
fn caller_version_and_cipher_restrictions_are_not_broadened() {
    let capture = capture();
    for policy in [
        TlsClientConfig::new().with_max_version(ProtocolVersion::TLSv1_2),
        TlsClientConfig::new()
            .with_cipher_suites(vec![rama_tls::CipherSuite::TLS13_AES_128_GCM_SHA256]),
    ] {
        let connector = TlsConnector::auto(()).with_base_config(policy);
        connector
            .profile_compiler()
            .prepare(&input(), &capture)
            .unwrap_err();
    }
}

#[test]
fn unsupported_algorithms_never_disappear_silently() {
    for id in [
        ExtensionId::SUPPORTED_GROUPS,
        ExtensionId::SIGNATURE_ALGORITHMS,
        ExtensionId::COMPRESS_CERTIFICATE,
        ExtensionId::SUPPORTED_VERSIONS,
    ] {
        let mut captured = capture();
        let field = captured
            .extensions
            .iter_mut()
            .find(|extension| extension.id == u16::from(id))
            .unwrap();
        let TlsCapturedExtensionValue::U16List(values) = &mut field.value else {
            panic!("fixture must contain a typed algorithm list");
        };
        values[0] = 0xffff;
        tls::compile(tls::TransportBinding::Tcp, &captured, None).unwrap_err();
    }
}

#[test]
fn native_lists_that_reorder_or_deduplicate_are_rejected() {
    let original = capture();
    for replacement in [vec![0x0303, 0x0304], vec![0x0304, 0x0304]] {
        let mut captured = original.clone();
        let field = captured
            .extensions
            .iter_mut()
            .find(|extension| extension.id == u16::from(ExtensionId::SUPPORTED_VERSIONS))
            .unwrap();
        field.value = TlsCapturedExtensionValue::U16List(replacement.into());
        tls::compile(tls::TransportBinding::Tcp, &captured, None).unwrap_err();
    }
    let mut captured = original;
    let field = captured
        .extensions
        .iter_mut()
        .find(|extension| extension.id == u16::from(ExtensionId::COMPRESS_CERTIFICATE))
        .unwrap();
    field.value = TlsCapturedExtensionValue::U16List(vec![2, 2].into());
    tls::compile(tls::TransportBinding::Tcp, &captured, None).unwrap_err();
}

#[cfg(feature = "http")]
#[test]
fn required_http_version_must_be_in_the_captured_offer() {
    let connector = TlsConnector::auto(());
    let request = input();
    request
        .extensions()
        .insert(TargetHttpVersion(Version::HTTP_11));
    connector
        .profile_compiler()
        .prepare(&request, &capture())
        .unwrap_err();
}

#[test]
fn native_required_fields_and_alps_membership_are_checked() {
    let original = capture();
    for id in [
        ExtensionId::SUPPORTED_GROUPS,
        ExtensionId::SIGNATURE_ALGORITHMS,
        ExtensionId::SUPPORTED_VERSIONS,
        ExtensionId::PSK_KEY_EXCHANGE_MODES,
        ExtensionId::KEY_SHARE,
    ] {
        let mut captured = original.clone();
        captured.extensions = captured
            .extensions
            .into_vec()
            .into_iter()
            .filter(|extension| extension.id != u16::from(id))
            .collect();
        tls::compile(tls::TransportBinding::Tcp, &captured, None).unwrap_err();
    }
    let mut captured = original;
    let mut extensions = captured.extensions.into_vec();
    extensions.push(TlsCapturedExtension {
        id: ExtensionId::APPLICATION_SETTINGS.into(),
        value: TlsCapturedExtensionValue::Protocols(vec![b"not-offered".to_vec().into()].into()),
    });
    captured.extensions = extensions.into();
    tls::compile(tls::TransportBinding::Tcp, &captured, None).unwrap_err();
}

#[test]
fn key_share_sizes_follow_native_emission_and_compile_back_to_the_same_shape() {
    for group in [
        SupportedGroup::SECP256R1,
        SupportedGroup::SECP384R1,
        SupportedGroup::SECP521R1,
        SupportedGroup::X25519,
        SupportedGroup::X25519MLKEM768,
    ] {
        let source = wire_variant()
            .with_grease(false)
            .with_supported_groups(vec![group])
            .with_key_shares(vec![group])
            .with_encrypted_client_hello(true)
            .with_ech_grease(crate::client::ech::EchGrease::Shape {
                kdf_id: 1,
                aead_id: 1,
                encapsulated_key_len: 32,
                payload_len: 320,
            });
        let original = TlsCapture::capture(
            ProfileCaptureCompleteness::Complete,
            TlsCaptureTransport::Tcp,
            &hello_from_data(TlsConnectorData::try_from(&source).unwrap()),
            TlsCaptureLimits::default(),
        )
        .unwrap();
        let shares = original
            .extensions
            .iter()
            .find_map(|extension| match &extension.value {
                TlsCapturedExtensionValue::KeyShares(shares) => Some(shares.as_ref()),
                _ => None,
            })
            .unwrap();
        assert_eq!(shares.len(), 1);
        assert_eq!(shares[0].group, u16::from(group));
        assert_eq!(group.tls13_client_key_share_len(), Some(shares[0].length));

        let config = tls::compile(tls::TransportBinding::Tcp, &original, None).unwrap();
        let replayed = TlsCapture::capture(
            ProfileCaptureCompleteness::Complete,
            TlsCaptureTransport::Tcp,
            &hello_from_data(TlsConnectorData::try_from(&config).unwrap()),
            TlsCaptureLimits::default(),
        )
        .unwrap();
        assert_eq!(
            original
                .canonical(TlsCaptureLimits::default())
                .unwrap()
                .bytes,
            replayed
                .canonical(TlsCaptureLimits::default())
                .unwrap()
                .bytes
        );
    }
}

// Exercise the actual SSL retained by the compiler, including caller policy.
// A mismatch is a bug even when the generic wire overrides look correct.
fn prepared_hello(mut compiled: CompiledConnection) -> rama_tls::client::ClientHello {
    #[derive(Default)]
    struct Sink(Vec<u8>);

    impl std::io::Read for Sink {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::ErrorKind::WouldBlock.into())
        }
    }

    impl std::io::Write for Sink {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let prepared = compiled
        .tls
        .as_mut()
        .unwrap()
        .1
        .prepared
        .get_mut()
        .take()
        .unwrap();
    let ssl = prepared.client.into_ssl_for_test();
    let Err(rama_boring::ssl::HandshakeError::WouldBlock(stream)) = ssl.connect(Sink::default())
    else {
        panic!("native first flight must precede reading a server response");
    };
    rama_tls::client::parse_client_hello_handshake(&stream.get_ref().0).unwrap()
}

fn mixed_version_capture() -> TlsCapture {
    let source = wire_variant()
        .with_grease(false)
        .with_supported_versions(vec![ProtocolVersion::TLSv1_3, ProtocolVersion::TLSv1_2])
        .with_encrypted_client_hello(true)
        .with_ech_grease(EchGrease::Shape {
            kdf_id: 1,
            aead_id: 1,
            encapsulated_key_len: 32,
            payload_len: 320,
        });
    TlsCapture::capture(
        ProfileCaptureCompleteness::Complete,
        TlsCaptureTransport::Tcp,
        &hello_from_data(TlsConnectorData::try_from(&source).unwrap()),
        TlsCaptureLimits::default(),
    )
    .unwrap()
}

fn remove_extension(captured: &mut TlsCapture, id: ExtensionId) {
    captured.extensions = std::mem::take(&mut captured.extensions)
        .into_vec()
        .into_iter()
        .filter(|extension| extension.id != u16::from(id))
        .collect();
}

fn assert_admitted_emission_matches(
    captured: &TlsCapture,
    policy: TlsClientConfig,
    must_admit: bool,
) {
    let connector = TlsConnector::auto(()).with_base_config(policy);
    let compiled = match connector.profile_compiler().prepare(&input(), captured) {
        Ok(compiled) => compiled,
        Err(error) => {
            assert!(!must_admit, "control shape must remain supported: {error}");
            return;
        }
    };
    assert!(compiled.supports(CapturedSlotKind::TcpTls));
    let actual = TlsCapture::capture(
        ProfileCaptureCompleteness::Complete,
        TlsCaptureTransport::Tcp,
        &prepared_hello(compiled),
        TlsCaptureLimits::default(),
    )
    .unwrap();
    assert_eq!(
        captured
            .canonical(TlsCaptureLimits::default())
            .unwrap()
            .bytes,
        actual.canonical(TlsCaptureLimits::default()).unwrap().bytes,
        "admitted capture must match the actual prepared native first flight"
    );
}

#[test]
fn prepared_native_control_preserves_the_selected_first_flight() {
    assert_admitted_emission_matches(&mixed_version_capture(), TlsClientConfig::new(), true);
}

#[test]
fn caller_version_floor_cannot_silently_change_the_selected_first_flight() {
    // The captured TLS 1.2 offer must not weaken a TLS 1.3 caller floor.
    let connector = TlsConnector::auto(())
        .with_base_config(TlsClientConfig::new().with_min_version(ProtocolVersion::TLSv1_3));
    let error = connector
        .profile_compiler()
        .prepare(&input(), &mixed_version_capture())
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("caller TLS version bounds conflict")
    );
}

#[test]
fn automatic_padding_cannot_silently_change_the_selected_first_flight() {
    let mut captured = mixed_version_capture();
    remove_extension(&mut captured, ExtensionId::ENCRYPTED_CLIENT_HELLO);
    assert_admitted_emission_matches(&captured, TlsClientConfig::new(), true);
}

#[test]
fn automatic_point_formats_cannot_silently_change_the_selected_first_flight() {
    let mut captured = mixed_version_capture();
    remove_extension(&mut captured, ExtensionId::EC_POINT_FORMATS);
    assert_admitted_emission_matches(&captured, TlsClientConfig::new(), false);
}

#[test]
fn zero_record_limit_cannot_silently_disappear_from_the_selected_first_flight() {
    let mut captured = mixed_version_capture();
    let mut extensions = captured.extensions.into_vec();
    extensions.push(TlsCapturedExtension {
        id: ExtensionId::RECORD_SIZE_LIMIT.into(),
        value: TlsCapturedExtensionValue::U16List(vec![0].into()),
    });
    captured.extensions = extensions.into();
    assert_admitted_emission_matches(&captured, TlsClientConfig::new(), false);
}

#[test]
fn broader_caller_version_bounds_do_not_expand_the_selected_first_flight() {
    assert_admitted_emission_matches(
        &capture(),
        TlsClientConfig::new().with_min_version(ProtocolVersion::TLSv1_2),
        true,
    );
}

#[test]
fn explicit_legacy_extension_pair_can_remain_in_a_tls13_only_first_flight() {
    let source = wire_variant()
        .with_legacy_extensions(true)
        .with_encrypted_client_hello(true)
        .with_ech_grease(EchGrease::Shape {
            kdf_id: 1,
            aead_id: 1,
            encapsulated_key_len: 32,
            payload_len: 320,
        });
    let captured = TlsCapture::capture(
        ProfileCaptureCompleteness::Complete,
        TlsCaptureTransport::Tcp,
        &hello_from_data(TlsConnectorData::try_from(&source).unwrap()),
        TlsCaptureLimits::default(),
    )
    .unwrap();
    assert_admitted_emission_matches(&captured, TlsClientConfig::new(), true);
}
