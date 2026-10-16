use super::*;
use rama_tls::{ExtensionId, ProtocolVersion, SupportedGroup};
use rama_ua::profile::capture::tls::TlsCapturedExtension;

#[test]
fn compiled_settings_reproduce_retained_tls_fields_with_fresh_crypto() {
    let capture = capture();
    let config = tls::compile(&capture, None).unwrap();
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
    tls::compile(&incomplete, None).unwrap_err();

    let mut unknown_cipher = original.clone();
    unknown_cipher.ciphers[0] = 0xffff;
    tls::compile(&unknown_cipher, None).unwrap_err();

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
    tls::compile(&unknown_share, None).unwrap_err();

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
    tls::compile(&resumed, None).unwrap_err();
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
    tls::compile(&captured, None).unwrap_err();
    let wrong = crate::client::BoringRequestedTrustAnchors::try_from_ids([vec![9; 8]]).unwrap();
    tls::compile(&captured, Some(&wrong)).unwrap_err();
    tls::compile(&captured, Some(&anchors)).unwrap();
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
        tls::compile(&captured, None).unwrap_err();
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
        tls::compile(&captured, None).unwrap_err();
    }
    let mut captured = original;
    let field = captured
        .extensions
        .iter_mut()
        .find(|extension| extension.id == u16::from(ExtensionId::COMPRESS_CERTIFICATE))
        .unwrap();
    field.value = TlsCapturedExtensionValue::U16List(vec![2, 2].into());
    tls::compile(&captured, None).unwrap_err();
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
        tls::compile(&captured, None).unwrap_err();
    }
    let mut captured = original;
    let mut extensions = captured.extensions.into_vec();
    extensions.push(TlsCapturedExtension {
        id: ExtensionId::APPLICATION_SETTINGS.into(),
        value: TlsCapturedExtensionValue::Protocols(vec![b"not-offered".to_vec().into()].into()),
    });
    captured.extensions = extensions.into();
    tls::compile(&captured, None).unwrap_err();
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

        let config = tls::compile(&original, None).unwrap();
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
