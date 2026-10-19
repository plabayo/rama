use super::*;
use rama_boring::ssl::Padding;

use crate::client::BoringExtensionPresence;
use rama_net::tls::{ApplicationProtocol, TlsAlpn};
use rama_tls::{
    CipherSuite, ExtensionId, ProtocolVersion, SupportedGroup,
    client::{ClientHandshake, ClientHello},
};
use rama_ua::profile::capture::tls::TlsCapturedExtension;

#[test]
fn compiled_settings_reproduce_retained_tls_fields_with_fresh_crypto() {
    let capture = capture();
    let config = wire::compile(wire::TransportShape::Tcp, &capture, None).unwrap();
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
    let key_shares = |hello: &ClientHello| {
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
    wire::compile(wire::TransportShape::Tcp, &incomplete, None).unwrap_err();

    let mut unknown_cipher = original.clone();
    unknown_cipher.ciphers[0] = 0xffff;
    wire::compile(wire::TransportShape::Tcp, &unknown_cipher, None).unwrap_err();

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
    wire::compile(wire::TransportShape::Tcp, &unknown_share, None).unwrap_err();

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
    wire::compile(wire::TransportShape::Tcp, &resumed, None).unwrap_err();
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
    wire::compile(wire::TransportShape::Tcp, &captured, None).unwrap_err();
    let wrong = crate::client::BoringRequestedTrustAnchors::try_from_ids([vec![9; 8]]).unwrap();
    wire::compile(wire::TransportShape::Tcp, &captured, Some(&wrong)).unwrap_err();
    wire::compile(wire::TransportShape::Tcp, &captured, Some(&anchors)).unwrap();
}

#[test]
fn caller_version_and_cipher_restrictions_are_not_broadened() {
    let capture = capture();
    for policy in [
        TlsClientConfig::new().with_max_version(ProtocolVersion::TLSv1_2),
        TlsClientConfig::new().with_cipher_suites(vec![CipherSuite::TLS13_AES_128_GCM_SHA256]),
    ] {
        let compiler = ConnectionProfileCompiler::new(policy);
        compiler.prepare_capture(&input(), &capture).unwrap_err();
    }
}

#[test]
fn explicit_caller_alpn_is_never_replaced_by_the_captured_offer() {
    let captured = capture();
    let offer = wire::compile(wire::TransportShape::Tcp, &captured, None)
        .unwrap()
        .alpn()
        .unwrap();
    let compiler = ConnectionProfileCompiler::new(TlsClientConfig::new());
    let request = input();
    request.extensions().insert(offer.clone());
    compiler.prepare_capture(&request, &captured).unwrap();
    for protocols in [
        Vec::new(),
        vec![ApplicationProtocol::HTTP_3],
        offer
            .0
            .iter()
            .cloned()
            .chain([ApplicationProtocol::HTTP_11])
            .collect(),
    ] {
        let request = input();
        request.extensions().insert(TlsAlpn(protocols.into()));
        let error = compiler.prepare_capture(&request, &captured).unwrap_err();
        assert!(
            error.to_string().contains("ALPN offers conflict"),
            "{error}"
        );
    }
}

#[test]
fn required_session_offer_cannot_be_replaced_by_a_fresh_capture() {
    for request_override in [false, true] {
        let policy = if request_override {
            TlsClientConfig::new()
        } else {
            TlsClientConfig::new().with_client_handshake(ClientHandshake::Resumed)
        };
        let request = input();
        if request_override {
            request.extensions().insert(ClientHandshake::Resumed);
        }
        let error = ConnectionProfileCompiler::new(policy)
            .prepare_capture(&request, &capture())
            .unwrap_err();
        assert!(
            error.to_string().contains("required session offer"),
            "{error}"
        );
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
        wire::compile(wire::TransportShape::Tcp, &captured, None).unwrap_err();
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
        wire::compile(wire::TransportShape::Tcp, &captured, None).unwrap_err();
    }
    let mut captured = original;
    let field = captured
        .extensions
        .iter_mut()
        .find(|extension| extension.id == u16::from(ExtensionId::COMPRESS_CERTIFICATE))
        .unwrap();
    field.value = TlsCapturedExtensionValue::U16List(vec![2, 2].into());
    wire::compile(wire::TransportShape::Tcp, &captured, None).unwrap_err();
}

#[cfg(feature = "http")]
#[test]
fn required_http_version_must_be_in_the_captured_offer() {
    let compiler = ConnectionProfileCompiler::new(TlsClientConfig::new());
    let request = input();
    request
        .extensions()
        .insert(TargetHttpVersion(Version::HTTP_11));
    compiler.prepare_capture(&request, &capture()).unwrap_err();
}

#[test]
fn native_required_fields_and_alps_membership_are_checked() {
    let original = capture();
    for id in [
        ExtensionId::SUPPORTED_GROUPS,
        ExtensionId::SIGNATURE_ALGORITHMS,
        ExtensionId::SUPPORTED_VERSIONS,
        ExtensionId::KEY_SHARE,
    ] {
        let mut captured = original.clone();
        captured.extensions = captured
            .extensions
            .into_vec()
            .into_iter()
            .filter(|extension| extension.id != u16::from(id))
            .collect();
        wire::compile(wire::TransportShape::Tcp, &captured, None).unwrap_err();
    }
    let mut captured = original;
    let mut extensions = captured.extensions.into_vec();
    extensions.push(TlsCapturedExtension {
        id: ExtensionId::APPLICATION_SETTINGS.into(),
        value: TlsCapturedExtensionValue::Protocols(vec![b"not-offered".to_vec().into()].into()),
    });
    captured.extensions = extensions.into();
    wire::compile(wire::TransportShape::Tcp, &captured, None).unwrap_err();
}

#[test]
fn optional_tls13_extension_presence_compiles_onto_native_controls() {
    let presence = |captured: &TlsCapture| {
        let config = wire::compile(wire::TransportShape::Tcp, captured, None).unwrap();
        *config
            .as_extensions()
            .get_ref::<BoringExtensionPresence>()
            .unwrap()
    };
    let original = capture();
    assert_eq!(presence(&original), BoringExtensionPresence::default());

    // psk_key_exchange_modes omitted: the connection then offers no session.
    let mut without_modes = original.clone();
    without_modes.extensions = without_modes
        .extensions
        .into_vec()
        .into_iter()
        .filter(|extension| extension.id != u16::from(ExtensionId::PSK_KEY_EXCHANGE_MODES))
        .collect();
    let compiled = presence(&without_modes);
    assert!(compiled.omit_psk_key_exchange_modes && !compiled.ec_point_formats);

    // ec_point_formats with a TLS 1.3-only offer, kept in its captured place.
    let mut with_formats = original;
    let mut extensions = with_formats.extensions.into_vec();
    extensions.insert(
        1,
        TlsCapturedExtension {
            id: ExtensionId::EC_POINT_FORMATS.into(),
            value: TlsCapturedExtensionValue::U8List(vec![0].into()),
        },
    );
    with_formats.extensions = extensions.into();
    let compiled = presence(&with_formats);
    assert!(compiled.ec_point_formats && !compiled.omit_psk_key_exchange_modes);

    // A PSK offer without its key exchange modes is invalid (RFC 8446 §4.2.9).
    let mut extensions = without_modes.extensions.into_vec();
    extensions.push(TlsCapturedExtension {
        id: ExtensionId::PRE_SHARED_KEY.into(),
        value: TlsCapturedExtensionValue::PreSharedKeys {
            identities: vec![32].into(),
            binders: vec![32].into(),
        },
    });
    without_modes.extensions = extensions.into();
    let error = wire::compile(wire::TransportShape::Tcp, &without_modes, None).unwrap_err();
    assert!(
        error.to_string().contains("psk_key_exchange_modes"),
        "{error}"
    );
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

        let config = wire::compile(wire::TransportShape::Tcp, &original, None).unwrap();
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

// Emit from the settings installed by the adapter. Native connection tests also
// exercise the real connector's policy merging, authentication and negotiated ALPN.
fn prepared_hello(compiled: CompiledConnection) -> ClientHello {
    let request = input();
    let bindings = <CompiledConnection as InstalledConnectionProfile<ConnectRequest>>::apply(
        compiled,
        request.extensions(),
    );
    bindings.check(&request).unwrap();
    let config = BoringTlsConnectorConfig::from_extensions(request.extensions());
    let mut data = TlsConnectorData::try_from(config).unwrap();
    data.server_name = Some(Host::from_static("prepared.test"));
    hello_from_data(data)
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
    let compiler = ConnectionProfileCompiler::new(policy);
    let compiled = match compiler.prepare_capture(&input(), captured) {
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
    let compiler = ConnectionProfileCompiler::new(
        TlsClientConfig::new().with_min_version(ProtocolVersion::TLSv1_3),
    );
    let error = compiler
        .prepare_capture(&input(), &mixed_version_capture())
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

#[test]
fn counted_server_padding_replays_exact_native_tcp_values() {
    for bytes in [None, Some(0), Some(32), Some(16_384), Some(u16::MAX)] {
        let original = wire_variant()
            .with_client_hello_padding(Padding::Off)
            .with_server_padding_request(bytes);
        let source = TlsCapture::capture(
            ProfileCaptureCompleteness::Complete,
            TlsCaptureTransport::Tcp,
            &hello_from_data(TlsConnectorData::try_from(&original).unwrap()),
            TlsCaptureLimits::default(),
        )
        .unwrap();
        let compiled = wire::compile(wire::TransportShape::Tcp, &source, None).unwrap();
        // A captured omission must override an otherwise configured native
        // request too, without trying to reset a previously used SSL.
        let current = TlsClientConfig::new().with_server_padding_request(99);
        current.as_extensions().extend(compiled.as_extensions());
        let emitted = hello_from_data(TlsConnectorData::try_from(&current).unwrap());
        let actual = TlsCapture::capture(
            ProfileCaptureCompleteness::Complete,
            TlsCaptureTransport::Tcp,
            &emitted,
            TlsCaptureLimits::default(),
        )
        .unwrap();
        assert_eq!(
            source.canonical(TlsCaptureLimits::default()).unwrap().bytes,
            actual.canonical(TlsCaptureLimits::default()).unwrap().bytes,
        );
    }
}

#[test]
fn counted_server_padding_rejects_malformed_retained_bodies() {
    let original = wire_variant().with_server_padding_request(32);
    let source = TlsCapture::capture(
        ProfileCaptureCompleteness::Complete,
        TlsCaptureTransport::Tcp,
        &hello_from_data(TlsConnectorData::try_from(&original).unwrap()),
        TlsCaptureLimits::default(),
    )
    .unwrap();
    for body in [vec![], vec![0], vec![0, 1, 2]] {
        let mut malformed = source.clone();
        malformed
            .extensions
            .iter_mut()
            .find(|extension| extension.id == u16::from(ExtensionId::SERVER_PADDING_REQUEST))
            .unwrap()
            .value = TlsCapturedExtensionValue::Literal(body.into());
        assert!(
            malformed
                .validate_fields(TlsCaptureLimits::default())
                .is_err()
        );
        wire::compile(wire::TransportShape::Tcp, &malformed, None).unwrap_err();
    }
}
