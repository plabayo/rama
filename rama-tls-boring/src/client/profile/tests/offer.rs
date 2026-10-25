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
    let (config, report) = compile_tcp(&capture, None).unwrap();
    assert!(report.is_exact(), "{report:?}");
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
fn unsupported_safari_ciphers_are_preserved_in_the_native_client_hello() {
    let mut captured = capture();
    let mut ciphers = captured.ciphers.to_vec();
    ciphers.extend([0xc008, 0xc012, 0xffff]);
    captured.ciphers = ciphers.into();
    let (config, report) = compile_tcp(&captured, None).unwrap();
    assert_eq!(lowered(&report), [LoweredProfileItem::TlsCipherNegotiation]);
    let hello = hello_from_data(TlsConnectorData::try_from(&config).unwrap());
    let actual = TlsCapture::capture(
        ProfileCaptureCompleteness::Complete,
        TlsCaptureTransport::Tcp,
        &hello,
        TlsCaptureLimits::default(),
    )
    .unwrap();
    assert_eq!(actual.ciphers, captured.ciphers);
}

#[test]
fn incomplete_captures_reject_and_unsupported_shapes_are_lowered() {
    let original = capture();
    let mut incomplete = original.clone();
    incomplete.completeness = ProfileCaptureCompleteness::Incomplete;
    compile_tcp(&incomplete, None).unwrap_err();

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
    let (_, report) = compile_tcp(&unknown_share, None).unwrap();
    assert_eq!(lowered(&report), [LoweredProfileItem::TlsKeyShares]);

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
    let (_, report) = compile_tcp(&resumed, None).unwrap();
    assert_eq!(
        lowered(&report),
        [LoweredProfileItem::TlsExtension {
            extension: ExtensionId::PRE_SHARED_KEY.into()
        }]
    );
}

#[test]
fn trust_advertisement_without_a_matching_current_binding_is_reported() {
    let mut captured = capture();
    let anchors = crate::client::BoringRequestedTrustAnchors::try_from_ids([vec![7; 13]]).unwrap();
    let length = anchors.extension_body().unwrap().len() as u16;
    let mut extensions = captured.extensions.into_vec();
    extensions.push(TlsCapturedExtension {
        id: 51764,
        value: TlsCapturedExtensionValue::ConnectionLength(length),
    });
    captured.extensions = extensions.into();
    let wrong = crate::client::BoringRequestedTrustAnchors::try_from_ids([vec![9; 8]]).unwrap();
    for current in [None, Some(&wrong)] {
        let (_, report) = compile_tcp(&captured, current).unwrap();
        assert_eq!(lowered(&report), [LoweredProfileItem::TlsTrustAnchors]);
    }
    let (_, report) = compile_tcp(&captured, Some(&anchors)).unwrap();
    assert!(report.is_exact());
}

#[test]
fn caller_version_and_cipher_restrictions_are_retained_and_reported() {
    let capture = capture();
    for (policy, item) in [
        (
            TlsClientConfig::new().with_max_version(ProtocolVersion::TLSv1_2),
            LoweredProfileItem::CallerTlsVersionBounds,
        ),
        (
            TlsClientConfig::new().with_cipher_suites(vec![CipherSuite::TLS13_AES_128_GCM_SHA256]),
            LoweredProfileItem::CallerTlsCipherSuites,
        ),
    ] {
        let compiler = ConnectionProfileCompiler::new(policy);
        let (_, report) = prepare(&compiler, &input(), &capture).unwrap();
        assert_eq!(lowered(&report), [item]);
    }
}

#[test]
fn explicit_caller_alpn_is_never_replaced_by_the_captured_offer() {
    let captured = capture();
    let offer = compile_tcp(&captured, None).unwrap().0.alpn().unwrap();
    let compiler = ConnectionProfileCompiler::new(TlsClientConfig::new());
    let request = input();
    request.extensions().insert(offer.clone());
    let (_, report) = prepare(&compiler, &request, &captured).unwrap();
    assert!(report.is_exact());
    for protocols in [
        vec![ApplicationProtocol::HTTP_11, ApplicationProtocol::HTTP_2],
        offer
            .0
            .iter()
            .cloned()
            .chain([ApplicationProtocol::HTTP_11])
            .collect(),
    ] {
        let caller = TlsAlpn(protocols.into());
        let request = input();
        request.extensions().insert(caller.clone());
        let (compiled, report) = prepare(&compiler, &request, &captured).unwrap();
        assert!(lowered(&report).contains(&LoweredProfileItem::CallerTlsAlpn));
        <CompiledConnection as InstalledConnectionProfile<ConnectRequest>>::apply(
            compiled,
            request.extensions(),
        );
        assert_eq!(request.extensions().get_ref::<TlsAlpn>(), Some(&caller));
    }
}

#[test]
fn required_session_offer_is_retained_and_reported() {
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
        let (_, report) = prepare(
            &ConnectionProfileCompiler::new(policy),
            &request,
            &capture(),
        )
        .unwrap();
        assert_eq!(
            lowered(&report),
            [LoweredProfileItem::CallerTlsSessionOffer]
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
        let (_, report) = compile_tcp(&captured, None).unwrap();
        assert!(!report.is_exact(), "{id:?}");
    }
}

#[test]
fn native_lists_that_reorder_or_deduplicate_are_reported() {
    let original = capture();
    for replacement in [vec![0x0303, 0x0304], vec![0x0304, 0x0304]] {
        let mut captured = original.clone();
        let field = captured
            .extensions
            .iter_mut()
            .find(|extension| extension.id == u16::from(ExtensionId::SUPPORTED_VERSIONS))
            .unwrap();
        field.value = TlsCapturedExtensionValue::U16List(replacement.into());
        let (_, report) = compile_tcp(&captured, None).unwrap();
        assert!(lowered(&report).contains(&LoweredProfileItem::TlsSupportedVersions));
    }
    let mut captured = original;
    let field = captured
        .extensions
        .iter_mut()
        .find(|extension| extension.id == u16::from(ExtensionId::COMPRESS_CERTIFICATE))
        .unwrap();
    field.value = TlsCapturedExtensionValue::U16List(vec![2, 2].into());
    let (_, report) = compile_tcp(&captured, None).unwrap();
    assert_eq!(
        lowered(&report),
        [LoweredProfileItem::TlsCertificateCompression]
    );
}

#[cfg(feature = "http")]
#[test]
fn required_http_version_absent_from_the_captured_offer_is_added_and_reported() {
    let compiler = ConnectionProfileCompiler::new(TlsClientConfig::new());
    let request = input();
    request
        .extensions()
        .insert(TargetHttpVersion(Version::HTTP_11));
    let (_, report) = prepare(&compiler, &request, &capture()).unwrap();
    assert_eq!(lowered(&report), [LoweredProfileItem::TlsAlpnTargetVersion]);
}

#[test]
fn native_required_fields_and_alps_membership_are_reported() {
    let original = capture();
    for id in [
        ExtensionId::SUPPORTED_GROUPS,
        ExtensionId::SIGNATURE_ALGORITHMS,
        ExtensionId::SUPPORTED_VERSIONS,
        ExtensionId::KEY_SHARE,
    ] {
        let mut captured = original.clone();
        remove_extension(&mut captured, id);
        let (_, report) = compile_tcp(&captured, None).unwrap();
        assert!(
            lowered(&report).contains(&LoweredProfileItem::TlsRequiredField {
                extension: id.into()
            }),
            "{id:?}: {report:?}"
        );
    }
    let mut captured = original;
    let mut extensions = captured.extensions.into_vec();
    extensions.push(TlsCapturedExtension {
        id: ExtensionId::APPLICATION_SETTINGS.into(),
        value: TlsCapturedExtensionValue::Protocols(vec![b"not-offered".to_vec().into()].into()),
    });
    captured.extensions = extensions.into();
    let (_, report) = compile_tcp(&captured, None).unwrap();
    assert_eq!(lowered(&report), [LoweredProfileItem::TlsAlps]);
}

#[test]
fn optional_tls13_extension_presence_compiles_onto_native_controls() {
    let presence = |captured: &TlsCapture| {
        let (config, report) = compile_tcp(captured, None).unwrap();
        assert!(report.is_exact(), "{report:?}");
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

    // Without a TLS 1.3 offer the modes stay native, as native configuration does.
    let mut tls12 = without_modes.clone();
    tls12.extensions = tls12
        .extensions
        .into_vec()
        .into_iter()
        .filter(|extension| extension.id != u16::from(ExtensionId::SUPPORTED_VERSIONS))
        .collect();
    let (config, _) = compile_tcp(&tls12, None).unwrap();
    assert!(
        !config
            .as_extensions()
            .get_ref::<BoringExtensionPresence>()
            .unwrap()
            .omit_psk_key_exchange_modes
    );

    // Another modes body has no native shape: native modes are sent, not omitted.
    let mut other_modes = original.clone();
    other_modes.extensions = other_modes
        .extensions
        .into_vec()
        .into_iter()
        .map(|mut extension| {
            if extension.id == u16::from(ExtensionId::PSK_KEY_EXCHANGE_MODES) {
                extension.value = TlsCapturedExtensionValue::U8List(vec![0, 1].into());
            }
            extension
        })
        .collect();
    let (config, report) = compile_tcp(&other_modes, None).unwrap();
    assert!(
        !config
            .as_extensions()
            .get_ref::<BoringExtensionPresence>()
            .unwrap()
            .omit_psk_key_exchange_modes
    );
    assert!(
        lowered(&report).contains(&LoweredProfileItem::TlsExtension {
            extension: ExtensionId::PSK_KEY_EXCHANGE_MODES.into()
        }),
        "{report:?}"
    );

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
    let error = compile_tcp(&without_modes, None).unwrap_err();
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

        let (config, report) = compile_tcp(&original, None).unwrap();
        assert!(report.is_exact(), "{report:?}");
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

fn assert_admitted_emission_matches(captured: &TlsCapture, policy: TlsClientConfig) {
    let compiler = ConnectionProfileCompiler::new(policy);
    let (compiled, report) = prepare(&compiler, &input(), captured).unwrap();
    assert!(report.is_exact(), "{report:?}");
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

fn assert_lowered(captured: &TlsCapture, item: LoweredProfileItem) {
    let compiler = ConnectionProfileCompiler::new(TlsClientConfig::new());
    let (compiled, report) = prepare(&compiler, &input(), captured).unwrap();
    assert!(compiled.supports(CapturedSlotKind::TcpTls));
    assert_eq!(lowered(&report), [item]);
}

#[test]
fn prepared_native_control_preserves_the_selected_first_flight() {
    assert_admitted_emission_matches(&mixed_version_capture(), TlsClientConfig::new());
}

#[test]
fn caller_version_floor_cannot_silently_change_the_selected_first_flight() {
    // The captured TLS 1.2 offer must not weaken a TLS 1.3 caller floor.
    let compiler = ConnectionProfileCompiler::new(
        TlsClientConfig::new().with_min_version(ProtocolVersion::TLSv1_3),
    );
    let (_, report) = prepare(&compiler, &input(), &mixed_version_capture()).unwrap();
    assert_eq!(
        lowered(&report),
        [LoweredProfileItem::CallerTlsVersionBounds]
    );
}

#[test]
fn automatic_padding_cannot_silently_change_the_selected_first_flight() {
    let mut captured = mixed_version_capture();
    remove_extension(&mut captured, ExtensionId::ENCRYPTED_CLIENT_HELLO);
    assert_admitted_emission_matches(&captured, TlsClientConfig::new());
}

#[test]
fn automatic_point_formats_cannot_silently_change_the_selected_first_flight() {
    let mut captured = mixed_version_capture();
    remove_extension(&mut captured, ExtensionId::EC_POINT_FORMATS);
    assert_lowered(&captured, LoweredProfileItem::TlsEcPointFormats);
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
    assert_lowered(
        &captured,
        LoweredProfileItem::TlsExtension {
            extension: ExtensionId::RECORD_SIZE_LIMIT.into(),
        },
    );
}

#[test]
fn broader_caller_version_bounds_do_not_expand_the_selected_first_flight() {
    assert_admitted_emission_matches(
        &capture(),
        TlsClientConfig::new().with_min_version(ProtocolVersion::TLSv1_2),
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
    assert_admitted_emission_matches(&captured, TlsClientConfig::new());
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
        let (compiled, report) = compile_tcp(&source, None).unwrap();
        assert!(report.is_exact(), "{report:?}");
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
        compile_tcp(&malformed, None).unwrap_err();
    }
}

#[test]
fn entirely_unsupported_cipher_offer_keeps_native_negotiable_list() {
    let mut captured = capture();
    captured.ciphers = vec![0xc008, 0xc012, 0xffff].into();
    let (config, report) = compile_tcp(&captured, None).unwrap();
    assert_eq!(lowered(&report), [LoweredProfileItem::TlsCipherSuites]);
    let hello = hello_from_data(TlsConnectorData::try_from(&config).unwrap());
    let actual = TlsCapture::capture(
        ProfileCaptureCompleteness::Complete,
        TlsCaptureTransport::Tcp,
        &hello,
        TlsCaptureLimits::default(),
    )
    .unwrap();
    assert_ne!(actual.ciphers, captured.ciphers);
    assert!(actual.ciphers.contains(&0x1301));
}
