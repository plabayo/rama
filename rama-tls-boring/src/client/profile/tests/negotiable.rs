use rama_boring::{
    pkey::PKey,
    ssl::{Ssl, SslConnector, SslContextBuilder, SslCurve, SslMethod, SslVerifyMode, SslVersion},
    x509::X509,
};
use rama_boring_tokio::SslStreamBuilder;
use rama_core::{Service as _, ServiceInput, service::service_fn};
use rama_net::{address::Domain, tls::ServerName};
use rama_tls::{
    CipherSuite, ExtensionId, ProtocolVersion,
    client::ServerVerifyMode,
    server::{GeneratedServerAuthConfig, LeafCertRequest, ServerAuthData, TlsServerConfig},
};
use rama_ua::profile::capture::tls::TlsCapturedExtension;
use rama_utils::octets::kib;
use tokio::io::DuplexStream;

use super::{
    wire::{NonNegotiable, NonNegotiableValues},
    *,
};
use crate::{TlsStream, server::TlsAcceptorService};

const SCSV: u16 = 0x00ff;

fn emitted(config: &TlsClientConfig) -> TlsCapture {
    TlsCapture::capture(
        ProfileCaptureCompleteness::Complete,
        TlsCaptureTransport::Tcp,
        &hello_from_data(TlsConnectorData::try_from(config).unwrap()),
        TlsCaptureLimits::default(),
    )
    .unwrap()
    .with_grease_placeholders()
    .unwrap()
}

fn list(capture: &TlsCapture, id: ExtensionId) -> Vec<u16> {
    capture
        .extensions
        .iter()
        .find_map(|extension| match &extension.value {
            TlsCapturedExtensionValue::U16List(values) if extension.id == u16::from(id) => {
                Some(values.to_vec())
            }
            _ => None,
        })
        .unwrap()
}

fn with_list(mut capture: TlsCapture, id: ExtensionId, values: &[u16]) -> TlsCapture {
    for extension in &mut capture.extensions {
        if extension.id == u16::from(id) {
            extension.value = TlsCapturedExtensionValue::U16List(values.into());
        }
    }
    capture
}

/// `values` with an unsupported value after the first entry and another at the end.
fn spliced(values: &[u16], unsupported: [u16; 2]) -> Vec<u16> {
    let mut spliced = values.to_vec();
    spliced.insert(1, unsupported[0]);
    spliced.push(unsupported[1]);
    spliced
}

#[test]
fn unsupported_ciphers_are_filtered_keeping_order_grease_and_the_renegotiation_scsv() {
    let original = capture();
    let mut offered = spliced(&original.ciphers, [0xfe00, 0xffff]);
    offered.push(SCSV);
    let mut captured = original.clone();
    captured.ciphers = offered.into();
    let (config, report) = compile_tcp(&captured, None).unwrap();
    assert_eq!(lowered(&report), [LoweredProfileItem::TlsCipherSuites]);
    let mut expected = original
        .with_grease_placeholders()
        .unwrap()
        .ciphers
        .to_vec();
    expected.push(SCSV);
    assert_eq!(emitted(&config).ciphers.as_ref(), expected.as_slice());
}

#[test]
fn unsupported_list_values_are_filtered_keeping_order_and_grease() {
    for (id, unsupported, item) in [
        (
            ExtensionId::SUPPORTED_GROUPS,
            // ffdhe4096 and an unassigned group.
            [0x0102, 0xfe00],
            LoweredProfileItem::TlsSupportedGroups,
        ),
        (
            ExtensionId::SIGNATURE_ALGORITHMS,
            // ed448 and rsa_pkcs1_sha224.
            [0x0808, 0x0301],
            LoweredProfileItem::TlsSignatureAlgorithms,
        ),
        (
            ExtensionId::SUPPORTED_VERSIONS,
            // SSL 3.0 and a TLS 1.3 draft.
            [0x0300, 0x7f1c],
            LoweredProfileItem::TlsSupportedVersions,
        ),
    ] {
        let original = capture();
        let offered = list(&original, id);
        let captured = with_list(original.clone(), id, &spliced(&offered, unsupported));
        let (config, report) = compile_tcp(&captured, None).unwrap();
        assert_eq!(lowered(&report), [item], "{id:?}");
        assert_eq!(
            list(&emitted(&config), id),
            list(&original.with_grease_placeholders().unwrap(), id),
            "{id:?}"
        );
    }
}

#[test]
fn a_list_without_negotiable_values_keeps_the_native_list() {
    let mut captured = capture();
    captured.ciphers = vec![0xfe00, SCSV, 0xffff].into();
    let (config, report) = compile_tcp(&captured, None).unwrap();
    assert_eq!(lowered(&report), [LoweredProfileItem::TlsCipherSuites]);
    assert!(emitted(&config).ciphers.contains(&0x1301));

    for (id, unsupported, item) in [
        (
            ExtensionId::SUPPORTED_GROUPS,
            vec![0x0102, 0xfe00],
            LoweredProfileItem::TlsSupportedGroups,
        ),
        (
            ExtensionId::SIGNATURE_ALGORITHMS,
            vec![0x0808, 0x0301],
            LoweredProfileItem::TlsSignatureAlgorithms,
        ),
    ] {
        let captured = with_list(capture(), id, &unsupported);
        let (config, report) = compile_tcp(&captured, None).unwrap();
        assert!(lowered(&report).contains(&item), "{id:?}: {report:?}");
        let sent = list(&emitted(&config), id);
        assert!(!sent.is_empty(), "{id:?}");
        assert!(
            sent.iter().all(|value| !unsupported.contains(value)),
            "{id:?}"
        );
    }
}

/// A native hello offering TLS 1.3 down to TLS 1.0, with suites every version can use.
fn legacy_versions_capture() -> TlsCapture {
    let source = wire_variant()
        .with_cipher_suites(vec![
            CipherSuite::TLS13_AES_128_GCM_SHA256,
            CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
        ])
        .with_supported_versions(vec![
            ProtocolVersion::TLSv1_3,
            ProtocolVersion::TLSv1_2,
            ProtocolVersion::TLSv1_1,
            ProtocolVersion::TLSv1_0,
        ]);
    TlsCapture::capture(
        ProfileCaptureCompleteness::Complete,
        TlsCaptureTransport::Tcp,
        &hello_from_data(TlsConnectorData::try_from(&source).unwrap()),
        TlsCaptureLimits::default(),
    )
    .unwrap()
}

fn server_auth() -> ServerAuthData {
    ServerAuthData::new_generated(GeneratedServerAuthConfig::SelfSignedLeaf(
        LeafCertRequest::default(),
    ))
    .unwrap()
}

/// The version `client` negotiates with a backend server accepting only `version`.
async fn negotiated(client: TlsClientConfig, version: SslVersion) -> Option<SslVersion> {
    handshake(client, version, &[])
        .await
        .and_then(|(version, _)| version)
}

/// The version and group `client` negotiates with a backend server accepting only
/// `version` and, unless empty, only `groups`.
async fn handshake(
    client: TlsClientConfig,
    version: SslVersion,
    groups: &[SslCurve],
) -> Option<(Option<SslVersion>, Option<SslCurve>)> {
    let auth = server_auth();
    let mut server = SslContextBuilder::new(SslMethod::tls_server()).unwrap();
    server
        .set_certificate(&X509::from_der(auth.cert_chain[0].as_ref()).unwrap())
        .unwrap();
    server
        .set_private_key(&PKey::private_key_from_der(auth.private_key.secret_der()).unwrap())
        .unwrap();
    server.set_min_proto_version(Some(version)).unwrap();
    server.set_max_proto_version(Some(version)).unwrap();
    if !groups.is_empty() {
        server.set_curves(groups).unwrap();
    }
    let server = Ssl::new(&server.build()).unwrap();
    let mut data =
        TlsConnectorData::try_from(&client.with_server_verify(ServerVerifyMode::Disable)).unwrap();
    data.server_name = Some(ServerName::from(Domain::from_static("example.test")));
    let (client_io, server_io) = tokio::io::duplex(kib(64));
    let (client, _server) = tokio::join!(
        SslStreamBuilder::new(data.into_ssl().unwrap(), client_io).connect(),
        SslStreamBuilder::new(server, server_io).accept(),
    );
    client
        .ok()
        .map(|stream| (stream.ssl().version(), stream.ssl().curve()))
}

#[test]
fn captured_tls11_and_tls10_offers_are_sent_as_captured() {
    let captured = legacy_versions_capture();
    let versions = list(
        &captured.clone().with_grease_placeholders().unwrap(),
        ExtensionId::SUPPORTED_VERSIONS,
    );
    assert_eq!(versions[1..], [0x0304, 0x0303, 0x0302, 0x0301]);
    let (config, report) = compile_tcp(&captured, None).unwrap();
    assert!(report.is_exact(), "{report:?}");
    assert_eq!(
        list(&emitted(&config), ExtensionId::SUPPORTED_VERSIONS),
        versions
    );
}

#[tokio::test]
async fn captured_tls11_and_tls10_offers_complete_against_servers_limited_to_them() {
    let (config, _report) = compile_tcp(&legacy_versions_capture(), None).unwrap();
    for version in [
        SslVersion::TLS1_3,
        SslVersion::TLS1_2,
        SslVersion::TLS1_1,
        SslVersion::TLS1,
    ] {
        let client = TlsClientConfig::new().with_overrides(config.as_extensions());
        assert_eq!(negotiated(client, version).await, Some(version));
    }
}

#[tokio::test]
async fn a_connector_without_a_profile_still_refuses_tls11_and_tls10() {
    for version in [SslVersion::TLS1_1, SslVersion::TLS1] {
        assert_eq!(negotiated(TlsClientConfig::new(), version).await, None);
    }
    assert_eq!(
        negotiated(TlsClientConfig::new(), SslVersion::TLS1_2).await,
        Some(SslVersion::TLS1_2)
    );
}

#[tokio::test]
async fn an_acceptor_still_refuses_tls11_and_tls10_clients() {
    for version in [SslVersion::TLS1_1, SslVersion::TLS1] {
        let acceptor = TlsAcceptorService::new(
            TlsServerConfig::new().with_server_auth(server_auth()),
            service_fn(|_: TlsStream<ServiceInput<DuplexStream>>| async { Ok::<_, BoxError>(()) }),
            false,
        );
        let mut client = SslConnector::builder(SslMethod::tls_client()).unwrap();
        client.set_verify(SslVerifyMode::NONE);
        client.set_min_proto_version(Some(version)).unwrap();
        client.set_max_proto_version(Some(version)).unwrap();
        let config = client.build().configure().unwrap();
        let (client_io, server_io) = tokio::io::duplex(kib(64));
        let (client, server) = tokio::join!(
            rama_boring_tokio::connect(config, Some("example.test"), client_io),
            acceptor.serve(ServiceInput::new(server_io)),
        );
        assert!(client.is_err() && server.is_err(), "{version:?}");
    }
}

#[test]
fn caller_minimum_version_narrows_a_captured_tls10_offer_and_is_reported() {
    let captured = legacy_versions_capture();
    let caller = TlsClientConfig::new().with_min_version(ProtocolVersion::TLSv1_2);
    let mut report = ProfilePreservationReport::default();
    let compiled = wire::compile_for_policy(
        wire::TransportShape::Tcp,
        &captured,
        &BoringTlsConnectorConfig::from_extensions(caller.as_extensions()),
        wire::NonNegotiableValues::new(),
        &mut report,
    )
    .unwrap();
    assert!(lowered(&report).contains(&LoweredProfileItem::CallerTlsVersionBounds));
    let sent = list(
        &emitted(&caller.with_overrides(compiled.as_extensions())),
        ExtensionId::SUPPORTED_VERSIONS,
    );
    assert!(sent.contains(&0x0303), "{sent:?}");
    assert!(
        !sent.contains(&0x0302) && !sent.contains(&0x0301),
        "{sent:?}"
    );
}

/// The TLS 1.2-only fallback hello embedded Safari profiles carry, as captured.
fn safari_tls12_fallback_capture() -> TlsCapture {
    let extension = |id: u16, value| TlsCapturedExtension { id, value };
    TlsCapture {
        completeness: ProfileCaptureCompleteness::Complete,
        transport: TlsCaptureTransport::Tcp,
        protocol_version: 0x0303,
        ciphers: vec![
            0x00ff, 0xc02c, 0xc02b, 0xc024, 0xc023, 0xc00a, 0xc009, 0xc008, 0xc030, 0xc02f, 0xc028,
            0xc027, 0xc014, 0xc013, 0xc012, 0x009d, 0x009c, 0x003d, 0x003c, 0x0035, 0x002f, 0x000a,
        ]
        .into(),
        compression: vec![0].into(),
        extensions: vec![
            extension(0, TlsCapturedExtensionValue::ServerName { present: true }),
            extension(
                10,
                TlsCapturedExtensionValue::U16List(vec![23, 24, 25].into()),
            ),
            extension(11, TlsCapturedExtensionValue::U8List(vec![0].into())),
            extension(
                13,
                TlsCapturedExtensionValue::U16List(
                    vec![
                        0x0401, 0x0201, 0x0501, 0x0601, 0x0403, 0x0203, 0x0503, 0x0603,
                    ]
                    .into(),
                ),
            ),
            extension(5, TlsCapturedExtensionValue::ConnectionLength(5)),
            extension(18, TlsCapturedExtensionValue::Literal(Box::default())),
            extension(23, TlsCapturedExtensionValue::Literal(Box::default())),
        ]
        .into(),
    }
}

#[tokio::test]
async fn safari_tls12_fallback_hello_is_replayed_exactly() {
    let captured = safari_tls12_fallback_capture();
    let (config, report) = compile_tcp(&captured, None).unwrap();
    assert!(report.is_exact(), "{report:?}");
    let sent = emitted(&config);
    // Same suites with the SCSV first, extended_master_secret without renegotiation_info.
    assert_eq!(replay_form(&sent), replay_form(&captured));
    assert!(
        sent.extensions
            .iter()
            .all(|extension| extension.id != u16::from(ExtensionId::RENEGOTIATION_INFO))
    );
    // The server's renegotiation_info reply is accepted, solicited by the SCSV.
    let client = || TlsClientConfig::new().with_overrides(config.as_extensions());
    assert_eq!(
        negotiated(client(), SslVersion::TLS1_2).await,
        Some(SslVersion::TLS1_2)
    );
    assert_eq!(negotiated(client(), SslVersion::TLS1_3).await, None);
}

fn retain(
    choice: fn(NonNegotiableValues, NonNegotiable) -> NonNegotiableValues,
) -> NonNegotiableValues {
    choice(NonNegotiableValues::new(), NonNegotiable::Retain)
}

#[test]
fn retained_ciphers_are_sent_as_captured_with_grease_and_the_scsv_in_place() {
    let original = capture();
    let mut offered = spliced(&original.ciphers, [0xfe00, 0xffff]);
    offered.insert(0, SCSV);
    let mut captured = original;
    captured.ciphers = offered.into();
    let (config, report) = compile_tcp_with(
        &captured,
        None,
        retain(NonNegotiableValues::with_cipher_suites),
    )
    .unwrap();
    assert_eq!(lowered(&report), [LoweredProfileItem::TlsCipherNegotiation]);
    assert_eq!(
        emitted(&config).ciphers,
        captured.with_grease_placeholders().unwrap().ciphers
    );
}

#[test]
fn retain_legacy_filters_and_reports_nonlegacy_values_in_the_same_offer() {
    let mut captured = capture();
    captured.ciphers = spliced(&captured.ciphers, [0x0004, 0xfe00]).into();
    for (extension, legacy, other) in [
        (ExtensionId::SUPPORTED_GROUPS, 1, 0xfe00),
        (ExtensionId::SIGNATURE_ALGORITHMS, 0x0301, 0x0808),
        (ExtensionId::SUPPORTED_VERSIONS, 0x0300, 0x7f1c),
    ] {
        let offered = list(&captured, extension);
        captured = with_list(captured, extension, &spliced(&offered, [legacy, other]));
    }
    let (config, report) = compile_tcp_with(
        &captured,
        None,
        NonNegotiableValues::all(NonNegotiable::RetainLegacy),
    )
    .unwrap();
    let wire = emitted(&config);
    let normalized = captured.with_grease_placeholders().unwrap();
    let without = |values: &[u16], other| {
        values
            .iter()
            .copied()
            .filter(|&value| value != other)
            .collect::<Vec<_>>()
    };
    assert_eq!(wire.ciphers.as_ref(), without(&normalized.ciphers, 0xfe00));
    for (extension, other) in [
        (ExtensionId::SUPPORTED_GROUPS, 0xfe00),
        (ExtensionId::SIGNATURE_ALGORITHMS, 0x0808),
        (ExtensionId::SUPPORTED_VERSIONS, 0x7f1c),
    ] {
        assert_eq!(
            list(&wire, extension),
            without(&list(&normalized, extension), other)
        );
    }
    let items = lowered(&report);
    for item in [
        LoweredProfileItem::TlsCipherSuites,
        LoweredProfileItem::TlsCipherNegotiation,
        LoweredProfileItem::TlsSupportedGroups,
        LoweredProfileItem::TlsGroupNegotiation,
        LoweredProfileItem::TlsSignatureAlgorithms,
        LoweredProfileItem::TlsSignatureAlgorithmNegotiation,
        LoweredProfileItem::TlsSupportedVersions,
        LoweredProfileItem::TlsVersionNegotiation,
    ] {
        assert!(items.contains(&item), "{item:?}: {items:?}");
    }
}

#[test]
fn legacy_only_cipher_suites_cannot_prevent_native_fallback() {
    let mut captured = capture();
    captured.ciphers = Box::new([0x0004, SCSV]);
    let (config, report) = compile_tcp_with(
        &captured,
        None,
        NonNegotiableValues::new().with_cipher_suites(NonNegotiable::RetainLegacy),
    )
    .unwrap();
    assert_eq!(lowered(&report), [LoweredProfileItem::TlsCipherSuites]);
    assert!(emitted(&config).ciphers.contains(&0x1301));
}

#[test]
fn retained_lists_are_sent_as_captured() {
    for (id, unsupported, choice, item) in [
        (
            ExtensionId::SUPPORTED_GROUPS,
            [0x0102, 0xfe00],
            retain(NonNegotiableValues::with_supported_groups),
            LoweredProfileItem::TlsGroupNegotiation,
        ),
        (
            ExtensionId::SIGNATURE_ALGORITHMS,
            [0x0808, 0x0301],
            retain(NonNegotiableValues::with_signature_algorithms),
            LoweredProfileItem::TlsSignatureAlgorithmNegotiation,
        ),
        (
            ExtensionId::SUPPORTED_VERSIONS,
            [0x0300, 0x7f1c],
            retain(NonNegotiableValues::with_supported_versions),
            LoweredProfileItem::TlsVersionNegotiation,
        ),
    ] {
        let original = capture();
        let offered = list(&original, id);
        let captured = with_list(original, id, &spliced(&offered, unsupported));
        let (config, report) = compile_tcp_with(&captured, None, choice).unwrap();
        assert_eq!(lowered(&report), [item], "{id:?}");
        assert_eq!(
            list(&emitted(&config), id),
            list(&captured.with_grease_placeholders().unwrap(), id),
            "{id:?}"
        );
    }
}

#[tokio::test]
async fn retained_versions_without_grease_are_sent_as_captured_and_still_negotiate() {
    let captured = with_list(
        legacy_versions_capture(),
        ExtensionId::SUPPORTED_VERSIONS,
        &[0x0304, 0x0303, 0x0300],
    );
    let (config, report) = compile_tcp_with(
        &captured,
        None,
        retain(NonNegotiableValues::with_supported_versions),
    )
    .unwrap();
    assert_eq!(
        lowered(&report),
        [LoweredProfileItem::TlsVersionNegotiation]
    );
    assert_eq!(
        list(&emitted(&config), ExtensionId::SUPPORTED_VERSIONS),
        [0x0304, 0x0303, 0x0300]
    );
    let client = TlsClientConfig::new().with_overrides(config.as_extensions());
    assert_eq!(
        negotiated(client, SslVersion::TLS1_2).await,
        Some(SslVersion::TLS1_2)
    );
}

#[test]
fn the_choice_is_per_list() {
    let original = capture();
    let mut captured = with_list(
        original.clone(),
        ExtensionId::SUPPORTED_GROUPS,
        &spliced(
            &list(&original, ExtensionId::SUPPORTED_GROUPS),
            [0x0102, 0xfe00],
        ),
    );
    captured.ciphers = spliced(&original.ciphers, [0xfe00, 0xffff]).into();
    let (config, report) = compile_tcp_with(
        &captured,
        None,
        retain(NonNegotiableValues::with_cipher_suites),
    )
    .unwrap();
    assert_eq!(
        lowered(&report),
        [
            LoweredProfileItem::TlsCipherNegotiation,
            LoweredProfileItem::TlsSupportedGroups
        ]
    );
    let sent = emitted(&config);
    let captured = captured.with_grease_placeholders().unwrap();
    assert_eq!(sent.ciphers, captured.ciphers);
    assert_eq!(
        list(&sent, ExtensionId::SUPPORTED_GROUPS),
        list(
            &original.with_grease_placeholders().unwrap(),
            ExtensionId::SUPPORTED_GROUPS
        )
    );
}

#[test]
fn a_retained_list_without_negotiable_values_keeps_the_native_list() {
    let mut captured = capture();
    captured.ciphers = vec![0xfe00, SCSV, 0xffff].into();
    let (config, report) = compile_tcp_with(
        &captured,
        None,
        NonNegotiableValues::all(NonNegotiable::Retain),
    )
    .unwrap();
    assert_eq!(lowered(&report), [LoweredProfileItem::TlsCipherSuites]);
    assert!(emitted(&config).ciphers.contains(&0x1301));
}

#[test]
fn the_profile_compiler_filters_unless_told_to_retain() {
    let mut captured = capture();
    captured.ciphers = spliced(&captured.ciphers, [0xfe00, 0xffff]).into();
    for (compiler, item) in [
        (
            ConnectionProfileCompiler::new(TlsClientConfig::new()),
            LoweredProfileItem::TlsCipherSuites,
        ),
        (
            ConnectionProfileCompiler::new(TlsClientConfig::new())
                .with_non_negotiable_values(retain(NonNegotiableValues::with_cipher_suites)),
            LoweredProfileItem::TlsCipherNegotiation,
        ),
    ] {
        let (_, report) = prepare(&compiler, &input(), &captured).unwrap();
        assert!(lowered(&report).contains(&item), "{report:?}");
    }
}

#[tokio::test]
async fn captured_ffdhe_groups_are_sent_as_captured_and_negotiate_over_tls13() {
    let original = capture();
    let mut groups = list(&original, ExtensionId::SUPPORTED_GROUPS);
    groups.extend([0x0100, 0x0101]);
    let captured = with_list(original, ExtensionId::SUPPORTED_GROUPS, &groups);
    let (config, report) = compile_tcp(&captured, None).unwrap();
    assert!(report.is_exact(), "{report:?}");
    assert_eq!(
        list(&emitted(&config), ExtensionId::SUPPORTED_GROUPS),
        list(
            &captured.with_grease_placeholders().unwrap(),
            ExtensionId::SUPPORTED_GROUPS
        )
    );
    let client = TlsClientConfig::new().with_overrides(config.as_extensions());
    assert_eq!(
        handshake(client, SslVersion::TLS1_3, &[SslCurve::FFDHE2048]).await,
        Some((Some(SslVersion::TLS1_3), Some(SslCurve::FFDHE2048)))
    );
}

/// `capture()` sending extended_master_secret and renegotiation_info as listed.
fn with_legacy_extensions(ems: bool, ri: bool) -> TlsCapture {
    let source = crate::client::tests::wire_variant().with_legacy_extensions(true);
    let mut captured = TlsCapture::capture(
        ProfileCaptureCompleteness::Complete,
        TlsCaptureTransport::Tcp,
        &hello_from_data(TlsConnectorData::try_from(&source).unwrap()),
        TlsCaptureLimits::default(),
    )
    .unwrap();
    let keep = |id: u16| {
        (ems || id != u16::from(ExtensionId::EXTENDED_MASTER_SECRET))
            && (ri || id != u16::from(ExtensionId::RENEGOTIATION_INFO))
    };
    captured.extensions = captured
        .extensions
        .into_vec()
        .into_iter()
        .filter(|extension| keep(extension.id))
        .collect();
    captured
}

#[test]
fn extended_master_secret_without_renegotiation_info_is_replayed_exactly() {
    let captured = with_legacy_extensions(true, false);
    let (config, report) = compile_tcp(&captured, None).unwrap();
    assert!(report.is_exact(), "{report:?}");
    assert_eq!(replay_form(&emitted(&config)), replay_form(&captured));
}

#[test]
fn renegotiation_info_without_extended_master_secret_is_reported() {
    let captured = with_legacy_extensions(false, true);
    let (config, report) = compile_tcp(&captured, None).unwrap();
    assert_eq!(
        lowered(&report),
        [LoweredProfileItem::TlsLegacyExtensionPair]
    );
    let sent = emitted(&config);
    for id in [
        ExtensionId::EXTENDED_MASTER_SECRET,
        ExtensionId::RENEGOTIATION_INFO,
    ] {
        assert!(
            sent.extensions
                .iter()
                .any(|extension| extension.id == u16::from(id))
        );
    }
}

#[tokio::test]
async fn a_sparse_version_list_is_sent_as_captured_and_never_negotiates_the_gap() {
    let captured = with_list(
        legacy_versions_capture(),
        ExtensionId::SUPPORTED_VERSIONS,
        &[0x0304, 0x0302],
    );
    let (config, report) = compile_tcp(&captured, None).unwrap();
    assert!(report.is_exact(), "{report:?}");
    assert_eq!(
        list(&emitted(&config), ExtensionId::SUPPORTED_VERSIONS),
        [0x0304, 0x0302]
    );
    let client = || TlsClientConfig::new().with_overrides(config.as_extensions());
    assert_eq!(negotiated(client(), SslVersion::TLS1_2).await, None);
    assert_eq!(
        negotiated(client(), SslVersion::TLS1_1).await,
        Some(SslVersion::TLS1_1)
    );
}

#[test]
fn finite_field_groups_are_not_negotiable_in_a_tls12_only_offer() {
    let fallback = safari_tls12_fallback_capture();
    let captured = with_list(
        fallback.clone(),
        ExtensionId::SUPPORTED_GROUPS,
        &[0x0100, 0x0017],
    );
    let (config, report) = compile_tcp(&captured, None).unwrap();
    assert_eq!(lowered(&report), [LoweredProfileItem::TlsSupportedGroups]);
    assert_eq!(
        list(&emitted(&config), ExtensionId::SUPPORTED_GROUPS),
        [0x0017]
    );

    let captured = with_list(fallback, ExtensionId::SUPPORTED_GROUPS, &[0x0100, 0x0101]);
    let (config, report) = compile_tcp(&captured, None).unwrap();
    assert_eq!(lowered(&report), [LoweredProfileItem::TlsSupportedGroups]);
    let sent = list(&emitted(&config), ExtensionId::SUPPORTED_GROUPS);
    assert!(!sent.is_empty() && !sent.contains(&0x0100) && !sent.contains(&0x0101));
}

fn without_extension(mut captured: TlsCapture, id: ExtensionId) -> TlsCapture {
    captured.extensions = captured
        .extensions
        .into_vec()
        .into_iter()
        .filter(|extension| extension.id != u16::from(id))
        .collect();
    captured
}

fn sends(sent: &TlsCapture, id: ExtensionId) -> bool {
    sent.extensions
        .iter()
        .any(|extension| extension.id == u16::from(id))
}

#[test]
fn a_native_fallback_cipher_list_keeps_renegotiation_info_for_the_lost_scsv() {
    let mut captured = safari_tls12_fallback_capture();
    captured.ciphers = vec![SCSV, 0xfe00, 0xffff].into();
    let (config, report) = compile_tcp(&captured, None).unwrap();
    assert_eq!(
        lowered(&report),
        [
            LoweredProfileItem::TlsCipherSuites,
            LoweredProfileItem::TlsLegacyExtensionPair
        ]
    );
    let sent = emitted(&config);
    assert!(!sent.ciphers.contains(&SCSV));
    assert!(sends(&sent, ExtensionId::EXTENDED_MASTER_SECRET));
    assert!(sends(&sent, ExtensionId::RENEGOTIATION_INFO));
}

#[test]
fn a_tls12_offer_without_legacy_extensions_is_reported_and_omits_renegotiation_info() {
    let captured = without_extension(
        safari_tls12_fallback_capture(),
        ExtensionId::EXTENDED_MASTER_SECRET,
    );
    let (config, report) = compile_tcp(&captured, None).unwrap();
    assert_eq!(
        lowered(&report),
        [LoweredProfileItem::TlsLegacyExtensionPair]
    );
    let sent = emitted(&config);
    // The backend always sends extended_master_secret below a TLS 1.3 minimum.
    assert!(sends(&sent, ExtensionId::EXTENDED_MASTER_SECRET));
    assert!(!sends(&sent, ExtensionId::RENEGOTIATION_INFO));
    assert_eq!(sent.ciphers, captured.ciphers);
}

#[tokio::test]
async fn a_tls11_psk_only_offer_falls_back_to_native_suites() {
    let mut captured = without_extension(
        safari_tls12_fallback_capture(),
        ExtensionId::SIGNATURE_ALGORITHMS,
    );
    captured.protocol_version = 0x0302;
    captured.ciphers = vec![0x008c].into();
    let (config, report) = compile_tcp(&captured, None).unwrap();
    assert_eq!(lowered(&report), [LoweredProfileItem::TlsCipherSuites]);
    assert!(!emitted(&config).ciphers.contains(&0x008c));
    let client = TlsClientConfig::new().with_overrides(config.as_extensions());
    assert_eq!(
        negotiated(client, SslVersion::TLS1_1).await,
        Some(SslVersion::TLS1_1)
    );
}

#[tokio::test]
async fn a_legacy_tls11_hello_offers_only_tls11() {
    let mut captured = without_extension(
        safari_tls12_fallback_capture(),
        ExtensionId::SIGNATURE_ALGORITHMS,
    );
    captured.protocol_version = 0x0302;
    let (config, report) = compile_tcp(&captured, None).unwrap();
    // Suites needing TLS 1.2 cannot negotiate at TLS 1.1.
    assert_eq!(lowered(&report), [LoweredProfileItem::TlsCipherSuites]);
    captured.ciphers = vec![
        SCSV, 0xc00a, 0xc009, 0xc008, 0xc014, 0xc013, 0xc012, 0x0035, 0x002f, 0x000a,
    ]
    .into();
    // Legacy version 0x0302 and no supported_versions, exactly as captured.
    assert_eq!(replay_form(&emitted(&config)), replay_form(&captured));
    let client = || TlsClientConfig::new().with_overrides(config.as_extensions());
    assert_eq!(negotiated(client(), SslVersion::TLS1_2).await, None);
    assert_eq!(
        negotiated(client(), SslVersion::TLS1_1).await,
        Some(SslVersion::TLS1_1)
    );

    // Native TLS sends no signature_algorithms below TLS 1.2.
    captured.extensions = safari_tls12_fallback_capture().extensions;
    let (config, report) = compile_tcp(&captured, None).unwrap();
    assert_eq!(
        lowered(&report),
        [LoweredProfileItem::TlsExtension {
            extension: ExtensionId::SIGNATURE_ALGORITHMS.into()
        }]
    );
    assert!(!sends(&emitted(&config), ExtensionId::SIGNATURE_ALGORITHMS));
}

const GREASE: u16 = 0x0a0a;

/// The emitted supported_versions list, GREASE slots as placeholders.
fn sent_versions(config: &TlsClientConfig) -> Option<Vec<u16>> {
    emitted(config)
        .extensions
        .iter()
        .find_map(|extension| match &extension.value {
            TlsCapturedExtensionValue::U16List(values)
                if extension.id == u16::from(ExtensionId::SUPPORTED_VERSIONS) =>
            {
                Some(values.to_vec())
            }
            _ => None,
        })
}

fn placeholders(values: &[u16]) -> Vec<u16> {
    let captured = with_list(capture(), ExtensionId::SUPPORTED_VERSIONS, values);
    list(
        &captured.with_grease_placeholders().unwrap(),
        ExtensionId::SUPPORTED_VERSIONS,
    )
}

#[test]
fn caller_bounds_are_checked_against_the_negotiable_offer() {
    let captured = with_list(
        legacy_versions_capture(),
        ExtensionId::SUPPORTED_VERSIONS,
        &[0x0304, 0x0300, GREASE, 0x0303],
    );
    let compile = |min| {
        let caller = TlsClientConfig::new().with_min_version(min);
        let mut report = ProfilePreservationReport::default();
        let compiled = wire::compile_for_policy(
            wire::TransportShape::Tcp,
            &captured,
            &BoringTlsConnectorConfig::from_extensions(caller.as_extensions()),
            NonNegotiableValues::new(),
            &mut report,
        )
        .unwrap();
        (caller.with_overrides(compiled.as_extensions()), report)
    };
    // SSL 3.0 is filtered anyway: no conflict, GREASE keeps its place.
    let (config, report) = compile(ProtocolVersion::TLSv1_2);
    assert_eq!(lowered(&report), [LoweredProfileItem::TlsSupportedVersions]);
    assert_eq!(
        sent_versions(&config),
        Some(placeholders(&[0x0304, GREASE, 0x0303]))
    );
    // A negotiable listed version below the caller's minimum is a real conflict.
    let (_, report) = compile(ProtocolVersion::TLSv1_3);
    assert!(lowered(&report).contains(&LoweredProfileItem::CallerTlsVersionBounds));
}

#[test]
fn grease_and_gaps_keep_their_positions() {
    for values in [
        vec![0x0304, GREASE, 0x0303],
        vec![0x0304, 0x0303, GREASE],
        vec![0x0302, 0x0304],
    ] {
        let captured = with_list(
            legacy_versions_capture(),
            ExtensionId::SUPPORTED_VERSIONS,
            &values,
        );
        let (config, report) = compile_tcp(&captured, None).unwrap();
        assert!(report.is_exact(), "{values:x?}: {report:?}");
        assert_eq!(
            sent_versions(&config),
            Some(placeholders(&values)),
            "{values:x?}"
        );
    }
}

#[tokio::test]
async fn a_version_list_without_tls13_bounds_the_offer_and_reports_the_missing_extension() {
    let captured = with_list(
        legacy_versions_capture(),
        ExtensionId::SUPPORTED_VERSIONS,
        &[0x0303, 0x0302],
    );
    let (config, report) = compile_tcp(&captured, None).unwrap();
    // The engine sends no supported_versions without a TLS 1.3 maximum, and the
    // TLS 1.3 suite cannot negotiate.
    assert_eq!(
        lowered(&report),
        [
            LoweredProfileItem::TlsCipherSuites,
            LoweredProfileItem::TlsSupportedVersions
        ]
    );
    assert_eq!(sent_versions(&config), None);
    let client = || TlsClientConfig::new().with_overrides(config.as_extensions());
    assert_eq!(negotiated(client(), SslVersion::TLS1_3).await, None);
    assert_eq!(
        negotiated(client(), SslVersion::TLS1_2).await,
        Some(SslVersion::TLS1_2)
    );
    assert_eq!(
        negotiated(client(), SslVersion::TLS1_1).await,
        Some(SslVersion::TLS1_1)
    );
}

/// Compile `captured` for a caller whose maximum is TLS 1.2, and emit its hello.
fn compile_tls12_caller(captured: &TlsCapture) -> (TlsCapture, Vec<LoweredProfileItem>) {
    let caller = TlsClientConfig::new().with_max_version(ProtocolVersion::TLSv1_2);
    let mut report = ProfilePreservationReport::default();
    let compiled = wire::compile_for_policy(
        wire::TransportShape::Tcp,
        captured,
        &BoringTlsConnectorConfig::from_extensions(caller.as_extensions()),
        NonNegotiableValues::new(),
        &mut report,
    )
    .unwrap();
    (
        emitted(&caller.with_overrides(compiled.as_extensions())),
        lowered(&report),
    )
}

#[test]
fn caller_bounds_decide_which_groups_and_suites_can_negotiate() {
    // FFDHE groups are TLS 1.3 key shares only: a TLS 1.2 caller keeps the native list.
    let captured = with_list(capture(), ExtensionId::SUPPORTED_GROUPS, &[0x0100]);
    let (sent, report) = compile_tls12_caller(&captured);
    assert!(report.contains(&LoweredProfileItem::CallerTlsVersionBounds));
    assert!(report.contains(&LoweredProfileItem::TlsSupportedGroups));
    let groups = list(&sent, ExtensionId::SUPPORTED_GROUPS);
    assert!(
        !groups.is_empty() && !groups.contains(&0x0100),
        "{groups:x?}"
    );

    // A capture offering only TLS 1.3 suites keeps the native list too.
    let mut captured = capture();
    captured.ciphers = vec![0x1301, 0x1302].into();
    let (sent, report) = compile_tls12_caller(&captured);
    assert!(report.contains(&LoweredProfileItem::TlsCipherSuites));
    assert!(
        sent.ciphers
            .iter()
            .any(|&suite| suite == 0xc02f || suite == 0xc02b)
    );
}

#[test]
fn caller_bounds_without_tls13_drop_captured_alps() {
    let mut captured = capture();
    let mut extensions = captured.extensions.into_vec();
    extensions.push(TlsCapturedExtension {
        id: ExtensionId::APPLICATION_SETTINGS.into(),
        value: TlsCapturedExtensionValue::Protocols(vec![b"h2".to_vec().into()].into()),
    });
    captured.extensions = extensions.into();
    let (sent, report) = compile_tls12_caller(&captured);
    assert!(report.contains(&LoweredProfileItem::TlsAlps), "{report:?}");
    assert!(!sends(&sent, ExtensionId::APPLICATION_SETTINGS));
}
