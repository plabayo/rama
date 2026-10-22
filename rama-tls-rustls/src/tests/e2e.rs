use rama_core::conversion::RamaTryFrom;
use rama_core::{Layer, Service as _, ServiceInput};
use rama_crypto::cert::generate_server_auth;
use rama_crypto::pki_types::{CertificateDer, ServerName};
use rama_net::{address::Host, stream::service::EchoService};
use rama_tls::{
    client::{
        DistrustedServerKeys, DynTlsServerCertChainPolicy, ServerCertChain, ServerCertChainKind,
        ServerVerifyMode, TlsClientConfig, TlsServerCertChainPolicy, TlsServerCertPin,
        TlsServerCertPinSet, TlsServerCertPins, TlsServerTrust, TlsServerTrustAnchors,
    },
    server::{
        CertificateIdentity, GeneratedServerAuthConfig, LeafCertRequest, SelfSignedCaConfig,
        ServerAuthData, TlsServerConfig,
    },
};

use crate::client::{RustlsTlsConnectorConfig, TlsConnectorData};
use crate::dep::tokio_rustls::TlsConnector as RustlsConnector;
use crate::server::TlsAcceptorLayer;

async fn connect_to_pinned_server(
    matching_pin: bool,
    server_verify_mode: ServerVerifyMode,
    server_name: Host,
) -> bool {
    connect_to_pinned_server_with_pins(server_verify_mode, server_name, move |cert_chain| {
        if matching_pin {
            TlsServerCertPins::new(
                TlsServerCertPinSet::try_new([
                    CertificateDer::from(vec![9, 9, 9]),
                    cert_chain[0].clone(),
                ])
                .unwrap(),
            )
        } else {
            TlsServerCertPins::new(CertificateDer::from(vec![1, 2, 3]))
        }
    })
    .await
}

async fn connect_to_pinned_server_with_pins<F>(
    server_verify_mode: ServerVerifyMode,
    server_name: Host,
    make_pins: F,
) -> bool
where
    F: FnOnce(&[CertificateDer<'static>]) -> TlsServerCertPins,
{
    connect_to_pinned_server_with_auth(
        GeneratedServerAuthConfig::default(),
        server_verify_mode,
        server_name,
        make_pins,
    )
    .await
}

async fn connect_to_pinned_server_with_auth<F>(
    generated_auth: GeneratedServerAuthConfig,
    server_verify_mode: ServerVerifyMode,
    server_name: Host,
    make_pins: F,
) -> bool
where
    F: FnOnce(&[CertificateDer<'static>]) -> TlsServerCertPins,
{
    crate::ensure_default_crypto_provider();

    let (cert_chain, private_key) =
        generate_server_auth(generated_auth).expect("generated server auth");
    let trust_anchor = cert_chain.last().expect("certificate chain").clone();
    let pins = make_pins(&cert_chain);
    let server = TlsAcceptorLayer::new(TlsServerConfig::new().with_single_cert(ServerAuthData {
        cert_chain,
        private_key,
        ocsp: None,
    }))
    .into_layer(EchoService::new());

    let client_config = TlsClientConfig::new()
        .with_server_name(server_name.clone())
        .with_server_cert_pins(pins)
        .with_server_verify(server_verify_mode)
        .try_with_server_trust_anchors([trust_anchor])
        .unwrap();
    let connector_data = TlsConnectorData::try_from(RustlsTlsConnectorConfig::from_extensions(
        client_config.as_extensions(),
    ))
    .expect("client connector data");

    let (stream_client, stream_server) = tokio::io::duplex(usize::MAX);
    let handle = tokio::spawn(async move { server.serve(ServiceInput::new(stream_server)).await });
    let connector = RustlsConnector::from(connector_data.client_config);
    let tls_server_name = ServerName::rama_try_from(server_name).expect("tls server name");
    let connected = connector
        .connect(tls_server_name, stream_client)
        .await
        .is_ok();
    drop(handle.await);
    connected
}

async fn connect_to_server_with_trust<F>(make_trust: F) -> bool
where
    F: FnOnce(&[CertificateDer<'static>]) -> TlsServerTrust,
{
    crate::ensure_default_crypto_provider();

    let (cert_chain, private_key) =
        generate_server_auth(GeneratedServerAuthConfig::default()).expect("generated server auth");
    let trust = make_trust(&cert_chain);
    let server = TlsAcceptorLayer::new(TlsServerConfig::new().with_single_cert(ServerAuthData {
        cert_chain,
        private_key,
        ocsp: None,
    }))
    .into_layer(EchoService::new());
    let server_name = Host::from_static("localhost");
    let client_config = TlsClientConfig::new()
        .with_server_name(server_name.clone())
        .with_server_trust(trust);
    let connector_data = TlsConnectorData::try_from(RustlsTlsConnectorConfig::from_extensions(
        client_config.as_extensions(),
    ))
    .expect("client connector data");

    let (stream_client, stream_server) = tokio::io::duplex(usize::MAX);
    let handle = tokio::spawn(async move { server.serve(ServiceInput::new(stream_server)).await });
    let connector = RustlsConnector::from(connector_data.client_config);
    let tls_server_name = ServerName::rama_try_from(server_name).expect("tls server name");
    let connected = connector
        .connect(tls_server_name, stream_client)
        .await
        .is_ok();
    drop(handle.await);
    connected
}

#[tokio::test]
async fn builtin_roots_reject_a_private_ca() {
    assert!(!connect_to_server_with_trust(|_| TlsServerTrust::native_roots()).await);
    assert!(!connect_to_server_with_trust(|_| TlsServerTrust::webpki_roots()).await);
}

#[tokio::test]
async fn additional_anchor_extends_native_and_webpki_roots() {
    assert!(
        connect_to_server_with_trust(|chain| {
            TlsServerTrust::native_roots()
                .try_with_additional_anchors([chain.last().unwrap().clone()])
                .unwrap()
        })
        .await
    );
    assert!(
        connect_to_server_with_trust(|chain| {
            TlsServerTrust::webpki_roots()
                .try_with_additional_anchors([chain.last().unwrap().clone()])
                .unwrap()
        })
        .await
    );
}

#[tokio::test]
async fn self_signed_leaf_verifies_when_directly_trusted() {
    assert!(
        connect_to_pinned_server_with_auth(
            GeneratedServerAuthConfig::SelfSignedLeaf(LeafCertRequest::default()),
            ServerVerifyMode::Auto,
            Host::from_static("localhost"),
            |cert_chain| TlsServerCertPins::new(cert_chain[0].clone()),
        )
        .await
    );
}

#[tokio::test]
async fn matching_server_cert_pin_connects() {
    assert!(
        connect_to_pinned_server(true, ServerVerifyMode::Auto, Host::from_static("localhost"))
            .await
    );
}

#[tokio::test]
async fn mismatched_server_cert_pin_is_rejected() {
    assert!(
        !connect_to_pinned_server(
            false,
            ServerVerifyMode::Auto,
            Host::from_static("localhost")
        )
        .await
    );
}

#[tokio::test]
async fn matching_server_cert_pin_still_checks_server_name() {
    assert!(
        !connect_to_pinned_server(
            true,
            ServerVerifyMode::Auto,
            Host::from_static("wrong.example")
        )
        .await
    );
}

#[tokio::test]
async fn matching_server_cert_pin_connects_without_child_verification() {
    assert!(
        connect_to_pinned_server(
            true,
            ServerVerifyMode::Disable,
            Host::from_static("localhost")
        )
        .await
    );
}

#[tokio::test]
async fn mismatched_server_cert_pin_is_rejected_without_child_verification() {
    assert!(
        !connect_to_pinned_server(
            false,
            ServerVerifyMode::Disable,
            Host::from_static("localhost")
        )
        .await
    );
}

#[tokio::test]
async fn unrelated_scoped_pin_set_delegates_to_default_verification() {
    assert!(
        connect_to_pinned_server_with_pins(
            ServerVerifyMode::Auto,
            Host::from_static("localhost"),
            |_| TlsServerCertPins::new(
                TlsServerCertPinSet::new(CertificateDer::from(vec![1, 2, 3]))
                    .with_server_name(Host::from_static("other.example"))
            ),
        )
        .await
    );
}

#[tokio::test]
async fn matching_any_applicable_pin_set_connects() {
    assert!(
        connect_to_pinned_server_with_pins(
            ServerVerifyMode::Auto,
            Host::from_static("localhost"),
            |cert_chain| TlsServerCertPins::new(
                TlsServerCertPinSet::new(CertificateDer::from(vec![1, 2, 3]))
                    .with_server_name(Host::from_static("localhost"))
            )
            .with_pin_set(
                TlsServerCertPinSet::new(cert_chain[0].clone())
                    .with_server_name(Host::from_static("localhost"))
            ),
        )
        .await
    );
}

#[tokio::test]
async fn matching_scoped_pin_set_rejects_a_mismatch() {
    assert!(
        !connect_to_pinned_server_with_pins(
            ServerVerifyMode::Auto,
            Host::from_static("localhost"),
            |_| TlsServerCertPins::new(
                TlsServerCertPinSet::new(CertificateDer::from(vec![1, 2, 3]))
                    .with_server_name(Host::from_static("localhost"))
            ),
        )
        .await
    );
}

#[tokio::test]
async fn unrelated_scoped_pin_set_is_not_a_check_when_verification_is_disabled() {
    assert!(
        connect_to_pinned_server_with_pins(
            ServerVerifyMode::Disable,
            Host::from_static("localhost"),
            |_| TlsServerCertPins::new(
                TlsServerCertPinSet::new(CertificateDer::from(vec![1, 2, 3]))
                    .with_server_name(Host::from_static("other.example"))
            ),
        )
        .await
    );
}

#[tokio::test]
async fn matching_spki_pin_connects() {
    assert!(
        connect_to_pinned_server_with_pins(
            ServerVerifyMode::Auto,
            Host::from_static("localhost"),
            |cert_chain| TlsServerCertPins::new(
                TlsServerCertPin::spki_sha256_of(&cert_chain[0]).unwrap()
            ),
        )
        .await
    );
}

#[tokio::test]
async fn mismatched_spki_pin_is_rejected() {
    assert!(
        !connect_to_pinned_server_with_pins(
            ServerVerifyMode::Auto,
            Host::from_static("localhost"),
            |cert_chain| TlsServerCertPins::new(
                // the CA's key pin does not match the leaf's key
                TlsServerCertPin::spki_sha256_of(&cert_chain[1]).unwrap()
            ),
        )
        .await
    );
}

#[tokio::test]
async fn matching_spki_pin_connects_without_child_verification() {
    assert!(
        connect_to_pinned_server_with_pins(
            ServerVerifyMode::Disable,
            Host::from_static("localhost"),
            |cert_chain| TlsServerCertPins::new(
                TlsServerCertPin::spki_sha256_of(&cert_chain[0]).unwrap()
            ),
        )
        .await
    );
}

async fn connect_with_config<F>(
    generated_auth: GeneratedServerAuthConfig,
    server_name: Host,
    make_config: F,
) -> bool
where
    F: FnOnce(&[CertificateDer<'static>]) -> TlsClientConfig,
{
    crate::ensure_default_crypto_provider();

    let (cert_chain, private_key) =
        generate_server_auth(generated_auth).expect("generated server auth");
    let client_config = make_config(&cert_chain).with_server_name(server_name.clone());
    let server = TlsAcceptorLayer::new(TlsServerConfig::new().with_single_cert(ServerAuthData {
        cert_chain,
        private_key,
        ocsp: None,
    }))
    .into_layer(EchoService::new());
    let connector_data = TlsConnectorData::try_from(RustlsTlsConnectorConfig::from_extensions(
        client_config.as_extensions(),
    ))
    .expect("client connector data");

    let (stream_client, stream_server) = tokio::io::duplex(usize::MAX);
    let handle = tokio::spawn(async move { server.serve(ServiceInput::new(stream_server)).await });
    let connector = RustlsConnector::from(connector_data.client_config);
    let tls_server_name = ServerName::rama_try_from(server_name).expect("tls server name");
    let connected = connector
        .connect(tls_server_name, stream_client)
        .await
        .is_ok();
    drop(handle.await);
    connected
}

fn platform_trusting(chain: &[CertificateDer<'static>]) -> TlsServerTrust {
    TlsServerTrust::platform_verifier()
        .try_with_additional_anchors([chain.last().unwrap().clone()])
        .unwrap()
}

#[tokio::test]
async fn platform_verifier_rejects_a_private_ca() {
    assert!(!connect_to_server_with_trust(|_| TlsServerTrust::platform_verifier()).await);
}

#[tokio::test]
async fn platform_verifier_trusts_additional_anchors() {
    assert!(connect_to_server_with_trust(platform_trusting).await);
}

#[tokio::test]
async fn platform_verifier_rejects_a_mismatched_server_name() {
    assert!(
        !connect_with_config(
            GeneratedServerAuthConfig::default(),
            Host::from_static("other.example.com"),
            |chain| TlsClientConfig::new().with_server_trust(platform_trusting(chain)),
        )
        .await
    );
}

#[tokio::test]
async fn platform_verifier_matches_ip_identities() {
    let ip_auth = || GeneratedServerAuthConfig::GeneratedCa {
        ca: SelfSignedCaConfig::default(),
        leaf: LeafCertRequest {
            identities: vec![CertificateIdentity::Ip(
                std::net::Ipv4Addr::LOCALHOST.into(),
            )],
            ..Default::default()
        },
    };
    let platform = |chain: &[CertificateDer<'static>]| {
        TlsClientConfig::new().with_server_trust(platform_trusting(chain))
    };
    assert!(
        connect_with_config(
            ip_auth(),
            Host::from(std::net::Ipv4Addr::LOCALHOST),
            platform
        )
        .await
    );
    assert!(
        !connect_with_config(
            ip_auth(),
            Host::from(std::net::Ipv4Addr::new(127, 0, 0, 2)),
            platform
        )
        .await
    );
}

/// Records the first chain it sees and how often it ran.
#[derive(Debug, Clone, Default)]
struct RecordingChainPolicy {
    first: std::sync::Arc<std::sync::OnceLock<(ServerCertChainKind, usize)>>,
    runs: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl TlsServerCertChainPolicy for RecordingChainPolicy {
    fn check(&self, chain: &ServerCertChain<'_>) -> Result<(), rama_core::error::BoxError> {
        self.runs.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        _ = self.first.set((chain.kind(), chain.certificates().len()));
        Ok(())
    }
}

fn distrusting(certificate: &CertificateDer<'_>) -> DynTlsServerCertChainPolicy {
    DynTlsServerCertChainPolicy::new(
        DistrustedServerKeys::new()
            .try_with_key_of(certificate)
            .unwrap(),
    )
}

#[tokio::test]
async fn distrusted_ca_key_rejects_chains_under_every_trust_source() {
    type MakeTrust = fn(&[CertificateDer<'static>]) -> TlsServerTrust;
    let sources: [(&str, MakeTrust); 3] = [
        ("custom", |chain| {
            TlsServerTrust::custom(
                TlsServerTrustAnchors::try_new([chain.last().unwrap().clone()]).unwrap(),
            )
        }),
        ("native", |chain| {
            TlsServerTrust::native_roots()
                .try_with_additional_anchors([chain.last().unwrap().clone()])
                .unwrap()
        }),
        ("platform", platform_trusting),
    ];
    for (name, make_trust) in sources {
        let trusted = connect_with_config(
            GeneratedServerAuthConfig::default(),
            Host::from_static("localhost"),
            |chain| TlsClientConfig::new().with_server_trust(make_trust(chain)),
        )
        .await;
        assert!(trusted, "{name}: trusted without a policy");

        let distrusted = connect_with_config(
            GeneratedServerAuthConfig::default(),
            Host::from_static("localhost"),
            |chain| {
                TlsClientConfig::new()
                    .with_server_trust(make_trust(chain))
                    .with_server_cert_chain_policy(distrusting(chain.last().unwrap()))
            },
        )
        .await;
        assert!(!distrusted, "{name}: distrusted CA key accepted");
    }
}

#[tokio::test]
async fn distrusted_keys_apply_without_server_verification() {
    let (unrelated, _) = generate_server_auth(GeneratedServerAuthConfig::default()).unwrap();
    assert!(
        connect_with_config(
            GeneratedServerAuthConfig::default(),
            Host::from_static("localhost"),
            |_| {
                TlsClientConfig::new()
                    .with_server_verify(ServerVerifyMode::Disable)
                    .with_server_cert_chain_policy(distrusting(&unrelated[0]))
            },
        )
        .await
    );
    assert!(
        !connect_with_config(
            GeneratedServerAuthConfig::default(),
            Host::from_static("localhost"),
            |chain| {
                TlsClientConfig::new()
                    .with_server_verify(ServerVerifyMode::Disable)
                    .with_server_cert_chain_policy(distrusting(&chain[0]))
            },
        )
        .await
    );
}

#[tokio::test]
async fn chain_policy_sees_the_verified_path_or_the_presented_chain() {
    for (verify, trust, expected) in [
        (
            ServerVerifyMode::Auto,
            "custom",
            ServerCertChainKind::Verified,
        ),
        (
            ServerVerifyMode::Auto,
            "platform",
            ServerCertChainKind::Verified,
        ),
        (
            ServerVerifyMode::Disable,
            "none",
            ServerCertChainKind::Presented,
        ),
    ] {
        let recorder = RecordingChainPolicy::default();
        let policy = DynTlsServerCertChainPolicy::new(recorder.clone());
        let connected = connect_with_config(
            GeneratedServerAuthConfig::default(),
            Host::from_static("localhost"),
            |chain| {
                let config = TlsClientConfig::new()
                    .with_server_verify(verify)
                    .with_server_cert_chain_policy(policy);
                match trust {
                    "custom" => config
                        .try_with_server_trust_anchors([chain.last().unwrap().clone()])
                        .unwrap(),
                    "platform" => config.with_server_trust(platform_trusting(chain)),
                    _ => config,
                }
            },
        )
        .await;
        assert!(connected, "{trust}");
        let runs = recorder.runs.load(std::sync::atomic::Ordering::Relaxed);
        assert_eq!(runs, 1, "{trust}: policy runs");
        let (kind, len) = *recorder.first.get().unwrap();
        assert_eq!(kind, expected, "{trust}");
        // The generated chain is leaf and CA; a verified path ends at the anchor.
        assert_eq!(len, 2, "{trust}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn platform_verification_runs_on_a_multi_thread_runtime() {
    assert!(connect_to_server_with_trust(platform_trusting).await);
    assert!(!connect_to_server_with_trust(|_| TlsServerTrust::platform_verifier()).await);
}

#[tokio::test]
async fn chain_policies_apply_after_a_custom_verifier() {
    use crate::client::RustlsClientConfigExt as _;

    let accept_any = || {
        TlsClientConfig::new().with_cert_verifier(std::sync::Arc::new(
            crate::verify::NoServerCertVerifier::new(),
        ))
    };
    assert!(
        connect_with_config(
            GeneratedServerAuthConfig::default(),
            Host::from_static("localhost"),
            |_| accept_any(),
        )
        .await
    );
    assert!(
        !connect_with_config(
            GeneratedServerAuthConfig::default(),
            Host::from_static("localhost"),
            |chain| accept_any().with_server_cert_chain_policy(distrusting(&chain[0])),
        )
        .await,
        "the policy rejects what the custom verifier accepted"
    );
}
