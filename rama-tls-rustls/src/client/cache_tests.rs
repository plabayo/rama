//! Native configuration caching of the TCP connector and the session
//! resumption it enables.

#[cfg(any(target_vendor = "apple", windows))]
use std::task::Poll;
use std::{sync::Arc, time::Duration};

use rama_core::{
    Service, ServiceInput,
    combinators::Either,
    error::BoxError,
    extensions::{Extensions, ExtensionsRef as _},
};
#[cfg(any(target_vendor = "apple", windows))]
use rama_core::{conversion::RamaTryFrom as _, futures::stream::poll_fn};
use rama_crypto::{cert::generate_server_auth, pki_types::CertificateDer};
use rama_net::{
    Protocol,
    address::{Domain, HostWithPort},
    client::{ConnectRequest, ConnectionError, EstablishedClientConnection},
    tls::{ApplicationProtocol, TlsAlpn},
};
use rama_tls::{
    KeyLogIntent,
    client::{
        ChannelReloadTrigger, ClientAuth, ClientAuthData, ClientHandshake, DistrustedServerKeys,
        EchRequirement, NegotiatedTlsParameters, PlatformTrustPolicy, ServerTrustSnapshot,
        TlsClientAuth, TlsClientConfig, TlsClientSni, TlsServerCertPinSet, TlsServerCertPins,
        TlsServerTrust, TlsServerTrustAnchors, shared_platform_verifier,
    },
    server::{CertificateIdentity, GeneratedServerAuthConfig, LeafCertRequest},
};
#[cfg(any(target_vendor = "apple", windows))]
use rama_utils::octets::kib;
#[cfg(any(target_vendor = "apple", windows))]
use rustls::{HandshakeKind, client::Resumption};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _, DuplexStream, duplex},
    time::timeout,
};

use super::{
    ConnectorKindSecure, RustlsClientConfigExt as _, RustlsServerTrustCache,
    RustlsServerVerification, RustlsTlsConnectorConfig, TlsConnector, TlsConnectorData,
    self_signed_client_auth,
};
#[cfg(any(target_vendor = "apple", windows))]
use crate::dep::{rustls, tokio_rustls};
use crate::{
    dep::{rustls::ServerConfig, tokio_rustls::TlsAcceptor},
    verify::NoServerCertVerifier,
};

/// Dials an in-memory origin. All connections share one server configuration,
/// and so its session cache, as a resuming server must.
#[derive(Clone)]
struct Dial(TlsAcceptor);

impl Service<ConnectRequest> for Dial {
    type Output = EstablishedClientConnection<ServiceInput<DuplexStream>, ConnectRequest>;

    type Error = ConnectionError;

    async fn serve(&self, input: ConnectRequest) -> Result<Self::Output, Self::Error> {
        let (client, server) = duplex(16 * 1024);
        let acceptor = self.0.clone();
        tokio::spawn(async move {
            if let Ok(mut stream) = acceptor.accept(server).await
                && let Ok(byte) = stream.read_u8().await
            {
                let _echoed = stream.write_u8(byte).await;
            }
        });
        Ok(EstablishedClientConnection {
            input,
            conn: ServiceInput::new(client),
        })
    }
}

/// An origin for `localhost` and the anchor of its chain.
fn origin() -> (Dial, CertificateDer<'static>) {
    crate::ensure_default_crypto_provider();
    let (cert_chain, private_key) = generate_server_auth(GeneratedServerAuthConfig::GeneratedCa {
        ca: Default::default(),
        leaf: LeafCertRequest {
            config: Default::default(),
            identities: [CertificateIdentity::Dns(Domain::tld_localhost())].into(),
        },
    })
    .unwrap();
    let anchor = cert_chain.last().unwrap().clone();
    let server = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, private_key)
        .unwrap();
    (Dial(TlsAcceptor::from(Arc::new(server))), anchor)
}

fn connector(dial: Dial, trust: TlsServerTrust) -> TlsConnector<Dial, ConnectorKindSecure> {
    TlsConnector::secure(dial).with_base_config(
        TlsClientConfig::new()
            .with_server_name(Domain::tld_localhost())
            .with_server_trust(trust),
    )
}

/// Connect with request `overrides` and exchange a byte, which also lets the
/// client store its tickets. Returns whether the handshake resumed.
async fn resumed(
    connector: &TlsConnector<Dial, ConnectorKindSecure>,
    overrides: &Extensions,
) -> bool {
    let request = ConnectRequest::new(HostWithPort::localhost_domain_https())
        .with_application_protocol(Protocol::HTTPS);
    request.extensions().extend(overrides);
    let connect = async {
        let mut conn = connector.serve(request).await.unwrap().conn;
        conn.write_all(b"x").await.unwrap();
        assert_eq!(conn.read_u8().await.unwrap(), b'x');
        conn.extensions()
            .get_ref::<NegotiatedTlsParameters>()
            .and_then(|params| params.resumed)
            .unwrap()
    };
    timeout(Duration::from_secs(5), connect).await.unwrap()
}

/// A valid anchor that has no part in the origin's chain.
fn unrelated_anchor() -> CertificateDer<'static> {
    let (chain, _) = generate_server_auth(GeneratedServerAuthConfig::default()).unwrap();
    chain.last().unwrap().clone()
}

fn other_name_pins(anchor: &CertificateDer<'static>) -> TlsServerCertPins {
    // Scoped to another name: the pins change the policy but accept this peer.
    TlsServerCertPins::new(
        TlsServerCertPinSet::new(anchor.clone())
            .with_server_name(Domain::from_static("other.test")),
    )
}

fn single_client_auth() -> TlsClientAuth {
    let (cert_chain, private_key) = self_signed_client_auth().unwrap();
    TlsClientAuth(ClientAuth::Single(ClientAuthData {
        cert_chain,
        private_key,
    }))
}

#[tokio::test]
async fn identical_policies_resume_and_every_policy_change_starts_fresh() {
    let (dial, anchor) = origin();
    let trust = TlsServerTrust::custom(TlsServerTrustAnchors::try_new([anchor.clone()]).unwrap());
    let connector = connector(dial, trust);
    let base = Extensions::new();
    assert!(!resumed(&connector, &base).await);
    assert!(resumed(&connector, &base).await);

    let pins = Extensions::new();
    pins.insert(other_name_pins(&anchor));
    let trust = Extensions::new();
    trust.insert(
        TlsServerTrust::custom(TlsServerTrustAnchors::try_new([anchor.clone()]).unwrap())
            .try_with_additional_anchors([unrelated_anchor()])
            .unwrap(),
    );
    let auth = Extensions::new();
    auth.insert(single_client_auth());
    let alpn = Extensions::new();
    alpn.insert(TlsAlpn::http_1());
    for changed in [pins, trust, auth, alpn] {
        assert!(!resumed(&connector, &changed).await);
        assert!(resumed(&connector, &changed).await);
    }
    assert!(resumed(&connector, &base).await);
}

#[tokio::test]
async fn throwaway_identities_and_full_offers_are_never_shared() {
    let (dial, anchor) = origin();
    let trust = TlsServerTrust::custom(TlsServerTrustAnchors::try_new([anchor]).unwrap());
    let connector = connector(dial, trust);
    let self_signed = Extensions::new();
    self_signed.insert(TlsClientAuth(ClientAuth::SelfSigned));
    let full = Extensions::new();
    full.insert(ClientHandshake::Full);
    for fresh in [self_signed, full] {
        for _ in 0..2 {
            assert!(!resumed(&connector, &fresh).await);
        }
    }
}

#[test]
fn native_config_keys_follow_every_policy_input() {
    let anchor = CertificateDer::from(vec![1]);
    let config = || {
        TlsClientConfig::new()
            .try_with_server_trust_anchors([anchor.clone()])
            .unwrap()
    };
    let key = |config: &TlsClientConfig| {
        RustlsTlsConnectorConfig::from_extensions(config.as_extensions()).native_config_key(None)
    };
    let base = config();
    let baseline = key(&base).unwrap();
    // Separately built, equal policies share one configuration.
    assert_eq!(key(&config()), Some(baseline.clone()));
    let variants = [
        base.clone().with_server_cert_pins(other_name_pins(&anchor)),
        base.clone().with_client_auth(single_client_auth().0),
        base.clone()
            .with_alpn([ApplicationProtocol::HTTP_11].into_iter().collect()),
        base.clone()
            .with_server_trust(TlsServerTrust::webpki_roots()),
        base.clone().with_ech_requirement(EchRequirement::Optional),
    ];
    for variant in &variants {
        assert_ne!(key(variant), Some(baseline.clone()));
    }
    let self_signed = base.clone().with_client_auth(ClientAuth::SelfSigned);
    assert_eq!(key(&self_signed), None);
    let uncached = [
        base.clone().with_client_handshake(ClientHandshake::Full),
        base.clone()
            .with_server_cert_chain_policy(DistrustedServerKeys::new().with_spki_sha256([0; 32])),
        base.clone()
            .with_cert_verifier(Arc::new(NoServerCertVerifier::new())),
        base.clone().with_modify_rustls_config(Ok),
        base.with_keylog(KeyLogIntent::Environment),
    ];
    for config in &uncached {
        assert_eq!(key(config), None);
    }
}

#[cfg(any(target_vendor = "apple", windows))]
#[tokio::test(flavor = "multi_thread")]
async fn trust_trigger_events_end_resumption() {
    let (dial, anchor) = origin();
    let (sender, trigger) = ChannelReloadTrigger::new();
    let trust = TlsServerTrust::from(PlatformTrustPolicy::new().with_reload_trigger(trigger))
        .try_with_additional_anchors([anchor])
        .unwrap();
    let connector = connector(dial, trust);
    let base = Extensions::new();
    assert!(!resumed(&connector, &base).await);
    assert!(resumed(&connector, &base).await);
    sender.request_reload().unwrap();
    assert!(!resumed(&connector, &base).await);
    assert!(resumed(&connector, &base).await);
}

#[test]
fn required_ech_is_rejected_after_a_cache_hit() {
    let (_dial, anchor) = origin();
    let cache = RustlsServerTrustCache::new(RustlsServerTrustCache::DEFAULT_CAPACITY);
    let policy = TlsClientConfig::new()
        .with_server_name(Domain::tld_localhost())
        .try_with_server_trust_anchors([anchor])
        .unwrap();
    let data = |extensions: &Extensions| {
        let verification = cache.server_verification(extensions).unwrap();
        TlsConnectorData::from_extensions(extensions, verification.as_ref(), &cache)
    };
    // A connection that did not require ECH seeds the native configuration cache.
    data(policy.as_extensions()).unwrap();
    let required = policy.as_extensions().fork();
    required.insert(EchRequirement::Required);
    data(&required).unwrap_err();
}

#[tokio::test]
async fn required_ech_is_rejected_by_the_connector_after_a_connection() {
    let (dial, anchor) = origin();
    let base = TlsClientConfig::new()
        .with_server_name(Domain::tld_localhost())
        .with_server_trust(TlsServerTrust::custom(
            TlsServerTrustAnchors::try_new([anchor]).unwrap(),
        ));
    // The connector reads its base policy for every connection.
    let policy = base.as_extensions().clone();
    let connector = TlsConnector::secure(dial).with_base_config(base);
    let connect = || async {
        let request = ConnectRequest::new(HostWithPort::localhost_domain_https());
        let mut conn = connector.serve(request).await?.conn;
        conn.write_all(b"x").await?;
        conn.read_u8().await?;
        Ok::<_, BoxError>(())
    };
    connect().await.unwrap();
    policy.insert(EchRequirement::Required);
    connect().await.unwrap_err();
}

#[tokio::test]
async fn ip_literal_sni_is_rejected_after_a_cache_hit() {
    let (dial, anchor) = origin();
    let base = TlsClientConfig::new()
        .with_server_name(Domain::tld_localhost())
        .try_with_server_trust_anchors([anchor])
        .unwrap();
    let policy = base.as_extensions().clone();
    let connector = TlsConnector::secure(dial).with_base_config(base);
    let connect = || async {
        let request = ConnectRequest::new(HostWithPort::localhost_domain_https());
        let mut conn = connector.serve(request).await?.conn;
        conn.write_all(b"x").await?;
        conn.read_u8().await?;
        Ok::<_, BoxError>(())
    };
    connect().await.unwrap();
    policy.insert(TlsClientSni::IncludeIp);
    let error = connect().await.unwrap_err();
    assert!(format!("{error:?}").contains("IP literal SNI requires the BoringSSL backend"));
}

#[test]
fn operating_system_verification_is_shared_only_with_a_reload_trigger() {
    let platform = RustlsServerVerification {
        verifier: Either::B(shared_platform_verifier()),
        trust_key: ServerTrustSnapshot::read(&TlsServerTrust::platform_verifier())
            .unwrap()
            .key(),
    };
    let key = |policy: PlatformTrustPolicy| {
        let config = TlsClientConfig::new().with_server_trust(policy);
        RustlsTlsConnectorConfig::from_extensions(config.as_extensions())
            .native_config_key(Some(&platform))
    };
    let (sender, trigger) = ChannelReloadTrigger::new();
    let triggered = PlatformTrustPolicy::new().with_reload_trigger(trigger);
    let trust = TlsServerTrust::from(triggered.clone());
    ServerTrustSnapshot::read(&trust).unwrap();
    assert!(key(triggered.clone()).is_some());
    // Once the trigger has ended, nothing reports a system trust change any more.
    drop(sender);
    ServerTrustSnapshot::read(&trust).unwrap();
    assert!(key(triggered).is_none());
    assert!(key(PlatformTrustPolicy::new()).is_none());
    assert!(key(PlatformTrustPolicy::new().with_max_age(Duration::from_mins(1))).is_none());
}

#[cfg(any(target_vendor = "apple", windows))]
#[tokio::test(flavor = "multi_thread")]
async fn static_operating_system_trust_never_resumes() {
    let (dial, anchor) = origin();
    let trust = TlsServerTrust::platform_verifier()
        .try_with_additional_anchors([anchor])
        .unwrap();
    let connector = connector(dial, trust);
    let base = Extensions::new();
    for _ in 0..2 {
        assert!(!resumed(&connector, &base).await);
    }
}

#[cfg(any(target_vendor = "apple", windows))]
#[tokio::test(flavor = "multi_thread")]
async fn an_ended_trust_trigger_ends_resumption() {
    let (dial, anchor) = origin();
    let (sender, trigger) = ChannelReloadTrigger::new();
    let trust = TlsServerTrust::from(PlatformTrustPolicy::new().with_reload_trigger(trigger))
        .try_with_additional_anchors([anchor])
        .unwrap();
    let connector = connector(dial, trust);
    let base = Extensions::new();
    assert!(!resumed(&connector, &base).await);
    assert!(resumed(&connector, &base).await);
    drop(sender);
    for _ in 0..2 {
        assert!(!resumed(&connector, &base).await);
    }
}

#[cfg(any(target_vendor = "apple", windows))]
#[tokio::test]
async fn public_native_platform_config_requires_a_live_signal_to_resume() {
    check_public_native_platform_config(false).await;
}

#[cfg(any(target_vendor = "apple", windows))]
#[tokio::test]
async fn public_native_platform_verifier_requires_a_live_signal_to_resume() {
    check_public_native_platform_config(true).await;
}

#[cfg(any(target_vendor = "apple", windows))]
#[tokio::test]
async fn retained_native_platform_config_stops_resuming_when_the_signal_ends() {
    check_retained_native_platform_config(false).await;
}

#[cfg(any(target_vendor = "apple", windows))]
#[tokio::test]
async fn retained_native_platform_config_stops_resuming_after_a_trust_event() {
    check_retained_native_platform_config(true).await;
}

#[cfg(any(target_vendor = "apple", windows))]
#[tokio::test]
async fn retained_native_platform_config_binds_sessions_to_its_verifier_generation() {
    let (origin, anchor) = origin();
    let mut polls = 0;
    // Its first read leaves an event that only a second read would consume.
    let trigger = poll_fn(move |cx| {
        polls += 1;
        match polls {
            1 => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            2 => Poll::Ready(Some(())),
            _ => Poll::Pending,
        }
    });
    let trust = TlsServerTrust::from(PlatformTrustPolicy::new().with_reload_trigger(trigger))
        .try_with_additional_anchors([anchor])
        .unwrap();
    let config = TlsClientConfig::new().with_server_trust(trust);
    let native = Arc::new(rustls::ClientConfig::rama_try_from(&config).unwrap());
    for _ in 0..2 {
        assert!(!retained_resumed(&origin, &native).await);
    }
}

#[cfg(any(target_vendor = "apple", windows))]
#[tokio::test]
async fn retained_native_platform_config_resumes_only_without_a_trust_read() {
    let (origin, anchor) = origin();
    let (_sender, trigger) = ChannelReloadTrigger::new();
    let policy = PlatformTrustPolicy::new()
        .with_reload_trigger(trigger)
        .with_max_age(Duration::ZERO);
    let trust = TlsServerTrust::from(policy)
        .try_with_additional_anchors([anchor])
        .unwrap();
    let config = TlsClientConfig::new().with_server_trust(trust);
    let native = Arc::new(rustls::ClientConfig::rama_try_from(&config).unwrap());
    for _ in 0..2 {
        assert!(!retained_resumed(&origin, &native).await);
    }
}

/// Connect with a retained native configuration; returns whether the handshake resumed.
#[cfg(any(target_vendor = "apple", windows))]
async fn retained_resumed(origin: &Dial, native: &Arc<rustls::ClientConfig>) -> bool {
    let (client, server) = duplex(kib(16));
    let acceptor = origin.0.clone();
    let accepted = tokio::spawn(async move {
        let mut stream = acceptor.accept(server).await.unwrap();
        let byte = stream.read_u8().await.unwrap();
        stream.write_u8(byte).await.unwrap();
    });
    let connector = tokio_rustls::TlsConnector::from(native.clone());
    let mut stream = connector
        .connect("localhost".try_into().unwrap(), client)
        .await
        .unwrap();
    stream.write_u8(b'x').await.unwrap();
    assert_eq!(stream.read_u8().await.unwrap(), b'x');
    accepted.await.unwrap();
    stream.get_ref().1.handshake_kind() == Some(HandshakeKind::Resumed)
}

#[cfg(any(target_vendor = "apple", windows))]
async fn check_retained_native_platform_config(reload: bool) {
    let (origin, anchor) = origin();
    let (sender, trigger) = ChannelReloadTrigger::new();
    let trust = TlsServerTrust::from(PlatformTrustPolicy::new().with_reload_trigger(trigger))
        .try_with_additional_anchors([anchor])
        .unwrap();
    let config = TlsClientConfig::new().with_server_trust(trust);
    let native = Arc::new(rustls::ClientConfig::rama_try_from(&config).unwrap());
    let mut sender = Some(sender);
    for attempt in 0..3 {
        if attempt == 2 {
            if reload {
                sender.as_ref().unwrap().request_reload().unwrap();
            } else {
                drop(sender.take());
            }
        }
        let (client, server) = duplex(kib(16));
        let acceptor = origin.0.clone();
        let accepted = tokio::spawn(async move {
            let mut stream = acceptor.accept(server).await.unwrap();
            let byte = stream.read_u8().await.unwrap();
            stream.write_u8(byte).await.unwrap();
        });
        let connector = tokio_rustls::TlsConnector::from(native.clone());
        let mut stream = connector
            .connect("localhost".try_into().unwrap(), client)
            .await
            .unwrap();
        stream.write_u8(b'x').await.unwrap();
        assert_eq!(stream.read_u8().await.unwrap(), b'x');
        assert_eq!(
            stream.get_ref().1.handshake_kind() == Some(HandshakeKind::Resumed),
            attempt == 1
        );
        accepted.await.unwrap();
    }
}

#[cfg(any(target_vendor = "apple", windows))]
async fn check_public_native_platform_config(verify_native: bool) {
    let (origin, anchor) = origin();
    for live in [false, true] {
        let (sender, trigger) = ChannelReloadTrigger::new();
        let policy = if live {
            PlatformTrustPolicy::new().with_reload_trigger(trigger)
        } else {
            PlatformTrustPolicy::new()
        };
        let trust = TlsServerTrust::from(policy)
            .try_with_additional_anchors([anchor.clone()])
            .unwrap();
        let config = TlsClientConfig::new()
            .with_server_trust(trust)
            .with_modify_rustls_config(move |mut native| {
                if !verify_native {
                    native
                        .dangerous()
                        .set_certificate_verifier(Arc::new(NoServerCertVerifier::default()));
                }
                native.resumption = Resumption::in_memory_sessions(8);
                Ok(native)
            });
        let native = Arc::new(rustls::ClientConfig::rama_try_from(&config).unwrap());
        for expected in [false, live] {
            let (client, server) = duplex(kib(16));
            let acceptor = origin.0.clone();
            let accepted = tokio::spawn(async move {
                let mut stream = acceptor.accept(server).await.unwrap();
                let byte = stream.read_u8().await.unwrap();
                stream.write_u8(byte).await.unwrap();
            });
            let connector = tokio_rustls::TlsConnector::from(native.clone());
            let mut stream = connector
                .connect("localhost".try_into().unwrap(), client)
                .await
                .unwrap();
            stream.write_u8(b'x').await.unwrap();
            assert_eq!(stream.read_u8().await.unwrap(), b'x');
            assert_eq!(
                stream.get_ref().1.handshake_kind() == Some(HandshakeKind::Resumed),
                expected
            );
            accepted.await.unwrap();
        }
        drop(sender);
    }
}
