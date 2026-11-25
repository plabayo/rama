//! Shared native configuration of the acceptor and the session resumption it enables.

use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime},
};

use rama_core::{
    Layer as _, Service, ServiceInput,
    error::BoxError,
    extensions::{Extensions, ExtensionsRef as _},
    service::service_fn,
};
use rama_crypto::pki_types::CertificateDer;
use rama_net::{
    Protocol,
    address::{Domain, HostWithPort},
    client::{ConnectRequest, ConnectionError, EstablishedClientConnection},
    stream::service::EchoService,
    tls::TlsAlpn,
};
use rama_tls::{
    client::{
        ClientAuth, ClientAuthData, NegotiatedTlsParameters, TlsClientConfig, TlsServerTrust,
        TlsServerTrustAnchors,
    },
    server::{
        CertificateAuthorityData, ClientVerifyMode, GeneratedServerAuthConfig, LeafCertRequest,
        SelfSignedCaConfig, ServerAuthData, TlsClientVerify, TlsServerConfig,
    },
};
use rcgen::{KeyPair, PublicKeyData as _};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _, DuplexStream, duplex},
    sync::mpsc,
    time::timeout,
};

use super::{
    RustlsServerConfigExt as _, TlsAcceptorLayer, TlsStream, service::ensure_currently_valid,
};
use crate::client::{ConnectorKindSecure, TlsConnector};

type Accept = Arc<dyn Fn(ServiceInput<DuplexStream>) + Send + Sync>;

/// Dials an in-memory origin, one served connection per dial.
#[derive(Clone)]
struct Dial(Accept);

impl Service<ConnectRequest> for Dial {
    type Output = EstablishedClientConnection<ServiceInput<DuplexStream>, ConnectRequest>;

    type Error = ConnectionError;

    async fn serve(&self, input: ConnectRequest) -> Result<Self::Output, Self::Error> {
        let (client, server) = duplex(16 * 1024);
        (self.0)(ServiceInput::new(server));
        Ok(EstablishedClientConnection {
            input,
            conn: ServiceInput::new(client),
        })
    }
}

/// Serve every dial with `acceptor`, which echoes.
fn echo_origin<S>(acceptor: S) -> Dial
where
    S: Service<ServiceInput<DuplexStream>, Error = BoxError> + Clone,
{
    Dial(Arc::new(move |io| {
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            let _served = acceptor.serve(io).await;
        });
    }))
}

fn server_auth() -> ServerAuthData {
    ServerAuthData::new_generated(GeneratedServerAuthConfig::default()).unwrap()
}

fn root(auth: &ServerAuthData) -> CertificateDer<'static> {
    auth.cert_chain.last().unwrap().clone()
}

fn client_config(anchor: CertificateDer<'static>) -> TlsClientConfig {
    TlsClientConfig::new()
        .with_server_name(Domain::tld_localhost())
        .with_server_trust(TlsServerTrust::custom(
            TlsServerTrustAnchors::try_new([anchor]).unwrap(),
        ))
}

fn client(dial: Dial, config: TlsClientConfig) -> TlsConnector<Dial, ConnectorKindSecure> {
    TlsConnector::secure(dial).with_base_config(config)
}

/// Connect and exchange a byte, which also lets the client store its tickets.
/// Returns whether the handshake resumed.
async fn resumed(connector: &TlsConnector<Dial, ConnectorKindSecure>) -> bool {
    let request = ConnectRequest::new(HostWithPort::localhost_domain_https())
        .with_application_protocol(Protocol::HTTPS);
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

#[tokio::test]
async fn sessions_resume_only_when_enabled() {
    for enabled in [false, true] {
        let auth = server_auth();
        let acceptor = TlsAcceptorLayer::new(TlsServerConfig::new().with_server_auth(auth.clone()))
            .with_session_resumption(enabled)
            .into_layer(EchoService::new());
        let connector = client(echo_origin(acceptor), client_config(root(&auth)));
        assert!(!resumed(&connector).await);
        assert_eq!(resumed(&connector).await, enabled);
    }
}

#[tokio::test]
async fn acceptors_never_resume_each_others_sessions() {
    let authority = CertificateAuthorityData::generate(SelfSignedCaConfig::default()).unwrap();
    let leaf = || ServerAuthData::new_issued_by(&authority, LeafCertRequest::default()).unwrap();
    let layer = TlsAcceptorLayer::new(TlsServerConfig::new().with_server_auth(leaf()))
        .with_session_resumption(true);
    let acceptors = [
        layer.layer(EchoService::new()),
        // The same configuration in another acceptor.
        layer.layer(EchoService::new()),
        // Another certificate from the same issuer.
        TlsAcceptorLayer::new(TlsServerConfig::new().with_server_auth(leaf()))
            .with_session_resumption(true)
            .into_layer(EchoService::new()),
    ];
    let target = Arc::new(AtomicUsize::new(0));
    let dial = Dial(Arc::new({
        let target = target.clone();
        move |io| {
            let acceptor = acceptors[target.load(Ordering::Relaxed)].clone();
            tokio::spawn(async move {
                let _served = acceptor.serve(io).await;
            });
        }
    }));
    let anchor = authority.certificate_chain().last().unwrap().clone();
    let connector = client(dial, client_config(anchor));
    for index in 0..3 {
        target.store(index, Ordering::Relaxed);
        assert!(!resumed(&connector).await);
        assert!(resumed(&connector).await);
    }
}

#[tokio::test]
async fn required_client_auth_resumes_with_the_verified_client_chain() {
    let auth = server_auth();
    let authority = CertificateAuthorityData::generate(SelfSignedCaConfig::default()).unwrap();
    let (cert_chain, private_key) = authority
        .issue_client_leaf(LeafCertRequest::default())
        .unwrap();
    let config = TlsServerConfig::new()
        .with_server_auth(auth.clone())
        .with_client_verify(ClientVerifyMode::ClientAuth(
            authority.certificate_chain().to_vec(),
        ));
    let (seen, mut chains) = mpsc::unbounded_channel();
    let acceptor = TlsAcceptorLayer::new(config)
        .with_session_resumption(true)
        .into_layer(service_fn(
            move |mut stream: TlsStream<ServiceInput<DuplexStream>>| {
                let seen = seen.clone();
                async move {
                    let chain = stream
                        .stream
                        .get_ref()
                        .1
                        .peer_certificates()
                        .map(<[_]>::to_vec);
                    let _sent = seen.send(chain);
                    let byte = stream.read_u8().await?;
                    stream.write_u8(byte).await?;
                    Ok::<_, BoxError>(())
                }
            },
        ));
    let dial = echo_origin(acceptor);

    let with_identity = client(
        dial.clone(),
        client_config(root(&auth)).with_client_auth(ClientAuth::Single(ClientAuthData {
            cert_chain: cert_chain.clone(),
            private_key,
        })),
    );
    // Resumption restores the chain verified in the full handshake instead of verifying again.
    for expect_resumed in [false, true] {
        assert_eq!(resumed(&with_identity).await, expect_resumed);
        let chain = chains.recv().await.unwrap().unwrap();
        assert_eq!(chain.first(), cert_chain.first());
    }

    // Without a client certificate there is no ticket to offer, and the full handshake fails.
    let without_identity = client(dial, client_config(root(&auth)));
    let request = ConnectRequest::new(HostWithPort::localhost_domain_https())
        .with_application_protocol(Protocol::HTTPS);
    let failed = async {
        let mut conn = without_identity.serve(request).await.ok()?.conn;
        conn.write_all(b"x").await.ok()?;
        conn.read_u8().await.ok()
    };
    assert_eq!(timeout(Duration::from_secs(5), failed).await.unwrap(), None);
}

#[tokio::test]
async fn per_connection_configurations_are_built_for_each_connection() {
    let auth = server_auth();
    let builds = Arc::new(AtomicUsize::new(0));
    let hooked = TlsServerConfig::new()
        .with_server_auth(auth.clone())
        .with_modify_rustls_config({
            let builds = builds.clone();
            move |config| {
                builds.fetch_add(1, Ordering::Relaxed);
                Ok(config)
            }
        });
    let acceptor = TlsAcceptorLayer::new(hooked)
        .with_session_resumption(true)
        .into_layer(EchoService::new());
    let connector = client(echo_origin(acceptor), client_config(root(&auth)));
    for _ in 0..2 {
        assert!(!resumed(&connector).await);
    }
    assert_eq!(builds.load(Ordering::Relaxed), 2);

    // A connection that overrides the configuration gets its own, and never resumes.
    let acceptor = TlsAcceptorLayer::new(TlsServerConfig::new().with_server_auth(auth.clone()))
        .with_session_resumption(true)
        .into_layer(EchoService::new());
    let overriding = Dial(Arc::new(move |io: ServiceInput<DuplexStream>| {
        let overrides = Extensions::new();
        overrides.insert(TlsAlpn::http_1());
        io.extensions().extend(&overrides);
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            let _served = acceptor.serve(io).await;
        });
    }));
    let connector = client(overriding, client_config(root(&auth)));
    for _ in 0..2 {
        assert!(!resumed(&connector).await);
    }
}

#[tokio::test]
async fn later_changes_to_a_retained_config_do_not_apply() {
    let auth = server_auth();
    let authority = CertificateAuthorityData::generate(SelfSignedCaConfig::default()).unwrap();
    let config = TlsServerConfig::new().with_server_auth(auth.clone());
    let retained = config.as_extensions().clone();
    let acceptor = TlsAcceptorLayer::new(config)
        .with_session_resumption(true)
        .into_layer(EchoService::new());
    // Applied, this policy would refuse this client, which has no certificate.
    retained.insert(TlsClientVerify(ClientVerifyMode::ClientAuth(
        authority.certificate_chain().to_vec(),
    )));
    let connector = client(echo_origin(acceptor), client_config(root(&auth)));
    assert!(!resumed(&connector).await);
    assert!(resumed(&connector).await);
}

#[test]
fn restored_client_certificates_must_be_currently_valid() {
    let authority = CertificateAuthorityData::generate(SelfSignedCaConfig::default()).unwrap();
    let (chain, _) = authority
        .issue_client_leaf(LeafCertRequest::default())
        .unwrap();
    let now = SystemTime::now();
    ensure_currently_valid(&chain[0], now).unwrap();
    let year = Duration::from_hours(24 * 365);
    ensure_currently_valid(&chain[0], now + 100 * year).unwrap_err();
    ensure_currently_valid(&chain[0], now - year).unwrap_err();
}

#[test]
fn restored_raw_public_keys_have_no_certificate_expiry() {
    let key = KeyPair::generate().unwrap();
    let spki = CertificateDer::from(key.subject_public_key_info());
    ensure_currently_valid(&spki, SystemTime::now()).unwrap();
    ensure_currently_valid(
        &spki,
        SystemTime::now() + Duration::from_hours(24 * 365 * 100),
    )
    .unwrap();
    let malformed = CertificateDer::from(vec![0x30, 0]);
    ensure_currently_valid(&malformed, SystemTime::now()).unwrap_err();
}
