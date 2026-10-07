use std::sync::Arc;

use parking_lot::Mutex;
use rama_boring::ssl::{SslConnector, SslConnectorBuilder, SslMethod, SslVerifyMode, SslVersion};
use rama_boring_tokio::{SslStream, SslStreamBuilder};
use rama_core::{
    Layer as _, Service, ServiceInput,
    conversion::RamaFrom as _,
    error::BoxError,
    extensions::{Extensions, ExtensionsRef as _},
    service::service_fn,
};
use rama_crypto::cert::{CertificateKeyKind, LeafCertConfig};
use rama_net::{
    address::{Host, HostWithPort},
    client::ConnectorTarget,
    tls::TlsAlpn,
};
use rama_tls::{
    CipherSuite, SignatureScheme, SupportedGroup,
    client::{
        ClientHello, NegotiatedTlsAlgorithms, NegotiatedTlsParameters, ServerVerifyMode,
        TlsClientConfig,
    },
    server::{
        CertificateIssuanceContext, DynamicCertIssuer, GeneratedServerAuthConfig, LeafCertRequest,
        ServerAuthData, TlsServerConfig,
    },
};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _, DuplexStream};

use super::{
    BoringServerConfigExt as _, ServerCertIssuerData, TlsAcceptorLayer, TlsAcceptorService,
};
use crate::{
    TlsStream,
    client::{
        BoringClientConfigExt as _, TlsClientSession, TlsConnectorContext,
        TlsConnectorContextBuilder,
    },
    types::SecureTransport,
};

/// Handshake `client` with a boring acceptor for `server`.
///
/// Returns the client stream and what the server recorded.
async fn handshake(
    server: TlsServerConfig,
    client: SslConnectorBuilder,
) -> (SslStream<DuplexStream>, NegotiatedTlsParameters) {
    let acceptor = TlsAcceptorService::new(
        server,
        service_fn(|stream: TlsStream<ServiceInput<DuplexStream>>| async move {
            Ok::<_, BoxError>(
                stream
                    .extensions()
                    .get_ref::<NegotiatedTlsParameters>()
                    .unwrap()
                    .clone(),
            )
        }),
        false,
    );
    let config = client.build().configure().unwrap();
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let (client, server) = tokio::join!(
        rama_boring_tokio::connect(config, Some("localhost"), client_io),
        acceptor.serve(ServiceInput::new(server_io)),
    );
    (client.unwrap(), server.unwrap())
}

fn client(max_version: SslVersion) -> SslConnectorBuilder {
    let mut client = SslConnector::builder(SslMethod::tls_client()).unwrap();
    client.set_verify(SslVerifyMode::NONE);
    client.set_max_proto_version(Some(max_version)).unwrap();
    client
}

fn server_auth(key_kind: CertificateKeyKind) -> ServerAuthData {
    ServerAuthData::new_generated(GeneratedServerAuthConfig::SelfSignedLeaf(LeafCertRequest {
        config: LeafCertConfig {
            key_kind,
            ..Default::default()
        },
        ..Default::default()
    }))
    .unwrap()
}

#[tokio::test]
async fn configured_cipher_suites_are_the_server_preference() {
    let auth = server_auth(CertificateKeyKind::EcP256);
    let offered = "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384";
    for (configured, negotiated) in [
        (None, CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
        (
            Some(vec![
                CipherSuite::TLS13_AES_128_GCM_SHA256,
                CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            ]),
            CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        ),
    ] {
        let mut server = TlsServerConfig::new().with_server_auth(auth.clone());
        if let Some(suites) = configured {
            server.set_cipher_suites(suites);
        }
        let mut client = client(SslVersion::TLS1_2);
        client.set_cipher_list(offered).unwrap();
        let (_, params) = handshake(server, client).await;
        assert_eq!(params.algorithms.cipher_suite, Some(negotiated));
    }
}

#[tokio::test]
async fn configured_groups_are_the_server_preference() {
    let auth = server_auth(CertificateKeyKind::EcP256);
    for version in [SslVersion::TLS1_2, SslVersion::TLS1_3] {
        for (configured, negotiated) in [
            (None, SupportedGroup::X25519),
            (
                Some(vec![SupportedGroup::SECP256R1, SupportedGroup::X25519]),
                SupportedGroup::SECP256R1,
            ),
        ] {
            let mut server = TlsServerConfig::new().with_server_auth(auth.clone());
            if let Some(groups) = configured {
                server.set_supported_groups(groups);
            }
            let mut client = client(version);
            client.set_curves_list("X25519:P-256").unwrap();
            let (_, params) = handshake(server, client).await;
            assert_eq!(
                params.algorithms.key_exchange_group,
                Some(negotiated),
                "{version:?}"
            );
        }
    }
}

struct FixedIssuer(ServerAuthData);

impl DynamicCertIssuer for FixedIssuer {
    async fn issue_cert(&self, _: CertificateIssuanceContext) -> Result<ServerAuthData, BoxError> {
        Ok(self.0.clone())
    }
}

#[tokio::test]
async fn configured_signature_schemes_sign_the_handshake_for_every_identity_source() {
    let auth = server_auth(CertificateKeyKind::Rsa2048);
    for issued in [false, true] {
        for version in [SslVersion::TLS1_2, SslVersion::TLS1_3] {
            for (configured, signed) in [
                (None, SignatureScheme::RSA_PSS_SHA256),
                (
                    Some(vec![
                        SignatureScheme::ED25519,
                        SignatureScheme::RSA_PSS_SHA512,
                        SignatureScheme::RSA_PSS_SHA256,
                    ]),
                    SignatureScheme::RSA_PSS_SHA512,
                ),
            ] {
                let mut server = if issued {
                    TlsServerConfig::new()
                        .with_cert_issuer(ServerCertIssuerData::new(FixedIssuer(auth.clone())))
                } else {
                    TlsServerConfig::new().with_server_auth(auth.clone())
                };
                if let Some(schemes) = configured {
                    server.set_signature_schemes(schemes);
                }
                let (client, _) = handshake(server, client(version)).await;
                let algorithms = NegotiatedTlsAlgorithms::rama_from(client.ssl());
                assert_eq!(
                    algorithms.peer_signature_scheme,
                    Some(signed),
                    "issued={issued} {version:?}"
                );
            }
        }
    }
}

#[cfg(feature = "compression")]
mod compression {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use rama_tls::CertificateCompressionAlgorithm as Algorithm;

    use super::*;
    use crate::certificate_compression::test_util::CountingBrotli;

    #[tokio::test]
    async fn configured_cert_compression_compresses_for_a_client_that_offers_it() {
        let auth = server_auth(CertificateKeyKind::EcP256);
        for (configured, compressed) in [
            (None, 0),
            (Some(vec![Algorithm::Zlib]), 0),
            (Some(vec![Algorithm::Zlib, Algorithm::Brotli]), 1),
        ] {
            let mut server = TlsServerConfig::new().with_server_auth(auth.clone());
            if let Some(algorithms) = configured.clone() {
                server.set_cert_compression(algorithms);
            }
            let decompressed = Arc::new(AtomicUsize::new(0));
            let mut client = client(SslVersion::TLS1_3);
            client
                .add_certificate_compression_algorithm(CountingBrotli(decompressed.clone()))
                .unwrap();
            handshake(server, client).await;
            assert_eq!(
                decompressed.load(Ordering::SeqCst),
                compressed,
                "{configured:?}"
            );
        }
    }
}

const VERSIONS: [SslVersion; 2] = [SslVersion::TLS1_2, SslVersion::TLS1_3];

/// What the acceptor recorded for one connection.
#[derive(Debug, Clone)]
struct Accepted {
    params: NegotiatedTlsParameters,
    client_hello: Option<ClientHello>,
}

/// Records each accepted connection.
#[derive(Debug, Clone)]
struct Inner;

impl Service<TlsStream<ServiceInput<DuplexStream>>> for Inner {
    type Output = Accepted;
    type Error = BoxError;

    async fn serve(
        &self,
        mut stream: TlsStream<ServiceInput<DuplexStream>>,
    ) -> Result<Accepted, BoxError> {
        // The client reads this byte, which delivers TLS 1.3 tickets before it.
        stream.write_all(b"x").await?;
        Ok(Accepted {
            params: stream
                .extensions()
                .get_ref::<NegotiatedTlsParameters>()
                .unwrap()
                .clone(),
            client_hello: stream
                .extensions()
                .get_ref::<SecureTransport>()
                .and_then(|transport| transport.client_hello())
                .cloned(),
        })
    }
}

fn acceptor(config: TlsServerConfig, resumption: bool) -> TlsAcceptorService<Inner> {
    TlsAcceptorService::new(config, Inner, true).with_session_resumption(resumption)
}

/// A client that remembers every session it is issued and offers the one it is given.
struct Client {
    context: TlsConnectorContext,
    sessions: Arc<Mutex<Vec<TlsClientSession>>>,
}

impl Client {
    fn new(version: SslVersion) -> Self {
        Self::with_config(
            version,
            &TlsClientConfig::new().with_server_verify(ServerVerifyMode::Disable),
        )
    }

    fn with_config(version: SslVersion, config: &TlsClientConfig) -> Self {
        let sessions: Arc<Mutex<Vec<TlsClientSession>>> = Arc::default();
        let sink = sessions.clone();
        let mut builder = TlsConnectorContextBuilder::try_from(config)
            .unwrap()
            .with_new_session_callback(move |_, session| sink.lock().push(session));
        builder.config.set_min_proto_version(Some(version)).unwrap();
        builder.config.set_max_proto_version(Some(version)).unwrap();
        Self {
            context: builder.build(),
            sessions,
        }
    }

    fn latest(&self) -> TlsClientSession {
        self.sessions
            .lock()
            .last()
            .cloned()
            .expect("the server issued a session")
    }

    /// Connect to `server` as `server_name`, offering `session`.
    ///
    /// Returns what the server recorded and the DNS names of its certificate.
    async fn connect(
        &self,
        server: &TlsAcceptorService<Inner>,
        server_name: Host,
        session: Option<&TlsClientSession>,
        connection: impl FnOnce(&Extensions),
    ) -> (Accepted, Vec<String>) {
        let mut data = self.context.configure().unwrap();
        data.server_name = Some(server_name);
        let mut ssl = data.into_ssl().unwrap();
        if let Some(session) = session {
            session.resume_on(&mut ssl).unwrap();
        }
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let input = ServiceInput::new(server_io);
        connection(input.extensions());
        let (client, accepted) = tokio::join!(
            async {
                let mut stream = SslStreamBuilder::new(ssl, client_io)
                    .connect()
                    .await
                    .unwrap();
                stream.read_exact(&mut [0]).await.unwrap();
                stream
            },
            server.serve(input),
        );
        let names = client
            .ssl()
            .peer_certificate()
            .and_then(|cert| cert.subject_alt_names())
            .into_iter()
            .flatten()
            .filter_map(|name| name.dnsname().map(str::to_owned))
            .collect();
        (accepted.unwrap(), names)
    }

    async fn resumes(
        &self,
        server: &TlsAcceptorService<Inner>,
        session: Option<&TlsClientSession>,
    ) -> bool {
        let (accepted, _) = self
            .connect(server, Host::from_static("localhost"), session, |_| {})
            .await;
        assert!(
            accepted.client_hello.is_some(),
            "every ClientHello is stored"
        );
        accepted.params.resumed.unwrap()
    }
}

fn static_config() -> TlsServerConfig {
    TlsServerConfig::new().with_server_auth(server_auth(CertificateKeyKind::EcP256))
}

#[tokio::test]
async fn acceptors_resume_only_when_opted_in() {
    for version in VERSIONS {
        let client = Client::new(version);
        let disabled = acceptor(static_config(), false);
        assert!(!client.resumes(&disabled, None).await);
        assert!(!client.resumes(&disabled, Some(&client.latest())).await);
        let enabled = acceptor(static_config(), true);
        assert!(!client.resumes(&enabled, None).await);
        for _ in 0..3 {
            assert!(
                client.resumes(&enabled, Some(&client.latest())).await,
                "{version:?}"
            );
        }
    }
}

#[tokio::test]
async fn acceptors_keep_no_session_state() {
    let client = Client::with_config(
        SslVersion::TLS1_2,
        &TlsClientConfig::new()
            .with_server_verify(ServerVerifyMode::Disable)
            .with_tls12_session_tickets(false),
    );
    let server = acceptor(static_config(), true);
    assert!(!client.resumes(&server, None).await);
    // Without a ticket, only a server-side session cache could make it resumable.
    assert!(client.sessions.lock().is_empty());
}

#[tokio::test]
async fn acceptors_only_resume_their_own_sessions() {
    for version in VERSIONS {
        let client = Client::new(version);
        let config = static_config();
        let (first, second) = (
            acceptor(config.clone(), true),
            acceptor(config.clone(), true),
        );
        assert!(!client.resumes(&first, None).await);
        let from_first = client.latest();
        // The same configuration does not make another acceptor's tickets valid.
        assert!(!client.resumes(&second, Some(&from_first)).await);
        let from_second = client.latest();
        assert!(!client.resumes(&first, Some(&from_second)).await);
        assert!(client.resumes(&first.clone(), Some(&from_first)).await);
        assert!(client.resumes(&second, Some(&from_second)).await);

        let layer = TlsAcceptorLayer::new(config)
            .with_store_client_hello(true)
            .with_session_resumption(true);
        let (one, other) = (layer.layer(Inner), layer.layer(Inner));
        assert!(!client.resumes(&one, None).await);
        let from_one = client.latest();
        assert!(!client.resumes(&other, Some(&from_one)).await);
        assert!(client.resumes(&one, Some(&from_one)).await);
    }
}

#[tokio::test]
async fn connections_overriding_the_config_never_resume() {
    let http2 = |extensions: &Extensions| {
        extensions.insert(TlsAlpn::http_2());
    };
    for version in VERSIONS {
        let client = Client::new(version);
        let server = acceptor(static_config(), true);
        assert!(!client.resumes(&server, None).await);
        let shared = client.latest();
        let localhost = || Host::from_static("localhost");
        let (accepted, _) = client
            .connect(&server, localhost(), Some(&shared), http2)
            .await;
        assert_eq!(accepted.params.resumed, Some(false));
        let overridden = client.latest();
        let (accepted, _) = client
            .connect(&server, localhost(), Some(&overridden), http2)
            .await;
        assert_eq!(accepted.params.resumed, Some(false));
        assert!(client.resumes(&server, Some(&shared)).await);
    }
}

#[tokio::test]
async fn shared_contexts_keep_connection_state_apart() {
    for version in VERSIONS {
        let client = Client::new(version);
        let server = acceptor(
            TlsServerConfig::new().with_cert_issuer(ServerCertIssuerData::default()),
            true,
        );
        let target = |name: &'static str| {
            move |extensions: &Extensions| {
                extensions.insert(ConnectorTarget(HostWithPort::new(
                    Host::from_static(name),
                    443,
                )));
            }
        };
        let ip = || Host::from_static("127.0.0.1");
        for (server_name, sni, connection, expected) in [
            (
                Host::from_static("a.test"),
                Some("a.test"),
                target("x.test"),
                "a.test",
            ),
            (
                Host::from_static("b.test"),
                Some("b.test"),
                target("x.test"),
                "b.test",
            ),
            (ip(), None, target("c.test"), "c.test"),
            (ip(), None, target("d.test"), "d.test"),
        ] {
            let (accepted, names) = client.connect(&server, server_name, None, connection).await;
            assert_eq!(names, [expected]);
            let stored = accepted.client_hello.expect("every ClientHello is stored");
            assert_eq!(
                stored.ext_server_name().map(ToString::to_string).as_deref(),
                sni
            );
        }
        let issued_for_d = client.latest();
        let (accepted, _) = client
            .connect(&server, ip(), Some(&issued_for_d), target("e.test"))
            .await;
        assert_eq!(accepted.params.resumed, Some(true));
        assert!(accepted.client_hello.is_some());
    }
}
