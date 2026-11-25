//! IP-literal server identities on both TLS backends: clients verify the
//! certificate against the address without sending SNI, and servers accept
//! clients that send no SNI or a non-conformant IP-literal SNI.

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
    time::Duration,
};

use parking_lot::Mutex;
use rama::{
    Layer as _, Service, ServiceInput, error::BoxError, extensions::ExtensionsRef,
    service::service_fn, utils::octets::kib,
};
use rama_crypto::{
    cert::{CertificateAuthorityData, CertificateIdentity, LeafCertRequest, SelfSignedCaConfig},
    dep::rcgen::{CertificateParams, Issuer, KeyPair, SanType, string::Ia5String},
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
};
use rama_net::{
    Protocol,
    address::{Domain, Host, HostWithPort},
    client::{ConnectRequest, ConnectionError, EstablishedClientConnection},
    tls::ServerName,
};
use rama_tls::{
    SecureTransport,
    client::{
        ClientHello, ClientHelloExtension, NegotiatedTlsParameters, TlsClientConfig, TlsClientSni,
        TlsServerCertPinSet, TlsServerCertPins,
    },
    server::{ServerAuthData, TlsServerConfig},
};
use rama_tls_boring::{
    client::TlsConnector as BoringConnector,
    core::{
        ssl::{SslConnector, SslMethod, SslVerifyMode},
        tokio::SslStreamBuilder,
    },
    server::TlsAcceptorLayer as BoringAcceptorLayer,
};
use rama_tls_rustls::{
    client::TlsConnector as RustlsConnector,
    dep::{rustls, rustls::version::TLS13},
    server::{
        DynamicConfigProvider, RustlsServerConfigExt as _, TlsAcceptorLayer as RustlsAcceptorLayer,
        TlsStream as RustlsStream,
    },
};
use tokio::{
    io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, DuplexStream, duplex},
    time::timeout,
};

const V4: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
const V6: IpAddr = IpAddr::V6(Ipv6Addr::LOCALHOST);

/// The hellos servers saw, in arrival order.
type Seen = Arc<Mutex<Vec<Option<ClientHello>>>>;

#[derive(Clone, Copy, Debug)]
enum Backend {
    Boring,
    Rustls,
}

/// Serves a TLS connection: records the hello it carried and echoes one byte.
#[derive(Clone)]
struct Recorder(Seen);

impl<S> Service<S> for Recorder
where
    S: AsyncRead + AsyncWrite + ExtensionsRef + Send + Unpin + 'static,
{
    type Output = ();

    type Error = std::io::Error;

    async fn serve(&self, mut stream: S) -> Result<Self::Output, Self::Error> {
        let hello = stream
            .extensions()
            .get_ref::<SecureTransport>()
            .and_then(SecureTransport::client_hello)
            .cloned();
        if let Some(hello) = &hello {
            assert_eq!(
                stream
                    .extensions()
                    .get_ref::<NegotiatedTlsParameters>()
                    .unwrap()
                    .server_name
                    .as_ref(),
                hello.ext_server_name()
            );
        }
        self.0.lock().push(hello);
        let byte = stream.read_u8().await?;
        stream.write_u8(byte).await
    }
}

type Accept = Arc<dyn Fn(ServiceInput<DuplexStream>) + Send + Sync>;

/// Dials an in-memory server, one served connection per dial.
#[derive(Clone)]
struct Dial(Accept);

impl Service<ConnectRequest> for Dial {
    type Output = EstablishedClientConnection<ServiceInput<DuplexStream>, ConnectRequest>;

    type Error = ConnectionError;

    async fn serve(&self, input: ConnectRequest) -> Result<Self::Output, Self::Error> {
        let (client, server) = duplex(kib(64));
        (self.0)(ServiceInput::new(server));
        Ok(EstablishedClientConnection {
            input,
            conn: ServiceInput::new(client),
        })
    }
}

/// A server on `backend` serving `auth` that records each hello.
fn server(backend: Backend, auth: ServerAuthData, seen: Seen) -> Dial {
    let config = TlsServerConfig::new().with_server_auth(auth);
    match backend {
        Backend::Boring => {
            let acceptor = BoringAcceptorLayer::new(config)
                .with_store_client_hello(true)
                .into_layer(Recorder(seen));
            Dial(Arc::new(move |io| {
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let _served = acceptor.serve(io).await;
                });
            }))
        }
        Backend::Rustls => {
            let acceptor = RustlsAcceptorLayer::new(config)
                .with_store_client_hello(true)
                .into_layer(Recorder(seen));
            Dial(Arc::new(move |io| {
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let _served = acceptor.serve(io).await;
                });
            }))
        }
    }
}

/// A CA and a leaf it issued for `identities`.
fn issued(identities: Vec<CertificateIdentity>) -> (ServerAuthData, CertificateDer<'static>) {
    let ca = CertificateAuthorityData::generate(SelfSignedCaConfig::default()).unwrap();
    let auth = ServerAuthData::new_issued_by(
        &ca,
        LeafCertRequest {
            config: Default::default(),
            identities,
        },
    )
    .unwrap();
    (auth, ca.certificate_chain()[0].clone())
}

/// A CA and a leaf whose only name is a `dNSName` spelling `ip`.
fn issued_with_ip_as_dns_name(ip: IpAddr) -> (ServerAuthData, CertificateDer<'static>) {
    let ca = CertificateAuthorityData::generate(SelfSignedCaConfig::default()).unwrap();
    let issuer = Issuer::from_ca_cert_der(
        &ca.certificate_chain()[0],
        KeyPair::try_from(ca.private_key()).unwrap(),
    )
    .unwrap();
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::default();
    params.subject_alt_names = vec![SanType::DnsName(
        Ia5String::try_from(ip.to_string()).unwrap(),
    )];
    let leaf = params.signed_by(&key, &issuer).unwrap();
    let auth = ServerAuthData {
        cert_chain: vec![leaf.into(), ca.certificate_chain()[0].clone()],
        private_key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        ocsp: None,
    };
    (auth, ca.certificate_chain()[0].clone())
}

/// Connect with `backend` to `ip`, trusting `anchor`. Returns whether the handshake verified.
async fn connect_to_ip(
    backend: Backend,
    dial: Dial,
    ip: IpAddr,
    anchor: CertificateDer<'static>,
) -> bool {
    let config = TlsClientConfig::new()
        .try_with_server_trust_anchors([anchor])
        .unwrap();
    connect_with(backend, dial, ip, config).await
}

/// Connect with `backend` and `config` to `ip`. Returns whether the handshake verified.
async fn connect_with(backend: Backend, dial: Dial, ip: IpAddr, config: TlsClientConfig) -> bool {
    let request = ConnectRequest::new(HostWithPort::new(Host::Address(ip), 443))
        .with_application_protocol(Protocol::HTTPS);
    let exchange = async {
        let mut conn: Box<dyn IoWithParams> = match backend {
            Backend::Boring => Box::new(
                BoringConnector::secure(dial)
                    .with_base_config(config)
                    .serve(request)
                    .await
                    .ok()?
                    .conn,
            ),
            Backend::Rustls => Box::new(
                RustlsConnector::secure(dial)
                    .with_base_config(config)
                    .serve(request)
                    .await
                    .ok()?
                    .conn,
            ),
        };
        conn.write_all(b"x").await.ok()?;
        (conn.read_u8().await.ok()? == b'x').then_some(())
    };
    timeout(Duration::from_secs(5), exchange)
        .await
        .unwrap()
        .is_some()
}

trait IoWithParams: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T: AsyncRead + AsyncWrite + Unpin + Send> IoWithParams for T {}

fn has_server_name_extension(hello: &ClientHello) -> bool {
    hello
        .extensions()
        .iter()
        .any(|extension| matches!(extension, ClientHelloExtension::ServerName(_)))
}

#[tokio::test]
async fn clients_verify_ip_identities_without_sending_sni() {
    for backend in [Backend::Boring, Backend::Rustls] {
        for ip in [V4, V6] {
            let seen = Seen::default();
            let (auth, anchor) = issued(vec![CertificateIdentity::Ip(ip)]);
            let dial = server(backend, auth, seen.clone());
            assert!(
                connect_to_ip(backend, dial, ip, anchor).await,
                "{backend:?} to {ip}"
            );
            let seen = seen.lock();
            let hello = seen[0].as_ref().expect("the server stores the hello");
            assert!(!has_server_name_extension(hello), "{backend:?} to {ip}");
        }
    }
}

#[tokio::test]
async fn clients_opt_in_to_ip_literal_sni_without_changing_verification() {
    for ip in [V4, V6] {
        let seen = Seen::default();
        let (auth, anchor) = issued(vec![CertificateIdentity::Ip(ip)]);
        let config = TlsClientConfig::new()
            .with_sni_policy(TlsClientSni::IncludeIp)
            .try_with_server_trust_anchors([anchor])
            .unwrap();
        assert!(
            connect_with(
                Backend::Boring,
                server(Backend::Boring, auth, seen.clone()),
                ip,
                config
            )
            .await
        );
        let seen = seen.lock();
        let hello = seen[0].as_ref().unwrap();
        assert_eq!(
            hello.ext_server_name().and_then(|name| name.as_ip()),
            Some(ip)
        );
        assert!(hello.ext_server_domain().is_none());
    }
}

#[tokio::test]
async fn rustls_rejects_the_ip_literal_sni_opt_in() {
    for ip in [V4, V6] {
        let (auth, anchor) = issued(vec![CertificateIdentity::Ip(ip)]);
        let config = TlsClientConfig::new()
            .with_sni_policy(TlsClientSni::IncludeIp)
            .try_with_server_trust_anchors([anchor])
            .unwrap();
        let request = ConnectRequest::new(HostWithPort::new(Host::Address(ip), 443))
            .with_application_protocol(Protocol::HTTPS);
        let error = RustlsConnector::secure(server(Backend::Boring, auth, Seen::default()))
            .with_base_config(config)
            .serve(request)
            .await
            .expect_err("unsupported SNI policy must fail the connection");
        assert!(format!("{error:?}").contains("IP literal SNI requires the BoringSSL backend"));
    }
}

#[tokio::test]
async fn disabling_dns_sni_preserves_certificate_name_verification() {
    for backend in [Backend::Boring, Backend::Rustls] {
        for certificate_name in ["localhost", "unrelated.example"] {
            let (auth, anchor) = issued(vec![CertificateIdentity::Dns(
                Domain::try_from(certificate_name).unwrap(),
            )]);
            let seen = Seen::default();
            let config = TlsClientConfig::new()
                .with_server_name(Domain::tld_localhost())
                .with_sni_policy(TlsClientSni::Disabled)
                .try_with_server_trust_anchors([anchor])
                .unwrap();
            let verified = connect_with(
                backend,
                server(Backend::Boring, auth, seen.clone()),
                V4,
                config,
            )
            .await;
            assert_eq!(verified, certificate_name == "localhost", "{backend:?}");
            if verified {
                assert!(!has_server_name_extension(seen.lock()[0].as_ref().unwrap()));
            }
        }
    }
}

#[tokio::test]
async fn ip_identities_match_only_their_own_ip_address_name() {
    let mapped = IpAddr::V6(Ipv4Addr::LOCALHOST.to_ipv6_mapped());
    for backend in [Backend::Boring, Backend::Rustls] {
        for (target, certificate) in [
            // Another address of the same family and of the other family.
            (
                V4,
                issued(vec![CertificateIdentity::Ip(
                    Ipv4Addr::new(127, 0, 0, 2).into(),
                )]),
            ),
            (V6, issued(vec![CertificateIdentity::Ip(V4)])),
            // An IPv4-mapped IPv6 address and its IPv4 address are distinct identities.
            (mapped, issued(vec![CertificateIdentity::Ip(V4)])),
            (V4, issued(vec![CertificateIdentity::Ip(mapped)])),
            // A name never matches an address, even when it spells it.
            (
                V4,
                issued(vec![CertificateIdentity::Dns(Domain::from_static(
                    "localhost",
                ))]),
            ),
            (V4, issued_with_ip_as_dns_name(V4)),
            (V6, issued_with_ip_as_dns_name(V6)),
        ] {
            let (auth, anchor) = certificate;
            let dial = server(backend, auth, Seen::default());
            assert!(
                !connect_to_ip(backend, dial, target, anchor).await,
                "{backend:?} to {target}"
            );
        }
    }
}

#[tokio::test]
async fn ip_literal_sni_accepts_only_the_matching_ip_address_san() {
    for (ip, certificate) in [
        (V4, issued_with_ip_as_dns_name(V4)),
        (V6, issued_with_ip_as_dns_name(V6)),
        (V4, issued(vec![CertificateIdentity::Ip(V6)])),
        (V6, issued(vec![CertificateIdentity::Ip(V4)])),
        (
            V4,
            issued(vec![CertificateIdentity::Ip(
                Ipv4Addr::LOCALHOST.to_ipv6_mapped().into(),
            )]),
        ),
    ] {
        let (auth, anchor) = certificate;
        let config = TlsClientConfig::new()
            .with_sni_policy(TlsClientSni::IncludeIp)
            .try_with_server_trust_anchors([anchor])
            .unwrap();
        assert!(
            !connect_with(
                Backend::Boring,
                server(Backend::Boring, auth, Seen::default()),
                ip,
                config
            )
            .await
        );
    }
}

/// Handshake with a client that sends `server_name` as SNI without verifying the server.
async fn handshake_with_raw_sni(dial: Dial, server_name: Option<&str>) -> bool {
    let (client, server) = duplex(kib(64));
    (dial.0)(ServiceInput::new(server));
    let mut builder = SslConnector::builder(SslMethod::tls()).unwrap();
    builder.set_verify(SslVerifyMode::NONE);
    let mut ssl = builder.build().configure().unwrap().into_ssl(None).unwrap();
    if let Some(server_name) = server_name {
        ssl.set_hostname(server_name).unwrap();
    }
    let exchange = async {
        let mut stream = SslStreamBuilder::new(ssl, client).connect().await.ok()?;
        stream.write_all(b"x").await.ok()?;
        (stream.read_u8().await.ok()? == b'x').then_some(())
    };
    timeout(Duration::from_secs(5), exchange)
        .await
        .unwrap()
        .is_some()
}

#[tokio::test]
async fn servers_accept_clients_without_sni_and_with_ip_literal_sni() {
    for backend in [Backend::Boring, Backend::Rustls] {
        for server_name in [None, Some("127.0.0.1"), Some("::1")] {
            let (auth, _) = issued(vec![CertificateIdentity::Ip(V4)]);
            let seen = Seen::default();
            // The other side reports hellos with an IP literal; this checks the handshake itself.
            let config = TlsServerConfig::new().with_server_auth(auth);
            let dial = match backend {
                Backend::Boring => {
                    let acceptor = BoringAcceptorLayer::new(config)
                        .with_store_client_hello(true)
                        .into_layer(Recorder(seen.clone()));
                    Dial(Arc::new(move |io| {
                        let acceptor = acceptor.clone();
                        tokio::spawn(async move {
                            let _served = acceptor.serve(io).await;
                        });
                    }))
                }
                Backend::Rustls => {
                    let acceptor = RustlsAcceptorLayer::new(config)
                        .with_store_client_hello(true)
                        .into_layer(Recorder(seen.clone()));
                    Dial(Arc::new(move |io| {
                        let acceptor = acceptor.clone();
                        tokio::spawn(async move {
                            let _served = acceptor.serve(io).await;
                        });
                    }))
                }
            };
            assert!(
                handshake_with_raw_sni(dial, server_name).await,
                "{backend:?} with SNI {server_name:?}"
            );
            let observed = seen.lock();
            assert_eq!(
                observed[0].as_ref().unwrap().ext_server_name(),
                server_name
                    .map(|name| name.parse::<ServerName>().unwrap())
                    .as_ref()
            );
        }
    }
}

#[tokio::test]
async fn address_scoped_pins_apply_to_every_spelling_of_the_address() {
    let spellings = [
        Host::Address(V4),
        Host::Name(Domain::try_from("127.0.0.1").unwrap()),
    ];
    for backend in [Backend::Boring, Backend::Rustls] {
        for scope in &spellings {
            for server_name in &spellings {
                let (auth, anchor) = issued(vec![CertificateIdentity::Ip(V4)]);
                let leaf = auth.cert_chain[0].clone();
                let (unrelated, _) = issued(vec![CertificateIdentity::Ip(V4)]);
                let pinned = |pin: CertificateDer<'static>| {
                    TlsClientConfig::new()
                        .try_with_server_trust_anchors([anchor.clone()])
                        .unwrap()
                        .with_server_name(ServerName::try_from(server_name).unwrap())
                        .with_server_cert_pins(TlsServerCertPins::new(
                            TlsServerCertPinSet::new(pin)
                                .with_server_name(ServerName::try_from(scope).unwrap()),
                        ))
                };
                let dial = server(backend, auth, Seen::default());
                assert!(
                    connect_with(backend, dial.clone(), V4, pinned(leaf)).await,
                    "{backend:?}: matching pin for {scope:?} via {server_name:?}"
                );
                assert!(
                    !connect_with(backend, dial, V4, pinned(unrelated.cert_chain[0].clone())).await,
                    "{backend:?}: mismatching pin for {scope:?} via {server_name:?}"
                );
            }
        }
    }
}

struct DynamicIpConfig {
    v4: Arc<rustls::ServerConfig>,
    v6: Arc<rustls::ServerConfig>,
}

impl DynamicConfigProvider for DynamicIpConfig {
    async fn get_config(
        &self,
        native: rustls::server::ClientHello<'_>,
        server_name: Option<&ServerName>,
    ) -> Result<Arc<rustls::ServerConfig>, BoxError> {
        assert!(native.server_name().is_none());
        match server_name.and_then(ServerName::as_ip) {
            Some(ip) if ip == V6 => Ok(self.v6.clone()),
            Some(ip) if ip == V4 => Ok(self.v4.clone()),
            None => Ok(self.v4.clone()),
            _ => unreachable!("the fixture offers only its two addresses"),
        }
    }
}

#[tokio::test]
async fn rustls_dynamic_certificate_selection_uses_observed_ip_sni() {
    #[cfg(feature = "aws-lc")]
    let provider = rustls::crypto::aws_lc_rs::default_provider;
    #[cfg(not(feature = "aws-lc"))]
    let provider = rustls::crypto::ring::default_provider;
    let config = |ip| {
        let (auth, _) = issued(vec![CertificateIdentity::Ip(ip)]);
        Arc::new(
            rustls::ServerConfig::builder_with_provider(Arc::new(provider()))
                .with_protocol_versions(&[&TLS13])
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(auth.cert_chain, auth.private_key)
                .unwrap(),
        )
    };
    let acceptor = RustlsAcceptorLayer::new(TlsServerConfig::new().with_dynamic_config(Arc::new(
        DynamicIpConfig {
            v4: config(V4),
            v6: config(V6),
        },
    )))
    .into_layer(service_fn(
        |stream: RustlsStream<ServiceInput<DuplexStream>>| async move {
            Ok::<_, BoxError>(
                stream
                    .extensions()
                    .get_ref::<NegotiatedTlsParameters>()
                    .unwrap()
                    .clone(),
            )
        },
    ));
    for ip in [None, Some(V4), Some(V6)] {
        let mut builder = SslConnector::builder(SslMethod::tls_client()).unwrap();
        builder.set_verify(SslVerifyMode::NONE);
        let mut ssl = builder.build().configure().unwrap().into_ssl(None).unwrap();
        if let Some(ip) = ip {
            ssl.set_hostname(&ip.to_string()).unwrap();
        }
        let (client, server) = duplex(kib(64));
        let (client, server) = tokio::join!(
            SslStreamBuilder::new(ssl, client).connect(),
            acceptor.serve(ServiceInput::new(server))
        );
        let client = client.unwrap();
        let metadata = server.unwrap();
        assert_eq!(metadata.server_name, ip.map(ServerName::from));
        let expected = match ip.unwrap_or(V4) {
            IpAddr::V4(ip) => ip.octets().to_vec(),
            IpAddr::V6(ip) => ip.octets().to_vec(),
        };
        let certificate = client.ssl().peer_certificate().unwrap();
        assert!(
            certificate
                .subject_alt_names()
                .unwrap()
                .iter()
                .any(|name| name.ipaddress() == Some(expected.as_slice()))
        );
    }
}

#[tokio::test]
async fn bracketed_ipv6_sni_follows_the_native_server_decoders() {
    for (backend, accepts) in [(Backend::Boring, true), (Backend::Rustls, false)] {
        let (auth, _) = issued(vec![CertificateIdentity::Ip(V6)]);
        let dial = server(backend, auth, Seen::default());
        assert_eq!(
            handshake_with_raw_sni(dial, Some("[::1]")).await,
            accepts,
            "{backend:?}"
        );
    }
}
