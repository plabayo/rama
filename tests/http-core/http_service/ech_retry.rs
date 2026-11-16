//! Authenticated ECH recovery must redial through the selected proxy.
use rama::{
    Layer as _,
    http::{
        conn::HttpOrigin,
        layer::{
            alt_svc::AltSvcCache, http_service::HttpServiceConnector,
            https_service::HttpsServiceLayer,
        },
    },
    net::{Protocol, client::ConnectionErrorKind},
};
use rama::{
    Service, ServiceInput,
    crypto::{
        cert::{GeneratedServerAuthConfig, generate_server_auth},
        pki_types::CertificateDer,
    },
    error::{BoxError, BoxErrorExt as _},
    extensions::ExtensionsRef,
    net::{
        ConnectorTargetInputExt as _,
        address::Domain,
        client::{ConnectRequest, ConnectionError, EstablishedClientConnection, ProxyRoute},
    },
    tls::{
        boring::{
            client::TlsConnector,
            core::{
                hpke::HpkeKey,
                pkey::PKey,
                ssl::{SslAcceptor, SslEchKeys, SslMethod},
                tokio as boring_tokio,
                x509::X509,
            },
        },
        client::{EchRequirement, TlsClientConfig, TlsEchAccepted},
    },
};
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
#[derive(Clone)]
struct ForbiddenDns(Arc<AtomicUsize>);
impl rama::dns::client::resolver::DnsAddressResolver for ForbiddenDns {
    type Error = BoxError;

    fn lookup_ipv4(
        &self,
        _: Domain,
    ) -> impl rama::futures::Stream<Item = Result<std::net::Ipv4Addr, Self::Error>> + Send + '_
    {
        self.0.fetch_add(1, Ordering::SeqCst);
        rama::futures::stream::empty()
    }

    fn lookup_ipv6(
        &self,
        _: Domain,
    ) -> impl rama::futures::Stream<Item = Result<std::net::Ipv6Addr, Self::Error>> + Send + '_
    {
        self.0.fetch_add(1, Ordering::SeqCst);
        rama::futures::stream::empty()
    }
}

/// An ECHConfigList with public name `ech.com` (config id 0).
const ECH_CONFIG_LIST: &[u8] = &[
    0x00, 0x3e, 0xfe, 0x0d, 0x00, 0x3a, 0x00, 0x00, 0x20, 0x00, 0x20, 0xbb, 0x2f, 0x29, 0xe3, 0xe3,
    0x05, 0x7e, 0x04, 0x19, 0xd5, 0x2f, 0xc5, 0xf4, 0x41, 0x18, 0x77, 0x6f, 0x8d, 0xb6, 0x1c, 0xea,
    0x4f, 0xdf, 0x76, 0x07, 0x9b, 0x93, 0x60, 0x6c, 0x5a, 0x62, 0x48, 0x00, 0x08, 0x00, 0x01, 0x00,
    0x01, 0x00, 0x01, 0x00, 0x03, 0x00, 0x07, 0x65, 0x63, 0x68, 0x2e, 0x63, 0x6f, 0x6d, 0x00, 0x00,
];

/// The server's ECHConfig (config id 1), whose key cannot decrypt the list above.
const SERVER_ECH_CONFIG: &[u8] = &[
    0xfe, 0x0d, 0x00, 0x3a, 0x01, 0x00, 0x20, 0x00, 0x20, 0x7e, 0xfb, 0x5f, 0xee, 0xa2, 0xa2, 0x74,
    0xb3, 0xff, 0xfe, 0x69, 0x51, 0x9e, 0xfa, 0xe1, 0xfa, 0x49, 0x8c, 0x61, 0x2c, 0xfa, 0xd0, 0x0f,
    0x8c, 0x22, 0x87, 0x0e, 0xbc, 0xb0, 0x2d, 0x76, 0x25, 0x00, 0x08, 0x00, 0x01, 0x00, 0x01, 0x00,
    0x01, 0x00, 0x03, 0x00, 0x07, 0x65, 0x63, 0x68, 0x2e, 0x63, 0x6f, 0x6d, 0x00, 0x00,
];

const SERVER_ECH_KEY: &[u8] = &[
    0xa7, 0x35, 0x44, 0x24, 0x6c, 0xfe, 0xb0, 0x53, 0x4c, 0x62, 0x7e, 0xca, 0x2e, 0x11, 0x8f, 0x56,
    0x3c, 0xc0, 0x2e, 0x6a, 0xa2, 0xe7, 0xaf, 0x3a, 0x7d, 0xb4, 0x72, 0x13, 0x1e, 0x88, 0xb6, 0x85,
];

const ORIGIN: &str = "origin.example";

fn retry_test_server(name: &'static str, config_id: u8) -> (SslAcceptor, CertificateDer<'static>) {
    let (chain, key) = generate_server_auth(GeneratedServerAuthConfig::generated_ca_for(
        Domain::from_static(name),
    ))
    .unwrap();
    let mut config = SERVER_ECH_CONFIG.to_vec();
    config[4] = config_id;
    let mut keys = SslEchKeys::builder().unwrap();
    keys.add_key(
        true,
        &config,
        HpkeKey::dhkem_p256_sha256(SERVER_ECH_KEY).unwrap(),
    )
    .unwrap();
    let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
    builder
        .set_certificate(&X509::from_der(&chain[0]).unwrap())
        .unwrap();
    builder
        .add_extra_chain_cert(X509::from_der(&chain[1]).unwrap())
        .unwrap();
    builder
        .set_private_key(&PKey::private_key_from_der(key.secret_der()).unwrap())
        .unwrap();
    builder.set_ech_keys(&keys.build()).unwrap();
    builder.set_alpn_select_callback(|_, offered| {
        rama::tls::boring::core::ssl::select_next_proto(b"\x02h2", offered)
            .ok_or(rama::tls::boring::core::ssl::AlpnError::NOACK)
    });
    (builder.build(), chain[1].clone())
}

#[tokio::test]
async fn authenticated_retry_preserves_http_connect_and_socks5h_routes() {
    for socks in [false, true] {
        let (first, first_ca) = retry_test_server("ech.com", 1);
        let (second, second_ca) = retry_test_server(ORIGIN, 1);
        let servers = Arc::new([first, second]);
        let calls = Arc::new(AtomicUsize::new(0));
        let transport = rama::service::service_fn({
            let calls = calls.clone();
            move |input: ConnectRequest| {
                assert_eq!(
                    input.connector_target().unwrap().to_string(),
                    "proxy.example:3128"
                );
                let server = servers[calls.fetch_add(1, Ordering::SeqCst)].clone();
                async move {
                    let (client, mut peer) = tokio::io::duplex(65536);
                    tokio::spawn(async move {
                        if socks {
                            let mut greeting = [0; 3];
                            peer.read_exact(&mut greeting).await.unwrap();
                            assert_eq!(greeting, [5, 1, 0]);
                            peer.write_all(&[5, 0]).await.unwrap();
                            let mut header = [0; 5];
                            peer.read_exact(&mut header).await.unwrap();
                            assert_eq!(&header[..4], &[5, 1, 0, 3]);
                            let mut name = vec![0; usize::from(header[4])];
                            peer.read_exact(&mut name).await.unwrap();
                            assert_eq!(name, ORIGIN.as_bytes());
                            assert_eq!(peer.read_u16().await.unwrap(), 443);
                            peer.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0])
                                .await
                                .unwrap();
                        } else {
                            let mut header = Vec::new();
                            while !header.ends_with(b"\r\n\r\n") {
                                header.push(peer.read_u8().await.unwrap());
                                assert!(header.len() < 8192);
                            }
                            assert!(header.starts_with(b"CONNECT origin.example:443 HTTP/1.1\r\n"));
                            peer.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                                .await
                                .unwrap();
                        }
                        drop(boring_tokio::accept(&server, peer).await);
                    });
                    Ok::<_, ConnectionError>(EstablishedClientConnection {
                        input,
                        conn: ServiceInput::new(client),
                    })
                }
            }
        });
        let proxy = rama::http::client::ProxyConnector::optional(
            transport,
            rama::proxy::socks5::Socks5ProxyConnectorLayer::required(),
            rama::http::client::proxy::layer::HttpProxyConnectorLayer::required(),
        );
        let tls = TlsClientConfig::new()
            .with_encrypted_client_hello(true)
            .try_with_server_trust_anchors(vec![first_ca, second_ca])
            .unwrap();
        let input = ConnectRequest::new("origin.example:443".parse().unwrap());
        let dns_calls = Arc::new(AtomicUsize::new(0));
        input.extensions().insert(
            rama::dns::client::resolver::DnsAddresssResolverOverwrite::new(ForbiddenDns(
                dns_calls.clone(),
            )),
        );
        input.extensions().insert(ProxyRoute::Proxy(
            if socks {
                "socks5h://proxy.example:3128"
            } else {
                "http://proxy.example:3128"
            }
            .parse()
            .unwrap(),
        ));
        input.extensions().insert(EchRequirement::Required);
        input
            .extensions()
            .insert(rama::net::tls::TargetEchConfig::new(
                input.authority.clone(),
                ECH_CONFIG_LIST,
            ));
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            TlsConnector::secure(proxy)
                .with_base_config(tls)
                .serve(input),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(dns_calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            result.conn.extensions().get_ref::<TlsEchAccepted>(),
            Some(&TlsEchAccepted(true))
        );
        assert!(
            result
                .input
                .extensions()
                .get_ref::<ProxyRoute>()
                .unwrap()
                .proxy_address()
                .is_some()
        );
    }
}

#[tokio::test]
async fn caller_required_ech_failure_does_not_poison_alt_svc() {
    let cache = AltSvcCache::default();
    let input = ConnectRequest::new("origin.example:443".parse().unwrap())
        .with_application_protocol(Protocol::HTTPS);
    let origin = HttpOrigin::new(Protocol::HTTPS, input.authority.clone()).unwrap();
    cache.record_frame(
        &origin,
        rama::bytes::Bytes::from_static(b"h2=\"alt.example:443\""),
        std::time::Instant::now(),
    );
    let snapshot = cache.lookup(&origin).unwrap();
    input.extensions().insert(EchRequirement::Required);
    let dials = Arc::new(AtomicUsize::new(0));
    let transport = rama::service::service_fn({
        let dials = dials.clone();
        move |_: ConnectRequest| {
            dials.fetch_add(1, Ordering::SeqCst);
            async {
                Err::<
                    EstablishedClientConnection<
                        ServiceInput<tokio::io::DuplexStream>,
                        ConnectRequest,
                    >,
                    _,
                >(ConnectionError::local(
                    BoxError::from_static_str("unexpected dial"),
                    ConnectionErrorKind::InvalidInput,
                ))
            }
        }
    });
    let error = HttpServiceConnector::new(TlsConnector::secure(transport))
        .with_cache(cache.clone())
        .serve(input)
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ConnectionErrorKind::InvalidInput);
    assert_eq!(dials.load(Ordering::SeqCst), 0);
    assert!(cache.is_usable(&snapshot, 0));
}

#[derive(Clone)]
struct SlowAlternativeDns;
impl rama::dns::client::resolver::DnsAddressResolver for SlowAlternativeDns {
    type Error = BoxError;

    fn lookup_ipv4(
        &self,
        _: Domain,
    ) -> impl rama::futures::Stream<Item = Result<std::net::Ipv4Addr, Self::Error>> + Send + '_
    {
        rama::futures::stream::empty()
    }

    fn lookup_ipv6(
        &self,
        _: Domain,
    ) -> impl rama::futures::Stream<Item = Result<std::net::Ipv6Addr, Self::Error>> + Send + '_
    {
        rama::futures::stream::empty()
    }
}

impl rama::dns::client::resolver::DnsServiceBindingResolver for SlowAlternativeDns {
    type Error = BoxError;

    fn lookup_https(
        &self,
        domain: Domain,
    ) -> impl rama::futures::Stream<
        Item = Result<rama::dns::client::resolver::ServiceBindingRecord, Self::Error>,
    > + Send
    + '_ {
        rama::futures::stream::once(async move {
            if domain != Domain::from_static(ORIGIN) {
                std::future::pending::<()>().await;
            }
            // Root target with H2 and the server's real ECHConfigList.
            let mut wire = vec![0, 1, 0, 0, 1, 0, 3, 2, b'h', b'2', 0, 5];
            wire.extend_from_slice(&((SERVER_ECH_CONFIG.len() + 2) as u16).to_be_bytes());
            wire.extend_from_slice(&(SERVER_ECH_CONFIG.len() as u16).to_be_bytes());
            wire.extend_from_slice(SERVER_ECH_CONFIG);
            Ok(rama::dns::client::resolver::ServiceBindingRecord {
                owner: rama::dns::wire::Name::from_presentation(ORIGIN).unwrap(),
                binding: rama::dns::wire::ServiceBinding::parse_rdata(&wire).unwrap(),
            })
        })
    }

    fn lookup_svcb(
        &self,
        _: Domain,
    ) -> impl rama::futures::Stream<
        Item = Result<rama::dns::client::resolver::ServiceBindingRecord, Self::Error>,
    > + Send
    + '_ {
        rama::futures::stream::empty()
    }
}

#[tokio::test]
async fn slow_alt_dns_retains_primary_real_ech_connection() {
    for required in [false, true] {
        let (server, ca) = retry_test_server(ORIGIN, 1);
        let transport = rama::service::service_fn(move |input: ConnectRequest| {
            let server = server.clone();
            assert_eq!(
                input.connector_target().unwrap().host,
                rama::net::address::Host::from_static(ORIGIN)
            );
            async move {
                let (client, peer) = tokio::io::duplex(65536);
                tokio::spawn(async move {
                    let stream = boring_tokio::accept(&server, peer).await.unwrap();
                    let service = rama::service::service_fn(async |_: rama::http::Request| {
                        Ok::<_, std::convert::Infallible>(rama::http::Response::new(
                            rama::http::Body::empty(),
                        ))
                    });
                    // Dropping the established client may close this fixture connection.
                    drop(
                        rama::http::server::HttpServer::auto(rama::graceful::WeakScope::detached())
                            .service(service)
                            .serve(ServiceInput::new(stream))
                            .await,
                    );
                });
                Ok::<_, ConnectionError>(EstablishedClientConnection {
                    input,
                    conn: ServiceInput::new(client),
                })
            }
        });
        let tls = TlsClientConfig::new()
            .with_encrypted_client_hello(true)
            .try_with_server_trust_anchors([ca])
            .unwrap();
        let input = ConnectRequest::new("origin.example:443".parse().unwrap())
            .with_application_protocol(Protocol::HTTPS);
        if required {
            input.extensions().insert(EchRequirement::Required);
        }
        let cache = AltSvcCache::default();
        cache.record_frame(
            &rama::http::conn::HttpOrigin::new(Protocol::HTTPS, input.authority.clone()).unwrap(),
            rama::bytes::Bytes::from_static(b"h2=\"slow.example:443\""),
            std::time::Instant::now(),
        );
        let connector = HttpsServiceLayer::new()
            .with_resolver(SlowAlternativeDns)
            .with_cache(cache)
            .with_ech_capable(true)
            .with_tls(tls.clone())
            .with_timeout(Duration::from_millis(20))
            .layer(HttpServiceConnector::new(
                rama::http::client::HttpConnector::<_, rama::http::Body>::new(
                    TlsConnector::secure(transport).with_base_config(tls),
                    rama::graceful::WeakScope::detached(),
                ),
            ));
        let connection = tokio::time::timeout(Duration::from_secs(5), connector.serve(input))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            connection.conn.extensions().get_ref::<TlsEchAccepted>(),
            Some(&TlsEchAccepted(true))
        );
    }
}

#[cfg(feature = "ua-embed-profiles")]
mod profile;
