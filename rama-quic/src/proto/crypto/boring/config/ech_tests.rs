use rama_core::{
    Service,
    error::CauseExt as _,
    extensions::{Extensions, ExtensionsRef},
    graceful::WeakScope,
};
use rama_crypto::dep::boring::{hpke::HpkeKey, ssl::SslEchKeys};
use rama_net::{
    address::{Domain, HostWithPort, SocketAddress},
    client::{ConnectRequest, ConnectorTarget, pool::ConnectionReuse},
    tls::{TargetEchConfig, TargetEchServiceBinding},
};
use rama_tls::{
    ExtensionId,
    client::{
        ClientHelloHandshakePrefix, EchRequirement, TlsEchAccepted,
        parse_client_hello_message_prefix,
    },
    server::{CertificateIssuanceContext, DynamicCertIssuer, ServerAuthData, TlsServerAuth},
};
use rama_tls_boring::server::{
    BoringServerConfigExt as _, CacheKind, EchServerKey, EchServerKeys, ReloadableEchServerKeys,
    ServerCertIssuerData,
};

use super::{
    super::tests::{configs, handshake},
    *,
};
use crate::{
    Endpoint, ServerConfig,
    client::{QuicConnector, SharedQuicEndpoint},
    proto::crypto::{ClientConfig as _, HandshakeEvent, ServerConfig as _},
    test_helpers::ech_keys::{SERVER_ECH_CONFIG, SERVER_ECH_KEY},
    tls::BoringTlsProvider,
};

fn ech_server(config: &TlsServerConfig) -> QuicServerConfig {
    let mut keys = SslEchKeys::builder().unwrap();
    keys.add_key(
        true,
        SERVER_ECH_CONFIG,
        HpkeKey::dhkem_p256_sha256(SERVER_ECH_KEY).unwrap(),
    )
    .unwrap();
    let keys = keys.build();
    let options = TlsOptions::default();
    let data = acceptor_data(config, options).unwrap();
    let mut server = QuicServerConfig::from_rama(config, options).unwrap();
    server.contexts = contexts(
        || {
            let builder = data.clone().into_static_acceptor_builder()?;
            builder.set_ech_keys(&keys)?;
            Ok(builder)
        },
        options,
    )
    .unwrap()
    .map(Arc::new);
    server
}

fn ech_config(target: HostWithPort) -> TargetEchConfig {
    let mut bytes = (SERVER_ECH_CONFIG.len() as u16).to_be_bytes().to_vec();
    bytes.extend_from_slice(SERVER_ECH_CONFIG);
    TargetEchConfig::new(target, bytes)
}

#[test]
fn native_session_checks_the_ech_resolution_it_constructs() {
    for ready in [false, true] {
        let (client, server) = configs();
        let target: HostWithPort = "localhost:443".parse().unwrap();
        client
            .as_extensions()
            .insert(ConnectorTarget(target.clone()));
        if ready {
            client.as_extensions().insert(ech_config(target.clone()));
        }
        let prepared = QuicClientConfig::from_rama(&client, TlsOptions::default()).unwrap();
        assert_eq!(prepared.ech.is_some(), ready);
        if ready {
            client
                .as_extensions()
                .insert(TlsEncryptedClientHello(false));
        } else {
            client.as_extensions().insert(ech_config(target));
        }
        let final_config = QuicClientConfig::from_rama(&client, TlsOptions::default()).unwrap();
        assert_eq!(final_config.ech.is_some(), !ready);
        let params = |id| TransportParameters {
            initial_src_cid: Some(ConnectionId::new(&[id])),
            ..TransportParameters::default()
        };
        let mut client = Arc::new(final_config)
            .start_session(Version::V1, "localhost", &params(1))
            .unwrap();
        let mut server = Arc::new(ech_server(&server))
            .start_session(Version::V1, &params(2))
            .unwrap();
        handshake(&mut *client, &mut *server).unwrap();
        assert_eq!(client.ech_accepted(), Some(!ready));
    }
}

#[test]
fn real_ech_resumes_only_in_the_ech_partition_and_disables_early_data() {
    let (client, server) = configs();
    client
        .as_extensions()
        .extend(&SharedClientSessions::defaults());
    let plain = Arc::new(QuicClientConfig::from_rama(&client, TlsOptions::default()).unwrap());
    // Opportunistic ECH uses endpoint knowledge without an explicit intent.

    client
        .as_extensions()
        .insert(rama_net::client::ConnectorTarget(
            "localhost:443".parse().unwrap(),
        ));
    client
        .as_extensions()
        .insert(ech_config("localhost:443".parse().unwrap()));
    let client = Arc::new(
        QuicClientConfig::from_rama(&client, TlsOptions::default().with_early_data(true)).unwrap(),
    );
    assert!(!client.early_data);
    let server = Arc::new(ech_server(&server));
    for version in [Version::V1, Version::V2] {
        for resumed in [false, true] {
            let params = |id| TransportParameters {
                initial_src_cid: Some(ConnectionId::new(&[id])),
                ..TransportParameters::default()
            };
            let mut c = client
                .clone()
                .start_session(version, "localhost", &params(1))
                .unwrap();
            let mut s = server.clone().start_session(version, &params(2)).unwrap();
            assert!(c.early_crypto().is_none());

            // Resumption must not expose the origin or real PSK identities in
            // ClientHelloOuter (the disclosure mechanism of GO-2026-5856).
            let mut outer = Vec::new();
            while let Some(event) = c.poll_handshake().unwrap() {
                let HandshakeEvent::Data(level, bytes) = event else {
                    panic!("unexpected client first-flight event");
                };
                outer.extend_from_slice(&bytes);
                s.read_handshake(level, &bytes).unwrap();
            }
            let ClientHelloHandshakePrefix::Complete(outer) =
                parse_client_hello_message_prefix(&outer)
            else {
                panic!("generated outer ClientHello is not complete");
            };
            assert_eq!(outer.ext_server_domain().unwrap().as_str(), "ech.com");
            // This backend omits outer PSK entirely; a future GREASE PSK
            // implementation must instead prove its identities are synthetic.
            assert!(
                !outer
                    .extensions()
                    .iter()
                    .any(|extension| extension.id() == ExtensionId::PRE_SHARED_KEY)
            );

            handshake(&mut *c, &mut *s).unwrap();
            assert_eq!(c.ech_accepted(), Some(true));
            assert_eq!(c.handshake_summary().unwrap().resumed, Some(resumed));
        }
        let params = |id| TransportParameters {
            initial_src_cid: Some(ConnectionId::new(&[id])),
            ..TransportParameters::default()
        };
        let mut c = plain
            .clone()
            .start_session(version, "localhost", &params(1))
            .unwrap();
        let mut s = server.clone().start_session(version, &params(2)).unwrap();
        handshake(&mut *c, &mut *s).unwrap();
        assert_eq!(c.ech_accepted(), Some(false));
        assert_eq!(c.handshake_summary().unwrap().resumed, Some(false));
    }
}

#[tokio::test]
async fn quic_connector_publishes_acceptance_before_required_reuse() {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let (tls, server_tls) = configs();
        let server = Endpoint::bind_server(
            WeakScope::detached(),
            ServerConfig::with_crypto(Arc::new(ech_server(&server_tls))),
            SocketAddress::local_ipv4(0),
        )
        .await
        .unwrap();
        let address = server.local_addr().unwrap();
        let incoming = server.clone();
        let task = tokio::spawn(async move {
            incoming
                .accept()
                .await
                .unwrap()
                .accept()
                .unwrap()
                .await
                .unwrap()
        });
        let endpoint = Endpoint::bind_client(WeakScope::detached(), SocketAddress::local_ipv4(0))
            .await
            .unwrap();
        let connector = QuicConnector::new(
            SharedQuicEndpoint::supplied(endpoint.clone(), WeakScope::detached()),
            tls,
            Arc::new(BoringTlsProvider::new()),
        );
        let request = ConnectRequest::new(HostWithPort::localhost_domain_with_port(address.port()));
        request.extensions().insert(ConnectorTarget(address.into()));
        request.extensions().insert(ech_config(address.into()));
        request.extensions().insert(EchRequirement::Required);
        let connection = connector.serve(request).await.unwrap().conn;
        assert_eq!(
            connection.extensions().get_ref::<TlsEchAccepted>(),
            Some(&TlsEchAccepted(true))
        );
        let next = Extensions::new();
        next.insert(EchRequirement::Required);
        let reuse = connection
            .extensions()
            .get_ref::<ConnectionReuse>()
            .unwrap();
        assert_eq!(reuse.request_key(&next).as_ref(), reuse.key());
        connection.close(0u32, b"done");
        task.await.unwrap().close(0u32, b"done");
        endpoint.shutdown().await;
        server.shutdown().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn quic_connector_retries_authenticated_ech_rejection_once() {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let (tls, server_tls) = super::super::tests::configs_for([
            Domain::from_static("localhost"),
            Domain::from_static("ech.com"),
        ]);
        let server = Endpoint::bind_server(
            WeakScope::detached(),
            ServerConfig::with_crypto(Arc::new(ech_server(&server_tls))),
            SocketAddress::local_ipv4(0),
        )
        .await
        .unwrap();
        let address = server.local_addr().unwrap();
        let incoming = server.clone();
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let seen = calls.clone();
        let task = tokio::spawn(async move {
            let mut connections = Vec::new();
            for _ in 0..2 {
                let connection = incoming.accept().await.unwrap();
                seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                if let Ok(connection) = connection.accept().unwrap().await {
                    connections.push(connection);
                }
            }
            connections
        });
        let endpoint = Endpoint::bind_client(WeakScope::detached(), SocketAddress::local_ipv4(0))
            .await
            .unwrap();
        let connector = QuicConnector::new(
            SharedQuicEndpoint::supplied(endpoint.clone(), WeakScope::detached()),
            tls,
            Arc::new(BoringTlsProvider::new()),
        );
        let request = ConnectRequest::new(HostWithPort::localhost_domain_with_port(address.port()));
        request.extensions().insert(ConnectorTarget(address.into()));
        let mut stale = ech_config(address.into()).config_list().to_vec();
        stale[6] = 0; // Server advertises only config id 1.
        request
            .extensions()
            .insert(TargetEchConfig::new(address.into(), stale));
        request.extensions().insert(EchRequirement::Required);
        let connection = connector.serve(request).await.unwrap().conn;
        assert_eq!(
            connection.extensions().get_ref::<TlsEchAccepted>(),
            Some(&TlsEchAccepted(true))
        );
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 2);
        connection.close(0u32, b"done");
        for peer in task.await.unwrap() {
            peer.close(0u32, b"done");
        }
        endpoint.shutdown().await;
        server.shutdown().await;
    })
    .await
    .unwrap();
}

#[test]
fn endpoint_ech_requires_independent_physical_target_and_origin_identity() {
    let (mut client, _) = configs();
    client.set_encrypted_client_hello(true);
    client
        .as_extensions()
        .insert(ech_config("alt.example:9443".parse().unwrap()));
    let native = QuicClientConfig::from_rama(&client, TlsOptions::default()).unwrap();
    assert!(native.ech.is_none());
    client.as_extensions().insert(EchRequirement::Required);
    QuicClientConfig::from_rama(&client, TlsOptions::default())
        .map(|_| ())
        .unwrap_err();
    client
        .as_extensions()
        .insert(ConnectorTarget("other.example:9443".parse().unwrap()));
    QuicClientConfig::from_rama(&client, TlsOptions::default())
        .map(|_| ())
        .unwrap_err();
    client
        .as_extensions()
        .insert(ConnectorTarget("alt.example:9443".parse().unwrap()));
    let native = QuicClientConfig::from_rama(&client, TlsOptions::default()).unwrap();
    let (identity, _) = native
        .configure_ssl(Some(ServerName::from(Domain::from_static("localhost"))))
        .unwrap();
    assert_eq!(identity, ServerName::from(Domain::from_static("localhost")));
    let cache = crate::tls::ClientConfigCache::new(
        Arc::new(crate::tls::BoringTlsProvider::new()),
        TlsOptions::default(),
    );
    cache
        .client_config(&client, client.as_extensions())
        .unwrap_err();
    client.set_server_name(Domain::from_static("localhost"));
    cache
        .client_config(&client, client.as_extensions())
        .unwrap();
}

#[test]
fn authenticated_rejection_retains_the_tls_ech_required_alert() {
    let (client, server) = super::super::tests::configs_for([
        Domain::from_static("localhost"),
        Domain::from_static("ech.com"),
    ]);
    let target: HostWithPort = "localhost:443".parse().unwrap();
    let mut stale = ech_config(target.clone()).config_list().to_vec();
    stale[6] = 0;
    client
        .as_extensions()
        .insert(ConnectorTarget(target.clone()));
    client
        .as_extensions()
        .insert(TargetEchConfig::new(target, stale));
    client.as_extensions().insert(EchRequirement::Required);
    let client = Arc::new(QuicClientConfig::from_rama(&client, TlsOptions::default()).unwrap());
    let server = Arc::new(ech_server(&server));
    let params = |id| TransportParameters {
        initial_src_cid: Some(ConnectionId::new(&[id])),
        ..TransportParameters::default()
    };
    let mut c = client
        .start_session(Version::V1, "localhost", &params(1))
        .unwrap();
    let mut s = server.start_session(Version::V1, &params(2)).unwrap();
    let error = handshake(&mut *c, &mut *s).unwrap_err();
    assert_eq!(error.code, rama_quic_proto::TransportErrorCode::crypto(121));
    assert!(
        error
            .find_cause::<rama_tls::client::EchRetryConfig>()
            .is_some()
    );
}

#[test]
fn service_binding_reliance_uses_final_quic_intent() {
    let (mut client, _) = configs();
    let target: HostWithPort = "localhost:443".parse().unwrap();
    client
        .as_extensions()
        .insert(ConnectorTarget(target.clone()));
    client.as_extensions().insert(TargetEchServiceBinding {
        target: target.clone(),
        reliant: true,
        mandatory: false,
    });
    client.set_encrypted_client_hello(false);
    let native = QuicClientConfig::from_rama(&client, TlsOptions::default()).unwrap();
    assert!(native.ech.is_none());
    client.set_encrypted_client_hello(true);
    QuicClientConfig::from_rama(&client, TlsOptions::default())
        .map(|_| ())
        .unwrap_err();
    client.as_extensions().insert(ech_config(target));
    let native = QuicClientConfig::from_rama(&client, TlsOptions::default()).unwrap();
    assert_eq!(native.ech.unwrap().requirement, EchRequirement::Required);
    assert!(!client.as_extensions().contains::<EchRequirement>());
}

#[test]
fn prepared_server_keys_rotate_without_replacing_quic_contexts() {
    let keys = |config: &[u8]| {
        EchServerKeys::new([EchServerKey::new(config, SERVER_ECH_KEY, true)]).unwrap()
    };
    let a = keys(SERVER_ECH_CONFIG);
    let mut b_config = SERVER_ECH_CONFIG.to_vec();
    b_config[4] = 2;
    let b = keys(&b_config);
    let both = EchServerKeys::new([
        EchServerKey::new(SERVER_ECH_CONFIG, SERVER_ECH_KEY, false),
        EchServerKey::new(&b_config, SERVER_ECH_KEY, true),
    ])
    .unwrap();
    let provider = ReloadableEchServerKeys::new(a.clone());
    let (client, server) = configs();
    let server = server.with_ech_keys(provider.clone());
    let server = Arc::new(QuicServerConfig::from_rama(&server, TlsOptions::default()).unwrap());
    let original = server.contexts.clone();
    for (generation, offered) in [
        (a.clone(), a.clone()),
        (both.clone(), a),
        (both, b.clone()),
        (b.clone(), b),
    ] {
        provider.replace(generation).unwrap();
        for version in [Version::V1, Version::V2] {
            let client = client.clone();
            client
                .as_extensions()
                .insert(ConnectorTarget("localhost:443".parse().unwrap()));
            client.as_extensions().insert(TargetEchConfig::new(
                "localhost:443".parse().unwrap(),
                offered.retry_configs().to_vec(),
            ));
            let client =
                Arc::new(QuicClientConfig::from_rama(&client, TlsOptions::default()).unwrap());
            let params = |id| TransportParameters {
                initial_src_cid: Some(ConnectionId::new(&[id])),
                ..TransportParameters::default()
            };
            let mut c = client
                .start_session(version, "localhost", &params(1))
                .unwrap();
            let mut s = server.clone().start_session(version, &params(2)).unwrap();
            handshake(&mut *c, &mut *s).unwrap();
            assert_eq!(s.ech_accepted(), Some(true));
            let inner = s.effective_client_hello().unwrap();
            assert_eq!(inner.ext_server_domain().unwrap().as_str(), "localhost");
            assert!(inner.extensions().iter().any(|extension| matches!(
                extension,
                rama_tls::client::ClientHelloExtension::EncryptedClientHello(
                    rama_tls::client::ECHClientHello::Inner
                )
            )));
        }
        for (before, after) in original.iter().zip(&server.contexts) {
            assert!(Arc::ptr_eq(before, after));
        }
    }
}

#[tokio::test]
async fn ech_pending_issuer_receives_inner_and_rejection_public_names() {
    struct Issuer {
        auth: ServerAuthData,
        names: Arc<parking_lot::Mutex<Vec<String>>>,
    }

    impl DynamicCertIssuer for Issuer {
        async fn issue_cert(
            &self,
            context: CertificateIssuanceContext,
        ) -> Result<ServerAuthData, BoxError> {
            self.names.lock().push(
                context
                    .client_hello
                    .ext_server_domain()
                    .unwrap()
                    .as_str()
                    .to_owned(),
            );
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            Ok(self.auth.clone())
        }
    }

    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let (tls, fixed) = super::super::tests::configs_for([
            Domain::from_static("localhost"),
            Domain::from_static("ech.com"),
        ]);
        let names = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let auth = fixed
            .as_extensions()
            .get_ref::<TlsServerAuth>()
            .unwrap()
            .0
            .clone();
        let keys = EchServerKeys::new([EchServerKey::new(SERVER_ECH_CONFIG, SERVER_ECH_KEY, true)])
            .unwrap();
        let dynamic = TlsServerConfig::new()
            .with_alpn(
                [rama_net::tls::ApplicationProtocol::from(
                    b"rama-boring-test".as_slice(),
                )]
                .into_iter()
                .collect(),
            )
            .with_cert_issuer(
                ServerCertIssuerData::new(Issuer {
                    auth,
                    names: names.clone(),
                })
                .with_cache_kind(CacheKind::Disabled),
            )
            .with_ech_keys(keys);
        let crypto = QuicServerConfig::from_rama(&dynamic, TlsOptions::default()).unwrap();
        let server = Endpoint::bind_server(
            WeakScope::detached(),
            ServerConfig::with_crypto(Arc::new(crypto)),
            SocketAddress::local_ipv4(0),
        )
        .await
        .unwrap();
        let address = server.local_addr().unwrap();
        let incoming = server.clone();
        let task = tokio::spawn(async move {
            let mut peers = Vec::new();
            for _ in 0..3 {
                let attempt = incoming.accept().await.unwrap().accept().unwrap();
                if let Ok(peer) = attempt.await {
                    peers.push(peer);
                }
            }
            peers
        });
        let endpoint = Endpoint::bind_client(WeakScope::detached(), SocketAddress::local_ipv4(0))
            .await
            .unwrap();
        let connector = QuicConnector::new(
            SharedQuicEndpoint::supplied(endpoint.clone(), WeakScope::detached()),
            tls,
            Arc::new(BoringTlsProvider::new()),
        );
        for stale in [false, true] {
            let request =
                ConnectRequest::new(HostWithPort::localhost_domain_with_port(address.port()));
            request.extensions().insert(ConnectorTarget(address.into()));
            let mut config = ech_config(address.into()).config_list().to_vec();
            if stale {
                config[6] = 0;
            }
            request
                .extensions()
                .insert(TargetEchConfig::new(address.into(), config));
            request.extensions().insert(EchRequirement::Required);
            let connection = connector.serve(request).await.unwrap().conn;
            assert_eq!(
                connection.extensions().get_ref::<TlsEchAccepted>(),
                Some(&TlsEchAccepted(true))
            );
            connection.close(0u32, b"done");
        }
        for peer in task.await.unwrap() {
            peer.close(0u32, b"done");
        }
        assert_eq!(*names.lock(), ["localhost", "ech.com", "localhost"]);
        endpoint.shutdown().await;
        server.shutdown().await;
    })
    .await
    .unwrap();
}
