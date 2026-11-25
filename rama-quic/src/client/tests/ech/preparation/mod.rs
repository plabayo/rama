use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use rama_core::{
    Service as _,
    extensions::{Extensions, ExtensionsRef as _},
    futures::future::BoxFuture,
    graceful::WeakScope,
    service::service_fn,
};
use rama_crypto::pki_types::CertificateDer;
use rama_net::{
    Protocol,
    address::HostWithPort,
    client::{
        ConnectRequest, ConnectionError, ConnectorTarget, EstablishedClientConnection,
        EstablishedProxyRoute, ProxyRoute, pool::ReuseKey,
    },
    tls::{ApplicationProtocol, ServerName, TargetEchConfig},
    transport::TransportProtocol,
};
use rama_quic_proto::capture::CaptureLimits;
use rama_tls::{
    client::{
        TlsClientConfig, TlsClientConfigProvider, TlsEchAccepted, TlsPoolId, TlsProfilePreparation,
    },
    server::{ServerClientHellos, TlsServerConfig},
};
use rama_tls_boring::server::{BoringServerConfigExt as _, EchServerKey, EchServerKeys};
use rama_udp::test_utils::MemoryDatagramSocket;
use rama_utils::macros::nonzero;
use tokio::time::{Duration, timeout};

use crate::{
    ClientConfig, Endpoint, ServerConfig,
    client::{ClientEndpoint, QuicConnector},
    test_helpers::{
        ech_keys::{SERVER_ECH_CONFIG, SERVER_ECH_KEY},
        identity,
    },
    tls::{
        BoringTlsProvider, ClientConfigRequest, QuicClientConfigProvider, TlsConfigError,
        TlsOptions,
    },
};

#[derive(Debug)]
struct CountingProvider(AtomicUsize);

impl TlsClientConfigProvider for CountingProvider {
    fn pool_id(&self, extensions: &Extensions) -> Option<TlsPoolId> {
        BoringTlsProvider::new().pool_id(extensions)
    }

    fn pool_classifier(&self) -> ReuseKey {
        BoringTlsProvider::new().pool_classifier()
    }

    fn authenticates_server(&self, extensions: &Extensions) -> bool {
        BoringTlsProvider::new().authenticates_server(extensions)
    }
}

impl QuicClientConfigProvider for CountingProvider {
    fn supports_ech(&self) -> bool {
        true
    }

    fn client_config(
        &self,
        config: &TlsClientConfig,
        options: TlsOptions,
    ) -> Result<ClientConfig, TlsConfigError> {
        BoringTlsProvider::new().client_config(config, options)
    }

    fn acquire_client_config(
        &self,
        request: ClientConfigRequest<'_>,
    ) -> Result<Option<ClientConfig>, TlsConfigError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        BoringTlsProvider::new().acquire_client_config(request)
    }

    fn acquire_client_config_async<'a>(
        &'a self,
        request: ClientConfigRequest<'a>,
    ) -> BoxFuture<'a, Result<Option<ClientConfig>, TlsConfigError>> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            BoringTlsProvider::new()
                .acquire_client_config_async(request)
                .await
        })
    }

    fn allows_early_data(&self, extensions: &Extensions) -> bool {
        BoringTlsProvider::new().allows_early_data(extensions)
    }

    fn peer_matches_name(
        &self,
        extensions: &Extensions,
        leaf: &CertificateDer<'_>,
        name: &ServerName,
    ) -> bool {
        BoringTlsProvider::new().peer_matches_name(extensions, leaf, name)
    }
}

#[tokio::test]
async fn provider_is_prepared_early_and_rebuilt_only_for_changed_ech() {
    timeout(Duration::from_secs(15), async {
        for proxy in [false, true] {
            for (initial, discovered) in
                [(false, false), (true, true), (false, true), (true, false)]
            {
                let identity = identity();
                let keys = EchServerKeys::new([EchServerKey::new(
                    SERVER_ECH_CONFIG,
                    SERVER_ECH_KEY,
                    true,
                )])
                .unwrap();
                let alpn = || {
                    [ApplicationProtocol::from(b"ech-test")]
                        .into_iter()
                        .collect()
                };
                let tls = TlsClientConfig::new()
                    .with_alpn(alpn())
                    .try_with_server_trust_anchors([identity.cert_chain.last().unwrap().clone()])
                    .unwrap();
                let mut config = ServerConfig::try_from_rama_tls_with_provider(
                    &TlsServerConfig::new()
                        .with_server_auth(identity)
                        .with_alpn(alpn())
                        .with_ech_keys(keys.clone()),
                    TlsOptions::default(),
                    &BoringTlsProvider::new(),
                )
                .unwrap();
                config.set_capture(CaptureLimits::default());
                let client_address: SocketAddr = ([127, 0, 0, 1], 25220).into();
                let server_address: SocketAddr = ([127, 0, 0, 1], 25221).into();
                let (local, remote) =
                    MemoryDatagramSocket::pair(client_address, server_address, nonzero!(64));
                let server = Endpoint::build(WeakScope::detached())
                    .with_server_config(config)
                    .with_datagram_socket(remote)
                    .unwrap();
                let endpoint = Endpoint::build(WeakScope::detached())
                    .with_datagram_socket(local)
                    .unwrap();
                let provider = Arc::new(CountingProvider(AtomicUsize::new(0)));
                let input = ConnectRequest::new(HostWithPort::localhost_domain_with_port(443))
                    .with_application_protocol(Protocol::HTTPS)
                    .with_transport_protocol(TransportProtocol::Udp);
                let target = HostWithPort::local_ipv4(443);
                input.extensions().insert(ConnectorTarget(target.clone()));
                if initial {
                    input.extensions().insert(TargetEchConfig::new(
                        target.clone(),
                        keys.retry_configs().to_vec(),
                    ));
                }
                if proxy {
                    input.extensions().insert(ProxyRoute::Proxy(
                        "http://proxy.example:3128".parse().unwrap(),
                    ));
                }
                let profiles = Arc::new(AtomicUsize::new(0));
                input.extensions().insert(TlsProfilePreparation::new({
                    let profiles = profiles.clone();
                    move |_, _, _| {
                        profiles.fetch_add(1, Ordering::SeqCst);
                        Ok(Extensions::new())
                    }
                }));
                let transport = service_fn({
                    let provider = provider.clone();
                    let endpoint = endpoint.clone();
                    move |input: ConnectRequest| {
                        assert_eq!(provider.0.load(Ordering::SeqCst), 1);
                        if discovered {
                            input.extensions().insert(TargetEchConfig::new(
                                target.clone(),
                                keys.retry_configs().to_vec(),
                            ));
                        } else {
                            input.extensions().insert(TargetEchConfig::new(
                                "other.example:443".parse().unwrap(),
                                keys.retry_configs().to_vec(),
                            ));
                        }
                        let conn = ClientEndpoint::new(endpoint.clone())
                            .with_peer(([127, 0, 0, 1], 25221).into());
                        if proxy {
                            conn.extensions().insert(EstablishedProxyRoute::Forward(
                                input
                                    .extensions()
                                    .get_ref::<ProxyRoute>()
                                    .unwrap()
                                    .proxy_address()
                                    .unwrap()
                                    .clone(),
                            ));
                        }
                        async move {
                            Ok::<_, ConnectionError>(EstablishedClientConnection { input, conn })
                        }
                    }
                });
                let connector = QuicConnector::new(transport, tls, provider.clone());
                let accept = async { server.accept().await.unwrap().await.unwrap() };
                let (connected, accepted) = tokio::join!(connector.serve(input), accept);
                let connected = connected.unwrap();
                assert_eq!(connected.input.application_protocol, Some(Protocol::HTTPS));
                assert_eq!(
                    connected.input.transport_protocol,
                    Some(TransportProtocol::Udp)
                );
                let calls = 1 + usize::from(initial != discovered);
                assert_eq!(provider.0.load(Ordering::SeqCst), calls);
                assert_eq!(profiles.load(Ordering::SeqCst), calls);
                assert_eq!(
                    connected.conn.extensions().get_ref::<TlsEchAccepted>(),
                    Some(&TlsEchAccepted(discovered))
                );
                let hellos = ServerClientHellos::from_extensions(accepted.extensions());
                assert_eq!(hellos.ech_accepted(), Some(discovered));
                assert_eq!(hellos.ech_inner().is_some(), discovered);
                connected.conn.close(0u32, b"done");
                accepted.close(0u32, b"done");
                endpoint.shutdown().await;
                server.shutdown().await;
            }
        }
    })
    .await
    .unwrap();
}
