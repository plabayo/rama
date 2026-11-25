mod preparation;

use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use parking_lot::Mutex;
use rama_core::{
    Service,
    extensions::{Extensions, ExtensionsRef as _},
    graceful::WeakScope,
    service::service_fn,
};
use rama_net::{
    address::HostWithPort,
    client::{
        ConnectRequest, ConnectionError, ConnectionErrorDomain, ConnectionErrorKind,
        ConnectorTarget, EstablishedClientConnection, EstablishedProxyRoute, ProxyRoute,
    },
    tls::{ApplicationProtocol, TargetEchConfig, TargetEchServiceBinding},
};
use rama_quic_proto::{
    capture::{CaptureLimits, QuicObservation},
    profile::QuicProfile,
    transport_parameters::TransportParameterId,
};
use rama_tls::{
    client::{
        EchDiscoveryComplete, EchRequirement, TlsClientConfig, TlsClientSni, TlsEchAccepted,
        TlsEncryptedClientHello, TlsProfilePreparation,
    },
    server::{ServerClientHellos, TlsServerConfig},
};
use rama_tls_boring::server::{BoringServerConfigExt as _, EchServerKey, EchServerKeys};
use rama_udp::test_utils::MemoryDatagramSocket;
use rama_utils::macros::nonzero;
use tokio::time::timeout;

use crate::{
    Endpoint, ServerConfig,
    client::{ClientEndpoint, QuicConnector, QuicEndpointConnector},
    test_helpers::{
        ech_keys::{SERVER_ECH_CONFIG, SERVER_ECH_KEY},
        identity,
    },
    tls::{BoringTlsProvider, TlsOptions},
};

#[tokio::test]
async fn required_ech_waits_for_endpoint_discovery_and_resolves_once_before_handshake() {
    timeout(Duration::from_secs(10), async {
        for proxy in [false, true] {
            for profile_owned in [false, true] {
                for (discovered, complete, initial) in [
                    (false, false, false),
                    (true, false, false),
                    (true, true, false),
                    (false, true, true),
                ] {
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
                    let server_tls = TlsServerConfig::new()
                        .with_server_auth(identity.clone())
                        .with_alpn(alpn())
                        .with_ech_keys(keys.clone());
                    let config = ServerConfig::try_from_rama_tls_with_provider(
                        &server_tls,
                        TlsOptions::default(),
                        &BoringTlsProvider::new(),
                    )
                    .unwrap();
                    let client_address: SocketAddr = ([127, 0, 0, 1], 25200).into();
                    let server_address: SocketAddr = ([127, 0, 0, 1], 25201).into();
                    let (local, remote) =
                        MemoryDatagramSocket::pair(client_address, server_address, nonzero!(64));
                    let server = Endpoint::build(WeakScope::detached())
                        .with_server_config(config)
                        .with_datagram_socket(remote)
                        .unwrap();
                    let endpoint = Endpoint::build(WeakScope::detached())
                        .with_datagram_socket(local)
                        .unwrap();
                    let tls = TlsClientConfig::new()
                        .with_alpn(alpn())
                        .try_with_server_trust_anchors([identity
                            .cert_chain
                            .last()
                            .unwrap()
                            .clone()])
                        .unwrap();
                    let input = ConnectRequest::new(HostWithPort::localhost_domain_with_port(443));
                    let target = HostWithPort::local_ipv4(443);
                    input.extensions().insert(ConnectorTarget(target.clone()));
                    input.extensions().insert(EchRequirement::Required);
                    let installed = Extensions::new();
                    if profile_owned {
                        installed.insert(TlsEncryptedClientHello(false));
                        input.extensions().extend(&installed);
                    }
                    if complete {
                        input.extensions().insert(EchDiscoveryComplete);
                    }
                    if initial {
                        input.extensions().insert(TargetEchConfig::new(
                            target.clone(),
                            keys.retry_configs().to_vec(),
                        ));
                    }
                    let route = "http://proxy.example:3128".parse().unwrap();
                    if proxy {
                        input.extensions().insert(ProxyRoute::Proxy(route));
                    }
                    let calls = Arc::new(AtomicUsize::new(0));
                    let preparations = Arc::new(AtomicUsize::new(0));
                    input.extensions().insert(TlsProfilePreparation::new({
                        let preparations = preparations.clone();
                        move |resolution, effective, _| {
                            preparations.fetch_add(1, Ordering::SeqCst);
                            assert!(resolution.required);
                            assert!(resolution.config.is_some());
                            effective.insert(TargetEchConfig::new(
                                "other.example:443".parse().unwrap(),
                                b"unusable".as_slice(),
                            ));
                            Ok(Extensions::new())
                        }
                    }));
                    let transport = service_fn({
                        let endpoint = endpoint.clone();
                        let calls = calls.clone();
                        move |input: ConnectRequest| {
                            calls.fetch_add(1, Ordering::SeqCst);
                            let conn =
                                ClientEndpoint::new(endpoint.clone()).with_peer(server_address);
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
                            if discovered {
                                input.extensions().insert(TargetEchConfig::new(
                                    target.clone(),
                                    keys.retry_configs().to_vec(),
                                ));
                            }
                            input
                                .extensions()
                                .insert(ConnectorTarget("transport.example:8443".parse().unwrap()));
                            async move {
                                Ok::<_, ConnectionError>(EstablishedClientConnection {
                                    input,
                                    conn,
                                })
                            }
                        }
                    });
                    let connector =
                        QuicConnector::new(transport, tls, Arc::new(BoringTlsProvider::new()));
                    let success = initial || (!complete && discovered);
                    let accept = async {
                        if success {
                            let connection = server.accept().await.unwrap().await.unwrap();
                            let hellos =
                                ServerClientHellos::from_extensions(connection.extensions());
                            assert_eq!(hellos.ech_accepted(), Some(true));
                            assert!(hellos.ech_inner().is_some());
                            Some(connection)
                        } else {
                            None
                        }
                    };
                    let (result, accepted) = tokio::join!(connector.serve(input), accept);
                    assert_eq!(
                        calls.load(Ordering::SeqCst),
                        usize::from(!complete || initial)
                    );
                    if success {
                        let connected = result.unwrap();
                        assert_eq!(
                            connected.conn.extensions().get_ref::<TlsEchAccepted>(),
                            Some(&TlsEchAccepted(true))
                        );
                        assert_eq!(preparations.load(Ordering::SeqCst), 1);
                        connected.conn.close(0u32, b"done");
                        accepted.unwrap().close(0u32, b"done");
                    } else {
                        let error = result.unwrap_err();
                        assert_eq!(error.kind(), ConnectionErrorKind::InvalidInput);
                        assert_eq!(error.domain(), ConnectionErrorDomain::Local);
                        assert_eq!(preparations.load(Ordering::SeqCst), 0);
                        assert_eq!(endpoint.stats().outgoing_handshakes, 0);
                    }
                    endpoint.shutdown().await;
                    server.shutdown().await;
                }
            }
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn final_ech_profile_configures_the_endpoint_before_the_first_packet() {
    timeout(Duration::from_secs(10), async {
        let identity = identity();
        let keys = EchServerKeys::new([EchServerKey::new(SERVER_ECH_CONFIG, SERVER_ECH_KEY, true)])
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
        let client_address: SocketAddr = ([127, 0, 0, 1], 25210).into();
        let server_address: SocketAddr = ([127, 0, 0, 1], 25211).into();
        let (local, remote) =
            MemoryDatagramSocket::pair(client_address, server_address, nonzero!(64));
        let server = Endpoint::build(WeakScope::detached())
            .with_server_config(config)
            .with_datagram_socket(remote)
            .unwrap();
        let local = Arc::new(Mutex::new(Some(local)));
        let transport = service_fn(move |input: ConnectRequest| {
            let socket = local.lock().take().unwrap();
            input.extensions().insert(TargetEchConfig::new(
                server_address.into(),
                keys.retry_configs().to_vec(),
            ));
            async move {
                Ok::<_, ConnectionError>(EstablishedClientConnection {
                    input,
                    conn: socket,
                })
            }
        });
        let connector = QuicConnector::new(
            QuicEndpointConnector::new(transport, WeakScope::detached()),
            tls,
            Arc::new(BoringTlsProvider::new()),
        );
        let input = ConnectRequest::new(HostWithPort::localhost_domain_with_port(
            server_address.port(),
        ));
        input
            .extensions()
            .insert(ConnectorTarget(server_address.into()));
        input.extensions().insert(EchRequirement::Required);
        let profile = QuicProfile::standard();
        let final_profile = profile
            .clone()
            .with_connection_ids((*profile.connection_ids()).try_with_local_len(3).unwrap());
        input.extensions().insert(profile);
        input
            .extensions()
            .insert(TlsProfilePreparation::new(move |resolution, _, request| {
                assert!(resolution.config.is_some());
                request.insert(final_profile.clone());
                Ok(Extensions::new())
            }));
        let accept = async {
            match server.accept().await {
                Some(incoming) => Some(incoming.await),
                None => None,
            }
        };
        let (connected, accepted) = tokio::join!(connector.serve(input), accept);
        let connected = connected.unwrap();
        let accepted = accepted.unwrap().unwrap();
        let observation = accepted.extensions().get_ref::<QuicObservation>().unwrap();
        let cid = observation
            .transport_parameters
            .iter()
            .find(|parameter| parameter.id == TransportParameterId::InitialSourceConnectionId)
            .unwrap();
        assert_eq!(cid.value.len(), 3);
        connected.conn.close(0u32, b"done");
        accepted.close(0u32, b"done");
        server.shutdown().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn ech_ready_after_the_socket_endpoint_gets_an_endpoint_for_the_final_profile() {
    timeout(Duration::from_secs(10), async {
        let identity = identity();
        let keys = EchServerKeys::new([EchServerKey::new(SERVER_ECH_CONFIG, SERVER_ECH_KEY, true)])
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
        let client_address: SocketAddr = ([127, 0, 0, 1], 25212).into();
        let server_address: SocketAddr = ([127, 0, 0, 1], 25213).into();
        let (local, remote) =
            MemoryDatagramSocket::pair(client_address, server_address, nonzero!(64));
        let server = Endpoint::build(WeakScope::detached())
            .with_server_config(config)
            .with_datagram_socket(remote)
            .unwrap();
        let local = Arc::new(Mutex::new(Some(local)));
        let transport = service_fn(move |input: ConnectRequest| {
            let socket = local.lock().take().unwrap();
            async move {
                Ok::<_, ConnectionError>(EstablishedClientConnection {
                    input,
                    conn: socket,
                })
            }
        });
        let endpoints = Arc::new(QuicEndpointConnector::new(transport, WeakScope::detached()));
        // ECH becomes ready only after the endpoint connector returned its endpoint.
        let endpoints = service_fn(move |input: ConnectRequest| {
            let endpoints = endpoints.clone();
            let retry_configs = keys.retry_configs().to_vec();
            async move {
                let established = endpoints.serve(input).await?;
                established
                    .input
                    .extensions()
                    .insert(TargetEchConfig::new(server_address.into(), retry_configs));
                Ok::<_, ConnectionError>(established)
            }
        });
        let connector = QuicConnector::new(endpoints, tls, Arc::new(BoringTlsProvider::new()));
        let input = ConnectRequest::new(HostWithPort::localhost_domain_with_port(
            server_address.port(),
        ));
        input
            .extensions()
            .insert(ConnectorTarget(server_address.into()));
        let profile = QuicProfile::standard();
        let ech_profile = profile
            .clone()
            .with_connection_ids((*profile.connection_ids()).try_with_local_len(3).unwrap());
        assert_ne!(profile.connection_ids().local_len(), 3);
        input.extensions().insert(profile);
        input
            .extensions()
            .insert(TlsProfilePreparation::new(move |resolution, _, request| {
                if resolution.config.is_some() {
                    request.insert(ech_profile.clone());
                }
                Ok(Extensions::new())
            }));
        let accept = async {
            match server.accept().await {
                Some(incoming) => Some(incoming.await),
                None => None,
            }
        };
        let (connected, accepted) = tokio::join!(connector.serve(input), accept);
        let connected = connected.unwrap();
        let accepted = accepted.unwrap().unwrap();
        assert_eq!(
            connected.conn.extensions().get_ref::<TlsEchAccepted>(),
            Some(&TlsEchAccepted(true))
        );
        let observation = accepted.extensions().get_ref::<QuicObservation>().unwrap();
        let cid = observation
            .transport_parameters
            .iter()
            .find(|parameter| parameter.id == TransportParameterId::InitialSourceConnectionId)
            .unwrap();
        assert_eq!(cid.value.len(), 3);
        connected.conn.close(0u32, b"done");
        accepted.close(0u32, b"done");
        server.shutdown().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn mandatory_discovery_never_reuses_a_clear_profile_native_config() {
    timeout(Duration::from_secs(15), async {
        let identity = identity();
        let keys = EchServerKeys::new([EchServerKey::new(SERVER_ECH_CONFIG, SERVER_ECH_KEY, true)])
            .unwrap();
        let alpn = || [ApplicationProtocol::HTTP_3].into_iter().collect();
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
        let server_address: SocketAddr = ([127, 0, 0, 1], 25301).into();
        let client_address: SocketAddr = ([127, 0, 0, 1], 25300).into();
        let (local, remote) =
            MemoryDatagramSocket::pair(client_address, server_address, nonzero!(64));
        let server = Endpoint::build(WeakScope::detached())
            .with_server_config(config)
            .with_datagram_socket(remote)
            .unwrap();
        let endpoint = Endpoint::build(WeakScope::detached())
            .with_datagram_socket(local)
            .unwrap();
        let attempts = Arc::new(AtomicUsize::new(0));
        let transport = service_fn({
            let endpoint = endpoint.clone();
            move |input: ConnectRequest| {
                match attempts.fetch_add(1, Ordering::SeqCst) {
                    1 => {
                        input.extensions().insert(TlsClientSni::Disabled);
                    }
                    2 => {
                        input.extensions().insert(TargetEchConfig::new(
                            server_address.into(),
                            keys.retry_configs().to_vec(),
                        ));
                        input.extensions().insert(TargetEchServiceBinding {
                            target: server_address.into(),
                            reliant: true,
                            mandatory: true,
                        });
                    }
                    _ => {}
                }
                let conn = ClientEndpoint::new(endpoint.clone()).with_peer(server_address);
                async move { Ok::<_, ConnectionError>(EstablishedClientConnection { input, conn }) }
            }
        });
        let connector = QuicConnector::new(transport, tls, Arc::new(BoringTlsProvider::new()))
            .with_early_data(true);
        for (index, required) in [false, false, true].into_iter().enumerate() {
            let input = ConnectRequest::new(HostWithPort::localhost_domain_with_port(443));
            input
                .extensions()
                .insert(ConnectorTarget(server_address.into()));
            let installed = Extensions::new();
            installed.insert(TlsEncryptedClientHello(false));
            input.extensions().extend(&installed);
            input
                .extensions()
                .insert(TlsProfilePreparation::new(|_, _, _| Ok(Extensions::new())));
            let (connected, accepted) = tokio::join!(connector.serve(input), async {
                server.accept().await.unwrap().await.unwrap()
            });
            let hellos = ServerClientHellos::from_extensions(accepted.extensions());
            if index == 1 {
                assert!(hellos.effective().unwrap().ext_server_name().is_none());
            }
            assert_eq!(hellos.ech_accepted(), Some(required));
            assert_eq!(hellos.ech_inner().is_some(), required);
            if required {
                assert_ne!(
                    hellos.wire().unwrap().ext_server_name(),
                    hellos.effective().unwrap().ext_server_name()
                );
            }
            let connected = connected.unwrap();
            assert_eq!(
                connected.conn.extensions().get_ref::<TlsEchAccepted>(),
                Some(&TlsEchAccepted(required))
            );
            connected.conn.close(0u32, b"verified");
            accepted.close(0u32, b"verified");
        }
        endpoint.shutdown().await;
        server.shutdown().await;
    })
    .await
    .unwrap();
}
