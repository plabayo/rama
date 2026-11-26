use std::{net::SocketAddr, sync::Arc};

use rama_core::{
    Service as _, extensions::ExtensionsRef as _, graceful::WeakScope, service::service_fn,
};
use rama_net::{
    Protocol,
    address::HostWithPort,
    client::{ConnectRequest, ConnectorTarget},
    tls::{ApplicationProtocol, TargetEchConfig},
};
use rama_quic_proto::capture::CaptureLimits;
use rama_tls::{
    client::{ClientHello, TlsClientConfig, TlsClientSni, TlsEchAccepted},
    server::{ServerClientHellos, TlsServerConfig},
};
use rama_tls_boring::server::{BoringServerConfigExt as _, EchServerKey, EchServerKeys};
use rama_ua::profile::{
    capture::{
        joint::{CapturedSlot, CapturedSlotKind},
        tls::TlsCaptureLimits,
    },
    model::identity::ConnectionContext,
    replay::connection::{
        compiler::{ConnectionProfileCompiler as _, InstalledConnectionProfile},
        preparation::ConnectionPreparation,
    },
    selection::variants::ConnectionSelection,
};
use rama_udp::test_utils::MemoryDatagramSocket;
use rama_utils::macros::nonzero;
use tokio::time::{Duration, timeout};

use super::{selected, tls_capture};
use crate::{
    Endpoint, ServerConfig,
    client::{QuicConnector, SharedQuicEndpoint},
    profile::replay::ConnectionProfileCompiler,
    test_helpers::{
        ech_keys::{SERVER_ECH_CONFIG, SERVER_ECH_KEY},
        identity,
    },
    tls::{BoringTlsProvider, QuicClientConfigProvider, TlsOptions},
};

#[tokio::test]
async fn endpoint_discovery_reprepares_the_drawn_offer_in_both_directions() {
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
        let server_address: SocketAddr = ([127, 0, 0, 1], 25231).into();
        let client_address: SocketAddr = ([127, 0, 0, 1], 25230).into();
        let (local, remote) =
            MemoryDatagramSocket::pair(client_address, server_address, nonzero!(64));
        let server = Endpoint::build(WeakScope::detached())
            .with_server_config(config)
            .with_datagram_socket(remote)
            .unwrap();
        let endpoint = Endpoint::build(WeakScope::detached())
            .with_datagram_socket(local)
            .unwrap();
        let endpoints = SharedQuicEndpoint::supplied(endpoint.clone(), WeakScope::detached());
        let provider: Arc<dyn QuicClientConfigProvider> = Arc::new(BoringTlsProvider::new());
        let connector = QuicConnector::new(endpoints.clone(), tls.clone(), provider.clone());
        let request = || {
            let input = ConnectRequest::new(HostWithPort::localhost_domain_with_port(25231))
                .with_application_protocol(Protocol::HTTPS);
            input
                .extensions()
                .insert(ConnectorTarget(server_address.into()));
            input
        };
        let input = request();
        input.extensions().insert(TargetEchConfig::new(
            server_address.into(),
            keys.retry_configs().to_vec(),
        ));
        let (connected, accepted) = tokio::join!(connector.serve(input), async {
            server.accept().await.unwrap().await.unwrap()
        });
        let connected = connected.unwrap();
        let hellos = ServerClientHellos::from_extensions(accepted.extensions());
        let slot = |kind, hello: &ClientHello| CapturedSlot {
            kind,
            value: tls_capture(hello)
                .canonical(TlsCaptureLimits::default())
                .unwrap(),
        };
        let paired = ConnectionContext {
            token_present: Some(true),
            ..ConnectionContext::default()
        };
        let context = selected(vec![
            (
                ConnectionContext::default(),
                vec![slot(CapturedSlotKind::QuicTls, hellos.wire().unwrap())],
            ),
            (
                paired.clone(),
                vec![
                    slot(CapturedSlotKind::QuicTls, hellos.effective().unwrap()),
                    slot(CapturedSlotKind::TlsOuter, hellos.wire().unwrap()),
                ],
            ),
        ]);
        connected.conn.close(0u32, b"done");
        accepted.close(0u32, b"done");
        let compiler = ConnectionProfileCompiler::new(tls.clone(), provider.clone());
        for (ready, suppress_sni) in [(false, false), (true, false), (true, true)] {
            let input = request();
            input.extensions().insert(paired.clone());
            if ready {
                input.extensions().insert(TargetEchConfig::new(
                    server_address.into(),
                    keys.retry_configs().to_vec(),
                ));
            }
            context.clone().publish(input.extensions());
            let (_, compiled) =
                ConnectionPreparation::prepare_with_ech(&input, ready, |selection, components| {
                    compiler.compile(&input, selection, components)
                })
                .unwrap()
                .unwrap();
            InstalledConnectionProfile::<ConnectRequest>::apply(compiled, input.extensions());
            let connector = QuicConnector::new(
                service_fn({
                    let endpoints = endpoints.clone();
                    let configs = keys.retry_configs().to_vec();
                    move |input: ConnectRequest| {
                        if suppress_sni {
                            input.extensions().insert(TlsClientSni::Disabled);
                        }
                        input.extensions().insert(TargetEchConfig::new(
                            if ready {
                                "other.example:443".parse().unwrap()
                            } else {
                                server_address.into()
                            },
                            configs.clone(),
                        ));
                        let endpoints = endpoints.clone();
                        async move { endpoints.serve(input).await }
                    }
                }),
                tls.clone(),
                provider.clone(),
            );
            let (connected, accepted) = tokio::join!(connector.serve(input), async {
                server.accept().await.unwrap().await.unwrap()
            });
            let connected = connected.unwrap();
            assert_eq!(
                connected.conn.extensions().get_ref::<TlsEchAccepted>(),
                Some(&TlsEchAccepted(!ready))
            );
            assert_eq!(
                connected
                    .conn
                    .extensions()
                    .get_ref::<ConnectionSelection>()
                    .unwrap()
                    .ech_ready,
                !ready
            );
            let hellos = ServerClientHellos::from_extensions(accepted.extensions());
            assert_eq!(hellos.ech_accepted(), Some(!ready));
            assert_eq!(hellos.ech_inner().is_some(), !ready);
            // A late SNI override yields to the profile when it prepares again.
            assert!(hellos.effective().unwrap().ext_server_name().is_some());
            connected.conn.close(0u32, b"done");
            accepted.close(0u32, b"done");
        }
        endpoint.shutdown().await;
        server.shutdown().await;
    })
    .await
    .unwrap();
}
