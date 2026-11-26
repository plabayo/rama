mod endpoint;

use std::net::{IpAddr, SocketAddr};

use rama_core::{Service as _, extensions::ExtensionsRef as _};
use rama_net::{
    Protocol,
    address::{Domain, Host, HostWithPort},
    client::{ConnectRequest, ConnectorTarget},
    tls::{ApplicationProtocol, TargetEchConfig},
};
use rama_quic_proto::capture::QuicObservation;
use rama_tls::{
    ExtensionId,
    client::{ClientHelloExtension, TlsClientSni, TlsEchAccepted},
    server::{
        CertificateIdentity, GeneratedServerAuthConfig, LeafCertRequest, ServerAuthData,
        ServerClientHellos, TlsServerConfig,
    },
};
use rama_tls_boring::server::{BoringServerConfigExt as _, EchServerKey, EchServerKeys};
use rama_ua::profile::{
    capture::{
        joint::{CapturedSlot, CapturedSlotKind},
        order::{OrderCaptureLimits, OrderNamespace, OrderedProtocolCapture, ProtocolValue},
        quic::{QuicFlightCapture, QuicFlightCaptureLimits},
        tls::{TlsCapture, TlsCaptureLimits, TlsCaptureTransport, TlsCapturedExtensionValue},
    },
    model::identity::ConnectionContext,
    replay::{
        connection::{
            compiler::{
                CompiledConnectionProfile as _, ConnectionProfileCompiler as _,
                InstalledConnectionProfile,
            },
            preparation::ConnectionPreparation,
        },
        request::{LoweredProfileItem, ProfilePreservationDifference},
    },
    selection::variants::ConnectionSelection,
};
use rama_udp::test_utils::MemoryDatagramSocket;
use rama_utils::macros::nonzero;
use tokio::{sync::mpsc, time::timeout};

use super::{grease::selected, *};
use crate::{
    client::{QuicConnector, SharedQuicEndpoint},
    profile::replay::ConnectionProfileCompiler,
    test_helpers::{ech_keys as keys, identity},
    tls::{BoringTlsProvider, QuicClientConfigProvider, TlsOptions},
};

fn tls_capture(hello: &ClientHello) -> TlsCapture {
    TlsCapture::capture(
        ProfileCaptureCompleteness::Complete,
        TlsCaptureTransport::Quic,
        hello,
        TlsCaptureLimits::default(),
    )
    .unwrap()
}

#[tokio::test]
async fn real_ech_replay_uses_the_effective_parameter_tuple_and_reports_outer_lowering() {
    timeout(Duration::from_secs(15), async {
        let keys = EchServerKeys::new([EchServerKey::new(
            keys::SERVER_ECH_CONFIG,
            keys::SERVER_ECH_KEY,
            true,
        )])
        .unwrap();
        let server_ip = IpAddr::from([192, 0, 2, 1]);
        let identity = ServerAuthData::new_generated(GeneratedServerAuthConfig::GeneratedCa {
            ca: Default::default(),
            leaf: LeafCertRequest {
                config: Default::default(),
                identities: vec![CertificateIdentity::Ip(server_ip)],
            },
        })
        .unwrap();
        let tls = TlsClientConfig::new()
            .with_alpn([ApplicationProtocol::HTTP_3].into_iter().collect())
            .try_with_server_trust_anchors([identity.cert_chain.last().unwrap().clone()])
            .unwrap();
        let server_tls = TlsServerConfig::new()
            .with_server_auth(identity)
            .with_alpn([ApplicationProtocol::HTTP_3].into_iter().collect())
            .with_ech_keys(keys.clone());
        let mut config = ServerConfig::try_from_rama_tls_with_provider(
            &server_tls,
            TlsOptions::default(),
            &BoringTlsProvider::new(),
        )
        .unwrap();
        config.set_capture(CaptureLimits::default());
        let client_address: SocketAddr = ([127, 0, 0, 1], 25000).into();
        let server_address: SocketAddr = ([127, 0, 0, 1], 25001).into();
        let (local, remote) =
            MemoryDatagramSocket::pair(client_address, server_address, nonzero!(64));
        let server = Endpoint::build(WeakScope::detached())
            .with_server_config(config)
            .with_datagram_socket(remote)
            .unwrap();
        let endpoint = Endpoint::build(WeakScope::detached())
            .with_datagram_socket(local)
            .unwrap();
        let accepting = server.clone();
        let (sent, mut received) = mpsc::unbounded_channel();
        let task = tokio::spawn(async move {
            let mut connections = Vec::new();
            for _ in 0..2 {
                let connection = accepting.accept().await.unwrap().await.unwrap();
                let hellos = ServerClientHellos::from_extensions(connection.extensions());
                assert_eq!(hellos.ech_accepted(), Some(true));
                sent.send((
                    hellos.ech_inner().unwrap().clone(),
                    hellos.wire().unwrap().clone(),
                    connection
                        .extensions()
                        .get_ref::<QuicObservation>()
                        .unwrap()
                        .clone(),
                ))
                .unwrap();
                connections.push(connection);
            }
            connections
        });
        let provider: Arc<dyn QuicClientConfigProvider> = Arc::new(BoringTlsProvider::new());
        let connector = QuicConnector::new(
            SharedQuicEndpoint::supplied(endpoint.clone(), WeakScope::detached()),
            tls.clone(),
            provider.clone(),
        );
        let request = || {
            let target = HostWithPort::new(Host::Address(server_ip), server_address.port());
            let request = ConnectRequest::new(target).with_application_protocol(Protocol::HTTPS);
            request
                .extensions()
                .insert(ConnectorTarget(server_address.into()));
            request.extensions().insert(TargetEchConfig::new(
                server_address.into(),
                keys.retry_configs().to_vec(),
            ));
            request
        };
        let initial = request();
        initial.extensions().insert(TlsClientSni::IncludeIp);
        let first = connector.serve(initial).await.unwrap().conn;
        let (inner, mut outer, observed) = received.recv().await.unwrap();
        assert_eq!(
            inner.ext_server_name().and_then(|name| name.as_ip()),
            Some(server_ip)
        );
        let full = transport_parameters_from_hello(&inner, &CaptureLimits::default()).unwrap();
        let reduced: Vec<_> = full
            .iter()
            .filter(|parameter| matches!(u64::from(parameter.id), 11 | 15 | 17))
            .cloned()
            .collect();
        assert!(full.len() > reduced.len());
        let mut body = Vec::new();
        for parameter in &reduced {
            body.push(u64::from(parameter.id) as u8);
            body.push(u8::try_from(parameter.value.len()).unwrap());
            body.extend_from_slice(&parameter.value);
        }
        outer = ClientHello::new(
            outer.protocol_version(),
            outer.cipher_suites().to_vec(),
            outer.compression_algorithms().to_vec(),
            outer
                .extensions()
                .iter()
                .cloned()
                .map(|extension| match extension {
                    ClientHelloExtension::Opaque {
                        id: ExtensionId::QUIC_TRANSPORT_PARAMETERS,
                        ..
                    } => ClientHelloExtension::Opaque {
                        id: ExtensionId::QUIC_TRANSPORT_PARAMETERS,
                        data: body.clone(),
                    },
                    extension => extension,
                })
                .collect(),
        );
        let mut flight =
            QuicFlightCapture::capture(&observed, QuicFlightCaptureLimits::default()).unwrap();
        flight.flight.parameters = reduced.iter().map(|parameter| parameter.id).collect();
        let parameters = OrderedProtocolCapture::capture(
            ProfileCaptureCompleteness::Complete,
            OrderNamespace::QuicParameter,
            full.iter()
                .map(|parameter| (u64::from(parameter.id), parameter.value.as_slice())),
            OrderCaptureLimits::default(),
        )
        .unwrap();
        let context = selected(vec![(
            ConnectionContext::default(),
            vec![
                CapturedSlot {
                    kind: CapturedSlotKind::QuicTls,
                    value: tls_capture(&inner)
                        .canonical(TlsCaptureLimits::default())
                        .unwrap(),
                },
                CapturedSlot {
                    kind: CapturedSlotKind::TlsOuter,
                    value: tls_capture(&outer)
                        .canonical(TlsCaptureLimits::default())
                        .unwrap(),
                },
                CapturedSlot {
                    kind: CapturedSlotKind::QuicParameters,
                    value: parameters.canonical(OrderCaptureLimits::default()).unwrap(),
                },
                CapturedSlot {
                    kind: CapturedSlotKind::QuicOuterParameters,
                    value: OrderedProtocolCapture::capture(
                        ProfileCaptureCompleteness::Complete,
                        OrderNamespace::QuicParameter,
                        reduced
                            .iter()
                            .map(|parameter| (u64::from(parameter.id), parameter.value.as_slice())),
                        OrderCaptureLimits::default(),
                    )
                    .unwrap()
                    .canonical(OrderCaptureLimits::default())
                    .unwrap(),
                },
                CapturedSlot {
                    kind: CapturedSlotKind::QuicFirstFlight,
                    value: flight
                        .canonical(QuicFlightCaptureLimits::default())
                        .unwrap(),
                },
            ],
        )]);
        let input = request();
        context.publish(input.extensions());
        let compiler = ConnectionProfileCompiler::new(tls, provider);
        assert!(compiler.ech_ready(&input));
        let mut outer_lowered = false;
        let (prepared, compiled) =
            ConnectionPreparation::prepare_with_ech(&input, true, |selection, components| {
                let compiled = compiler.compile(&input, selection, components)?;
                assert!(!components.preservation_report.differences.iter().any(
                    |difference| matches!(
                        difference,
                        ProfilePreservationDifference::LoweredProfileItem {
                            item: LoweredProfileItem::TlsEchInner
                        }
                    )
                ));
                outer_lowered =
                    components
                        .preservation_report
                        .differences
                        .iter()
                        .any(|difference| {
                            matches!(
                                difference,
                                ProfilePreservationDifference::LoweredProfileItem {
                                    item: LoweredProfileItem::QuicEchOuterParameters
                                }
                            )
                        });
                Ok(compiled)
            })
            .unwrap()
            .unwrap();
        assert!(outer_lowered);
        InstalledConnectionProfile::<ConnectRequest>::apply(compiled, input.extensions());
        let second = connector.serve(input).await.unwrap().conn;
        assert_eq!(
            second.extensions().get_ref::<TlsEchAccepted>(),
            Some(&TlsEchAccepted(true))
        );
        let (actual_inner, actual_outer, _) = received.recv().await.unwrap();
        assert_eq!(
            actual_inner.ext_server_name().and_then(|name| name.as_ip()),
            Some(server_ip)
        );
        let normalized = |hello: &ClientHello| {
            OrderedProtocolCapture::capture(
                ProfileCaptureCompleteness::Complete,
                OrderNamespace::QuicParameter,
                transport_parameters_from_hello(hello, &CaptureLimits::default())
                    .unwrap()
                    .iter()
                    .map(|parameter| (u64::from(parameter.id), parameter.value.as_slice())),
                OrderCaptureLimits::default(),
            )
            .unwrap()
        };
        assert_eq!(
            normalized(&actual_inner)
                .canonical(OrderCaptureLimits::default())
                .unwrap()
                .bytes,
            parameters
                .canonical(OrderCaptureLimits::default())
                .unwrap()
                .bytes
        );
        assert_eq!(
            normalized(&actual_outer)
                .canonical(OrderCaptureLimits::default())
                .unwrap()
                .bytes,
            parameters
                .canonical(OrderCaptureLimits::default())
                .unwrap()
                .bytes
        );
        assert_ne!(normalized(&actual_outer).fields.len(), reduced.len());
        let mut values_only = prepared.selection().prepare_components().unwrap();
        let mut outer_parameters = parameters.clone();
        let field = outer_parameters
            .fields
            .iter_mut()
            .find(|field| field.id == u64::from(TransportParameterId::InitialMaxData))
            .unwrap();
        let ProtocolValue::Literal(value) = &mut field.value else {
            panic!("the flow limit is a scalar");
        };
        *value.first_mut().unwrap() ^= 1;
        values_only.quic_outer_parameters = Some(outer_parameters);
        values_only.quic_first_flight = Some(
            QuicFlightCapture::capture(&observed, QuicFlightCaptureLimits::default()).unwrap(),
        );
        let full_shape = values_only
            .tls
            .as_ref()
            .unwrap()
            .extensions
            .iter()
            .find(|extension| extension.id == u16::from(ExtensionId::QUIC_TRANSPORT_PARAMETERS))
            .unwrap()
            .value
            .clone();
        values_only
            .tls_outer
            .as_mut()
            .unwrap()
            .extensions
            .iter_mut()
            .find(|extension| extension.id == u16::from(ExtensionId::QUIC_TRANSPORT_PARAMETERS))
            .unwrap()
            .value = full_shape;
        let compiled = compiler
            .compile(&request(), prepared.selection(), &mut values_only)
            .unwrap();
        assert!(
            values_only
                .preservation_report
                .differences
                .iter()
                .any(|difference| matches!(
                    difference,
                    ProfilePreservationDifference::LoweredProfileItem {
                        item: LoweredProfileItem::QuicEchOuterParameters
                    }
                ))
        );
        assert!(!compiled.supports(CapturedSlotKind::QuicFirstFlight));
        first.close(0u32, b"done");
        second.close(0u32, b"done");
        for connection in task.await.unwrap() {
            connection.close(0u32, b"done");
        }
        endpoint.shutdown().await;
        server.shutdown().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn late_ech_discovery_reprepares_the_drawn_quic_offer_in_both_directions() {
    timeout(Duration::from_secs(15), async {
        let keys = EchServerKeys::new([EchServerKey::new(
            keys::SERVER_ECH_CONFIG,
            keys::SERVER_ECH_KEY,
            true,
        )])
        .unwrap();
        let identity = identity();
        let tls = TlsClientConfig::new()
            .with_alpn([ApplicationProtocol::HTTP_3].into_iter().collect())
            .try_with_server_trust_anchors([identity.cert_chain.last().unwrap().clone()])
            .unwrap();
        let mut config = ServerConfig::try_from_rama_tls_with_provider(
            &TlsServerConfig::new()
                .with_server_auth(identity)
                .with_alpn([ApplicationProtocol::HTTP_3].into_iter().collect())
                .with_ech_keys(keys.clone()),
            TlsOptions::default(),
            &BoringTlsProvider::new(),
        )
        .unwrap();
        config.set_capture(CaptureLimits::default());
        let client_address: SocketAddr = ([127, 0, 0, 1], 25010).into();
        let server_address: SocketAddr = ([127, 0, 0, 1], 25011).into();
        let (local, remote) =
            MemoryDatagramSocket::pair(client_address, server_address, nonzero!(64));
        let server = Endpoint::build(WeakScope::detached())
            .with_server_config(config)
            .with_datagram_socket(remote)
            .unwrap();
        let endpoint = Endpoint::build(WeakScope::detached())
            .with_datagram_socket(local)
            .unwrap();
        let accepting = server.clone();
        let (sent, mut received) = mpsc::unbounded_channel();
        let task = tokio::spawn(async move {
            let mut connections = Vec::new();
            for _ in 0..3 {
                let connection = accepting.accept().await.unwrap().await.unwrap();
                let hellos = ServerClientHellos::from_extensions(connection.extensions());
                sent.send((
                    hellos.ech_accepted(),
                    hellos.ech_inner().is_some(),
                    hellos.effective().unwrap().clone(),
                    hellos.wire().unwrap().clone(),
                ))
                .unwrap();
                connections.push(connection);
            }
            connections
        });
        let provider: Arc<dyn QuicClientConfigProvider> = Arc::new(BoringTlsProvider::new());
        let connector = QuicConnector::new(
            SharedQuicEndpoint::supplied(endpoint.clone(), WeakScope::detached()),
            tls.clone(),
            provider.clone(),
        );
        let request = || {
            let request = ConnectRequest::new(HostWithPort::localhost_domain_with_port(
                server_address.port(),
            ))
            .with_application_protocol(Protocol::HTTPS);
            request
                .extensions()
                .insert(ConnectorTarget(server_address.into()));
            request
        };
        let add_config = |input: &ConnectRequest| {
            input.extensions().insert(TargetEchConfig::new(
                server_address.into(),
                keys.retry_configs().to_vec(),
            ));
        };
        let initial = request();
        add_config(&initial);
        let first = connector.serve(initial).await.unwrap().conn;
        let (accepted, inner_present, inner, outer) = received.recv().await.unwrap();
        assert_eq!(accepted, Some(true));
        assert!(inner_present);
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
                vec![slot(CapturedSlotKind::QuicTls, &outer)],
            ),
            (
                paired.clone(),
                vec![
                    slot(CapturedSlotKind::QuicTls, &inner),
                    slot(CapturedSlotKind::TlsOuter, &outer),
                ],
            ),
        ]);
        let compiler = ConnectionProfileCompiler::new(tls, provider);
        for ready in [false, true] {
            let input = request();
            input.extensions().insert(paired.clone());
            if ready {
                add_config(&input);
            }
            context.clone().publish(input.extensions());
            let (_, compiled) =
                ConnectionPreparation::prepare_with_ech(&input, ready, |selection, components| {
                    compiler.compile(&input, selection, components)
                })
                .unwrap()
                .unwrap();
            InstalledConnectionProfile::<ConnectRequest>::apply(compiled, input.extensions());
            if ready {
                input.extensions().insert(TargetEchConfig::new(
                    "other.example:443".parse().unwrap(),
                    keys.retry_configs().to_vec(),
                ));
            } else {
                add_config(&input);
            }
            let connection = connector.serve(input).await.unwrap().conn;
            assert_eq!(
                connection.extensions().get_ref::<TlsEchAccepted>(),
                Some(&TlsEchAccepted(!ready))
            );
            assert_eq!(
                connection
                    .extensions()
                    .get_ref::<ConnectionSelection>()
                    .unwrap()
                    .ech_ready,
                !ready
            );
            let (accepted, inner_present, effective, wire) = received.recv().await.unwrap();
            assert_eq!(accepted, Some(!ready));
            assert_eq!(inner_present, !ready);
            assert!(
                wire.extensions()
                    .iter()
                    .any(|extension| extension.id() == ExtensionId::ENCRYPTED_CLIENT_HELLO)
            );
            let captured = tls_capture(&effective);
            assert_eq!(
                captured.extensions.iter().any(|extension| matches!(
                    extension.value,
                    TlsCapturedExtensionValue::EchInner
                )),
                !ready
            );
            assert!(
                !tls_capture(&wire)
                    .extensions
                    .iter()
                    .any(|extension| matches!(
                        extension.value,
                        TlsCapturedExtensionValue::EchInner
                    ))
            );
            assert_eq!(
                effective.ext_server_name().unwrap().as_domain(),
                Some(&Domain::tld_localhost())
            );
            connection.close(0u32, b"done");
        }
        first.close(0u32, b"done");
        for connection in task.await.unwrap() {
            connection.close(0u32, b"done");
        }
        endpoint.shutdown().await;
        server.shutdown().await;
    })
    .await
    .unwrap();
}
