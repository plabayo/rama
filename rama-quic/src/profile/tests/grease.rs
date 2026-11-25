//! A connection context observed only with accepted ECH, replayed to a target without ECH.

use std::{collections::BTreeMap, net::SocketAddr};

use rama_core::{Service as _, extensions::ExtensionsRef as _};
use rama_net::{
    Protocol,
    address::{Host, HostWithPort, SocketAddress},
    client::{ConnectRequest, ConnectorTarget},
    http::Version as HttpVersion,
    tls::ApplicationProtocol,
};
use rama_tls::{
    ExtensionId,
    client::{ClientHello, NegotiatedTlsParameters, TlsClientSni, TlsEchAccepted},
    server::TlsServerConfig,
};
use rama_ua::profile::{
    capture::{
        CAPTURE_REVISION,
        headers::{HeaderCapture, HeaderCapturePolicy},
        joint::{CaptureLevel, CapturedSlot, CapturedSlotKind, JointCapture, JointCaptureLimits},
        observation::ProfileCapture,
        tls::{TlsCapture, TlsCaptureLimits, TlsCaptureTransport, TlsCapturedExtensionValue},
    },
    evidence::{
        ProfileEvidence, ProfileScopeEvidence,
        ingestion::ObservationId,
        window::{ProfileWindowLimits, RetainedBucketWindow},
    },
    format::archive::{ProfileArchiveEntry, ProfileArchiveLimits, ProfileArchiveWriter},
    model::identity::{ConnectionContext, FlowKey, ProfileKey},
    replay::{
        connection::{
            compiler::{ConnectionProfileCompiler as _, InstalledConnectionProfile},
            preparation::ConnectionPreparation,
        },
        request::{LoweredProfileItem, ProfilePreservationDifference},
    },
    selection::{
        DrawKey, ProfileSeed,
        capabilities::CapabilitySet,
        database::UserAgentDatabase,
        variants::{EmulationContext, ProfileSelector, SelectionRequest, VariantPins},
    },
};
use rama_udp::test_utils::MemoryDatagramSocket;
use rama_utils::macros::nonzero;
use tokio::{sync::mpsc, time::timeout};

use super::*;
use crate::{
    ServerConfig,
    client::{QuicConnector, SharedQuicEndpoint},
    profile::replay::ConnectionProfileCompiler,
    test_helpers::identity,
    tls::{BoringTlsProvider, QuicClientConfigProvider, TlsOptions},
};

fn captured(hello: &ClientHello) -> TlsCapture {
    TlsCapture::capture(
        ProfileCaptureCompleteness::Complete,
        TlsCaptureTransport::Quic,
        hello,
        TlsCaptureLimits::default(),
    )
    .unwrap()
}

fn replay_form(capture: &TlsCapture) -> TlsCapture {
    // Without a captured transport the parameters are native, their GREASE varying per connection.
    let mut capture = capture.clone().with_grease_placeholders().unwrap();
    for extension in &mut capture.extensions {
        if extension.id == u16::from(ExtensionId::QUIC_TRANSPORT_PARAMETERS) {
            extension.value = TlsCapturedExtensionValue::ConnectionLength(0);
        }
    }
    capture
}

pub(super) fn selected(
    connections: Vec<(ConnectionContext, Vec<CapturedSlot>)>,
) -> EmulationContext {
    let flow = FlowKey::Http {
        version: HttpVersion::HTTP_3,
        method: "GET".parse().unwrap(),
        initiator: None,
        fetch: None,
        connection: ConnectionContext::default(),
    };
    let request = HeaderCapture {
        completeness: ProfileCaptureCompleteness::Complete,
        version: HttpVersion::HTTP_3,
        fields: Box::default(),
    }
    .canonical(&HeaderCapturePolicy::default())
    .unwrap();
    let settings = OrderedProtocolCapture {
        completeness: ProfileCaptureCompleteness::Complete,
        namespace: OrderNamespace::Http3Setting,
        fields: Box::default(),
    }
    .canonical(OrderCaptureLimits::default())
    .unwrap();
    let observations = connections
        .into_iter()
        .map(|(context, mut slots)| {
            slots.push(CapturedSlot {
                kind: CapturedSlotKind::Http3Settings,
                value: settings.clone(),
            });
            (None, context, CaptureLevel::Connection, slots)
        })
        .chain([(
            Some(flow.clone()),
            ConnectionContext::default(),
            CaptureLevel::Request,
            vec![CapturedSlot {
                kind: CapturedSlotKind::Headers,
                value: request,
            }],
        )]);
    let mut windows = BTreeMap::new();
    for (sequence, (flow, connection, level, slots)) in (1..).zip(observations) {
        let prepared = ProfileCapture {
            revision: CAPTURE_REVISION,
            profile: ProfileKey::new("quic-grease"),
            flow,
            connection,
            joint: JointCapture {
                completeness: ProfileCaptureCompleteness::Complete,
                level,
                slots: slots.into(),
            },
        }
        .prepare(false, JointCaptureLimits::default())
        .unwrap();
        for bucket in prepared.buckets {
            let (_, _, _, window) = windows.entry(bucket.scope.id).or_insert_with(|| {
                (
                    bucket.scope.clone(),
                    prepared.flow.clone(),
                    bucket.structure.clone(),
                    RetainedBucketWindow::new(
                        bucket.value.validated_domain(65536).unwrap(),
                        bucket.scope.id,
                        [3; 32],
                        ProfileWindowLimits::default(),
                    )
                    .unwrap(),
                )
            });
            window
                .observe(
                    100,
                    100,
                    ObservationId {
                        run: [1; 16],
                        sequence,
                    },
                    &bucket.value,
                )
                .unwrap();
        }
    }
    let scopes: Vec<_> = windows
        .into_values()
        .map(|(scope, flow, structure, window)| ProfileScopeEvidence {
            scope,
            flow,
            structure,
            window: window.snapshot(),
        })
        .collect();
    let archive =
        ProfileArchiveWriter::new(Vec::new(), false, 100, 14, ProfileArchiveLimits::default())
            .unwrap()
            .write_profile(ProfileArchiveEntry {
                evidence: ProfileEvidence {
                    format_version: 1,
                    profile: ProfileKey::new("quic-grease").canonical(65536).unwrap(),
                    scopes: scopes.into(),
                },
                sampler_seed: [3; 32],
            })
            .unwrap()
            .finish()
            .unwrap();
    let database = UserAgentDatabase::try_from_archive(
        &archive,
        false,
        100,
        14,
        ProfileArchiveLimits::default(),
    )
    .unwrap();
    let selected = database
        .select(
            &SelectionRequest {
                client: ProfileSelector::default(),
                required: CapabilitySet {
                    h3: true,
                    tls_quic: true,
                    ..CapabilitySet::default()
                },
                flow,
                pins: VariantPins::default(),
            },
            ProfileSeed([4; 32]),
            DrawKey([5; 32]),
        )
        .unwrap();
    Arc::new(selected).emulation_context(ProfileSeed([4; 32]), DrawKey([6; 32]), DrawKey([7; 32]))
}

#[tokio::test]
async fn paired_only_context_offers_its_outer_with_grease_ech_over_quic() {
    timeout(Duration::from_secs(15), async {
        let identity = identity();
        let server_tls = TlsServerConfig::new()
            .with_alpn([ApplicationProtocol::HTTP_3].into_iter().collect())
            .with_server_auth(identity.clone());
        let mut config =
            ServerConfig::try_from_rama_tls(&server_tls, TlsOptions::default()).unwrap();
        config.set_capture(CaptureLimits::default());
        let server =
            Endpoint::bind_server(WeakScope::detached(), config, SocketAddress::local_ipv4(0))
                .await
                .unwrap();
        let address = server.local_addr().unwrap();
        let (hellos, mut observed) = mpsc::unbounded_channel();
        let accept = server.clone();
        let task = tokio::spawn(async move {
            let mut connections = Vec::new();
            for _ in 0..2 {
                let mut incoming = accept.accept().await.unwrap();
                hellos.send(incoming.client_hello().await.unwrap()).unwrap();
                connections.push(incoming.accept().unwrap().await.unwrap());
            }
            connections
        });
        // No ECH configuration is published for the target, so ECH is offered as GREASE.
        let tls = TlsClientConfig::new()
            .with_alpn([ApplicationProtocol::HTTP_3].into_iter().collect())
            .with_encrypted_client_hello(true)
            .try_with_server_trust_anchors([identity.cert_chain.last().unwrap().clone()])
            .unwrap();
        let provider: Arc<dyn QuicClientConfigProvider> = Arc::new(BoringTlsProvider::new());
        let endpoint = Endpoint::bind_client(WeakScope::detached(), SocketAddress::local_ipv4(0))
            .await
            .unwrap();
        let connector = QuicConnector::new(
            SharedQuicEndpoint::supplied(endpoint.clone(), WeakScope::detached()),
            tls.clone(),
            provider.clone(),
        );
        let request = || {
            let request =
                ConnectRequest::new(HostWithPort::localhost_domain_with_port(address.port()))
                    .with_application_protocol(Protocol::HTTPS);
            request.extensions().insert(ConnectorTarget(address.into()));
            request
        };
        let first = connector.serve(request()).await.unwrap().conn;
        let grease = captured(&observed.recv().await.unwrap());
        // The native stack builds its ECH outer like its GREASE offer; the inner only marks the pair.
        let mut inner = grease.clone();
        for extension in &mut inner.extensions {
            if matches!(extension.value, TlsCapturedExtensionValue::EchOuter { .. }) {
                extension.value = TlsCapturedExtensionValue::EchInner;
            }
        }
        assert_ne!(inner, grease);
        let slot = |kind, capture: &TlsCapture| CapturedSlot {
            kind,
            value: capture.canonical(TlsCaptureLimits::default()).unwrap(),
        };
        let paired_only = ConnectionContext {
            token_present: Some(true),
            ..ConnectionContext::default()
        };
        let context = selected(vec![
            (
                ConnectionContext::default(),
                vec![slot(CapturedSlotKind::QuicTls, &grease)],
            ),
            (
                paired_only.clone(),
                vec![
                    slot(CapturedSlotKind::QuicTls, &inner),
                    slot(CapturedSlotKind::TlsOuter, &grease),
                ],
            ),
        ]);

        let input = request();
        input.extensions().insert(paired_only);
        context.publish(input.extensions());
        let compiler = ConnectionProfileCompiler::new(tls, provider);
        let ech = compiler.ech_ready(&input);
        assert!(!ech);
        let (preparation, compiled) =
            ConnectionPreparation::prepare_with_ech(&input, ech, |selection, components| {
                compiler.compile(&input, selection, components)
            })
            .unwrap()
            .unwrap();
        assert!(!preparation.selection().ech_ready);
        let expected = preparation
            .selection()
            .prepare_components()
            .unwrap()
            .tls_outer
            .unwrap();
        InstalledConnectionProfile::<ConnectRequest>::apply(compiled, input.extensions());
        let second = connector.serve(input).await.unwrap().conn;
        assert_eq!(
            replay_form(&captured(&observed.recv().await.unwrap())),
            replay_form(&expected)
        );
        assert_eq!(
            second.extensions().get_ref::<TlsEchAccepted>(),
            Some(&TlsEchAccepted(false))
        );
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
async fn quic_profile_replay_to_ip_honors_sni_policy() {
    timeout(Duration::from_secs(15), async {
        let identity = identity();
        let server_tls = TlsServerConfig::new()
            .with_alpn([ApplicationProtocol::HTTP_3].into_iter().collect())
            .with_server_auth(identity);
        let mut server_config = ServerConfig::try_from_rama_tls_with_provider(
            &server_tls,
            TlsOptions::default(),
            &BoringTlsProvider::new(),
        )
        .unwrap();
        server_config.set_capture(CaptureLimits::default());
        let client_address: SocketAddr = ([127, 0, 0, 1], 24900).into();
        let server_address: SocketAddr = ([127, 0, 0, 1], 24901).into();
        let (local, remote) =
            MemoryDatagramSocket::pair(client_address, server_address, nonzero!(64));
        let server = Endpoint::build(WeakScope::detached())
            .with_server_config(server_config)
            .with_datagram_socket(remote)
            .unwrap();
        let endpoint = Endpoint::build(WeakScope::detached())
            .with_datagram_socket(local)
            .unwrap();
        let accepting = server.clone();
        let (sent, mut received) = mpsc::unbounded_channel();
        let task = tokio::spawn(async move {
            let mut connections = Vec::new();
            for _ in 0..25 {
                let mut incoming = accepting.accept().await.unwrap();
                let hello = incoming.client_hello().await.unwrap();
                let connection = incoming.accept().unwrap().await.unwrap();
                assert_eq!(
                    connection
                        .extensions()
                        .get_ref::<NegotiatedTlsParameters>()
                        .unwrap()
                        .server_name
                        .as_ref(),
                    hello.ext_server_name()
                );
                sent.send(hello).unwrap();
                connections.push(connection);
            }
            connections
        });
        let tls = TlsClientConfig::new()
            .with_alpn([ApplicationProtocol::HTTP_3].into_iter().collect())
            .with_server_verify(ServerVerifyMode::Disable);
        let provider: Arc<dyn QuicClientConfigProvider> = Arc::new(BoringTlsProvider::new());
        let connector = QuicConnector::new(
            SharedQuicEndpoint::supplied(endpoint.clone(), WeakScope::detached()),
            tls.clone(),
            provider.clone(),
        );
        let request = |host| {
            let request = ConnectRequest::new(HostWithPort::new(host, 443))
                .with_application_protocol(Protocol::HTTPS);
            request
                .extensions()
                .insert(ConnectorTarget(server_address.into()));
            request
        };
        let first = connector
            .serve(request(Host::LOCALHOST_NAME))
            .await
            .unwrap()
            .conn;
        let source = captured(&received.recv().await.unwrap());
        let mut ip_source = source.clone();
        for extension in &mut ip_source.extensions {
            if matches!(
                extension.value,
                TlsCapturedExtensionValue::ServerName { .. }
            ) {
                extension.value = TlsCapturedExtensionValue::IpServerName;
            }
        }
        let ip_context = selected(vec![(
            ConnectionContext::default(),
            vec![CapturedSlot {
                kind: CapturedSlotKind::QuicTls,
                value: ip_source.canonical(TlsCaptureLimits::default()).unwrap(),
            }],
        )]);
        let dns_context = selected(vec![(
            ConnectionContext::default(),
            vec![CapturedSlot {
                kind: CapturedSlotKind::QuicTls,
                value: source.canonical(TlsCaptureLimits::default()).unwrap(),
            }],
        )]);
        let mut unnamed = source;
        unnamed.extensions = unnamed
            .extensions
            .into_vec()
            .into_iter()
            .filter(|extension| extension.id != u16::from(ExtensionId::SERVER_NAME))
            .collect();
        let unnamed_context = selected(vec![(
            ConnectionContext::default(),
            vec![CapturedSlot {
                kind: CapturedSlotKind::QuicTls,
                value: unnamed.canonical(TlsCaptureLimits::default()).unwrap(),
            }],
        )]);
        let compiler = ConnectionProfileCompiler::new(tls, provider);
        for ip in ["192.0.2.1".parse().unwrap(), "2001:db8::1".parse().unwrap()] {
            for captured in [0, 1, 2] {
                let captured_ip = captured == 1;
                let captured_sni = captured != 0;
                for policy in [
                    None,
                    Some(TlsClientSni::Auto),
                    Some(TlsClientSni::IncludeIp),
                    Some(TlsClientSni::Disabled),
                ] {
                    let input = request(Host::Address(ip));
                    if let Some(policy) = policy {
                        input.extensions().insert(policy);
                    }
                    let sends_ip = match policy {
                        None => captured_ip,
                        Some(TlsClientSni::IncludeIp) => true,
                        _ => false,
                    };
                    match captured {
                        1 => ip_context.clone(),
                        2 => dns_context.clone(),
                        _ => unnamed_context.clone(),
                    }
                    .publish(input.extensions());
                    let mut lowered_sni = false;
                    let (_, compiled) = ConnectionPreparation::prepare_with_ech(
                        &input,
                        false,
                        |selection, components| {
                            let compiled = compiler.compile(&input, selection, components)?;
                            lowered_sni = components.preservation_report.differences.iter().any(
                                |difference| {
                                    matches!(
                                        difference,
                                        ProfilePreservationDifference::LoweredProfileItem {
                                            item: LoweredProfileItem::TlsServerNamePresence
                                        }
                                    )
                                },
                            );
                            Ok(compiled)
                        },
                    )
                    .unwrap()
                    .unwrap();
                    assert_eq!(lowered_sni, captured_sni != sends_ip);
                    InstalledConnectionProfile::<ConnectRequest>::apply(
                        compiled,
                        input.extensions(),
                    );
                    let connection = connector.serve(input).await.unwrap().conn;
                    assert_eq!(
                        received.recv().await.unwrap().ext_server_name().cloned(),
                        if sends_ip { Some(ip.into()) } else { None }
                    );
                    connection.close(0u32, b"done");
                }
            }
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
