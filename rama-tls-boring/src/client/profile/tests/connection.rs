use std::{
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};

use rama_core::{Service, ServiceInput, service::service_fn};
use rama_net::{
    address::Domain,
    client::{ConnectionError, ConnectionErrorKind, EstablishedClientConnection},
    tls::{ApplicationProtocol, ServerName, TargetEchServiceBinding},
};
#[cfg(feature = "http")]
use rama_net::{
    client::pool::ConnectionReuse,
    http::{FallbackHttpVersion, HttpRequestVersion},
};
#[cfg(feature = "http")]
use rama_tls::ExtensionId;
use rama_tls::{
    client::{
        NegotiatedTlsParameters, ServerVerifyMode, TargetEchResolution, TlsClientSni,
        TlsEncryptedClientHello, TlsProfilePreparation, TlsServerAuthentication,
    },
    server::{
        CertificateIdentity, GeneratedServerAuthConfig, LeafCertRequest, ServerAuthData,
        TlsServerConfig, peek_client_hello_from_input,
    },
};
use rama_ua::profile::{
    capture::joint::CapturedSlot,
    model::identity::{ConnectionContext, ConnectionIpFamily, ResumptionContext},
    replay::connection::{
        compiler::ConnectionProfileCompiler as _, preparation::ConnectionPreparation,
    },
    selection::{ProfileSeed, variants::EmulationContext},
};
use rama_utils::octets::kib;
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _, duplex},
    time::timeout,
};

use super::{
    fixture::{selected, selected_connections},
    *,
};
use crate::{
    client::{TlsClientSession, TlsClientSessionKey, TlsClientSessionStore},
    server::TlsAcceptorData,
};

#[tokio::test]
async fn incompatible_caller_policy_is_retained_and_reported_before_dial() {
    let calls = Arc::new(AtomicUsize::new(0));
    let counted = calls.clone();
    let inner = service_fn(move |input: ConnectRequest| {
        counted.fetch_add(1, Ordering::Relaxed);
        let report = input
            .extensions()
            .get_ref::<ProfilePreservationReport>()
            .cloned()
            .unwrap_or_default();
        async move {
            assert_eq!(
                lowered(&report),
                [LoweredProfileItem::CallerTlsVersionBounds]
            );
            Err::<
                EstablishedClientConnection<ServiceInput<tokio::io::DuplexStream>, ConnectRequest>,
                _,
            >(ConnectionError::local(
                BoxError::from_static_str("fixture dial"),
                ConnectionErrorKind::Internal,
            ))
        }
    });
    let connector = ProfileEmulateHttpConnectModifier::new(inner)
        .with_connection_compiler(ConnectionProfileCompiler::new(TlsClientConfig::new()));
    let request = input();
    let (context, _) = selected("prepared-profile");
    context.publish(request.extensions());
    TlsClientConfig::new()
        .with_max_version(rama_tls::ProtocolVersion::TLSv1_2)
        .write_to(request.extensions());
    let error = connector.serve(request).await.unwrap_err();
    assert!(error.to_string().contains("fixture dial"), "{error}");
    assert_eq!(calls.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn transport_adapter_rejects_changed_policy_before_tls() {
    let inner = service_fn(|input: ConnectRequest| async move {
        TlsClientConfig::new()
            .with_server_verify(ServerVerifyMode::Disable)
            .write_to(input.extensions());
        let (client, _server) = tokio::io::duplex(1024);
        Ok::<_, ConnectionError>(EstablishedClientConnection {
            input,
            conn: ServiceInput::new(client),
        })
    });
    let connector = ProfileEmulateHttpConnectModifier::new(inner)
        .with_connection_compiler(ConnectionProfileCompiler::new(TlsClientConfig::new()));
    let request = input();
    let (context, _) = selected("prepared-profile");
    context.publish(request.extensions());
    let error = connector.serve(request).await.unwrap_err();
    assert!(error.to_string().contains("policy changed"), "{error}");
}

#[tokio::test]
async fn transport_adapter_binds_destination_and_protocol() {
    for (protocol, change_authority) in [
        (Some(Protocol::HTTP), false),
        (None, false),
        (Some(Protocol::WSS), false),
        (Some(Protocol::HTTPS), true),
    ] {
        let inner = service_fn(move |mut input: ConnectRequest| {
            input.application_protocol = protocol.clone();
            if change_authority {
                input.authority = "other.test:443".parse().unwrap();
            }
            async move {
                let (client, _server) = tokio::io::duplex(1024);
                Ok::<_, ConnectionError>(EstablishedClientConnection {
                    input,
                    conn: ServiceInput::new(client),
                })
            }
        });
        let connector = ProfileEmulateHttpConnectModifier::new(inner)
            .with_connection_compiler(ConnectionProfileCompiler::new(TlsClientConfig::new()));
        let request = input();
        let (context, _) = selected("prepared-profile");
        context.publish(request.extensions());
        let error = connector.serve(request).await.unwrap_err();
        assert!(error.to_string().contains("policy changed"), "{error}");
    }
}

#[tokio::test]
async fn ordinary_auto_connections_can_still_return_plaintext_after_transport() {
    for protocol in [Some(Protocol::HTTP), None] {
        let inner = service_fn(move |mut input: ConnectRequest| {
            input.application_protocol = protocol.clone();
            async move {
                let (client, _server) = tokio::io::duplex(1024);
                Ok::<_, ConnectionError>(EstablishedClientConnection {
                    input,
                    conn: ServiceInput::new(client),
                })
            }
        });
        let connection = TlsConnector::auto(inner).serve(input()).await.unwrap();
        assert!(connection.conn.ssl_ref().is_none());
    }
}

#[derive(Default)]
struct SessionAccess {
    reads: AtomicUsize,
    writes: AtomicUsize,
}

impl TlsClientSessionStore for SessionAccess {
    fn put(&self, _: TlsClientSession) {
        self.writes.fetch_add(1, Ordering::Relaxed);
    }

    fn take(&self, _: &TlsClientSessionKey) -> Option<TlsClientSession> {
        self.reads.fetch_add(1, Ordering::Relaxed);
        None
    }
}

#[tokio::test]
async fn a_configured_session_store_does_not_change_a_fresh_captured_offer() {
    let store = Arc::new(SessionAccess::default());
    Box::pin(established_with_store(
        None,
        Some(store.clone()),
        ConnectionContext::default(),
    ))
    .await;
    assert_eq!(store.reads.load(Ordering::Relaxed), 0);
    assert!(
        store.writes.load(Ordering::Relaxed) > 0,
        "new tickets still reach the configured store"
    );
}

#[tokio::test]
async fn outer_adapter_preserves_native_trust_and_negotiated_alpn() {
    let connection = Box::pin(established(None)).await;
    #[cfg(not(feature = "http"))]
    {
        let request = input();
        let (context, _) = selected("prepared-profile");
        context.publish(request.extensions());
        assert!(
            !connection
                .get_ref::<rama_net::client::pool::ConnectionReuse>()
                .unwrap()
                .matches(request.extensions()),
            "without negotiated HTTP, native wire policy must restrict reuse"
        );
    }
    #[cfg(feature = "http")]
    let _ = connection;
}

pub(super) async fn established(
    context: Option<(&EmulationContext, &ConnectionSelection)>,
) -> rama_core::extensions::Extensions {
    Box::pin(established_with_store(
        context,
        None,
        ConnectionContext::default(),
    ))
    .await
}

/// Establish a connection for `context` drawn in `connection` against a server without ECH.
pub(super) async fn established_in(
    context: (&EmulationContext, &ConnectionSelection),
    connection: ConnectionContext,
) -> Extensions {
    Box::pin(established_with_store(Some(context), None, connection)).await
}

async fn established_with_store(
    context: Option<(&EmulationContext, &ConnectionSelection)>,
    store: Option<Arc<dyn TlsClientSessionStore>>,
    connection: ConnectionContext,
) -> Extensions {
    let auth = ServerAuthData::new_generated(GeneratedServerAuthConfig::GeneratedCa {
        ca: Default::default(),
        leaf: LeafCertRequest {
            config: Default::default(),
            identities: [CertificateIdentity::Dns("prepared.test".parse().unwrap())]
                .into_iter()
                .collect(),
        },
    })
    .unwrap();
    let config = TlsClientConfig::new()
        .try_with_server_trust_anchors([auth.cert_chain.last().unwrap().clone()])
        .unwrap();
    let server = TlsAcceptorData::try_from(
        &TlsServerConfig::new()
            .with_single_cert(auth)
            .with_alpn(vec![ApplicationProtocol::HTTP_2].into()),
    )
    .unwrap()
    .into_static_acceptor_builder()
    .unwrap()
    .build();
    let (client_io, server_io) = tokio::io::duplex(kib(32));
    let io = Arc::new(Mutex::new(Some(client_io)));
    let inner = service_fn(move |input: ConnectRequest| {
        assert!(
            !BoringTlsConnectorConfig::from_extensions(input.extensions()).is_empty(),
            "the UA adapter installs ordinary native settings before transport"
        );
        let io = io.lock().take().unwrap();
        async move {
            Ok::<_, ConnectionError>(EstablishedClientConnection {
                input,
                conn: ServiceInput::new(io),
            })
        }
    });
    let mut native = TlsConnector::auto(inner).with_base_config(config.clone());
    if let Some(store) = store {
        native.set_session_store(store);
    }
    let connector = ProfileEmulateHttpConnectModifier::new(native)
        .with_connection_compiler(ConnectionProfileCompiler::new(config));
    let request = input();
    request.extensions().insert(connection);
    let (default_context, default_selection) = selected("prepared-profile");
    // The wire offer: a matched ECH outer when the connection drew one, else its hello.
    let components = context
        .map(|(_, selection)| selection)
        .unwrap_or(&default_selection)
        .prepare_components()
        .unwrap();
    let expected = components.tls_outer.or(components.tls).unwrap();
    #[cfg(feature = "http")]
    let expected = {
        let mut expected = expected;
        for extension in &mut expected.extensions {
            if extension.id == u16::from(ExtensionId::APPLICATION_LAYER_PROTOCOL_NEGOTIATION) {
                extension.value = TlsCapturedExtensionValue::Protocols(Box::new([Box::from(
                    ApplicationProtocol::HTTP_2.as_bytes(),
                )]));
            }
        }
        expected
    };
    context
        .map(|(context, _)| context)
        .unwrap_or(&default_context)
        .clone()
        .publish(request.extensions());
    let client = async {
        let mut connection = connector.serve(request).await.unwrap();
        assert_eq!(
            connection
                .conn
                .extensions()
                .get_ref::<rama_net::client::ConnectionPolicyScope>(),
            Some(&rama_net::client::ConnectionPolicyScope::Connector),
            "authenticated compiled profiles retain the connector trust scope",
        );
        assert!(
            connection
                .conn
                .extensions()
                .get_ref::<TlsServerAuthentication>()
                .unwrap()
                .0
                .is_some()
        );
        assert_eq!(
            connection
                .conn
                .extensions()
                .get_ref::<NegotiatedTlsParameters>()
                .unwrap()
                .application_layer_protocol,
            Some(ApplicationProtocol::HTTP_2)
        );
        let mut message = [0; 6];
        connection.conn.read_exact(&mut message).await.unwrap();
        assert_eq!(&message, b"server");
        connection.conn.write_all(b"client").await.unwrap();
        connection.conn.extensions().clone()
    };
    let server = async {
        let (peek, hello) = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            rama_tls::server::peek_client_hello_from_input(ServiceInput::new(server_io)),
        )
        .await
        .unwrap()
        .unwrap();
        let hello = hello.unwrap();
        let actual = TlsCapture::capture(
            ProfileCaptureCompleteness::Complete,
            TlsCaptureTransport::Tcp,
            &hello,
            TlsCaptureLimits::default(),
        )
        .unwrap();
        assert_eq!(
            replay_form(&actual),
            replay_form(&expected),
            "the consuming connector must emit the admitted capture"
        );
        let mut stream = rama_boring_tokio::accept(&server, peek).await.unwrap();
        stream.write_all(b"server").await.unwrap();
        let mut message = [0; 6];
        stream.read_exact(&mut message).await.unwrap();
        assert_eq!(&message, b"client");
    };
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let (connection, ()) = tokio::join!(client, server);
        connection
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn transport_adapter_rejects_changed_context() {
    let inner = service_fn(|input: ConnectRequest| async move {
        let (mut context, _) = selected("prepared-profile");
        context.connection_key = rama_ua::profile::selection::DrawKey([88; 32]);
        context.publish(input.extensions());
        let (client, _server) = tokio::io::duplex(1024);
        Ok::<_, ConnectionError>(EstablishedClientConnection {
            input,
            conn: ServiceInput::new(client),
        })
    });
    let request = input();
    let (context, _) = selected("prepared-profile");
    context.publish(request.extensions());
    let error = ProfileEmulateHttpConnectModifier::new(inner)
        .with_connection_compiler(ConnectionProfileCompiler::new(TlsClientConfig::new()))
        .serve(request)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("context differs"), "{error}");
}

#[cfg(feature = "http")]
#[tokio::test]
async fn transport_adapter_rejects_changed_http_target() {
    let inner = service_fn(|input: ConnectRequest| async move {
        input
            .extensions()
            .insert(TargetHttpVersion(Version::HTTP_11));
        let (client, _server) = tokio::io::duplex(1024);
        Ok::<_, ConnectionError>(EstablishedClientConnection {
            input,
            conn: ServiceInput::new(client),
        })
    });
    let request = input();
    let (context, _) = selected("prepared-profile");
    context.publish(request.extensions());
    let error = ProfileEmulateHttpConnectModifier::new(inner)
        .with_connection_compiler(ConnectionProfileCompiler::new(TlsClientConfig::new()))
        .serve(request)
        .await
        .unwrap_err();
    assert!(
        error.to_string().contains("target HTTP version changed"),
        "{error}"
    );
}

#[cfg(feature = "http")]
#[tokio::test]
async fn plaintext_profiles_publish_selection_and_configure_the_http_connector() {
    for (target, fallback, request_version) in [
        (
            Some(Version::HTTP_2),
            Some(Version::HTTP_11),
            Version::HTTP_11,
        ),
        (None, Some(Version::HTTP_2), Version::HTTP_11),
        (None, None, Version::HTTP_2),
    ] {
        let request = ConnectRequest::new("prepared.test:80".parse().unwrap())
            .with_application_protocol(Protocol::HTTP);
        if let Some(version) = target {
            request.extensions().insert(TargetHttpVersion(version));
        }
        if let Some(version) = fallback {
            request.extensions().insert(FallbackHttpVersion(version));
        }
        request
            .extensions()
            .insert(HttpRequestVersion(request_version));
        let (context, selection) = super::fixture::selected_with_tls("plaintext-profile", false);
        context.clone().publish(request.extensions());
        let inner = service_fn(|input: ConnectRequest| async move {
            let (io, _peer) = tokio::io::duplex(1024);
            Ok::<_, ConnectionError>(EstablishedClientConnection {
                input,
                conn: ServiceInput::new(io),
            })
        });
        let connection = ProfileEmulateHttpConnectModifier::new(TlsConnector::auto(inner))
            .with_connection_compiler(ConnectionProfileCompiler::new(TlsClientConfig::new()))
            .serve(request)
            .await
            .unwrap();
        assert!(connection.conn.ssl_ref().is_none());
        let facts = connection.conn.extensions();
        assert_eq!(
            facts.get_ref::<ConnectionSelection>().unwrap().variant,
            selection.variant
        );
        let next = Extensions::new();
        context.publish(&next);
        let reuse = facts.get_ref::<ConnectionReuse>().unwrap();
        assert!(reuse.is_reusable() && reuse.matches(&next));
        assert!(
            !reuse.matches(&Extensions::new()),
            "plaintext profiles must remain isolated from ordinary traffic"
        );
    }
}

#[tokio::test]
async fn transport_cannot_change_connection_seed_before_native_output() {
    reject_changed_draw_input(Some(ProfileSeed([88; 32])), ConnectionContext::default()).await;
}

#[tokio::test]
async fn transport_cannot_change_connection_scope_before_native_output() {
    for connection in [
        ConnectionContext {
            resumption: ResumptionContext::Resumed,
            ..Default::default()
        },
        ConnectionContext {
            early_data: Some(true),
            ..Default::default()
        },
        ConnectionContext {
            token_present: Some(true),
            ..Default::default()
        },
        ConnectionContext {
            ip_family: Some(ConnectionIpFamily::V4),
            ..Default::default()
        },
    ] {
        reject_changed_draw_input(None, connection).await;
    }
}

async fn reject_changed_draw_input(seed: Option<ProfileSeed>, connection: ConnectionContext) {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let request = input();
        let (context, _) = selected("draw-input-binding");
        context.clone().publish(request.extensions());
        let (client, mut peer) = tokio::io::duplex(32768);
        let client = Arc::new(Mutex::new(Some(client)));
        let inner = service_fn(move |input: ConnectRequest| {
            let io = client.lock().take().unwrap();
            if let Some(seed) = seed {
                let mut changed = context.clone();
                changed.seed = seed;
                changed.publish(input.extensions());
            } else {
                input.extensions().insert(connection.clone());
            }
            async move {
                Ok::<_, ConnectionError>(EstablishedClientConnection {
                    input,
                    conn: ServiceInput::new(io),
                })
            }
        });
        let attempt = ProfileEmulateHttpConnectModifier::new(inner)
            .with_connection_compiler(ConnectionProfileCompiler::new(TlsClientConfig::new()));
        let peer = async move {
            let mut first = [0u8];
            assert_eq!(
                peer.read(&mut first).await.unwrap(),
                0,
                "native TLS bytes escaped after the connection draw inputs changed"
            );
        };
        let (result, ()) = tokio::join!(attempt.serve(request), peer);
        let error = result.unwrap_err();
        assert!(error.to_string().contains("context differs"), "{error}");
    })
    .await
    .unwrap();
}

#[test]
fn sni_presence_follows_policy_and_the_canonical_server_identity() {
    let compiler = ConnectionProfileCompiler::new(TlsClientConfig::new());
    for host in [
        Host::Address("192.0.2.1".parse().unwrap()),
        Host::Name(Domain::try_from("192.0.2.1").unwrap()),
        Host::from_static("prepared.test"),
    ] {
        for policy in [
            TlsClientSni::Auto,
            TlsClientSni::IncludeIp,
            TlsClientSni::Disabled,
        ] {
            let request = input();
            request
                .extensions()
                .insert(ServerName::try_from(&host).unwrap());
            request.extensions().insert(policy);
            let (compiled, report) = prepare(&compiler, &request, &capture()).unwrap();
            InstalledConnectionProfile::<ConnectRequest>::apply(compiled, request.extensions());
            assert_eq!(
                request.extensions().get_ref::<TlsClientSni>(),
                Some(&policy)
            );
            let sends = policy.sends(&ServerName::try_from(&host).unwrap());
            assert_eq!(
                lowered(&report).contains(&LoweredProfileItem::TlsServerNamePresence),
                !sends,
                "{host}: {policy:?}: {report:?}"
            );
        }
    }
}

#[tokio::test]
async fn final_profile_ech_intent_is_enforced_after_transport_discovery() {
    let calls = Arc::new(AtomicUsize::new(0));
    let peer = Arc::new(Mutex::new(None));
    let inner = service_fn({
        let calls = calls.clone();
        let peer = peer.clone();
        move |input: ConnectRequest| {
            calls.fetch_add(1, Ordering::Relaxed);
            let peer = peer.clone();
            async move {
                let (io, remote) = duplex(64);
                *peer.lock() = Some(tokio::spawn(async move {
                    let mut remote = remote;
                    let mut byte = [0];
                    remote.read(&mut byte).await.unwrap()
                }));
                Ok::<_, ConnectionError>(EstablishedClientConnection {
                    input,
                    conn: ServiceInput::new(io),
                })
            }
        }
    });
    let request = input();
    request.extensions().insert(TargetEchServiceBinding {
        target: request.authority.clone(),
        reliant: true,
        mandatory: false,
    });
    assert!(
        request
            .extensions()
            .get_ref::<TlsEncryptedClientHello>()
            .is_none()
    );
    let (context, _) = selected("ech-reliant-profile");
    context.publish(request.extensions());
    let error = ProfileEmulateHttpConnectModifier::new(TlsConnector::secure(inner))
        .with_connection_compiler(ConnectionProfileCompiler::new(TlsClientConfig::new()))
        .serve(request)
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ConnectionErrorKind::InvalidInput);
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    assert!(format!("{error:?}").contains("required ECH"), "{error:?}");
    let remote = peer.lock().take().unwrap();
    assert_eq!(remote.await.unwrap(), 0);
}

#[tokio::test]
async fn profile_replay_to_an_ip_preserves_explicit_and_captured_sni_policy() {
    timeout(Duration::from_secs(10), async {
        for ip in ["192.0.2.1".parse().unwrap(), "2001:db8::1".parse().unwrap()] {
            for captured_ip in [false, true] {
                for policy in [
                    None,
                    Some(TlsClientSni::Auto),
                    Some(TlsClientSni::IncludeIp),
                    Some(TlsClientSni::Disabled),
                ] {
                    let auth =
                        ServerAuthData::new_generated(GeneratedServerAuthConfig::GeneratedCa {
                            ca: Default::default(),
                            leaf: LeafCertRequest {
                                config: Default::default(),
                                identities: vec![CertificateIdentity::Ip(ip)],
                            },
                        })
                        .unwrap();
                    let config = TlsClientConfig::new()
                        .try_with_server_trust_anchors([auth.cert_chain.last().unwrap().clone()])
                        .unwrap();
                    let server = TlsAcceptorData::try_from(
                        &TlsServerConfig::new()
                            .with_single_cert(auth)
                            .with_alpn(vec![ApplicationProtocol::HTTP_2].into()),
                    )
                    .unwrap()
                    .into_static_acceptor_builder()
                    .unwrap()
                    .build();
                    let (client_io, server_io) = duplex(kib(32));
                    let io = Arc::new(Mutex::new(Some(client_io)));
                    let inner = service_fn(move |input: ConnectRequest| {
                        let io = io.lock().take().unwrap();
                        async move {
                            Ok::<_, ConnectionError>(EstablishedClientConnection {
                                input,
                                conn: ServiceInput::new(io),
                            })
                        }
                    });
                    let request = input();
                    request.extensions().insert(ServerName::from(ip));
                    if let Some(policy) = policy {
                        request.extensions().insert(policy);
                    }
                    let mut captured = capture();
                    captured.extensions = captured
                        .extensions
                        .into_vec()
                        .into_iter()
                        .filter_map(|mut extension| {
                            if matches!(
                                extension.value,
                                TlsCapturedExtensionValue::ServerName { .. }
                            ) {
                                if !captured_ip {
                                    return None;
                                }
                                extension.value = TlsCapturedExtensionValue::IpServerName;
                            }
                            Some(extension)
                        })
                        .collect();
                    let sends_ip = match policy {
                        None => captured_ip,
                        Some(TlsClientSni::IncludeIp) => true,
                        _ => false,
                    };
                    let compiler = ConnectionProfileCompiler::new(config.clone());
                    let (compiled, report) = prepare(&compiler, &request, &captured).unwrap();
                    assert_eq!(
                        lowered(&report).contains(&LoweredProfileItem::TlsServerNamePresence),
                        captured_ip != sends_ip
                    );
                    InstalledConnectionProfile::<ConnectRequest>::apply(
                        compiled,
                        request.extensions(),
                    );
                    let connector = TlsConnector::auto(inner).with_base_config(config);
                    let client = async { connector.serve(request).await.unwrap() };
                    let peer = async {
                        let (io, hello) =
                            peek_client_hello_from_input(ServiceInput::new(server_io))
                                .await
                                .unwrap();
                        let name = hello.unwrap().ext_server_name().cloned();
                        let expected = sends_ip.then_some(ServerName::from(ip));
                        assert_eq!(name, expected);
                        rama_boring_tokio::accept(&server, io).await.unwrap()
                    };
                    let (_client, _server) = tokio::join!(client, peer);
                }
            }
        }
    })
    .await
    .unwrap();
}

#[test]
fn paired_replay_uses_the_effective_inner_sni_policy() {
    let outer = capture();
    let mut inner = outer.clone();
    for extension in &mut inner.extensions {
        match extension.value {
            TlsCapturedExtensionValue::ServerName { .. } => {
                extension.value = TlsCapturedExtensionValue::IpServerName
            }
            TlsCapturedExtensionValue::EchOuter { .. } => {
                extension.value = TlsCapturedExtensionValue::EchInner
            }
            _ => {}
        }
    }
    let (_, mut selection) = selected("paired-sni-policy");
    selection.ech_ready = true;
    let mut components = selection.prepare_components().unwrap();
    components.tls = Some(inner);
    components.tls_outer = Some(outer);
    let input = input();
    input
        .extensions()
        .insert("192.0.2.1".parse::<ServerName>().unwrap());
    let compiler = ConnectionProfileCompiler::new(TlsClientConfig::new());
    let compiled =
        rama_ua::profile::replay::connection::compiler::ConnectionProfileCompiler::compile(
            &compiler,
            &input,
            &selection,
            &mut components,
        )
        .unwrap();
    InstalledConnectionProfile::<ConnectRequest>::apply(compiled, input.extensions());
    assert_eq!(
        input.extensions().get_ref::<TlsClientSni>(),
        Some(&TlsClientSni::IncludeIp)
    );
}

#[test]
fn unchanged_ech_and_caller_settings_reuse_the_admitted_tcp_recipe() {
    let request = input();
    let (context, _) = selected("unchanged-profile");
    context.publish(request.extensions());
    let compiler = ConnectionProfileCompiler::new(TlsClientConfig::new());
    let (_, compiled) = ConnectionPreparation::prepare(&request, |selection, components| {
        compiler.compile(&request, selection, components)
    })
    .unwrap()
    .unwrap();
    <CompiledConnection as InstalledConnectionProfile<ConnectRequest>>::apply(
        compiled,
        request.extensions(),
    );
    let installed = request.extensions().get_arc::<TlsClientSni>().unwrap();
    let effective = request.extensions().fork();
    TlsProfilePreparation::apply(
        &TargetEchResolution {
            config: None,
            required: false,
        },
        &effective,
        request.extensions(),
    )
    .unwrap();
    assert!(Arc::ptr_eq(
        &installed,
        &request.extensions().get_arc::<TlsClientSni>().unwrap()
    ));
}

#[tokio::test]
async fn final_profile_preservation_differences_are_published_once() {
    let mut captured = capture();
    let mut ciphers = captured.ciphers.into_vec();
    ciphers.push(0xffff);
    captured.ciphers = ciphers.into();
    let (context, selection) = selected_connections(
        "reported-profile",
        true,
        vec![(
            ConnectionContext::default(),
            vec![CapturedSlot {
                kind: CapturedSlotKind::TcpTls,
                value: captured.canonical(TlsCaptureLimits::default()).unwrap(),
            }],
        )],
        &ConnectionContext::default(),
    );
    let connection = Box::pin(established(Some((&context, &selection)))).await;
    let report = connection.get_ref::<ProfilePreservationReport>().unwrap();
    assert!(!report.is_exact());
    for (index, difference) in report.differences.iter().enumerate() {
        assert!(
            !report.differences[..index].contains(difference),
            "{report:?}"
        );
    }
}
