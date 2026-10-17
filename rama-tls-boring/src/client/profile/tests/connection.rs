use super::fixture::selected;
use super::*;
use crate::server::TlsAcceptorData;
use rama_core::{Service, ServiceInput, service::service_fn};
#[cfg(feature = "http")]
use rama_net::{
    client::pool::ConnectionReuse,
    http::{FallbackHttpVersion, HttpRequestVersion},
};
use rama_net::{
    client::{ConnectionError, ConnectionErrorKind, EstablishedClientConnection},
    tls::ApplicationProtocol,
};
use rama_tls::{
    client::{NegotiatedTlsParameters, ServerVerifyMode, TlsServerAuthentication},
    server::{
        CertificateIdentity, GeneratedServerAuthConfig, LeafCertRequest, ServerAuthData,
        TlsServerConfig,
    },
};
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

#[tokio::test]
async fn incompatible_caller_policy_rejects_before_dial() {
    let calls = Arc::new(AtomicUsize::new(0));
    let counted = calls.clone();
    let inner = service_fn(move |_input: ConnectRequest| {
        counted.fetch_add(1, Ordering::Relaxed);
        async {
            Err::<
                EstablishedClientConnection<ServiceInput<tokio::io::DuplexStream>, ConnectRequest>,
                _,
            >(ConnectionError::local(
                BoxError::from_static_str("unexpected dial"),
                ConnectionErrorKind::Internal,
            ))
        }
    });
    let connector = TlsConnector::auto(inner);
    let request = input();
    let (context, _) = selected("prepared-profile");
    context.publish(request.extensions());
    TlsClientConfig::new()
        .with_max_version(rama_tls::ProtocolVersion::TLSv1_2)
        .write_to(request.extensions());
    let error = connector.serve(request).await.unwrap_err();
    assert!(!error.to_string().contains("unexpected dial"), "{error}");
    assert_eq!(calls.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn changed_policy_after_transport_rejects_before_handshake() {
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
    let connector = TlsConnector::secure(inner);
    let request = input();
    let (context, _) = selected("prepared-profile");
    context.publish(request.extensions());
    let error = connector.serve(request).await.unwrap_err();
    assert!(error.to_string().contains("policy changed"), "{error}");
}

#[tokio::test]
async fn transport_cannot_change_or_remove_the_prepared_destination_or_protocol() {
    for secure in [false, true] {
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
            let auto = TlsConnector::auto(inner.clone());
            let forced = TlsConnector::secure(inner);
            let request = input();
            let (context, _) = selected("prepared-profile");
            context.publish(request.extensions());
            let result = if secure {
                forced.serve(request).await.map(|_| ())
            } else {
                auto.serve(request).await.map(|_| ())
            };
            let error = result.unwrap_err();
            assert!(error.to_string().contains("policy changed"), "{error}");
        }
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

#[tokio::test]
async fn connector_consumes_the_prepared_native_session_with_trust_and_alpn() {
    let connection = established(None).await;
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
    context: Option<(
        &rama_ua::profile::selection::variants::EmulationContext,
        &ConnectionSelection,
    )>,
) -> rama_core::extensions::Extensions {
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
    let (client_io, server_io) = tokio::io::duplex(32 * 1024);
    let io = Arc::new(Mutex::new(Some(client_io)));
    let inner = service_fn(move |input: ConnectRequest| {
        assert!(
            BoringTlsConnectorConfig::from_extensions(input.extensions()).is_empty(),
            "captured native wire overrides must not leak into caller TLS policy"
        );
        let io = io.lock().take().unwrap();
        async move {
            Ok::<_, ConnectionError>(EstablishedClientConnection {
                input,
                conn: ServiceInput::new(io),
            })
        }
    });
    let connector = TlsConnector::auto(inner).with_base_config(config);
    let request = input();
    let (default_context, default_selection) = selected("prepared-profile");
    let expected = context
        .map(|(_, selection)| selection)
        .unwrap_or(&default_selection)
        .prepare_components()
        .unwrap()
        .tls
        .unwrap();
    context
        .map(|(context, _)| context)
        .unwrap_or(&default_context)
        .clone()
        .publish(request.extensions());
    let client = async {
        let mut connection = connector.serve(request).await.unwrap();
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
        let (peek, hello) = rama_tls::server::peek_client_hello_from_input(
            ServiceInput::new(server_io),
            Some(std::time::Duration::from_secs(5)),
        )
        .await
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
            actual.canonical(TlsCaptureLimits::default()).unwrap().bytes,
            expected
                .canonical(TlsCaptureLimits::default())
                .unwrap()
                .bytes,
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
async fn changed_context_after_transport_rejects_before_handshake() {
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
    let error = TlsConnector::secure(inner)
        .serve(request)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("context differs"), "{error}");
}

#[cfg(feature = "http")]
#[tokio::test]
async fn changed_http_target_after_transport_rejects_before_handshake() {
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
    let error = TlsConnector::secure(inner)
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
async fn plaintext_profiles_publish_selection_and_preserve_http_version_precedence() {
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
        let connection = TlsConnector::auto(inner).serve(request).await.unwrap();
        assert!(connection.conn.ssl_ref().is_none());
        let facts = connection.conn.extensions();
        assert_eq!(
            facts.get_ref::<TargetHttpVersion>().unwrap().0,
            Version::HTTP_2
        );
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

#[cfg(feature = "http")]
#[tokio::test]
async fn plaintext_legacy_profiles_are_applied_before_http_output() {
    for version in [Version::HTTP_11, Version::HTTP_2] {
        let request = ConnectRequest::new("prepared.test:80".parse().unwrap())
            .with_application_protocol(Protocol::HTTP);
        request.extensions().insert(HttpRequestVersion(version));
        request
            .extensions()
            .insert(HttpProfile { h1: None, h2: None });
        let inner = service_fn(|input: ConnectRequest| async move {
            let (io, _peer) = tokio::io::duplex(1024);
            Ok::<_, ConnectionError>(EstablishedClientConnection {
                input,
                conn: ServiceInput::new(io),
            })
        });
        let error = TlsConnector::auto(inner).serve(request).await.unwrap_err();
        assert!(error.to_string().contains("missing HTTP/"), "{error}");
    }
}

#[cfg(not(feature = "http"))]
#[tokio::test]
async fn a_plain_profile_without_http_cannot_publish_an_unrestricted_socket() {
    let request = ConnectRequest::new("prepared.test:80".parse().unwrap())
        .with_application_protocol(Protocol::HTTP);
    let (context, _) = super::fixture::selected_with_tls("plaintext-profile", false);
    context.publish(request.extensions());
    let inner = service_fn(|input: ConnectRequest| async move {
        let (io, _peer) = tokio::io::duplex(1024);
        Ok::<_, ConnectionError>(EstablishedClientConnection {
            input,
            conn: ServiceInput::new(io),
        })
    });
    let error = TlsConnector::auto(inner).serve(request).await.unwrap_err();
    assert!(
        error.to_string().contains("requires an HTTP version"),
        "{error}"
    );
}
