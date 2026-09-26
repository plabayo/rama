use super::{AutoTlsStream, RustlsTlsStream, TlsConnectorData, TlsStream};
use crate::client::config::{RustlsTlsClientConfigProvider, RustlsTlsConnectorConfig};
use crate::dep::tokio_rustls::TlsConnector as RustlsConnector;
use rama_core::conversion::{RamaInto, RamaTryFrom};
use rama_core::error::{BoxError, ErrorContext};
use rama_core::extensions::{Extensions, ExtensionsRef};
use rama_core::io::Io;
use rama_net::address::Host;
use rama_net::tls::ApplicationProtocol;
use rama_tls::client::NegotiatedTlsParameters;
use rama_tls::client::connector::{self, TlsConnectorBackend};

pub use connector::{ConnectorKindAuto, ConnectorKindSecure, ConnectorKindTunnel};

/// A [`Layer`] which wraps the given service with a rustls [`TlsConnector`].
///
/// See [`connector::TlsConnectorLayer`] for more information.
///
/// [`Layer`]: rama_core::Layer
pub type TlsConnectorLayer<K = ConnectorKindAuto> =
    connector::TlsConnectorLayer<RustlsTlsConnectorBackend, K>;

/// A connector which secures connections using rustls.
///
/// See [`connector::TlsConnector`] for more information.
pub type TlsConnector<S, K = ConnectorKindAuto> =
    connector::TlsConnector<S, RustlsTlsConnectorBackend, K>;

/// [`TlsConnectorBackend`] which establishes TLS sessions using rustls.
#[derive(Debug, Clone, Copy, Default)]
pub struct RustlsTlsConnectorBackend;

impl TlsConnectorBackend for RustlsTlsConnectorBackend {
    const NAME: &'static str = "rama-tls-rustls::TlsConnector";

    type Provider = RustlsTlsClientConfigProvider;
    type Data = TlsConnectorData;
    type Stream<IO: Io + Unpin + ExtensionsRef> = TlsStream<IO>;
    type AutoStream<IO: Io + Unpin + ExtensionsRef> = AutoTlsStream<IO>;

    fn has_overrides(extensions: &Extensions) -> bool {
        RustlsTlsConnectorConfig::from_extensions(extensions).has_overrides()
    }

    fn connector_data(ext: &Extensions, fallback: Option<&Host>) -> Result<Self::Data, BoxError> {
        let mut data = TlsConnectorData::try_from(RustlsTlsConnectorConfig::from_extensions(ext))?;
        data.server_name = data.server_name.or_else(|| fallback.cloned());
        Ok(data)
    }

    fn server_name(data: &Self::Data) -> Option<&Host> {
        data.server_name.as_ref()
    }

    fn verifies_server(data: &Self::Data) -> bool {
        data.verification_enabled
    }

    async fn handshake<IO>(
        data: Self::Data,
        io: IO,
    ) -> Result<(Self::Stream<IO>, NegotiatedTlsParameters), BoxError>
    where
        IO: Io + Unpin + ExtensionsRef,
    {
        let (stream, params) = handshake(data, io).await?;
        Ok((TlsStream::new(stream), params))
    }

    fn auto_secure<IO: Io + Unpin + ExtensionsRef>(tls: Self::Stream<IO>) -> Self::AutoStream<IO> {
        AutoTlsStream::secure(tls.into())
    }

    fn auto_plain<IO: Io + Unpin + ExtensionsRef>(io: IO) -> Self::AutoStream<IO> {
        AutoTlsStream::plain(io)
    }
}

async fn handshake<T>(
    data: TlsConnectorData,
    stream: T,
) -> Result<(RustlsTlsStream<T>, NegotiatedTlsParameters), BoxError>
where
    T: Io + ExtensionsRef + Unpin,
{
    let server_host = data
        .server_name
        .clone()
        .context("server identity missing")?;
    #[cfg(feature = "dial9")]
    let dial9_server_name = server_host.clone();

    let authenticated_identity = data.verification_enabled.then(|| server_host.clone());
    let server_name = rama_crypto::pki_types::ServerName::rama_try_from(server_host)?;

    let connector = RustlsConnector::from(data.client_config);
    #[cfg(feature = "dial9")]
    crate::dial9::record_handshake_started(dial9_server_name.clone());

    let stream = match connector.connect(server_name, stream).await {
        Ok(stream) => stream,
        Err(err) => {
            #[cfg(feature = "dial9")]
            crate::dial9::record_handshake_failed(dial9_server_name.clone(), &err);
            return Err(err.into());
        }
    };

    stream
        .get_ref()
        .0
        .extensions()
        .insert(rama_tls::client::TlsServerAuthentication(
            authenticated_identity,
        ));
    let (_, conn_data_ref) = stream.get_ref();

    let server_certificate_chain = if data.store_server_certificate_chain {
        conn_data_ref.peer_certificates().map(RamaInto::rama_into)
    } else {
        None
    };

    let params = NegotiatedTlsParameters {
        protocol_version: conn_data_ref
            .protocol_version()
            .context("no protocol version available")?
            .rama_into(),
        application_layer_protocol: conn_data_ref.alpn_protocol().map(ApplicationProtocol::from),
        peer_certificate_chain: server_certificate_chain,
        server_name: None,
        resumed: conn_data_ref
            .handshake_kind()
            .map(|kind| kind == crate::dep::rustls::HandshakeKind::Resumed),
    };

    #[cfg(feature = "dial9")]
    {
        let depth = params
            .peer_certificate_chain
            .as_ref()
            .map_or(0, |chain| chain.len());
        crate::dial9::record_handshake_completed(
            dial9_server_name,
            params.protocol_version,
            conn_data_ref.alpn_protocol().map(ApplicationProtocol::from),
            depth,
        );
    }

    Ok((stream, params))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::TlsTunnel;
    use rama_core::{Layer, Service};
    use rama_net::client::pool::ConnectionReuse;

    use rama_core::{ServiceInput, service::service_fn};
    #[cfg(feature = "http")]
    use rama_net::http::{TargetHttpVersion, Version};
    use rama_net::{
        Protocol,
        address::HostWithPort,
        client::{
            ConnectRequest, ConnectionAttempt, ConnectionError, ConnectionPolicyScope,
            EstablishedClientConnection,
        },
    };
    use rama_tls::client::{ServerVerifyMode, TlsClientConfig, TlsServerName, TlsServerVerify};

    use rama_crypto::cert::generate_server_auth;
    use rama_net::stream::service::EchoService;
    use rama_tls::server::{GeneratedServerAuthConfig, ServerAuthData, TlsServerConfig};
    use std::{sync::Arc, time::Duration};

    #[tokio::test]
    async fn successful_origin_handshake_reports_effective_policy_scope() {
        let (cert_chain, private_key) =
            generate_server_auth(GeneratedServerAuthConfig::default()).expect("server auth");
        let trust_anchor = cert_chain.last().expect("trust anchor").clone();
        let server = Arc::new(
            crate::server::TlsAcceptorLayer::new(TlsServerConfig::new().with_single_cert(
                ServerAuthData {
                    cert_chain,
                    private_key,
                    ocsp: None,
                },
            ))
            .into_layer(EchoService::new()),
        );
        let base = TlsClientConfig::new()
            .with_server_name(Host::from_static("localhost"))
            .try_with_server_trust_anchors([trust_anchor])
            .expect("trust anchor");

        for request_override in [false, true] {
            let (client_io, server_io) = tokio::io::duplex(64);
            let server = server.clone();
            let server_task =
                tokio::spawn(async move { server.serve(ServiceInput::new(server_io)).await });
            let client_io = Arc::new(tokio::sync::Mutex::new(Some(client_io)));
            let transport = service_fn(move |input: ConnectRequest| {
                let client_io = client_io.clone();
                async move {
                    let conn = ServiceInput::new(client_io.lock().await.take().expect("one dial"));
                    Ok::<_, ConnectionError>(EstablishedClientConnection { input, conn })
                }
            });
            let connector = TlsConnector::secure(transport).with_base_config(base.clone());
            let input = ConnectRequest::new(HostWithPort::new(Host::from_static("localhost"), 443));
            if request_override {
                input
                    .extensions()
                    .insert(TlsServerVerify(ServerVerifyMode::Auto));
                input.extensions().insert(
                    ConnectionAttempt::new()
                        .with_authenticated_peer(Host::from_static("localhost")),
                );
            }
            let established = tokio::time::timeout(Duration::from_secs(5), connector.serve(input))
                .await
                .expect("handshake timeout")
                .expect("origin handshake");
            assert_eq!(
                established
                    .conn
                    .extensions()
                    .get_ref::<ConnectionPolicyScope>()
                    .copied(),
                Some(if request_override {
                    ConnectionPolicyScope::Request
                } else {
                    ConnectionPolicyScope::Connector
                }),
            );
            let reuse = established
                .conn
                .extensions()
                .get_ref::<ConnectionReuse>()
                .expect("native TLS connector publishes reuse policy");
            let same = Extensions::new();
            if request_override {
                same.insert(TlsServerVerify(ServerVerifyMode::Auto));
            }
            assert!(reuse.is_reusable());
            assert!(reuse.matches(&same));
            let changed = same.fork();
            changed.insert(TlsServerVerify(ServerVerifyMode::Disable));
            assert!(!reuse.matches(&changed));
            drop(established);
            let _server_result = tokio::time::timeout(Duration::from_secs(5), server_task)
                .await
                .expect("server shutdown")
                .expect("server task");
        }
    }

    #[tokio::test]
    async fn tunnel_handshake_uses_proxy_base_and_keeps_version_scoped() {
        use rama_core::{ServiceInput, service::service_fn};
        use rama_crypto::{cert::generate_server_auth, pki_types::CertificateDer};
        use rama_net::{client::EstablishedClientConnection, stream::service::EchoService};
        use rama_tls::{
            ProtocolVersion,
            client::{ServerVerifyMode, TlsServerCertPins},
            server::{GeneratedServerAuthConfig, ServerAuthData, TlsServerConfig},
        };
        use std::sync::Arc;

        let (cert_chain, private_key) =
            generate_server_auth(GeneratedServerAuthConfig::default()).expect("server auth");
        let trust_anchor = cert_chain.last().expect("trust anchor").clone();
        let server_pin = cert_chain.first().expect("leaf certificate").clone();
        let server = crate::server::TlsAcceptorLayer::new(
            TlsServerConfig::new()
                .with_single_cert(ServerAuthData {
                    cert_chain,
                    private_key,
                    ocsp: None,
                })
                .with_alpn_http_2(),
        )
        .into_layer(EchoService::new());

        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server_task =
            tokio::spawn(async move { server.serve(ServiceInput::new(server_io)).await });
        let client_io = Arc::new(tokio::sync::Mutex::new(Some(client_io)));
        let transport = service_fn(move |input: ServiceInput<()>| {
            let client_io = client_io.clone();
            async move {
                let conn =
                    ServiceInput::new(client_io.lock().await.take().expect("one connection"));
                Ok::<_, ConnectionError>(EstablishedClientConnection { input, conn })
            }
        });
        let proxy_base = TlsClientConfig::new()
            .with_alpn_http_2()
            .with_server_name(Host::from_static("localhost"))
            .with_server_cert_pins(TlsServerCertPins::new(server_pin))
            .with_server_verify(ServerVerifyMode::Auto)
            .try_with_server_trust_anchors([trust_anchor])
            .expect("proxy trust")
            .with_supported_versions(vec![ProtocolVersion::TLSv1_3]);
        let connector = TlsConnector::tunnel(transport, None).with_base_config(proxy_base);

        let input = ServiceInput::new(());
        input.extensions().insert(
            ConnectionAttempt::new().with_authenticated_peer(Host::from_static("origin.example")),
        );
        TlsClientConfig::new()
            .with_alpn_http_1()
            .with_server_name(Host::from_static("origin.example"))
            .with_server_verify(ServerVerifyMode::Disable)
            .with_server_cert_pins(TlsServerCertPins::new(CertificateDer::from(vec![9])))
            .write_to(input.extensions());
        #[cfg(feature = "http")]
        input
            .extensions()
            .insert(TargetHttpVersion(Version::HTTP_11));
        input.extensions().insert(TlsTunnel {
            server_identity: Some(Host::from_static("proxy-route.example")),
            application_protocol: Some(Protocol::HTTPS),
            alpn: None,
        });

        let established = connector.serve(input).await.expect("proxy TLS handshake");
        let reuse = established
            .conn
            .extensions()
            .get_ref::<ConnectionReuse>()
            .expect("proxy TLS connector publishes reuse policy");
        let next_origin = Extensions::new();
        next_origin.insert(TlsServerName(Host::from_static("another-origin.example")));
        next_origin.insert(TlsServerVerify(ServerVerifyMode::Disable));
        assert!(reuse.is_reusable());
        assert!(!reuse.matches(&next_origin));
        next_origin.insert(
            established
                .input
                .extensions()
                .get_ref::<TlsTunnel>()
                .unwrap()
                .clone(),
        );
        assert!(reuse.matches(&next_origin));
        next_origin.insert(TlsTunnel {
            server_identity: None,
            application_protocol: None,
            alpn: None,
        });
        assert!(!reuse.matches(&next_origin));
        assert_eq!(
            established
                .input
                .extensions()
                .get_ref::<ConnectionAttempt>()
                .unwrap()
                .policy_scope(),
            ConnectionPolicyScope::Unknown,
        );
        assert!(
            !established
                .conn
                .extensions()
                .contains::<ConnectionPolicyScope>()
        );
        let negotiated = established
            .conn
            .extensions()
            .get_ref::<NegotiatedTlsParameters>()
            .expect("proxy TLS parameters");
        assert_eq!(negotiated.resumed, Some(false));
        assert_eq!(negotiated.server_name, None);
        assert_eq!(
            negotiated.application_layer_protocol,
            Some(ApplicationProtocol::HTTP_2)
        );
        #[cfg(feature = "http")]
        assert!(
            established
                .conn
                .extensions()
                .get_ref::<TargetHttpVersion>()
                .is_none()
        );
        drop(established);
        // The client is dropped immediately after the handshake assertions,
        // so the TLS server may finish with an EOF/close-notify error.
        let _server_result = tokio::time::timeout(std::time::Duration::from_secs(5), server_task)
            .await
            .expect("server shutdown")
            .expect("server task");
    }

    #[test]
    fn assert_send() {
        use rama_utils::test_helpers::assert_send;

        assert_send::<TlsConnectorLayer>();
    }

    #[test]
    fn assert_sync() {
        use rama_utils::test_helpers::assert_sync;

        assert_sync::<TlsConnectorLayer>();
    }

    #[test]
    fn connector_data_keeps_transport_host_as_server_identity() {
        let host = Host::from(std::net::Ipv4Addr::LOCALHOST);

        let data = RustlsTlsConnectorBackend::connector_data(&Extensions::new(), Some(&host))
            .expect("connector data");
        assert_eq!(data.server_name, Some(host));

        let configured = Host::from_static("configured.example");
        let effective = Extensions::new();
        effective.insert(TlsServerName(configured.clone()));
        let data = RustlsTlsConnectorBackend::connector_data(
            &effective,
            Some(&Host::from_static("transport.example")),
        )
        .expect("connector data");
        assert_eq!(data.server_name, Some(configured));
    }

    #[tokio::test]
    async fn handshake_rejects_missing_server_identity() {
        let effective = Extensions::new();
        effective.insert(TlsServerVerify(ServerVerifyMode::Disable));
        let data =
            RustlsTlsConnectorBackend::connector_data(&effective, None).expect("connector data");
        let (stream, _) = tokio::io::duplex(64);
        let error = handshake(data, ServiceInput::new(stream))
            .await
            .expect_err("missing identity");
        assert!(error.to_string().contains("server identity missing"));
    }
}
