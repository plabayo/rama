use rama_boring::ssl::{ConnectConfiguration, SslAlert, SslVerifyError, SslVerifyMode};
use rama_boring_tokio::{HandshakeError, SslStream};
use rama_core::conversion::RamaTryInto;
use rama_core::error::BoxErrorExt as _;
use rama_core::error::{BoxError, ErrorContext, ErrorExt};
use rama_core::extensions::{Extensions, ExtensionsRef};
use rama_core::io::Io;
use rama_core::telemetry::tracing;
use rama_crypto::pki_types::CertificateDer;
use rama_net::address::Host;
use rama_net::tls::{ApplicationProtocol, TlsAlpn};
use rama_tls::client::connector::{self, TlsConnectorBackend};

pub use connector::{ConnectorKindAuto, ConnectorKindSecure, ConnectorKindTunnel};
use rama_tls::client::{
    NegotiatedTlsParameters, ServerVerifyMode, TlsClientConfig, TlsServerCertPinCheck,
    TlsServerCertPins, TlsServerIdentity,
};
use std::fmt;

use super::{
    AutoTlsStream, BoringTlsClientConfigProvider, BoringTlsConnectorConfig, TlsConnectorData,
    set_alpn_list_with_coupled_alps,
};

use crate::TlsStream;

/// A [`Layer`] which wraps the given service with a BoringSSL [`TlsConnector`].
///
/// See [`connector::TlsConnectorLayer`] for more information.
///
/// [`Layer`]: rama_core::Layer
pub type TlsConnectorLayer<K = ConnectorKindAuto> =
    connector::TlsConnectorLayer<BoringTlsConnectorBackend, K>;

/// A connector which secures connections using BoringSSL.
///
/// See [`connector::TlsConnector`] for more information.
pub type TlsConnector<S, K = ConnectorKindAuto> =
    connector::TlsConnector<S, BoringTlsConnectorBackend, K>;

/// [`TlsConnectorBackend`] which establishes TLS sessions using BoringSSL.
#[derive(Debug, Clone, Copy, Default)]
pub struct BoringTlsConnectorBackend;

impl TlsConnectorBackend for BoringTlsConnectorBackend {
    const NAME: &'static str = "rama-tls-boring::TlsConnector";

    type Provider = BoringTlsClientConfigProvider;
    type Data = TlsConnectorData;
    type Stream<IO: Io + Unpin + ExtensionsRef> = TlsStream<IO>;
    type AutoStream<IO: Io + Unpin + ExtensionsRef> = AutoTlsStream<IO>;

    fn has_overrides(extensions: &Extensions) -> bool {
        BoringTlsConnectorConfig::from_extensions(extensions).has_overrides()
    }

    fn connector_data(ext: &Extensions, fallback: Option<&Host>) -> Result<Self::Data, BoxError> {
        let mut data = TlsConnectorData::try_from(BoringTlsConnectorConfig::from_extensions(ext))?;
        data.server_name = data.server_name.or_else(|| fallback.cloned());
        Ok(data)
    }

    fn server_name(data: &Self::Data) -> Option<&Host> {
        data.server_name.as_ref()
    }

    fn verifies_server(data: &Self::Data) -> bool {
        data.server_verify_mode != ServerVerifyMode::Disable
    }

    fn set_alpn(extensions: &Extensions, alpn: TlsAlpn) {
        let coupling = set_alpn_list_with_coupled_alps(extensions, alpn);
        tracing::trace!(?coupling, "coupled ALPS to TLS ALPN");
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
        AutoTlsStream::secure(tls.inner)
    }

    fn auto_plain<IO: Io + Unpin + ExtensionsRef>(io: IO) -> Self::AutoStream<IO> {
        AutoTlsStream::plain(io)
    }
}

pub(super) fn server_identity_for(host: &Host) -> Result<String, BoxError> {
    match TlsServerIdentity::try_from(host)
        .context("server identity is not a DNS name or IP address")?
    {
        TlsServerIdentity::Dns(domain) => Ok(domain.as_str().to_owned()),
        TlsServerIdentity::Ip(ip) => Ok(ip.to_string()),
    }
}

#[derive(Debug)]
pub enum TlsConnectError<S> {
    Builder(BoxError),
    Handshake {
        server_name: Option<Host>,
        error: HandshakeError<S>,
    },
}

impl<S> fmt::Display for TlsConnectError<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Builder(error) => write!(f, "Builder: {error}"),
            Self::Handshake { error, server_name } => {
                write!(
                    f,
                    "Handshake: {error} (server identity = '{}')",
                    server_name
                        .as_ref()
                        .map(ToString::to_string)
                        .unwrap_or_default()
                )
            }
        }
    }
}

impl<S: std::fmt::Debug> std::error::Error for TlsConnectError<S> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Builder(error) => error.source(),
            Self::Handshake {
                error,
                server_name: _,
            } => error.source(),
        }
    }
}

/// Establish a TLS connection with the fully resolved connector data.
///
/// Normal verification requires a server identity. Identity-less connections
/// are available only through an explicit [`ServerVerifyMode::Disable`].
pub async fn tls_connect<T>(
    stream: T,
    connector_data: Option<TlsConnectorData>,
) -> Result<TlsStream<T>, TlsConnectError<T>>
where
    T: Io + Unpin + ExtensionsRef,
{
    let data = match connector_data {
        Some(connector_data) => connector_data,
        None => {
            TlsConnectorData::try_from(&TlsClientConfig::new()).map_err(TlsConnectError::Builder)?
        }
    };

    let server_name = data.server_name.clone();
    let ssl = data.into_ssl().map_err(TlsConnectError::Builder)?;
    let stream: SslStream<T> = rama_boring_tokio::SslStreamBuilder::new(ssl, stream)
        .connect()
        .await
        .map_err(|error| TlsConnectError::Handshake {
            error,
            server_name: server_name.clone(),
        })?;
    Ok(TlsStream::new(stream))
}

pub(super) fn configure_server_cert_pins(
    config: &mut ConnectConfiguration,
    verify_mode: ServerVerifyMode,
    pins: Option<TlsServerCertPins>,
    server_name: Option<&Host>,
) {
    let Some(pins) = pins else {
        return;
    };
    let server_name = server_name.cloned();

    match verify_mode {
        ServerVerifyMode::Auto => {
            config.set_verify_callback(SslVerifyMode::PEER, move |preverified, store_ctx| {
                if !preverified || store_ctx.error_depth() != 0 {
                    return preverified;
                }
                let Some(cert) = store_ctx.current_cert() else {
                    return false;
                };
                let Ok(der) = cert.to_der() else {
                    return false;
                };
                match pins.check(server_name.as_ref(), &CertificateDer::from(der)) {
                    TlsServerCertPinCheck::Matched | TlsServerCertPinCheck::NotApplicable => true,
                    TlsServerCertPinCheck::Mismatched => {
                        tracing::debug!(
                            ?server_name,
                            "boring connector: server certificate pin mismatch"
                        );
                        false
                    }
                }
            });
        }
        ServerVerifyMode::Disable => {
            config.set_custom_verify_callback(SslVerifyMode::PEER, move |ssl| {
                if !pins.applies_to(server_name.as_ref()) {
                    return Ok(());
                }
                let Some(der) = ssl.peer_certificate().and_then(|cert| cert.to_der().ok()) else {
                    return Err(SslVerifyError::Invalid(SslAlert::BAD_CERTIFICATE));
                };
                match pins.check(server_name.as_ref(), &CertificateDer::from(der)) {
                    TlsServerCertPinCheck::Matched | TlsServerCertPinCheck::NotApplicable => Ok(()),
                    TlsServerCertPinCheck::Mismatched => {
                        tracing::debug!(
                            ?server_name,
                            "boring connector: server certificate pin mismatch"
                        );
                        Err(SslVerifyError::Invalid(SslAlert::BAD_CERTIFICATE))
                    }
                }
            });
        }
    }
}

async fn handshake<T>(
    connector_data: TlsConnectorData,
    stream: T,
) -> Result<(SslStream<T>, NegotiatedTlsParameters), BoxError>
where
    T: Io + Unpin + ExtensionsRef,
{
    // High-level connectors always resolve an identity. Treat its absence as
    // invalid connector state even when low-level verification is disabled.
    if connector_data.server_name.is_none() {
        return Err(BoxError::from_static_str("server identity missing"));
    }

    let authenticated_identity = (connector_data.server_verify_mode != ServerVerifyMode::Disable)
        .then(|| connector_data.server_name.clone())
        .flatten();
    let store_server_certificate_chain = connector_data.store_server_certificate_chain;
    #[cfg(feature = "dial9")]
    let dial9_server_name = connector_data.server_name.clone();
    #[cfg(feature = "dial9")]
    crate::dial9::record_handshake_started(dial9_server_name.clone());
    let TlsStream { inner: stream } = match tls_connect(stream, Some(connector_data)).await {
        Ok(s) => s,
        Err(err) => {
            #[cfg(feature = "dial9")]
            {
                use crate::dial9::tls_handshake_error_kind as kind;
                let (error_kind, io_error_kind) = match &err {
                    TlsConnectError::Builder(_) => (kind::BUILDER, None),
                    TlsConnectError::Handshake { error, .. } => {
                        let io_error_kind = error
                            .as_io_error()
                            .map(|error| rama_net::dial9::io_error_kind_code(error.kind()));
                        let error_kind = if io_error_kind.is_some() {
                            kind::HANDSHAKE_IO
                        } else if error.as_ssl_error_stack().is_some() {
                            kind::HANDSHAKE_SSL_STACK
                        } else {
                            kind::HANDSHAKE_OTHER
                        };
                        (error_kind, io_error_kind)
                    }
                };
                crate::dial9::record_handshake_failed(
                    dial9_server_name.clone(),
                    error_kind,
                    io_error_kind,
                );
            }
            return Err(match err {
                TlsConnectError::Builder(error) => error.context("tls connect builder error"),
                TlsConnectError::Handshake { error, server_name } => {
                    let maybe_ssl_code = error.code();
                    if let Some(io_err) = error.as_io_error() {
                        BoxError::from(format!(
                            "boring ssl connector (connect): with io error: {io_err}"
                        ))
                        .context_debug_field("server_identity", server_name)
                        .context_debug_field("code", maybe_ssl_code)
                    } else if let Some(ssl_error) = error.as_ssl_error_stack() {
                        ssl_error
                            .context("boring ssl connector (connect): with ssl-error info")
                            .context_debug_field("server_identity", server_name)
                            .context_debug_field("code", maybe_ssl_code)
                    } else {
                        BoxError::from_static_str(
                            "boring ssl connector (connect): without error info",
                        )
                        .context_debug_field("server_identity", server_name)
                        .context_debug_field("code", maybe_ssl_code)
                    }
                }
            });
        }
    };

    stream
        .get_ref()
        .extensions()
        .insert(rama_tls::client::TlsServerAuthentication(
            authenticated_identity,
        ));
    let params = match stream.ssl().session() {
        Some(ssl_session) => {
            let protocol_version = ssl_session
                .protocol_version()
                .rama_try_into()
                .map_err(|v| {
                    BoxError::from_static_str("boring ssl connector: cast min proto version")
                        .context_field("protocol_version", v)
                })?;
            let application_layer_protocol = stream
                .ssl()
                .selected_alpn_protocol()
                .map(ApplicationProtocol::from);
            if let Some(ref proto) = application_layer_protocol {
                tracing::trace!("boring client (connector) has selected ALPN {proto}");
            }

            let server_certificate_chain = match store_server_certificate_chain
                .then(|| stream.ssl().peer_cert_chain())
                .flatten()
            {
                Some(chain) => Some(chain.rama_try_into()?),
                None => None,
            };

            NegotiatedTlsParameters {
                protocol_version,
                application_layer_protocol,
                peer_certificate_chain: server_certificate_chain,
                server_name: None,
                resumed: Some(stream.ssl().session_reused()),
            }
        }
        None => {
            return Err(BoxError::from_static_str(
                "boring ssl connector: failed to establish session...",
            ));
        }
    };

    #[cfg(feature = "dial9")]
    {
        // Approximate cert-chain depth: opaque single Der/Pem counts as
        // 1 (we don't parse PEM here), an explicit DerStack contributes
        // its real length, no chain stored yields 0. Used for telemetry
        // bucketing only — exact length lives in the structured chain.
        let depth = params
            .peer_certificate_chain
            .as_ref()
            .map_or(0, |chain| chain.len());
        crate::dial9::record_handshake_completed(
            dial9_server_name,
            params.protocol_version,
            stream
                .ssl()
                .selected_alpn_protocol()
                .map(rama_net::tls::ApplicationProtocol::from),
            depth,
        );
    }

    Ok((stream, params))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::TlsTunnel;
    use rama_core::{Layer, Service, ServiceInput, service::service_fn};
    use rama_net::client::pool::ConnectionReuse;
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
    use rama_tls::client::{TlsServerName, TlsServerVerify};

    use rama_crypto::cert::generate_server_auth;
    use rama_net::stream::service::EchoService;
    use rama_tls::server::{GeneratedServerAuthConfig, ServerAuthData, TlsServerConfig};
    use std::{sync::Arc, time::Duration};

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
    fn server_identity_canonicalizes_ips() {
        let host = Host::from(std::net::Ipv4Addr::LOCALHOST);
        assert_eq!(server_identity_for(&host).unwrap(), "127.0.0.1");

        let host = Host::try_from("%31%32%37.0.0.1").unwrap();
        assert_eq!(server_identity_for(&host).unwrap(), "127.0.0.1");
    }

    #[test]
    fn server_identity_promotes_encoded_dns_name() {
        let host = Host::try_from("exa%6Dple.com").unwrap();
        assert_eq!(server_identity_for(&host).unwrap(), "example.com");
    }

    #[test]
    fn server_identity_preserves_numeric_domain_for_ip_classification() {
        let host = Host::Name(rama_net::address::Domain::try_from("127.0.0.1").unwrap());
        assert_eq!(server_identity_for(&host).unwrap(), "127.0.0.1");
    }

    #[test]
    fn server_identity_rejects_ipvfuture() {
        let host = Host::try_from("[v1.fe80::a]").unwrap();
        server_identity_for(&host).unwrap_err();
    }

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
        use rama_crypto::cert::generate_server_auth;
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
        let client_io = Arc::new(parking_lot::Mutex::new(Some(client_io)));
        let transport = service_fn(move |input: ServiceInput<()>| {
            let conn = ServiceInput::new(client_io.lock().take().expect("one connection"));
            async move { Ok::<_, ConnectionError>(EstablishedClientConnection { input, conn }) }
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

    #[tokio::test]
    async fn handshake_rejects_missing_server_identity() {
        let config = TlsConnectorData::try_from(
            &TlsClientConfig::new().with_server_verify(ServerVerifyMode::Disable),
        )
        .unwrap();
        let (stream, _) = tokio::io::duplex(64);
        let error = handshake(config, rama_core::ServiceInput::new(stream))
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), "server identity missing");
    }

    #[tokio::test]
    async fn tls_connect_rejects_missing_identity_when_verifying() {
        let config = TlsConnectorData::try_from(&TlsClientConfig::new()).unwrap();
        let (stream, _) = tokio::io::duplex(64);
        let error = tls_connect(rama_core::ServiceInput::new(stream), Some(config))
            .await
            .unwrap_err();
        let TlsConnectError::Builder(error) = error else {
            panic!("expected builder error");
        };
        assert_eq!(
            error.to_string(),
            "server identity required when server verification is enabled"
        );
    }

    #[test]
    fn connector_data_keeps_transport_ip_as_server_identity() {
        let host = Host::from(std::net::Ipv4Addr::LOCALHOST);

        let data = BoringTlsConnectorBackend::connector_data(&Extensions::new(), Some(&host))
            .expect("connector data");

        assert_eq!(data.server_name, Some(host));
    }

    #[test]
    fn alpn_offer_retains_alps_within_offer() {
        use crate::client::BoringAlps;

        for (alpn, expected_alps) in [
            (TlsAlpn::http_auto(), vec![ApplicationProtocol::HTTP_2]),
            (TlsAlpn::http_2(), vec![ApplicationProtocol::HTTP_2]),
            (TlsAlpn::http_1(), Vec::new()),
        ] {
            let base = Extensions::new();
            base.insert(TlsAlpn::http_auto());
            base.insert(BoringAlps {
                protocols: vec![ApplicationProtocol::HTTP_2],
                new_codepoint: true,
            });
            let effective = Extensions::new().fork().with_base(&base);

            BoringTlsConnectorBackend::set_alpn(&effective, alpn.clone());

            assert_eq!(effective.get_ref::<TlsAlpn>(), Some(&alpn));
            assert_eq!(
                effective
                    .get_ref::<BoringAlps>()
                    .map(|alps| (alps.protocols.as_slice(), alps.new_codepoint)),
                Some((expected_alps.as_slice(), true))
            );
        }
    }

    #[test]
    fn alpn_offer_without_alps_only_sets_alpn() {
        use crate::client::BoringAlps;

        let effective = Extensions::new();
        BoringTlsConnectorBackend::set_alpn(&effective, TlsAlpn::empty());

        assert_eq!(effective.get_ref::<TlsAlpn>(), Some(&TlsAlpn::empty()));
        assert!(effective.get_ref::<BoringAlps>().is_none());
    }
}
