//! HTTP/3 establishment using Rama DNS candidates and the existing multiplex pool.

use super::Http3Transport;
use rama_core::{
    Service,
    error::{BoxError, BoxErrorExt as _, error_chain},
    extensions::ExtensionsRef,
    futures::{StreamExt as _, stream},
    rt::Executor,
    telemetry::tracing,
};
use rama_http::layer::http_service::HttpServiceAttempt;
use rama_http_core::h3::connection::Config;
use rama_http_types::{Version, conn::TargetHttpVersion};
use rama_net::{
    ConnectorTargetInputExt, ProtocolInputExt,
    address::{Host, SocketAddress},
    client::{
        ConnectRequest, ConnectionError, ConnectionErrorKind, ConnectorTargetStream,
        EstablishedClientConnection, EstablishedProxyRoute, ProxyRoute, race_connect,
    },
    stream::SocketInfo,
    tls::ApplicationProtocol,
};
use rama_quic::{
    ClientConfig, Connection, ConnectionError as QuicConnectionError, Endpoint, TransportConfig,
    tls::{QuicClientConfigProvider, TlsOptions, default_tls_provider},
};
use rama_tls::client::{
    TlsClientConfig, TlsServerAuthentication, TlsServerName, TlsStoreServerCertChain,
};
use rama_utils::macros::generate_set_and_with;
use std::{net::SocketAddr, sync::Arc};

/// Establish authenticated QUIC transports for the common HTTP handshake.
///
/// Wrap this connector with Rama's DNS connector and HTTP connection pool,
/// with a connection identifier that classifies TLS overrides before lookup.
/// Rama’s easy client builder assembles this policy automatically.
/// The connector selects `h3` ALPN; the origin hostname remains the TLS
/// verification target even when routing selects a different physical address.
/// TCP proxy routes are rejected before any UDP connection is attempted.
pub struct Http3Connector {
    endpoint: Endpoint,
    tls: TlsClientConfig,
    provider: Arc<dyn QuicClientConfigProvider>,
    transport: Arc<TransportConfig>,
    config: Config,
    executor: Executor,
}

impl Clone for Http3Connector {
    fn clone(&self) -> Self {
        Self {
            endpoint: self.endpoint.clone(),
            tls: self.tls.clone(),
            provider: self.provider.clone(),
            transport: self.transport.clone(),
            config: self.config.clone(),
            executor: self.executor.clone(),
        }
    }
}

impl std::fmt::Debug for Http3Connector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Http3Connector")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

/// Configure an HTTP/3 connector, including its reusable UDP endpoint.
///
/// The supplied executor owns endpoint and connection tasks. Pass an executor
/// tied to the application's graceful shutdown when those tasks should drain
/// with the application. A custom endpoint can be supplied when its socket or
/// lifecycle is managed separately.
#[derive(Debug)]
pub struct Http3ConnectorBuilder {
    endpoint: Option<Endpoint>,
    tls: TlsClientConfig,
    provider: Option<Arc<dyn QuicClientConfigProvider>>,
    config: Config,
    executor: Executor,
}

impl Http3Connector {
    /// Configure a connector with default TLS verification and HTTP/3 limits.
    #[must_use]
    pub fn builder(executor: Executor) -> Http3ConnectorBuilder {
        Http3ConnectorBuilder {
            endpoint: None,
            tls: TlsClientConfig::default_http(),
            provider: None,
            config: Config::default(),
            executor,
        }
    }

    /// Executor shared by the endpoint and connection drivers.
    #[must_use]
    pub fn executor(&self) -> &Executor {
        &self.executor
    }

    /// Fixed TLS defaults for this connector. Rebuild its pool when these defaults
    /// or behavior captured by native TLS hooks change.
    #[must_use]
    pub fn tls_config(&self) -> &TlsClientConfig {
        &self.tls
    }

    /// Provider selection used for establishment and TLS pool identity.
    #[must_use]
    pub fn tls_provider(&self) -> &Arc<dyn QuicClientConfigProvider> {
        &self.provider
    }
}

impl Http3ConnectorBuilder {
    generate_set_and_with! {
        /// Reuse an application-managed endpoint instead of binding a new socket.
        pub fn endpoint(mut self, endpoint: Endpoint) -> Self {
            self.endpoint = Some(endpoint);
            self
        }
    }

    generate_set_and_with! {
        /// Set TLS defaults; request TLS extensions can override these settings.
        pub fn tls_config(mut self, tls: TlsClientConfig) -> Self {
            self.tls = tls;
            self
        }
    }

    generate_set_and_with! {
        /// Inject the fixed TLS configuration provider, including custom implementations.
        pub fn tls_provider(mut self, provider: Arc<dyn QuicClientConfigProvider>) -> Self {
            self.provider = Some(provider);
            self
        }
    }

    generate_set_and_with! {
        /// Configure HTTP/3 limits and their corresponding QUIC receive budgets.
        pub fn config(mut self, config: Config) -> Self {
            self.config = config;
            self
        }
    }

    /// Validate the limits and bind a default outbound endpoint when needed.
    pub async fn build(self) -> Result<Http3Connector, BoxError> {
        let mut transport = TransportConfig::default();
        self.config.configure_transport(&mut transport)?;
        let provider = match self.provider {
            Some(provider) => provider,
            None => default_tls_provider()?,
        };

        let endpoint = match self.endpoint {
            Some(endpoint) => endpoint,
            None => {
                // Reuse QUIC's dual-stack socket policy; fall back when the host
                // cannot bind IPv6. Both attempts use the same graceful executor.
                match Endpoint::bind_client(self.executor.clone(), SocketAddress::default_ipv6(0))
                    .await
                {
                    Ok(endpoint) => endpoint,
                    Err(error) => {
                        tracing::debug!(%error, "binding IPv4 H3 endpoint after IPv6 bind failed");
                        Endpoint::bind_client(self.executor.clone(), SocketAddress::default_ipv4(0))
                            .await?
                    }
                }
            }
        };

        Ok(Http3Connector {
            endpoint,
            tls: self.tls,
            provider,
            transport: Arc::new(transport),
            config: self.config,
            executor: self.executor,
        })
    }
}

fn invalid(message: &'static str) -> ConnectionError {
    ConnectionError::local(
        BoxError::from_static_str(message),
        ConnectionErrorKind::InvalidInput,
    )
}

/// Values derived once from the effective TLS configuration for one dial.
struct PreparedTls {
    config: ClientConfig,
    server_name: String,
    authenticated_identity: Option<Host>,
    capture_chain: bool,
}

impl Http3Connector {
    fn prepare_tls(&self, input: &ConnectRequest) -> Result<PreparedTls, ConnectionError> {
        let tls = self
            .tls
            .clone()
            .with_overrides(input.extensions())
            .with_alpn([ApplicationProtocol::HTTP_3].into_iter().collect());
        let server_identity = tls
            .as_extensions()
            .get_ref::<TlsServerName>()
            .map_or_else(|| input.authority.host.clone(), |name| name.0.clone());
        let authenticated_identity = self
            .provider
            .authenticates_server(tls.as_extensions())
            .then(|| server_identity.clone());
        let capture_chain = tls
            .as_extensions()
            .get_ref::<TlsStoreServerCertChain>()
            .is_some_and(|capture| capture.0);
        let mut tls = self
            .provider
            .client_config(&tls, TlsOptions::default())
            .map_err(|error| ConnectionError::local(error, ConnectionErrorKind::InvalidInput))?;
        tls.set_transport_config(self.transport.clone());
        let server_name = if let Ok(ip) = server_identity.try_as_ip() {
            ip.to_string()
        } else {
            server_identity
                .try_as_domain()
                .map_err(|_error| invalid("invalid TLS origin host"))?
                .to_string()
        };
        Ok(PreparedTls {
            config: tls,
            server_name,
            authenticated_identity,
            capture_chain,
        })
    }

    async fn connect(
        &self,
        input: &ConnectRequest,
        prepared: &PreparedTls,
    ) -> Result<(SocketAddr, Connection), ConnectionError> {
        let tls = &prepared.config;
        let server_name = prepared.server_name.as_str();
        let target = input
            .connector_target()
            .ok_or_else(|| invalid("HTTP/3 connector target is missing"))?;
        let attempt = input
            .extensions()
            .get_arc::<HttpServiceAttempt>()
            .unwrap_or_default();
        let attempt = &attempt;
        let dial = |address| async move {
            let result: Result<_, BoxError> = async {
                let connection = self
                    .endpoint
                    .connect_with(tls.clone(), address, server_name)?
                    .await?;
                connection.handshake_confirmed().await?;
                if connection
                    .handshake_data()
                    .and_then(|data| data.application_layer_protocol)
                    != Some(ApplicationProtocol::HTTP_3)
                {
                    connection.close(0u32, b"h3 ALPN required");
                    return Err(BoxError::from_static_str("HTTP/3 requires h3 ALPN"));
                }
                Ok(connection)
            }
            .await;
            if let Err(error) = &result
                && !availability_error(error.as_ref())
            {
                attempt.reject();
            }
            result
        };
        if let Ok(ip) = target.host.try_as_ip() {
            race_connect(
                stream::once(async { Ok(SocketAddr::new(ip, target.port)) }),
                1,
                dial,
            )
            .await
        } else {
            let domain = target
                .host
                .try_as_domain()
                .map_err(|_error| invalid("unsupported HTTP/3 target host"))?;
            let candidates = input
                .extensions()
                .get_ref::<ConnectorTargetStream>()
                .filter(|c| c.domain() == domain.as_ref())
                .ok_or_else(|| invalid("HTTP/3 requires DNS candidates for this domain"))?;
            let addresses = candidates
                .stream(input.extensions())
                .map(|result| result.map(|ip| SocketAddr::new(ip, target.port)));
            race_connect(addresses, 2, dial).await
        }
        .map_err(|error| {
            let error = if attempt.failed() {
                ConnectionError::application(error, ConnectionErrorKind::Authentication)
            } else {
                ConnectionError::transport(error, ConnectionErrorKind::Unavailable)
            };
            error.context("HTTP/3 connection establishment")
        })
    }

    fn set_connection_extensions(
        &self,
        connection: &Connection,
        address: SocketAddr,
        prepared: PreparedTls,
    ) {
        // Populate only connection facts: inheriting the request store here would
        // retain request metadata and could create a cycle through Egress.
        let extensions = connection.extensions();
        extensions.insert(TargetHttpVersion(Version::HTTP_3));
        extensions.insert(TlsServerAuthentication(prepared.authenticated_identity));
        extensions.insert(EstablishedProxyRoute::Direct);
        extensions.insert(SocketInfo::new(
            self.endpoint.local_addr().ok().map(Into::into),
            address.into(),
        ));
        if let Some(mut parameters) = connection.handshake_data() {
            if prepared.capture_chain {
                parameters.peer_certificate_chain = connection.peer_identity();
            }
            extensions.insert(parameters);
        }
    }
}

impl Service<ConnectRequest> for Http3Connector {
    type Output = EstablishedClientConnection<Http3Transport, ConnectRequest>;
    type Error = ConnectionError;

    async fn serve(&self, input: ConnectRequest) -> Result<Self::Output, Self::Error> {
        if input
            .extensions()
            .get_ref::<ProxyRoute>()
            .and_then(ProxyRoute::proxy_address)
            .is_some()
        {
            return Err(ConnectionError::transport(
                BoxError::from_static_str("HTTP/3 is not available over this TCP proxy route"),
                ConnectionErrorKind::Unavailable,
            ));
        }
        if input.protocol().is_none_or(|p| !p.is_secure()) {
            return Err(invalid("HTTP/3 requires a secure origin"));
        }
        validate_version(&input)?;

        let prepared = self.prepare_tls(&input)?;
        // Keep QUIC address-race and handshake state out of enclosing pool and
        // service-selection futures. Allocate only when opening a connection;
        // either transport's pool hits bypass this boundary entirely.
        let (address, connection) = Box::pin(self.connect(&input, &prepared)).await?;
        self.set_connection_extensions(&connection, address, prepared);
        input
            .extensions()
            .insert(TargetHttpVersion(Version::HTTP_3));

        let conn = Http3Transport {
            connection,
            config: self.config.clone(),
        };
        Ok(EstablishedClientConnection { input, conn })
    }
}

fn validate_version(input: &ConnectRequest) -> Result<(), ConnectionError> {
    if input
        .extensions()
        .get_ref::<TargetHttpVersion>()
        .is_some_and(|version| version.0 != Version::HTTP_3)
    {
        return Err(invalid(
            "explicit HTTP version conflicts with HTTP/3 connector",
        ));
    }
    Ok(())
}

// Classify QUIC address-race failures at the transport boundary. Generic HTTP
// service selection consumes ConnectionError classifications, never QUIC errors.
const MAX_ERROR_CHAIN_DEPTH: usize = 32;

fn availability_error(error: &(dyn std::error::Error + 'static)) -> bool {
    error_chain(error, MAX_ERROR_CHAIN_DEPTH).any(|error| {
        error
            .downcast_ref::<QuicConnectionError>()
            .is_some_and(|error| {
                matches!(
                    error,
                    QuicConnectionError::TimedOut | QuicConnectionError::VersionMismatch { .. }
                )
            })
            || error.downcast_ref::<std::io::Error>().is_some_and(|error| {
                matches!(
                    error.kind(),
                    std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::ConnectionRefused
                        | std::io::ErrorKind::NetworkUnreachable
                        | std::io::ErrorKind::HostUnreachable
                )
            })
    })
}

#[cfg(test)]
mod concrete_transport_tests {
    use super::*;
    use rama_net::{
        Protocol,
        address::{HostWithPort, SocketAddress},
        client::{ConnectionErrorDomain, ProxyRoutes, ProxyRoutesConnector},
        tls::TlsAlpn,
    };

    use rama_core::extensions::Extensions;
    use rama_quic::tls::TlsConfigError;
    use rama_tls::client::{ServerVerifyMode, TlsClientConfigProvider, TlsPoolId, TlsServerVerify};
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Debug, Default)]
    struct CustomProvider {
        calls: AtomicUsize,
        authenticated_checks: AtomicUsize,
    }

    impl TlsClientConfigProvider for CustomProvider {
        fn pool_id(&self, extensions: &Extensions) -> Option<TlsPoolId> {
            TlsPoolId::builder()
                .maybe_with_verify(extensions.get_ref::<TlsServerVerify>())
                .build()
        }

        fn authenticates_server(&self, extensions: &Extensions) -> bool {
            self.authenticated_checks.fetch_add(1, Ordering::Relaxed);
            assert_eq!(
                extensions.get_ref::<TlsAlpn>().unwrap().0.as_slice(),
                &[ApplicationProtocol::HTTP_3]
            );
            extensions
                .get_ref::<TlsServerVerify>()
                .is_none_or(|verify| verify.0 != ServerVerifyMode::Disable)
        }
    }

    impl QuicClientConfigProvider for CustomProvider {
        fn client_config(
            &self,
            config: &TlsClientConfig,
            _: TlsOptions,
        ) -> Result<ClientConfig, TlsConfigError> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            assert_eq!(
                config
                    .as_extensions()
                    .get_ref::<TlsAlpn>()
                    .unwrap()
                    .0
                    .as_slice(),
                &[ApplicationProtocol::HTTP_3]
            );
            assert_eq!(
                config
                    .as_extensions()
                    .get_ref::<TlsServerVerify>()
                    .unwrap()
                    .0,
                ServerVerifyMode::Disable
            );
            Err(TlsConfigError::InvalidConfiguration(
                BoxError::from_static_str("custom factory invoked"),
            ))
        }
    }

    #[tokio::test]
    async fn custom_factory_uses_public_builder_without_builtin_provider() {
        let provider = Arc::new(CustomProvider::default());
        let connector = Http3Connector::builder(Executor::default())
            .with_tls_provider(provider.clone())
            .with_tls_config(TlsClientConfig::new().with_server_verify(ServerVerifyMode::Auto))
            .build()
            .await
            .unwrap();
        let input = ConnectRequest::new(HostWithPort::local_ipv4(443))
            .with_application_protocol(Protocol::HTTPS);
        input
            .extensions
            .insert(TlsServerVerify(ServerVerifyMode::Disable));
        let classifier: Arc<dyn TlsClientConfigProvider> = connector.tls_provider().clone();
        assert_eq!(
            classifier.pool_id(input.extensions()),
            provider.pool_id(input.extensions())
        );

        let error = connector.serve(input).await.err().unwrap();
        assert_eq!(error.kind(), ConnectionErrorKind::InvalidInput);
        assert_eq!(provider.calls.load(Ordering::Relaxed), 1);
        assert_eq!(provider.authenticated_checks.load(Ordering::Relaxed), 1);
        connector.endpoint.close(0u32, b"test complete");
    }

    #[tokio::test]
    async fn proxy_only_route_never_implicitly_dials_direct_quic() {
        let executor = Executor::default();
        let endpoint = Endpoint::build(executor.clone())
            .bind_address(SocketAddress::local_ipv4(0))
            .await
            .unwrap();
        // Deliberately omit a TLS provider: reaching direct establishment would
        // fail locally instead of returning the proxy capability error.
        let http3 = Http3Connector {
            endpoint: endpoint.clone(),
            tls: TlsClientConfig::default_http(),
            provider: Arc::new(CustomProvider::default()),
            transport: Arc::new(TransportConfig::default()),
            config: Config::default(),
            executor,
        };
        let connector = ProxyRoutesConnector::new(http3);
        let input = ConnectRequest::new("origin.example:443".parse().unwrap())
            .with_application_protocol(Protocol::HTTPS);
        input
            .extensions()
            .insert(TargetHttpVersion(Version::HTTP_3));
        input
            .extensions()
            .insert(ProxyRoutes::new(vec![ProxyRoute::Proxy(
                "http://proxy.example:8080".parse().unwrap(),
            )]));
        let error = connector.serve(input).await.err().unwrap();
        assert_eq!(error.domain(), ConnectionErrorDomain::Transport);
        assert_eq!(error.kind(), ConnectionErrorKind::Unavailable);
        endpoint.close(0u32, b"test complete");
    }
}
