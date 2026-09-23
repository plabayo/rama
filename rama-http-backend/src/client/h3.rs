//! HTTP/3 establishment using Rama DNS candidates and the existing multiplex pool.

use super::Http3Transport;
use parking_lot::Mutex;
use rama_core::{
    Service,
    error::{ArcError, BoxError, BoxErrorExt as _, error_chain},
    extensions::ExtensionsRef,
    futures::{StreamExt as _, stream},
    rt::Executor,
    telemetry::tracing,
};
use rama_http_core::h3::connection::Config;
use rama_http_types::{Version, conn::TargetHttpVersion};
use rama_net::{
    ConnectorTargetInputExt, ProtocolInputExt,
    address::{Host, SocketAddress},
    client::{
        ConnectRequest, ConnectionAttempt, ConnectionError, ConnectionErrorDomain,
        ConnectionErrorDomain::{Application, Local, Transport},
        ConnectionErrorKind,
        ConnectionErrorKind::{Internal, InvalidInput, Rejected, Timeout, Unavailable},
        ConnectionPolicyScope, ConnectorTargetStream, EstablishedClientConnection,
        EstablishedProxyRoute, ProxyRoute, race_connect,
    },
    mode::ConnectIpMode,
    stream::SocketInfo,
    tls::ApplicationProtocol,
};
use rama_quic::{
    ClientConfig, ConnectError as QuicConnectError, Connection,
    ConnectionError as QuicConnectionError, Endpoint, TransportConfig,
    tls::{ClientConfigCache, QuicClientConfigProvider, TlsOptions, default_tls_provider},
};
use rama_quic_proto::TransportErrorCode;
use rama_tls::client::{
    TlsClientConfig, TlsConnectionReuse, TlsServerAuthentication, TlsServerName,
    TlsStoreServerCertChain,
};
use rama_utils::macros::generate_set_and_with;
use std::{
    error::Error as StdError,
    io::{Error as IoError, ErrorKind as IoErrorKind},
    net::{IpAddr, SocketAddr},
    sync::Arc,
};
use tokio::sync::OnceCell;

/// Establish authenticated QUIC transports for the common HTTP handshake.
///
/// Wrap this connector with Rama's DNS connector and HTTP connection pool,
/// which checks the reuse policy published by this connector. TLS overrides
/// are classified by the same provider that configures the handshake.
/// The connector selects `h3` ALPN; the origin hostname remains the TLS
/// verification target even when routing selects a different physical address.
/// This direct UDP connector rejects proxy routes before any connection attempt.
/// Proxy-capable QUIC connectors can be injected separately.
pub struct Http3Connector {
    endpoint: Arc<OnceCell<Endpoint>>,
    tls: TlsClientConfig,
    tls_configs: ClientConfigCache,
    transport: Arc<TransportConfig>,
    config: Config,
    executor: Executor,
}

impl Clone for Http3Connector {
    fn clone(&self) -> Self {
        Self {
            endpoint: self.endpoint.clone(),
            tls: self.tls.clone(),
            tls_configs: self.tls_configs.clone(),
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
        self.tls_configs.provider()
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
        let connector = self.build_lazy()?;
        connector.endpoint().await?;
        Ok(connector)
    }

    /// Validate configuration now and bind the endpoint on the first connection attempt.
    ///
    /// Construction requires no runtime or socket. Clones share initialization
    /// and the resulting endpoint; failed or cancelled initialization can be retried.
    /// An application-supplied endpoint is used immediately.
    pub fn build_lazy(self) -> Result<Http3Connector, BoxError> {
        let mut transport = TransportConfig::default();
        self.config.configure_transport(&mut transport)?;
        let provider = match self.provider {
            Some(provider) => provider,
            None => default_tls_provider()?,
        };

        Ok(Http3Connector {
            endpoint: Arc::new(OnceCell::new_with(self.endpoint)),
            tls: self.tls,
            tls_configs: ClientConfigCache::new(provider, TlsOptions::default()),
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
    policy_scope: ConnectionPolicyScope,
    reuse: TlsConnectionReuse<Arc<dyn QuicClientConfigProvider>>,
}

impl Http3Connector {
    async fn endpoint(&self) -> Result<&Endpoint, BoxError> {
        self.endpoint
            .get_or_try_init(|| async {
                // Reuse QUIC's dual-stack socket policy, including IPv4 fallback.
                // Both attempts use the connector's graceful executor.
                match Endpoint::bind_client(self.executor.clone(), SocketAddress::default_ipv6(0))
                    .await
                {
                    Ok(endpoint) => Ok(endpoint),
                    Err(error) => {
                        tracing::debug!(%error, "binding IPv4 H3 endpoint after IPv6 bind failed");
                        Ok(Endpoint::bind_client(
                            self.executor.clone(),
                            SocketAddress::default_ipv4(0),
                        )
                        .await?)
                    }
                }
            })
            .await
    }

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
            .tls_provider()
            .authenticates_server(tls.as_extensions())
            .then(|| server_identity.clone());
        let request_policy = self.tls_provider().pool_id(input.extensions());
        let policy_scope = if request_policy.is_some() {
            ConnectionPolicyScope::Request
        } else {
            ConnectionPolicyScope::Connector
        };
        if let Some(attempt) = input.extensions().get_ref::<ConnectionAttempt>() {
            let identity = self
                .tls_provider()
                .authenticates_origin(tls.as_extensions(), &input.authority.host)
                .then_some(authenticated_identity.as_ref())
                .flatten();
            attempt.check_policy(policy_scope, identity)?;
        }
        let capture_chain = tls
            .as_extensions()
            .get_ref::<TlsStoreServerCertChain>()
            .is_some_and(|capture| capture.0);
        let effective_policy = self.tls_provider().pool_id(tls.as_extensions());
        let mut config = self
            .tls_configs
            .client_config(&tls, input.extensions())
            .map_err(|error| ConnectionError::local(error, InvalidInput))?;
        config.set_transport_config(self.transport.clone());
        let server_name = if let Ok(ip) = server_identity.try_as_ip() {
            ip.to_string()
        } else {
            server_identity
                .try_as_domain()
                .map_err(|_error| invalid("invalid TLS origin host"))?
                .to_string()
        };
        Ok(PreparedTls {
            config,
            server_name,
            authenticated_identity,
            capture_chain,
            policy_scope,
            reuse: TlsConnectionReuse::new(
                self.tls_provider().clone(),
                input.extensions(),
                effective_policy,
            ),
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
            .get_arc::<ConnectionAttempt>()
            .unwrap_or_default();
        let attempt = &attempt;
        let failures = ConnectFailures::default();
        let failures = &failures;
        let endpoint = self.endpoint().await.map_err(|error| {
            ConnectionError::local(error, Unavailable).context("binding HTTP/3 endpoint")
        })?;
        let dial = |address| async move {
            let result: Result<_, BoxError> = async {
                let connection = endpoint
                    .connect_with(tls.clone(), address, server_name)?
                    .await?;
                connection.handshake_confirmed().await?;
                if connection
                    .handshake_data()
                    .and_then(|data| data.application_layer_protocol)
                    != Some(ApplicationProtocol::HTTP_3)
                {
                    connection.close(0u32, b"h3 ALPN required");
                    return Err(ConnectionError::application(
                        BoxError::from_static_str("HTTP/3 requires h3 ALPN"),
                        ConnectionErrorKind::Protocol,
                    )
                    .into());
                }
                Ok(connection)
            }
            .await;
            result.map_err(|error| failures.record(error, attempt))
        };
        if let Ok(ip) = target.host.try_as_ip() {
            let ip = input
                .extensions()
                .get_ref::<ConnectIpMode>()
                .copied()
                .unwrap_or_default()
                .validate_ip(ip)
                .map_err(|error| ConnectionError::local(error, InvalidInput))?;
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
                .ok_or_else(|| invalid("HTTP/3 domain targets require an outer DNS connector"))?;
            let addresses = candidates
                .stream(input.extensions())
                .map(|result| result.map(|ip| SocketAddr::new(ip, target.port)));
            race_connect(addresses, 2, dial).await
        }
        .map_err(|error| {
            failures
                .finish(error)
                .context("HTTP/3 connection establishment")
        })
    }

    fn set_connection_extensions(&self, connection: &Connection, prepared: PreparedTls) {
        // Populate only connection facts: inheriting the request store here would
        // retain request metadata and could create a cycle through Egress.
        let extensions = connection.extensions();
        prepared.reuse.publish(extensions);
        extensions.insert(TargetHttpVersion(Version::HTTP_3));
        extensions.insert(TlsServerAuthentication(prepared.authenticated_identity));
        extensions.insert(prepared.policy_scope);
        extensions.insert(EstablishedProxyRoute::Direct);
        extensions.insert(SocketInfo::new(
            known_local_address(
                self.endpoint
                    .get()
                    .and_then(|endpoint| endpoint.local_addr().ok()),
                connection.local_ip(),
            ),
            connection.remote_address().into(),
        ));
        if let Some(mut parameters) = connection.handshake_data() {
            if prepared.capture_chain {
                parameters.peer_certificate_chain = connection.peer_identity();
            }
            extensions.insert(parameters);
        }
    }
}

// A wildcard bind is not a connection's source address. Packet metadata may
// identify the actual interface; otherwise leave the optional address unknown.
fn known_local_address(
    bound: Option<SocketAddr>,
    observed_ip: Option<IpAddr>,
) -> Option<SocketAddress> {
    let bound = bound?;
    let ip = observed_ip
        .filter(|ip| !ip.is_unspecified())
        .or_else(|| (!bound.ip().is_unspecified()).then_some(bound.ip()))?;
    Some(SocketAddr::new(ip, bound.port()).into())
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
            return Err(ConnectionError::local(
                BoxError::from_static_str("this QUIC connector does not support proxy routes"),
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
        let (_, connection) = Box::pin(self.connect(&input, &prepared)).await?;
        self.set_connection_extensions(&connection, prepared);
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

// Keep the first terminal failure when a later address merely times out. An
// authentication failure takes precedence, including when an outer speculative
// deadline cancels the race. Only failed dials acquire this lock or share errors.
#[derive(Default)]
struct ConnectFailures(Mutex<Option<ConnectionError>>);

impl ConnectFailures {
    fn record(&self, error: BoxError, attempt: &ConnectionAttempt) -> BoxError {
        let (domain, kind) = classify_connect_error(error.as_ref());
        if domain == Transport && matches!(kind, Unavailable | Timeout) {
            return error;
        }
        attempt.reject_with_kind(kind);
        let mut terminal = self.0.lock();
        if terminal.is_none() || kind == ConnectionErrorKind::Authentication {
            let error = ArcError::from_box_error(error);
            *terminal = Some(ConnectionError::new(error.clone(), domain, kind));
            return error.into();
        }
        error
    }

    fn finish(&self, error: BoxError) -> ConnectionError {
        self.0.lock().take().unwrap_or_else(|| {
            let (domain, kind) = classify_connect_error(error.as_ref());
            ConnectionError::new(error, domain, kind)
        })
    }
}

// Classify QUIC address-race failures at the transport boundary. Generic HTTP
// service selection consumes ConnectionError classifications, never QUIC errors.
const MAX_ERROR_CHAIN_DEPTH: usize = 32;
// RFC 7301 §3.2: negotiation failed because the peer supports no offered ALPN.
const TLS_NO_APPLICATION_PROTOCOL: u8 = 120;

fn classify_connect_error(
    error: &(dyn StdError + 'static),
) -> (ConnectionErrorDomain, ConnectionErrorKind) {
    for error in error_chain(error, MAX_ERROR_CHAIN_DEPTH) {
        if let Some(error) = error.downcast_ref::<ConnectionError>() {
            return (error.domain(), error.kind());
        }
        if let Some(error) = error.downcast_ref::<QuicConnectionError>() {
            return match error {
                QuicConnectionError::TimedOut => (Transport, Timeout),
                QuicConnectionError::VersionMismatch { .. } | QuicConnectionError::Reset => {
                    (Transport, Unavailable)
                }
                QuicConnectionError::ApplicationClosed(_) => (Application, Rejected),
                QuicConnectionError::CidsExhausted | QuicConnectionError::LocallyClosed => {
                    (Local, Unavailable)
                }
                QuicConnectionError::TransportError(error) => classify_transport_code(error.code),
                QuicConnectionError::ConnectionClosed(error) => {
                    classify_transport_code(error.error_code)
                }
            };
        }
        if let Some(error) = error.downcast_ref::<QuicConnectError>() {
            return match error {
                QuicConnectError::EndpointStopping | QuicConnectError::CidsExhausted => {
                    (Local, Unavailable)
                }
                QuicConnectError::Crypto(error) => classify_transport_code(error.code),
                QuicConnectError::InvalidRemoteAddress(address)
                    if address.port() != 0 && !address.ip().is_unspecified() =>
                {
                    // A valid address may have an unsupported family for the
                    // configured endpoint. Other candidates can still work.
                    (Transport, Unavailable)
                }
                _ => (Local, InvalidInput),
            };
        }
        if let Some(error) = error.downcast_ref::<IoError>() {
            return match error.kind() {
                IoErrorKind::TimedOut => (Transport, Timeout),
                IoErrorKind::ConnectionRefused
                | IoErrorKind::ConnectionReset
                | IoErrorKind::ConnectionAborted
                | IoErrorKind::NetworkUnreachable
                | IoErrorKind::HostUnreachable => (Transport, Unavailable),
                _ => (Local, Internal),
            };
        }
    }
    // DNS streams may finish without an address or return resolver-specific errors.
    (Transport, Unavailable)
}

fn classify_transport_code(
    code: TransportErrorCode,
) -> (ConnectionErrorDomain, ConnectionErrorKind) {
    if code == TransportErrorCode::CONNECTION_REFUSED {
        (
            ConnectionErrorDomain::Transport,
            ConnectionErrorKind::Unavailable,
        )
    } else if code.tls_alert() == Some(TLS_NO_APPLICATION_PROTOCOL) {
        (
            ConnectionErrorDomain::Application,
            ConnectionErrorKind::Protocol,
        )
    } else if code.tls_alert().is_some() {
        // TLS alerts include certificate failures; fail closed across speculative races.
        (
            ConnectionErrorDomain::Application,
            ConnectionErrorKind::Authentication,
        )
    } else {
        (
            ConnectionErrorDomain::Application,
            ConnectionErrorKind::Protocol,
        )
    }
}

#[cfg(test)]
mod concrete_transport_tests {
    use super::*;
    use rama_net::{
        Protocol,
        address::{HostWithPort, SocketAddress},
        client::{
            ConnectionErrorDomain, ProxyRouteFailureCache, ProxyRouteFailureCacheConnector,
            ProxyRoutes, ProxyRoutesConnector,
        },
        tls::TlsAlpn,
    };

    use rama_core::extensions::Extensions;
    use rama_quic::tls::TlsConfigError;
    use rama_quic_proto::{TransportError, frame::ApplicationClose};
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

    #[test]
    fn lazy_connector_construction_needs_no_runtime() {
        let connector = Http3Connector::builder(Executor::new())
            .with_tls_provider(Arc::new(CustomProvider::default()))
            .build_lazy()
            .unwrap();
        assert!(connector.endpoint.get().is_none());
    }

    #[tokio::test]
    async fn lazy_connector_clones_share_concurrent_endpoint_initialization() {
        let connector = Http3Connector::builder(Executor::new())
            .with_tls_provider(Arc::new(CustomProvider::default()))
            .build_lazy()
            .unwrap();
        let clone = connector.clone();
        let (first, second) = tokio::join!(connector.endpoint(), clone.endpoint());
        let first = first.unwrap();
        assert!(std::ptr::eq(first, second.unwrap()));
        first.close(0u32, b"test complete");
        first.shutdown().await;
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
        connector
            .endpoint
            .get()
            .unwrap()
            .close(0u32, b"test complete");
    }

    #[tokio::test]
    async fn proxy_only_route_never_implicitly_dials_direct_quic() {
        let executor = Executor::default();
        let endpoint = Endpoint::build(executor.clone())
            .bind_address(SocketAddress::local_ipv4(0))
            .await
            .unwrap();
        // This provider cannot establish TLS: reaching direct establishment
        // would fail locally instead of returning the proxy capability error.
        let http3 = Http3Connector {
            endpoint: Arc::new(OnceCell::new_with(Some(endpoint.clone()))),
            tls: TlsClientConfig::default_http(),
            tls_configs: ClientConfigCache::new(
                Arc::new(CustomProvider::default()),
                TlsOptions::default(),
            ),
            transport: Arc::new(TransportConfig::default()),
            config: Config::default(),
            executor,
        };
        let cache = ProxyRouteFailureCache::default();
        let connector =
            ProxyRoutesConnector::new(ProxyRouteFailureCacheConnector::new(http3, cache.clone()));
        let proxy = ProxyRoute::Proxy("http://proxy.example:8080".parse().unwrap());
        for routes in [vec![proxy.clone()], vec![proxy, ProxyRoute::Direct]] {
            for _ in 0..2 {
                let input = ConnectRequest::new("origin.example:443".parse().unwrap())
                    .with_application_protocol(Protocol::HTTPS);
                input
                    .extensions()
                    .insert(TargetHttpVersion(Version::HTTP_3));
                input.extensions().insert(ProxyRoutes::new(routes.clone()));
                let error = connector.serve(input).await.err().unwrap();
                assert_eq!(error.domain(), ConnectionErrorDomain::Local);
                assert_eq!(error.kind(), ConnectionErrorKind::Unavailable);
                assert_eq!(cache.entry_count(), 0);
            }
        }
        // A direct fallback would reach provider configuration and return InvalidInput.
        endpoint.close(0u32, b"test complete");
    }

    #[test]
    fn connection_metadata_never_reports_a_wildcard_source() {
        let concrete = SocketAddress::local_ipv4(443);
        let wildcard = SocketAddress::default_ipv4(443);
        assert_eq!(known_local_address(Some(wildcard.into()), None), None);
        assert_eq!(
            known_local_address(Some(concrete.into()), None),
            Some(concrete)
        );
        assert_eq!(
            known_local_address(Some(wildcard.into()), Some(SocketAddr::from(concrete).ip())),
            Some(concrete)
        );
        assert_eq!(
            known_local_address(None, Some(SocketAddr::from(concrete).ip())),
            None
        );
    }

    #[test]
    fn address_race_preserves_authentication_failure_in_any_order() {
        let authentication =
            QuicConnectionError::TransportError(TransportErrorCode::crypto(42).into());
        let protocol =
            QuicConnectionError::TransportError(TransportErrorCode::PROTOCOL_VIOLATION.into());
        for errors in [
            vec![authentication.clone(), QuicConnectionError::TimedOut],
            vec![
                authentication.clone(),
                QuicConnectionError::TimedOut,
                protocol.clone(),
                QuicConnectionError::Reset,
            ],
            vec![
                protocol,
                QuicConnectionError::Reset,
                authentication.clone(),
                QuicConnectionError::TimedOut,
            ],
        ] {
            let failures = ConnectFailures::default();
            let attempt = ConnectionAttempt::default();
            for error in errors {
                drop(failures.record(error.into(), &attempt));
            }
            // The final race result may only expose its last timed-out address.
            let error = failures.finish(QuicConnectionError::TimedOut.into());
            assert_eq!(
                attempt.failure_kind(),
                Some(ConnectionErrorKind::Authentication)
            );
            assert_eq!(error.domain(), ConnectionErrorDomain::Application);
            assert_eq!(error.kind(), ConnectionErrorKind::Authentication);
            assert!(
                error_chain(error.get_ref(), MAX_ERROR_CHAIN_DEPTH).any(|cause| {
                    cause.downcast_ref::<QuicConnectionError>() == Some(&authentication)
                })
            );
        }
    }

    #[test]
    fn unsupported_address_family_does_not_poison_the_address_race() {
        let failures = ConnectFailures::default();
        let attempt = ConnectionAttempt::default();
        let ipv6 = QuicConnectError::InvalidRemoteAddress(SocketAddress::local_ipv6(443).into());
        drop(failures.record(ipv6.into(), &attempt));
        let timeout = failures.record(QuicConnectionError::TimedOut.into(), &attempt);
        let error = failures.finish(timeout);
        assert!(!attempt.failed());
        assert_eq!((error.domain(), error.kind()), (Transport, Timeout));
        for address in [
            SocketAddress::local_ipv4(0),
            SocketAddress::default_ipv6(443),
        ] {
            assert_eq!(
                classify_connect_error(&QuicConnectError::InvalidRemoteAddress(address.into())),
                (Local, InvalidInput)
            );
        }
    }

    #[test]
    fn quic_establishment_failures_preserve_their_domain() {
        let cases = [
            (QuicConnectionError::Reset, Transport, Unavailable),
            (QuicConnectionError::TimedOut, Transport, Timeout),
            (QuicConnectionError::CidsExhausted, Local, Unavailable),
            (QuicConnectionError::LocallyClosed, Local, Unavailable),
            (
                QuicConnectionError::TransportError(TransportErrorCode::CONNECTION_REFUSED.into()),
                Transport,
                Unavailable,
            ),
            (
                QuicConnectionError::ConnectionClosed(
                    TransportError::from(TransportErrorCode::CONNECTION_REFUSED).into(),
                ),
                Transport,
                Unavailable,
            ),
            (
                QuicConnectionError::TransportError(TransportErrorCode::PROTOCOL_VIOLATION.into()),
                Application,
                ConnectionErrorKind::Protocol,
            ),
            (
                QuicConnectionError::TransportError(TransportErrorCode::crypto(42).into()),
                Application,
                ConnectionErrorKind::Authentication,
            ),
            (
                QuicConnectionError::TransportError(
                    TransportErrorCode::crypto(TLS_NO_APPLICATION_PROTOCOL).into(),
                ),
                Application,
                ConnectionErrorKind::Protocol,
            ),
            (
                QuicConnectionError::ApplicationClosed(ApplicationClose {
                    error_code: 0u32.into(),
                    reason: Default::default(),
                }),
                Application,
                Rejected,
            ),
        ];
        for (error, domain, kind) in cases {
            assert_eq!(classify_connect_error(&error), (domain, kind), "{error}");
        }
        let alpn = ConnectionError::application(
            BoxError::from_static_str("wrong ALPN"),
            ConnectionErrorKind::Protocol,
        );
        assert_eq!(
            classify_connect_error(&alpn),
            (Application, ConnectionErrorKind::Protocol)
        );
    }
}
