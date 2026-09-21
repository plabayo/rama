//! HTTP/3 establishment using Rama DNS candidates and the existing multiplex pool.

use super::{HttpClientService, HttpTlsPoolConfig, TlsPoolPolicy};
use rama_core::{
    Service, ServiceInput,
    error::{BoxError, BoxErrorExt as _},
    extensions::ExtensionsRef,
    futures::{StreamExt as _, stream},
    rt::Executor,
};
use rama_http_core::h3::connection::Config;
use rama_http_types::{Version, conn::TargetHttpVersion};
use rama_net::{
    ConnectorTargetInputExt, ProtocolInputExt,
    client::{
        ConnectRequest, ConnectionError, ConnectionErrorKind, ConnectorService as _,
        ConnectorTargetStream, EstablishedClientConnection, EstablishedProxyRoute, ProxyRoute,
        race_connect,
    },
    conn::MaxConcurrency,
    stream::SocketInfo,
    tls::ApplicationProtocol,
};
use rama_tls::{TlsBackend, client::TlsClientConfig};
use std::{marker::PhantomData, net::SocketAddr, sync::Arc};

/// Establish authenticated HTTP/3 connections on a reusable QUIC endpoint.
///
/// Wrap this connector with Rama's DNS connector and HTTP connection pool,
/// then put [`Http3Policy`] outside the pool so TLS overrides affect lookup.
/// The connector selects `h3` ALPN; the origin hostname remains the TLS
/// verification target even when routing selects a different physical address.
/// TCP proxy routes are rejected before any UDP connection is attempted.
pub struct Http3Connector<B> {
    endpoint: rama_quic::Endpoint,
    tls: rama_tls::client::TlsClientConfig,
    backend: TlsBackend,
    transport: Arc<rama_quic::TransportConfig>,
    config: rama_http_core::h3::connection::Config,
    executor: Executor,
    _body: PhantomData<fn(B)>,
}

impl<B> Clone for Http3Connector<B> {
    fn clone(&self) -> Self {
        Self {
            endpoint: self.endpoint.clone(),
            tls: self.tls.clone(),
            backend: self.backend,
            transport: self.transport.clone(),
            config: self.config.clone(),
            executor: self.executor.clone(),
            _body: PhantomData,
        }
    }
}

impl<B> std::fmt::Debug for Http3Connector<B> {
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
pub struct Http3ConnectorBuilder<B> {
    endpoint: Option<rama_quic::Endpoint>,
    tls: TlsClientConfig,
    backend: TlsBackend,
    config: Config,
    executor: Executor,
    _body: PhantomData<fn(B)>,
}

impl<B> Http3Connector<B> {
    /// Configure a connector with default TLS verification and HTTP/3 limits.
    #[must_use]
    pub fn builder(executor: Executor) -> Http3ConnectorBuilder<B> {
        Http3ConnectorBuilder {
            endpoint: None,
            tls: TlsClientConfig::default_http(),
            backend: TlsBackend::Auto,
            config: Config::default(),
            executor,
            _body: PhantomData,
        }
    }

    /// Executor shared by the endpoint and connection drivers.
    #[must_use]
    pub fn executor(&self) -> &Executor {
        &self.executor
    }

    /// TLS defaults that pool policy must combine with request overrides.
    #[must_use]
    pub fn tls_config(&self) -> &TlsClientConfig {
        &self.tls
    }

    /// Provider selection used for both establishment and pool policy.
    #[must_use]
    pub fn tls_backend(&self) -> TlsBackend {
        self.backend
    }
}

impl<B> Http3ConnectorBuilder<B> {
    rama_utils::macros::generate_set_and_with! {
        /// Reuse an application-managed endpoint instead of binding a new socket.
        pub fn endpoint(mut self, endpoint: rama_quic::Endpoint) -> Self {
            self.endpoint = Some(endpoint);
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set TLS defaults; request TLS extensions can override these settings.
        pub fn tls_config(mut self, tls: TlsClientConfig) -> Self {
            self.tls = tls;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Select the TLS provider. Auto follows Rama QUIC's provider preference.
        pub fn tls_backend(mut self, backend: TlsBackend) -> Self {
            self.backend = backend;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Configure HTTP/3 limits and their corresponding QUIC receive budgets.
        pub fn config(mut self, config: Config) -> Self {
            self.config = config;
            self
        }
    }

    /// Validate the limits and bind a default outbound endpoint when needed.
    pub async fn build(self) -> Result<Http3Connector<B>, BoxError> {
        let mut transport = rama_quic::TransportConfig::default();
        self.config.configure_transport(&mut transport)?;
        let backend = rama_quic::tls::TlsOptions::default()
            .with_backend(self.backend)
            .resolve_backend()?;

        let endpoint = match self.endpoint {
            Some(endpoint) => endpoint,
            None => {
                // Reuse QUIC's dual-stack socket policy; fall back when the host
                // cannot bind IPv6. Both attempts use the same graceful executor.
                match rama_quic::Endpoint::bind_client(
                    self.executor.clone(),
                    rama_net::address::SocketAddress::default_ipv6(0),
                )
                .await
                {
                    Ok(endpoint) => endpoint,
                    Err(error) => {
                        rama_core::telemetry::tracing::debug!(%error, "binding IPv4 H3 endpoint after IPv6 bind failed");
                        rama_quic::Endpoint::bind_client(
                            self.executor.clone(),
                            rama_net::address::SocketAddress::default_ipv4(0),
                        )
                        .await?
                    }
                }
            }
        };

        Ok(Http3Connector {
            endpoint,
            tls: self.tls,
            backend,
            transport: Arc::new(transport),
            config: self.config,
            executor: self.executor,
            _body: PhantomData,
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
    config: rama_quic::ClientConfig,
    server_name: String,
    authenticated_identity: Option<rama_net::address::Host>,
    capture_chain: bool,
}

impl<B> Http3Connector<B> {
    fn prepare_tls(&self, input: &ConnectRequest) -> Result<PreparedTls, ConnectionError> {
        let tls = self.tls.clone().with_overrides(input.extensions());
        let server_identity = tls
            .as_extensions()
            .get_ref::<rama_tls::client::TlsServerName>()
            .map_or_else(|| input.authority.host.clone(), |name| name.0.clone());
        let authenticated_identity =
            rama_quic::tls::client_authenticates_server(tls.as_extensions(), self.backend)
                .then(|| server_identity.clone());
        let capture_chain = tls
            .as_extensions()
            .get_ref::<rama_tls::client::TlsStoreServerCertChain>()
            .is_some_and(|capture| capture.0);
        let tls = tls.with_alpn([ApplicationProtocol::HTTP_3].into_iter().collect());
        let mut tls = rama_quic::ClientConfig::try_from_rama_tls(
            &tls,
            rama_quic::tls::TlsOptions::default().with_backend(self.backend),
        )
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
    ) -> Result<(SocketAddr, rama_quic::Connection), ConnectionError> {
        let tls = &prepared.config;
        let server_name = prepared.server_name.as_str();
        let target = input
            .connector_target()
            .ok_or_else(|| invalid("HTTP/3 connector target is missing"))?;
        let attempt = input
            .extensions()
            .get_ref::<rama_http::layer::http_service::HttpServiceAttempt>()
            .cloned()
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

    fn connection_extensions(
        &self,
        connection: &rama_quic::Connection,
        address: SocketAddr,
        prepared: PreparedTls,
    ) -> rama_core::extensions::Extensions {
        // Connection metadata must not inherit a request store: attaching it back
        // as Egress would form a recursive extension chain and retain that request.
        let extensions = rama_core::extensions::Extensions::new();
        extensions.insert(TargetHttpVersion(Version::HTTP_3));
        extensions.insert(rama_tls::client::TlsServerAuthentication(
            prepared.authenticated_identity,
        ));
        extensions.insert(EstablishedProxyRoute::Direct);
        extensions.insert(MaxConcurrency::new(self.config.max_requests));
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
        extensions
    }
}

impl<B: Send + 'static> Service<ConnectRequest> for Http3Connector<B> {
    type Output = EstablishedClientConnection<HttpClientService<B>, ConnectRequest>;
    type Error = ConnectionError;

    async fn serve(&self, input: ConnectRequest) -> Result<Self::Output, Self::Error> {
        if input
            .extensions()
            .get_ref::<ProxyRoute>()
            .and_then(ProxyRoute::proxy_address)
            .is_some()
        {
            return Err(invalid("HTTP/3 is not available over this TCP proxy route"));
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
        let extensions = self.connection_extensions(&connection, address, prepared);
        input
            .extensions()
            .insert(TargetHttpVersion(Version::HTTP_3));

        let conn = HttpClientService::http3(
            ServiceInput {
                input: connection,
                extensions,
            },
            self.config.clone(),
            self.executor.clone(),
        )
        .map_err(|error| ConnectionError::application(error, ConnectionErrorKind::Protocol))?;
        Ok(EstablishedClientConnection { input, conn })
    }
}

/// Apply H3 intent before DNS, route selection and pool selection.
#[derive(Clone, Debug)]
pub struct Http3Policy<S> {
    inner: TlsPoolPolicy<S>,
}

impl<S> Http3Policy<S> {
    /// Wrap the complete H3 connector stack using its effective TLS defaults.
    pub fn new(
        inner: S,
        tls: rama_tls::client::TlsClientConfig,
        backend: rama_tls::TlsBackend,
    ) -> Self {
        let classify: fn(&rama_core::extensions::Extensions) -> rama_tls::client::TlsClientPoolKey =
            match backend {
                TlsBackend::Auto => {
                    |extensions| rama_quic::tls::client_pool_key(extensions, TlsBackend::Auto)
                }
                TlsBackend::Rustls => {
                    |extensions| rama_quic::tls::client_pool_key(extensions, TlsBackend::Rustls)
                }
                TlsBackend::Boring => {
                    |extensions| rama_quic::tls::client_pool_key(extensions, TlsBackend::Boring)
                }
            };
        Self {
            inner: TlsPoolPolicy::new(inner, HttpTlsPoolConfig::new(tls, classify)),
        }
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

impl<S> Service<ConnectRequest> for Http3Policy<S>
where
    S: rama_net::client::ConnectorService<ConnectRequest>,
{
    type Output = EstablishedClientConnection<S::Connection, ConnectRequest>;
    type Error = ConnectionError;
    async fn serve(&self, input: ConnectRequest) -> Result<Self::Output, Self::Error> {
        validate_version(&input)?;
        let extensions = input.extensions();
        extensions.insert(TargetHttpVersion(Version::HTTP_3));
        extensions.insert(rama_net::client::ConnectorTransportProtocol(
            rama_net::transport::TransportProtocol::Udp,
        ));
        self.inner.connect(input).await
    }
}

// Classify QUIC address-race failures at the transport boundary. Generic HTTP
// service selection consumes ConnectionError classifications, never QUIC errors.
const MAX_ERROR_CHAIN_DEPTH: usize = 32;

fn availability_error(error: &(dyn std::error::Error + 'static)) -> bool {
    rama_core::error::error_chain(error, MAX_ERROR_CHAIN_DEPTH).any(|error| {
        error
            .downcast_ref::<rama_quic::ConnectionError>()
            .is_some_and(|error| {
                matches!(
                    error,
                    rama_quic::ConnectionError::TimedOut
                        | rama_quic::ConnectionError::VersionMismatch { .. }
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
mod tests {
    use super::*;
    use rama_core::{extensions::Extensions, service::service_fn};
    use rama_net::client::pool::ReqToConnID as _;

    fn request() -> ConnectRequest {
        ConnectRequest::new("example.com:443".parse().unwrap())
            .with_application_protocol(rama_net::Protocol::HTTPS)
    }

    #[tokio::test]
    async fn tcp_policy_isolates_overrides_without_changing_transport() {
        let inspect = service_fn(async |input: ConnectRequest| {
            assert!(!input.extensions().contains::<TargetHttpVersion>());
            assert!(
                !input
                    .extensions()
                    .contains::<rama_net::client::ConnectorTransportProtocol>()
            );
            let id = crate::client::HttpConnIdentifier::new().id(&input).unwrap();
            Ok::<_, ConnectionError>(EstablishedClientConnection {
                input,
                conn: ServiceInput {
                    input: id,
                    extensions: Extensions::new(),
                },
            })
        });
        let policy = TlsPoolPolicy::new(
            inspect,
            HttpTlsPoolConfig::new(rama_tls::client::TlsClientConfig::new(), |extensions| {
                rama_tls::client::TlsClientPoolKey::from_extensions(extensions, TlsBackend::Rustls)
            }),
        );
        let cached = policy.serve(request()).await.unwrap().conn.input;
        assert_eq!(cached, policy.serve(request()).await.unwrap().conn.input);
        let changed = || {
            let request = request();
            request
                .extensions()
                .insert(rama_tls::client::TlsServerCertPins::new(
                    rama_tls::client::TlsServerCertPin::SpkiSha256([1; 32]),
                ));
            request
        };
        let fresh = policy.serve(changed()).await.unwrap().conn.input;
        assert_ne!(cached, fresh);
        assert_eq!(fresh, policy.serve(changed()).await.unwrap().conn.input);
    }

    #[tokio::test]
    async fn policy_partitions_pool_before_lookup() {
        let inspect = service_fn(async |input: ConnectRequest| {
            assert_eq!(
                input.extensions().get_ref::<TargetHttpVersion>().unwrap().0,
                Version::HTTP_3
            );
            let id = crate::client::HttpConnIdentifier::new().id(&input).unwrap();
            Ok::<_, ConnectionError>(EstablishedClientConnection {
                input,
                conn: ServiceInput {
                    input: id,
                    extensions: Extensions::new(),
                },
            })
        });
        let policy = Http3Policy::new(
            inspect,
            rama_tls::client::TlsClientConfig::new(),
            rama_tls::TlsBackend::Auto,
        );
        let first = policy.serve(request()).await.unwrap().conn.input;
        let second = policy.serve(request()).await.unwrap().conn.input;
        assert_eq!(first, second);
        let conflicting = request();
        conflicting
            .extensions()
            .insert(TargetHttpVersion(Version::HTTP_2));
        assert_eq!(
            policy.serve(conflicting).await.unwrap_err().kind(),
            ConnectionErrorKind::InvalidInput
        );
        let overridden = || {
            let request = request();
            request.extensions().insert(rama_tls::client::TlsServerName(
                "other.example".parse().unwrap(),
            ));
            request
        };
        let override_id = policy.serve(overridden()).await.unwrap().conn.input;
        assert_ne!(first, override_id);
        assert_eq!(
            override_id,
            policy.serve(overridden()).await.unwrap().conn.input
        );
        assert_ne!(
            first,
            crate::client::HttpConnIdentifier::new()
                .id(&request())
                .unwrap()
        );
    }
}
