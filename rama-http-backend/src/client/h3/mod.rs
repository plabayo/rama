//! HTTP/3 establishment using Rama DNS candidates and the existing multiplex pool.

pub(crate) mod coalescing;
#[doc(inline)]
pub use coalescing::Http3Coalescing;

#[cfg(test)]
mod tests;

use super::Http3Transport;
use coalescing::PendingAliases;
use parking_lot::Mutex;
use rama_core::{
    Service,
    error::{ArcError, BoxError, BoxErrorExt as _, error_chain},
    extensions::ExtensionsRef,
    futures::{FutureExt as _, StreamExt as _, stream},
    rt::Executor,
    telemetry::tracing,
};
use rama_http_core::h3::connection::Config;
use rama_http_types::{
    Version,
    conn::TargetHttpVersion,
    proto::h3::{
        ClientSettingsProfile, control::ClientControlPreferences,
        critical_streams::Preferences as CriticalStreamPreferences, qpack::EncoderPreferences,
    },
};
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
    tls::{AlpnPolicy, ApplicationProtocol, TlsAlpn},
};
use rama_quic::{
    ClientConfig, ConnectError as QuicConnectError, Connection,
    ConnectionError as QuicConnectionError, Endpoint, EndpointConfig, TransportConfig,
    tls::{ClientConfigCache, QuicClientConfigProvider, TlsOptions, default_tls_provider},
};
use rama_quic_proto::{
    TransportErrorCode,
    profile::{QuicProfile, TransportLimits},
};
use rama_tls::{
    alpn::required_alpn_override,
    client::{
        TlsClientConfig, TlsConnectionReuse, TlsServerAuthentication, TlsServerName,
        TlsStoreServerCertChain,
    },
};
use rama_utils::macros::generate_set_and_with;
use std::{
    collections::VecDeque,
    error::Error as StdError,
    io::{Error as IoError, ErrorKind as IoErrorKind},
    net::{IpAddr, SocketAddr},
    sync::Arc,
};
use tokio::sync::Mutex as AsyncMutex;

// Allow the alternate address family to progress while one QUIC handshake is waiting,
// without starting a handshake (and its retransmission state) for every DNS result.
const MAX_IN_FLIGHT_CONNECT_ATTEMPTS: usize = 2;
const MAX_CACHED_PROFILE_ENDPOINTS: usize = 8;

/// Establish authenticated QUIC transports for the common HTTP handshake.
///
/// Wrap this connector with Rama's DNS connector and HTTP connection pool,
/// which checks the reuse policy published by this connector. TLS overrides
/// are classified by the same provider that configures the handshake.
/// Requests may supply an explicit ALPN offer containing `h3`; otherwise the
/// connector offers `h3` alone. The origin hostname remains the TLS
/// verification target even when routing selects a different physical address.
/// This direct UDP connector rejects proxy routes before any connection attempt.
/// Proxy-capable QUIC connectors can be injected separately.
///
/// A [`QuicProfile`] on the input applies to the client, transport and endpoint.
/// The default HTTP pool identifier includes explicit profiles by value; custom
/// identifiers must preserve that separation. Managed endpoints cache at most
/// eight endpoint policies. Zero-length local CIDs use a fresh bound endpoint
/// for each address-race attempt. A supplied zero-CID endpoint accepts one
/// connection at a time, so address attempts on it run sequentially.
pub struct Http3Connector {
    endpoint: Arc<ConnectorEndpoint>,
    tls: TlsClientConfig,
    tls_configs: ClientConfigCache,
    transport: Arc<TransportConfig>,
    config: Arc<Config>,
    executor: Executor,
}

// Only endpoints owned by this connector may be rebound after their driver exits.
// Supplied endpoints retain the application's explicit lifecycle and socket policy.
#[derive(Debug)]
enum ConnectorEndpoint {
    Supplied(Endpoint),
    Managed(AsyncMutex<ManagedEndpoints>),
}

#[derive(Debug, Default)]
struct ManagedEndpoints {
    default: Option<Endpoint>,
    profiles: VecDeque<(EndpointProfileKey, Endpoint)>,
}

// Only endpoint-wide wire properties determine socket compatibility. Packet
// layouts and parameter permutations remain per-connection client configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct EndpointProfileKey {
    cid_len: u8,
    grease_quic_bit: bool,
    max_udp_payload_size: u64,
}

impl EndpointProfileKey {
    fn of(profile: &QuicProfile) -> Self {
        Self {
            cid_len: profile.connection_ids().local_len(),
            grease_quic_bit: profile.greases_quic_bit(),
            max_udp_payload_size: profile.limits().max_udp_payload_size,
        }
    }
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
            .field("endpoint", &self.endpoint)
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
        /// HTTP/3 requires ALPN by default. With [`AlpnPolicy::OutOfBandAgreement`],
        /// an explicitly empty ALPN offer is preserved for known HTTP/3 peers.
        /// The selected QUIC TLS backend must support this mode.
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
    /// If the runtime shuts down, a later attempt recreates the owned endpoint,
    /// provided the configured graceful executor has not been cancelled.
    /// An application-supplied endpoint is used immediately and is never replaced.
    pub fn build_lazy(self) -> Result<Http3Connector, BoxError> {
        let mut transport = TransportConfig::default();
        self.config.configure_transport(&mut transport)?;
        let provider = match self.provider {
            Some(provider) => provider,
            None => default_tls_provider()?,
        };

        Ok(Http3Connector {
            endpoint: Arc::new(match self.endpoint {
                Some(endpoint) => ConnectorEndpoint::Supplied(endpoint),
                None => ConnectorEndpoint::Managed(AsyncMutex::new(ManagedEndpoints::default())),
            }),
            tls: self.tls,
            tls_configs: ClientConfigCache::new(provider, TlsOptions::default()),
            transport: Arc::new(transport),
            config: Arc::new(self.config),
            executor: self.executor,
        })
    }
}

/// Values derived once from the effective TLS configuration for one dial.
struct PreparedTls {
    alpn_policy: AlpnPolicy,
    profile: Option<Arc<QuicProfile>>,
    config: ClientConfig,
    server_name: String,
    authenticated_identity: Option<Host>,
    capture_chain: bool,
    policy_scope: ConnectionPolicyScope,
    reuse: TlsConnectionReuse<Arc<dyn QuicClientConfigProvider>>,
    aliases: Option<PendingAliases>,
}

impl Http3Connector {
    async fn endpoint(&self) -> Result<Endpoint, BoxError> {
        let endpoint = match self.endpoint.as_ref() {
            ConnectorEndpoint::Supplied(endpoint) => return Ok(endpoint.clone()),
            ConnectorEndpoint::Managed(endpoint) => endpoint,
        };
        if self
            .executor
            .guard()
            .is_some_and(|guard| guard.cancelled().now_or_never().is_some())
        {
            return Err(BoxError::from_static_str(
                "HTTP/3 connector is shutting down",
            ));
        }
        let mut managed = endpoint.lock().await;
        let endpoint = &mut managed.default;
        if let Some(endpoint) = endpoint.as_ref().filter(|endpoint| !endpoint.is_closed()) {
            return Ok(endpoint.clone());
        }

        // Reuse QUIC's dual-stack socket policy, including IPv4 fallback.
        // A driver lost with its runtime is recreated in the requesting runtime;
        // the configured graceful executor still controls its shutdown lifetime.
        let bound = match Endpoint::bind_client(
            self.executor.clone(),
            SocketAddress::default_ipv6(0),
        )
        .await
        {
            Ok(endpoint) => endpoint,
            Err(error) => {
                tracing::debug!(%error, "binding IPv4 H3 endpoint after IPv6 bind failed");
                Endpoint::bind_client(self.executor.clone(), SocketAddress::default_ipv4(0)).await?
            }
        };
        *endpoint = Some(bound.clone());
        Ok(bound)
    }

    async fn endpoint_for_profile(
        &self,
        profile: Option<&QuicProfile>,
    ) -> Result<Endpoint, BoxError> {
        let Some(profile) = profile else {
            return self.endpoint().await;
        };
        let managed = match self.endpoint.as_ref() {
            ConnectorEndpoint::Supplied(endpoint) => {
                return Ok(endpoint.clone());
            }
            ConnectorEndpoint::Managed(managed) => managed,
        };
        if self
            .executor
            .guard()
            .is_some_and(|guard| guard.cancelled().now_or_never().is_some())
        {
            return Err(BoxError::from_static_str(
                "HTTP/3 connector is shutting down",
            ));
        }
        if profile.connection_ids().local_len() == 0 {
            return self.bind_profile_endpoint(profile).await;
        }

        let key = EndpointProfileKey::of(profile);
        let mut managed = managed.lock().await;
        if let Some(index) = managed
            .profiles
            .iter()
            .position(|(stored, _)| *stored == key)
            && let Some((key, endpoint)) = managed.profiles.remove(index)
            && !endpoint.is_closed()
        {
            managed.profiles.push_back((key, endpoint.clone()));
            return Ok(endpoint);
        }
        let endpoint = self.bind_profile_endpoint(profile).await?;
        if managed.profiles.len() == MAX_CACHED_PROFILE_ENDPOINTS {
            // Active connections keep their endpoint driver and socket alive;
            // dropping a cached handle does not close a connection using it.
            managed.profiles.pop_front();
        }
        managed.profiles.push_back((key, endpoint.clone()));
        Ok(endpoint)
    }

    async fn bind_profile_endpoint(&self, profile: &QuicProfile) -> Result<Endpoint, BoxError> {
        let mut config = EndpointConfig::try_with_rand_key()?;
        config.apply_quic_profile(profile)?;
        match Endpoint::build(self.executor.clone())
            .with_config(config.clone())
            .bind_client_address(SocketAddress::default_ipv6(0))
            .await
        {
            Ok(endpoint) => Ok(endpoint),
            Err(error) => {
                tracing::debug!(%error, "binding IPv4 profile endpoint after IPv6 bind failed");
                Ok(Endpoint::build(self.executor.clone())
                    .with_config(config)
                    .bind_client_address(SocketAddress::default_ipv4(0))
                    .await?)
            }
        }
    }

    fn prepare_connection(
        &self,
        input: &ConnectRequest,
    ) -> Result<(PreparedTls, Arc<Config>), ConnectionError> {
        let profile = input.extensions().get_arc::<QuicProfile>();
        let mut tls = self.tls.clone().with_overrides(input.extensions());
        let alpn_policy = tls
            .as_extensions()
            .get_ref::<AlpnPolicy>()
            .copied()
            .unwrap_or_default();
        let omit_alpn = alpn_policy == AlpnPolicy::OutOfBandAgreement
            && tls
                .as_extensions()
                .get_ref::<TlsAlpn>()
                .is_some_and(|offer| offer.0.is_empty());
        if !omit_alpn
            && let Some(required) = required_alpn_override(
                ApplicationProtocol::HTTP_3,
                input.extensions().get_ref::<TlsAlpn>(),
            )
        {
            tls.set_alpn([required].into_iter().collect());
        }
        let server_identity = tls
            .as_extensions()
            .get_ref::<TlsServerName>()
            .map_or_else(|| input.authority.host.clone(), |name| name.0.clone());
        let authenticated_identity = self
            .tls_provider()
            .authenticates_server(tls.as_extensions())
            .then(|| server_identity.clone());
        let reuse = TlsConnectionReuse::new(self.tls_provider().clone(), input.extensions());
        let policy_scope = reuse.policy_scope();
        let policy_scope = if let Some(attempt) = input.extensions().get_ref::<ConnectionAttempt>()
        {
            let identity = self
                .tls_provider()
                .authenticates_origin(tls.as_extensions(), &input.authority.host)
                .then_some(authenticated_identity.as_ref())
                .flatten();
            attempt.check_policy(policy_scope, identity)?;
            attempt.policy_scope()
        } else {
            policy_scope
        };
        let capture_chain = tls
            .as_extensions()
            .get_ref::<TlsStoreServerCertChain>()
            .is_some_and(|capture| capture.0);
        let profile = profile.map(with_critical_stream_credit);
        let mut h3_config = match input.extensions().get_ref::<ClientSettingsProfile>() {
            Some(settings) => {
                let datagrams = match profile.as_deref() {
                    Some(profile) => TransportConfig::from_quic_profile(profile)
                        .map_err(|error| ConnectionError::local(error, InvalidInput))?
                        .datagram_receive_enabled(),
                    None => self.transport.datagram_receive_enabled(),
                };
                // A captured datagram grant without QUIC reception is dropped while fitting.
                let config = if datagrams || self.config.datagrams.is_none() {
                    self.config.try_with_client_settings(settings.0.clone())
                } else {
                    Config {
                        datagrams: None,
                        ..(*self.config).clone()
                    }
                    .try_with_client_settings(settings.0.clone())
                };
                Arc::new(config.map_err(|error| ConnectionError::local(error, InvalidInput))?)
            }
            None => self.config.clone(),
        };
        if let Some(preferences) = input.extensions().get_ref::<CriticalStreamPreferences>() {
            Arc::make_mut(&mut h3_config).critical_streams = *preferences;
        }
        if let Some(preferences) = input.extensions().get_ref::<EncoderPreferences>() {
            Arc::make_mut(&mut h3_config)
                .encoder
                .apply_preferences(*preferences);
        }
        if let Some(preferences) = input.extensions().get_arc::<ClientControlPreferences>() {
            Arc::make_mut(&mut h3_config)
                .try_set_client_controls(Some(preferences))
                .map_err(|error| ConnectionError::local(error, InvalidInput))?;
        }
        let mut config = self
            .tls_configs
            .client_config_for_peer(&tls, input.extensions(), &server_identity)
            .map_err(|error| ConnectionError::local(error, InvalidInput))?;
        if let Some(profile) = &profile {
            config
                .apply_quic_profile(profile)
                .map_err(|error| ConnectionError::local(error, InvalidInput))?;
        } else {
            config.set_transport_config(self.transport.clone());
        }
        let server_name = if let Ok(ip) = server_identity.try_as_ip() {
            ip.to_string()
        } else {
            server_identity
                .try_as_domain()
                .map_err(|_error| {
                    ConnectionError::local(
                        BoxError::from_static_str("invalid TLS origin host"),
                        InvalidInput,
                    )
                })?
                .to_string()
        };
        let aliases = PendingAliases::new(input, tls, authenticated_identity.as_ref());
        Ok((
            PreparedTls {
                alpn_policy,
                profile,
                config,
                server_name,
                authenticated_identity,
                capture_chain,
                policy_scope,
                reuse,
                aliases,
            },
            h3_config,
        ))
    }

    async fn connect(
        &self,
        input: &ConnectRequest,
        prepared: &PreparedTls,
    ) -> Result<(Endpoint, Connection), ConnectionError> {
        let tls = &prepared.config;
        let server_name = prepared.server_name.as_str();
        let target = input.connector_target().ok_or_else(|| {
            ConnectionError::local(
                BoxError::from_static_str("HTTP/3 connector target is missing"),
                InvalidInput,
            )
        })?;
        let attempt = input
            .extensions()
            .get_arc::<ConnectionAttempt>()
            .unwrap_or_default();
        let attempt = &attempt;
        let failures = ConnectFailures::default();
        let failures = &failures;
        let zero_cid = prepared
            .profile
            .as_ref()
            .is_some_and(|profile| profile.connection_ids().local_len() == 0);
        let supplied = matches!(self.endpoint.as_ref(), ConnectorEndpoint::Supplied(_));
        let shared_endpoint = if zero_cid && !supplied {
            None
        } else {
            Some(
                self.endpoint_for_profile(prepared.profile.as_deref())
                    .await
                    .map_err(|error| {
                        ConnectionError::local(error, Unavailable)
                            .context("binding HTTP/3 endpoint")
                    })?,
            )
        };
        let shared_endpoint = &shared_endpoint;
        let dial = |address| async move {
            let result: Result<_, BoxError> = async {
                let endpoint = match shared_endpoint {
                    Some(endpoint) => endpoint.clone(),
                    None => self
                        .endpoint_for_profile(prepared.profile.as_deref())
                        .await
                        .map_err(|error| {
                            ConnectionError::local(error, Unavailable)
                                .context("binding HTTP/3 profile endpoint")
                        })?,
                };
                let connection = endpoint
                    .connect_with(tls.clone(), address, server_name)?
                    .await?;
                connection.handshake_confirmed().await?;
                let negotiated = connection
                    .handshake_data()
                    .and_then(|data| data.application_layer_protocol);
                if !prepared
                    .alpn_policy
                    .accepts(&ApplicationProtocol::HTTP_3, negotiated.as_ref())
                {
                    connection.close(0u32, b"h3 ALPN required");
                    return Err(ConnectionError::application(
                        BoxError::from_static_str(
                            "HTTP/3 requires h3 ALPN or explicit out-of-band agreement",
                        ),
                        ConnectionErrorKind::Protocol,
                    )
                    .into());
                }
                Ok((endpoint, connection))
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
            let domain = target.host.try_as_domain().map_err(|_error| {
                ConnectionError::local(
                    BoxError::from_static_str("unsupported HTTP/3 target host"),
                    InvalidInput,
                )
            })?;
            let candidates = input
                .extensions()
                .get_ref::<ConnectorTargetStream>()
                .filter(|c| c.domain() == domain.as_ref())
                .ok_or_else(|| {
                    ConnectionError::local(
                        BoxError::from_static_str(
                            "HTTP/3 domain targets require an outer DNS connector",
                        ),
                        InvalidInput,
                    )
                })?;
            // Resolution policy chooses which records to query; connection
            // policy independently constrains every result, including custom
            // candidate sources and IPv4-mapped IPv6 answers.
            let mode = input
                .extensions()
                .get_ref::<ConnectIpMode>()
                .copied()
                .unwrap_or_default();
            let addresses = candidates.stream(input.extensions()).map(|result| {
                result.and_then(|ip| {
                    mode.validate_ip(ip)
                        .map(|ip| SocketAddr::new(ip, target.port))
                        .map_err(|error| ConnectionError::local(error, InvalidInput).into())
                })
            });
            let concurrency = if zero_cid && supplied {
                1
            } else {
                MAX_IN_FLIGHT_CONNECT_ATTEMPTS
            };
            race_connect(addresses, concurrency, dial).await
        }
        .map(|(_, connection)| connection)
        .map_err(|error| {
            failures
                .finish(error)
                .context("HTTP/3 connection establishment")
        })
    }

    fn set_connection_extensions(
        endpoint: &Endpoint,
        connection: &Connection,
        prepared: PreparedTls,
    ) {
        // Populate only connection facts: inheriting the request store here would
        // retain request metadata and could create a cycle through Egress.
        let extensions = connection.extensions();
        prepared.reuse.publish(extensions);
        extensions.insert(prepared.alpn_policy);
        extensions.insert(TargetHttpVersion(Version::HTTP_3));
        extensions.insert(TlsServerAuthentication(prepared.authenticated_identity));
        extensions.insert(prepared.policy_scope);
        extensions.insert(EstablishedProxyRoute::Direct);
        extensions.insert(SocketInfo::new(
            known_local_address(endpoint.local_addr().ok(), connection.local_ip()),
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

/// `profile` granting at least the peer's three critical unidirectional streams.
fn with_critical_stream_credit(profile: Arc<QuicProfile>) -> Arc<QuicProfile> {
    let captured = profile.limits().initial_max_streams_uni;
    if captured >= 3 {
        return profile;
    }
    let limits = TransportLimits {
        initial_max_streams_uni: 3,
        ..profile.limits().clone()
    };
    match (*profile).clone().try_with_limits(limits) {
        Ok(raised) => {
            tracing::debug!(
                captured,
                "HTTP/3 QUIC profile raises unidirectional stream credit to three critical streams"
            );
            Arc::new(raised)
        }
        Err(error) => {
            tracing::debug!(%error, "HTTP/3 QUIC profile keeps its unidirectional stream credit");
            profile
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
        if input.target_protocol().is_none_or(|p| !p.is_secure()) {
            return Err(ConnectionError::local(
                BoxError::from_static_str("HTTP/3 requires a secure origin"),
                InvalidInput,
            ));
        }
        validate_version(&input)?;

        let (mut prepared, h3_config) = self.prepare_connection(&input)?;
        // Keep QUIC address-race and handshake state out of enclosing pool and
        // service-selection futures. Allocate only when opening a connection;
        // either transport's pool hits bypass this boundary entirely.
        let (endpoint, connection) = Box::pin(self.connect(&input, &prepared)).await?;
        let aliases = prepared.aliases.take();
        Self::set_connection_extensions(&endpoint, &connection, prepared);
        if let Some(aliases) = aliases {
            aliases.verify(&connection, self.tls_provider().as_ref());
        }
        input
            .extensions()
            .insert(TargetHttpVersion(Version::HTTP_3));

        let conn = Http3Transport {
            connection,
            config: h3_config,
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
        return Err(ConnectionError::local(
            BoxError::from_static_str("explicit HTTP version conflicts with HTTP/3 connector"),
            InvalidInput,
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

// RFC 7301 §3.2: negotiation failed because the peer supports no offered ALPN.
const TLS_NO_APPLICATION_PROTOCOL: u8 = 120;

// Classify QUIC address-race failures at the transport boundary. Generic HTTP
// service selection consumes ConnectionError classifications, never QUIC errors.
fn classify_connect_error(
    error: &(dyn StdError + 'static),
) -> (ConnectionErrorDomain, ConnectionErrorKind) {
    for error in error_chain(error) {
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
                QuicConnectionError::CidsExhausted
                | QuicConnectionError::EndpointInUse
                | QuicConnectionError::LocallyClosed => (Local, Unavailable),
                QuicConnectionError::TransportError(error) => classify_transport_code(error.code),
                QuicConnectionError::ConnectionClosed(error) => {
                    classify_transport_code(error.error_code)
                }
            };
        }
        if let Some(error) = error.downcast_ref::<QuicConnectError>() {
            return match error {
                QuicConnectError::EndpointStopping
                | QuicConnectError::CidsExhausted
                | QuicConnectError::EndpointInUse => (Local, Unavailable),
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
        address::{Domain, HostWithPort, SocketAddress},
        client::{
            AddressCandidates, ConnectionErrorDomain, ProxyRouteFailureCache,
            ProxyRouteFailureCacheConnector, ProxyRoutes, ProxyRoutesConnector, pool::ReuseKey,
        },
        tls::TlsAlpn,
    };
    use std::assert_matches;

    use rama_core::{extensions::Extensions, graceful::Shutdown};
    use rama_core::{futures::stream::BoxStream, rt::spawn};
    use rama_crypto::pki_types::CertificateDer;
    use rama_http_core::h3::{
        client as h3_client,
        observation::{H3Observer, SettingsObservation},
        server as h3_server,
    };
    use rama_http_types::{
        Body, Request, Response,
        proto::h3::{SettingId, Settings},
    };
    use rama_net::client::ConnectorTarget;
    use rama_quic::{ServerConfig, tls::TlsConfigError};
    use rama_quic_proto::{
        TransportError,
        frame::ApplicationClose,
        profile::{
            ConnectionIdProfile, ParameterOrder, TransportLimits, TransportParameterProfile,
        },
        transport_parameters::TransportParameterId,
    };
    use rama_quic_proto::{
        VarInt,
        capture::{CaptureLimits, QuicObservation},
        coding::Codec,
        version::{ClientVersionPolicy, Version as QuicVersion},
    };
    use rama_tls::client::{ServerVerifyMode, TlsClientConfigProvider, TlsPoolId, TlsServerVerify};
    use rama_tls::server::{LeafCertRequest, ServerAuthData, TlsServerConfig};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;
    use tokio::{runtime::Runtime, sync::oneshot, time::Instant};

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

        fn pool_classifier(&self) -> ReuseKey {
            ReuseKey::of::<Self>()
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
        fn peer_matches_name(&self, _: &Extensions, _: &CertificateDer<'_>, _: &Host) -> bool {
            false
        }

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
    async fn http3_without_alpn_requires_explicit_agreement() {
        tokio::time::timeout(Duration::from_secs(20), async {
            for (base_policy, request_policy) in [
                (None, None),
                (Some(AlpnPolicy::Require), None),
                (Some(AlpnPolicy::OutOfBandAgreement), None),
                (None, Some(AlpnPolicy::OutOfBandAgreement)),
                (
                    Some(AlpnPolicy::Require),
                    Some(AlpnPolicy::OutOfBandAgreement),
                ),
                (
                    Some(AlpnPolicy::OutOfBandAgreement),
                    Some(AlpnPolicy::Require),
                ),
            ] {
                let policy = request_policy.or(base_policy);
                let identity =
                    ServerAuthData::new_self_signed_leaf(LeafCertRequest::default()).unwrap();
                let server_tls = TlsServerConfig::new()
                    .with_server_auth(identity)
                    .with_alpn(Default::default());
                let server = Endpoint::bind_server(
                    Executor::new(),
                    ServerConfig::try_from_rama_tls(
                        &server_tls,
                        TlsOptions::default().with_alpn(AlpnPolicy::OutOfBandAgreement),
                    )
                    .unwrap(),
                    SocketAddress::local_ipv4(0),
                )
                .await
                .unwrap();
                let address = server.local_addr().unwrap();
                let accept = server.clone();
                let serve = spawn(async move {
                    let connecting = accept.accept().await.unwrap().accept().unwrap();
                    let Ok(connection) = connecting.await else {
                        return;
                    };
                    assert!(
                        connection
                            .handshake_data()
                            .unwrap()
                            .application_layer_protocol
                            .is_none()
                    );
                    connection
                        .extensions()
                        .insert(AlpnPolicy::OutOfBandAgreement);
                    let (mut http, driver) =
                        h3_server::handshake(connection, Config::default()).unwrap();
                    spawn(driver.run());
                    let (_, response) = http.accept().await.unwrap().resolve().await.unwrap();
                    response
                        .send_response(Response::new(Body::empty()))
                        .await
                        .unwrap();
                    // Keep the HTTP service alive until the test closes the endpoint.
                    drop(http.accept().await);
                });
                let mut tls = TlsClientConfig::new()
                    .with_server_verify(ServerVerifyMode::Disable)
                    .with_alpn(Default::default());
                if let Some(policy) = base_policy {
                    tls.set_alpn_policy(policy);
                }
                let connector = Http3Connector::builder(Executor::new())
                    .with_tls_config(tls)
                    .build_lazy()
                    .unwrap();
                let input = ConnectRequest::new(HostWithPort::local_ipv4(address.port()))
                    .with_application_protocol(Protocol::HTTPS);
                if let Some(policy) = request_policy {
                    input.extensions().insert(policy);
                }
                let result = connector.serve(input).await;
                assert_eq!(
                    result.is_ok(),
                    policy == Some(AlpnPolicy::OutOfBandAgreement),
                    "{policy:?}"
                );
                if let Ok(established) = result {
                    let connection = established.conn.connection.clone();
                    let established = crate::client::http_connect::<_, _, Body>(
                        established.conn,
                        established.input,
                        Executor::new(),
                    )
                    .await
                    .unwrap();
                    let request = Request::builder()
                        .version(Version::HTTP_3)
                        .uri(format!("https://{address}/"))
                        .body(Body::empty())
                        .unwrap();
                    let response = established.conn.serve(request).await.unwrap();
                    assert_eq!(response.version(), Version::HTTP_3);
                    assert!(
                        connection
                            .handshake_data()
                            .unwrap()
                            .application_layer_protocol
                            .is_none()
                    );
                    connection.close(0u32, b"done");
                }
                serve.abort();
                server.close(0u32, b"done");
            }
        })
        .await
        .expect("HTTP/3 no-ALPN matrix deadline");
    }

    #[cfg(feature = "boring")]
    #[test]
    fn boring_rejects_unsupported_alpnless_http3_configuration() {
        let connector = Http3Connector::builder(Executor::new())
            .with_tls_provider(Arc::new(rama_quic::tls::BoringTlsProvider))
            .with_tls_config(
                TlsClientConfig::new()
                    .with_alpn_policy(AlpnPolicy::OutOfBandAgreement)
                    .with_alpn(Default::default()),
            )
            .build_lazy()
            .unwrap();
        let input = ConnectRequest::new(HostWithPort::local_ipv4(443))
            .with_application_protocol(Protocol::HTTPS);
        let error = connector.prepare_connection(&input).err().unwrap();
        assert!(rama_core::error::error_chain(&error).any(|cause| {
            matches!(
                cause.downcast_ref::<TlsConfigError>(),
                Some(TlsConfigError::UnsupportedOutOfBandAgreement)
            )
        }));
    }

    #[tokio::test]
    async fn explicit_alpn_conflicts_are_lowered_to_http3() {
        for offer in [TlsAlpn::empty(), TlsAlpn::http_auto()] {
            let provider = Arc::new(CustomProvider::default());
            let connector = Http3Connector::builder(Executor::new())
                .with_tls_provider(provider.clone())
                .build_lazy()
                .unwrap();
            let input = ConnectRequest::new(HostWithPort::local_ipv4(443))
                .with_application_protocol(Protocol::HTTPS);
            input.extensions().insert(offer);
            input
                .extensions()
                .insert(TlsServerVerify(ServerVerifyMode::Disable));
            // The provider asserts it is handed exactly the HTTP/3 offer.
            drop(connector.serve(input).await.err().unwrap());
            assert_eq!(provider.calls.load(Ordering::Relaxed), 1);
        }
    }

    #[tokio::test]
    async fn captured_h3_datagrams_without_quic_reception_are_dropped() {
        for (window, advertised) in [(None, None), (Some(0), None), (Some(4096), Some(0))] {
            for request_settings in [false, true] {
                let mut settings = Settings::default();
                settings.set(SettingId::H3_DATAGRAM, 1).unwrap();
                let settings = Arc::new(settings);
                let config = if request_settings {
                    Config::default()
                } else {
                    Config::default()
                        .try_with_client_settings(settings.clone())
                        .unwrap()
                };
                let connector = Http3Connector::builder(Executor::new())
                    .with_config(config)
                    .build_lazy()
                    .unwrap();
                let input = ConnectRequest::new(HostWithPort::local_ipv4(443))
                    .with_application_protocol(Protocol::HTTPS);
                input
                    .extensions
                    .insert(TlsServerVerify(ServerVerifyMode::Disable));
                // Without a version switch every TLS provider accepts the profile.
                let profile = QuicProfile::standard()
                    .with_versions(ClientVersionPolicy::new(QuicVersion::V1).unwrap())
                    .with_transport_parameters(
                        TransportParameterProfile::standard()
                            .try_with_max_datagram_frame_size(advertised)
                            .unwrap(),
                    )
                    .try_with_limits(TransportLimits {
                        datagram_receive_buffer_size: window,
                        ..TransportLimits::standard()
                    })
                    .unwrap();
                input.extensions.insert(profile);
                if request_settings {
                    input.extensions.insert(ClientSettingsProfile(settings));
                }
                let (_, h3_config) = connector.prepare_connection(&input).unwrap();
                if request_settings {
                    assert!(!h3_config.settings_profile.as_ref().unwrap().h3_datagram());
                    assert!(h3_config.datagrams.is_none());
                }
            }
        }
    }

    #[tokio::test]
    async fn captured_h3_without_datagrams_allows_quic_reception_disabled() {
        let provider = Arc::new(CustomProvider::default());
        let connector = Http3Connector::builder(Executor::new())
            .with_tls_provider(provider.clone())
            .build_lazy()
            .unwrap();
        let input = ConnectRequest::new(HostWithPort::local_ipv4(443))
            .with_application_protocol(Protocol::HTTPS);
        input
            .extensions
            .insert(TlsServerVerify(ServerVerifyMode::Disable));
        input
            .extensions
            .insert(ClientSettingsProfile(Arc::new(Settings::default())));
        input.extensions.insert(
            QuicProfile::standard()
                .try_with_limits(TransportLimits {
                    datagram_receive_buffer_size: None,
                    ..TransportLimits::standard()
                })
                .unwrap(),
        );
        // This fixture provider deliberately fails once reached. Its call count
        // proves the compatible profile passes the cross-protocol preflight.
        let error = connector.serve(input).await.err().unwrap();
        assert_eq!(error.kind(), ConnectionErrorKind::InvalidInput);
        assert_eq!(provider.calls.load(Ordering::Relaxed), 1);
    }

    struct RepeatedAddress {
        domain: Domain,
        address: IpAddr,
    }

    impl AddressCandidates for RepeatedAddress {
        fn domain(&self) -> &Domain {
            &self.domain
        }

        fn stream<'a>(&'a self, _: &'a Extensions) -> BoxStream<'a, Result<IpAddr, BoxError>> {
            Box::pin(stream::iter([Ok(self.address), Ok(self.address)]))
        }
    }

    #[tokio::test]
    async fn supplied_zero_cid_endpoint_retries_after_peer_refusal() {
        tokio::time::timeout(Duration::from_secs(10), async {
            let identity =
                ServerAuthData::new_self_signed_leaf(LeafCertRequest::default()).unwrap();
            let server_tls = TlsServerConfig::new()
                .with_alpn([ApplicationProtocol::HTTP_3].into_iter().collect())
                .with_server_auth(identity.clone());
            let server = Endpoint::bind_server(
                Executor::new(),
                ServerConfig::try_from_rama_tls(&server_tls, TlsOptions::default()).unwrap(),
                SocketAddress::local_ipv4(0),
            )
            .await
            .unwrap();
            let address = server.local_addr().unwrap();
            let accept = server.clone();
            let serve = spawn(async move {
                // Reuse one peer address to isolate endpoint admission from DNS
                // ordering, IP-family policy and local-interface availability.
                accept.accept().await.unwrap().refuse();
                let connection = accept
                    .accept()
                    .await
                    .unwrap()
                    .accept()
                    .unwrap()
                    .await
                    .unwrap();
                let (mut send, _) = connection.accept_bi().await.unwrap();
                send.write_all(b"accepted after refusal").await.unwrap();
                send.finish().unwrap();
                connection
            });
            let profile = QuicProfile::standard()
                .with_versions(ClientVersionPolicy::new(QuicVersion::V1).unwrap())
                .with_connection_ids(
                    ConnectionIdProfile::standard()
                        .try_with_local_len(0)
                        .unwrap(),
                );
            let mut endpoint_config = EndpointConfig::try_with_rand_key().unwrap();
            endpoint_config.apply_quic_profile(&profile).unwrap();
            let endpoint = Endpoint::build(Executor::new())
                .with_config(endpoint_config)
                .bind_client_address(SocketAddress::local_ipv4(0))
                .await
                .unwrap();
            let connector = Http3Connector::builder(Executor::new())
                .with_endpoint(endpoint.clone())
                .with_tls_config(
                    TlsClientConfig::new()
                        .try_with_server_trust_anchors([identity
                            .cert_chain
                            .last()
                            .unwrap()
                            .clone()])
                        .unwrap(),
                )
                .build_lazy()
                .unwrap();
            let input =
                ConnectRequest::new(HostWithPort::localhost_domain_with_port(address.port()))
                    .with_application_protocol(Protocol::HTTPS);
            input.extensions.insert(profile);
            input
                .extensions
                .insert(ConnectorTargetStream::new(RepeatedAddress {
                    domain: "localhost".parse().unwrap(),
                    address: address.ip(),
                }));
            let transport = connector.serve(input).await.unwrap().conn;
            let (mut send, mut recv) = transport.connection.open_bi().await.unwrap();
            send.write_all(b"hello").await.unwrap();
            send.finish().unwrap();
            assert_eq!(
                recv.read_to_end(64).await.unwrap(),
                b"accepted after refusal"
            );
            let peer = serve.await.unwrap();
            transport.connection.close(0u32, b"test complete");
            peer.close(0u32, b"test complete");
            endpoint.shutdown().await;
            server.shutdown().await;
        })
        .await
        .unwrap();
    }

    #[test]
    fn lazy_connector_construction_needs_no_runtime() {
        let connector = Http3Connector::builder(Executor::new())
            .with_tls_provider(Arc::new(CustomProvider::default()))
            .build_lazy()
            .unwrap();
        assert_matches!(connector.endpoint.as_ref(), ConnectorEndpoint::Managed(endpoint) if endpoint.try_lock().unwrap().default.is_none());
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
        let second = second.unwrap();
        assert_eq!(first.local_addr().unwrap(), second.local_addr().unwrap());
        first.close(0u32, b"test complete");
        assert!(second.is_closed());
        first.shutdown().await;
    }

    #[test]
    fn lazy_connector_recovers_after_its_runtime_is_dropped() {
        let connector = Http3Connector::builder(Executor::new())
            .with_tls_provider(Arc::new(CustomProvider::default()))
            .build_lazy()
            .unwrap();
        let runtime = Runtime::new().unwrap();
        let first = runtime.block_on(connector.endpoint()).unwrap();
        assert!(!first.is_closed());
        drop(runtime);
        assert!(first.is_closed());

        let runtime = Runtime::new().unwrap();
        runtime.block_on(async {
            let recovered = connector.endpoint().await.unwrap();
            assert!(!recovered.is_closed());
            assert!(first.is_closed());
            recovered.shutdown().await;
        });
    }

    #[tokio::test]
    async fn cancelled_executor_does_not_initialize_an_endpoint() {
        let (cancel, cancelled) = oneshot::channel::<()>();
        let shutdown = Shutdown::new(async move {
            _ = cancelled.await;
        });
        let guard = shutdown.guard();
        let connector = Http3Connector::builder(Executor::graceful(guard.clone()))
            .with_tls_provider(Arc::new(CustomProvider::default()))
            .build_lazy()
            .unwrap();
        cancel.send(()).unwrap();
        guard.cancelled().await;
        _ = connector.endpoint().await.unwrap_err();
        assert_matches!(connector.endpoint.as_ref(), ConnectorEndpoint::Managed(endpoint) if endpoint.try_lock().unwrap().default.is_none());
    }

    #[tokio::test]
    async fn supplied_endpoint_is_not_replaced_after_shutdown() {
        let endpoint = Endpoint::bind_client(Executor::new(), SocketAddress::local_ipv4(0))
            .await
            .unwrap();
        let connector = Http3Connector::builder(Executor::new())
            .with_tls_provider(Arc::new(CustomProvider::default()))
            .with_endpoint(endpoint.clone())
            .build_lazy()
            .unwrap();
        endpoint.shutdown().await;
        assert!(connector.endpoint().await.unwrap().is_closed());
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
            .endpoint()
            .await
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
            endpoint: Arc::new(ConnectorEndpoint::Supplied(endpoint.clone())),
            tls: TlsClientConfig::default_http(),
            tls_configs: ClientConfigCache::new(
                Arc::new(CustomProvider::default()),
                TlsOptions::default(),
            ),
            transport: Arc::new(TransportConfig::default()),
            config: Arc::new(Config::default()),
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
            assert!(error_chain(error.get_ref()).any(|cause| {
                cause.downcast_ref::<QuicConnectionError>() == Some(&authentication)
            }));
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
            (QuicConnectionError::EndpointInUse, Local, Unavailable),
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
        for error in [
            QuicConnectError::CidsExhausted,
            QuicConnectError::EndpointInUse,
        ] {
            assert_eq!(classify_connect_error(&error), (Local, Unavailable));
        }
    }

    #[tokio::test]
    async fn profile_endpoints_cache_only_endpoint_wide_policy() {
        let connector = Http3Connector::builder(Executor::new())
            .with_tls_provider(Arc::new(CustomProvider::default()))
            .build_lazy()
            .unwrap();
        let profile = QuicProfile::standard();
        let first = connector
            .endpoint_for_profile(Some(&profile))
            .await
            .unwrap();
        let reordered = profile.clone().with_transport_parameters(
            profile
                .transport_parameters()
                .clone()
                .try_with_order(ParameterOrder::fixed(vec![
                    TransportParameterId::MaxIdleTimeout,
                ]))
                .unwrap(),
        );
        let same = connector
            .endpoint_for_profile(Some(&reordered))
            .await
            .unwrap();
        assert_eq!(first.local_addr().unwrap(), same.local_addr().unwrap());
        let changes = [
            profile.clone().with_grease_quic_bit(false),
            profile
                .clone()
                .with_connection_ids((*profile.connection_ids()).try_with_local_len(3).unwrap()),
            profile
                .clone()
                .try_with_limits(TransportLimits {
                    max_udp_payload_size: 1400,
                    ..profile.limits().clone()
                })
                .unwrap(),
        ];
        let mut addresses = vec![first.local_addr().unwrap()];
        let mut endpoints = vec![first];
        for changed in changes {
            let different = connector
                .endpoint_for_profile(Some(&changed))
                .await
                .unwrap();
            let address = different.local_addr().unwrap();
            assert!(!addresses.contains(&address));
            addresses.push(address);
            endpoints.push(different);
        }
        for endpoint in endpoints {
            endpoint.shutdown().await;
        }
    }

    #[tokio::test]
    async fn profile_endpoints_zero_cids_never_share_a_bound_socket() {
        let connector = Http3Connector::builder(Executor::new())
            .with_tls_provider(Arc::new(CustomProvider::default()))
            .build_lazy()
            .unwrap();
        let profile = QuicProfile::standard().with_connection_ids(
            ConnectionIdProfile::standard()
                .try_with_local_len(0)
                .unwrap(),
        );
        let (first, second) = tokio::join!(
            connector.endpoint_for_profile(Some(&profile)),
            connector.endpoint_for_profile(Some(&profile)),
        );
        let first = first.unwrap();
        let second = second.unwrap();
        assert_ne!(first.local_addr().unwrap(), second.local_addr().unwrap());
        let ConnectorEndpoint::Managed(cache) = connector.endpoint.as_ref() else {
            panic!("expected managed endpoints");
        };
        assert!(cache.lock().await.profiles.is_empty());
        first.shutdown().await;
        second.shutdown().await;
    }

    #[tokio::test]
    async fn profile_endpoints_cache_has_a_finite_bound() {
        let connector = Http3Connector::builder(Executor::new())
            .with_tls_provider(Arc::new(CustomProvider::default()))
            .build_lazy()
            .unwrap();
        for len in 1..=(MAX_CACHED_PROFILE_ENDPOINTS + 1) {
            let profile = QuicProfile::standard().with_connection_ids(
                ConnectionIdProfile::standard()
                    .try_with_local_len(len as u8)
                    .unwrap(),
            );
            let _endpoint = connector
                .endpoint_for_profile(Some(&profile))
                .await
                .unwrap();
        }
        let ConnectorEndpoint::Managed(cache) = connector.endpoint.as_ref() else {
            panic!("expected managed endpoints");
        };
        assert_eq!(
            cache.lock().await.profiles.len(),
            MAX_CACHED_PROFILE_ENDPOINTS
        );
    }

    #[tokio::test]
    async fn profile_endpoints_reach_the_peer_and_survive_connector_drop() {
        profile_peer_exchange(false).await;
    }

    #[tokio::test]
    async fn profile_supplied_zero_cid_endpoint_survives_connector_drop() {
        profile_peer_exchange(true).await;
    }

    async fn profile_peer_exchange(supplied: bool) {
        tokio::time::timeout(Duration::from_secs(10), async {
            let identity =
                ServerAuthData::new_self_signed_leaf(LeafCertRequest::default()).unwrap();
            let server_tls = TlsServerConfig::new()
                .with_alpn([ApplicationProtocol::HTTP_3].into_iter().collect())
                .with_server_auth(identity.clone());
            let mut server_config =
                ServerConfig::try_from_rama_tls(&server_tls, TlsOptions::default()).unwrap();
            server_config.set_capture(CaptureLimits::default());
            let server =
                Endpoint::bind_server(Executor::new(), server_config, SocketAddress::local_ipv4(0))
                    .await
                    .unwrap();
            let address = server.local_addr().unwrap();
            let count = if supplied { 1 } else { 2 };
            let accept = server.clone();
            let serve = spawn(async move {
                let mut handlers = Vec::new();
                for _ in 0..count {
                    let connection = accept
                        .accept()
                        .await
                        .unwrap()
                        .accept()
                        .unwrap()
                        .await
                        .unwrap();
                    let remote = connection.remote_address();
                    let observed = connection
                        .extensions()
                        .get_ref::<QuicObservation>()
                        .unwrap()
                        .clone();
                    let (mut http, driver) = h3_server::handshake(
                        connection.clone(),
                        Config {
                            observation: Some(Default::default()),
                            ..Config::default()
                        },
                    )
                    .unwrap();
                    spawn(driver.run());
                    handlers.push(spawn(async move {
                        let (request, response) =
                            http.accept().await.unwrap().resolve().await.unwrap();
                        let observer = request
                            .extensions()
                            .get_ref::<H3Observer>()
                            .unwrap()
                            .clone();
                        let SettingsObservation::Received(settings) = observer
                            .settings(Instant::now() + Duration::from_secs(1))
                            .await
                        else {
                            panic!("client settings were not observed");
                        };
                        let actual: Vec<_> = settings
                            .settings
                            .as_ref()
                            .unwrap()
                            .iter()
                            .map(|setting| (setting.id, setting.value))
                            .collect();
                        assert_eq!(
                            actual,
                            [(SettingId::FIRST_RESERVED.value(), 17), (0xface, 29)]
                        );
                        response
                            .send_response(Response::new(Body::empty()))
                            .await
                            .unwrap();
                        (remote, observed, connection)
                    }));
                }
                let mut results = Vec::new();
                for handler in handlers {
                    results.push(handler.await.unwrap());
                }
                results
            });
            let tls = TlsClientConfig::new()
                .try_with_server_trust_anchors([identity.cert_chain.last().unwrap().clone()])
                .unwrap();
            let profile = QuicProfile::standard()
                .with_versions(ClientVersionPolicy::new(QuicVersion::V1).unwrap())
                .with_connection_ids(
                    ConnectionIdProfile::standard()
                        .try_with_local_len(0)
                        .unwrap(),
                )
                .with_grease_quic_bit(false)
                .try_with_limits(TransportLimits {
                    max_udp_payload_size: 1400,
                    initial_max_data: 1_234_567,
                    ..TransportLimits::standard()
                })
                .unwrap();
            let mut builder = Http3Connector::builder(Executor::new()).with_tls_config(tls);
            if supplied {
                let mut endpoint = EndpointConfig::try_with_rand_key().unwrap();
                endpoint.apply_quic_profile(&profile).unwrap();
                builder = builder.with_endpoint(
                    Endpoint::build(Executor::new())
                        .with_config(endpoint)
                        .bind_client_address(SocketAddress::local_ipv4(0))
                        .await
                        .unwrap(),
                );
            }
            let connector = builder.build_lazy().unwrap();
            let mut transports = Vec::new();
            for _ in 0..count {
                let input =
                    ConnectRequest::new(HostWithPort::localhost_domain_with_port(address.port()))
                        .with_application_protocol(Protocol::HTTPS);
                input
                    .extensions()
                    .insert(ConnectorTarget(HostWithPort::local_ipv4(address.port())));
                input.extensions().insert(profile.clone());
                let mut settings = Settings::new();
                settings.set(SettingId::FIRST_RESERVED, 17).unwrap();
                settings.set(SettingId::new(0xface), 29).unwrap();
                input
                    .extensions()
                    .insert(ClientSettingsProfile(Arc::new(settings)));
                transports.push(connector.serve(input).await.unwrap().conn);
            }
            // Each established connection retains its socket through the driver;
            // neither the connector nor an endpoint-cache entry is needed now.
            drop(connector);
            let connections: Vec<_> = transports
                .iter()
                .map(|transport| transport.connection.clone())
                .collect();
            let mut senders = Vec::new();
            for transport in transports {
                let (mut sender, driver) = h3_client::handshake::<Body>(
                    transport.connection,
                    Arc::unwrap_or_clone(transport.config),
                    Executor::new(),
                )
                .unwrap();
                spawn(driver.run());
                sender
                    .send_request(
                        Request::builder()
                            .uri("https://localhost/")
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                senders.push(sender);
            }
            let results = serve.await.unwrap();
            if !supplied {
                assert_ne!(results[0].0.port(), results[1].0.port());
            }
            for (_, observed, connection) in results {
                assert_eq!(observed.first_flight.as_ref().unwrap().scid_len, 0);
                assert!(
                    !observed
                        .transport_parameters
                        .iter()
                        .any(|parameter| parameter.id == TransportParameterId::GreaseQuicBit)
                );
                let max_udp = observed
                    .transport_parameters
                    .iter()
                    .find(|parameter| parameter.id == TransportParameterId::MaxUdpPayloadSize)
                    .unwrap();
                assert_eq!(
                    VarInt::decode(&mut max_udp.value.as_slice())
                        .unwrap()
                        .into_inner(),
                    1400
                );
                let max_data = observed
                    .transport_parameters
                    .iter()
                    .find(|parameter| parameter.id == TransportParameterId::InitialMaxData)
                    .unwrap();
                assert_eq!(
                    VarInt::decode(&mut max_data.value.as_slice())
                        .unwrap()
                        .into_inner(),
                    1_234_567
                );
                connection.close(0u32, b"test complete");
            }
            for connection in connections {
                connection.close(0u32, b"test complete");
            }
            drop(senders);
            server.shutdown().await;
        })
        .await
        .unwrap();
    }
}
