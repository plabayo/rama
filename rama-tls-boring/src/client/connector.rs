use std::marker::PhantomData;

#[cfg(feature = "http")]
use rama_net::tls::AlpnPolicy;

use rama_boring_tokio::{HandshakeError, SslStream};
use rama_core::{
    Layer, Service,
    conversion::{RamaInto as _, RamaTryInto},
    error::{BoxError, BoxErrorExt as _, CauseExt as _, ErrorContext, ErrorExt},
    extensions::{Extensions, ExtensionsRef},
    io::Io,
    telemetry::tracing,
};
use rama_net::{
    AuthorityInputExt, ConnectorTargetInputExt, Protocol, ProtocolInputExt,
    address::{Host, HostWithPort},
    client::{
        ConnectionAttempt, ConnectionError, ConnectionErrorKind, ConnectionPolicyScope,
        ConnectorService, ConnectorTarget, EstablishedClientConnection,
    },
    extensions::StreamTransformed,
    tls::{ApplicationProtocol, TlsAlpn, TlsRequired, default_tls_alpn},
};
use rama_tls::client::{
    EchRequirement, EchRetryConfig, NegotiatedTlsParameters, ServerVerifyMode, TlsClientConfig,
    TlsConnectionReuse, TlsServerAuthentication, TlsServerIdentity, publish_tls_required,
    resolve_target_ech,
};
use rama_utils::macros::{define_inner_service_accessors, generate_set_and_with};
use std::{fmt, sync::Arc};

#[cfg(feature = "http")]
use super::set_alpn_with_coupled_alps;
use super::{
    AutoTlsStream, BoringTlsClientConfigProvider, BoringTlsConnectorConfig, ServerAnswerRecorder,
    TlsClientSessionStore, TlsConnectorData,
    session::{ConnectorSessions, SessionStore},
    set_alpn_list_with_coupled_alps,
};

use crate::{TlsStream, type_conversion::peer_certificate_chain};
#[cfg(all(test, feature = "http"))]
use rama_net::http::Version;
#[cfg(feature = "http")]
use rama_net::http::{FallbackHttpVersion, HttpRequestVersion, TargetHttpVersion};
#[cfg(feature = "http")]
use rama_tls::{
    alpn::required_alpn_override,
    client::{http_alpn_override, negotiated_http_version},
};

/// A [`Layer`] which wraps the given service with a [`TlsConnector`].
///
/// See [`TlsConnector`] for more information.
#[derive(Debug, Clone)]
pub struct TlsConnectorLayer<K = ConnectorKindAuto> {
    base: Option<TlsClientConfig>,
    session_store: Option<SessionStore>,
    kind: PhantomData<K>,
}

impl<K> TlsConnectorLayer<K> {
    generate_set_and_with!(
        /// Set the base [`TlsClientConfig`] for this connector.
        ///
        /// Per-request TLS pieces of the connection being established layer on
        /// top of this base; the pieces of a connection underneath never do.
        ///
        /// NOTE: for a smooth interaction with HTTP you most likely want to at
        /// least define the ALPN protocols (e.g. [`TlsClientConfig::with_alpn_http_auto`]);
        /// the connector then sets the request http version from the negotiated ALPN.
        pub fn base_config(mut self, base: Option<TlsClientConfig>) -> Self {
            self.base = base;
            self
        }
    );

    generate_set_and_with!(
        /// Resume TLS sessions in each connector this layer makes; see
        /// [`TlsConnector::with_session_store`]. Connectors keep their own sessions,
        /// also when they share a store.
        pub fn session_store(mut self, store: Option<Arc<dyn TlsClientSessionStore>>) -> Self {
            self.session_store = store.map(SessionStore);
            self
        }
    );
}

impl TlsConnectorLayer<ConnectorKindAuto> {
    /// Creates a new [`TlsConnectorLayer`] which will establish
    /// a secure connection when the input protocol is secure. Otherwise it
    /// forwards the inner connection. The logical authority remains the default
    /// server identity.
    #[must_use]
    pub fn auto() -> Self {
        Self {
            base: None,
            session_store: None,
            kind: PhantomData,
        }
    }
}

impl TlsConnectorLayer<ConnectorKindSecure> {
    /// Creates a new [`TlsConnectorLayer`] which will always
    /// establish a secure connection regardless of the request it is for.
    #[must_use]
    pub fn secure() -> Self {
        Self {
            base: None,
            session_store: None,
            kind: PhantomData,
        }
    }
}

impl<K: Clone, S> Layer<S> for TlsConnectorLayer<K> {
    type Service = TlsConnector<S, K>;

    fn layer(&self, inner: S) -> Self::Service {
        TlsConnector {
            inner,
            base_config: self.base.clone(),
            sessions: connector_sessions(self.session_store.clone()),
            kind: PhantomData,
        }
    }

    fn into_layer(self, inner: S) -> Self::Service {
        TlsConnector {
            inner,
            base_config: self.base,
            sessions: connector_sessions(self.session_store),
            kind: PhantomData,
        }
    }
}

impl Default for TlsConnectorLayer<ConnectorKindAuto> {
    fn default() -> Self {
        Self::auto()
    }
}

/// A connector which can be used to establish a connection to a server.
///
/// By default it will created in auto mode ([`TlsConnector::auto`]),
/// which will perform the Tls handshake on the underlying stream,
/// only if the request requires a secure connection. You can instead use
/// [`TlsConnector::secure`] to force the connector to always
/// establish a secure connection.
#[derive(Debug, Clone, ExtensionsRef)]
pub struct TlsConnector<S, K = ConnectorKindAuto> {
    inner: S,
    base_config: Option<TlsClientConfig>,
    sessions: Option<Arc<ConnectorSessions>>,
    kind: PhantomData<K>,
}

fn connector_sessions(store: Option<SessionStore>) -> Option<Arc<ConnectorSessions>> {
    store.map(|SessionStore(store)| Arc::new(ConnectorSessions::new(store)))
}

impl<S, K> TlsConnector<S, K> {
    define_inner_service_accessors!();

    /// Creates a new [`TlsConnector`].
    const fn new(inner: S) -> Self {
        Self {
            inner,
            base_config: None,
            sessions: None,
            kind: PhantomData,
        }
    }

    generate_set_and_with!(
        /// Set the base [`TlsClientConfig`] for this connector.
        ///
        /// Per-request TLS pieces of the connection being established layer on
        /// top of this base; the pieces of a connection underneath never do.
        pub fn base_config(mut self, base: Option<TlsClientConfig>) -> Self {
            self.base_config = base;
            self
        }
    );

    generate_set_and_with!(
        /// Resume TLS sessions with servers this connector connected to before,
        /// keeping them in `store`. Off by default.
        ///
        /// A session only resumes with the server identity it was established with,
        /// under the same security policy and optional emulation profile scope.
        /// Compatible drawn extension orders can use sibling native contexts.
        /// Separate connectors stay isolated even when they share a store; clones
        /// of this connector share its session domain.
        pub fn session_store(mut self, store: Option<Arc<dyn TlsClientSessionStore>>) -> Self {
            self.sessions = connector_sessions(store.map(SessionStore));
            self
        }
    );
}

impl<S> TlsConnector<S, ConnectorKindAuto> {
    /// Creates a new [`TlsConnector`] which will establish
    /// a secure connection when the input protocol is secure. Otherwise it
    /// forwards the inner connection. The logical authority remains the default
    /// server identity.
    pub const fn auto(inner: S) -> Self {
        Self::new(inner)
    }

    /// Turn this connector into one which always handshakes, see [`TlsConnector::secure`],
    /// keeping its base configuration and session store.
    #[must_use]
    pub fn into_secure(self) -> TlsConnector<S, ConnectorKindSecure> {
        TlsConnector {
            inner: self.inner,
            base_config: self.base_config,
            sessions: self.sessions,
            kind: PhantomData,
        }
    }
}

impl<S> TlsConnector<S, ConnectorKindSecure> {
    /// Creates a new [`TlsConnector`] which will always
    /// establish a secure connection regardless of the request it is for.
    pub const fn secure(inner: S) -> Self {
        Self::new(inner)
    }
}

/// Whether the connection to establish is to be secured: its protocol is a secure one,
/// or its input asks for TLS whatever the protocol.
fn secure_requested(input: &(impl ProtocolInputExt + ExtensionsRef)) -> bool {
    input.target_protocol().is_some_and(Protocol::is_secure)
        || input.extensions().get_ref::<TlsRequired>().is_some()
}

// this way we do not need a hacky macro... however is there a way to do this without needing to hacK?!?!

impl<S, Input> Service<Input> for TlsConnector<S, ConnectorKindAuto>
where
    S: ConnectorService<Input, Connection: Io + Unpin>,
    Input: AuthorityInputExt + ProtocolInputExt + Send + ExtensionsRef + 'static,
{
    type Output = EstablishedClientConnection<AutoTlsStream<S::Connection>, Input>;
    type Error = ConnectionError;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        self.check_attempt_policy(&input, secure_requested(&input))?;
        let ech_target = input.connector_target();
        let EstablishedClientConnection { input, conn } = self.inner.connect(input).await?;

        let authority = input.target_authority().ok_or_else(|| {
            ConnectionError::local(
                BoxError::from_static_str("TlsConnector(auto): authority missing from input"),
                ConnectionErrorKind::InvalidInput,
            )
        })?;

        if !secure_requested(&input) {
            self.check_attempt_policy(&input, false)?;
            tracing::trace!(
                server.address = %authority.host,
                server.port = authority.port_u16(),
                "TlsConnector(auto): protocol not secure, return inner connection",
            );
            publish_tls_required(conn.extensions(), false);
            let conn = AutoTlsStream::plain(conn);
            return Ok(EstablishedClientConnection { input, conn });
        }

        let OriginHandshake {
            input,
            stream,
            negotiated_params,
            reuse,
            scope,
        } = self.handshake_origin(input, conn, ech_target).await?;
        #[cfg(feature = "http")]
        let app_protocol = input.target_protocol();

        tracing::trace!(
            server.address = %authority.host,
            server.port = authority.port_u16(),
            "TlsConnector(auto): protocol secure, established tls connection",
        );

        let conn = AutoTlsStream::secure(stream);

        #[cfg(feature = "http")]
        set_target_http_version(
            app_protocol,
            input.extensions(),
            conn.extensions(),
            &negotiated_params,
            input
                .extensions()
                .get_ref::<AlpnPolicy>()
                .copied()
                .or_else(|| {
                    self.base_config
                        .as_ref()
                        .and_then(|base| base.as_extensions().get_ref::<AlpnPolicy>().copied())
                }),
        )
        .map_err(|error| {
            ConnectionError::application(error, ConnectionErrorKind::Protocol)
                .context("TlsConnector(auto): validate negotiated HTTP version")
        })?;

        reuse.publish(conn.extensions(), self.base_config.as_ref());
        if !input.target_protocol().is_some_and(Protocol::is_secure) {
            publish_tls_required(conn.extensions(), true);
        }
        conn.extensions().insert(scope);
        conn.extensions().insert(negotiated_params);
        conn.extensions().insert(StreamTransformed {
            by: "rama-tls-boring::TlsConnector",
        });
        Ok(EstablishedClientConnection { input, conn })
    }
}

impl<S, Input> Service<Input> for TlsConnector<S, ConnectorKindSecure>
where
    S: ConnectorService<Input, Connection: Io + Unpin>,
    Input: AuthorityInputExt + ProtocolInputExt + Send + ExtensionsRef + 'static,
{
    type Output = EstablishedClientConnection<TlsStream<S::Connection>, Input>;
    type Error = ConnectionError;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        self.check_attempt_policy(&input, true)?;
        let ech_target = input.connector_target();
        let EstablishedClientConnection { input, conn } = self.inner.connect(input).await?;

        let authority = input.target_authority().ok_or_else(|| {
            ConnectionError::local(
                BoxError::from_static_str("TlsConnector(secure): authority missing from input"),
                ConnectionErrorKind::InvalidInput,
            )
        })?;
        tracing::trace!(
            server.address = %authority.host,
            server.port = authority.port_u16(),
            "TlsConnector(secure): attempt to secure inner connection w/ app protocol: {:?}",
            input.target_protocol(),
        );

        let OriginHandshake {
            input,
            stream,
            negotiated_params,
            reuse,
            scope,
        } = self.handshake_origin(input, conn, ech_target).await?;
        #[cfg(feature = "http")]
        let app_protocol = input.target_protocol();
        let conn = TlsStream::new(stream);

        #[cfg(feature = "http")]
        set_target_http_version(
            app_protocol,
            input.extensions(),
            conn.extensions(),
            &negotiated_params,
            input
                .extensions()
                .get_ref::<AlpnPolicy>()
                .copied()
                .or_else(|| {
                    self.base_config
                        .as_ref()
                        .and_then(|base| base.as_extensions().get_ref::<AlpnPolicy>().copied())
                }),
        )
        .map_err(|error| {
            ConnectionError::application(error, ConnectionErrorKind::Protocol)
                .context("TlsConnector(secure): validate negotiated HTTP version")
        })?;

        reuse.publish(conn.extensions(), self.base_config.as_ref());
        conn.extensions().insert(scope);
        conn.extensions().insert(negotiated_params);
        conn.extensions().insert(StreamTransformed {
            by: "rama-tls-boring::TlsConnector",
        });
        Ok(EstablishedClientConnection { input, conn })
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

#[cfg(feature = "http")]
fn set_target_http_version(
    application_protocol: Option<&Protocol>,
    request_extensions: &Extensions,
    conn_extensions: &Extensions,
    tls_params: &NegotiatedTlsParameters,
    policy: Option<AlpnPolicy>,
) -> Result<(), BoxError> {
    if let Some(neg_version) = negotiated_http_version(
        application_protocol,
        request_extensions
            .get_ref::<TargetHttpVersion>()
            .map(|version| version.0),
        request_extensions
            .get_ref::<FallbackHttpVersion>()
            .map(|version| version.0)
            .or_else(|| {
                request_extensions
                    .get_ref::<HttpRequestVersion>()
                    .map(|version| version.0)
            }),
        tls_params.application_layer_protocol.as_ref(),
        policy,
    )? {
        tracing::trace!(
            "setting connection TargetHttpVersion to {:?} based on negotiated ALPN",
            neg_version,
        );
        conn_extensions.insert(TargetHttpVersion(neg_version));
    }
    Ok(())
}

struct OriginHandshake<Input, Conn> {
    input: Input,
    stream: SslStream<Conn>,
    negotiated_params: NegotiatedTlsParameters,
    reuse: TlsConnectionReuse<BoringTlsClientConfigProvider>,
    scope: ConnectionPolicyScope,
}

impl<S, K> TlsConnector<S, K> {
    // One authentication-driven retry, still inside the caller's original
    // connection future/deadline. No HTTP data or single-use relay is replayed.
    async fn handshake_origin<Input>(
        &self,
        mut input: Input,
        mut conn: S::Connection,
        target: Option<HostWithPort>,
    ) -> Result<OriginHandshake<Input, S::Connection>, ConnectionError>
    where
        S: ConnectorService<Input, Connection: Io + Unpin>,
        K: Send + Sync,
        Input: AuthorityInputExt + ProtocolInputExt + ExtensionsRef + Send + 'static,
    {
        let mut retry_config: Option<EchRetryConfig> = None;
        loop {
            let authority = input.target_authority().ok_or_else(|| {
                ConnectionError::local(
                    BoxError::from_static_str("TLS origin authority missing"),
                    ConnectionErrorKind::InvalidInput,
                )
            })?;
            let mut data = self
                .connector_data(
                    input.extensions(),
                    input.target_protocol(),
                    Some(&authority.host),
                )
                .map_err(|error| {
                    ConnectionError::local(error, ConnectionErrorKind::InvalidInput)
                })?;
            let effective = self.effective_extensions(input.extensions());
            if let Some(target) = &target {
                if let Some(retry) = &retry_config {
                    retry.apply(&effective, target.clone());
                }
                data.configure_target_ech(&effective, target)
                    .map_err(|error| {
                        ConnectionError::local(error, ConnectionErrorKind::InvalidInput)
                    })?;
            }
            let scope = Self::check_connection_identity(
                &input,
                data.server_verify_mode,
                data.server_name.as_ref(),
                &authority.host,
            )?;
            let reuse = TlsConnectionReuse::new(BoringTlsClientConfigProvider, input.extensions());
            match handshake(data, conn).await {
                Ok((stream, negotiated_params)) => {
                    return Ok(OriginHandshake {
                        input,
                        stream,
                        negotiated_params,
                        reuse,
                        scope,
                    });
                }
                Err(error) => {
                    if retry_config.is_none()
                        && let Some(target) = &target
                        && let Some(retry) = error.find_cause::<EchRetryConfig>()
                    {
                        retry_config = Some(retry.clone());
                        // A proxy may have replaced this with its dial target.
                        input.extensions().insert(ConnectorTarget(target.clone()));
                        let next = self.inner.connect(input).await?;
                        input = next.input;
                        conn = next.conn;
                        continue;
                    }
                    return Err(
                        ConnectionError::application(error, ConnectionErrorKind::Protocol)
                            .context("TLS origin handshake"),
                    );
                }
            }
        }
    }

    fn build_connector_data(
        &self,
        config: BoringTlsConnectorConfig<'_>,
    ) -> Result<TlsConnectorData, BoxError> {
        match &self.sessions {
            Some(sessions) => sessions.connector_data(config),
            None => TlsConnectorData::try_from(config),
        }
    }

    /// Request extensions resolved over the connector base, local to the caller.
    fn effective_extensions(&self, request: &Extensions) -> Extensions {
        match &self.base_config {
            Some(base) => base.overlay(request),
            None => request.fork(),
        }
    }

    /// Reject an incompatible discovery policy before dialing. Ordinary connections
    /// retain their existing inner-connector override behavior.
    fn check_attempt_policy(
        &self,
        input: &(impl AuthorityInputExt + ProtocolInputExt + ExtensionsRef),
        secure: bool,
    ) -> Result<(), ConnectionError> {
        let effective = self.effective_extensions(input.extensions());
        let (requirement, _) = EchRequirement::effective(&effective)
            .map_err(|error| ConnectionError::local(error, ConnectionErrorKind::InvalidInput))?;
        if requirement == EchRequirement::Required {
            if !secure
                || BoringTlsConnectorConfig::from_extensions(&effective)
                    .verify
                    .is_some_and(|verify| verify.0 == ServerVerifyMode::Disable)
            {
                return Err(ConnectionError::local(
                    BoxError::from_static_str("required ECH needs authenticated TLS"),
                    ConnectionErrorKind::InvalidInput,
                ));
            }
            let target = input.connector_target().ok_or_else(|| {
                ConnectionError::local(
                    BoxError::from_static_str("required ECH needs a target"),
                    ConnectionErrorKind::InvalidInput,
                )
            })?;
            resolve_target_ech(&effective, &target, true).map_err(|error| {
                ConnectionError::local(error, ConnectionErrorKind::InvalidInput)
            })?;
        }
        if secure && let Some(target) = input.connector_target() {
            resolve_target_ech(&effective, &target, true)
                .map_err(|error| ConnectionError::local(error, ConnectionErrorKind::Unavailable))?;
        }
        let Some(attempt) = input.extensions().get_ref::<ConnectionAttempt>() else {
            return Ok(());
        };
        let scope = TlsConnectionReuse::new(BoringTlsClientConfigProvider, input.extensions())
            .policy_scope();
        if !secure {
            return attempt.check_policy(scope, None);
        }

        let config = BoringTlsConnectorConfig::from_extensions(&effective);
        if !config.authenticates_server() {
            return attempt.check_policy(scope, None);
        }
        let authority = config
            .server_name
            .is_none()
            .then(|| input.target_authority())
            .flatten();
        let peer = config
            .server_name
            .map(|name| &name.0)
            .or_else(|| authority.as_ref().map(|authority| &authority.host));
        attempt.check_policy(scope, peer)
    }

    /// Classify the request after inner connectors have added their extensions,
    /// and check the actual native configuration used by this handshake.
    fn check_connection_identity(
        input: &impl ExtensionsRef,
        verify_mode: ServerVerifyMode,
        server_name: Option<&Host>,
        server_host: &Host,
    ) -> Result<ConnectionPolicyScope, ConnectionError> {
        let scope = TlsConnectionReuse::new(BoringTlsClientConfigProvider, input.extensions())
            .policy_scope();
        if let Some(attempt) = input.extensions().get_ref::<ConnectionAttempt>() {
            let peer = (verify_mode != ServerVerifyMode::Disable)
                .then_some(server_name.unwrap_or(server_host));
            attempt.check_policy(scope, peer)?;
            return Ok(attempt.policy_scope());
        }
        Ok(scope)
    }

    fn connector_data(
        &self,
        request_extensions: &Extensions,
        application_protocol: Option<&Protocol>,
        maybe_server_host: Option<&Host>,
    ) -> Result<TlsConnectorData, BoxError> {
        let extensions = self.effective_extensions(request_extensions);

        apply_default_alpn(&extensions, application_protocol);

        // A request-owned offer is authoritative. Otherwise narrow defaults to
        // the required HTTP protocol before starting the handshake.
        #[cfg(feature = "http")]
        resolve_http_alpn(
            &extensions,
            application_protocol,
            request_extensions.get_ref::<TlsAlpn>(),
        )?;

        let config = BoringTlsConnectorConfig::from_extensions(&extensions);
        let mut data = self.build_connector_data(config)?;

        // A configured server identity overrides the transport host.
        if data.server_name.is_none() {
            data.server_name = maybe_server_host.cloned();
        }

        Ok(data)
    }
}

fn apply_default_alpn(effective_extensions: &Extensions, application_protocol: Option<&Protocol>) {
    // Any ALPN in the effective chain is explicit connector policy, whether
    // supplied by the request or inherited from a base configuration.
    let alpn = effective_extensions
        .get_ref::<TlsAlpn>()
        .cloned()
        .or_else(|| {
            application_protocol
                .map(|protocol| default_tls_alpn(protocol).unwrap_or_else(TlsAlpn::empty))
        });
    if let Some(alpn) = alpn {
        let coupling = set_alpn_list_with_coupled_alps(effective_extensions, alpn);
        tracing::trace!(?coupling, "coupled ALPS to protocol-derived TLS ALPN");
    }
}

/// Resolve the required HTTP protocol without rewriting an explicit request offer.
/// Connector defaults are narrowed so, for example, a WebSocket upgrade cannot
/// negotiate HTTP/2 accidentally. A conflicting explicit offer fails instead.
#[cfg(feature = "http")]
fn resolve_http_alpn(
    ext: &Extensions,
    application_protocol: Option<&Protocol>,
    offered: Option<&TlsAlpn>,
) -> Result<(), BoxError> {
    let target_version = ext.get_ref::<TargetHttpVersion>();
    let Some(target_alpn) = http_alpn_override(
        application_protocol,
        target_version.map(|target| target.0),
        offered,
    )?
    else {
        return Ok(());
    };
    let Some(target_alpn) = required_alpn_override(target_alpn, offered) else {
        return Ok(());
    };
    tracing::trace!(
        ?target_version,
        ?target_alpn,
        "override TLS ALPN to match TargetHttpVersion",
    );

    let alps_coupling = set_alpn_with_coupled_alps(ext, target_alpn);
    tracing::trace!(?alps_coupling, "coupled ALPS to forced TLS ALPN");
    Ok(())
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

    super::handshake::PreparedClient::try_from(data)
        .map_err(TlsConnectError::Builder)?
        .connect(stream)
        .await
}

#[derive(Debug)]
struct HandshakeMetadata {
    server_name: Option<Host>,
    server_verify_mode: ServerVerifyMode,
    store_server_certificate_chain: bool,
    store_server_hello: bool,
}

impl From<&TlsConnectorData> for HandshakeMetadata {
    fn from(data: &TlsConnectorData) -> Self {
        Self {
            server_name: data.server_name.clone(),
            server_verify_mode: data.server_verify_mode,
            store_server_certificate_chain: data.store_server_certificate_chain,
            store_server_hello: data.store_server_hello,
        }
    }
}

async fn handshake<T>(
    configuration: TlsConnectorData,
    stream: T,
) -> Result<(SslStream<T>, NegotiatedTlsParameters), BoxError>
where
    T: Io + Unpin + ExtensionsRef,
{
    let handshake = async {
        let metadata = HandshakeMetadata::from(&configuration);
        // High-level connectors always resolve an identity. Treat its absence as
        // invalid connector state even when low-level verification is disabled.
        if metadata.server_name.is_none() {
            return Err(BoxError::from_static_str("server identity missing"));
        }

        let authenticated_identity = (metadata.server_verify_mode != ServerVerifyMode::Disable)
            .then(|| metadata.server_name.clone())
            .flatten();
        let store_server_certificate_chain = metadata.store_server_certificate_chain;
        let store_server_hello = metadata.store_server_hello;
        #[cfg(feature = "dial9")]
        let dial9_server_name = rama_core::telemetry::dial9::Dial9Handle::current()
            .is_enabled()
            .then(|| metadata.server_name.clone())
            .flatten();
        #[cfg(feature = "dial9")]
        crate::dial9::record_handshake_started(dial9_server_name.as_ref());
        let connected = tls_connect(stream, Some(configuration)).await;
        let TlsStream { inner: stream } = match connected {
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
                        dial9_server_name.as_ref(),
                        error_kind,
                        io_error_kind,
                    );
                }
                if let TlsConnectError::Handshake { error, .. } = &err
                    && let (Some(ssl), Some(errors)) = (error.ssl(), error.as_ssl_error_stack())
                    && let Some(retry) = super::ech::authenticated_retry_config(
                        ssl,
                        errors
                            .iter()
                            .map(|error| (error.library_code(), error.reason_code())),
                    )
                {
                    return Err(Box::new(retry) as BoxError);
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
            .insert(TlsServerAuthentication(authenticated_identity));
        let params = match stream.ssl().session() {
            Some(ssl_session) => {
                let protocol_version =
                    ssl_session
                        .protocol_version()
                        .rama_try_into()
                        .map_err(|v| {
                            BoxError::from_static_str(
                                "boring ssl connector: cast min proto version",
                            )
                            .context_field("protocol_version", v)
                        })?;
                let application_layer_protocol = stream
                    .ssl()
                    .selected_alpn_protocol()
                    .map(ApplicationProtocol::from);
                if let Some(ref proto) = application_layer_protocol {
                    tracing::trace!("boring client (connector) has selected ALPN {proto}");
                }

                let server_certificate_chain = if store_server_certificate_chain {
                    peer_certificate_chain(stream.ssl())?
                } else {
                    None
                };

                NegotiatedTlsParameters {
                    protocol_version,
                    application_layer_protocol,
                    peer_certificate_chain: server_certificate_chain,
                    server_name: None,
                    resumed: Some(stream.ssl().session_reused()),
                    algorithms: stream.ssl().rama_into(),
                    server_hello: store_server_hello
                        .then(|| ServerAnswerRecorder::installed(stream.ssl()))
                        .flatten()
                        .and_then(|recorder| recorder.server_hello(false)),
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
                dial9_server_name.as_ref(),
                params.protocol_version,
                stream.ssl().selected_alpn_protocol(),
                depth,
            );
        }

        Ok((stream, params))
    };
    #[cfg(feature = "dial9")]
    {
        rama_core::telemetry::dial9::record_result("tls.boring.client", handshake).await
    }
    #[cfg(not(feature = "dial9"))]
    handshake.await
}

#[non_exhaustive]
#[derive(Debug, Clone)]
/// A connector which can be used to establish a connection to a server
/// in function of the Request, meaning either it will be a seucre
/// connector or it will be a plain connector.
///
/// This connector can be handy as it allows to have a single layer
/// which will work both for plain and secure connections.
pub struct ConnectorKindAuto;

#[non_exhaustive]
#[derive(Debug, Clone)]
/// A connector which can _only_ be used to establish a secure connection,
/// regardless of the scheme of the request URI.
pub struct ConnectorKindSecure;

#[cfg(test)]
mod tests {
    use super::*;
    use rama_core::extensions::NoExtensionsTransfer;
    #[cfg(feature = "http")]
    use rama_tls::ProtocolVersion;

    use rama_net::client::pool::ConnectionReuse;
    #[cfg(feature = "http")]
    use rama_net::tls::TlsAlpn;

    use rama_core::{ServiceInput, service::service_fn};
    use rama_net::{
        address::HostWithPort,
        client::{ConnectRequest, ConnectionErrorDomain},
    };
    use rama_tls::client::{
        ClientHelloExtension, ECHClientHello, NegotiatedTlsParameters, ServerVerifyMode,
        TlsServerName, TlsServerVerify, TlsStoreServerHello,
    };

    use crate::{
        client::{BoringClientConfigExt as _, ech::EchGrease, tests::hello_from_data},
        server::TlsAcceptorLayer,
    };
    use rama_crypto::cert::generate_server_auth;
    use rama_net::stream::service::EchoService;
    use rama_tls::client::{ClientAuth, ClientAuthData};
    use rama_tls::server::{
        CertificateAuthorityData, ClientVerifyMode, GeneratedServerAuthConfig, LeafCertRequest,
        SelfSignedCaConfig, ServerAuthData, TlsServerConfig,
    };
    use rama_utils::octets::kib;
    use std::{sync::Arc, time::Duration};
    use tokio::io::DuplexStream;

    fn origin_attempt() -> ConnectRequest {
        let input =
            ConnectRequest::new(HostWithPort::new(Host::from_static("origin.example"), 443))
                .with_application_protocol(Protocol::HTTPS);
        input.extensions().insert(
            ConnectionAttempt::new().with_authenticated_peer(Host::from_static("origin.example")),
        );
        input
    }

    #[tokio::test]
    async fn discovery_rejects_incompatible_defaults_before_dial() {
        for base in [
            TlsClientConfig::new().with_server_verify(ServerVerifyMode::Disable),
            TlsClientConfig::new().with_server_name(Host::from_static("other.example")),
        ] {
            let transport = service_fn(
                async |_input: ConnectRequest| -> Result<
                    EstablishedClientConnection<
                        ServiceInput<tokio::io::DuplexStream>,
                        ConnectRequest,
                    >,
                    ConnectionError,
                > {
                    panic!("incompatible authentication must be rejected before dialing");
                },
            );
            let connector = TlsConnector::auto(transport).with_base_config(base);
            let input = origin_attempt();
            let caller = TlsConnectionReuse::new(BoringTlsClientConfigProvider, input.extensions());
            input
                .extensions()
                .insert(TlsAlpn([ApplicationProtocol::HTTP_2].into_iter().collect()));
            input
                .extensions()
                .insert(caller.for_derived_settings(input.extensions()).unwrap());
            let attempt = input.extensions().get_arc::<ConnectionAttempt>().unwrap();
            let error = connector.serve(input).await.expect_err("policy rejection");
            assert_eq!(error.domain(), ConnectionErrorDomain::Local);
            assert_eq!(error.kind(), ConnectionErrorKind::Unavailable);
            assert_eq!(attempt.policy_scope(), ConnectionPolicyScope::Connector);
        }
    }

    #[tokio::test]
    async fn discovery_rejects_inner_connector_plaintext_downgrade() {
        let transport = service_fn(async |mut input: ConnectRequest| {
            input.application_protocol = Some(Protocol::HTTP);
            Ok::<_, ConnectionError>(EstablishedClientConnection {
                input,
                conn: ServiceInput::new(tokio::io::duplex(64).0),
            })
        });
        let connector = TlsConnector::auto(transport);
        let error = connector
            .serve(origin_attempt())
            .await
            .expect_err("plaintext rejection");
        assert_eq!(error.domain(), ConnectionErrorDomain::Local);
        assert_eq!(error.kind(), ConnectionErrorKind::Unavailable);
    }

    #[test]
    fn discovery_preserves_validated_derived_tls_policy_scope() {
        let connector = TlsConnector::secure(()).with_base_config(TlsClientConfig::default_http());
        for caller_override in [false, true] {
            let input = origin_attempt();
            if caller_override {
                input
                    .extensions()
                    .insert(TlsServerVerify(ServerVerifyMode::Auto));
            }
            let caller = TlsConnectionReuse::new(BoringTlsClientConfigProvider, input.extensions());
            input
                .extensions()
                .insert(TlsAlpn([ApplicationProtocol::HTTP_2].into_iter().collect()));
            let derived = caller.for_derived_settings(input.extensions()).unwrap();
            input.extensions().insert(derived);
            let expected = if caller_override {
                ConnectionPolicyScope::Request
            } else {
                ConnectionPolicyScope::Connector
            };
            connector.check_attempt_policy(&input, true).unwrap();
            assert_eq!(
                input
                    .extensions()
                    .get_ref::<ConnectionAttempt>()
                    .unwrap()
                    .policy_scope(),
                expected
            );
            assert_eq!(
                TlsConnector::<(), ConnectorKindSecure>::check_connection_identity(
                    &input,
                    ServerVerifyMode::Auto,
                    None,
                    &Host::from_static("origin.example"),
                )
                .unwrap(),
                expected
            );
            // A later TLS override invalidates the derived-policy token.
            input
                .extensions()
                .insert(TlsServerVerify(ServerVerifyMode::Auto));
            if !caller_override {
                connector.check_attempt_policy(&input, true).unwrap();
                assert_eq!(
                    input
                        .extensions()
                        .get_ref::<ConnectionAttempt>()
                        .unwrap()
                        .policy_scope(),
                    ConnectionPolicyScope::Request
                );
            }
        }
    }

    #[test]
    fn discovery_request_policy_overrides_connector_defaults() {
        let connector = TlsConnector::secure(()).with_base_config(
            TlsClientConfig::new()
                .with_server_verify(ServerVerifyMode::Disable)
                .with_server_name(Host::from_static("other.example")),
        );
        let input = origin_attempt();
        input
            .extensions()
            .insert(TlsServerVerify(ServerVerifyMode::Auto));
        input
            .extensions()
            .insert(TlsServerName(Host::from_static("origin.example")));
        connector
            .check_attempt_policy(&input, true)
            .expect("request restores authentication");
        assert_eq!(
            input
                .extensions()
                .get_ref::<ConnectionAttempt>()
                .unwrap()
                .policy_scope(),
            ConnectionPolicyScope::Request
        );
    }

    #[tokio::test]
    async fn discovery_rechecks_inner_connector_tls_overrides() {
        for disable_verification in [false, true] {
            let transport = service_fn(move |input: ConnectRequest| async move {
                if disable_verification {
                    input
                        .extensions()
                        .insert(TlsServerVerify(ServerVerifyMode::Disable));
                } else {
                    input
                        .extensions()
                        .insert(TlsServerName(Host::from_static("other.example")));
                }
                let (io, peer) = tokio::io::duplex(64);
                drop(peer);
                Ok::<_, ConnectionError>(EstablishedClientConnection {
                    input,
                    conn: ServiceInput::new(io),
                })
            });
            let connector = TlsConnector::secure(transport);
            let input = origin_attempt();
            let caller = TlsConnectionReuse::new(BoringTlsClientConfigProvider, input.extensions());
            input
                .extensions()
                .insert(TlsAlpn([ApplicationProtocol::HTTP_2].into_iter().collect()));
            input
                .extensions()
                .insert(caller.for_derived_settings(input.extensions()).unwrap());
            let attempt = input.extensions().get_arc::<ConnectionAttempt>().unwrap();
            let error = connector
                .serve(input)
                .await
                .expect_err("policy rejection before handshake");
            assert_eq!(error.domain(), ConnectionErrorDomain::Local);
            assert_eq!(error.kind(), ConnectionErrorKind::Unavailable);
            assert_eq!(attempt.policy_scope(), ConnectionPolicyScope::Request);
        }
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

    #[test]
    fn connector_data_keeps_transport_ip_as_server_identity() {
        let connector = TlsConnector::secure(());
        let extensions = Extensions::new();
        let host = Host::from(std::net::Ipv4Addr::LOCALHOST);

        let data = connector
            .connector_data(&extensions, None, Some(&host))
            .expect("connector data");

        assert_eq!(data.server_name, Some(host));
    }

    #[test]
    fn request_ech_intent_overrides_the_connector_default() {
        let shape = EchGrease::Shape {
            kdf_id: 1,
            aead_id: 3,
            encapsulated_key_len: 32,
            payload_len: 208,
        };
        for base_value in [None, Some(false), Some(true)] {
            for request_value in [None, Some(false), Some(true)] {
                let mut base = TlsClientConfig::new().with_ech_grease(shape);
                if let Some(value) = base_value {
                    base.set_encrypted_client_hello(value);
                }
                let mut request = TlsClientConfig::new();
                if let Some(value) = request_value {
                    request.set_encrypted_client_hello(value);
                }
                let data = TlsConnector::secure(())
                    .with_base_config(base)
                    .connector_data(request.as_extensions(), None, None)
                    .expect("connector data");
                let outer = hello_from_data(data)
                    .extensions()
                    .iter()
                    .find_map(|extension| match extension {
                        ClientHelloExtension::EncryptedClientHello(ECHClientHello::Outer(
                            outer,
                        )) => Some(outer.payload.len()),
                        _ => None,
                    });
                let expected = request_value.or(base_value).unwrap_or(false).then_some(208);
                assert_eq!(
                    outer, expected,
                    "base {base_value:?}, request {request_value:?}"
                );
            }
        }
    }

    /// An input whose forwarded context names another host than its own target.
    #[derive(ExtensionsRef)]
    struct ForwardedInput(rama_core::extensions::Extensions);

    impl AuthorityInputExt for ForwardedInput {
        fn authority(&self) -> Option<rama_net::address::HostWithOptPort> {
            Some(Host::from_static("public.test").into())
        }

        fn target_authority(&self) -> Option<rama_net::address::HostWithOptPort> {
            Some(Host::from_static("localhost").into())
        }
    }

    impl ProtocolInputExt for ForwardedInput {
        fn protocol(&self) -> Option<&Protocol> {
            Some(&Protocol::HTTPS)
        }
    }

    /// TLS SNI and server verification follow the input's own target, never its forwarded
    /// context: the certificate covers only the target.
    #[tokio::test]
    async fn sni_names_the_target_not_the_forwarded_authority() {
        let (cert_chain, private_key) =
            generate_server_auth(GeneratedServerAuthConfig::default()).expect("server auth");
        let trust_anchor = cert_chain.last().expect("trust anchor").clone();
        let server = crate::server::TlsAcceptorLayer::new(
            TlsServerConfig::new()
                .with_alpn_http_auto()
                .with_single_cert(ServerAuthData {
                    cert_chain,
                    private_key,
                    ocsp: None,
                }),
        )
        .into_layer(EchoService::new());
        let base = TlsClientConfig::new()
            .try_with_server_trust_anchors([trust_anchor])
            .expect("trust anchor");
        let (client_io, server_io) = tokio::io::duplex(64);
        let server_task =
            tokio::spawn(async move { server.serve(ServiceInput::new(server_io)).await });
        let client_io = Arc::new(tokio::sync::Mutex::new(Some(client_io)));
        let transport = service_fn(move |input: ForwardedInput| {
            let client_io = client_io.clone();
            async move {
                let conn = ServiceInput::new(client_io.lock().await.take().expect("one dial"));
                Ok::<_, ConnectionError>(EstablishedClientConnection { input, conn })
            }
        });
        let connector = TlsConnector::secure(transport).with_base_config(base);
        tokio::time::timeout(
            Duration::from_secs(5),
            connector.serve(ForwardedInput(rama_core::extensions::Extensions::new())),
        )
        .await
        .expect("handshake timeout")
        .expect("the handshake names and verifies the target");
        server_task.abort();
    }

    #[tokio::test]
    async fn a_connection_publishes_its_server_hello_only_when_asked() {
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
        // Off, on through the connector's configuration, and on for one request.
        for (base_stores, request_stores) in [(false, None), (true, None), (false, Some(true))] {
            let base = TlsClientConfig::new()
                .with_server_name(Host::from_static("localhost"))
                .with_store_server_hello(base_stores)
                .try_with_server_trust_anchors([trust_anchor.clone()])
                .expect("trust anchor");
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
            let connector = TlsConnector::secure(transport).with_base_config(base);
            let input = ConnectRequest::new(HostWithPort::new(Host::from_static("localhost"), 443));
            if let Some(store) = request_stores {
                input.extensions().insert(TlsStoreServerHello(store));
            }
            let established = tokio::time::timeout(Duration::from_secs(5), connector.serve(input))
                .await
                .expect("handshake timeout")
                .expect("origin handshake");
            let extensions = established.conn.extensions();
            let stored = request_stores.unwrap_or(base_stores);
            let hello = extensions
                .get_ref::<NegotiatedTlsParameters>()
                .expect("negotiated parameters")
                .server_hello
                .clone();
            assert_eq!(hello.is_some(), stored);
            // Unless asked, a connection does not even record the server's answer.
            assert_eq!(
                ServerAnswerRecorder::installed(established.conn.ssl_ref()).is_some(),
                stored
            );
            if stored {
                let hello = hello.unwrap();
                assert!(!hello.is_quic());
                assert_eq!(hello.protocol_version(), rama_tls::ProtocolVersion::TLSv1_3);
                let ja4s = rama_tls::fingerprint::Ja4S::compute(extensions).expect("ja4s");
                assert!(ja4s.to_string().starts_with("t13"), "{ja4s}");
                let ja3s = rama_tls::fingerprint::Ja3S::compute(extensions).expect("ja3s");
                assert!(ja3s.to_string().starts_with("771,"), "{ja3s}");
            } else {
                rama_tls::fingerprint::Ja4S::compute(extensions).unwrap_err();
            }
            drop(established);
            server_task.abort();
        }
    }

    #[tokio::test]
    async fn successful_origin_handshake_reports_effective_policy_scope() {
        let (cert_chain, private_key) =
            generate_server_auth(GeneratedServerAuthConfig::default()).expect("server auth");
        let trust_anchor = cert_chain.last().expect("trust anchor").clone();
        let server = Arc::new(
            crate::server::TlsAcceptorLayer::new(
                TlsServerConfig::new()
                    .with_alpn_http_auto()
                    .with_single_cert(ServerAuthData {
                        cert_chain,
                        private_key,
                        ocsp: None,
                    }),
            )
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
            let input = ConnectRequest::new(HostWithPort::new(Host::from_static("localhost"), 443))
                .with_application_protocol(Protocol::HTTPS);
            #[cfg(feature = "http")]
            {
                // A fallback does not constrain ALPN, but an explicit target does.
                input
                    .extensions()
                    .insert(rama_net::http::FallbackHttpVersion(Version::HTTP_11));
                if request_override {
                    input
                        .extensions()
                        .insert(TargetHttpVersion(Version::HTTP_11));
                }
            }
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
            #[cfg(feature = "http")]
            {
                let expected = if request_override {
                    Version::HTTP_11
                } else {
                    Version::HTTP_2
                };
                assert_eq!(
                    established
                        .conn
                        .extensions()
                        .get_ref::<TargetHttpVersion>()
                        .map(|v| v.0),
                    Some(expected),
                );
                assert_eq!(
                    established
                        .conn
                        .extensions()
                        .get_ref::<NegotiatedTlsParameters>()
                        .and_then(|params| params.application_layer_protocol.as_ref()),
                    Some(&ApplicationProtocol::try_from(expected).unwrap()),
                );
                assert_eq!(
                    established
                        .input
                        .extensions()
                        .get_ref::<TargetHttpVersion>()
                        .map(|v| v.0),
                    request_override.then_some(Version::HTTP_11),
                );
            }
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

    #[cfg(feature = "http")]
    #[test]
    fn fallback_http_version_does_not_constrain_alpn() {
        use rama_net::http::{FallbackHttpVersion, Version};

        let extensions = Extensions::new();
        extensions.insert(TlsAlpn::http_auto());
        extensions.insert(FallbackHttpVersion(Version::HTTP_11));

        resolve_http_alpn(&extensions, Some(&Protocol::HTTPS), None).unwrap();
        assert_eq!(
            extensions.get_ref::<TlsAlpn>().map(|alpn| alpn.0.clone()),
            Some(TlsAlpn::http_auto().0),
        );
    }

    #[cfg(feature = "http")]
    #[test]
    fn concrete_http_version_keeps_alps_coupled_to_forced_alpn() {
        use crate::client::BoringAlps;

        for (version, expected_alps) in [
            (Version::HTTP_11, Vec::new()),
            (Version::HTTP_2, vec![ApplicationProtocol::HTTP_2]),
        ] {
            let extensions = Extensions::new();
            extensions.insert(TlsAlpn::http_auto());
            extensions.insert(BoringAlps {
                protocols: vec![ApplicationProtocol::HTTP_2],
                new_codepoint: true,
            });
            extensions.insert(TargetHttpVersion(version));

            resolve_http_alpn(&extensions, Some(&Protocol::HTTPS), None)
                .expect("resolve concrete HTTP ALPN");

            let expected_alpn = ApplicationProtocol::try_from(version).unwrap();
            assert_eq!(
                extensions
                    .get_ref::<TlsAlpn>()
                    .map(|alpn| alpn.0.as_slice()),
                Some([expected_alpn].as_slice())
            );
            assert_eq!(
                extensions
                    .get_ref::<BoringAlps>()
                    .map(|alps| (alps.protocols.as_slice(), alps.new_codepoint)),
                Some((expected_alps.as_slice(), true))
            );
        }
    }

    #[test]
    fn inherited_alpn_and_alps_are_preserved_for_any_application_protocol() {
        use crate::client::BoringAlps;

        let base = Extensions::new();
        base.insert(TlsAlpn::http_auto());
        base.insert(BoringAlps {
            protocols: vec![ApplicationProtocol::HTTP_2],
            new_codepoint: true,
        });
        let request = Extensions::new();
        let effective = request.fork().with_base(&base);

        apply_default_alpn(&effective, Some(&Protocol::ICAPS));

        assert_eq!(
            effective.get_ref::<TlsAlpn>().map(|alpn| alpn.0.as_slice()),
            Some([ApplicationProtocol::HTTP_2, ApplicationProtocol::HTTP_11].as_slice()),
        );
        assert_eq!(
            effective
                .get_ref::<BoringAlps>()
                .map(|alps| (alps.protocols.as_slice(), alps.new_codepoint)),
            Some(([ApplicationProtocol::HTTP_2].as_slice(), true)),
        );
    }

    #[test]
    fn derives_empty_alpn_for_icaps_without_explicit_policy() {
        let effective = Extensions::new();

        apply_default_alpn(&effective, Some(&Protocol::ICAPS));

        assert_eq!(
            effective.get_ref::<TlsAlpn>().map(|alpn| alpn.0.as_slice()),
            Some([].as_slice()),
        );
    }

    #[test]
    fn inherited_http_alpn_and_alps_survive_for_https() {
        use crate::client::BoringAlps;

        let base = Extensions::new();
        base.insert(TlsAlpn::http_auto());
        base.insert(BoringAlps {
            protocols: vec![ApplicationProtocol::HTTP_2],
            new_codepoint: true,
        });
        let request = Extensions::new();
        let effective = request.fork().with_base(&base);

        apply_default_alpn(&effective, Some(&Protocol::HTTPS));

        assert_eq!(
            effective.get_ref::<TlsAlpn>().map(|alpn| alpn.0.as_slice()),
            Some([ApplicationProtocol::HTTP_2, ApplicationProtocol::HTTP_11].as_slice()),
        );
        assert_eq!(
            effective
                .get_ref::<BoringAlps>()
                .map(|alps| (alps.protocols.as_slice(), alps.new_codepoint)),
            Some(([ApplicationProtocol::HTTP_2].as_slice(), true)),
        );
    }

    #[test]
    fn inherited_http_alpn_suppresses_incompatible_alps() {
        use crate::client::BoringAlps;

        let base = Extensions::new();
        base.insert(TlsAlpn::http_1());
        base.insert(BoringAlps {
            protocols: vec![ApplicationProtocol::HTTP_2],
            new_codepoint: true,
        });
        let request = Extensions::new();
        let effective = request.fork().with_base(&base);

        apply_default_alpn(&effective, Some(&Protocol::HTTPS));

        assert_eq!(
            effective.get_ref::<TlsAlpn>().map(|alpn| alpn.0.as_slice()),
            Some([ApplicationProtocol::HTTP_11].as_slice()),
        );
        assert_eq!(
            effective
                .get_ref::<BoringAlps>()
                .map(|alps| (alps.protocols.as_slice(), alps.new_codepoint)),
            Some(([].as_slice(), true)),
        );
    }

    #[test]
    fn request_alpn_overrides_base_and_recouples_alps() {
        use crate::client::BoringAlps;

        let base = Extensions::new();
        base.insert(TlsAlpn::http_auto());
        base.insert(BoringAlps {
            protocols: vec![ApplicationProtocol::HTTP_2],
            new_codepoint: true,
        });
        let request = Extensions::new();
        request.insert(TlsAlpn::http_1());
        let effective = request.with_base(&base);

        apply_default_alpn(&effective, Some(&Protocol::HTTPS));

        assert_eq!(
            effective.get_ref::<TlsAlpn>().map(|alpn| alpn.0.as_slice()),
            Some([ApplicationProtocol::HTTP_11].as_slice()),
        );
        assert_eq!(
            effective
                .get_ref::<BoringAlps>()
                .map(|alps| alps.protocols.as_slice()),
            Some([].as_slice()),
        );
    }

    #[test]
    fn inherited_alpn_survives_without_application_protocol() {
        let base = Extensions::new();
        base.insert(TlsAlpn::http_1());
        let effective = Extensions::new().with_base(&base);

        apply_default_alpn(&effective, None);

        assert_eq!(
            effective.get_ref::<TlsAlpn>().map(|alpn| alpn.0.as_slice()),
            Some([ApplicationProtocol::HTTP_11].as_slice()),
        );
    }

    #[cfg(feature = "http")]
    #[test]
    fn icaps_ignores_http_version_hint() {
        let extensions = Extensions::new();
        extensions.insert(TlsAlpn::empty());
        extensions.insert(TargetHttpVersion(Version::HTTP_2));

        resolve_http_alpn(&extensions, Some(&Protocol::ICAPS), None).unwrap();

        assert_eq!(
            extensions
                .get_ref::<TlsAlpn>()
                .map(|alpn| alpn.0.as_slice()),
            Some([].as_slice()),
        );
    }

    /// Both ends store the peer's whole chain, leaf first.
    #[tokio::test]
    async fn stored_peer_chains_are_complete_and_leaf_first() {
        let ca = CertificateAuthorityData::generate(SelfSignedCaConfig::default()).unwrap();
        let anchor = ca.certificate_chain()[0].clone();
        let server_auth = ServerAuthData::new_issued_by(&ca, LeafCertRequest::default()).unwrap();
        let (client_chain, private_key) = ca.issue_client_leaf(LeafCertRequest::default()).unwrap();
        assert!(
            server_auth.cert_chain.len() > 1 && client_chain.len() > 1,
            "a single certificate cannot show a missing leaf"
        );
        let server_chain = server_auth.cert_chain.clone();
        let server = TlsAcceptorLayer::new(
            TlsServerConfig::new()
                .with_server_auth(server_auth)
                .with_client_verify(ClientVerifyMode::ClientAuth(vec![anchor.clone()]))
                .with_store_client_cert_chain(true),
        )
        .into_layer(service_fn(
            |stream: TlsStream<ServiceInput<DuplexStream>>| async move {
                Ok::<_, BoxError>(
                    stream
                        .extensions()
                        .get_ref::<NegotiatedTlsParameters>()
                        .and_then(|params| params.peer_certificate_chain.clone()),
                )
            },
        ));
        let client = TlsConnectorData::try_from(
            &TlsClientConfig::new()
                .with_server_name(Host::from_static("localhost"))
                .try_with_server_trust_anchors([anchor])
                .unwrap()
                .with_client_auth(ClientAuth::Single(ClientAuthData {
                    private_key,
                    cert_chain: client_chain.clone(),
                }))
                .with_store_server_cert_chain(true),
        )
        .unwrap();
        let (client_io, server_io) = tokio::io::duplex(kib(64));
        let (client, server) = tokio::join!(
            handshake(client, ServiceInput::new(client_io)),
            server.serve(ServiceInput::new(server_io)),
        );
        let (_stream, params) = client.unwrap();
        assert_eq!(params.peer_certificate_chain, Some(server_chain));
        assert_eq!(server.unwrap(), Some(client_chain));
    }

    #[cfg(feature = "http")]
    #[test]
    fn no_alpn_checks_resolved_versions_without_fabricating_metadata() {
        let tls = NegotiatedTlsParameters {
            protocol_version: ProtocolVersion::TLSv1_3,
            application_layer_protocol: None,
            peer_certificate_chain: None,
            server_name: None,
            resumed: None,
            algorithms: Default::default(),
            server_hello: None,
        };
        for version in [Version::HTTP_11, Version::HTTP_2] {
            for fallback in [false, true] {
                for policy in [
                    None,
                    Some(AlpnPolicy::Require),
                    Some(AlpnPolicy::OutOfBandAgreement),
                ] {
                    let request = Extensions::new();
                    if fallback {
                        request.insert(FallbackHttpVersion(version));
                        request.insert(HttpRequestVersion(Version::HTTP_2));
                    } else {
                        request.insert(HttpRequestVersion(version));
                    }
                    let connection = Extensions::new();
                    let result = set_target_http_version(
                        Some(&Protocol::HTTPS),
                        &request,
                        &connection,
                        &tls,
                        policy,
                    );
                    assert_eq!(
                        result.is_err(),
                        policy == Some(AlpnPolicy::Require) && version == Version::HTTP_2
                    );
                    assert!(!connection.contains::<TargetHttpVersion>());
                }
            }
        }
    }

    fn origin_tls_inputs() -> Extensions {
        let origin = Extensions::new();
        TlsClientConfig::new()
            .with_alpn_http_1()
            .with_server_name(Host::from_static("origin.example"))
            .with_server_verify(ServerVerifyMode::Disable)
            .with_ech_requirement(EchRequirement::Required)
            .write_to(&origin);
        origin
    }

    /// The input that dials a proxy, as the proxy connectors build it.
    fn nested_leg(origin: &Extensions) -> ConnectRequest {
        rama_net::client::proxy_request(&"https://localhost:443".parse().unwrap(), origin)
    }

    #[test]
    fn a_nested_leg_takes_its_tls_config_from_the_connector() {
        let proxy_name = Host::from_static("proxy.example");
        let connector = TlsConnector::auto(()).with_base_config(
            TlsClientConfig::new()
                .with_server_name(proxy_name.clone())
                .with_alpn_http_2(),
        );

        let leg = origin_tls_inputs().fork_connection(&NoExtensionsTransfer::new());
        let effective = connector.effective_extensions(&leg);
        let config = BoringTlsConnectorConfig::from_extensions(&effective);

        let http_2 = TlsAlpn::http_2();
        assert_eq!(config.server_name.map(|name| &name.0), Some(&proxy_name));
        assert_eq!(
            config.alpn.map(|alpn| alpn.0.as_slice()),
            Some(http_2.0.as_slice())
        );
        assert!(
            config.verify.is_none(),
            "origin verify mode reached the connection to the proxy"
        );
        assert!(
            config.ech_requirement.is_none(),
            "origin ECH requirement reached the connection to the proxy"
        );
    }

    #[tokio::test]
    async fn hop_settings_configure_the_leg_handshake() {
        use rama_net::client::ProxyConnectionExtensions;

        let (cert_chain, private_key) =
            generate_server_auth(GeneratedServerAuthConfig::default()).expect("server auth");
        let server =
            TlsAcceptorLayer::new(TlsServerConfig::new().with_single_cert(ServerAuthData {
                cert_chain,
                private_key,
                ocsp: None,
            }))
            .into_layer(EchoService::new());

        let (client_io, server_io) = tokio::io::duplex(kib(64));
        let server_task =
            tokio::spawn(async move { server.serve(ServiceInput::new(server_io)).await });
        // No trust anchor: only the hop's own settings can let this through.
        let connector = TlsConnector::auto(leg_transport(client_io)).with_base_config(
            TlsClientConfig::new().with_server_name(Host::from_static("localhost")),
        );

        let origin = origin_tls_inputs();
        let bag = Extensions::new();
        bag.insert(TlsServerVerify(ServerVerifyMode::Disable));
        origin.insert(ProxyConnectionExtensions(bag));

        let established = connector
            .serve(nested_leg(&origin))
            .await
            .expect("the hop's own settings configure the proxy handshake");
        drop(established);
        drop(server_task.await);
    }

    #[test]
    fn a_bag_verify_off_does_not_disable_origin_verification() {
        use rama_net::client::ProxyConnectionExtensions;

        let connector = TlsConnector::auto(()).with_base_config(TlsClientConfig::new());

        let origin = Extensions::new();
        let bag = Extensions::new();
        bag.insert(TlsServerVerify(ServerVerifyMode::Disable));
        origin.insert(ProxyConnectionExtensions(bag));

        let effective = connector.effective_extensions(&origin);
        let config = BoringTlsConnectorConfig::from_extensions(&effective);
        assert!(
            config.verify.is_none(),
            "the hop's settings are no input of the origin's handshake"
        );
    }

    #[test]
    fn a_request_input_still_overrides_the_connector_config() {
        let connector = TlsConnector::auto(())
            .with_base_config(TlsClientConfig::new().with_alpn(Default::default()));

        let request = Extensions::new();
        request.insert(TlsAlpn::http_1());
        let effective = connector.effective_extensions(&request);
        let config = BoringTlsConnectorConfig::from_extensions(&effective);

        let http_1 = TlsAlpn::http_1();
        assert_eq!(
            config.alpn.map(|alpn| alpn.0.as_slice()),
            Some(http_1.0.as_slice())
        );
    }

    #[test]
    fn a_nested_leg_keeps_every_config_piece_of_its_connector() {
        use rama_crypto::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
        use rama_tls::client::{ClientAuth, ClientAuthData, TlsServerCertPins};
        use rama_tls::{KeyLogIntent, ProtocolVersion};

        let pin = CertificateDer::from(vec![1, 2, 3]);
        let auth = ClientAuth::Single(ClientAuthData {
            cert_chain: vec![CertificateDer::from(vec![4])],
            private_key: PrivatePkcs8KeyDer::from(vec![5]).into(),
        });
        let connector = TlsConnector::auto(()).with_base_config(
            TlsClientConfig::new()
                .with_server_cert_pins(TlsServerCertPins::new(pin.clone()))
                .with_client_auth(auth)
                .with_keylog(KeyLogIntent::Disabled)
                .with_supported_versions(vec![ProtocolVersion::TLSv1_3]),
        );

        let origin = Extensions::new();
        TlsClientConfig::new()
            .with_server_cert_pins(TlsServerCertPins::new(CertificateDer::from(vec![9])))
            .with_client_auth(ClientAuth::SelfSigned)
            .with_keylog(KeyLogIntent::Environment)
            .with_supported_versions(vec![ProtocolVersion::TLSv1_2])
            .write_to(&origin);

        let leg = origin.fork_connection(&NoExtensionsTransfer::new());
        let effective = connector.effective_extensions(&leg);
        let config = BoringTlsConnectorConfig::from_extensions(&effective);

        assert!(
            config
                .server_cert_pins
                .expect("the connector's pins")
                .check(None, &pin)
                != rama_tls::client::TlsServerCertPinCheck::Mismatched
        );
        assert!(matches!(
            config.client_auth.map(|auth| &auth.0),
            Some(ClientAuth::Single(_))
        ));
        assert!(matches!(
            config.keylog.map(|keylog| &keylog.0),
            Some(KeyLogIntent::Disabled)
        ));
        assert_eq!(
            config.versions.map(|versions| versions.0.as_slice()),
            Some([ProtocolVersion::TLSv1_3].as_slice())
        );
    }

    #[tokio::test]
    async fn a_nested_leg_handshake_keeps_the_origin_attempt_untouched() {
        let (cert_chain, private_key) =
            generate_server_auth(GeneratedServerAuthConfig::default()).expect("server auth");
        let trust_anchor = cert_chain.last().expect("trust anchor").clone();
        let server =
            TlsAcceptorLayer::new(TlsServerConfig::new().with_single_cert(ServerAuthData {
                cert_chain,
                private_key,
                ocsp: None,
            }))
            .into_layer(EchoService::new());

        let (client_io, server_io) = tokio::io::duplex(kib(64));
        let server_task =
            tokio::spawn(async move { server.serve(ServiceInput::new(server_io)).await });
        let connector = TlsConnector::auto(leg_transport(client_io)).with_base_config(
            TlsClientConfig::new()
                .with_server_name(Host::from_static("localhost"))
                .try_with_server_trust_anchors([trust_anchor])
                .expect("proxy trust"),
        );

        // The origin's attempt authenticates the origin, not the proxy.
        let origin = Extensions::new();
        origin.insert(
            ConnectionAttempt::new().with_authenticated_peer(Host::from_static("origin.example")),
        );

        let established = connector
            .serve(nested_leg(&origin))
            .await
            .expect("the origin's attempt is not the proxy connection's");
        assert_eq!(
            origin
                .get_ref::<ConnectionAttempt>()
                .expect("the origin's attempt")
                .policy_scope(),
            ConnectionPolicyScope::Unknown,
            "the connection to the proxy does not classify the origin's attempt"
        );

        // A connection nested on the connection to the proxy is a different connection: its
        // own classification is no fact of it.
        let tunnel = established
            .conn
            .extensions()
            .fork_connection(&rama_net::stream::DefaultExtensionsTransfer::new());
        assert!(
            established
                .conn
                .extensions()
                .contains::<ConnectionPolicyScope>(),
            "the connection to the proxy publishes its own scope"
        );
        assert!(
            !tunnel.contains::<ConnectionPolicyScope>(),
            "the origin over the tunnel does not inherit the scope of the connection to the proxy"
        );
        drop(established);
        drop(server_task.await);
    }

    #[test]
    fn an_origin_ech_requirement_is_not_the_policy_of_a_nested_leg() {
        let connector = TlsConnector::auto(()).with_base_config(
            TlsClientConfig::new().with_server_name(Host::from_static("proxy.example")),
        );

        connector
            .check_attempt_policy(&nested_leg(&origin_tls_inputs()), true)
            .expect("the origin's ECH requirement is not the proxy connection's");
    }

    fn leg_transport(
        io: DuplexStream,
    ) -> impl ConnectorService<ConnectRequest, Connection: Io + Unpin> {
        let io = Arc::new(parking_lot::Mutex::new(Some(io)));
        service_fn(move |input: ConnectRequest| {
            let conn = ServiceInput::new(io.lock().take().expect("one proxy connection"));
            async move {
                Ok::<_, ConnectionError>(rama_net::client::EstablishedClientConnection {
                    input,
                    conn,
                })
            }
        })
    }

    #[tokio::test]
    async fn auto_handshakes_when_the_input_asks_for_tls() {
        for asks in [false, true] {
            let auth =
                ServerAuthData::new_generated(GeneratedServerAuthConfig::default()).expect("auth");
            let base = TlsClientConfig::new()
                .with_server_name(Host::from_static("localhost"))
                .try_with_server_trust_anchors(auth.cert_chain.clone())
                .expect("trust anchor");
            let server = TlsAcceptorLayer::new(TlsServerConfig::new().with_server_auth(auth))
                .into_layer(EchoService::new());
            let (client_io, server_io) = tokio::io::duplex(kib(64));
            let server_task =
                tokio::spawn(async move { server.serve(ServiceInput::new(server_io)).await });

            let connector =
                TlsConnector::auto(leg_transport(client_io)).with_base_config(base.clone());
            // A plaintext protocol: only the input's own ask can secure this connection.
            let input = ConnectRequest::new(HostWithPort::new(Host::from_static("localhost"), 80))
                .with_application_protocol(Protocol::HTTP);
            if asks {
                input.extensions().insert(TlsRequired::new());
            }
            let established = tokio::time::timeout(Duration::from_secs(5), connector.serve(input))
                .await
                .expect("handshake timeout")
                .expect("connection");
            assert_eq!(
                established
                    .conn
                    .extensions()
                    .get_ref::<NegotiatedTlsParameters>()
                    .is_some(),
                asks,
            );
            drop(established);
            server_task.abort();
        }
    }

    #[tokio::test]
    async fn a_nested_leg_handshake_ignores_origin_tls_inputs() {
        use rama_net::tls::ApplicationProtocol;

        let (cert_chain, private_key) =
            generate_server_auth(GeneratedServerAuthConfig::default()).expect("server auth");
        let trust_anchor = cert_chain.last().expect("trust anchor").clone();
        let server = TlsAcceptorLayer::new(
            TlsServerConfig::new()
                .with_single_cert(ServerAuthData {
                    cert_chain,
                    private_key,
                    ocsp: None,
                })
                .with_alpn_http_2(),
        )
        .into_layer(EchoService::new());

        let (client_io, server_io) = tokio::io::duplex(kib(64));
        let server_task =
            tokio::spawn(async move { server.serve(ServiceInput::new(server_io)).await });
        let connector = TlsConnector::auto(leg_transport(client_io)).with_base_config(
            TlsClientConfig::new()
                .with_alpn_http_2()
                .with_server_name(Host::from_static("localhost"))
                .try_with_server_trust_anchors([trust_anchor])
                .expect("proxy trust"),
        );

        let established = connector
            .serve(nested_leg(&origin_tls_inputs()))
            .await
            .expect("the proxy handshake uses the connector's own config");
        assert_eq!(
            established
                .conn
                .extensions()
                .get_ref::<NegotiatedTlsParameters>()
                .expect("proxy TLS parameters")
                .application_layer_protocol,
            Some(ApplicationProtocol::HTTP_2),
        );
        drop(established);
        drop(server_task.await);
    }

    #[tokio::test]
    async fn an_origin_verify_off_does_not_authenticate_the_peer_of_a_nested_leg() {
        let (cert_chain, private_key) =
            generate_server_auth(GeneratedServerAuthConfig::default()).expect("server auth");
        let server =
            TlsAcceptorLayer::new(TlsServerConfig::new().with_single_cert(ServerAuthData {
                cert_chain,
                private_key,
                ocsp: None,
            }))
            .into_layer(EchoService::new());

        let (client_io, server_io) = tokio::io::duplex(kib(64));
        let server_task =
            tokio::spawn(async move { server.serve(ServiceInput::new(server_io)).await });
        // No trust anchor for the generated certificate: the connection to the proxy must refuse it.
        let connector = TlsConnector::auto(leg_transport(client_io)).with_base_config(
            TlsClientConfig::new().with_server_name(Host::from_static("localhost")),
        );

        let origin = Extensions::new();
        origin.insert(TlsServerVerify(ServerVerifyMode::Disable));

        assert!(
            connector.serve(nested_leg(&origin)).await.is_err(),
            "an origin verify-off must not reach the connection to the proxy"
        );
        drop(server_task.await);
    }
}
