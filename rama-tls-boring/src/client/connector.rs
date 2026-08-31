use rama_boring::ssl::{ConnectConfiguration, SslAlert, SslVerifyError, SslVerifyMode};
use rama_boring_tokio::{HandshakeError, SslStream};
use rama_core::conversion::RamaTryInto;
use rama_core::error::BoxErrorExt as _;
use rama_core::error::{BoxError, ErrorContext, ErrorExt};
use rama_core::extensions::{Extensions, ExtensionsRef};
use rama_core::io::Io;
use rama_core::telemetry::tracing;
use rama_core::{Layer, Service};
use rama_crypto::pki_types::CertificateDer;
use rama_net::address::Host;
use rama_net::client::{
    ConnectionError, ConnectionErrorKind, ConnectorService, EstablishedClientConnection,
};
use rama_net::extensions::StreamTransformed;
use rama_net::{
    AuthorityInputExt, Protocol, ProtocolInputExt,
    tls::{ApplicationProtocol, TlsAlpn, default_tls_alpn},
};
use rama_tls::client::{
    NegotiatedTlsParameters, ServerVerifyMode, TlsClientConfig, TlsServerCertPinCheck,
    TlsServerCertPins, TlsServerIdentity,
};
use rama_tls::{TlsTunnelMode, resolve_tls_tunnel};
use rama_utils::macros::generate_set_and_with;
use std::fmt;

#[cfg(feature = "http")]
use super::set_alpn_with_coupled_alps;
use super::{
    AutoTlsStream, BoringTlsConnectorConfig, TlsConnectorData, set_alpn_list_with_coupled_alps,
};

use crate::{TlsStream, types::TlsTunnel};
#[cfg(feature = "http")]
use rama_net::http::{TargetHttpVersion, Version};

/// A [`Layer`] which wraps the given service with a [`TlsConnector`].
///
/// See [`TlsConnector`] for more information.
#[derive(Debug, Clone)]
pub struct TlsConnectorLayer<K = ConnectorKindAuto> {
    base: Option<TlsClientConfig>,
    kind: K,
}

impl<K> TlsConnectorLayer<K> {
    generate_set_and_with!(
        /// Set the base [`TlsClientConfig`] for this connector.
        ///
        /// Auto and secure connectors layer per-request TLS pieces on top of this
        /// base. Tunnel connectors intentionally use only this base plus the
        /// proxy-scoped [`TlsTunnel`] fields.
        ///
        /// NOTE: for a smooth interaction with HTTP you most likely want to at
        /// least define the ALPN protocols (e.g. [`TlsClientConfig::with_alpn_http_auto`]);
        /// the connector then sets the request http version from the negotiated ALPN.
        pub fn base_config(mut self, base: Option<TlsClientConfig>) -> Self {
            self.base = base;
            self
        }
    );
}

impl TlsConnectorLayer<ConnectorKindAuto> {
    /// Creates a new [`TlsConnectorLayer`] which will establish
    /// a secure connection if the request demands it,
    /// otherwise it will forward the pre-established inner connection.
    #[must_use]
    pub fn auto() -> Self {
        Self {
            base: None,
            kind: ConnectorKindAuto,
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
            kind: ConnectorKindSecure,
        }
    }
}

impl TlsConnectorLayer<ConnectorKindTunnel> {
    /// Creates a new [`TlsConnectorLayer`] which will establish
    /// a secure connection if the request is to be tunneled.
    #[must_use]
    pub fn tunnel(host: Option<Host>) -> Self {
        Self {
            base: None,
            kind: ConnectorKindTunnel { host },
        }
    }
}

impl<K: Clone, S> Layer<S> for TlsConnectorLayer<K> {
    type Service = TlsConnector<S, K>;

    fn layer(&self, inner: S) -> Self::Service {
        TlsConnector {
            inner,
            base_config: self.base.clone(),
            kind: self.kind.clone(),
        }
    }

    fn into_layer(self, inner: S) -> Self::Service {
        TlsConnector {
            inner,
            base_config: self.base,
            kind: self.kind,
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
#[derive(Debug, Clone)]
pub struct TlsConnector<S, K = ConnectorKindAuto> {
    inner: S,
    base_config: Option<TlsClientConfig>,
    kind: K,
}

impl<S, K> TlsConnector<S, K> {
    /// Creates a new [`TlsConnector`].
    const fn new(inner: S, kind: K) -> Self {
        Self {
            inner,
            base_config: None,
            kind,
        }
    }

    generate_set_and_with!(
        /// Set the base [`TlsClientConfig`] for this connector.
        ///
        /// Auto and secure connectors layer per-request TLS pieces on top of this
        /// base. Tunnel connectors intentionally use only this base plus the
        /// proxy-scoped [`TlsTunnel`] fields.
        pub fn base_config(mut self, base: Option<TlsClientConfig>) -> Self {
            self.base_config = base;
            self
        }
    );
}

impl<S> TlsConnector<S, ConnectorKindAuto> {
    /// Creates a new [`TlsConnector`] which will establish
    /// a secure connection if the request demands it,
    /// otherwise it will forward the pre-established inner connection.
    pub const fn auto(inner: S) -> Self {
        Self::new(inner, ConnectorKindAuto)
    }
}

impl<S> TlsConnector<S, ConnectorKindSecure> {
    /// Creates a new [`TlsConnector`] which will always
    /// establish a secure connection regardless of the request it is for.
    pub const fn secure(inner: S) -> Self {
        Self::new(inner, ConnectorKindSecure)
    }
}

impl<S> TlsConnector<S, ConnectorKindTunnel> {
    /// Creates a new [`TlsConnector`] which will establish
    /// a secure connection if the request is to be tunneled.
    pub const fn tunnel(inner: S, host: Option<Host>) -> Self {
        Self::new(inner, ConnectorKindTunnel { host })
    }
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
        let EstablishedClientConnection { input, conn } = self.inner.connect(input).await?;

        let authority = input.authority().ok_or_else(|| {
            ConnectionError::local(
                BoxError::from_static_str("TlsConnector(auto): authority missing from input"),
                ConnectionErrorKind::InvalidInput,
            )
        })?;
        let app_protocol = input.protocol();

        if !app_protocol
            .as_ref()
            .map(|p| p.is_secure())
            .unwrap_or_default()
        {
            tracing::trace!(
                server.address = %authority.host,
                server.port = authority.port_u16(),
                "TlsConnector(auto): protocol not secure, return inner connection",
            );
            return Ok(EstablishedClientConnection {
                input,
                conn: AutoTlsStream::plain(conn),
            });
        }

        // Use the authority host as the certificate identity unless overridden.
        let connector_data = self
            .connector_data(input.extensions(), app_protocol, Some(&authority.host))
            .map_err(|error| {
                ConnectionError::local(error, ConnectionErrorKind::InvalidInput)
                    .context("TlsConnector(auto): build connector configuration")
            })?;

        let (stream, negotiated_params) =
            handshake(connector_data, conn).await.map_err(|error| {
                ConnectionError::application(error, ConnectionErrorKind::Protocol)
                    .context("TlsConnector(auto): TLS handshake")
            })?;

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
        )
        .map_err(|error| {
            ConnectionError::application(error, ConnectionErrorKind::Protocol)
                .context("TlsConnector(auto): validate negotiated HTTP version")
        })?;

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
        let EstablishedClientConnection { input, conn } = self.inner.connect(input).await?;

        let authority = input.authority().ok_or_else(|| {
            ConnectionError::local(
                BoxError::from_static_str("TlsConnector(secure): authority missing from input"),
                ConnectionErrorKind::InvalidInput,
            )
        })?;
        tracing::trace!(
            server.address = %authority.host,
            server.port = authority.port_u16(),
            "TlsConnector(secure): attempt to secure inner connection w/ app protocol: {:?}",
            input.protocol(),
        );

        let app_protocol = input.protocol();
        let connector_data = self
            .connector_data(input.extensions(), app_protocol, Some(&authority.host))
            .map_err(|error| {
                ConnectionError::local(error, ConnectionErrorKind::InvalidInput)
                    .context("TlsConnector(secure): build connector configuration")
            })?;

        let (conn, negotiated_params) = handshake(connector_data, conn).await.map_err(|error| {
            ConnectionError::application(error, ConnectionErrorKind::Protocol)
                .context("TlsConnector(secure): TLS handshake")
        })?;
        let conn = TlsStream::new(conn);

        #[cfg(feature = "http")]
        set_target_http_version(
            app_protocol,
            input.extensions(),
            conn.extensions(),
            &negotiated_params,
        )
        .map_err(|error| {
            ConnectionError::application(error, ConnectionErrorKind::Protocol)
                .context("TlsConnector(secure): validate negotiated HTTP version")
        })?;

        conn.extensions().insert(negotiated_params);
        conn.extensions().insert(StreamTransformed {
            by: "rama-tls-boring::TlsConnector",
        });
        Ok(EstablishedClientConnection { input, conn })
    }
}

impl<S, Input> Service<Input> for TlsConnector<S, ConnectorKindTunnel>
where
    S: ConnectorService<Input, Connection: Io + Unpin>,
    Input: Send + ExtensionsRef + 'static,
{
    type Output = EstablishedClientConnection<AutoTlsStream<S::Connection>, Input>;
    type Error = ConnectionError;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        let EstablishedClientConnection { input, conn } = self.inner.connect(input).await?;

        let tunnel = input.extensions().get_ref::<TlsTunnel>().cloned();

        let TlsTunnelMode::Tls(maybe_server_host) =
            resolve_tls_tunnel(tunnel.as_ref(), self.kind.host.as_ref())
        else {
            tracing::trace!(
                "TlsConnector(tunnel): return inner connection: no Tls tunnel is requested"
            );
            return Ok(EstablishedClientConnection {
                input,
                conn: AutoTlsStream::plain(conn),
            });
        };

        let tunnel_protocol = tunnel
            .as_ref()
            .and_then(|tunnel| tunnel.application_protocol.as_ref());
        let connector_data = self
            .tunnel_connector_data(tunnel.as_ref(), tunnel_protocol, maybe_server_host)
            .map_err(|error| {
                ConnectionError::local(error, ConnectionErrorKind::InvalidInput)
                    .context("TlsConnector(tunnel): build connector configuration")
            })?;

        let (stream, negotiated_params) =
            handshake(connector_data, conn).await.map_err(|error| {
                ConnectionError::transport(error, ConnectionErrorKind::Protocol)
                    .context("TlsConnector(tunnel): TLS handshake")
            })?;
        let conn = AutoTlsStream::secure(stream);

        conn.extensions().insert(negotiated_params);
        conn.extensions().insert(StreamTransformed {
            by: "rama-tls-boring::TlsConnector",
        });
        tracing::trace!("TlsConnector(tunnel): connection secured");
        Ok(EstablishedClientConnection { input, conn })
    }
}

fn server_identity_for(host: &Host) -> Result<String, BoxError> {
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
) -> Result<(), BoxError> {
    if !application_protocol.is_some_and(Protocol::is_http_based) {
        return Ok(());
    }
    if let Some(proto) = tls_params.application_layer_protocol.as_ref() {
        let neg_version: Version = proto.try_into()?;
        if let Some(target_version) = request_extensions.get_ref::<TargetHttpVersion>()
            && target_version.0 != neg_version
        {
            return Err(BoxError::from_static_str(
                "target http version not compatible with negotiated tls alpn version",
            )
            .context_debug_field("target_version", *target_version)
            .context_debug_field("negotiated_version", neg_version));
        }

        tracing::trace!(
            "setting request TargetHttpVersion to {:?} based on negotiated APLN",
            neg_version,
        );
        conn_extensions.insert(TargetHttpVersion(neg_version));
    }
    Ok(())
}

impl<S, K> TlsConnector<S, K> {
    fn tunnel_connector_data(
        &self,
        tunnel: Option<&TlsTunnel>,
        application_protocol: Option<&Protocol>,
        maybe_server_host: Option<&Host>,
    ) -> Result<TlsConnectorData, BoxError> {
        let effective = self.tunnel_config_extensions(tunnel, application_protocol);

        let mut data =
            TlsConnectorData::try_from(BoringTlsConnectorConfig::from_extensions(&effective))?;
        if data.server_name.is_none() {
            data.server_name = maybe_server_host.cloned();
        }
        Ok(data)
    }

    fn tunnel_config_extensions(
        &self,
        tunnel: Option<&TlsTunnel>,
        application_protocol: Option<&Protocol>,
    ) -> Extensions {
        let effective = Extensions::new();
        if let Some(base) = &self.base_config {
            effective.extend(base.as_extensions());
        }
        if let Some(alpn) = tunnel.and_then(|tunnel| tunnel.alpn.clone()) {
            effective.insert(alpn);
        }

        apply_default_alpn(&effective, application_protocol);
        effective
    }

    fn connector_data(
        &self,
        request_extensions: &Extensions,
        application_protocol: Option<&Protocol>,
        maybe_server_host: Option<&Host>,
    ) -> Result<TlsConnectorData, BoxError> {
        // Create new extensions only for this function that also apply the base_config
        let effective = request_extensions.fork();
        let extensions = if let Some(base) = &self.base_config {
            effective.with_base(base.as_extensions())
        } else {
            effective
        };

        apply_default_alpn(&extensions, application_protocol);

        // When HTTP pins a concrete target version, force the TLS ALPN to match
        // it before the handshake
        #[cfg(feature = "http")]
        resolve_http_alpn(&extensions, application_protocol)?;

        let mut data =
            TlsConnectorData::try_from(BoringTlsConnectorConfig::from_extensions(&extensions))?;

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

/// Force the TLS ALPN to match a concrete [`TargetHttpVersion`] when HTTP pins
/// one. Otherwise protocols like WebSocket can negotiate `h2` even though the
/// request requires an HTTP/1.1 upgrade.
#[cfg(feature = "http")]
fn resolve_http_alpn(
    ext: &Extensions,
    application_protocol: Option<&Protocol>,
) -> Result<(), BoxError> {
    if application_protocol.is_some_and(|protocol| !protocol.is_http_based()) {
        return Ok(());
    }
    let Some(target_version) = ext.get_ref::<TargetHttpVersion>() else {
        return Ok(());
    };

    let target_alpn = ApplicationProtocol::try_from(target_version.0)?;
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
    let TlsConnectorData {
        mut config,
        store_server_certificate_chain: _,
        ref server_name,
        server_verify_mode,
        server_cert_pins,
    } = match connector_data {
        Some(connector_data) => connector_data,
        None => {
            TlsConnectorData::try_from(&TlsClientConfig::new()).map_err(TlsConnectError::Builder)?
        }
    };

    if server_verify_mode == ServerVerifyMode::Auto && server_name.is_none() {
        return Err(TlsConnectError::Builder(BoxError::from_static_str(
            "server identity required when server verification is enabled",
        )));
    }

    configure_server_cert_pins(
        &mut config,
        server_verify_mode,
        server_cert_pins,
        server_name.as_ref(),
    );
    let server_identity = server_name
        .as_ref()
        .map(server_identity_for)
        .transpose()
        .map_err(TlsConnectError::Builder)?;
    let stream: SslStream<T> =
        rama_boring_tokio::connect(config, server_identity.as_deref(), stream)
            .await
            .map_err(|error| TlsConnectError::Handshake {
                error,
                server_name: server_name.clone(),
            })?;
    Ok(TlsStream::new(stream))
}

fn configure_server_cert_pins(
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

#[derive(Debug, Clone)]
/// A connector which can be used to use this connector to support
/// secure https tunnel connections.
///
/// TLS is requested when [`TlsTunnel`] is present or a hardcoded server
/// identity is configured. A dedicated base-config identity takes precedence,
/// followed by the tunnel identity and then this connector fallback.
///
/// [`TlsTunnel`]: rama_tls::TlsTunnel
pub struct ConnectorKindTunnel {
    host: Option<Host>,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "http")]
    use rama_net::tls::TlsAlpn;

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
    fn tunnel_config_uses_only_base_and_explicit_tunnel_policy() {
        use rama_tls::client::{TlsServerName, TlsServerVerify};

        let base_name = Host::from_static("proxy-cert.example");
        let route_name = Host::from_static("proxy-route.example");
        let connector = TlsConnector::tunnel((), None).with_base_config(
            TlsClientConfig::new()
                .with_alpn_http_2()
                .with_server_name(base_name.clone())
                .with_server_verify(ServerVerifyMode::Disable),
        );
        let tunnel = TlsTunnel {
            server_identity: Some(route_name),
            application_protocol: Some(Protocol::HTTPS),
            alpn: Some(TlsAlpn::http_1()),
        };

        let effective = connector.tunnel_config_extensions(Some(&tunnel), Some(&Protocol::HTTPS));
        assert_eq!(
            effective.get_ref::<TlsAlpn>().cloned(),
            Some(TlsAlpn::http_1())
        );
        assert_eq!(
            effective
                .get_ref::<TlsServerName>()
                .map(|server_name| server_name.0.clone()),
            Some(base_name.clone())
        );
        assert_eq!(
            effective
                .get_ref::<TlsServerVerify>()
                .map(|verify| verify.0),
            Some(ServerVerifyMode::Disable)
        );

        let data = connector
            .tunnel_connector_data(Some(&tunnel), Some(&Protocol::HTTPS), None)
            .expect("tunnel connector data");
        assert_eq!(data.server_name, Some(base_name));
    }

    #[test]
    fn tunnel_config_isolates_all_origin_tls_extensions() {
        use crate::client::BoringClientConfigExt as _;
        use rama_crypto::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
        use rama_tls::{
            KeyLogIntent, ProtocolVersion, TlsKeyLog,
            client::{
                ClientAuth, ClientAuthData, ServerVerifyMode, TlsClientAuth, TlsServerCertPinCheck,
                TlsServerCertPins, TlsServerTrust,
            },
        };

        let base_name = Host::from_static("proxy-cert.example");
        let base_pin = CertificateDer::from(vec![1, 2, 3]);
        let base_pins = TlsServerCertPins::new(base_pin.clone());
        let base_trust = TlsServerTrust::webpki_roots();
        let base = TlsClientConfig::new()
            .with_alpn_http_2()
            .with_server_name(base_name.clone())
            .with_server_verify(ServerVerifyMode::Disable)
            .with_server_cert_pins(base_pins)
            .with_server_trust(base_trust.clone())
            .with_supported_versions(vec![ProtocolVersion::TLSv1_3])
            .with_keylog(KeyLogIntent::Disabled)
            .with_client_auth(ClientAuth::SelfSigned)
            .with_store_server_cert_chain(true)
            .with_grease(true);
        let connector = TlsConnector::tunnel((), None).with_base_config(base);

        let origin = Extensions::new();
        TlsClientConfig::new()
            .with_alpn_http_1()
            .with_server_name(Host::from_static("origin.example"))
            .with_server_verify(ServerVerifyMode::Auto)
            .with_server_cert_pins(TlsServerCertPins::new(CertificateDer::from(vec![9])))
            .with_server_trust(TlsServerTrust::default_roots())
            .with_supported_versions(vec![ProtocolVersion::TLSv1_2])
            .with_keylog(KeyLogIntent::Environment)
            .with_client_auth(ClientAuth::Single(ClientAuthData {
                cert_chain: vec![CertificateDer::from(vec![8])],
                private_key: PrivatePkcs8KeyDer::from(vec![7]).into(),
            }))
            .with_store_server_cert_chain(false)
            .with_grease(false)
            .write_to(&origin);
        origin.insert(TlsTunnel {
            server_identity: Some(Host::from_static("proxy-route.example")),
            application_protocol: Some(Protocol::HTTPS),
            alpn: None,
        });

        let tunnel = origin.get_ref::<TlsTunnel>();
        let effective = connector.tunnel_config_extensions(tunnel, Some(&Protocol::HTTPS));
        let config = BoringTlsConnectorConfig::from_extensions(&effective);

        assert_eq!(config.alpn.cloned(), Some(TlsAlpn::http_2()));
        assert_eq!(
            config.server_name.map(|name| name.0.clone()),
            Some(base_name.clone())
        );
        assert_eq!(
            config.verify.map(|verify| verify.0),
            Some(ServerVerifyMode::Disable)
        );
        assert_eq!(config.server_trust, Some(&base_trust));
        assert_eq!(
            config.versions.map(|versions| versions.0.as_slice()),
            Some([ProtocolVersion::TLSv1_3].as_slice())
        );
        assert!(matches!(
            config.keylog,
            Some(TlsKeyLog(KeyLogIntent::Disabled))
        ));
        assert!(matches!(
            config.client_auth,
            Some(TlsClientAuth(ClientAuth::SelfSigned))
        ));
        assert_eq!(config.store_chain.map(|store| store.0), Some(true));
        assert_eq!(config.grease.map(|grease| grease.0), Some(true));
        assert_eq!(
            config
                .server_cert_pins
                .expect("base pins")
                .check(Some(&base_name), &base_pin),
            TlsServerCertPinCheck::Matched
        );

        let data = connector
            .tunnel_connector_data(tunnel, Some(&Protocol::HTTPS), None)
            .expect("resolved tunnel connector data");
        assert_eq!(data.server_name, Some(base_name));
        assert_eq!(data.server_verify_mode, ServerVerifyMode::Disable);
        assert!(data.store_server_certificate_chain);
        assert!(data.server_cert_pins.is_some());
    }

    #[test]
    fn explicit_empty_tunnel_alpn_overrides_base() {
        let connector = TlsConnector::tunnel((), None)
            .with_base_config(TlsClientConfig::new().with_alpn_http_auto());
        let tunnel = TlsTunnel {
            server_identity: None,
            application_protocol: Some(Protocol::HTTPS),
            alpn: Some(TlsAlpn::empty()),
        };

        let effective = connector.tunnel_config_extensions(Some(&tunnel), Some(&Protocol::HTTPS));
        assert_eq!(
            effective.get_ref::<TlsAlpn>().cloned(),
            Some(TlsAlpn::empty())
        );
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
        let negotiated = established
            .conn
            .extensions()
            .get_ref::<NegotiatedTlsParameters>()
            .expect("proxy TLS parameters");
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

    #[cfg(feature = "http")]
    #[test]
    fn fallback_http_version_does_not_constrain_alpn() {
        use rama_net::http::{FallbackHttpVersion, Version};

        let extensions = Extensions::new();
        extensions.insert(TlsAlpn::http_auto());
        extensions.insert(FallbackHttpVersion(Version::HTTP_11));

        resolve_http_alpn(&extensions, Some(&Protocol::HTTPS)).unwrap();
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

            resolve_http_alpn(&extensions, Some(&Protocol::HTTPS))
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

        resolve_http_alpn(&extensions, Some(&Protocol::ICAPS)).unwrap();

        assert_eq!(
            extensions
                .get_ref::<TlsAlpn>()
                .map(|alpn| alpn.0.as_slice()),
            Some([].as_slice()),
        );
    }
}
