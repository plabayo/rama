use super::{AutoTlsStream, RustlsTlsStream, TlsConnectorData, TlsStream};
use crate::client::config::{RustlsTlsClientConfigProvider, RustlsTlsConnectorConfig};
use crate::dep::tokio_rustls::TlsConnector as RustlsConnector;
use crate::types::TlsTunnel;
use rama_core::conversion::{RamaInto, RamaTryFrom};
use rama_core::error::{BoxError, BoxErrorExt as _, ErrorContext};
use rama_core::extensions::{Extensions, ExtensionsRef};
use rama_core::io::Io;
use rama_core::telemetry::tracing;
use rama_core::{Layer, Service};
use rama_net::address::Host;
use rama_net::client::{
    ConnectionAttempt, ConnectionError, ConnectionErrorKind, ConnectionPolicyScope,
    ConnectorService, EstablishedClientConnection,
};
use rama_net::extensions::StreamTransformed;
use rama_net::{
    AuthorityInputExt, Protocol, ProtocolInputExt,
    tls::{ApplicationProtocol, TlsAlpn, default_tls_alpn},
};
use rama_tls::client::{NegotiatedTlsParameters, TlsClientConfig, TlsConnectionReuse, TlsPoolId};
use rama_tls::{TlsTunnelMode, resolve_tls_tunnel};
#[cfg(feature = "http")]
use rama_utils::collections::smallvec::smallvec;
use rama_utils::macros::generate_set_and_with;

#[cfg(feature = "http")]
use ::{
    rama_core::error::ErrorExt,
    rama_net::http::{TargetHttpVersion, Version},
};

/// A [`Layer`] which wraps the given service with a [`TlsConnector`].
///
/// See [`TlsConnector`] for more information.
#[derive(Debug, Clone)]
pub struct TlsConnectorLayer<K = ConnectorKindAuto> {
    base_config: Option<TlsClientConfig>,
    kind: K,
}

impl<K> TlsConnectorLayer<K> {
    generate_set_and_with! {
        /// Define the base [`TlsClientConfig`] for this [`TlsConnectorLayer`].
        ///
        /// Auto and secure connectors layer per-request TLS pieces on top of this
        /// base. Tunnel connectors intentionally use only this base plus the
        /// proxy-scoped [`TlsTunnel`] fields.
        pub fn base_config(mut self, base: Option<TlsClientConfig>) -> Self {
            self.base_config = base;
            self
        }
    }
}

impl TlsConnectorLayer<ConnectorKindAuto> {
    /// Creates a new [`TlsConnectorLayer`] which will establish
    /// a secure connection when the input protocol is secure. Otherwise it
    /// forwards the inner connection. The logical authority remains the default
    /// server identity.
    #[must_use]
    pub fn auto() -> Self {
        Self {
            base_config: None,
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
            base_config: None,
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
            base_config: None,
            kind: ConnectorKindTunnel { host },
        }
    }
}

impl<K: Clone, S> Layer<S> for TlsConnectorLayer<K> {
    type Service = TlsConnector<S, K>;

    fn layer(&self, inner: S) -> Self::Service {
        TlsConnector {
            inner,
            base_config: self.base_config.clone(),
            kind: self.kind.clone(),
        }
    }

    fn into_layer(self, inner: S) -> Self::Service {
        TlsConnector {
            inner,
            base_config: self.base_config,
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
    pub const fn new(inner: S, kind: K) -> Self {
        Self {
            inner,
            base_config: None,
            kind,
        }
    }

    generate_set_and_with! {
        /// Define the base [`TlsClientConfig`] for this [`TlsConnector`].
        ///
        /// Auto and secure connectors layer per-request TLS pieces on top of this
        /// base. Tunnel connectors intentionally use only this base plus the
        /// proxy-scoped [`TlsTunnel`] fields.
        pub fn base_config(mut self, base: Option<TlsClientConfig>) -> Self {
            self.base_config = base;
            self
        }
    }
}

impl<S> TlsConnector<S, ConnectorKindAuto> {
    /// Creates a new [`TlsConnector`] which will establish
    /// a secure connection when the input protocol is secure. Otherwise it
    /// forwards the inner connection. The logical authority remains the default
    /// server identity.
    pub fn auto(inner: S) -> Self {
        Self::new(inner, ConnectorKindAuto)
    }
}

impl<S> TlsConnector<S, ConnectorKindSecure> {
    /// Creates a new [`TlsConnector`] which will always
    /// establish a secure connection regardless of the request it is for.
    pub fn secure(inner: S) -> Self {
        Self::new(inner, ConnectorKindSecure)
    }
}

impl<S> TlsConnector<S, ConnectorKindTunnel> {
    /// Creates a new [`TlsConnector`] which will establish
    /// a secure connection if the request is to be tunneled.
    pub fn tunnel(inner: S, host: Option<Host>) -> Self {
        Self::new(inner, ConnectorKindTunnel { host })
    }
}

// this way we do not need a hacky macro... however is there a way to do this without needing to hacK?!?!

impl<S, Input> Service<Input> for TlsConnector<S, ConnectorKindAuto>
where
    S: ConnectorService<Input, Connection: Io + Unpin>,
    Input: AuthorityInputExt + ProtocolInputExt + ExtensionsRef + Send + 'static,
{
    type Output = EstablishedClientConnection<AutoTlsStream<S::Connection>, Input>;
    type Error = ConnectionError;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        self.check_attempt_policy(&input, input.protocol().is_some_and(Protocol::is_secure))?;
        let EstablishedClientConnection { input, conn } = self.inner.connect(input).await?;

        let authority = input.authority().ok_or_else(|| {
            ConnectionError::local(
                BoxError::from_static_str("TlsConnector(auto): authority missing from input"),
                ConnectionErrorKind::InvalidInput,
            )
        })?;
        let app_protocol = input.protocol();

        if !app_protocol.is_some_and(Protocol::is_secure) {
            self.check_attempt_policy(&input, false)?;
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

        let server_host = &authority.host;

        tracing::trace!(
            server.address = %authority.host,
            server.port = authority.port_u16(),
            "TlsConnector(auto): attempt to secure inner connection w/ app protcol: {:?}",
            app_protocol,
        );

        let (connector_data, effective_id) = self
            .connector_data(input.extensions(), app_protocol)
            .map_err(|error| {
                ConnectionError::local(error, ConnectionErrorKind::InvalidInput)
                    .context("TlsConnector(auto): build connector configuration")
            })?;

        let scope = Self::check_connector_data(&input, &connector_data, &authority.host)?;
        let reuse = TlsConnectionReuse::new(
            RustlsTlsClientConfigProvider,
            input.extensions(),
            effective_id,
        );

        let (stream, negotiated_params) = self
            .handshake(connector_data, Some(server_host), conn)
            .await
            .map_err(|error| {
                ConnectionError::application(error, ConnectionErrorKind::Protocol)
                    .context("TlsConnector(auto): TLS handshake")
            })?;

        tracing::trace!(
            server.address = %authority.host,
            server.port = authority.port_u16(),
            "TlsConnector(auto): protocol secure, established tls connection w/ app protcol: {:?}",
            app_protocol,
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

        reuse.publish(conn.extensions());
        conn.extensions().insert(scope);
        conn.extensions().insert(negotiated_params);
        conn.extensions().insert(StreamTransformed {
            by: "rama-tls-rustls::TlsConnector",
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
            "TlsConnector(secure): attempt to secure inner connection w/ app protcol: {:?}",
            input.protocol(),
        );

        let server_host = &authority.host;

        let app_protocol = input.protocol();
        let (connector_data, effective_id) = self
            .connector_data(input.extensions(), app_protocol)
            .map_err(|error| {
                ConnectionError::local(error, ConnectionErrorKind::InvalidInput)
                    .context("TlsConnector(secure): build connector configuration")
            })?;

        let scope = Self::check_connector_data(&input, &connector_data, &authority.host)?;
        let reuse = TlsConnectionReuse::new(
            RustlsTlsClientConfigProvider,
            input.extensions(),
            effective_id,
        );

        let (conn, negotiated_params) = self
            .handshake(connector_data, Some(server_host), conn)
            .await
            .map_err(|error| {
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

        reuse.publish(conn.extensions());
        conn.extensions().insert(scope);
        conn.extensions().insert(negotiated_params);
        conn.extensions().insert(StreamTransformed {
            by: "rama-tls-rustls::TlsConnector",
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
        let (connector_data, effective_id) = self
            .tunnel_connector_data(tunnel.as_ref(), tunnel_protocol)
            .map_err(|error| {
                ConnectionError::local(error, ConnectionErrorKind::InvalidInput)
                    .context("TlsConnector(tunnel): build connector configuration")
            })?;

        let (conn, negotiated_params) = self
            .handshake(connector_data, maybe_server_host, conn)
            .await
            .map_err(|error| {
                ConnectionError::transport(error, ConnectionErrorKind::Protocol)
                    .context("TlsConnector(tunnel): TLS handshake")
            })?;
        let conn = AutoTlsStream::secure(conn);

        TlsConnectionReuse::tunnel(RustlsTlsClientConfigProvider, effective_id)
            .publish(conn.extensions());
        conn.extensions().insert(negotiated_params);
        conn.extensions().insert(StreamTransformed {
            by: "rama-tls-rustls::TlsConnector",
        });
        tracing::trace!("TlsConnector(tunnel): connection secured");
        Ok(EstablishedClientConnection { input, conn })
    }
}

impl<S, K> TlsConnector<S, K> {
    fn tunnel_connector_data(
        &self,
        tunnel: Option<&TlsTunnel>,
        application_protocol: Option<&Protocol>,
    ) -> Result<(TlsConnectorData, Option<TlsPoolId>), BoxError> {
        let effective = self.tunnel_config_extensions(tunnel, application_protocol);

        let config = RustlsTlsConnectorConfig::from_extensions(&effective);
        let effective_id = config.pool_id();
        Ok((TlsConnectorData::try_from(config)?, effective_id))
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

    /// Reject an incompatible discovery policy before dialing. Ordinary connections
    /// retain their existing inner-connector override behavior.
    fn check_attempt_policy(
        &self,
        input: &(impl AuthorityInputExt + ExtensionsRef),
        secure: bool,
    ) -> Result<(), ConnectionError> {
        let Some(attempt) = input.extensions().get_ref::<ConnectionAttempt>() else {
            return Ok(());
        };
        let request = RustlsTlsConnectorConfig::from_extensions(input.extensions());
        let scope = if request.has_overrides() {
            ConnectionPolicyScope::Request
        } else {
            ConnectionPolicyScope::Connector
        };
        if !secure {
            return attempt.check_policy(scope, None);
        }

        let merged;
        let extensions = match (&self.base_config, request.has_overrides()) {
            (Some(base), true) => {
                merged = input.extensions().fork().with_base(base.as_extensions());
                &merged
            }
            (Some(base), false) => base.as_extensions(),
            (None, _) => input.extensions(),
        };
        let effective = RustlsTlsConnectorConfig::from_extensions(extensions);
        if !effective.authenticates_server() {
            return attempt.check_policy(scope, None);
        }
        let authority = effective
            .server_name
            .is_none()
            .then(|| input.authority())
            .flatten();
        let peer = effective
            .server_name
            .map(|name| &name.0)
            .or_else(|| authority.as_ref().map(|authority| &authority.host));
        attempt.check_policy(scope, peer)
    }

    /// Classify the request after inner connectors have added their extensions,
    /// and check the actual native configuration used by this handshake.
    fn check_connector_data(
        input: &impl ExtensionsRef,
        data: &TlsConnectorData,
        server_host: &Host,
    ) -> Result<ConnectionPolicyScope, ConnectionError> {
        let scope = if RustlsTlsConnectorConfig::from_extensions(input.extensions()).has_overrides()
        {
            ConnectionPolicyScope::Request
        } else {
            ConnectionPolicyScope::Connector
        };
        if let Some(attempt) = input.extensions().get_ref::<ConnectionAttempt>() {
            let peer = data
                .verification_enabled
                .then_some(data.server_name.as_ref().unwrap_or(server_host));
            attempt.check_policy(scope, peer)?;
        }
        Ok(scope)
    }

    fn connector_data(
        &self,
        request_extensions: &Extensions,
        application_protocol: Option<&Protocol>,
    ) -> Result<(TlsConnectorData, Option<TlsPoolId>), BoxError> {
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

        let config = RustlsTlsConnectorConfig::from_extensions(&extensions);
        let effective_id = config.pool_id();
        Ok((TlsConnectorData::try_from(config)?, effective_id))
    }

    async fn handshake<T>(
        &self,
        connector_data: TlsConnectorData,
        maybe_server_host: Option<&Host>,
        stream: T,
    ) -> Result<(RustlsTlsStream<T>, NegotiatedTlsParameters), BoxError>
    where
        T: Io + ExtensionsRef + Unpin,
    {
        #[cfg(feature = "dial9")]
        let dial9_server_name = connector_data
            .server_name
            .clone()
            .or_else(|| maybe_server_host.cloned())
            .context("server identity missing")?;

        let authenticated_identity = connector_data
            .verification_enabled
            .then(|| {
                connector_data
                    .server_name
                    .clone()
                    .or_else(|| maybe_server_host.cloned())
            })
            .flatten();
        let server_name = rama_crypto::pki_types::ServerName::rama_try_from(
            connector_data
                .server_name
                .or_else(|| maybe_server_host.cloned())
                .context("server identity missing")?,
        )?;

        let connector = RustlsConnector::from(connector_data.client_config);

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

        let server_certificate_chain = if connector_data.store_server_certificate_chain {
            conn_data_ref.peer_certificates().map(RamaInto::rama_into)
        } else {
            None
        };

        let params = NegotiatedTlsParameters {
            protocol_version: conn_data_ref
                .protocol_version()
                .context("no protocol version available")?
                .rama_into(),
            application_layer_protocol: conn_data_ref
                .alpn_protocol()
                .map(ApplicationProtocol::from),
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
}

fn apply_default_alpn(effective_extensions: &Extensions, application_protocol: Option<&Protocol>) {
    // Any ALPN in the effective chain is explicit connector policy, whether
    // supplied by the request or inherited from a base configuration.
    if effective_extensions.get_ref::<TlsAlpn>().is_some() {
        return;
    }
    let Some(protocol) = application_protocol else {
        return;
    };

    effective_extensions.insert(default_tls_alpn(protocol).unwrap_or_else(TlsAlpn::empty));
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

    ext.insert(TlsAlpn(smallvec![target_alpn]));
    Ok(())
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
                "TargetHTTPVersion incompatible with tls ALPN negotiated version",
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

#[non_exhaustive]
#[derive(Debug, Clone)]
/// A connector which can be used to establish a connection to a server
/// in function of the input, meaning either it will be a secure
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
/// secure tls tunnel connections.
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
    use rama_net::client::pool::ConnectionReuse;

    use rama_core::{ServiceInput, service::service_fn};
    use rama_net::{
        address::HostWithPort,
        client::{ConnectRequest, ConnectionErrorDomain},
    };
    use rama_tls::client::{ServerVerifyMode, TlsServerName, TlsServerVerify};

    use rama_crypto::cert::generate_server_auth;
    use rama_net::stream::service::EchoService;
    use rama_tls::server::{GeneratedServerAuthConfig, ServerAuthData, TlsServerConfig};
    use std::{sync::Arc, time::Duration};

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

    #[test]
    fn tunnel_config_uses_only_base_and_explicit_tunnel_policy() {
        use rama_net::tls::TlsAlpn;
        use rama_tls::client::{ServerVerifyMode, TlsServerName, TlsServerVerify};

        let base_name = Host::from_static("proxy-cert.example");
        let connector = TlsConnector::tunnel((), None).with_base_config(
            TlsClientConfig::new()
                .with_alpn_http_2()
                .with_server_name(base_name.clone())
                .with_server_verify(ServerVerifyMode::Disable),
        );
        let tunnel = TlsTunnel {
            server_identity: Some(Host::from_static("proxy-route.example")),
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
            Some(base_name)
        );
        assert_eq!(
            effective
                .get_ref::<TlsServerVerify>()
                .map(|verify| verify.0),
            Some(ServerVerifyMode::Disable)
        );
    }

    #[test]
    fn tunnel_config_isolates_all_origin_tls_extensions() {
        use crate::client::{ModifyRustlsClientConfig, RustlsClientConfigExt as _};
        use rama_crypto::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
        use rama_tls::{
            KeyLogIntent, ProtocolVersion, TlsKeyLog,
            client::{
                ClientAuth, ClientAuthData, ServerVerifyMode, TlsClientAuth, TlsServerCertPinCheck,
                TlsServerCertPins, TlsServerTrust,
            },
        };
        use std::sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        };

        let base_modifier_used = Arc::new(AtomicBool::new(false));
        let base_modifier_flag = base_modifier_used.clone();
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
            .with_modify_rustls_config(move |config| {
                base_modifier_flag.store(true, Ordering::SeqCst);
                Ok(config)
            });
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
            .write_to(&origin);
        origin.insert(ModifyRustlsClientConfig::new(|_| {
            panic!("origin rustls modifier leaked into proxy TLS")
        }));
        origin.insert(TlsTunnel {
            server_identity: Some(Host::from_static("proxy-route.example")),
            application_protocol: Some(Protocol::HTTPS),
            alpn: None,
        });

        let tunnel = origin.get_ref::<TlsTunnel>();
        let effective = connector.tunnel_config_extensions(tunnel, Some(&Protocol::HTTPS));
        let config = RustlsTlsConnectorConfig::from_extensions(&effective);

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
        assert_eq!(
            config
                .server_cert_pins
                .expect("base pins")
                .check(Some(&base_name), &base_pin),
            TlsServerCertPinCheck::Matched
        );
        assert!(config.modify.is_some());

        let (data, effective_id) = connector
            .tunnel_connector_data(tunnel, Some(&Protocol::HTTPS))
            .expect("resolved tunnel connector data");
        assert!(effective_id.is_some_and(|id| !id.is_reusable()));
        assert!(base_modifier_used.load(Ordering::SeqCst));
        assert_eq!(data.server_name, Some(base_name));
        assert!(data.store_server_certificate_chain);
        assert_eq!(
            data.client_config.alpn_protocols,
            vec![ApplicationProtocol::HTTP_2.as_bytes().to_vec()]
        );
    }

    #[test]
    fn explicit_empty_tunnel_alpn_overrides_base() {
        use rama_net::tls::TlsAlpn;

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

    #[cfg(feature = "http")]
    mod http_alpn_resolution {
        use super::*;
        use rama_core::extensions::Extensions;
        use rama_net::http::{FallbackHttpVersion, TargetHttpVersion, Version};
        use rama_net::tls::ApplicationProtocol;

        fn alpn_of(ext: &Extensions) -> Option<Vec<ApplicationProtocol>> {
            ext.get_ref::<TlsAlpn>().map(|a| a.0.clone().into_vec())
        }

        #[test]
        fn forces_http11_alpn_when_target_is_http11() {
            let ext = Extensions::new();
            ext.insert(TargetHttpVersion(Version::HTTP_11));

            resolve_http_alpn(&ext, Some(&Protocol::HTTPS)).unwrap();
            assert_eq!(alpn_of(&ext), Some(vec![ApplicationProtocol::HTTP_11]));
        }

        #[test]
        fn forces_http2_alpn_when_target_is_http2() {
            let ext = Extensions::new();
            ext.insert(TargetHttpVersion(Version::HTTP_2));

            resolve_http_alpn(&ext, Some(&Protocol::HTTPS)).unwrap();
            assert_eq!(alpn_of(&ext), Some(vec![ApplicationProtocol::HTTP_2]));
        }

        #[test]
        fn leaves_alpn_untouched_without_target_version() {
            let ext = Extensions::new();
            resolve_http_alpn(&ext, Some(&Protocol::HTTPS)).unwrap();
            assert_eq!(alpn_of(&ext), None);
        }

        #[test]
        fn fallback_version_does_not_constrain_alpn() {
            let ext = Extensions::new();
            ext.insert(TlsAlpn::http_auto());
            ext.insert(FallbackHttpVersion(Version::HTTP_11));

            resolve_http_alpn(&ext, Some(&Protocol::HTTPS)).unwrap();
            assert_eq!(
                alpn_of(&ext),
                Some(vec![
                    ApplicationProtocol::HTTP_2,
                    ApplicationProtocol::HTTP_11
                ])
            );
        }

        #[test]
        fn overrides_existing_alpn_to_match_target() {
            let ext = Extensions::new();
            ext.insert(TlsAlpn::http_auto());
            ext.insert(TargetHttpVersion(Version::HTTP_11));

            resolve_http_alpn(&ext, Some(&Protocol::HTTPS)).unwrap();
            assert_eq!(alpn_of(&ext), Some(vec![ApplicationProtocol::HTTP_11]));
        }

        #[test]
        fn inherited_alpn_is_preserved_for_any_application_protocol() {
            let base = Extensions::new();
            base.insert(TlsAlpn::http_auto());
            let request = Extensions::new();
            let effective = request.fork().with_base(&base);

            apply_default_alpn(&effective, Some(&Protocol::ICAPS));

            assert_eq!(
                alpn_of(&effective),
                Some(vec![
                    ApplicationProtocol::HTTP_2,
                    ApplicationProtocol::HTTP_11
                ])
            );
        }

        #[test]
        fn derives_default_alpn_when_no_explicit_policy_exists() {
            let effective = Extensions::new();

            apply_default_alpn(&effective, Some(&Protocol::HTTPS));

            assert_eq!(
                alpn_of(&effective),
                Some(vec![
                    ApplicationProtocol::HTTP_2,
                    ApplicationProtocol::HTTP_11
                ])
            );
        }

        #[test]
        fn derives_empty_alpn_for_icaps_without_explicit_policy() {
            let effective = Extensions::new();

            apply_default_alpn(&effective, Some(&Protocol::ICAPS));

            assert_eq!(alpn_of(&effective), Some(Vec::new()));
        }

        #[test]
        fn explicit_request_alpn_wins_for_icaps() {
            let base = Extensions::new();
            base.insert(TlsAlpn::http_auto());
            let request = Extensions::new();
            request.insert(TlsAlpn::http_1());
            let effective = request.fork().with_base(&base);

            apply_default_alpn(&effective, Some(&Protocol::ICAPS));

            assert_eq!(
                alpn_of(&effective),
                Some(vec![ApplicationProtocol::HTTP_11])
            );
        }

        #[test]
        fn inherited_http_alpn_survives_for_https() {
            let base = Extensions::new();
            base.insert(TlsAlpn::http_1());
            let request = Extensions::new();
            let effective = request.fork().with_base(&base);

            apply_default_alpn(&effective, Some(&Protocol::HTTPS));

            assert_eq!(
                alpn_of(&effective),
                Some(vec![ApplicationProtocol::HTTP_11])
            );
        }

        #[test]
        fn inherited_alpn_survives_without_application_protocol() {
            let base = Extensions::new();
            base.insert(TlsAlpn::http_1());
            let effective = Extensions::new().with_base(&base);

            apply_default_alpn(&effective, None);

            assert_eq!(
                alpn_of(&effective),
                Some(vec![ApplicationProtocol::HTTP_11])
            );
        }

        #[test]
        fn icaps_ignores_http_version_hint() {
            let ext = Extensions::new();
            ext.insert(TlsAlpn::empty());
            ext.insert(TargetHttpVersion(Version::HTTP_2));

            resolve_http_alpn(&ext, Some(&Protocol::ICAPS)).unwrap();

            assert_eq!(alpn_of(&ext), Some(Vec::new()));
        }
    }
}
