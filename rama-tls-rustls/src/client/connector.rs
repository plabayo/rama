use std::{marker::PhantomData, num::NonZeroUsize};

use rama_core::{
    Layer, Service,
    conversion::{RamaFrom, RamaInto, RamaTryFrom},
    error::{BoxError, BoxErrorExt as _, ErrorContext},
    extensions::{Extensions, ExtensionsRef},
    io::Io,
    telemetry::tracing,
};
#[cfg(all(test, feature = "http"))]
use rama_net::http::Version;
use rama_net::{
    AuthorityInputExt, ConnectorTargetInputExt, Protocol, ProtocolInputExt,
    address::Host,
    client::{
        ConnectionAttempt, ConnectionError, ConnectionErrorKind, ConnectionPolicyScope,
        ConnectorService, EstablishedClientConnection,
    },
    extensions::StreamTransformed,
    tls::{ApplicationProtocol, ServerName, TlsAlpn, TlsRequired, default_tls_alpn},
};
#[cfg(feature = "http")]
use rama_net::{
    http::{FallbackHttpVersion, HttpRequestVersion, TargetHttpVersion},
    tls::AlpnPolicy,
};
use rama_tls::client::{
    EchRequirement, NegotiatedTlsAlgorithms, NegotiatedTlsParameters, TlsClientConfig,
    TlsConnectionReuse, publish_tls_required, resolve_target_ech,
};
#[cfg(feature = "http")]
use rama_tls::{
    alpn::required_alpn_override,
    client::{http_alpn_override, negotiated_http_version},
};
#[cfg(feature = "http")]
use rama_utils::collections::smallvec::smallvec;
use rama_utils::macros::{define_inner_service_accessors, generate_set_and_with};

use super::{
    AutoTlsStream, RustlsServerTrustCache, RustlsTlsStream, TlsConnectorData, TlsStream,
    connector_data::reject_unsupported,
};
use crate::{
    client::config::{RustlsTlsClientConfigProvider, RustlsTlsConnectorConfig},
    dep::tokio_rustls::TlsConnector as RustlsConnector,
};

/// A [`Layer`] which wraps the given service with a [`TlsConnector`].
///
/// See [`TlsConnector`] for more information.
#[derive(Debug, Clone)]
pub struct TlsConnectorLayer<K = ConnectorKindAuto> {
    base_config: Option<TlsClientConfig>,
    server_trust_cache_capacity: NonZeroUsize,
    kind: PhantomData<K>,
}

impl<K> TlsConnectorLayer<K> {
    generate_set_and_with! {
        /// Set the capacity of the derived server trust cache for new connectors.
        pub fn server_trust_cache_capacity(mut self, capacity: NonZeroUsize) -> Self {
            self.server_trust_cache_capacity = capacity;
            self
        }
    }

    generate_set_and_with! {
        /// Define the base [`TlsClientConfig`] for this [`TlsConnectorLayer`].
        ///
        /// Per-request TLS pieces of the connection being established layer on
        /// top of this base; the pieces of a connection underneath never do.
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
            server_trust_cache_capacity: RustlsServerTrustCache::DEFAULT_CAPACITY,
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
            base_config: None,
            server_trust_cache_capacity: RustlsServerTrustCache::DEFAULT_CAPACITY,
            kind: PhantomData,
        }
    }
}

impl<K: Clone, S> Layer<S> for TlsConnectorLayer<K> {
    type Service = TlsConnector<S, K>;

    fn layer(&self, inner: S) -> Self::Service {
        TlsConnector {
            inner,
            base_config: self.base_config.clone(),
            server_trust_cache: RustlsServerTrustCache::new(self.server_trust_cache_capacity),
            kind: PhantomData,
        }
    }

    fn into_layer(self, inner: S) -> Self::Service {
        TlsConnector {
            inner,
            base_config: self.base_config,
            server_trust_cache: RustlsServerTrustCache::new(self.server_trust_cache_capacity),
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
    server_trust_cache: RustlsServerTrustCache,
    kind: PhantomData<K>,
}

impl<S, K> TlsConnector<S, K> {
    define_inner_service_accessors!();

    generate_set_and_with! {
        /// Replace this connector's derived server trust cache with a new cache.
        /// Subsequent clones share the replacement cache.
        pub fn server_trust_cache_capacity(mut self, capacity: NonZeroUsize) -> Self {
            self.server_trust_cache = RustlsServerTrustCache::new(capacity);
            self
        }
    }

    /// Creates a new [`TlsConnector`].
    pub const fn new(inner: S) -> Self {
        Self {
            inner,
            base_config: None,
            server_trust_cache: RustlsServerTrustCache::new(
                RustlsServerTrustCache::DEFAULT_CAPACITY,
            ),
            kind: PhantomData,
        }
    }

    generate_set_and_with! {
        /// Define the base [`TlsClientConfig`] for this [`TlsConnector`].
        ///
        /// Per-request TLS pieces of the connection being established layer on
        /// top of this base; the pieces of a connection underneath never do.
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
        Self::new(inner)
    }

    /// Turn this connector into one which always handshakes, see [`TlsConnector::secure`],
    /// keeping its base configuration.
    #[must_use]
    pub fn into_secure(self) -> TlsConnector<S, ConnectorKindSecure> {
        TlsConnector {
            inner: self.inner,
            base_config: self.base_config,
            server_trust_cache: self.server_trust_cache,
            kind: PhantomData,
        }
    }
}

impl<S> TlsConnector<S, ConnectorKindSecure> {
    /// Creates a new [`TlsConnector`] which will always
    /// establish a secure connection regardless of the request it is for.
    pub fn secure(inner: S) -> Self {
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
    Input: AuthorityInputExt + ProtocolInputExt + ExtensionsRef + Send + 'static,
{
    type Output = EstablishedClientConnection<AutoTlsStream<S::Connection>, Input>;
    type Error = ConnectionError;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        self.check_attempt_policy(&input, secure_requested(&input))?;
        let EstablishedClientConnection { input, conn } = self.inner.connect(input).await?;

        let authority = input.target_authority().ok_or_else(|| {
            ConnectionError::local(
                BoxError::from_static_str("TlsConnector(auto): authority missing from input"),
                ConnectionErrorKind::InvalidInput,
            )
        })?;
        let app_protocol = input.target_protocol();

        if !secure_requested(&input) {
            self.check_attempt_policy(&input, false)?;
            tracing::trace!(
                server.address = %authority.host,
                server.port = authority.port_u16(),
                "TlsConnector(auto): protocol not secure, return inner connection",
            );

            publish_tls_required(conn.extensions(), false);
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

        let connector_data = self
            .connector_data(input.extensions(), app_protocol)
            .await
            .map_err(|error| {
                ConnectionError::local(error, ConnectionErrorKind::InvalidInput)
                    .context("TlsConnector(auto): build connector configuration")
            })?;

        let fallback_server_name = transport_server_name(&connector_data, server_host)?;
        let scope =
            Self::check_connector_data(&input, &connector_data, fallback_server_name.as_ref())?;
        let reuse = TlsConnectionReuse::new(RustlsTlsClientConfigProvider, input.extensions());

        let (stream, negotiated_params) = self
            .handshake(connector_data, fallback_server_name.as_ref(), conn)
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

        let authority = input.target_authority().ok_or_else(|| {
            ConnectionError::local(
                BoxError::from_static_str("TlsConnector(secure): authority missing from input"),
                ConnectionErrorKind::InvalidInput,
            )
        })?;
        tracing::trace!(
            server.address = %authority.host,
            server.port = authority.port_u16(),
            "TlsConnector(secure): attempt to secure inner connection w/ app protcol: {:?}",
            input.target_protocol(),
        );

        let server_host = &authority.host;

        let app_protocol = input.target_protocol();
        let connector_data = self
            .connector_data(input.extensions(), app_protocol)
            .await
            .map_err(|error| {
                ConnectionError::local(error, ConnectionErrorKind::InvalidInput)
                    .context("TlsConnector(secure): build connector configuration")
            })?;

        let fallback_server_name = transport_server_name(&connector_data, server_host)?;
        let scope =
            Self::check_connector_data(&input, &connector_data, fallback_server_name.as_ref())?;
        let reuse = TlsConnectionReuse::new(RustlsTlsClientConfigProvider, input.extensions());

        let (conn, negotiated_params) = self
            .handshake(connector_data, fallback_server_name.as_ref(), conn)
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
            by: "rama-tls-rustls::TlsConnector",
        });
        Ok(EstablishedClientConnection { input, conn })
    }
}

impl<S, K> TlsConnector<S, K> {
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
        if effective.get_ref::<EchRequirement>() == Some(&EchRequirement::Required) {
            return Err(ConnectionError::local(
                BoxError::from_static_str("required ECH is not supported by the rustls connector"),
                ConnectionErrorKind::InvalidInput,
            ));
        }
        if secure && let Some(target) = input.connector_target() {
            resolve_target_ech(&effective, &target, false)
                .map_err(|error| ConnectionError::local(error, ConnectionErrorKind::Unavailable))?;
        }
        let Some(attempt) = input.extensions().get_ref::<ConnectionAttempt>() else {
            return Ok(());
        };
        let request = RustlsTlsConnectorConfig::from_extensions(input.extensions());
        let scope = if !request.is_empty() {
            ConnectionPolicyScope::Request
        } else {
            ConnectionPolicyScope::Connector
        };
        if !secure {
            return attempt.check_policy(scope, None);
        }

        let config = RustlsTlsConnectorConfig::from_extensions(&effective);
        if !config.authenticates_server() {
            return attempt.check_policy(scope, None);
        }
        // A target that is not a server name cannot be authenticated.
        let fallback = config
            .server_name
            .is_none()
            .then(|| input.target_authority())
            .flatten()
            .and_then(|authority| ServerName::try_from(&authority.host).ok());
        attempt.check_policy(scope, config.server_name.or(fallback.as_ref()))
    }

    /// Classify the request after inner connectors have added their extensions,
    /// and check the actual native configuration used by this handshake.
    fn check_connector_data(
        input: &impl ExtensionsRef,
        data: &TlsConnectorData,
        fallback_server_name: Option<&ServerName>,
    ) -> Result<ConnectionPolicyScope, ConnectionError> {
        let scope = if !RustlsTlsConnectorConfig::from_extensions(input.extensions()).is_empty() {
            ConnectionPolicyScope::Request
        } else {
            ConnectionPolicyScope::Connector
        };
        if let Some(attempt) = input.extensions().get_ref::<ConnectionAttempt>() {
            let peer = data
                .verification_enabled
                .then(|| data.server_name.as_ref().or(fallback_server_name))
                .flatten();
            attempt.check_policy(scope, peer)?;
            return Ok(attempt.policy_scope());
        }
        Ok(scope)
    }

    async fn connector_data(
        &self,
        request_extensions: &Extensions,
        application_protocol: Option<&Protocol>,
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

        reject_unsupported(&RustlsTlsConnectorConfig::from_extensions(&extensions))?;
        let verification = self
            .server_trust_cache
            .server_verification_async(&extensions)
            .await?;
        TlsConnectorData::from_extensions(
            &extensions,
            verification.as_ref(),
            &self.server_trust_cache,
        )
    }

    async fn handshake<T>(
        &self,
        connector_data: TlsConnectorData,
        maybe_server_name: Option<&ServerName>,
        stream: T,
    ) -> Result<(RustlsTlsStream<T>, NegotiatedTlsParameters), BoxError>
    where
        T: Io + ExtensionsRef + Unpin,
    {
        let handshake = async {
            #[cfg(feature = "dial9")]
            let dial9_server_name = rama_core::telemetry::dial9::Dial9Handle::current()
                .is_enabled()
                .then(|| {
                    connector_data
                        .server_name
                        .clone()
                        .or_else(|| maybe_server_name.cloned())
                })
                .flatten();

            let authenticated_identity = connector_data
                .verification_enabled
                .then(|| {
                    connector_data
                        .server_name
                        .clone()
                        .or_else(|| maybe_server_name.cloned())
                })
                .flatten();
            let server_name = rama_crypto::pki_types::ServerName::rama_try_from(Host::from(
                connector_data
                    .server_name
                    .or_else(|| maybe_server_name.cloned())
                    .context("server identity missing")?,
            ))?;

            let connector = RustlsConnector::from(connector_data.client_config);

            #[cfg(feature = "dial9")]
            crate::dial9::record_handshake_started(dial9_server_name.as_ref());

            let stream = match connector.connect(server_name, stream).await {
                Ok(stream) => stream,
                Err(err) => {
                    #[cfg(feature = "dial9")]
                    crate::dial9::record_handshake_failed(dial9_server_name.as_ref(), &err);
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
                algorithms: NegotiatedTlsAlgorithms::rama_from(&***conn_data_ref),
                server_hello: None,
            };

            #[cfg(feature = "dial9")]
            {
                let depth = params
                    .peer_certificate_chain
                    .as_ref()
                    .map_or(0, |chain| chain.len());
                crate::dial9::record_handshake_completed(
                    dial9_server_name.as_ref(),
                    params.protocol_version,
                    conn_data_ref.alpn_protocol(),
                    depth,
                );
            }

            Ok((stream, params))
        };
        #[cfg(feature = "dial9")]
        {
            rama_core::telemetry::dial9::record_result("tls.rustls.client", handshake).await
        }
        #[cfg(not(feature = "dial9"))]
        handshake.await
    }
}

/// Return the transport host as server name when the connector data names none.
fn transport_server_name(
    data: &TlsConnectorData,
    host: &Host,
) -> Result<Option<ServerName>, ConnectionError> {
    if data.server_name.is_some() {
        return Ok(None);
    }
    ServerName::try_from(host)
        .context("server identity is not a DNS name or IP address")
        .map(Some)
        .map_err(|error| ConnectionError::local(error, ConnectionErrorKind::InvalidInput))
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

    ext.insert(TlsAlpn(smallvec![target_alpn]));
    Ok(())
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

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use rama_core::{ServiceInput, extensions::NoExtensionsTransfer, service::service_fn};
    use rama_crypto::cert::generate_server_auth;
    use rama_net::{
        address::{Domain, HostWithPort},
        client::{
            ConnectRequest, ConnectionErrorDomain, EstablishedClientConnection,
            pool::ConnectionReuse, proxy_request,
        },
        stream::service::EchoService,
        tls::{ServerName, TlsAlpn},
    };
    #[cfg(feature = "http")]
    use rama_tls::ProtocolVersion;
    use rama_tls::{
        client::{ServerVerifyMode, TlsServerVerify},
        server::{GeneratedServerAuthConfig, ServerAuthData, TlsServerConfig},
    };

    use super::*;

    #[test]
    fn layered_connectors_own_independent_caches_and_clones_share() {
        let layer = TlsConnectorLayer::secure()
            .with_server_trust_cache_capacity(NonZeroUsize::new(2).unwrap());
        let first = layer.layer(());
        let clone = first.clone();
        let second = layer.layer(());
        let config = TlsClientConfig::new()
            .try_with_server_trust_anchors([
                rama_crypto::native_certs::bundled_root_certs()[0].clone()
            ])
            .unwrap();
        let resolve = |connector: &TlsConnector<_, _>| match connector
            .server_trust_cache
            .server_verification(config.as_extensions())
            .unwrap()
            .map(|verification| verification.verifier)
        {
            Some(rama_core::combinators::Either::A(roots)) => roots,
            _ => panic!("expected a rustls root store"),
        };
        let roots = resolve(&first);
        assert!(Arc::ptr_eq(&roots, &resolve(&clone)));
        assert!(!Arc::ptr_eq(&roots, &resolve(&second)));
    }

    fn origin_attempt() -> ConnectRequest {
        let input =
            ConnectRequest::new(HostWithPort::new(Host::from_static("origin.example"), 443))
                .with_application_protocol(Protocol::HTTPS);
        input.extensions().insert(
            ConnectionAttempt::new().with_authenticated_peer(Domain::from_static("origin.example")),
        );
        input
    }

    #[tokio::test]
    async fn discovery_rejects_incompatible_defaults_before_dial() {
        for base in [
            TlsClientConfig::new().with_server_verify(ServerVerifyMode::Disable),
            TlsClientConfig::new().with_server_name(Domain::from_static("other.example")),
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
                .with_server_name(Domain::from_static("other.example")),
        );
        let input = origin_attempt();
        input
            .extensions()
            .insert(TlsServerVerify(ServerVerifyMode::Auto));
        input
            .extensions()
            .insert(ServerName::from(Domain::from_static("origin.example")));
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
                        .insert(ServerName::from(Domain::from_static("other.example")));
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

    /// An input whose forwarded context names another host than its own target.
    #[derive(ExtensionsRef)]
    struct ForwardedInput(rama_core::extensions::Extensions);

    impl AuthorityInputExt for ForwardedInput {
        fn authority(&self) -> Option<rama_net::address::HostWithOptPort> {
            Some(Host::from_static("public.test").into())
        }

        fn target_authority(&self) -> Option<rama_net::address::HostWithOptPort> {
            Some(Domain::tld_localhost().into_host().into())
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
            .with_server_name(Domain::tld_localhost())
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
            let input = ConnectRequest::new(HostWithPort::localhost_domain_https())
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
                    ConnectionAttempt::new().with_authenticated_peer(Domain::tld_localhost()),
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

    #[test]
    fn assert_send() {
        rama_utils::test_helpers::assert_send::<TlsConnectorLayer>();
    }

    #[test]
    fn assert_sync() {
        rama_utils::test_helpers::assert_sync::<TlsConnectorLayer>();
    }

    #[cfg(feature = "http")]
    mod http_alpn_resolution {
        use rama_core::extensions::Extensions;
        use rama_net::{
            http::{FallbackHttpVersion, TargetHttpVersion, Version},
            tls::ApplicationProtocol,
        };

        use super::*;

        #[test]
        fn explicit_multiplexed_targets_reject_absent_negotiated_alpn() {
            let tls = NegotiatedTlsParameters {
                protocol_version: rama_tls::ProtocolVersion::TLSv1_3,
                application_layer_protocol: None,
                peer_certificate_chain: None,
                server_name: None,
                resumed: None,
                algorithms: Default::default(),
                server_hello: None,
            };
            for target in [
                None,
                Some(Version::HTTP_11),
                Some(Version::HTTP_2),
                Some(Version::HTTP_3),
            ] {
                let request = Extensions::new();
                if let Some(version) = target {
                    request.insert(TargetHttpVersion(version));
                }
                let connection = Extensions::new();
                let result = set_target_http_version(
                    Some(&Protocol::HTTPS),
                    &request,
                    &connection,
                    &tls,
                    Some(AlpnPolicy::Require),
                );
                assert_eq!(
                    result.is_err(),
                    matches!(target, Some(Version::HTTP_2 | Version::HTTP_3))
                );
                assert!(!connection.contains::<TargetHttpVersion>());
            }
        }

        fn alpn_of(ext: &Extensions) -> Option<Vec<ApplicationProtocol>> {
            ext.get_ref::<TlsAlpn>().map(|a| a.0.clone().into_vec())
        }

        #[test]
        fn forces_http11_alpn_when_target_is_http11() {
            let ext = Extensions::new();
            ext.insert(TargetHttpVersion(Version::HTTP_11));

            resolve_http_alpn(&ext, Some(&Protocol::HTTPS), None).unwrap();
            assert_eq!(alpn_of(&ext), Some(vec![ApplicationProtocol::HTTP_11]));
        }

        #[test]
        fn forces_http2_alpn_when_target_is_http2() {
            let ext = Extensions::new();
            ext.insert(TargetHttpVersion(Version::HTTP_2));

            resolve_http_alpn(&ext, Some(&Protocol::HTTPS), None).unwrap();
            assert_eq!(alpn_of(&ext), Some(vec![ApplicationProtocol::HTTP_2]));
        }

        #[test]
        fn leaves_alpn_untouched_without_target_version() {
            let ext = Extensions::new();
            resolve_http_alpn(&ext, Some(&Protocol::HTTPS), None).unwrap();
            assert_eq!(alpn_of(&ext), None);
        }

        #[test]
        fn fallback_version_does_not_constrain_alpn() {
            let ext = Extensions::new();
            ext.insert(TlsAlpn::http_auto());
            ext.insert(FallbackHttpVersion(Version::HTTP_11));

            resolve_http_alpn(&ext, Some(&Protocol::HTTPS), None).unwrap();
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

            resolve_http_alpn(&ext, Some(&Protocol::HTTPS), None).unwrap();
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

            resolve_http_alpn(&ext, Some(&Protocol::ICAPS), None).unwrap();

            assert_eq!(alpn_of(&ext), Some(Vec::new()));
        }
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
            .with_server_name(Domain::from_static("origin.example"))
            .with_server_verify(ServerVerifyMode::Disable)
            .with_ech_requirement(EchRequirement::Required)
            .write_to(&origin);
        origin
    }

    /// The input that dials a proxy, as the proxy connectors build it.
    fn nested_leg(origin: &Extensions) -> ConnectRequest {
        proxy_request(&"https://localhost:443".parse().unwrap(), origin)
    }

    #[test]
    fn a_nested_leg_takes_its_tls_config_from_the_connector() {
        let proxy_name = ServerName::from(Domain::from_static("proxy.example"));
        let connector = TlsConnector::auto(()).with_base_config(
            TlsClientConfig::new()
                .with_server_name(proxy_name.clone())
                .with_alpn_http_2(),
        );

        let leg = origin_tls_inputs().fork_connection(&NoExtensionsTransfer::new());
        let effective = connector.effective_extensions(&leg);
        let config = RustlsTlsConnectorConfig::from_extensions(&effective);

        let http_2 = TlsAlpn::http_2();
        assert_eq!(config.server_name, Some(&proxy_name));
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

    #[test]
    fn a_request_input_still_overrides_the_connector_config() {
        let connector = TlsConnector::auto(())
            .with_base_config(TlsClientConfig::new().with_alpn(Default::default()));

        let request = Extensions::new();
        request.insert(TlsAlpn::http_1());
        let effective = connector.effective_extensions(&request);
        let config = RustlsTlsConnectorConfig::from_extensions(&effective);

        let http_1 = TlsAlpn::http_1();
        assert_eq!(
            config.alpn.map(|alpn| alpn.0.as_slice()),
            Some(http_1.0.as_slice())
        );
    }

    #[test]
    fn an_origin_ech_requirement_is_not_the_policy_of_a_nested_leg() {
        let connector = TlsConnector::auto(()).with_base_config(
            TlsClientConfig::new().with_server_name(Domain::from_static("proxy.example")),
        );

        connector
            .check_attempt_policy(&nested_leg(&origin_tls_inputs()), true)
            .expect("the origin's ECH requirement is not the proxy connection's");
    }

    fn leg_transport(
        io: tokio::io::DuplexStream,
    ) -> impl ConnectorService<ConnectRequest, Connection: Io + Unpin> {
        let io = Arc::new(tokio::sync::Mutex::new(Some(io)));
        service_fn(move |input: ConnectRequest| {
            let io = io.clone();
            async move {
                let conn = ServiceInput::new(io.lock().await.take().expect("one proxy connection"));
                Ok::<_, ConnectionError>(EstablishedClientConnection { input, conn })
            }
        })
    }

    #[tokio::test]
    async fn auto_handshakes_when_the_input_asks_for_tls() {
        for asks in [false, true] {
            let auth =
                ServerAuthData::new_generated(GeneratedServerAuthConfig::default()).expect("auth");
            let base = TlsClientConfig::new()
                .with_server_name(Domain::from_static("localhost"))
                .try_with_server_trust_anchors(auth.cert_chain.clone())
                .expect("trust anchor");
            let server =
                crate::server::TlsAcceptorLayer::new(TlsServerConfig::new().with_server_auth(auth))
                    .into_layer(EchoService::new());
            let (client_io, server_io) = tokio::io::duplex(64 * 1024);
            let server_task =
                tokio::spawn(async move { server.serve(ServiceInput::new(server_io)).await });

            let connector = TlsConnector::auto(leg_transport(client_io)).with_base_config(base);
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
        let (cert_chain, private_key) =
            generate_server_auth(GeneratedServerAuthConfig::default()).expect("server auth");
        let trust_anchor = cert_chain.last().expect("trust anchor").clone();
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
        let connector = TlsConnector::auto(leg_transport(client_io)).with_base_config(
            TlsClientConfig::new()
                .with_alpn_http_2()
                .with_server_name(Domain::from_static("localhost"))
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
        let server = crate::server::TlsAcceptorLayer::new(TlsServerConfig::new().with_single_cert(
            ServerAuthData {
                cert_chain,
                private_key,
                ocsp: None,
            },
        ))
        .into_layer(EchoService::new());

        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server_task =
            tokio::spawn(async move { server.serve(ServiceInput::new(server_io)).await });
        // No trust anchor for the generated certificate: the connection to the proxy must refuse it.
        let connector = TlsConnector::auto(leg_transport(client_io)).with_base_config(
            TlsClientConfig::new().with_server_name(Domain::from_static("localhost")),
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
