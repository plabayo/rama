use rama_boring_tokio::{HandshakeError, SslStream};
use rama_core::conversion::RamaTryInto;
use rama_core::error::BoxErrorExt as _;
use rama_core::error::{BoxError, ErrorContext as _, ErrorExt};
use rama_core::extensions::{Extensions, ExtensionsRef};
use rama_core::io::Io;
use rama_core::telemetry::tracing;
use rama_core::{Layer, Service};
use rama_net::address::Domain;
use rama_net::client::{ConnectorService, EstablishedClientConnection};
use rama_net::extensions::StreamTransformed;
use rama_net::tls::ApplicationProtocol;
use rama_net::tls::client::{NegotiatedTlsParameters, TlsClientConfig};
use rama_net::{AuthorityInputExt, ProtocolInputExt};
#[cfg(feature = "http")]
use rama_utils::collections::smallvec::smallvec;
use rama_utils::macros::generate_set_and_with;
use std::fmt;

use super::{AutoTlsStream, BoringTlsConnectorConfig, TlsConnectorData};

use crate::{TlsStream, types::TlsTunnel};
#[cfg(feature = "http")]
use rama_net::tls::client::TlsAlpn;

#[cfg(feature = "http")]
use rama_http_types::{Version, conn::TargetHttpVersion};

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
        /// Per-connection pieces inserted in the request's extensions are layered
        /// on top of this base, so these are basically the defaults if the request
        /// doesn't specify them.
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
    pub fn tunnel(sni: Option<Domain>) -> Self {
        Self {
            base: None,
            kind: ConnectorKindTunnel { sni },
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
        /// Per-connection pieces inserted in the request's extensions are layered
        /// on top of this base, so these are basically the defaults if the request
        /// doesn't specify them.
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
    pub const fn tunnel(inner: S, sni: Option<Domain>) -> Self {
        Self::new(inner, ConnectorKindTunnel { sni })
    }
}

// this way we do not need a hacky macro... however is there a way to do this without needing to hacK?!?!

impl<S, Input> Service<Input> for TlsConnector<S, ConnectorKindAuto>
where
    S: ConnectorService<Input, Connection: Io + Unpin>,
    Input: AuthorityInputExt + ProtocolInputExt + Send + ExtensionsRef + 'static,
{
    type Output = EstablishedClientConnection<AutoTlsStream<S::Connection>, Input>;
    type Error = BoxError;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        let EstablishedClientConnection { input, conn } =
            self.inner.connect(input).await.into_box_error()?;

        let authority = input
            .authority()
            .context("TlsConnector(auto): resolve authority")?;
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

        // SNI is a DNS name. IP-first per RFC 6066 §3: drop SNI for
        // IP-shaped hosts (including pct-encoded IP literals inside
        // `Uninterpreted`). Otherwise bridge `Uninterpreted` to Domain.
        let sni_domain = sni_domain_for(&authority.host);
        let connector_data = self.connector_data(input.extensions(), sni_domain.as_deref())?;

        let (stream, negotiated_params) = handshake(connector_data, conn).await?;

        tracing::trace!(
            server.address = %authority.host,
            server.port = authority.port_u16(),
            "TlsConnector(auto): protocol secure, established tls connection",
        );

        let conn = AutoTlsStream::secure(stream);

        #[cfg(feature = "http")]
        set_target_http_version(input.extensions(), conn.extensions(), &negotiated_params)?;

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
    type Error = BoxError;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        let EstablishedClientConnection { input, conn } =
            self.inner.connect(input).await.into_box_error()?;

        let authority = input
            .authority()
            .context("TlsConnector(secure): resolve authority")?;
        tracing::trace!(
            server.address = %authority.host,
            server.port = authority.port_u16(),
            "TlsConnector(secure): attempt to secure inner connection w/ app protocol: {:?}",
            input.protocol(),
        );

        let sni_domain = sni_domain_for(&authority.host);
        let connector_data = self.connector_data(input.extensions(), sni_domain.as_deref())?;

        let (conn, negotiated_params) = handshake(connector_data, conn).await?;
        let conn = TlsStream::new(conn);

        #[cfg(feature = "http")]
        set_target_http_version(input.extensions(), conn.extensions(), &negotiated_params)?;

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
    type Error = BoxError;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        let EstablishedClientConnection { input, conn } =
            self.inner.connect(input).await.into_box_error()?;

        // Same IP-first bridging on the tunnel SNI overwrite. Bind the
        // owned/borrowed Cow to a local so its reference is valid for
        // the duration of the connector_data call below.
        let tunnel_sni_owned = input
            .extensions()
            .get_ref::<TlsTunnel>()
            .and_then(|t| t.sni.as_ref())
            .and_then(sni_domain_for);
        let maybe_sni_overwrite = if input.extensions().get_ref::<TlsTunnel>().is_some() {
            tunnel_sni_owned.as_deref().or(self.kind.sni.as_ref())
        } else {
            tracing::trace!(
                "TlsConnector(tunnel): return inner connection: no Tls tunnel is requested"
            );
            return Ok(EstablishedClientConnection {
                input,
                conn: AutoTlsStream::plain(conn),
            });
        };

        let connector_data = self.connector_data(input.extensions(), maybe_sni_overwrite)?;

        let (stream, negotiated_params) = handshake(connector_data, conn).await?;
        let conn = AutoTlsStream::secure(stream);

        #[cfg(feature = "http")]
        set_target_http_version(input.extensions(), conn.extensions(), &negotiated_params)?;

        conn.extensions().insert(negotiated_params);
        conn.extensions().insert(StreamTransformed {
            by: "rama-tls-boring::TlsConnector",
        });
        tracing::trace!("TlsConnector(tunnel): connection secured");
        Ok(EstablishedClientConnection { input, conn })
    }
}

/// SNI extraction with IP-first policy (RFC 6066 §3 forbids IP literals
/// in SNI). Returns `None` for IP-shaped hosts (including pct-encoded
/// IP literals inside `Uninterpreted`) and for non-promotable
/// reg-names / IPvFuture; otherwise returns the bridged [`Domain`].
///
/// The IP-first guard exists because `Domain::try_from("127.0.0.1")`
/// succeeds — RFC 1123 §2.1 permits all-digit DNS labels — so an
/// IPv4-shaped reg-name (`Host::Uninterpreted("127.0.0.1")` or the
/// pct-encoded form `%31%32%37.0.0.1`) would otherwise promote to a
/// "domain" of `"127.0.0.1"` and ship as SNI. RFC 6066 forbids that.
fn sni_domain_for(host: &rama_net::address::Host) -> Option<std::borrow::Cow<'_, Domain>> {
    if host.try_as_ip().is_ok() {
        return None;
    }
    host.try_as_domain().ok()
}

#[cfg(feature = "http")]
fn set_target_http_version(
    request_extensions: &Extensions,
    conn_extensions: &Extensions,
    tls_params: &NegotiatedTlsParameters,
) -> Result<(), BoxError> {
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
    fn connector_data(
        &self,
        extensions: &Extensions,
        maybe_sni_overwrite: Option<&Domain>,
    ) -> Result<TlsConnectorData, BoxError> {
        // Create new extensions only for this function that also apply the base_config
        let extensions = if let Some(base) = &self.base_config {
            &extensions.with_base(base.as_extensions())
        } else {
            extensions
        };

        // When HTTP pins a concrete target version, force the TLS ALPN to match
        // it before the handshake
        #[cfg(feature = "http")]
        resolve_http_alpn(extensions)?;

        let mut data =
            TlsConnectorData::try_from(BoringTlsConnectorConfig::from_extensions(extensions))?;

        // Fall back to the connector/transport SNI if none was configured.
        if data.server_name.is_none()
            && let Some(sni_overwrite) = maybe_sni_overwrite.cloned()
        {
            data.server_name = Some(sni_overwrite);
        }

        Ok(data)
    }
}

/// Force the TLS ALPN to match a concrete [`TargetHttpVersion`] when HTTP pins
/// one. Otherwise protocols like WebSocket can negotiate `h2` even though the
/// request requires an HTTP/1.1 upgrade.
#[cfg(feature = "http")]
fn resolve_http_alpn(ext: &Extensions) -> Result<(), BoxError> {
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

#[derive(Debug)]
pub enum TlsConnectError<S> {
    Builder(BoxError),
    Handshake {
        server_name: Option<Domain>,
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
                    "Handshake: {error} (SNI = '{}')",
                    server_name.as_ref().map(|d| d.as_str()).unwrap_or_default()
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

pub async fn tls_connect<T>(
    stream: T,
    connector_data: Option<TlsConnectorData>,
) -> Result<TlsStream<T>, TlsConnectError<T>>
where
    T: Io + Unpin + ExtensionsRef,
{
    let TlsConnectorData {
        config,
        store_server_certificate_chain: _,
        server_name,
    } = match connector_data {
        Some(connector_data) => connector_data,
        None => {
            TlsConnectorData::try_from(&TlsClientConfig::new()).map_err(TlsConnectError::Builder)?
        }
    };

    let sni = server_name.as_ref().map(|sni| sni.as_str());
    let stream: SslStream<T> = rama_boring_tokio::connect(config, sni, stream)
        .await
        .map_err(|error| TlsConnectError::Handshake { error, server_name })?;
    Ok(TlsStream::new(stream))
}

async fn handshake<T>(
    connector_data: TlsConnectorData,
    stream: T,
) -> Result<(SslStream<T>, NegotiatedTlsParameters), BoxError>
where
    T: Io + Unpin + ExtensionsRef,
{
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
                        .context_debug_field("sni", server_name)
                        .context_debug_field("code", maybe_ssl_code)
                    } else if let Some(ssl_error) = error.as_ssl_error_stack() {
                        ssl_error
                            .context("boring ssl connector (connect): with ssl-error info")
                            .context_debug_field("sni", server_name)
                            .context_debug_field("code", maybe_ssl_code)
                    } else {
                        BoxError::from_static_str(
                            "boring ssl connector (connect): without error info",
                        )
                        .context_debug_field("sni", server_name)
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
        use rama_net::tls::DataEncoding;
        // Approximate cert-chain depth: opaque single Der/Pem counts as
        // 1 (we don't parse PEM here), an explicit DerStack contributes
        // its real length, no chain stored yields 0. Used for telemetry
        // bucketing only — exact length lives in the structured chain.
        let depth = match params.peer_certificate_chain.as_ref() {
            Some(DataEncoding::Der(_) | DataEncoding::Pem(_)) => 1,
            Some(DataEncoding::DerStack(stack)) => stack.len(),
            None => 0,
        };
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
/// The connections will only be done if the [`TlsTunnel`]
/// is present in the context for optional versions,
/// and using the hardcoded domain otherwise.
/// Context always overwrites though.
///
/// [`TlsTunnel`]: rama_net::tls::TlsTunnel
pub struct ConnectorKindTunnel {
    sni: Option<Domain>,
}

#[cfg(test)]
mod tests {
    use super::*;

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

    /// Regression for the IP-first guard in [`sni_domain_for`].
    /// `Host::Uninterpreted("127.0.0.1")` could otherwise promote to
    /// Domain `"127.0.0.1"` and ship as SNI in violation of RFC 6066 §3.
    #[test]
    fn sni_domain_for_drops_ip_shaped_uninterpreted() {
        let host = rama_net::address::Host::try_from("127.0.0.1").unwrap();
        assert!(sni_domain_for(&host).is_none());
        // Pct-encoded equivalent also resolves to IpAddr first.
        let host = rama_net::address::Host::try_from("%31%32%37.0.0.1").unwrap();
        assert!(sni_domain_for(&host).is_none());
    }

    #[test]
    fn sni_domain_for_keeps_pct_encoded_reg_name() {
        // `exa%6Dple.com` bridges Uninterpreted → Domain "example.com".
        let host = rama_net::address::Host::try_from("exa%6Dple.com").unwrap();
        let domain = sni_domain_for(&host).expect("should bridge to Domain");
        assert_eq!(domain.as_str(), "example.com");
    }
}
