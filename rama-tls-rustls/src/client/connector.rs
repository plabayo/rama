use super::{AutoTlsStream, RustlsTlsStream, TlsConnectorData, TlsStream};
use crate::client::config::RustlsTlsConnectorConfig;
use crate::dep::tokio_rustls::TlsConnector as RustlsConnector;
use crate::types::TlsTunnel;
use rama_core::conversion::{RamaInto, RamaTryFrom};
#[cfg(feature = "http")]
use rama_core::error::extra::OpaqueError;
use rama_core::error::{BoxError, ErrorContext};
#[cfg(feature = "http")]
use rama_core::extensions::Extensions;
use rama_core::extensions::ExtensionsRef;
use rama_core::io::Io;
use rama_core::telemetry::tracing;
use rama_core::{Layer, Service};
use rama_net::address::Host;
use rama_net::client::{ConnectorService, EstablishedClientConnection};
use rama_net::extensions::StreamTransformed;
use rama_net::tls::ApplicationProtocol;
#[cfg(feature = "http")]
use rama_net::tls::client::TlsAlpn;
use rama_net::tls::client::{NegotiatedTlsParameters, TlsClientConfig};
use rama_net::transport::TryRefIntoTransportContext;

#[cfg(feature = "http")]
use ::{
    rama_core::error::ErrorExt,
    rama_http_types::{Version, conn::TargetHttpVersion},
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
    rama_utils::macros::generate_set_and_with! {
        /// Define the base [`TlsClientConfig`] for this [`TlsConnectorLayer`].
        ///
        /// Per connection pieces inserted in the request's extensions are layered
        /// on top of this base (newest-wins).
        pub fn base_config(mut self, base: Option<TlsClientConfig>) -> Self {
            self.base_config = base;
            self
        }
    }
}

impl TlsConnectorLayer<ConnectorKindAuto> {
    /// Creates a new [`TlsConnectorLayer`] which will establish
    /// a secure connection if the request demands it,
    /// otherwise it will forward the pre-established inner connection.
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

    rama_utils::macros::generate_set_and_with! {
        /// Define the base [`TlsClientConfig`] for this [`TlsConnector`].
        ///
        /// Per connection pieces inserted in the request's extensions are layered
        /// on top of this base (newest-wins).
        pub fn base_config(mut self, base: Option<TlsClientConfig>) -> Self {
            self.base_config = base;
            self
        }
    }
}

impl<S> TlsConnector<S, ConnectorKindAuto> {
    /// Creates a new [`TlsConnector`] which will establish
    /// a secure connection if the request demands it,
    /// otherwise it will forward the pre-established inner connection.
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
    Input: TryRefIntoTransportContext<Error: Into<BoxError> + Send + 'static>
        + ExtensionsRef
        + Send
        + 'static,
{
    type Output = EstablishedClientConnection<AutoTlsStream<S::Connection>, Input>;
    type Error = BoxError;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        let EstablishedClientConnection { input, conn } =
            self.inner.connect(input).await.into_box_error()?;

        let transport_ctx = input
            .try_ref_into_transport_ctx()
            .context("TlsConnector(auto): compute transport context")?;

        if !transport_ctx
            .app_protocol
            .as_ref()
            .map(|p| p.is_secure())
            .unwrap_or_default()
        {
            tracing::trace!(
                server.address = %transport_ctx.authority.host,
                server.port = transport_ctx.authority.port_u16(),
                "TlsConnector(auto): protocol not secure, return inner connection",
            );

            return Ok(EstablishedClientConnection {
                input,
                conn: AutoTlsStream::plain(conn),
            });
        }

        let server_host = &transport_ctx.authority.host;

        tracing::trace!(
            server.address = %transport_ctx.authority.host,
            server.port = transport_ctx.authority.port_u16(),
            "TlsConnector(auto): attempt to secure inner connection w/ app protcol: {:?}",
            transport_ctx.app_protocol,
        );

        let connector_data = self.connector_data(&input)?;

        let (stream, negotiated_params) = self
            .handshake(connector_data, Some(server_host), conn)
            .await?;

        tracing::trace!(
            server.address = %transport_ctx.authority.host,
            server.port = transport_ctx.authority.port_u16(),
            "TlsConnector(auto): protocol secure, established tls connection w/ app protcol: {:?}",
            transport_ctx.app_protocol,
        );

        let conn = AutoTlsStream::secure(stream);
        #[cfg(feature = "http")]
        set_target_http_version(input.extensions(), conn.extensions(), &negotiated_params)?;

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
    Input: TryRefIntoTransportContext<Error: Into<BoxError> + Send + 'static>
        + Send
        + ExtensionsRef
        + 'static,
{
    type Output = EstablishedClientConnection<TlsStream<S::Connection>, Input>;
    type Error = BoxError;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        let EstablishedClientConnection { input, conn } =
            self.inner.connect(input).await.into_box_error()?;

        let transport_ctx = input
            .try_ref_into_transport_ctx()
            .context("TlsConnector(auto): compute transport context")?;
        tracing::trace!(
            server.address = %transport_ctx.authority.host,
            server.port = transport_ctx.authority.port_u16(),
            "TlsConnector(secure): attempt to secure inner connection w/ app protcol: {:?}",
            transport_ctx.app_protocol,
        );

        let server_host = &transport_ctx.authority.host;

        let connector_data = self.connector_data(&input)?;

        let (conn, negotiated_params) = self
            .handshake(connector_data, Some(server_host), conn)
            .await?;

        let conn = TlsStream::new(conn);
        #[cfg(feature = "http")]
        set_target_http_version(input.extensions(), conn.extensions(), &negotiated_params)?;

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
    type Error = BoxError;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        let EstablishedClientConnection { input, conn } =
            self.inner.connect(input).await.into_box_error()?;

        let maybe_server_host = if let Some(tunnel) = input.extensions().get_ref::<TlsTunnel>() {
            tunnel.sni.as_ref()
        } else if let Some(hardcoded_sni) = self.kind.host.as_ref() {
            Some(hardcoded_sni)
        } else {
            tracing::trace!(
                "TlsConnector(tunnel): return inner connection: no Tls tunnel is requested"
            );

            return Ok(EstablishedClientConnection {
                input,
                conn: AutoTlsStream::plain(conn),
            });
        };

        let connector_data = self.connector_data(&input)?;

        let (conn, negotiated_params) = self
            .handshake(connector_data, maybe_server_host, conn)
            .await?;
        let conn = AutoTlsStream::secure(conn);

        #[cfg(feature = "http")]
        set_target_http_version(input.extensions(), conn.extensions(), &negotiated_params)?;

        conn.extensions().insert(negotiated_params);
        conn.extensions().insert(StreamTransformed {
            by: "rama-tls-rustls::TlsConnector",
        });
        tracing::trace!("TlsConnector(tunnel): connection secured");
        Ok(EstablishedClientConnection { input, conn })
    }
}

impl<S, K> TlsConnector<S, K> {
    fn connector_data<Input>(&self, input: &Input) -> Result<TlsConnectorData, BoxError>
    where
        Input: ExtensionsRef,
    {
        // rustls needs a process default crypto provider before any config build
        // ensure it once here (the connector is the entry point), not in build().
        crate::ensure_default_crypto_provider();

        let extensions = if let Some(base) = &self.base_config {
            &input.extensions().with_base(base.as_extensions())
        } else {
            input.extensions()
        };

        // When HTTP pins a concrete target version, force the TLS ALPN to match
        // it before the handshake
        #[cfg(feature = "http")]
        resolve_http_alpn(extensions)?;

        let config = RustlsTlsConnectorConfig::from_extensions(extensions);
        TlsConnectorData::try_from(config)
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
            .context("server name missing")?;

        let server_name = rama_crypto::pki_types::ServerName::rama_try_from(
            connector_data
                .server_name
                .or_else(|| maybe_server_host.cloned())
                .context("server name missing")?,
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
        };

        #[cfg(feature = "dial9")]
        {
            use rama_net::tls::DataEncoding;
            let depth = match params.peer_certificate_chain.as_ref() {
                Some(DataEncoding::Der(_) | DataEncoding::Pem(_)) => 1,
                Some(DataEncoding::DerStack(stack)) => stack.len(),
                None => 0,
            };
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

    ext.insert(TlsAlpn(vec![target_alpn]));
    Ok(())
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
            return Err(OpaqueError::from_static_str(
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
/// The connections will only be done if the [`TlsTunnel`]
/// is present in the context for optional versions,
/// and using the hardcoded host otherwise.
/// Context always overwrites though.
///
/// [`TlsTunnel`]: rama_net::tls::TlsTunnel
pub struct ConnectorKindTunnel {
    host: Option<Host>,
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

    #[cfg(feature = "http")]
    mod http_alpn_resolution {
        use super::*;
        use rama_core::extensions::Extensions;
        use rama_http_types::{Version, conn::TargetHttpVersion};
        use rama_net::tls::ApplicationProtocol;

        fn alpn_of(ext: &Extensions) -> Option<Vec<ApplicationProtocol>> {
            ext.get_ref::<TlsAlpn>().map(|a| a.0.clone())
        }

        #[test]
        fn forces_http11_alpn_when_target_is_http11() {
            let ext = Extensions::new();
            ext.insert(TargetHttpVersion(Version::HTTP_11));

            resolve_http_alpn(&ext).unwrap();
            assert_eq!(alpn_of(&ext), Some(vec![ApplicationProtocol::HTTP_11]));
        }

        #[test]
        fn forces_http2_alpn_when_target_is_http2() {
            let ext = Extensions::new();
            ext.insert(TargetHttpVersion(Version::HTTP_2));

            resolve_http_alpn(&ext).unwrap();
            assert_eq!(alpn_of(&ext), Some(vec![ApplicationProtocol::HTTP_2]));
        }

        #[test]
        fn leaves_alpn_untouched_without_target_version() {
            let ext = Extensions::new();
            resolve_http_alpn(&ext).unwrap();
            assert_eq!(alpn_of(&ext), None);
        }

        #[test]
        fn overrides_existing_alpn_to_match_target() {
            let ext = Extensions::new();
            ext.insert(TlsAlpn::http_auto());
            ext.insert(TargetHttpVersion(Version::HTTP_11));

            resolve_http_alpn(&ext).unwrap();
            assert_eq!(alpn_of(&ext), Some(vec![ApplicationProtocol::HTTP_11]));
        }
    }
}
