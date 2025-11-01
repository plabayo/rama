use rama_boring_tokio::SslStream;
use rama_core::conversion::RamaTryInto;
use rama_core::error::{BoxError, ErrorExt, OpaqueError};
use rama_core::extensions::{Extensions, ExtensionsMut};
use rama_core::stream::Stream;
use rama_core::telemetry::tracing;
use rama_core::{Layer, Service};
use rama_http_types::conn::TargetHttpVersion;
use rama_net::address::Host;
use rama_net::client::{ConnectorService, EstablishedClientConnection};
use rama_net::tls::ApplicationProtocol;
use rama_net::tls::client::NegotiatedTlsParameters;
use rama_net::transport::TryRefIntoTransportContext;
use rama_utils::macros::generate_set_and_with;
use std::fmt;
use std::sync::Arc;

use super::{AutoTlsStream, TlsConnectorData, TlsConnectorDataBuilder, TlsStream};
use crate::types::TlsTunnel;

/// A [`Layer`] which wraps the given service with a [`TlsConnector`].
///
/// See [`TlsConnector`] for more information.
pub struct TlsConnectorLayer<K = ConnectorKindAuto> {
    connector_data: Option<Arc<TlsConnectorDataBuilder>>,
    kind: K,
}

impl<K: fmt::Debug> std::fmt::Debug for TlsConnectorLayer<K> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsConnectorLayer")
            .field("connector_data", &self.connector_data)
            .field("kind", &self.kind)
            .finish()
    }
}

impl<K: Clone> Clone for TlsConnectorLayer<K> {
    fn clone(&self) -> Self {
        Self {
            connector_data: self.connector_data.clone(),
            kind: self.kind.clone(),
        }
    }
}

impl<K> TlsConnectorLayer<K> {
    generate_set_and_with!(
        /// Set base [`TlsConnectorDataBuilder`] that will be used for this connector
        ///
        /// This builder will be chained with the [`TlsConnectorDataBuilder`] found in
        /// the context in this order: BaseBuilder -> CtxBuilder
        ///
        /// NOTE: for a smooth interaction with HTTP you most likely do want to
        /// create tls connector data to at the very least define the ALPN's correctly.
        ///
        /// E.g. if you create an auto client, you want to make sure your ALPN can handle all.
        /// It will be then also be the [`TlsConnector`] that sets the request http version correctly.
        pub fn connector_data(
            mut self,
            connector_data: Option<Arc<TlsConnectorDataBuilder>>,
        ) -> Self {
            self.connector_data = connector_data;
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
            connector_data: None,
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
            connector_data: None,
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
            connector_data: None,
            kind: ConnectorKindTunnel { host },
        }
    }
}

impl<K: Clone, S> Layer<S> for TlsConnectorLayer<K> {
    type Service = TlsConnector<S, K>;

    fn layer(&self, inner: S) -> Self::Service {
        TlsConnector {
            inner,
            connector_data: self.connector_data.clone(),
            kind: self.kind.clone(),
        }
    }

    fn into_layer(self, inner: S) -> Self::Service {
        TlsConnector {
            inner,
            connector_data: self.connector_data,
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
/// [`TlsConnector::secure_only`] to force the connector to always
/// establish a secure connection.
pub struct TlsConnector<S, K = ConnectorKindAuto> {
    inner: S,
    connector_data: Option<Arc<TlsConnectorDataBuilder>>,
    kind: K,
}

impl<S: fmt::Debug, K: fmt::Debug> fmt::Debug for TlsConnector<S, K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsConnector")
            .field("inner", &self.inner)
            .field("connector_data", &self.connector_data)
            .field("kind", &self.kind)
            .finish()
    }
}

impl<S: Clone, K: Clone> Clone for TlsConnector<S, K> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            connector_data: self.connector_data.clone(),
            kind: self.kind.clone(),
        }
    }
}

impl<S, K> TlsConnector<S, K> {
    /// Creates a new [`TlsConnector`].
    const fn new(inner: S, kind: K) -> Self {
        Self {
            inner,
            connector_data: None,
            kind,
        }
    }

    generate_set_and_with!(
        /// Set base [`TlsConnectorDataBuilder`] that will be used for this connector
        ///
        /// This builder will be chained with the [`TlsConnectorDataBuilder`] found in
        /// the context in this order: BaseBuilder -> CtxBuilder
        ///
        /// NOTE: for a smooth interaction with HTTP you most likely do want to
        /// create tls connector data to at the very least define the ALPN's correctly.
        ///
        /// E.g. if you create an auto client, you want to make sure your ALPN can handle all.
        /// It will be then also be the [`TlsConnector`] that sets the request http version correctly.
        pub fn connector_data(
            mut self,
            connector_data: Option<Arc<TlsConnectorDataBuilder>>,
        ) -> Self {
            self.connector_data = connector_data;
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

impl<S, Request> Service<Request> for TlsConnector<S, ConnectorKindAuto>
where
    S: ConnectorService<Request, Connection: Stream + Unpin>,
    Request: TryRefIntoTransportContext<Error: Into<BoxError> + Send + 'static>
        + Send
        + ExtensionsMut
        + 'static,
{
    type Response = EstablishedClientConnection<AutoTlsStream<S::Connection>, Request>;
    type Error = BoxError;

    async fn serve(&self, req: Request) -> Result<Self::Response, Self::Error> {
        let EstablishedClientConnection { mut req, conn } =
            self.inner.connect(req).await.map_err(Into::into)?;

        let transport_ctx = req.try_ref_into_transport_ctx().map_err(|err| {
            OpaqueError::from_boxed(err.into())
                .context("TlsConnector(auto): compute transport context")
        })?;

        if !transport_ctx
            .app_protocol
            .as_ref()
            .map(|p| p.is_secure())
            .unwrap_or_default()
        {
            tracing::trace!(
                server.address = %transport_ctx.authority.host(),
                server.port = %transport_ctx.authority.port(),
                "TlsConnector(auto): protocol not secure, return inner connection",
            );
            return Ok(EstablishedClientConnection {
                req,
                conn: AutoTlsStream::plain(conn),
            });
        }

        let host = transport_ctx.authority.host().clone();

        let connector_data = self.connector_data(req.extensions_mut())?;
        let (stream, negotiated_params) = handshake(connector_data, host, conn).await?;

        tracing::trace!(
            server.address = %transport_ctx.authority.host(),
            server.port = %transport_ctx.authority.port(),
            "TlsConnector(auto): protocol secure, established tls connection",
        );

        let mut conn = AutoTlsStream::secure(stream);
        conn.extensions_mut().insert(negotiated_params);

        Ok(EstablishedClientConnection { req, conn })
    }
}

impl<S, Request> Service<Request> for TlsConnector<S, ConnectorKindSecure>
where
    S: ConnectorService<Request, Connection: Stream + Unpin>,
    Request: TryRefIntoTransportContext<Error: Into<BoxError> + Send + 'static>
        + Send
        + ExtensionsMut
        + 'static,
{
    type Response = EstablishedClientConnection<TlsStream<S::Connection>, Request>;
    type Error = BoxError;

    async fn serve(&self, req: Request) -> Result<Self::Response, Self::Error> {
        let EstablishedClientConnection { mut req, conn } =
            self.inner.connect(req).await.map_err(Into::into)?;

        let transport_ctx = req.try_ref_into_transport_ctx().map_err(|err| {
            OpaqueError::from_boxed(err.into())
                .context("TlsConnector(auto): compute transport context")
        })?;
        tracing::trace!(
            server.address = %transport_ctx.authority.host(),
            server.port = %transport_ctx.authority.port(),
            "TlsConnector(secure): attempt to secure inner connection w/ app protocol: {:?}",
            transport_ctx.app_protocol,
        );

        let host = transport_ctx.authority.host().clone();

        let connector_data = self.connector_data(req.extensions_mut())?;
        let (conn, negotiated_params) = handshake(connector_data, host, conn).await?;
        let mut conn = TlsStream::new(conn);
        conn.extensions_mut().insert(negotiated_params);

        Ok(EstablishedClientConnection { req, conn })
    }
}

impl<S, Request> Service<Request> for TlsConnector<S, ConnectorKindTunnel>
where
    S: ConnectorService<Request, Connection: Stream + Unpin>,
    Request: Send + ExtensionsMut + 'static,
{
    type Response = EstablishedClientConnection<AutoTlsStream<S::Connection>, Request>;
    type Error = BoxError;

    async fn serve(&self, req: Request) -> Result<Self::Response, Self::Error> {
        let EstablishedClientConnection { mut req, conn } =
            self.inner.connect(req).await.map_err(Into::into)?;

        let host = if let Some(host) = req
            .extensions()
            .get::<TlsTunnel>()
            .as_ref()
            .map(|t| &t.server_host)
            .or(self.kind.host.as_ref())
        {
            host.clone()
        } else {
            tracing::trace!(
                "TlsConnector(tunnel): return inner connection: no Tls tunnel is requested"
            );
            return Ok(EstablishedClientConnection {
                req,
                conn: AutoTlsStream::plain(conn),
            });
        };

        let connector_data = self.connector_data(req.extensions_mut())?;
        let (stream, negotiated_params) = handshake(connector_data, host, conn).await?;
        let mut conn = AutoTlsStream::secure(stream);
        conn.extensions_mut().insert(negotiated_params);

        tracing::trace!("TlsConnector(tunnel): connection secured");
        Ok(EstablishedClientConnection { req, conn })
    }
}

impl<S, K> TlsConnector<S, K> {
    fn connector_data(&self, extensions: &mut Extensions) -> Result<TlsConnectorData, OpaqueError> {
        let target_version = extensions
            .get::<TargetHttpVersion>()
            .map(|version| ApplicationProtocol::try_from(version.0))
            .transpose()?;

        let builder = if let Some(builder) = extensions.get_mut::<TlsConnectorDataBuilder>() {
            tracing::trace!(
                "use TlsConnectorDataBuilder from extensions as foundation for connector cfg"
            );
            builder
        } else {
            tracing::trace!(
                "start from Default TlsConnectorDataBuilder as foundation for connector cfg"
            );
            extensions.insert_mut(TlsConnectorDataBuilder::default())
        };

        if let Some(base_builder) = self.connector_data.clone() {
            tracing::trace!("prepend connector data (base) config to TlsConnectorDataBuilder");
            builder.prepend_base_config(base_builder);
        }

        if let Some(target_version) = target_version {
            builder.try_set_rama_alpn_protos(&[target_version])?;
        }
        builder.build()
    }
}

pub async fn tls_connect<T>(
    server_host: Host,
    stream: T,
    connector_data: Option<TlsConnectorData>,
) -> Result<TlsStream<T>, OpaqueError>
where
    T: Stream + Unpin + ExtensionsMut,
{
    let data = match connector_data {
        Some(connector_data) => connector_data,
        None => TlsConnectorDataBuilder::new().build()?,
    };

    let server_host = data.server_name.map(Host::Name).unwrap_or(server_host);
    let stream: SslStream<T> =
        rama_boring_tokio::connect(data.config, server_host.to_string().as_str(), stream)
            .await
            .map_err(|err| match err.as_io_error() {
                Some(err) => OpaqueError::from_display(err.to_string())
                    .context("boring ssl connector: connect")
                    .into_boxed(),
                None => OpaqueError::from_display("boring ssl connector: connect").into_boxed(),
            })?;
    Ok(TlsStream::new(stream))
}

async fn handshake<T>(
    connector_data: TlsConnectorData,
    server_host: Host,
    stream: T,
) -> Result<(SslStream<T>, NegotiatedTlsParameters), BoxError>
where
    T: Stream + Unpin + ExtensionsMut,
{
    let store_server_certificate_chain = connector_data.store_server_certificate_chain;
    let TlsStream { inner: stream } =
        tls_connect(server_host, stream, Some(connector_data)).await?;

    let params = match stream.ssl().session() {
        Some(ssl_session) => {
            let protocol_version = ssl_session
                .protocol_version()
                .rama_try_into()
                .map_err(|v| {
                    OpaqueError::from_display(format!("protocol version {v}"))
                        .context("boring ssl connector: min proto version")
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
            return Err(OpaqueError::from_display(
                "boring ssl connector: failed to establish session...",
            )
            .into_boxed());
        }
    };

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
/// and using the hardcoded host otherwise.
/// Context always overwrites though.
///
/// [`TlsTunnel`]: crate::TlsTunnel
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
}
