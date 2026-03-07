use rama_boring_tokio::SslStream;
use rama_core::conversion::RamaTryInto;
use rama_core::error::{BoxError, ErrorContext as _, ErrorExt};
use rama_core::extensions::{Extensions, ExtensionsMut};
use rama_core::io::Io;
use rama_core::telemetry::tracing;
use rama_core::{Layer, Service};
use rama_net::address::Domain;
use rama_net::client::{ConnectorService, EstablishedClientConnection};
use rama_net::tls::ApplicationProtocol;
use rama_net::tls::client::NegotiatedTlsParameters;
use rama_net::transport::TryRefIntoTransportContext;
use rama_utils::macros::generate_set_and_with;
use std::sync::Arc;

use super::{AutoTlsStream, TlsConnectorData, TlsConnectorDataBuilder};
use crate::{TlsStream, types::TlsTunnel};

#[cfg(feature = "http")]
use rama_http_types::{Version, conn::TargetHttpVersion};

/// A [`Layer`] which wraps the given service with a [`TlsConnector`].
///
/// See [`TlsConnector`] for more information.
#[derive(Debug, Clone)]
pub struct TlsConnectorLayer<K = ConnectorKindAuto> {
    connector_data: Option<Arc<TlsConnectorDataBuilder>>,
    kind: K,
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
    pub fn tunnel(sni: Option<Domain>) -> Self {
        Self {
            connector_data: None,
            kind: ConnectorKindTunnel { sni },
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
/// [`TlsConnector::secure`] to force the connector to always
/// establish a secure connection.
#[derive(Debug, Clone)]
pub struct TlsConnector<S, K = ConnectorKindAuto> {
    inner: S,
    connector_data: Option<Arc<TlsConnectorDataBuilder>>,
    kind: K,
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
    pub const fn tunnel(inner: S, sni: Option<Domain>) -> Self {
        Self::new(inner, ConnectorKindTunnel { sni })
    }
}

// this way we do not need a hacky macro... however is there a way to do this without needing to hacK?!?!

impl<S, Input> Service<Input> for TlsConnector<S, ConnectorKindAuto>
where
    S: ConnectorService<Input, Connection: Io + Unpin>,
    Input: TryRefIntoTransportContext<Error: Into<BoxError> + Send + 'static>
        + Send
        + ExtensionsMut
        + 'static,
{
    type Output = EstablishedClientConnection<AutoTlsStream<S::Connection>, Input>;
    type Error = BoxError;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        let EstablishedClientConnection { mut input, conn } =
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
                server.port = transport_ctx.authority.port,
                "TlsConnector(auto): protocol not secure, return inner connection",
            );
            return Ok(EstablishedClientConnection {
                input,
                conn: AutoTlsStream::plain(conn),
            });
        }

        let (connector_data, connector_data_builder) =
            self.connector_data(input.extensions(), transport_ctx.authority.host.as_domain())?;

        // We dont have to insert, but it's nice to have...
        input.extensions_mut().insert(connector_data_builder);

        let (stream, negotiated_params) = handshake(connector_data, conn).await?;

        tracing::trace!(
            server.address = %transport_ctx.authority.host,
            server.port = transport_ctx.authority.port,
            "TlsConnector(auto): protocol secure, established tls connection",
        );

        let mut conn = AutoTlsStream::secure(stream);

        #[cfg(feature = "http")]
        set_target_http_version(
            input.extensions(),
            conn.extensions_mut(),
            &negotiated_params,
        )?;

        conn.extensions_mut().insert(negotiated_params);
        Ok(EstablishedClientConnection { input, conn })
    }
}

impl<S, Input> Service<Input> for TlsConnector<S, ConnectorKindSecure>
where
    S: ConnectorService<Input, Connection: Io + Unpin>,
    Input: TryRefIntoTransportContext<Error: Into<BoxError> + Send + 'static>
        + Send
        + ExtensionsMut
        + 'static,
{
    type Output = EstablishedClientConnection<TlsStream<S::Connection>, Input>;
    type Error = BoxError;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        let EstablishedClientConnection { mut input, conn } =
            self.inner.connect(input).await.into_box_error()?;

        let transport_ctx = input
            .try_ref_into_transport_ctx()
            .context("TlsConnector(auto): compute transport context")?;
        tracing::trace!(
            server.address = %transport_ctx.authority.host,
            server.port = transport_ctx.authority.port,
            "TlsConnector(secure): attempt to secure inner connection w/ app protocol: {:?}",
            transport_ctx.app_protocol,
        );

        let (connector_data, connector_data_builder) =
            self.connector_data(input.extensions(), transport_ctx.authority.host.as_domain())?;

        // We dont have to insert, but it's nice to have...
        input.extensions_mut().insert(connector_data_builder);

        let (conn, negotiated_params) = handshake(connector_data, conn).await?;
        let mut conn = TlsStream::new(conn);

        #[cfg(feature = "http")]
        set_target_http_version(
            input.extensions(),
            conn.extensions_mut(),
            &negotiated_params,
        )?;

        conn.extensions_mut().insert(negotiated_params);
        Ok(EstablishedClientConnection { input, conn })
    }
}

impl<S, Input> Service<Input> for TlsConnector<S, ConnectorKindTunnel>
where
    S: ConnectorService<Input, Connection: Io + Unpin>,
    Input: Send + ExtensionsMut + 'static,
{
    type Output = EstablishedClientConnection<AutoTlsStream<S::Connection>, Input>;
    type Error = BoxError;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        let EstablishedClientConnection { mut input, conn } =
            self.inner.connect(input).await.into_box_error()?;

        let maybe_sni_overwrite = if let Some(tunnel) = input.extensions().get::<TlsTunnel>() {
            tunnel
                .sni
                .as_ref()
                .and_then(|h| h.as_domain())
                .or(self.kind.sni.as_ref())
        } else {
            tracing::trace!(
                "TlsConnector(tunnel): return inner connection: no Tls tunnel is requested"
            );
            return Ok(EstablishedClientConnection {
                input,
                conn: AutoTlsStream::plain(conn),
            });
        };

        let (connector_data, connector_data_builder) =
            self.connector_data(input.extensions(), maybe_sni_overwrite)?;

        // We dont have to insert, but it's nice to have...
        input.extensions_mut().insert(connector_data_builder);

        let (stream, negotiated_params) = handshake(connector_data, conn).await?;
        let mut conn = AutoTlsStream::secure(stream);

        #[cfg(feature = "http")]
        set_target_http_version(
            input.extensions(),
            conn.extensions_mut(),
            &negotiated_params,
        )?;

        conn.extensions_mut().insert(negotiated_params);
        tracing::trace!("TlsConnector(tunnel): connection secured");
        Ok(EstablishedClientConnection { input, conn })
    }
}

#[cfg(feature = "http")]
fn set_target_http_version(
    request_extensions: &Extensions,
    conn_extensions: &mut Extensions,
    tls_params: &NegotiatedTlsParameters,
) -> Result<(), BoxError> {
    if let Some(proto) = tls_params.application_layer_protocol.as_ref() {
        let neg_version: Version = proto.try_into()?;
        if let Some(target_version) = request_extensions.get::<TargetHttpVersion>()
            && target_version.0 != neg_version
        {
            return Err(BoxError::from(
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
    ) -> Result<(TlsConnectorData, TlsConnectorDataBuilder), BoxError> {
        #[cfg(feature = "http")]
        let target_version = extensions
            .get::<TargetHttpVersion>()
            .map(|version| ApplicationProtocol::try_from(version.0))
            .transpose()?;

        let mut builder =
            if let Some(builder) = extensions.get::<TlsConnectorDataBuilder>().cloned() {
                tracing::trace!(
                    "use TlsConnectorDataBuilder from extensions as foundation for connector cfg"
                );
                builder
            } else {
                tracing::trace!(
                    "start from Default TlsConnectorDataBuilder as foundation for connector cfg"
                );
                TlsConnectorDataBuilder::default()
            };
        let has_custom_sni = builder.server_name().is_some();

        if let Some(base_builder) = self.connector_data.clone() {
            tracing::trace!("prepend connector data (base) config to TlsConnectorDataBuilder");
            builder.prepend_base_config(base_builder);
        }

        if !has_custom_sni && let Some(sni_overwrite) = maybe_sni_overwrite.cloned() {
            builder.set_server_name(sni_overwrite);
        }

        #[cfg(feature = "http")]
        if let Some(target_version) = target_version {
            builder.try_set_rama_alpn_protos(&[target_version])?;
        }

        builder.build().map(|cfg| (cfg, builder))
    }
}

pub async fn tls_connect<T>(
    stream: T,
    connector_data: Option<TlsConnectorData>,
) -> Result<TlsStream<T>, BoxError>
where
    T: Io + Unpin + ExtensionsMut,
{
    let TlsConnectorData {
        config,
        store_server_certificate_chain: _,
        server_name,
    } = match connector_data {
        Some(connector_data) => connector_data,
        None => TlsConnectorDataBuilder::new().build()?,
    };

    let sni = server_name.as_ref().map(|sni| sni.as_str());
    let stream: SslStream<T> = rama_boring_tokio::connect(config, sni, stream)
        .await
        .map_err(|err| {
            let maybe_ssl_code = err.code();
            if let Some(io_err) = err.as_io_error() {
                BoxError::from(format!(
                    "boring ssl connector (connect): with io error: {io_err}"
                ))
                .context_debug_field("sni", server_name)
                .context_debug_field("code", maybe_ssl_code)
            } else if let Some(err) = err.as_ssl_error_stack() {
                err.context("boring ssl connector (connect): with ssl-error info")
                    .context_debug_field("sni", server_name)
                    .context_debug_field("code", maybe_ssl_code)
            } else {
                BoxError::from("boring ssl connector (connect): without error info")
                    .context_debug_field("sni", server_name)
                    .context_debug_field("code", maybe_ssl_code)
            }
        })?;
    Ok(TlsStream::new(stream))
}

async fn handshake<T>(
    connector_data: TlsConnectorData,
    stream: T,
) -> Result<(SslStream<T>, NegotiatedTlsParameters), BoxError>
where
    T: Io + Unpin + ExtensionsMut,
{
    let store_server_certificate_chain = connector_data.store_server_certificate_chain;
    let TlsStream { inner: stream } = tls_connect(stream, Some(connector_data)).await?;

    let params = match stream.ssl().session() {
        Some(ssl_session) => {
            let protocol_version = ssl_session
                .protocol_version()
                .rama_try_into()
                .map_err(|v| {
                    BoxError::from("boring ssl connector: cast min proto version")
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
            return Err(BoxError::from(
                "boring ssl connector: failed to establish session...",
            ));
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
}
