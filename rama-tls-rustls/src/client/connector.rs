use super::{AutoTlsStream, RustlsTlsStream, TlsConnectorData, TlsStream};
use crate::dep::tokio_rustls::TlsConnector as RustlsConnector;
use crate::types::TlsTunnel;
use rama_core::conversion::{RamaInto, RamaTryFrom};
use rama_core::error::{BoxError, ErrorContext};
use rama_core::extensions::{ExtensionsMut, ExtensionsRef};
use rama_core::io::Io;
use rama_core::telemetry::tracing;
use rama_core::{Layer, Service};
use rama_net::address::Host;
use rama_net::client::{ConnectorService, EstablishedClientConnection};
use rama_net::tls::ApplicationProtocol;
use rama_net::tls::client::NegotiatedTlsParameters;
use rama_net::transport::TryRefIntoTransportContext;

#[cfg(feature = "http")]
use ::{
    rama_core::{error::ErrorExt, extensions::Extensions},
    rama_http_types::{Version, conn::TargetHttpVersion},
};

/// A [`Layer`] which wraps the given service with a [`TlsConnector`].
///
/// See [`TlsConnector`] for more information.
#[derive(Debug, Clone)]
pub struct TlsConnectorLayer<K = ConnectorKindAuto> {
    connector_data: Option<TlsConnectorData>,
    kind: K,
}

impl<K> TlsConnectorLayer<K> {
    rama_utils::macros::generate_set_and_with! {
        /// Define [`TlsConnectorData`] for this [`TlsConnectorLayer`].
        pub fn connector_data(mut self, connector_data: Option<TlsConnectorData>) -> Self {
            self.connector_data = connector_data;
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
/// [`TlsConnector::secure`] to force the connector to always
/// establish a secure connection.
#[derive(Debug, Clone)]
pub struct TlsConnector<S, K = ConnectorKindAuto> {
    inner: S,
    connector_data: Option<TlsConnectorData>,
    kind: K,
}

impl<S, K> TlsConnector<S, K> {
    /// Creates a new [`TlsConnector`].
    pub const fn new(inner: S, kind: K) -> Self {
        Self {
            inner,
            connector_data: None,
            kind,
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Define the [`TlsConnectorData`] for this [`TlsConnector`],
        ///
        /// NOTE: for a smooth interaction with HTTP you most likely do want to
        /// create tls connector data to at the very least define the ALPN's correctly.
        ///
        /// E.g. if you create an auto client, you want to make sure your ALPN can handle all.
        /// It will be then also be the [`TlsConnector`] that sets the request http version correctly.
        pub fn connector_data(mut self, connector_data: Option<TlsConnectorData>) -> Self {
            self.connector_data = connector_data;
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
                server.port = transport_ctx.authority.port,
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
            server.port = transport_ctx.authority.port,
            "TlsConnector(auto): attempt to secure inner connection w/ app protcol: {:?}",
            transport_ctx.app_protocol,
        );

        let connector_data = self.connector_data(&input)?;

        let (stream, negotiated_params) = self
            .handshake(connector_data, Some(server_host), conn)
            .await?;

        tracing::trace!(
            server.address = %transport_ctx.authority.host,
            server.port = transport_ctx.authority.port,
            "TlsConnector(auto): protocol secure, established tls connection w/ app protcol: {:?}",
            transport_ctx.app_protocol,
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
            server.port = transport_ctx.authority.port,
            "TlsConnector(secure): attempt to secure inner connection w/ app protcol: {:?}",
            transport_ctx.app_protocol,
        );

        let server_host = &transport_ctx.authority.host;

        let connector_data = self.connector_data(&input)?;

        let (conn, negotiated_params) = self
            .handshake(connector_data, Some(server_host), conn)
            .await?;

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
    Input: Send + ExtensionsRef + 'static,
{
    type Output = EstablishedClientConnection<AutoTlsStream<S::Connection>, Input>;
    type Error = BoxError;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        let EstablishedClientConnection { input, conn } =
            self.inner.connect(input).await.into_box_error()?;

        let maybe_server_host = if let Some(tunnel) = input.extensions().get::<TlsTunnel>() {
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
        let mut conn = AutoTlsStream::secure(conn);

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

impl<S, K> TlsConnector<S, K> {
    fn connector_data<Input>(&self, input: &Input) -> Result<Option<TlsConnectorData>, BoxError>
    where
        Input: ExtensionsRef,
    {
        let request_extensions = input.extensions();
        let connector_data = request_extensions
            .get::<TlsConnectorData>()
            .cloned()
            .or(self.connector_data.clone());

        #[cfg(feature = "http")]
        let connector_data = resolve_http_connector_data(request_extensions, connector_data)?;

        Ok(connector_data)
    }

    async fn handshake<T>(
        &self,
        connector_data: Option<TlsConnectorData>,
        maybe_server_host: Option<&Host>,
        stream: T,
    ) -> Result<(RustlsTlsStream<T>, NegotiatedTlsParameters), BoxError>
    where
        T: Io + ExtensionsMut + Unpin,
    {
        let connector_data = connector_data.unwrap_or(TlsConnectorData::try_new()?);

        let server_name = rustls_pki_types::ServerName::rama_try_from(
            connector_data
                .server_name
                .or_else(|| maybe_server_host.cloned())
                .context("server name missing")?,
        )?;

        let connector = RustlsConnector::from(connector_data.client_config);

        let stream = connector.connect(server_name, stream).await?;

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

        Ok((stream, params))
    }
}

/// Resolve request-scoped connector data for HTTP.
///
/// When HTTP sets a concrete [`TargetHttpVersion`], rustls ALPN needs to match
/// that version before the handshake starts. Otherwise protocols like WebSocket
/// can negotiate `h2` even though the request requires HTTP/1.1 upgrade.
#[cfg(feature = "http")]
fn resolve_http_connector_data(
    request_extensions: &Extensions,
    connector_data: Option<TlsConnectorData>,
) -> Result<Option<TlsConnectorData>, BoxError> {
    let Some(target_version) = request_extensions.get::<TargetHttpVersion>() else {
        return Ok(connector_data);
    };

    let target_alpn = ApplicationProtocol::try_from(target_version.0)?;
    tracing::trace!(
        ?target_version,
        ?target_alpn,
        "resolving TLS connector data to match TargetHttpVersion",
    );

    Ok(Some(
        connector_data
            .map(Ok)
            .unwrap_or_else(TlsConnectorData::try_new)?
            .with_alpn_protocols(&[target_alpn]),
    ))
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
    mod connector_data_resolution {
        use super::*;
        use rama_core::extensions::Extensions;
        use rama_http_types::{Version, conn::TargetHttpVersion};
        use rama_net::tls::ApplicationProtocol;

        use crate::client::TlsConnectorDataBuilder;

        fn make_http_auto() -> TlsConnectorData {
            TlsConnectorDataBuilder::new()
                .with_alpn_protocols_http_auto()
                .build()
        }

        fn make_http_1() -> TlsConnectorData {
            TlsConnectorDataBuilder::new()
                .with_alpn_protocols_http_1()
                .build()
        }

        #[test]
        fn creates_http11_connector_data_when_missing() {
            let mut ext = Extensions::new();
            ext.insert(TargetHttpVersion(Version::HTTP_11));

            assert_eq!(
                resolve_http_connector_data(&ext, None)
                    .unwrap()
                    .expect("connector data should be created")
                    .client_config
                    .alpn_protocols,
                vec![ApplicationProtocol::HTTP_11.as_bytes().to_vec()],
            );
        }

        #[test]
        fn creates_http2_connector_data_when_missing() {
            let mut ext = Extensions::new();
            ext.insert(TargetHttpVersion(Version::HTTP_2));

            assert_eq!(
                resolve_http_connector_data(&ext, None)
                    .unwrap()
                    .expect("connector data should be created")
                    .client_config
                    .alpn_protocols,
                vec![ApplicationProtocol::HTTP_2.as_bytes().to_vec()],
            );
        }

        #[test]
        fn leaves_missing_connector_data_undefined_without_target_version() {
            let ext = Extensions::new();
            assert!(resolve_http_connector_data(&ext, None).unwrap().is_none());
        }

        #[test]
        fn leaves_existing_connector_data_unchanged_without_target_version() {
            let ext = Extensions::new();
            let data = make_http_auto();
            let arc_before = data.client_config.clone();

            let data = resolve_http_connector_data(&ext, Some(data))
                .unwrap()
                .expect("existing connector data should be preserved");

            assert!(std::sync::Arc::ptr_eq(&arc_before, &data.client_config));
        }

        #[test]
        fn constrains_existing_connector_data_to_h1_when_target_is_http11() {
            let mut ext = Extensions::new();
            ext.insert(TargetHttpVersion(Version::HTTP_11));

            let data = make_http_auto();
            assert_eq!(
                data.client_config.alpn_protocols,
                vec![
                    ApplicationProtocol::HTTP_2.as_bytes().to_vec(),
                    ApplicationProtocol::HTTP_11.as_bytes().to_vec(),
                ],
                "precondition: default auto has h2+h1.1"
            );

            let data = resolve_http_connector_data(&ext, Some(data))
                .unwrap()
                .expect("existing connector data should be preserved");
            assert_eq!(
                data.client_config.alpn_protocols,
                vec![ApplicationProtocol::HTTP_11.as_bytes().to_vec()],
            );
        }

        #[test]
        fn does_not_clone_when_existing_h1_alpn_already_matches() {
            let mut ext = Extensions::new();
            ext.insert(TargetHttpVersion(Version::HTTP_11));

            let data = make_http_1();
            let arc_before = data.client_config.clone();

            let data = resolve_http_connector_data(&ext, Some(data))
                .unwrap()
                .expect("existing connector data should be preserved");
            // Same Arc — no clone occurred.
            assert!(std::sync::Arc::ptr_eq(&arc_before, &data.client_config));
        }
    }
}
