use rama_core::{
    Service,
    error::{BoxError, ErrorContext as _},
    extensions,
    io::{BridgeIo, Io},
    telemetry::tracing,
};
use rama_net::tls::{client::ServerVerifyMode, server::InputWithClientHello};

use crate::{TlsStream, client::TlsConnectorDataBuilder, proxy::TlsMitmRelay};

#[derive(Debug, Clone)]
/// A utility that can be used by MITM services such as transparent proxies,
/// in order to relay (and MITM a TLS connection between a client and server,
/// as part of a deep protocol inspection protocol (DPI) flow.
pub struct TlsMitmRelayService<Issuer, Inner> {
    relay: TlsMitmRelay<Issuer>,
    inner: Inner,
}

impl<Issuer, Inner> TlsMitmRelayService<Issuer, Inner> {
    #[inline(always)]
    #[must_use]
    /// Create a new [`TlsMitmRelayService`] which is ready to serve,
    /// bridged Io streams. It's a [`Service`] (layer) implementation
    /// on top of [`TlsMitmRelay`].
    pub fn new(relay: TlsMitmRelay<Issuer>, inner: Inner) -> Self {
        Self { relay, inner }
    }
}

impl<Issuer, Inner, Ingress, Egress> Service<BridgeIo<Ingress, Egress>>
    for TlsMitmRelayService<Issuer, Inner>
where
    Issuer: super::issuer::BoringMitmCertIssuer<Error: Into<BoxError>>,
    Inner: Service<BridgeIo<TlsStream<Ingress>, TlsStream<Egress>>, Output = (), Error: Into<BoxError>>,
    Ingress: Io + Unpin + extensions::ExtensionsMut,
    Egress: Io + Unpin + extensions::ExtensionsMut,
{
    type Output = ();
    type Error = BoxError;

    async fn serve(&self, input: BridgeIo<Ingress, Egress>) -> Result<Self::Output, Self::Error> {
        let maybe_connector_data = TlsConnectorDataBuilder::default()
            .with_server_verify_mode(ServerVerifyMode::Disable)
            .build()
            .inspect_err(|err| {
                tracing::debug!(
                    "failed to build default TlsConnectorData: {err}; try anyway without data"
                )
            })
            .ok();

        let tls_input = self
            .relay
            .handshake(input, maybe_connector_data)
            .await
            .context("tls MITM relay handshake")?;

        self.inner.serve(tls_input).await.map_err(Into::into)
    }
}

impl<Issuer, Inner, Ingress, Egress> Service<InputWithClientHello<BridgeIo<Ingress, Egress>>>
    for TlsMitmRelayService<Issuer, Inner>
where
    Issuer: super::issuer::BoringMitmCertIssuer<Error: Into<BoxError>>,
    Inner: Service<BridgeIo<TlsStream<Ingress>, TlsStream<Egress>>, Output = (), Error: Into<BoxError>>,
    Ingress: Io + Unpin + extensions::ExtensionsMut,
    Egress: Io + Unpin + extensions::ExtensionsMut,
{
    type Output = ();
    type Error = BoxError;

    async fn serve(
        &self,
        InputWithClientHello {
            input,
            client_hello,
        }: InputWithClientHello<BridgeIo<Ingress, Egress>>,
    ) -> Result<Self::Output, Self::Error> {
        let maybe_connector_data = TlsConnectorDataBuilder::try_from(client_hello)
            .unwrap_or_default()
            .with_server_verify_mode(ServerVerifyMode::Disable)
            .build()
            .inspect_err(|err| {
                tracing::debug!("failed to build TlsConnectorData (from CH or default): {err}; try anyway without data")
            })
            .ok();

        let tls_input = self
            .relay
            .handshake(input, maybe_connector_data)
            .await
            .context("tls MITM relay handshake")?;

        self.inner.serve(tls_input).await.map_err(Into::into)
    }
}
