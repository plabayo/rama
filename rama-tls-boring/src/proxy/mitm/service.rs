use rama_core::{
    Service,
    error::BoxError,
    extensions::{self, ExtensionsRef},
    io::{BridgeIo, Io},
    telemetry::tracing,
};
use rama_net::{
    proxy::ProxyTarget,
    tls::{
        client::{ServerVerifyMode, TlsClientConfig},
        server::InputWithClientHello,
    },
};

use crate::{
    TlsStream,
    client::{BoringClientConfigExt, BoringTlsConnectorConfig, TlsConnectorData},
    proxy::{TlsMitmRelay, TlsMitmRelayError},
};

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
    Ingress: Io + Unpin + extensions::ExtensionsRef,
    Egress: Io + Unpin + extensions::ExtensionsRef,
{
    type Output = ();
    type Error = TlsMitmRelayError;

    async fn serve(&self, input: BridgeIo<Ingress, Egress>) -> Result<Self::Output, Self::Error> {
        // No-CH path: egress will send a default builder CH (no SNI /
        // ALPN). Surface it so we can audit who's reaching this impl —
        // in normal MITM setups everyone goes through the
        // `InputWithClientHello` impl below.
        tracing::warn!(
            "tls mitm relay: BridgeIo (no ClientHello) impl invoked; \
             egress will ship boring defaults"
        );
        let cfg = TlsClientConfig::new()
            .with_server_verify(ServerVerifyMode::Disable)
            .with_keylog(self.relay.keylog_intent_ref().clone());

        let maybe_connector_data = TlsConnectorData::try_from(
            BoringTlsConnectorConfig::from_extensions(cfg.as_extensions()),
        )
        .inspect_err(|err| {
            tracing::debug!(
                %err,
                "failed to build default TlsConnectorData; try anyway without data"
            )
        })
        .ok();

        let proxy_target = input.extensions().get_ref::<ProxyTarget>().cloned();
        let tls_input = self
            .relay
            .handshake(input, maybe_connector_data)
            .await
            .map_err(|err| err.maybe_with_proxy_target(proxy_target))?;

        self.inner
            .serve(tls_input)
            .await
            .map_err(TlsMitmRelayError::tls_serve)
    }
}

impl<Issuer, Inner, Ingress, Egress> Service<InputWithClientHello<BridgeIo<Ingress, Egress>>>
    for TlsMitmRelayService<Issuer, Inner>
where
    Issuer: super::issuer::BoringMitmCertIssuer<Error: Into<BoxError>>,
    Inner: Service<BridgeIo<TlsStream<Ingress>, TlsStream<Egress>>, Output = (), Error: Into<BoxError>>,
    Ingress: Io + Unpin + extensions::ExtensionsRef,
    Egress: Io + Unpin + extensions::ExtensionsRef,
{
    type Output = ();
    type Error = TlsMitmRelayError;

    async fn serve(
        &self,
        InputWithClientHello {
            input,
            client_hello,
        }: InputWithClientHello<BridgeIo<Ingress, Egress>>,
    ) -> Result<Self::Output, Self::Error> {
        // TODO: in future have flow that works for SNI
        // as well as ECH target data??? If not already...
        let maybe_sni = client_hello.ext_server_name().cloned();
        // Split the mirror+default fallback so we can surface which
        // CHs trip it. `try_from` failure here is the silent route to
        // a default builder; that builder is what produces the
        // ~133-byte SNI-less ClientHello seen on the wire.
        let config = TlsClientConfig::new_from_client_hello(&client_hello)
            .with_server_verify(ServerVerifyMode::Disable)
            .with_keylog(self.relay.keylog_intent_ref().clone());

        let maybe_connector_data = TlsConnectorData::try_from(&config)
            .or_else(|err| {
                tracing::warn!(
                    ?maybe_sni,
                    %err,
                    "tls mitm relay: build TlsConnectorData from ClientHello failed; falling back to default (no SNI / ALPN)"
                );
                let config = TlsClientConfig::new()
                    .with_server_verify(ServerVerifyMode::Disable)
                    .with_keylog(self.relay.keylog_intent_ref().clone());
                TlsConnectorData::try_from(&config)
            })
            .inspect_err(|err| {
                tracing::debug!(%err, "failed to build TlsConnectorData (from CH or default); try anyway without data")
            })
            .ok();

        let proxy_target = input.extensions().get_ref::<ProxyTarget>().cloned();
        let tls_input = self
            .relay
            .handshake(input, maybe_connector_data)
            .await
            .map_err(|err| {
                err.maybe_with_proxy_target(proxy_target)
                    .maybe_with_sni(maybe_sni.clone())
            })?;

        tracing::debug!(
            "tls MITM relay handshake for SNI={maybe_sni:?} is complete... continue to serve tls tunnel bridge from within..."
        );

        self.inner
            .serve(tls_input)
            .await
            .map_err(TlsMitmRelayError::tls_serve)
    }
}
