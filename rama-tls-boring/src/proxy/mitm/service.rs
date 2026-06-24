use rama_core::{
    Service,
    error::BoxError,
    extensions::{self, ExtensionsRef},
    io::{BridgeIo, Io},
    telemetry::tracing,
};
use rama_net::{address::Domain, client::ConnectorTarget};
use rama_tls::{
    KeyLogIntent,
    client::{ClientHello, ServerVerifyMode, TlsClientConfig},
    server::InputWithClientHello,
};

use crate::{
    TlsStream,
    client::{BoringClientConfigExt, BoringTlsConnectorConfig, TlsConnectorData},
    proxy::{TlsMitmRelay, TlsMitmRelayError},
};

/// Build the egress [`TlsClientConfig`] for the MITM relay from the peeked
/// ingress [`ClientHello`] (or boring defaults when none is available).
///
/// `new_from_client_hello` deliberately strips the SNI: regular connectors
/// re-derive it per-request from the transport authority. The relay reaches
/// the upstream through [`tls_connect`], which has no such fallback, so the
/// peeked SNI is re-attached here — otherwise egress ships an SNI-less
/// ClientHello and the upstream serves the wrong cert (or rejects the hello).
///
/// [`tls_connect`]: crate::client::tls_connect
fn egress_tls_client_config(
    client_hello: Option<&ClientHello>,
    sni: Option<Domain>,
    keylog: KeyLogIntent,
) -> TlsClientConfig {
    let config = match client_hello {
        Some(hello) => TlsClientConfig::new_from_client_hello(hello),
        None => TlsClientConfig::new(),
    }
    .with_server_verify(ServerVerifyMode::Disable)
    .with_keylog(keylog);
    match sni {
        Some(sni) => config.with_server_name(sni.into()),
        None => config,
    }
}

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

        let connector_target = input
            .extensions()
            .get_ref()
            .map(|ConnectorTarget(target)| target.clone());
        let tls_input = self
            .relay
            .handshake(input, maybe_connector_data)
            .await
            .map_err(|err| err.maybe_with_connector_target(connector_target))?;

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
        let keylog = self.relay.keylog_intent_ref().clone();
        // Split the mirror+default fallback so we can surface which
        // CHs trip it. `try_from` failure here is the silent route to
        // a default builder; that builder is what produces the
        // ~133-byte SNI-less ClientHello seen on the wire.
        let config =
            egress_tls_client_config(Some(&client_hello), maybe_sni.clone(), keylog.clone());

        let maybe_connector_data = TlsConnectorData::try_from(&config)
            .or_else(|err| {
                tracing::warn!(
                    ?maybe_sni,
                    %err,
                    "tls mitm relay: build TlsConnectorData from ClientHello failed; falling back to default (no ALPN)"
                );
                let config = egress_tls_client_config(None, maybe_sni.clone(), keylog);
                TlsConnectorData::try_from(&config)
            })
            .inspect_err(|err| {
                tracing::debug!(%err, "failed to build TlsConnectorData (from CH or default); try anyway without data")
            })
            .ok();

        let connector_target = input
            .extensions()
            .get_ref()
            .map(|ConnectorTarget(target)| target.clone());

        let tls_input = self
            .relay
            .handshake(input, maybe_connector_data)
            .await
            .map_err(|err| {
                err.maybe_with_connector_target(connector_target)
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

#[cfg(test)]
mod tests {
    use super::*;
    use rama_tls::{ProtocolVersion, client::ClientHelloExtension};

    fn hello_with_sni(sni: &Domain) -> ClientHello {
        ClientHello::new(
            ProtocolVersion::TLSv1_3,
            Vec::new(),
            Vec::new(),
            vec![ClientHelloExtension::ServerName(Some(sni.clone()))],
        )
    }

    // Regression (boring extensions refactor): `new_from_client_hello`
    // strips the SNI and the relay's `tls_connect` path can't re-derive it
    // from a transport authority, so the egress config MUST carry the peeked
    // SNI or the upstream gets an SNI-less hello (wrong cert / handshake
    // failure). Pin that the egress connector data keeps the ingress SNI.
    #[test]
    fn egress_config_carries_ingress_sni() {
        let sni = Domain::from_static("example.com");
        let hello = hello_with_sni(&sni);

        let config =
            egress_tls_client_config(Some(&hello), Some(sni.clone()), KeyLogIntent::Disabled);
        let data = TlsConnectorData::try_from(&config).expect("build egress connector data");
        assert_eq!(data.server_name.as_ref(), Some(&sni));

        // Guard the contract the re-attach compensates for: the config taken
        // straight from the hello carries no SNI on its own.
        let stripped = TlsClientConfig::new_from_client_hello(&hello);
        let stripped_data =
            TlsConnectorData::try_from(&stripped).expect("build stripped connector data");
        assert_eq!(stripped_data.server_name, None);
    }
}
