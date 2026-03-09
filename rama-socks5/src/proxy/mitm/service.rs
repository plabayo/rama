use rama_core::{
    Service,
    error::{BoxError, ErrorContext as _},
    extensions,
    io::{BridgeIo, Io},
};
use rama_net::proxy::IoForwardService;

use super::Socks5MitmHandshakeOutcome;

#[derive(Debug, Clone)]
/// A service that can be used by MITM services such as transparent proxies,
/// in order to relay a socks5 proxy connection between a client and server,
/// as part of a deep protocol inspection protocol (DPI) flow.
pub struct Socks5MitmRelayService<I, F = IoForwardService> {
    dpi_svc: I,
    fallback_svc: F,
}

impl<I> Socks5MitmRelayService<I> {
    /// Create a new [`Socks5MitmRelayService`] using the given
    /// provided inspector servicew to continue the DPI of (socks5) handshaked traffic with a
    /// [`Socks5MitmHandshakeOutcome::ContinueInspection`] outcome.
    ///
    /// Use [`Self::with_fallback`] to define a custom [`Service`]
    /// if you wish behaviour for unsupported flows other than
    /// mindlessly proxying bytes using [`IoForwardService`] (the default).
    pub fn new(dpi_svc: I) -> Self {
        Self {
            dpi_svc,
            fallback_svc: IoForwardService::new(),
        }
    }

    /// Attach a fallback [`Service`] to this [`Socks5MitmRelayService`].
    ///
    /// Used in case the handshaked resulted in a
    /// [`Socks5MitmHandshakeOutcome::UnsupportedFlow`] outcome,
    /// e.g. because the method or command was not compatible with DPI (or desired).
    pub fn with_fallback<F>(self, fallback_svc: F) -> Socks5MitmRelayService<I, F> {
        Socks5MitmRelayService {
            dpi_svc: self.dpi_svc,
            fallback_svc,
        }
    }
}

impl<I, F, Ingress, Egress> Service<BridgeIo<Ingress, Egress>> for Socks5MitmRelayService<I, F>
where
    I: Service<BridgeIo<Ingress, Egress>, Output = (), Error: Into<BoxError>>,
    F: Service<BridgeIo<Ingress, Egress>, Output = (), Error: Into<BoxError>>,
    Ingress: Io + Unpin + extensions::ExtensionsMut,
    Egress: Io + Unpin + extensions::ExtensionsMut,
{
    type Output = ();
    type Error = BoxError;

    async fn serve(
        &self,
        BridgeIo(mut ingress_stream, mut egress_stream): BridgeIo<Ingress, Egress>,
    ) -> Result<Self::Output, Self::Error> {
        let outcome = super::socks5_mitm_relay_handshake(&mut ingress_stream, &mut egress_stream)
            .await
            .context("socks5 relay handshake using provided I/O bridge")?;
        match outcome {
            Socks5MitmHandshakeOutcome::ContinueInspection => self
                .dpi_svc
                .serve(BridgeIo(ingress_stream, egress_stream))
                .await
                .context("serve socks5 handshake-relayed bridge I/O using DPI svc"),
            Socks5MitmHandshakeOutcome::UnsupportedFlow => self
                .fallback_svc
                .serve(BridgeIo(ingress_stream, egress_stream))
                .await
                .context("serve socks5 handshake-relayed bridge I/O using fallback svc"),
        }
    }
}
