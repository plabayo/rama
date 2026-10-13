//! Route an established connection by the application protocol its handshake negotiated.

use std::fmt;

use rama_core::{Service, error::BoxError, extensions::ExtensionsRef, service::RejectService};
use rama_net::tls::ApplicationProtocol;

use crate::client::NegotiatedTlsParameters;

/// Routes input whose TLS handshake negotiated `protocol` to `inner`, and everything else to the
/// fallback, which rejects by default.
///
/// The protocol is read from the [`NegotiatedTlsParameters`] the TLS stack put in the input's
/// extensions: the one both peers agreed on, never one only offered. That makes it the same
/// decision for a TLS stream, a pair of relayed streams (whose extensions are the ingress
/// side's) or a QUIC connection.
#[derive(Debug, Clone)]
pub struct AlpnRouter<S, F = RejectService<(), UnsupportedAlpnError>> {
    protocol: ApplicationProtocol,
    inner: S,
    fallback: F,
}

impl<S> AlpnRouter<S> {
    /// Route input that negotiated `protocol` to `inner`.
    pub fn new(protocol: ApplicationProtocol, inner: S) -> Self {
        Self {
            protocol,
            inner,
            fallback: RejectService::new(UnsupportedAlpnError),
        }
    }
}

impl<S, F> AlpnRouter<S, F> {
    /// Route all other input, including input without a negotiated protocol, to `fallback`.
    pub fn with_fallback<G>(self, fallback: G) -> AlpnRouter<S, G> {
        AlpnRouter {
            protocol: self.protocol,
            inner: self.inner,
            fallback,
        }
    }
}

impl<Input, S, F, O> Service<Input> for AlpnRouter<S, F>
where
    Input: ExtensionsRef + Send + 'static,
    S: Service<Input, Output = O, Error: Into<BoxError>>,
    F: Service<Input, Output = O, Error: Into<BoxError>>,
    O: Send + 'static,
{
    type Output = O;
    type Error = BoxError;

    async fn serve(&self, input: Input) -> Result<O, BoxError> {
        let negotiated = input
            .extensions()
            .get_ref::<NegotiatedTlsParameters>()
            .is_some_and(|params| {
                params.application_layer_protocol.as_ref() == Some(&self.protocol)
            });
        if negotiated {
            self.inner.serve(input).await.map_err(Into::into)
        } else {
            self.fallback.serve(input).await.map_err(Into::into)
        }
    }
}

/// The default fallback's rejection: nothing routes the negotiated protocol, or none was.
#[derive(Debug, Clone, Copy, Default)]
pub struct UnsupportedAlpnError;

impl fmt::Display for UnsupportedAlpnError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("no route for the negotiated application protocol")
    }
}

impl std::error::Error for UnsupportedAlpnError {}

#[cfg(test)]
mod tests {
    use rama_core::{ServiceInput, service::service_fn};

    use super::*;
    use crate::ProtocolVersion;

    fn input(protocol: Option<ApplicationProtocol>) -> ServiceInput<()> {
        let input = ServiceInput::new(());
        if let Some(protocol) = protocol {
            input.extensions().insert(NegotiatedTlsParameters {
                protocol_version: ProtocolVersion::TLSv1_3,
                application_layer_protocol: Some(protocol),
                peer_certificate_chain: None,
                server_name: None,
                resumed: None,
                algorithms: Default::default(),
            });
        }
        input
    }

    #[tokio::test]
    async fn routes_on_the_negotiated_protocol_only() {
        let router = AlpnRouter::new(
            ApplicationProtocol::HTTP_3,
            service_fn(async |_: ServiceInput<()>| Ok::<_, BoxError>("h3")),
        )
        .with_fallback(service_fn(async |_: ServiceInput<()>| {
            Ok::<_, BoxError>("fallback")
        }));
        for (negotiated, expected) in [
            (Some(ApplicationProtocol::HTTP_3), "h3"),
            (Some(ApplicationProtocol::HTTP_2), "fallback"),
            (None, "fallback"),
        ] {
            assert_eq!(
                router.serve(input(negotiated.clone())).await.unwrap(),
                expected,
                "{negotiated:?}"
            );
        }
    }

    #[tokio::test]
    async fn the_default_fallback_rejects() {
        let router = AlpnRouter::new(
            ApplicationProtocol::HTTP_3,
            service_fn(async |_: ServiceInput<()>| Ok::<_, BoxError>(())),
        );
        router.serve(input(None)).await.unwrap_err();
    }
}
