use rama_core::{
    Layer, Service,
    error::{BoxError, BoxErrorExt as _},
    extensions::ExtensionsRef,
};
use rama_utils::macros::define_inner_service_accessors;

use crate::{
    ProtocolInputExt,
    client::{ConnectionError, ConnectionErrorKind},
    tls::TlsRequired,
};

/// The TLS stage of a connector towards proxies that has no TLS: it refuses every proxy
/// that asks for TLS, before anything is dialed.
///
/// In a stack with TLS, the TLS connector reads the proxy's protocol and [`TlsRequired`]
/// and secures the connection. Without one, nothing below it does: a TCP connector dials
/// whatever it is given, so an `https://` or `socks5+tls://` proxy would be reached in
/// plaintext, credentials included. This layer takes that slot and refuses instead.
/// `ProxyConnectorBuilder::without_tls_support` in `rama` installs it.
#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct PlaintextProxyOnlyLayer;

impl PlaintextProxyOnlyLayer {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl<S> Layer<S> for PlaintextProxyOnlyLayer {
    type Service = PlaintextProxyOnly<S>;

    fn layer(&self, inner: S) -> Self::Service {
        PlaintextProxyOnly::new(inner)
    }

    fn into_layer(self, inner: S) -> Self::Service {
        PlaintextProxyOnly::new(inner)
    }
}

/// The connector towards proxies [`PlaintextProxyOnlyLayer`] creates.
#[derive(Debug, Clone)]
pub struct PlaintextProxyOnly<S> {
    inner: S,
}

impl<S> PlaintextProxyOnly<S> {
    /// Create a new [`PlaintextProxyOnly`] over the connector towards proxies.
    pub const fn new(inner: S) -> Self {
        Self { inner }
    }

    define_inner_service_accessors!();
}

impl<S, Input> Service<Input> for PlaintextProxyOnly<S>
where
    S: Service<Input, Error: Into<ConnectionError>>,
    Input: ProtocolInputExt + ExtensionsRef + Send + 'static,
{
    type Output = S::Output;
    type Error = ConnectionError;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        if input
            .target_protocol()
            .is_some_and(|protocol| protocol.is_secure())
            || input.extensions().get_ref::<TlsRequired>().is_some()
        {
            return Err(ConnectionError::transport(
                BoxError::from_static_str("a secure proxy needs a TLS connector to be reached"),
                ConnectionErrorKind::Protocol,
            ));
        }
        self.inner.serve(input).await.map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Protocol,
        address::HostWithPort,
        client::{ConnectRequest, EstablishedClientConnection},
    };
    use rama_core::service::service_fn;

    #[tokio::test]
    async fn only_a_plaintext_proxy_is_dialed() {
        let connector =
            PlaintextProxyOnlyLayer::new().into_layer(service_fn(async |input: ConnectRequest| {
                Ok::<_, ConnectionError>(EstablishedClientConnection { input, conn: () })
            }));

        for (protocol, dialed) in [
            (Protocol::HTTP, true),
            (Protocol::SOCKS5, true),
            (Protocol::HTTPS, false),
        ] {
            let input = ConnectRequest::new(HostWithPort::try_from("proxy.example:8080").unwrap())
                .with_application_protocol(protocol.clone());
            assert_eq!(connector.serve(input).await.is_ok(), dialed, "{protocol:?}");
        }
    }

    #[tokio::test]
    async fn a_proxy_which_asks_for_tls_is_not_dialed_in_plaintext() {
        let connector =
            PlaintextProxyOnlyLayer::new().into_layer(service_fn(async |input: ConnectRequest| {
                Ok::<_, ConnectionError>(EstablishedClientConnection { input, conn: () })
            }));

        let input = ConnectRequest::new(HostWithPort::try_from("proxy.example:1080").unwrap())
            .with_application_protocol(Protocol::SOCKS5);
        input.extensions().insert(TlsRequired::new());
        let error = connector.serve(input).await.unwrap_err();
        assert_eq!(error.kind(), ConnectionErrorKind::Protocol);
    }
}
