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

/// Refuse to dial a secure proxy over a connector which has no TLS to secure it with.
///
/// Credentials must not travel over a connection that cannot be encrypted. A connector
/// towards proxies without a TLS stage knows that up front, so the proxy is never dialed
/// at all; a connector which does have one secures the connection itself.
///
/// A proxy whose address does not ask for TLS is refused just the same once the request to it
/// carries [`TlsRequired`]: asking for TLS where there is none is never answered with
/// plaintext.
#[derive(Debug, Clone, Copy, Default)]
pub struct PlaintextProxyOnlyLayer;

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
            PlaintextProxyOnlyLayer.into_layer(service_fn(async |input: ConnectRequest| {
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
            PlaintextProxyOnlyLayer.into_layer(service_fn(async |input: ConnectRequest| {
                Ok::<_, ConnectionError>(EstablishedClientConnection { input, conn: () })
            }));

        let input = ConnectRequest::new(HostWithPort::try_from("proxy.example:1080").unwrap())
            .with_application_protocol(Protocol::SOCKS5);
        input.extensions().insert(TlsRequired);
        let error = connector.serve(input).await.unwrap_err();
        assert_eq!(error.kind(), ConnectionErrorKind::Protocol);
    }
}
