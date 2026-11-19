use rama_core::{
    Layer, Service,
    error::{BoxError, BoxErrorExt as _},
    extensions::ExtensionsRef,
};

use crate::client::{
    ConnectionError, ConnectionErrorKind, ConnectorService, EstablishedClientConnection, ProxyRoute,
};

/// A connector for a client without proxy support: it serves a route without a proxy and
/// refuses a proxied [`ProxyRoute`] instead of connecting around the proxy.
#[derive(Debug, Clone)]
pub struct DirectOnlyConnector<S> {
    inner: S,
}

impl<S> DirectOnlyConnector<S> {
    /// Serve the routes without a proxy over `inner`.
    pub const fn new(inner: S) -> Self {
        Self { inner }
    }
}

impl<S, Input> Service<Input> for DirectOnlyConnector<S>
where
    S: ConnectorService<Input>,
    Input: ExtensionsRef + Send + 'static,
{
    type Output = EstablishedClientConnection<S::Connection, Input>;
    type Error = ConnectionError;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        if let Some(ProxyRoute::Proxy(_)) = input.extensions().get_ref::<ProxyRoute>() {
            return Err(ConnectionError::local(
                BoxError::from_static_str("proxy route on a client without proxy support"),
                ConnectionErrorKind::Unavailable,
            ));
        }
        self.inner.connect(input).await
    }
}

/// [`Layer`] producing a [`DirectOnlyConnector`].
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct DirectOnlyConnectorLayer;

impl<S> Layer<S> for DirectOnlyConnectorLayer {
    type Service = DirectOnlyConnector<S>;

    fn layer(&self, inner: S) -> Self::Service {
        DirectOnlyConnector::new(inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        address::HostWithPort,
        client::ConnectRequest,
        test_utils::client::{MockConnectorService, MockSocket},
    };
    use rama_core::service::service_fn;
    use std::convert::Infallible;

    fn connector() -> DirectOnlyConnector<impl ConnectorService<ConnectRequest>> {
        DirectOnlyConnector::new(MockConnectorService::new(|_| {
            service_fn(async |_socket: MockSocket| Ok::<_, Infallible>(()))
        }))
    }

    #[tokio::test]
    async fn a_proxied_route_is_refused() {
        let input = ConnectRequest::new(HostWithPort::example_domain_https());
        input.extensions.insert(ProxyRoute::Proxy(
            "socks5://proxy.example:1080".parse().unwrap(),
        ));

        let Err(error) = connector().connect(input).await else {
            panic!("a client without proxy support never connects around the proxy");
        };
        assert_eq!(error.kind(), ConnectionErrorKind::Unavailable);
    }

    #[tokio::test]
    async fn a_direct_or_absent_route_is_served() {
        connector()
            .connect(ConnectRequest::new(HostWithPort::example_domain_https()))
            .await
            .expect("no route connects");

        let input = ConnectRequest::new(HostWithPort::example_domain_https());
        input.extensions.insert(ProxyRoute::Direct);
        connector()
            .connect(input)
            .await
            .expect("a direct route connects");
    }
}
