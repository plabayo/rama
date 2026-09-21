//! Dispatch an already selected HTTP protocol to its transport connector.

use rama_core::{Service, error::BoxErrorExt as _, extensions::ExtensionsRef as _};
use rama_http_types::{Version, conn::TargetHttpVersion};
use rama_net::client::{
    ConnectRequest, ConnectionError, ConnectionErrorKind, ConnectorService,
    EstablishedClientConnection, ProxyRoute,
};

/// Connect HTTP/3 over QUIC and other HTTP versions over the supplied TCP stack.
///
/// Service discovery and fallback belong to
/// [`HttpServiceConnector`](rama_http::layer::http_service::HttpServiceConnector),
/// outside proxy-route selection and these independently pooled transports.
#[derive(Clone, Debug)]
pub struct Http3TransportConnector<H, T> {
    h3: H,
    tcp: T,
}

impl<H, T> Http3TransportConnector<H, T> {
    /// Compose transport stacks which return the same HTTP connection type.
    pub const fn new(h3: H, tcp: T) -> Self {
        Self { h3, tcp }
    }
}

impl<H, T> Service<ConnectRequest> for Http3TransportConnector<H, T>
where
    H: ConnectorService<ConnectRequest>,
    T: ConnectorService<ConnectRequest, Connection = H::Connection>,
{
    type Output = EstablishedClientConnection<H::Connection, ConnectRequest>;
    type Error = ConnectionError;

    async fn serve(&self, input: ConnectRequest) -> Result<Self::Output, Self::Error> {
        if input
            .extensions()
            .get_ref::<TargetHttpVersion>()
            .is_some_and(|version| version.0 == Version::HTTP_3)
        {
            // Current HTTP CONNECT and SOCKS routes carry TCP. Reject before
            // touching the QUIC pool, so the outer selectors can try another
            // explicitly configured route or alternative service.
            if input
                .extensions()
                .get_ref::<ProxyRoute>()
                .and_then(ProxyRoute::proxy_address)
                .is_some()
            {
                return Err(ConnectionError::transport(
                    rama_core::error::BoxError::from_static_str(
                        "proxy route does not provide a QUIC transport",
                    ),
                    ConnectionErrorKind::Unavailable,
                ));
            }
            self.h3.connect(input).await
        } else {
            self.tcp.connect(input).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama_core::{ServiceInput, service::service_fn};
    use rama_net::client::{ProxyRoutes, ProxyRoutesConnector};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    #[tokio::test]
    async fn proxy_routes_never_implicitly_bypass_the_proxy_for_quic() {
        for allow_direct in [false, true] {
            let calls = Arc::new(AtomicUsize::new(0));
            let quic = service_fn({
                let calls = calls.clone();
                move |input: ConnectRequest| {
                    calls.fetch_add(1, Ordering::SeqCst);
                    async move {
                        assert_eq!(
                            input.extensions().get_ref::<ProxyRoute>(),
                            Some(&ProxyRoute::Direct)
                        );
                        Ok::<_, ConnectionError>(EstablishedClientConnection {
                            input,
                            conn: ServiceInput::new(()),
                        })
                    }
                }
            });
            let tcp = service_fn(
                async |_input: ConnectRequest| -> Result<
                    EstablishedClientConnection<ServiceInput<()>, ConnectRequest>,
                    ConnectionError,
                > {
                    panic!("an explicitly selected H3 service must not use TCP");
                },
            );
            let connector = ProxyRoutesConnector::new(Http3TransportConnector::new(quic, tcp));
            let mut routes = vec![ProxyRoute::Proxy(
                "http://proxy.example:8080".parse().unwrap(),
            )];
            if allow_direct {
                routes.push(ProxyRoute::Direct);
            }
            let input = ConnectRequest::new("example.com:443".parse().unwrap());
            input.extensions().insert(ProxyRoutes::new(routes));
            input
                .extensions()
                .insert(TargetHttpVersion(Version::HTTP_3));
            let result = connector.serve(input).await;
            assert_eq!(result.is_ok(), allow_direct);
            assert_eq!(calls.load(Ordering::SeqCst), usize::from(allow_direct));
            if let Err(error) = result {
                assert_eq!(error.kind(), ConnectionErrorKind::Unavailable);
            }
        }
    }
}
