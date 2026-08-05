use crate::client::{
    ConnectionError, ConnectionErrorDomain, ConnectionErrorKind, ConnectorService,
    EstablishedClientConnection, ProxyRoute, ProxyRoutes,
};
use crate::std::sync::Arc;
use rama_core::{
    Fork, Layer, Service,
    error::{BoxError, BoxErrorExt as _},
    extensions::ExtensionsRef,
    telemetry::tracing,
};
use rama_utils::macros::define_inner_service_accessors;

const DIRECT_PROXY_ROUTES: [ProxyRoute; 1] = [ProxyRoute::Direct];

fn routes_or_direct(routes: &[ProxyRoute]) -> &[ProxyRoute] {
    if routes.is_empty() {
        &DIRECT_PROXY_ROUTES
    } else {
        routes
    }
}

fn route_error_context(
    error: ConnectionError,
    route: &ProxyRoute,
    index: usize,
) -> ConnectionError {
    let error = error.context_field("proxy_route_index", index);
    match route {
        ProxyRoute::Direct => error.context_field("proxy_route", "DIRECT"),
        ProxyRoute::Proxy(proxy) => error
            .context_field("proxy_route", "PROXY")
            .context_field("proxy_host", proxy.address.host.clone())
            .context_field("proxy_port", proxy.address.port),
    }
}

/// Try ordered proxy routes until a connection is established.
///
/// Every route receives an isolated [`Fork`] of the original input with the
/// selected [`ProxyRoute`] inserted into its extensions. A transport-domain
/// failure advances to the next route. Application, local and unclassified
/// failures are returned immediately because another transport route should
/// not normally change their outcome. When every route fails at the transport
/// domain, the final route's error is returned with non-sensitive route context.
///
/// Routes can be supplied by a [`ProxyRoutes`] extension. Without one, an
/// existing singular [`ProxyRoute`] is honored, or [`ProxyRoute::Direct`] is
/// used by default. [`Self::with_routes`] configures a fixed route collection
/// instead of reading it from the input.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ProxyRoutesConnector<S> {
    inner: S,
    routes: Option<Arc<ProxyRoutes>>,
}

impl<S> ProxyRoutesConnector<S> {
    /// Create a connector that reads routes from the input extensions.
    #[must_use]
    pub const fn new(inner: S) -> Self {
        Self {
            inner,
            routes: None,
        }
    }

    /// Create a connector that always uses the given ordered routes.
    #[must_use]
    pub fn with_routes(inner: S, routes: impl Into<ProxyRoutes>) -> Self {
        Self {
            inner,
            routes: Some(Arc::new(routes.into())),
        }
    }

    define_inner_service_accessors!();

    async fn connect_routes<Input>(
        &self,
        input: Input,
        routes: &[ProxyRoute],
    ) -> Result<EstablishedClientConnection<S::Connection, Input>, ConnectionError>
    where
        S: ConnectorService<Input>,
        Input: Fork + ExtensionsRef + Send + 'static,
    {
        for (index, route) in routes.iter().enumerate() {
            let attempt = input.fork();
            attempt.extensions().insert(route.clone());

            match self.inner.connect(attempt).await {
                Ok(established) => return Ok(established),
                Err(error)
                    if error.domain() == ConnectionErrorDomain::Transport
                        && index + 1 < routes.len() =>
                {
                    match route {
                        ProxyRoute::Direct => tracing::debug!(
                            route.index = index,
                            route.kind = "direct",
                            error = ?error,
                            "proxy route failed; trying next route",
                        ),
                        ProxyRoute::Proxy(proxy) => tracing::debug!(
                            route.index = index,
                            route.kind = "proxy",
                            server.address = %proxy.address.host,
                            server.port = proxy.address.port,
                            error = ?error,
                            "proxy route failed; trying next route",
                        ),
                    }
                }
                Err(error) => {
                    return Err(route_error_context(error, route, index));
                }
            }
        }

        Err(ConnectionError::local(
            BoxError::from_static_str("proxy route resolution produced no attempts"),
            ConnectionErrorKind::Internal,
        ))
    }
}

impl<S, Input> Service<Input> for ProxyRoutesConnector<S>
where
    S: ConnectorService<Input>,
    Input: Fork + ExtensionsRef + Send + 'static,
{
    type Output = EstablishedClientConnection<S::Connection, Input>;
    type Error = ConnectionError;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        if let Some(routes) = self.routes.as_deref() {
            return self
                .connect_routes(input, routes_or_direct(routes.as_slice()))
                .await;
        }

        if let Some(routes) = input.extensions().get_arc::<ProxyRoutes>() {
            return self
                .connect_routes(input, routes_or_direct(routes.as_slice()))
                .await;
        }

        if let Some(route) = input.extensions().get_arc::<ProxyRoute>() {
            return self
                .connect_routes(input, core::slice::from_ref(route.as_ref()))
                .await;
        }

        self.connect_routes(input, &DIRECT_PROXY_ROUTES).await
    }
}

/// Layer that tries ordered proxy routes while establishing a connection.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct ProxyRoutesConnectorLayer {
    routes: Option<Arc<ProxyRoutes>>,
}

impl ProxyRoutesConnectorLayer {
    /// Create a layer that reads routes from input extensions.
    #[must_use]
    pub const fn new() -> Self {
        Self { routes: None }
    }

    /// Create a layer that always uses the given ordered routes.
    #[must_use]
    pub fn with_routes(routes: impl Into<ProxyRoutes>) -> Self {
        Self {
            routes: Some(Arc::new(routes.into())),
        }
    }
}

impl<S> Layer<S> for ProxyRoutesConnectorLayer {
    type Service = ProxyRoutesConnector<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ProxyRoutesConnector {
            inner,
            routes: self.routes.clone(),
        }
    }

    fn into_layer(self, inner: S) -> Self::Service {
        ProxyRoutesConnector {
            inner,
            routes: self.routes,
        }
    }
}

#[cfg(test)]
mod tests {
    use core::sync::atomic::{AtomicUsize, Ordering};

    use parking_lot::Mutex;
    use rama_core::{
        ServiceInput,
        error::{BoxError, BoxErrorExt as _},
        extensions::Extension,
        service::service_fn,
    };

    use crate::{
        address::{HostWithPort, ProxyAddress},
        client::{ConnectRequest, ConnectionErrorKind},
    };

    use super::*;

    fn proxy(name: &str) -> ProxyRoute {
        ProxyRoute::Proxy(
            format!("http://{name}.example:8080")
                .parse::<ProxyAddress>()
                .unwrap(),
        )
    }

    fn route_name(route: &ProxyRoute) -> String {
        match route {
            ProxyRoute::Direct => "DIRECT".to_owned(),
            ProxyRoute::Proxy(address) => address.address.host.to_string(),
        }
    }

    #[tokio::test]
    async fn retries_transport_failures_in_order() {
        let attempts = Arc::new(Mutex::new(Vec::new()));
        let inner = service_fn({
            let attempts = attempts.clone();
            move |input: ConnectRequest| {
                let attempts = attempts.clone();
                async move {
                    let route = input.extensions.get_ref::<ProxyRoute>().unwrap();
                    attempts.lock().push(route_name(route));
                    if attempts.lock().len() < 3 {
                        Err(ConnectionError::transport(
                            BoxError::from_static_str("route unavailable"),
                            ConnectionErrorKind::Unavailable,
                        ))
                    } else {
                        Ok(EstablishedClientConnection {
                            input,
                            conn: ServiceInput::new(()),
                        })
                    }
                }
            }
        });
        let connector = ProxyRoutesConnector::new(inner);
        let input = ConnectRequest::new(HostWithPort::example_domain_https());
        input
            .extensions
            .insert(ProxyRoutes::new([proxy("a"), proxy("b"), proxy("c")]));

        let established = connector.serve(input).await.unwrap();
        assert_eq!(
            attempts.lock().as_slice(),
            ["a.example", "b.example", "c.example"]
        );
        assert_eq!(
            route_name(
                established
                    .input
                    .extensions
                    .get_ref::<ProxyRoute>()
                    .unwrap()
            ),
            "c.example"
        );
    }

    #[tokio::test]
    async fn application_failure_stops_route_fallback() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let inner = service_fn({
            let attempts = attempts.clone();
            move |_input: ConnectRequest| {
                let attempts = attempts.clone();
                async move {
                    attempts.fetch_add(1, Ordering::SeqCst);
                    Err::<EstablishedClientConnection<ServiceInput<()>, _>, _>(
                        ConnectionError::application(
                            BoxError::from_static_str("origin handshake failed"),
                            ConnectionErrorKind::Protocol,
                        ),
                    )
                }
            }
        });
        let connector = ProxyRoutesConnector::new(inner);
        let input = ConnectRequest::new(HostWithPort::example_domain_https());
        input
            .extensions
            .insert(ProxyRoutes::new([proxy("a"), proxy("b")]));

        let error = connector.serve(input).await.unwrap_err();
        assert_eq!(error.domain(), ConnectionErrorDomain::Application);
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
    }

    #[derive(Debug, Extension)]
    struct FailedAttemptMarker;

    #[tokio::test]
    async fn failed_attempt_extensions_do_not_leak() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let inner = service_fn({
            let attempts = attempts.clone();
            move |input: ConnectRequest| {
                let attempts = attempts.clone();
                async move {
                    let index = attempts.fetch_add(1, Ordering::SeqCst);
                    if index == 0 {
                        input.extensions.insert(FailedAttemptMarker);
                        Err(ConnectionError::transport(
                            BoxError::from_static_str("first route failed"),
                            ConnectionErrorKind::Unavailable,
                        ))
                    } else {
                        assert!(!input.extensions.contains::<FailedAttemptMarker>());
                        Ok(EstablishedClientConnection {
                            input,
                            conn: ServiceInput::new(()),
                        })
                    }
                }
            }
        });
        let connector = ProxyRoutesConnector::new(inner);
        let input = ConnectRequest::new(HostWithPort::example_domain_https());
        input
            .extensions
            .insert(ProxyRoutes::new([proxy("a"), proxy("b")]));

        connector.serve(input).await.unwrap();
    }

    #[tokio::test]
    async fn empty_routes_mean_direct() {
        let inner = service_fn(async |input: ConnectRequest| {
            assert_eq!(
                input.extensions.get_ref::<ProxyRoute>(),
                Some(&ProxyRoute::Direct)
            );
            Ok::<_, core::convert::Infallible>(EstablishedClientConnection {
                input,
                conn: ServiceInput::new(()),
            })
        });
        let connector = ProxyRoutesConnector::new(inner);
        let input = ConnectRequest::new(HostWithPort::example_domain_https());
        input.extensions.insert(ProxyRoutes::default());

        connector.serve(input).await.unwrap();
    }

    #[tokio::test]
    async fn hardcoded_routes_override_context_routes() {
        let inner = service_fn(async |input: ConnectRequest| {
            assert_eq!(
                route_name(input.extensions.get_ref::<ProxyRoute>().unwrap()),
                "fixed.example"
            );
            Ok::<_, core::convert::Infallible>(EstablishedClientConnection {
                input,
                conn: ServiceInput::new(()),
            })
        });
        let connector = ProxyRoutesConnector::with_routes(inner, proxy("fixed"));
        let input = ConnectRequest::new(HostWithPort::example_domain_https());
        input.extensions.insert(ProxyRoutes::from(proxy("context")));

        connector.serve(input).await.unwrap();
    }
}
