use crate::client::{
    ConnectionError, ConnectionErrorDomain, ConnectionErrorKind, ConnectorService,
    EstablishedClientConnection, ProxyRoute, ProxyRoutes,
};
use crate::std::sync::Arc;
use core::fmt;
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

fn should_try_next_route(error: &ConnectionError) -> bool {
    error.domain() == ConnectionErrorDomain::Transport
        && matches!(
            error.kind(),
            ConnectionErrorKind::Unavailable
                | ConnectionErrorKind::Timeout
                | ConnectionErrorKind::Rejected
                | ConnectionErrorKind::Protocol
                | ConnectionErrorKind::Other
        )
}

/// Errors produced by every attempted route of an unsuccessful connection.
///
/// The failures remain ordered by route preference and each one contains safe
/// route metadata such as its index, kind, host and port. The aggregate's
/// [`Display`](fmt::Display) and [`Debug`](fmt::Debug) implementations do not
/// print route addresses or nested error messages, so they cannot newly expose
/// proxy credentials. Callers that intentionally need the detailed causes can
/// inspect [`Self::failures`].
pub struct ProxyRouteConnectError {
    failures: Box<[ConnectionError]>,
}

impl ProxyRouteConnectError {
    fn new(failures: Vec<ConnectionError>) -> Self {
        debug_assert!(failures.len() > 1);
        Self {
            failures: failures.into_boxed_slice(),
        }
    }

    /// Return the attempted route failures in route preference order.
    pub fn failures(&self) -> &[ConnectionError] {
        &self.failures
    }

    /// Consume the aggregate and return its ordered route failures.
    #[must_use]
    pub fn into_failures(self) -> Box<[ConnectionError]> {
        self.failures
    }
}

impl fmt::Debug for ProxyRouteConnectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProxyRouteConnectError")
            .field("failure_count", &self.failures.len())
            .field(
                "final_classification",
                &self
                    .failures
                    .last()
                    .map(|error| (error.domain(), error.kind())),
            )
            .finish()
    }
}

impl fmt::Display for ProxyRouteConnectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "all {} attempted proxy routes failed",
            self.failures.len()
        )
    }
}

impl core::error::Error for ProxyRouteConnectError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        self.failures.last().map(|error| error as _)
    }
}

/// Try ordered proxy routes until a connection is established.
///
/// Every route receives an isolated [`Fork`] of the original input with the
/// selected [`ProxyRoute`] inserted into its extensions. A transport-domain
/// failure advances to the next route only when its kind indicates that another
/// route can plausibly help. Authentication, invalid-input and internal failures
/// stop fallback even when reported by the transport domain. Application, local
/// and unclassified failures also stop immediately because another transport
/// route should not normally change their outcome. If multiple attempted routes
/// fail, their contextualized errors are retained in a
/// [`ProxyRouteConnectError`].
///
/// Routes can be supplied by a [`ProxyRoutes`] extension. Without one, an
/// existing singular [`ProxyRoute`] is honored, or [`ProxyRoute::Direct`] is
/// used by default. [`Self::with_routes`] configures a fixed route collection
/// instead of reading it from the input. The complete precedence order is:
/// fixed routes, [`ProxyRoutes`], singular [`ProxyRoute`], implicit direct.
/// Consequently, inserting a singular route does not override an existing
/// route collection; replace the [`ProxyRoutes`] extension instead.
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
        let mut failures = Vec::with_capacity(routes.len());
        for (index, route) in routes.iter().enumerate() {
            let attempt = input.fork();
            attempt.extensions().insert(route.clone());

            match self.inner.connect(attempt).await {
                Ok(established) => return Ok(established),
                Err(error) => {
                    let error = route_error_context(error, route, index);
                    let try_next = should_try_next_route(&error) && index + 1 < routes.len();

                    if try_next {
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
                        failures.push(error);
                        continue;
                    }

                    if failures.is_empty() {
                        return Err(error);
                    }

                    let domain = error.domain();
                    let kind = error.kind();
                    failures.push(error);
                    return Err(ConnectionError::new(
                        ProxyRouteConnectError::new(failures),
                        domain,
                        kind,
                    ));
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
    async fn retryable_transport_kinds_advance_to_next_route() {
        for kind in [
            ConnectionErrorKind::Unavailable,
            ConnectionErrorKind::Timeout,
            ConnectionErrorKind::Rejected,
            ConnectionErrorKind::Protocol,
            ConnectionErrorKind::Other,
        ] {
            let attempts = Arc::new(AtomicUsize::new(0));
            let inner = service_fn({
                let attempts = attempts.clone();
                move |input: ConnectRequest| {
                    let attempts = attempts.clone();
                    async move {
                        if attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                            Err(ConnectionError::transport(
                                BoxError::from_static_str("try another route"),
                                kind,
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
                .insert(ProxyRoutes::new([proxy("a"), proxy("b")]));

            connector.serve(input).await.unwrap();
            assert_eq!(attempts.load(Ordering::SeqCst), 2, "kind: {kind}");
        }
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

    #[tokio::test]
    async fn unsafe_failure_classifications_stop_route_fallback() {
        for (domain, kind) in [
            (
                ConnectionErrorDomain::Transport,
                ConnectionErrorKind::Authentication,
            ),
            (
                ConnectionErrorDomain::Transport,
                ConnectionErrorKind::InvalidInput,
            ),
            (
                ConnectionErrorDomain::Transport,
                ConnectionErrorKind::Internal,
            ),
            (ConnectionErrorDomain::Local, ConnectionErrorKind::Internal),
            (ConnectionErrorDomain::Unknown, ConnectionErrorKind::Other),
        ] {
            let attempts = Arc::new(AtomicUsize::new(0));
            let inner = service_fn({
                let attempts = attempts.clone();
                move |_input: ConnectRequest| {
                    let attempts = attempts.clone();
                    async move {
                        attempts.fetch_add(1, Ordering::SeqCst);
                        Err::<EstablishedClientConnection<ServiceInput<()>, _>, _>(
                            ConnectionError::new(
                                BoxError::from_static_str("do not retry"),
                                domain,
                                kind,
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
            assert_eq!(error.domain(), domain);
            assert_eq!(error.kind(), kind);
            assert_eq!(attempts.load(Ordering::SeqCst), 1);
        }
    }

    #[tokio::test]
    async fn exhaustion_retains_ordered_route_failures_without_credentials() {
        let inner = service_fn(async |_input: ConnectRequest| {
            Err::<EstablishedClientConnection<ServiceInput<()>, _>, _>(ConnectionError::transport(
                BoxError::from_static_str("route unavailable"),
                ConnectionErrorKind::Unavailable,
            ))
        });
        let connector = ProxyRoutesConnector::new(inner);
        let input = ConnectRequest::new(HostWithPort::example_domain_https());
        input.extensions.insert(ProxyRoutes::new([
            ProxyRoute::Proxy("http://alice:first-secret@a.example:8080".parse().unwrap()),
            ProxyRoute::Proxy("http://bob:second-secret@b.example:8080".parse().unwrap()),
        ]));

        let error = connector.serve(input).await.unwrap_err();
        assert_eq!(error.domain(), ConnectionErrorDomain::Transport);
        assert_eq!(error.kind(), ConnectionErrorKind::Unavailable);
        assert_eq!(error.to_string(), "all 2 attempted proxy routes failed");

        let aggregate = error
            .get_ref()
            .downcast_ref::<ProxyRouteConnectError>()
            .unwrap();
        let failures = aggregate.failures();
        assert_eq!(failures.len(), 2);
        for (index, host) in ["a.example", "b.example"].into_iter().enumerate() {
            let message = failures[index].to_string();
            assert!(
                message.contains(&format!("proxy_route_index=\"{index}\"")),
                "{message}"
            );
            assert!(
                message.contains(&format!("proxy_host=\"{host}\"")),
                "{message}"
            );
            assert!(message.contains("proxy_port=\"8080\""), "{message}");
        }

        let formatted = format!("{aggregate:?} {aggregate}");
        assert!(formatted.contains("ProxyRouteConnectError"), "{formatted}");
        assert!(formatted.contains("failure_count: 2"), "{formatted}");
        assert!(!formatted.contains("first-secret"), "{formatted}");
        assert!(!formatted.contains("second-secret"), "{formatted}");
        assert!(!formatted.contains("alice"), "{formatted}");
        assert!(!formatted.contains("bob"), "{formatted}");

        let final_source = core::error::Error::source(aggregate).unwrap();
        assert!(
            final_source.to_string().contains("proxy_route_index=\"1\""),
            "{final_source}"
        );
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

    #[tokio::test]
    async fn layer_can_configure_hardcoded_routes() {
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
        let connector = ProxyRoutesConnectorLayer::with_routes(proxy("fixed")).into_layer(inner);
        let input = ConnectRequest::new(HostWithPort::example_domain_https());
        input.extensions.insert(ProxyRoutes::from(proxy("context")));

        connector.serve(input).await.unwrap();
    }
}
