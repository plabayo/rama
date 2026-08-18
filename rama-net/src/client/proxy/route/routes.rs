use crate::client::{
    ConnectionError, ConnectionErrorDomain, ConnectionErrorKind, ConnectorService,
    EstablishedClientConnection,
};
use crate::std::sync::Arc;
use core::{fmt, time::Duration};
use rama_core::{
    Fork, Layer, Service,
    error::{BoxError, BoxErrorExt as _},
    extensions::ExtensionsRef,
    telemetry::tracing,
};
use rama_utils::macros::{define_inner_service_accessors, generate_set_and_with};
use tokio::time::Instant;

use super::{ProxyRoute, ProxyRouteIndex, ProxyRoutes};

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
/// By default an existing singular [`ProxyRoute`] is honored before a
/// [`ProxyRoutes`] extension, or [`ProxyRoute::Direct`] is used when neither is
/// present. [`Self::with_routes`] configures a route collection that takes
/// precedence over a collection on the input. The default precedence order is:
/// singular [`ProxyRoute`], configured routes, input routes, implicit direct.
/// [`Self::with_overwrite`] or [`ProxyRoutes::with_overwrite`] explicitly lets
/// the selected route collection take precedence over a singular route.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ProxyRoutesConnector<S> {
    inner: S,
    routes: Option<Arc<ProxyRoutes>>,
    timeout: Option<Duration>,
    overwrite: bool,
}

impl<S> ProxyRoutesConnector<S> {
    /// Create a connector that reads routes from the input extensions.
    #[must_use]
    pub const fn new(inner: S) -> Self {
        Self {
            inner,
            routes: None,
            timeout: None,
            overwrite: false,
        }
    }

    /// Create a connector that uses the given ordered routes unless the input
    /// already contains a singular selected route.
    #[must_use]
    pub fn with_routes(inner: S, routes: impl Into<ProxyRoutes>) -> Self {
        Self {
            inner,
            routes: Some(Arc::new(routes.into())),
            timeout: None,
            overwrite: false,
        }
    }

    generate_set_and_with! {
        /// Let the selected route collection take precedence over an existing
        /// singular [`ProxyRoute`].
        ///
        /// Overwriting is disabled by default. A [`ProxyRoutes`] extension can
        /// independently opt in through [`ProxyRoutes::with_overwrite`].
        pub const fn overwrite(mut self, overwrite: bool) -> Self {
            self.overwrite = overwrite;
            self
        }
    }

    generate_set_and_with! {
        /// Limit the complete ordered-route operation to `timeout`.
        ///
        /// This is distinct from a timeout applied to the inner connector: an
        /// inner timeout applies to one route and can advance to the next route,
        /// while this budget covers every route and stops the operation when it is
        /// exhausted. Failures completed before the budget expired remain available
        /// through [`ProxyRouteConnectError`].
        pub fn timeout(mut self, timeout: Duration) -> Self {
            self.timeout = Some(timeout);
            self
        }
    }

    define_inner_service_accessors!();

    async fn connect_routes<Input>(
        &self,
        input: Input,
        routes: &[ProxyRoute],
        route_contexts: Option<&ProxyRoutes>,
        deadline: Option<Instant>,
    ) -> Result<EstablishedClientConnection<S::Connection, Input>, ConnectionError>
    where
        S: ConnectorService<Input>,
        Input: Fork + ExtensionsRef + Send + 'static,
    {
        let mut failures = Vec::new();
        for (index, route) in routes.iter().enumerate() {
            let attempt = input.fork();
            if let Some(extensions) =
                route_contexts.and_then(|contexts| contexts.route_extensions(index))
            {
                attempt.extensions().extend(extensions);
            }
            attempt.extensions().insert(route.clone());
            attempt.extensions().insert(ProxyRouteIndex::new(index));

            let result = match deadline {
                Some(deadline) => {
                    match tokio::time::timeout_at(deadline, self.inner.connect(attempt)).await {
                        Ok(result) => result,
                        Err(error) => {
                            let error = route_error_context(
                                ConnectionError::local(error, ConnectionErrorKind::Timeout)
                                    .context("proxy route connector: overall timeout"),
                                route,
                                index,
                            );
                            if failures.is_empty() {
                                return Err(error);
                            }

                            failures.push(error);
                            return Err(ConnectionError::new(
                                ProxyRouteConnectError::new(failures),
                                ConnectionErrorDomain::Local,
                                ConnectionErrorKind::Timeout,
                            ));
                        }
                    }
                }
                None => self.inner.connect(attempt).await,
            };

            match result {
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

    async fn connect_routes_with_timeout<Input>(
        &self,
        input: Input,
        routes: &[ProxyRoute],
        route_contexts: Option<&ProxyRoutes>,
    ) -> Result<EstablishedClientConnection<S::Connection, Input>, ConnectionError>
    where
        S: ConnectorService<Input>,
        Input: Fork + ExtensionsRef + Send + 'static,
    {
        let deadline = self.timeout.map(|timeout| Instant::now() + timeout);
        self.connect_routes(input, routes, route_contexts, deadline)
            .await
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
        let input_routes = input.extensions().get_arc::<ProxyRoutes>();
        let routes = self.routes.as_deref().or(input_routes.as_deref());

        if let Some(routes) = routes
            && (self.overwrite || routes.overwrite())
        {
            return self
                .connect_routes_with_timeout(
                    input,
                    routes_or_direct(routes.as_slice()),
                    Some(routes),
                )
                .await;
        }

        if let Some(route) = input.extensions().get_arc::<ProxyRoute>() {
            return self
                .connect_routes_with_timeout(input, core::slice::from_ref(route.as_ref()), None)
                .await;
        }

        if let Some(routes) = routes {
            return self
                .connect_routes_with_timeout(
                    input,
                    routes_or_direct(routes.as_slice()),
                    Some(routes),
                )
                .await;
        }

        self.connect_routes_with_timeout(input, &DIRECT_PROXY_ROUTES, None)
            .await
    }
}

/// Layer that tries ordered proxy routes while establishing a connection.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct ProxyRoutesConnectorLayer {
    routes: Option<Arc<ProxyRoutes>>,
    timeout: Option<Duration>,
    overwrite: bool,
}

impl ProxyRoutesConnectorLayer {
    /// Create a layer that reads routes from input extensions.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            routes: None,
            timeout: None,
            overwrite: false,
        }
    }

    /// Create a layer that uses the given ordered routes unless the input
    /// already contains a singular selected route.
    #[must_use]
    pub fn with_routes(routes: impl Into<ProxyRoutes>) -> Self {
        Self {
            routes: Some(Arc::new(routes.into())),
            timeout: None,
            overwrite: false,
        }
    }

    generate_set_and_with! {
        /// Let the selected route collection take precedence over an existing
        /// singular [`ProxyRoute`].
        ///
        /// Overwriting is disabled by default. A [`ProxyRoutes`] extension can
        /// independently opt in through [`ProxyRoutes::with_overwrite`].
        pub const fn overwrite(mut self, overwrite: bool) -> Self {
            self.overwrite = overwrite;
            self
        }
    }

    generate_set_and_with! {
        /// Limit the complete ordered-route operation to `timeout` while retaining
        /// any route failures completed before the budget expires.
        pub const fn timeout(mut self, timeout: Duration) -> Self {
            self.timeout = Some(timeout);
            self
        }
    }
}

impl<S> Layer<S> for ProxyRoutesConnectorLayer {
    type Service = ProxyRoutesConnector<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ProxyRoutesConnector {
            inner,
            routes: self.routes.clone(),
            timeout: self.timeout,
            overwrite: self.overwrite,
        }
    }

    fn into_layer(self, inner: S) -> Self::Service {
        ProxyRoutesConnector {
            inner,
            routes: self.routes,
            timeout: self.timeout,
            overwrite: self.overwrite,
        }
    }
}

#[cfg(test)]
mod tests {
    use core::sync::atomic::{AtomicUsize, Ordering};

    use parking_lot::Mutex;
    use rama_core::{
        ServiceInput,
        error::BoxError,
        extensions::{Extension, Extensions},
        layer::TimeoutLayer,
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

    #[derive(Debug, Clone, PartialEq, Eq, Extension)]
    struct RoutePreference(&'static str);

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
        assert_eq!(
            established
                .input
                .extensions
                .get_ref::<ProxyRouteIndex>()
                .copied()
                .map(ProxyRouteIndex::get),
            Some(2)
        );
    }

    #[tokio::test]
    async fn route_extensions_are_isolated_per_attempt_and_survive_success() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let inner = service_fn({
            let attempts = attempts.clone();
            move |input: ConnectRequest| {
                let attempts = attempts.clone();
                async move {
                    let attempt = attempts.fetch_add(1, Ordering::SeqCst);
                    let preference = input
                        .extensions
                        .get_ref::<RoutePreference>()
                        .expect("route preference");
                    assert_eq!(preference.0, if attempt == 0 { "first" } else { "second" });
                    assert_eq!(
                        input
                            .extensions
                            .get_ref::<ProxyRoute>()
                            .and_then(ProxyRoute::proxy_address)
                            .map(|address| address.address.host.to_string()),
                        Some(if attempt == 0 {
                            "first.example".to_owned()
                        } else {
                            "second.example".to_owned()
                        })
                    );
                    assert_eq!(
                        input
                            .extensions
                            .get_ref::<ProxyRouteIndex>()
                            .copied()
                            .map(ProxyRouteIndex::get),
                        Some(attempt)
                    );

                    if attempt == 0 {
                        Err(ConnectionError::transport(
                            BoxError::from_static_str("first route unavailable"),
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
        let first_extensions = Extensions::new();
        first_extensions.insert(RoutePreference("first"));
        first_extensions.insert(proxy("hidden-first"));
        first_extensions.insert(ProxyRouteIndex::new(99));
        let second_extensions = Extensions::new();
        second_extensions.insert(RoutePreference("second"));
        second_extensions.insert(proxy("hidden-second"));
        second_extensions.insert(ProxyRouteIndex::new(99));
        let routes = [
            (proxy("first"), first_extensions),
            (proxy("second"), second_extensions),
        ]
        .into_iter()
        .collect::<ProxyRoutes>();
        let connector = ProxyRoutesConnector::new(inner);
        let input = ConnectRequest::new(HostWithPort::example_domain_https());
        let original_extensions = input.extensions.clone();
        input.extensions.insert(routes);

        let established = connector.serve(input).await.unwrap();

        assert_eq!(attempts.load(Ordering::SeqCst), 2);
        assert_eq!(
            established.input.extensions.get_ref::<RoutePreference>(),
            Some(&RoutePreference("second"))
        );
        assert_eq!(
            established
                .input
                .extensions
                .iter_ref::<RoutePreference>()
                .count(),
            1
        );
        assert!(original_extensions.get_ref::<RoutePreference>().is_none());
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

    #[tokio::test(start_paused = true)]
    async fn timeout_layer_failure_advances_to_next_route() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let inner = TimeoutLayer::new(Duration::from_secs(1)).into_layer(service_fn({
            let attempts = attempts.clone();
            move |input: ConnectRequest| {
                let attempts = attempts.clone();
                async move {
                    if attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                        core::future::pending::<()>().await;
                    }
                    Ok::<_, core::convert::Infallible>(EstablishedClientConnection {
                        input,
                        conn: ServiceInput::new(()),
                    })
                }
            }
        }));
        let connector = ProxyRoutesConnector::new(inner);
        let input = ConnectRequest::new(HostWithPort::example_domain_https());
        input
            .extensions
            .insert(ProxyRoutes::new([proxy("a"), proxy("b")]));

        connector.serve(input).await.unwrap();
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn overall_timeout_limits_all_route_attempts() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let inner = service_fn({
            let attempts = attempts.clone();
            move |_input: ConnectRequest| {
                let attempts = attempts.clone();
                async move {
                    attempts.fetch_add(1, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_secs(10)).await;
                    Err::<EstablishedClientConnection<ServiceInput<()>, _>, _>(
                        ConnectionError::transport(
                            BoxError::from_static_str("route unavailable"),
                            ConnectionErrorKind::Unavailable,
                        ),
                    )
                }
            }
        });
        let connector = ProxyRoutesConnector::new(inner).with_timeout(Duration::from_secs(15));
        let input = ConnectRequest::new(HostWithPort::example_domain_https());
        input
            .extensions
            .insert(ProxyRoutes::new([proxy("a"), proxy("b"), proxy("c")]));

        let error = connector.serve(input).await.unwrap_err();
        assert_eq!(error.domain(), ConnectionErrorDomain::Local);
        assert_eq!(error.kind(), ConnectionErrorKind::Timeout);
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
        let aggregate = error
            .get_ref()
            .downcast_ref::<ProxyRouteConnectError>()
            .unwrap();
        assert_eq!(aggregate.failures().len(), 2);
        assert_eq!(
            aggregate.failures()[0].kind(),
            ConnectionErrorKind::Unavailable
        );
        assert_eq!(aggregate.failures()[1].kind(), ConnectionErrorKind::Timeout);
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
    async fn concurrent_route_plans_remain_isolated() {
        let inner = service_fn(async |input: ConnectRequest| {
            let route = route_name(input.extensions.get_ref::<ProxyRoute>().unwrap());
            tokio::task::yield_now().await;
            if route.contains("first") {
                Err(ConnectionError::transport(
                    BoxError::from_static_str("first route unavailable"),
                    ConnectionErrorKind::Unavailable,
                ))
            } else {
                Ok(EstablishedClientConnection {
                    input,
                    conn: ServiceInput::new(()),
                })
            }
        });
        let connector = ProxyRoutesConnector::new(inner);
        let first = ConnectRequest::new(HostWithPort::example_domain_https());
        first
            .extensions
            .insert(ProxyRoutes::new([proxy("a-first"), proxy("a-second")]));
        let second = ConnectRequest::new(HostWithPort::example_domain_https());
        second
            .extensions
            .insert(ProxyRoutes::new([proxy("b-first"), proxy("b-second")]));

        let (first, second) = tokio::join!(connector.serve(first), connector.serve(second));
        let first = first.unwrap();
        let second = second.unwrap();

        assert_eq!(
            route_name(first.input.extensions.get_ref::<ProxyRoute>().unwrap()),
            "a-second.example"
        );
        assert_eq!(
            route_name(second.input.extensions.get_ref::<ProxyRoute>().unwrap()),
            "b-second.example"
        );
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
    async fn singular_route_overrides_context_routes() {
        let inner = service_fn(async |input: ConnectRequest| {
            assert_eq!(
                route_name(input.extensions.get_ref::<ProxyRoute>().unwrap()),
                "selected.example"
            );
            Ok::<_, core::convert::Infallible>(EstablishedClientConnection {
                input,
                conn: ServiceInput::new(()),
            })
        });
        let connector = ProxyRoutesConnector::new(inner);
        let input = ConnectRequest::new(HostWithPort::example_domain_https());
        input.extensions.insert(ProxyRoutes::from(proxy("planned")));
        input.extensions.insert(proxy("selected"));

        connector.serve(input).await.unwrap();
    }

    #[tokio::test]
    async fn context_routes_can_opt_into_overwriting_singular_route() {
        let inner = service_fn(async |input: ConnectRequest| {
            assert_eq!(
                route_name(input.extensions.get_ref::<ProxyRoute>().unwrap()),
                "planned.example"
            );
            Ok::<_, core::convert::Infallible>(EstablishedClientConnection {
                input,
                conn: ServiceInput::new(()),
            })
        });
        let connector = ProxyRoutesConnector::new(inner);
        let input = ConnectRequest::new(HostWithPort::example_domain_https());
        input
            .extensions
            .insert(ProxyRoutes::from(proxy("planned")).with_overwrite(true));
        input.extensions.insert(proxy("selected"));

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
    async fn singular_route_overrides_hardcoded_routes() {
        let inner = service_fn(async |input: ConnectRequest| {
            assert_eq!(
                route_name(input.extensions.get_ref::<ProxyRoute>().unwrap()),
                "selected.example"
            );
            Ok::<_, core::convert::Infallible>(EstablishedClientConnection {
                input,
                conn: ServiceInput::new(()),
            })
        });
        let connector = ProxyRoutesConnector::with_routes(inner, proxy("fixed"));
        let input = ConnectRequest::new(HostWithPort::example_domain_https());
        input.extensions.insert(proxy("selected"));

        connector.serve(input).await.unwrap();
    }

    #[tokio::test]
    async fn connector_can_opt_into_overwriting_singular_route() {
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
        let connector =
            ProxyRoutesConnector::with_routes(inner, proxy("fixed")).with_overwrite(true);
        let input = ConnectRequest::new(HostWithPort::example_domain_https());
        input.extensions.insert(proxy("selected"));

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

    #[tokio::test]
    async fn layer_can_opt_into_overwriting_singular_route() {
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
        let connector = ProxyRoutesConnectorLayer::with_routes(proxy("fixed"))
            .with_overwrite(true)
            .into_layer(inner);
        let input = ConnectRequest::new(HostWithPort::example_domain_https());
        input.extensions.insert(proxy("selected"));

        connector.serve(input).await.unwrap();
    }
}
