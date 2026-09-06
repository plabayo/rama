use crate::client::{
    ConnectionError, ConnectionErrorDomain, ConnectionErrorKind, ConnectorService,
    EstablishedClientConnection,
};
use crate::std::sync::Arc;
use core::{fmt, time::Duration};
use rama_core::{
    Fork, Layer, Service,
    error::{BoxError, BoxErrorExt as _},
    extensions::{ExtensionsRef, FromExtensions},
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

fn should_try_next_route(error: &ConnectionError, next_route: &ProxyRoute) -> bool {
    if error.domain() != ConnectionErrorDomain::Transport {
        return false;
    }

    match error.kind() {
        ConnectionErrorKind::Unavailable | ConnectionErrorKind::Timeout => true,
        // These failures can be specific to a particular proxy implementation
        // or transport. Rotate to another proxy, but never turn them into an
        // implicit direct-origin fallback.
        ConnectionErrorKind::Rejected
        | ConnectionErrorKind::Protocol
        | ConnectionErrorKind::Other => matches!(next_route, ProxyRoute::Proxy(_)),
        ConnectionErrorKind::Authentication
        | ConnectionErrorKind::InvalidInput
        | ConnectionErrorKind::Internal => false,
    }
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

#[derive(FromExtensions)]
enum ProxyRouteSelection {
    Route(Arc<ProxyRoute>),
    Routes(Arc<ProxyRoutes>),
}

/// Resolve and materialize the route decision for downstream middleware.
///
/// Place every route-selection layer before this one, then place middleware
/// that consumes [`ProxyRoute`] after it. This is the sole middleware boundary
/// that needs to understand both route forms. The most recently inserted input
/// decision wins. An optional configured plan supplies defaults unless
/// [`Self::with_overwrite`] makes it authoritative. The selected plan publishes
/// its first route (or direct for an empty plan) to middleware and remains
/// authoritative for [`ProxyRoutesConnector`], which still owns fallback
/// attempts.
///
/// Credentials and route-specific extensions are omitted from the middleware
/// view of a multi-route plan. One HTTP header cannot safely authenticate every
/// fallback and could leak to a later direct route, while publishing the first
/// route's extensions would contaminate later attempts. The connector retains
/// the original per-route state and applies it to isolated attempts.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct ProxyRoutesLayer {
    routes: Option<Arc<ProxyRoutes>>,
    overwrite: bool,
}

impl ProxyRoutesLayer {
    /// Create a route materialization layer without configured defaults.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            routes: None,
            overwrite: false,
        }
    }

    /// Create a route materialization layer with an ordered default plan.
    ///
    /// An input [`ProxyRoute`] or `ProxyRoutes` decision takes precedence by
    /// default. Use [`Self::with_overwrite`] when this plan is authoritative.
    #[must_use]
    pub fn with_routes(routes: impl Into<ProxyRoutes>) -> Self {
        Self {
            routes: Some(Arc::new(routes.into())),
            overwrite: false,
        }
    }

    generate_set_and_with! {
        /// Let the configured route plan take precedence over an input route
        /// decision.
        pub const fn overwrite(mut self, overwrite: bool) -> Self {
            self.overwrite = overwrite;
            self
        }
    }
}

impl<S> Layer<S> for ProxyRoutesLayer {
    type Service = ProxyRoutesService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ProxyRoutesService {
            inner,
            routes: self.routes.clone(),
            overwrite: self.overwrite,
        }
    }

    fn into_layer(self, inner: S) -> Self::Service {
        ProxyRoutesService {
            inner,
            routes: self.routes,
            overwrite: self.overwrite,
        }
    }
}

/// Service produced by [`ProxyRoutesLayer`].
#[derive(Debug, Clone)]
pub struct ProxyRoutesService<S> {
    inner: S,
    routes: Option<Arc<ProxyRoutes>>,
    overwrite: bool,
}

impl<S> ProxyRoutesService<S> {
    /// Create a service that materializes route plans for middleware.
    pub const fn new(inner: S) -> Self {
        Self {
            inner,
            routes: None,
            overwrite: false,
        }
    }

    define_inner_service_accessors!();
}

impl<S, Input> Service<Input> for ProxyRoutesService<S>
where
    S: Service<Input>,
    Input: ExtensionsRef + Send + 'static,
{
    type Output = S::Output;
    type Error = S::Error;

    fn serve(
        &self,
        input: Input,
    ) -> impl Future<Output = Result<Self::Output, Self::Error>> + Send + '_ {
        let extensions = input.extensions();
        let selected = if self.overwrite {
            self.routes
                .clone()
                .map(ProxyRouteSelection::Routes)
                .or_else(|| ProxyRouteSelection::from_extensions(extensions))
        } else {
            ProxyRouteSelection::from_extensions(extensions)
                .or_else(|| self.routes.clone().map(ProxyRouteSelection::Routes))
        };
        match selected {
            Some(ProxyRouteSelection::Routes(routes)) => {
                let singular = routes.as_slice().len() == 1;
                let mut route = routes
                    .as_slice()
                    .first()
                    .cloned()
                    .unwrap_or(ProxyRoute::Direct);
                if singular {
                    if let Some(route_extensions) = routes.route_extensions(0) {
                        extensions.extend(route_extensions);
                    }
                } else if let ProxyRoute::Proxy(address) = &mut route {
                    address.credential = None;
                }
                extensions.insert(route);

                // Keep the complete plan authoritative after publishing its
                // middleware view as a singular route.
                extensions.insert_arc(routes);
            }
            Some(ProxyRouteSelection::Route(_)) | None => {}
        }
        self.inner.serve(input)
    }
}

/// Try ordered proxy routes until a connection is established.
///
/// Every route receives an isolated [`Fork`] of the original input with the
/// selected [`ProxyRoute`] inserted into its extensions. A transport-domain
/// unavailable or timeout failure advances to any next configured route.
/// Explicit rejection, protocol, and other transport failures advance only to
/// another proxy route, never to a direct route. Authentication, invalid-input,
/// and internal failures stop fallback even in the transport domain.
/// Application, local, and unclassified failures also stop immediately because
/// another transport route should not normally change their outcome. This lets
/// proxy-specific failures rotate without turning an intentional rejection into
/// an implicit direct-origin fallback. If multiple attempted routes fail, their
/// contextualized errors are retained in a [`ProxyRouteConnectError`].
///
/// Input route decisions use extension insertion order: the most recently
/// inserted [`ProxyRoute`] or [`ProxyRoutes`] wins. Configure default or
/// authoritative plans on [`ProxyRoutesLayer`], before route-aware middleware,
/// so every consumer observes the same selected route.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ProxyRoutesConnector<S> {
    inner: S,
    timeout: Option<Duration>,
}

impl<S> ProxyRoutesConnector<S> {
    /// Create a connector that reads routes from the input extensions.
    #[must_use]
    pub const fn new(inner: S) -> Self {
        Self {
            inner,
            timeout: None,
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
                    let try_next = routes
                        .get(index + 1)
                        .is_some_and(|next_route| should_try_next_route(&error, next_route));

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
        match ProxyRouteSelection::from_extensions(input.extensions()) {
            Some(ProxyRouteSelection::Route(route)) => {
                return self
                    .connect_routes_with_timeout(input, core::slice::from_ref(route.as_ref()), None)
                    .await;
            }
            Some(ProxyRouteSelection::Routes(routes)) => {
                return self
                    .connect_routes_with_timeout(
                        input,
                        routes_or_direct(routes.as_slice()),
                        Some(routes.as_ref()),
                    )
                    .await;
            }
            None => {}
        }

        // No route decision was requested. Preserve that absence instead of
        // turning an ordinary connection into an explicit direct-route attempt.
        // Keep the same attempt isolation as an explicitly selected route.
        let attempt = input.fork();
        match self.timeout {
            Some(timeout) => tokio::time::timeout(timeout, self.inner.connect(attempt))
                .await
                .map_err(|error| {
                    ConnectionError::local(error, ConnectionErrorKind::Timeout)
                        .context("proxy route connector: overall timeout")
                })?,
            None => self.inner.connect(attempt).await,
        }
    }
}

/// Layer that tries ordered proxy routes while establishing a connection.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct ProxyRoutesConnectorLayer {
    timeout: Option<Duration>,
}

impl ProxyRoutesConnectorLayer {
    /// Create a layer that reads routes from input extensions.
    #[must_use]
    pub const fn new() -> Self {
        Self { timeout: None }
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
            timeout: self.timeout,
        }
    }

    fn into_layer(self, inner: S) -> Self::Service {
        ProxyRoutesConnector {
            inner,
            timeout: self.timeout,
        }
    }
}

#[cfg(test)]
mod tests {
    use core::{
        convert::Infallible,
        sync::atomic::{AtomicUsize, Ordering},
    };

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

    #[tokio::test]
    async fn unconfigured_routes_preserve_absence_with_or_without_timeout() {
        #[derive(Debug, Extension)]
        struct AttemptMarker;

        for timeout in [None, Some(Duration::from_secs(5))] {
            let inner = service_fn(|input: ConnectRequest| async move {
                assert!(!input.extensions.contains::<ProxyRoute>());
                assert!(!input.extensions.contains::<ProxyRouteIndex>());
                input.extensions.insert(AttemptMarker);
                Ok::<_, Infallible>(EstablishedClientConnection {
                    input,
                    conn: ServiceInput::new(()),
                })
            });
            let mut connector = ProxyRoutesConnector::new(inner);
            if let Some(timeout) = timeout {
                connector.set_timeout(timeout);
            }
            let input = ConnectRequest::new(HostWithPort::example_domain_http());
            let original_extensions = input.extensions.clone();
            let established = connector.serve(input).await.unwrap();
            assert!(!established.input.extensions.contains::<ProxyRoute>());
            assert!(
                !established
                    .conn
                    .extensions()
                    .contains::<crate::client::EstablishedProxyRoute>()
            );
            assert!(established.input.extensions.contains::<AttemptMarker>());
            assert!(!original_extensions.contains::<AttemptMarker>());
        }
    }

    #[tokio::test(start_paused = true)]
    async fn unconfigured_routes_still_obey_the_overall_timeout() {
        let inner = service_fn(|_: ConnectRequest| async move {
            std::future::pending::<
                Result<EstablishedClientConnection<ServiceInput<()>, ConnectRequest>, Infallible>,
            >()
            .await
        });
        let connector = ProxyRoutesConnector::new(inner).with_timeout(Duration::from_secs(5));
        let start = Instant::now();
        let error = connector
            .serve(ConnectRequest::new(HostWithPort::example_domain_http()))
            .await
            .unwrap_err();
        assert_eq!(error.domain(), ConnectionErrorDomain::Local);
        assert_eq!(error.kind(), ConnectionErrorKind::Timeout);
        assert_eq!(start.elapsed(), Duration::from_secs(5));
    }

    #[tokio::test]
    async fn route_layer_materializes_plans_without_replacing_singular_routes() {
        let service =
            ProxyRoutesLayer::new().into_layer(service_fn(|input: ServiceInput<()>| async move {
                Ok::<_, Infallible>(input)
            }));

        let singular = ServiceInput::new(());
        singular.extensions.insert(proxy("selected"));
        let singular = service.serve(singular).await.unwrap();
        assert_eq!(
            route_name(singular.extensions.get_ref::<ProxyRoute>().unwrap()),
            "selected.example"
        );
        assert!(!singular.extensions.contains::<ProxyRoutes>());

        let authoritative = ServiceInput::new(());
        authoritative.extensions.insert(proxy("stale"));
        authoritative
            .extensions
            .insert(ProxyRoutes::new([proxy("primary"), ProxyRoute::Direct]));
        let authoritative = service.serve(authoritative).await.unwrap();
        assert_eq!(
            route_name(authoritative.extensions.get_ref::<ProxyRoute>().unwrap()),
            "primary.example"
        );
        assert_eq!(
            authoritative
                .extensions
                .get_ref::<ProxyRoutes>()
                .unwrap()
                .as_slice()
                .len(),
            2
        );

        let route_extensions = Extensions::new();
        route_extensions.insert(RoutePreference("singleton"));
        let singleton = ServiceInput::new(());
        singleton.extensions.insert(
            [(proxy("only"), route_extensions)]
                .into_iter()
                .collect::<ProxyRoutes>(),
        );
        let singleton = service.serve(singleton).await.unwrap();
        assert_eq!(
            singleton.extensions.get_ref::<RoutePreference>(),
            Some(&RoutePreference("singleton"))
        );
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
    async fn route_layer_keeps_extensions_isolated_per_attempt() {
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
        let connector = ProxyRoutesLayer::new().into_layer(ProxyRoutesConnector::new(inner));
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
    async fn unavailable_and_timeout_transport_failures_advance() {
        for kind in [
            ConnectionErrorKind::Unavailable,
            ConnectionErrorKind::Timeout,
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
    async fn proxy_specific_transport_failures_advance_to_another_proxy() {
        for kind in [
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
                                BoxError::from_static_str("proxy-specific failure"),
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
    async fn proxy_specific_transport_failures_do_not_fall_back_to_direct() {
        for kind in [
            ConnectionErrorKind::Rejected,
            ConnectionErrorKind::Protocol,
            ConnectionErrorKind::Other,
        ] {
            let attempts = Arc::new(AtomicUsize::new(0));
            let inner = service_fn({
                let attempts = attempts.clone();
                move |_input: ConnectRequest| {
                    let attempts = attempts.clone();
                    async move {
                        attempts.fetch_add(1, Ordering::SeqCst);
                        Err::<EstablishedClientConnection<ServiceInput<()>, _>, _>(
                            ConnectionError::transport(
                                BoxError::from_static_str("proxy-specific failure"),
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
                .insert(ProxyRoutes::new([proxy("a"), ProxyRoute::Direct]));

            let error = connector.serve(input).await.unwrap_err();
            assert_eq!(error.kind(), kind);
            assert_eq!(attempts.load(Ordering::SeqCst), 1, "kind: {kind}");
        }
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
    async fn newer_context_routes_override_a_singular_route() {
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
        input.extensions.insert(proxy("selected"));
        input.extensions.insert(ProxyRoutes::from(proxy("planned")));

        connector.serve(input).await.unwrap();
    }

    #[tokio::test]
    async fn input_plan_overrides_configured_default_routes() {
        let inner = service_fn(async |input: ConnectRequest| {
            assert_eq!(
                route_name(input.extensions.get_ref::<ProxyRoute>().unwrap()),
                "context.example"
            );
            Ok::<_, core::convert::Infallible>(EstablishedClientConnection {
                input,
                conn: ServiceInput::new(()),
            })
        });
        let connector = ProxyRoutesLayer::with_routes(proxy("fixed"))
            .into_layer(ProxyRoutesConnector::new(inner));
        let input = ConnectRequest::new(HostWithPort::example_domain_https());
        input.extensions.insert(ProxyRoutes::from(proxy("context")));

        connector.serve(input).await.unwrap();
    }

    #[tokio::test]
    async fn singular_route_overrides_configured_default_routes() {
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
        let connector = ProxyRoutesLayer::with_routes(proxy("fixed"))
            .into_layer(ProxyRoutesConnector::new(inner));
        let input = ConnectRequest::new(HostWithPort::example_domain_https());
        input.extensions.insert(proxy("selected"));

        connector.serve(input).await.unwrap();
    }

    #[tokio::test]
    async fn route_layer_can_overwrite_a_singular_route() {
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
        let connector = ProxyRoutesLayer::with_routes(proxy("fixed"))
            .with_overwrite(true)
            .into_layer(ProxyRoutesConnector::new(inner));
        let input = ConnectRequest::new(HostWithPort::example_domain_https());
        input.extensions.insert(proxy("selected"));

        connector.serve(input).await.unwrap();
    }

    #[tokio::test]
    async fn configured_routes_are_used_without_an_input_decision() {
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
        let connector = ProxyRoutesLayer::with_routes(proxy("fixed"))
            .into_layer(ProxyRoutesConnector::new(inner));
        let input = ConnectRequest::new(HostWithPort::example_domain_https());

        connector.serve(input).await.unwrap();
    }

    #[tokio::test]
    async fn authoritative_configured_routes_override_an_input_plan() {
        let inner = service_fn(async |input: ConnectRequest| {
            assert_eq!(
                route_name(input.extensions.get_ref::<ProxyRoute>().unwrap()),
                "fixed.example"
            );
            assert!(input.extensions.get_ref::<RoutePreference>().is_none());
            Ok::<_, core::convert::Infallible>(EstablishedClientConnection {
                input,
                conn: ServiceInput::new(()),
            })
        });
        let connector = ProxyRoutesLayer::with_routes(proxy("fixed"))
            .with_overwrite(true)
            .into_layer(ProxyRoutesConnector::new(inner));
        let input = ConnectRequest::new(HostWithPort::example_domain_https());
        let route_extensions = Extensions::new();
        route_extensions.insert(RoutePreference("context"));
        input.extensions.insert(
            [(proxy("context"), route_extensions)]
                .into_iter()
                .collect::<ProxyRoutes>(),
        );

        connector.serve(input).await.unwrap();
    }
}
