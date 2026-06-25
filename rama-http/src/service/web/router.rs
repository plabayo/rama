#![expect(
    clippy::allow_attributes,
    reason = "macro-generated `#[allow]` attributes whose underlying lints fire only for some expansions"
)]

use std::{cmp::Reverse, convert::Infallible, error::Error, fmt};

use rama_core::{
    Layer,
    extensions::{Extensions, ExtensionsRef},
    layer::MapResult,
    matcher::Matcher,
    service::{BoxService, Service},
    telemetry::tracing,
};
use rama_http_types::Method;
use rama_http_types::{Body, OriginalRouterUri, StatusCode};
use rama_net::uri::{
    PathPattern, PathPatternSegmentKind, PathPatternSegmentSpecificity, PathRouter,
};
use rama_utils::collections::NonEmptySmallVec;

use crate::{
    Request, Response,
    headers::Allow,
    matcher::path::{compile_pattern, match_pattern},
    matcher::{HttpMatcher, MethodMatcher, UriParams},
    service::web::{
        IntoEndpointService, IntoEndpointServiceWithState,
        response::{ErrorResponse, Headers, IntoResponse},
    },
};

/// Default endpoint layer for the router.
/// It converts Output and Error types of endpoints using [`IntoResponse`] trait,
/// same as [`ErrorHandlerLayer`], except it returns [`RouterError`] instead of [`Infallible`]
/// to fit default Router.
///
/// [`ErrorHandlerLayer`]: crate::layer::error_handling::ErrorHandlerLayer
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct DefaultEndpointLayer;

impl<S> Layer<S> for DefaultEndpointLayer
where
    S: Service<Request, Output: IntoResponse, Error: Into<ErrorResponse>>,
{
    type Service = MapResult<S, fn(Result<S::Output, S::Error>) -> Result<Response, RouterError>>;

    fn layer(&self, inner: S) -> Self::Service {
        MapResult::new(inner, |res| match res {
            Ok(v) => Ok(v.into_response()),
            Err(err) => Ok(err.into().into_response()),
        })
    }
}

/// A basic router that can be used to route requests to different services based on the request path.
///
/// Each route compiles to a [`PathPattern`]; on lookup the most-specific
/// matching pattern wins (static segments beat captures beat catch-alls).
/// Nested services are mounted under a prefix via a typed [`PathRouter`].
#[allow(unused)]
pub struct Router<State = (), Layer = DefaultEndpointLayer, O = Response, E = RouterError> {
    routes: Vec<RouteEntry<O, E>>,
    sub_services: Option<PathRouter<SubService<O, E>>>,
    not_found: Option<BoxService<Request, O, E>>,
    layer: Layer,
    state: State,
}

/// One registered route path: its compiled pattern, a specificity key (kept
/// sorted most-specific-first across `routes`), and the per-method handlers
/// sharing this path.
struct RouteEntry<O, E> {
    pattern: PathPattern,
    /// Per-segment specificity ranks (static=2, capture=1, catch-all=0);
    /// higher under `Vec`'s ordering = more specific.
    specificity: Vec<SegmentSpecificityRank>,
    handlers: Vec<(HttpMatcher<Body>, BoxService<Request, O, E>)>,
}

/// Specificity rank of one segment. Literal beats dynamic beats catch-all; for
/// two dynamic segments, more literal bytes and fewer wildcard/capture/optional
/// parts wins (e.g. `{file}.json` beats `{file}`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct SegmentSpecificityRank {
    kind: u8,
    literal_bytes: usize,
    fewer_dynamic_parts: Reverse<usize>,
    fewer_optional_parts: Reverse<usize>,
}

fn rank(spec: PathPatternSegmentSpecificity) -> SegmentSpecificityRank {
    let kind = match spec.kind {
        PathPatternSegmentKind::Literal => 2,
        PathPatternSegmentKind::Dynamic => 1,
        PathPatternSegmentKind::CatchAll => 0,
    };
    SegmentSpecificityRank {
        kind,
        literal_bytes: spec.literal_bytes,
        fewer_dynamic_parts: Reverse(spec.dynamic_parts),
        fewer_optional_parts: Reverse(spec.optional_parts),
    }
}

/// Per-segment specificity key for a compiled pattern. The pattern itself is
/// the authority on what each segment is — the router never parses the syntax.
fn specificity_of(pattern: &PathPattern) -> Vec<SegmentSpecificityRank> {
    pattern.segment_specificity().map(rank).collect()
}

impl<S, L, O, E> std::fmt::Debug for Router<S, L, O, E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Router").finish()
    }
}

impl<O, E> Router<(), DefaultEndpointLayer, O, E> {
    /// create a new router.
    #[must_use]
    pub fn new() -> Self {
        Self::new_with_state(())
    }
}

impl<State, O, E> Router<State, DefaultEndpointLayer, O, E>
where
    State: Send + Sync + Clone + 'static,
{
    #[must_use]
    /// Create a new router with state
    pub fn new_with_state(state: State) -> Self {
        Self {
            routes: Vec::new(),
            sub_services: None,
            not_found: None,
            layer: Default::default(),
            state,
        }
    }
}

impl<State, L, O, E> Router<State, L, O, E>
where
    State: Send + Sync + Clone + 'static,
{
    /// Get reference to the state.
    #[inline]
    pub fn state(&self) -> &State {
        &self.state
    }

    /// Apply `layer` to every endpoint registered after this call.
    ///
    /// Routes registered before this call keep whatever layer was in effect at the time of registration.
    pub fn with_endpoint_layer<N>(self, layer: N) -> Router<State, N, O, E> {
        Router {
            routes: self.routes,
            sub_services: self.sub_services,
            not_found: self.not_found,
            layer,
            state: self.state,
        }
    }

    /// Apply [`DefaultEndpointLayer`] to every endpoint registered after this call.
    ///
    /// Routes registered before this call keep whatever layer was in effect at the time of registration.
    pub fn with_default_endpoint_layer(self) -> Router<State, DefaultEndpointLayer, O, E> {
        Router {
            routes: self.routes,
            sub_services: self.sub_services,
            not_found: self.not_found,
            layer: DefaultEndpointLayer,
            state: self.state,
        }
    }

    /// add a GET route to the router.
    /// the path can contain parameters, e.g. `/users/{id}`.
    /// the path can also contain a catch call, e.g. `/assets/{*path}`.
    #[must_use]
    #[inline]
    pub fn with_get<I, T>(self, path: impl AsRef<str>, service: I) -> Self
    where
        I: IntoEndpointServiceWithState<T, State>,
        L: Layer<I::Service, Service: Service<Request, Output = O, Error = E>>,
    {
        let matcher = HttpMatcher::method_get();
        self.with_match_route(path, matcher, service)
    }

    /// add a GET route to the router.
    /// the path can contain parameters, e.g. `/users/{id}`.
    /// the path can also contain a catch call, e.g. `/assets/{*path}`.
    #[inline]
    pub fn set_get<I, T>(&mut self, path: impl AsRef<str>, service: I) -> &mut Self
    where
        I: IntoEndpointServiceWithState<T, State>,
        L: Layer<I::Service, Service: Service<Request, Output = O, Error = E>>,
    {
        let matcher = HttpMatcher::method_get();
        self.set_match_route(path, matcher, service)
    }

    /// add a POST route to the router.
    #[must_use]
    #[inline]
    pub fn with_post<I, T>(self, path: impl AsRef<str>, service: I) -> Self
    where
        I: IntoEndpointServiceWithState<T, State>,
        L: Layer<I::Service, Service: Service<Request, Output = O, Error = E>>,
    {
        let matcher = HttpMatcher::method_post();
        self.with_match_route(path, matcher, service)
    }

    /// add a POST route to the router.
    #[inline]
    pub fn set_post<I, T>(&mut self, path: impl AsRef<str>, service: I) -> &mut Self
    where
        I: IntoEndpointServiceWithState<T, State>,
        L: Layer<I::Service, Service: Service<Request, Output = O, Error = E>>,
    {
        let matcher = HttpMatcher::method_post();
        self.set_match_route(path, matcher, service)
    }

    /// add a PUT route to the router.
    #[must_use]
    #[inline]
    pub fn with_put<I, T>(self, path: impl AsRef<str>, service: I) -> Self
    where
        I: IntoEndpointServiceWithState<T, State>,
        L: Layer<I::Service, Service: Service<Request, Output = O, Error = E>>,
    {
        let matcher = HttpMatcher::method_put();
        self.with_match_route(path, matcher, service)
    }

    /// add a PUT route to the router.
    #[inline]
    pub fn set_put<I, T>(&mut self, path: impl AsRef<str>, service: I) -> &mut Self
    where
        I: IntoEndpointServiceWithState<T, State>,
        L: Layer<I::Service, Service: Service<Request, Output = O, Error = E>>,
    {
        let matcher = HttpMatcher::method_put();
        self.set_match_route(path, matcher, service)
    }

    /// add a DELETE route to the router.
    #[must_use]
    #[inline]
    pub fn with_delete<I, T>(self, path: impl AsRef<str>, service: I) -> Self
    where
        I: IntoEndpointServiceWithState<T, State>,
        L: Layer<I::Service, Service: Service<Request, Output = O, Error = E>>,
    {
        let matcher = HttpMatcher::method_delete();
        self.with_match_route(path, matcher, service)
    }

    /// add a DELETE route to the router.
    #[inline]
    pub fn set_delete<I, T>(&mut self, path: impl AsRef<str>, service: I) -> &mut Self
    where
        I: IntoEndpointServiceWithState<T, State>,
        L: Layer<I::Service, Service: Service<Request, Output = O, Error = E>>,
    {
        let matcher = HttpMatcher::method_delete();
        self.set_match_route(path, matcher, service)
    }

    /// add a PATCH route to the router.
    #[must_use]
    #[inline]
    pub fn with_patch<I, T>(self, path: impl AsRef<str>, service: I) -> Self
    where
        I: IntoEndpointServiceWithState<T, State>,
        L: Layer<I::Service, Service: Service<Request, Output = O, Error = E>>,
    {
        let matcher = HttpMatcher::method_patch();
        self.with_match_route(path, matcher, service)
    }

    /// add a PATCH route to the router.
    #[inline]
    pub fn set_patch<I, T>(&mut self, path: impl AsRef<str>, service: I) -> &mut Self
    where
        I: IntoEndpointServiceWithState<T, State>,
        L: Layer<I::Service, Service: Service<Request, Output = O, Error = E>>,
    {
        let matcher = HttpMatcher::method_patch();
        self.set_match_route(path, matcher, service)
    }

    /// add a HEAD route to the router.
    #[must_use]
    #[inline]
    pub fn with_head<I, T>(self, path: impl AsRef<str>, service: I) -> Self
    where
        I: IntoEndpointServiceWithState<T, State>,
        L: Layer<I::Service, Service: Service<Request, Output = O, Error = E>>,
    {
        let matcher = HttpMatcher::method_head();
        self.with_match_route(path, matcher, service)
    }

    /// add a HEAD route to the router.
    #[inline]
    pub fn set_head<I, T>(&mut self, path: impl AsRef<str>, service: I) -> &mut Self
    where
        I: IntoEndpointServiceWithState<T, State>,
        L: Layer<I::Service, Service: Service<Request, Output = O, Error = E>>,
    {
        let matcher = HttpMatcher::method_head();
        self.set_match_route(path, matcher, service)
    }

    /// add a OPTIONS route to the router.
    #[must_use]
    #[inline]
    pub fn with_options<I, T>(self, path: impl AsRef<str>, service: I) -> Self
    where
        I: IntoEndpointServiceWithState<T, State>,
        L: Layer<I::Service, Service: Service<Request, Output = O, Error = E>>,
    {
        let matcher = HttpMatcher::method_options();
        self.with_match_route(path, matcher, service)
    }

    /// add a OPTIONS route to the router.
    #[inline]
    pub fn set_options<I, T>(&mut self, path: impl AsRef<str>, service: I) -> &mut Self
    where
        I: IntoEndpointServiceWithState<T, State>,
        L: Layer<I::Service, Service: Service<Request, Output = O, Error = E>>,
    {
        let matcher = HttpMatcher::method_options();
        self.set_match_route(path, matcher, service)
    }

    /// add a TRACE route to the router.
    #[must_use]
    #[inline]
    pub fn with_trace<I, T>(self, path: impl AsRef<str>, service: I) -> Self
    where
        I: IntoEndpointServiceWithState<T, State>,
        L: Layer<I::Service, Service: Service<Request, Output = O, Error = E>>,
    {
        let matcher = HttpMatcher::method_trace();
        self.with_match_route(path, matcher, service)
    }

    /// add a TRACE route to the router.
    #[inline]
    pub fn set_trace<I, T>(&mut self, path: impl AsRef<str>, service: I) -> &mut Self
    where
        I: IntoEndpointServiceWithState<T, State>,
        L: Layer<I::Service, Service: Service<Request, Output = O, Error = E>>,
    {
        let matcher = HttpMatcher::method_trace();
        self.set_match_route(path, matcher, service)
    }

    /// add a CONNECT route to the router.
    #[must_use]
    #[inline]
    pub fn with_connect<I, T>(self, path: impl AsRef<str>, service: I) -> Self
    where
        I: IntoEndpointServiceWithState<T, State>,
        L: Layer<I::Service, Service: Service<Request, Output = O, Error = E>>,
    {
        let matcher = HttpMatcher::method_connect();
        self.with_match_route(path, matcher, service)
    }

    /// add a CONNECT route to the router.
    #[inline]
    pub fn set_connect<I, T>(&mut self, path: impl AsRef<str>, service: I) -> &mut Self
    where
        I: IntoEndpointServiceWithState<T, State>,
        L: Layer<I::Service, Service: Service<Request, Output = O, Error = E>>,
    {
        let matcher = HttpMatcher::method_connect();
        self.set_match_route(path, matcher, service)
    }

    /// add a QUERY route to the router.
    ///
    /// QUERY ([RFC 10008](https://www.rfc-editor.org/rfc/rfc10008)) is a safe,
    /// idempotent method whose request content defines the query.
    #[must_use]
    #[inline]
    pub fn with_query<I, T>(self, path: impl AsRef<str>, service: I) -> Self
    where
        I: IntoEndpointServiceWithState<T, State>,
        L: Layer<I::Service, Service: Service<Request, Output = O, Error = E>>,
    {
        let matcher = HttpMatcher::method_query();
        self.with_match_route(path, matcher, service)
    }

    /// add a QUERY route to the router.
    #[inline]
    pub fn set_query<I, T>(&mut self, path: impl AsRef<str>, service: I) -> &mut Self
    where
        I: IntoEndpointServiceWithState<T, State>,
        L: Layer<I::Service, Service: Service<Request, Output = O, Error = E>>,
    {
        let matcher = HttpMatcher::method_query();
        self.set_match_route(path, matcher, service)
    }

    /// register a nested router under a prefix (path).
    ///
    /// The prefix is used to match the request path and strip it from the request URI.
    ///
    /// Note: this sub-router is configured with the same State this router has.
    #[must_use]
    #[inline]
    pub fn with_sub_router_make_fn<Layer>(
        mut self,
        prefix: impl AsRef<str>,
        configure_router: impl FnOnce(Self) -> Router<State, Layer, O, E>,
    ) -> Self
    where
        L: Clone,
        Router<State, Layer, O, E>: Service<Request, Output = O, Error = E>,
    {
        self.set_sub_router_make_fn(prefix, configure_router);
        self
    }

    /// register a nested router under a prefix (path).
    ///
    /// The prefix is used to match the request path and strip it from the request URI.
    ///
    /// Note: this sub-router is configured with the same State this router has.
    pub fn set_sub_router_make_fn<Layer>(
        &mut self,
        prefix: impl AsRef<str>,
        configure_router: impl FnOnce(Self) -> Router<State, Layer, O, E>,
    ) -> &mut Self
    where
        L: Clone,
        Router<State, Layer, O, E>: Service<Request, Output = O, Error = E>,
    {
        let router = Self {
            routes: Vec::new(),
            sub_services: None,
            not_found: None,
            layer: self.layer.clone(),
            state: self.state.clone(),
        };
        let router = configure_router(router);
        let nested = router.boxed();
        self.set_sub_service_inner(prefix, nested)
    }

    /// Register a nested endpoint service under a prefix (path).
    ///
    /// The prefix is used to match the request path and strip it from the request URI.
    /// Endpoint layer is applied to this sub-service.
    ///
    /// Warning: If a sub-service is a plain [`Service`], not an endpoint function,
    /// it has no notion of the state this router has. If you want to create a sub-router
    /// that shares the same state this router has, use [`Router::with_sub_router_make_fn`] instead.
    #[must_use]
    #[inline]
    pub fn with_endpoint_service<I, T>(mut self, prefix: impl AsRef<str>, service: I) -> Self
    where
        I: IntoEndpointService<T>,
        L: Layer<I::Service, Service: Service<Request, Output = O, Error = E>>,
    {
        self.set_endpoint_service(prefix, service);
        self
    }

    /// Register a nested endpoint service under a prefix (path).
    ///
    /// The prefix is used to match the request path and strip it from the request URI.
    /// Endpoint layer is applied to this sub-service.
    ///
    /// Warning: If a sub-service is a plain [`Service`], not an endpoint function,
    /// it has no notion of the state this router has. If you want to create a sub-router
    /// that shares the same state this router has, use [`Router::with_sub_router_make_fn`] instead.
    #[inline]
    pub fn set_endpoint_service<I, T>(&mut self, prefix: impl AsRef<str>, service: I) -> &mut Self
    where
        I: IntoEndpointService<T>,
        L: Layer<I::Service, Service: Service<Request, Output = O, Error = E>>,
    {
        let nested = self.layer.layer(service.into_endpoint_service()).boxed();
        self.set_sub_service_inner(prefix, nested)
    }

    /// Register a nested service under a prefix (path).
    ///
    /// The prefix is used to match the request path and strip it from the request URI.
    ///
    /// Warning: This sub-service has no notion of the state this router has. If you want
    /// to create a sub-router that shares the same state this router has, use [`Router::with_sub_router_make_fn`] instead.
    /// Also, the endpoint layer is not applied to it, so its Output / Error must match those of the Router
    /// If you need its type conversions, consider [`Router::with_endpoint_service`]
    #[must_use]
    #[inline]
    pub fn with_sub_service<S>(mut self, prefix: impl AsRef<str>, service: S) -> Self
    where
        S: Service<Request, Output = O, Error = E>,
    {
        self.set_sub_service(prefix, service);
        self
    }

    /// Register a nested service under a prefix.
    ///
    /// The prefix is used to match the request path and strip it from the request URI.
    ///
    /// Warning: This sub-service has no notion of the state this router has. If you want
    /// to create a sub-router that shares the same state this router has, use [`Router::with_sub_router_make_fn`] instead.
    /// Also, the endpoint layer is not applied to it, so its Output / Error must match those of the Router
    /// If you need its type conversions, consider [`Router::set_endpoint_service`]
    #[inline]
    pub fn set_sub_service<S>(&mut self, prefix: impl AsRef<str>, service: S) -> &mut Self
    where
        S: Service<Request, Output = O, Error = E>,
    {
        let nested = service.into_endpoint_service().boxed();
        self.set_sub_service_inner(prefix, nested)
    }

    fn set_sub_service_inner(
        &mut self,
        prefix: impl AsRef<str>,
        nested: BoxService<Request, O, E>,
    ) -> &mut Self {
        let router = self.sub_services.get_or_insert_default();
        router.insert_prefix_with_opts(
            prefix.as_ref().trim(),
            crate::matcher::path::HTTP_PATH_OPTS,
            SubService { svc: nested },
        );

        self
    }

    /// add a route to the router with it's matcher and service.
    #[inline(always)]
    #[must_use]
    pub fn with_match_route<I, T>(
        mut self,
        path: impl AsRef<str>,
        matcher: HttpMatcher<Body>,
        service: I,
    ) -> Self
    where
        I: IntoEndpointServiceWithState<T, State>,
        L: Layer<I::Service, Service: Service<Request, Output = O, Error = E>>,
    {
        self.set_match_route(path, matcher, service);
        self
    }

    /// add a route to the router with it's matcher and service.
    pub fn set_match_route<I, T>(
        &mut self,
        path: impl AsRef<str>,
        matcher: HttpMatcher<Body>,
        service: I,
    ) -> &mut Self
    where
        I: IntoEndpointServiceWithState<T, State>,
        L: Layer<I::Service, Service: Service<Request, Output = O, Error = E>>,
    {
        let service = self
            .layer
            .layer(service.into_endpoint_service_with_state(self.state.clone()))
            .boxed();

        let pattern = compile_pattern(path.as_ref());

        if let Some(entry) = self.routes.iter_mut().find(|e| e.pattern == pattern) {
            entry.handlers.push((matcher, service));
        } else {
            let specificity = specificity_of(&pattern);
            // keep `routes` most-specific-first; first match wins at lookup
            let pos = self
                .routes
                .partition_point(|e| e.specificity >= specificity);
            self.routes.insert(
                pos,
                RouteEntry {
                    pattern,
                    specificity,
                    handlers: vec![(matcher, service)],
                },
            );
        }

        self
    }

    /// use the provided service when no route matches the request.
    #[inline(always)]
    #[must_use]
    pub fn with_not_found<I, T>(mut self, service: I) -> Self
    where
        I: IntoEndpointServiceWithState<T, State>,
        L: Layer<I::Service, Service: Service<Request, Output = O, Error = E>>,
    {
        self.set_not_found(service);
        self
    }

    /// use the provided service when no route matches the request.
    pub fn set_not_found<I, T>(&mut self, service: I) -> &mut Self
    where
        I: IntoEndpointServiceWithState<T, State>,
        L: Layer<I::Service, Service: Service<Request, Output = O, Error = E>>,
    {
        self.not_found = Some(
            self.layer
                .layer(service.into_endpoint_service_with_state(self.state.clone()))
                .boxed(),
        );
        self
    }
}

impl Default for Router {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub enum RouterError {
    /// This one should never fire, if it does something is wrong in uri prefix stripped
    Internal,
    MethodNotAllowed(Box<NonEmptySmallVec<7, Method>>),
    NotFound,
}

impl fmt::Display for RouterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

impl Error for RouterError {}

impl IntoResponse for RouterError {
    fn into_response(self) -> Response {
        match self {
            Self::Internal => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
            Self::MethodNotAllowed(allowed) => (
                Headers::single(Allow(*allowed)),
                StatusCode::METHOD_NOT_ALLOWED,
            )
                .into_response(),
            Self::NotFound => StatusCode::NOT_FOUND.into_response(),
        }
    }
}

impl From<Infallible> for RouterError {
    fn from(infallible: Infallible) -> Self {
        match infallible {}
    }
}

struct SubService<O, E> {
    svc: BoxService<Request, O, E>,
}

impl<State, L, O, E> Service<Request> for Router<State, L, O, E>
where
    O: Send + 'static,
    E: Send + From<RouterError> + 'static,
    L: Send + Sync + 'static,
    State: Send + Sync + Clone + 'static,
{
    type Output = O;
    type Error = E;

    async fn serve(&self, req: Request) -> Result<Self::Output, Self::Error> {
        let path = req.uri().path_ref_or_root();

        // Collect allowed methods when a path matches but no method matches.
        // Initialised here so it is visible after the route scan and after
        // sub_services, letting sub_services take priority over a 405.
        let mut allowed_methods: Option<MethodMatcher> = None;

        // most-specific-first: the first matching route owns the path
        // (method mismatch -> 405, no fall-through to a vaguer route).
        for entry in self.routes.iter() {
            let ext = Extensions::new();
            if !match_pattern(&entry.pattern, Some(&ext), path) {
                continue;
            }

            // merge with any existing (nested-router) UriParams
            let captured = ext.get_ref::<UriParams>().cloned().unwrap_or_default();
            let params = match req.extensions().get_ref::<UriParams>() {
                Some(existing) => {
                    let mut params = existing.clone();
                    params.extend(captured.iter());
                    params
                }
                None => captured,
            };
            req.extensions().insert(params);

            for (matcher, service) in entry.handlers.iter() {
                let mext = Extensions::new();
                if matcher.matches(Some(&mext), &req) {
                    req.extensions().extend(&mext);
                    return service.serve(req).await;
                }
            }

            // Path matched but no method matched — collect for a potential 405.
            // Do not return yet: a sub_service may still handle this request.
            for (matcher, _) in entry.handlers.iter() {
                if let Some(m) = matcher.allowed_methods() {
                    allowed_methods = Some(allowed_methods.map_or(m, |acc| acc.or_method(m)));
                }
            }
            break;
        }

        let (mut parts, body) = req.into_parts();

        let sub_match = self.sub_services.as_ref().and_then(|router| {
            router
                .match_prefix(parts.uri.path_ref_or_root())
                .map(|matched| {
                    let (sub_svc, matched_segment_count, captures) = matched.into_parts();
                    (
                        sub_svc,
                        matched_segment_count,
                        UriParams::from_captures(&captures),
                    )
                })
        });

        if let Some((sub_svc, matched_segment_count, captured)) = sub_match {
            let mut modified_uri = parts.uri.clone();
            if !modified_uri
                .path_mut()
                .strip_prefix_segments(matched_segment_count)
            {
                tracing::warn!(
                    "failed to strip {matched_segment_count} matched path segments from Uri (bug??)",
                );
                return Err(RouterError::Internal.into());
            }

            if !captured.is_empty() {
                let params = match parts.extensions.get_ref::<UriParams>() {
                    Some(existing) => {
                        let mut params = existing.clone();
                        params.extend(captured.iter());
                        params
                    }
                    None => captured,
                };
                parts.extensions.insert(params);
            }

            if !parts.extensions.contains::<OriginalRouterUri>() {
                parts.extensions.insert(OriginalRouterUri(parts.uri));
            }
            parts.uri = modified_uri;

            tracing::trace!(
                "svc request using sub service of router with {matched_segment_count} matched path segments removed from path; new uri: {}",
                parts.uri,
            );
            let req = Request::from_parts(parts, body);
            return sub_svc.svc.serve(req).await;
        }

        // A route matched the path but no registered method matched, and no sub_service
        // handled the request — return 405 with the Allow header per RFC 7231.
        if let Some(matcher) = allowed_methods
            && let Some(methods) = NonEmptySmallVec::collect(matcher.iter())
        {
            return Err(RouterError::MethodNotAllowed(Box::new(methods)).into());
        }

        if let Some(not_found) = &self.not_found {
            let req = Request::from_parts(parts, body);
            not_found.serve(req).await
        } else {
            Err(RouterError::NotFound.into())
        }
    }
}

#[cfg(test)]
mod tests {
    use rama_core::{extensions::ExtensionsRef, service::service_fn};
    use rama_http_types::{Body, Method, Request, StatusCode, body::util::BodyExt, header};

    use super::*;
    use crate::{
        layer::error_handling::ErrorHandlerLayer, matcher::UriParams, service::web::extract::State,
    };

    fn root_service() -> impl Service<Request, Output = Response, Error = Infallible> {
        service_fn(|_req| async {
            Ok(Response::builder()
                .status(200)
                .body(Body::from("Hello, World!"))
                .unwrap())
        })
    }

    fn create_user_service() -> impl Service<Request, Output = Response, Error = Infallible> {
        service_fn(|_req| async {
            Ok(Response::builder()
                .status(200)
                .body(Body::from("Create User"))
                .unwrap())
        })
    }

    fn get_users_service() -> impl Service<Request, Output = Response, Error = Infallible> {
        service_fn(|_req| async {
            Ok(Response::builder()
                .status(200)
                .body(Body::from("List Users"))
                .unwrap())
        })
    }

    fn get_user_service() -> impl Service<Request, Output = Response, Error = Infallible> {
        service_fn(|req: Request| async move {
            let uri_params = req.extensions().get_ref::<UriParams>().unwrap();
            let id = uri_params.get("user_id").unwrap();
            Ok(Response::builder()
                .status(200)
                .body(Body::from(format!("Get User: {id}")))
                .unwrap())
        })
    }

    fn delete_user_service() -> impl Service<Request, Output = Response, Error = Infallible> {
        service_fn(|req: Request| async move {
            let uri_params = req.extensions().get_ref::<UriParams>().unwrap();
            let id = uri_params.get("user_id").unwrap();
            Ok(Response::builder()
                .status(200)
                .body(Body::from(format!("Delete User: {id}")))
                .unwrap())
        })
    }

    fn serve_assets_service() -> impl Service<Request, Output = Response, Error = Infallible> {
        service_fn(|req: Request| async move {
            let uri_params = req.extensions().get_ref::<UriParams>().unwrap();
            let path = uri_params.get("path").unwrap();
            Ok(Response::builder()
                .status(200)
                .body(Body::from(format!("Serve Assets: /{path}")))
                .unwrap())
        })
    }

    fn not_found_service() -> impl Service<Request, Output = Response, Error = Infallible> {
        service_fn(|_req| async {
            Ok(Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Body::from("Not Found"))
                .unwrap())
        })
    }

    fn get_user_order_service() -> impl Service<Request, Output = Response, Error = Infallible> {
        service_fn(|req: Request| async move {
            let uri_params = req.extensions().get_ref::<UriParams>().unwrap();
            let user_id = uri_params.get("user_id").unwrap();
            let order_id = uri_params.get("order_id").unwrap();
            Ok(Response::builder()
                .status(200)
                .body(Body::from(format!(
                    "Get Order: {order_id} for User: {user_id}",
                )))
                .unwrap())
        })
    }

    // Echoes the request content back, proving the QUERY body (the query) reaches the handler.
    fn query_echo_service() -> impl Service<Request, Output = Response, Error = Infallible> {
        service_fn(|req: Request| async move {
            let body = req.into_body().collect().await.unwrap().to_bytes();
            Ok(Response::builder()
                .status(200)
                .body(Body::from(format!(
                    "query: {}",
                    String::from_utf8_lossy(&body)
                )))
                .unwrap())
        })
    }

    #[tokio::test]
    async fn test_router() {
        let cases = vec![
            (Method::GET, "/", "Hello, World!", StatusCode::OK),
            (Method::GET, "/users", "List Users", StatusCode::OK),
            (Method::POST, "/users", "Create User", StatusCode::OK),
            (Method::GET, "/users/123", "Get User: 123", StatusCode::OK),
            (
                Method::DELETE,
                "/users/123",
                "Delete User: 123",
                StatusCode::OK,
            ),
            (
                Method::GET,
                "/users/123/orders/456",
                "Get Order: 456 for User: 123",
                StatusCode::OK,
            ),
            (
                Method::PUT,
                "/users/123",
                "",
                StatusCode::METHOD_NOT_ALLOWED,
            ),
            (
                Method::GET,
                "/assets/css/style.css",
                "Serve Assets: /css/style.css",
                StatusCode::OK,
            ),
            (
                Method::GET,
                "/not-found",
                "Not Found",
                StatusCode::NOT_FOUND,
            ),
        ];

        for prefix in ["/", ""] {
            let router = Router::new()
                .with_get(prefix, root_service())
                .with_get(format!("{prefix}users"), get_users_service())
                .with_post(format!("{prefix}users"), create_user_service())
                .with_get(format!("{prefix}users/{{user_id}}"), get_user_service())
                .with_delete(format!("{prefix}users/{{user_id}}"), delete_user_service())
                .with_get(
                    format!("{prefix}users/{{user_id}}/orders/{{order_id}}"),
                    get_user_order_service(),
                )
                .with_get(format!("{prefix}assets/{{*path}}"), serve_assets_service())
                .with_not_found(not_found_service());

            let router = ErrorHandlerLayer::new().layer(router);

            for (method, path, expected_body, expected_status) in cases.iter() {
                let req = match *method {
                    Method::GET => Request::get(*path),
                    Method::POST => Request::post(*path),
                    Method::PUT => Request::put(*path),
                    Method::DELETE => Request::delete(*path),
                    _ => panic!("Unsupported HTTP method"),
                }
                .body(Body::empty())
                .unwrap();

                let res = router.serve(req).await.unwrap();
                assert_eq!(
                    res.status(),
                    *expected_status,
                    "method: {method} ; path = {path}; prefix = {prefix}"
                );
                let body = res.into_body().collect().await.unwrap().to_bytes();
                assert_eq!(
                    body, expected_body,
                    "method: {method} ; path = {path}; prefix = {prefix}"
                );
            }
        }
    }

    #[tokio::test]
    async fn test_router_query_method() {
        let router = Router::new()
            .with_query("/search", query_echo_service())
            .with_get("/search", get_users_service())
            .with_not_found(not_found_service());

        let router = ErrorHandlerLayer::new().layer(router);

        // QUERY with a body is routed to the QUERY handler and the body reaches it.
        let req = Request::query("/search")
            .header(header::CONTENT_TYPE, "application/sql")
            .body(Body::from("SELECT 1"))
            .unwrap();
        let res = router.serve(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = res.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body, "query: SELECT 1");

        // GET on the same path is distinct from QUERY and hits the GET handler.
        let req = Request::get("/search").body(Body::empty()).unwrap();
        let res = router.serve(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = res.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body, "List Users");

        // A method registered on neither route → 405 listing GET and QUERY in the Allow header.
        let req = Request::post("/search").body(Body::empty()).unwrap();
        let res = router.serve(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(
            res.headers()
                .get(header::ALLOW)
                .expect("Allow header must be present on 405")
                .to_str()
                .unwrap(),
            "GET, QUERY"
        );
    }

    #[tokio::test]
    async fn test_router_merges_case_insensitive_pattern_registrations() {
        let router = Router::new()
            .with_get("/Users/{user_id}", get_user_service())
            .with_post("/users/{user_id}", create_user_service());

        let router = ErrorHandlerLayer::new().layer(router);

        let req = Request::post("/USERS/123").body(Body::empty()).unwrap();
        let res = router.serve(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = res.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body, "Create User");

        let req = Request::put("/users/123").body(Body::empty()).unwrap();
        let res = router.serve(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(
            res.headers().get(header::ALLOW).unwrap().to_str().unwrap(),
            "GET, POST"
        );
    }

    #[tokio::test]
    async fn test_router_method_not_allowed() {
        let router = Router::new()
            .with_get("/users", get_users_service())
            .with_post("/users", create_user_service())
            .with_get("/users/{user_id}", get_user_service())
            .with_delete("/users/{user_id}", delete_user_service())
            .with_not_found(not_found_service());

        let router = ErrorHandlerLayer::new().layer(router);

        // PUT /users/123 → 405: verify status, Allow header, and empty body in one shot
        let req = Request::put("/users/123").body(Body::empty()).unwrap();
        let res = router.serve(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(
            res.headers()
                .get(header::ALLOW)
                .expect("Allow header must be present on 405")
                .to_str()
                .unwrap(),
            "DELETE, GET"
        );
        let body = res.into_body().collect().await.unwrap().to_bytes();
        assert!(
            body.is_empty(),
            "405 body must be empty, not from not_found service"
        );

        // DELETE /users → 405 with a different Allow set (GET, POST)
        let req = Request::delete("/users").body(Body::empty()).unwrap();
        let res = router.serve(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(
            res.headers().get(header::ALLOW).unwrap().to_str().unwrap(),
            "GET, POST"
        );

        // Unknown path → 404, no Allow header (not_found service body present)
        let req = Request::get("/nonexistent").body(Body::empty()).unwrap();
        let res = router.serve(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
        assert!(
            res.headers().get(header::ALLOW).is_none(),
            "404 must not carry Allow header"
        );
    }

    #[tokio::test]
    async fn test_router_method_not_allowed_no_not_found_service() {
        // Verify 405 fires correctly when no custom not_found service is registered.
        let router = Router::new()
            .with_get("/users/{user_id}", get_user_service())
            .with_delete("/users/{user_id}", delete_user_service());

        let router = ErrorHandlerLayer::new().layer(router);

        let req = Request::put("/users/123").body(Body::empty()).unwrap();
        let res = router.serve(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(
            res.headers().get(header::ALLOW).unwrap().to_str().unwrap(),
            "DELETE, GET"
        );

        // Unknown path without not_found service → plain 404, no Allow header
        let req = Request::get("/nonexistent").body(Body::empty()).unwrap();
        let res = router.serve(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
        assert!(res.headers().get(header::ALLOW).is_none());
    }

    #[test]
    fn specificity_reflects_segment_kinds() {
        let spec = |p: &str| {
            specificity_of(&compile_pattern(p))
                .into_iter()
                .map(|rank| rank.kind)
                .collect::<Vec<_>>()
        };
        assert_eq!(spec("/a/b/c"), vec![2, 2, 2]); // all literal
        assert_eq!(spec("/users/{id}"), vec![2, 1]); // literal + capture
        assert_eq!(spec("/files/{}.json"), vec![2, 1]); // literal + affixed wildcard
        assert_eq!(spec("/assets/{*path}"), vec![2, 0]); // literal + catch-all
        // An invalid catch-all body is a literal in the matcher, so it ranks as
        // a literal here too — the router no longer guesses, so no drift.
        assert_eq!(spec("/api/{*bad name}"), vec![2, 2]);
    }

    #[test]
    fn specificity_breaks_dynamic_ties_with_literal_weight() {
        let plain = specificity_of(&compile_pattern("/files/{name}"));
        let json = specificity_of(&compile_pattern("/files/{name}.json"));
        let wildcard_json = specificity_of(&compile_pattern("/files/{}.json"));

        assert!(json > plain);
        assert!(wildcard_json > plain);
    }

    #[tokio::test]
    async fn test_router_capture_beats_catch_all_either_order() {
        fn name_svc() -> impl Service<Request, Output = Response, Error = Infallible> {
            service_fn(|req: Request| async move {
                let p = req.extensions().get_ref::<UriParams>().unwrap();
                Ok(Response::builder()
                    .status(200)
                    .body(Body::from(format!("name:{}", p.get("name").unwrap())))
                    .unwrap())
            })
        }
        fn rest_svc() -> impl Service<Request, Output = Response, Error = Infallible> {
            service_fn(|req: Request| async move {
                let p = req.extensions().get_ref::<UriParams>().unwrap();
                Ok(Response::builder()
                    .status(200)
                    .body(Body::from(format!("rest:{}", p.get("rest").unwrap())))
                    .unwrap())
            })
        }

        // `{name}` (rank 1) must win over `{*rest}` (rank 0) on a single-segment
        // path, independent of registration order.
        let routers = [
            Router::new()
                .with_get("/files/{name}", name_svc())
                .with_get("/files/{*rest}", rest_svc()),
            Router::new()
                .with_get("/files/{*rest}", rest_svc())
                .with_get("/files/{name}", name_svc()),
        ];
        for router in routers {
            let router = ErrorHandlerLayer::new().layer(router);
            let req = Request::get("/files/x").body(Body::empty()).unwrap();
            let res = router.serve(req).await.unwrap();
            let body = res.into_body().collect().await.unwrap().to_bytes();
            assert_eq!(body, "name:x");
        }

        // A multi-segment path no longer fits `{name}` and falls to the catch-all.
        let router = ErrorHandlerLayer::new().layer(
            Router::new()
                .with_get("/files/{name}", name_svc())
                .with_get("/files/{*rest}", rest_svc()),
        );
        let req = Request::get("/files/a/b").body(Body::empty()).unwrap();
        let res = router.serve(req).await.unwrap();
        let body = res.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body, "rest:a/b");
    }

    #[tokio::test]
    async fn test_router_affixed_dynamic_beats_plain_dynamic_either_order() {
        fn plain_svc() -> impl Service<Request, Output = Response, Error = Infallible> {
            service_fn(|req: Request| async move {
                let p = req.extensions().get_ref::<UriParams>().unwrap();
                Ok(Response::builder()
                    .status(200)
                    .body(Body::from(format!("plain:{}", p.get("name").unwrap())))
                    .unwrap())
            })
        }
        fn json_svc() -> impl Service<Request, Output = Response, Error = Infallible> {
            service_fn(|req: Request| async move {
                let p = req.extensions().get_ref::<UriParams>().unwrap();
                Ok(Response::builder()
                    .status(200)
                    .body(Body::from(format!("json:{}", p.get("name").unwrap())))
                    .unwrap())
            })
        }

        let routers = [
            Router::new()
                .with_get("/files/{name}", plain_svc())
                .with_get("/files/{name}.json", json_svc()),
            Router::new()
                .with_get("/files/{name}.json", json_svc())
                .with_get("/files/{name}", plain_svc()),
        ];
        for router in routers {
            let router = ErrorHandlerLayer::new().layer(router);
            let req = Request::get("/files/readme.json")
                .body(Body::empty())
                .unwrap();
            let res = router.serve(req).await.unwrap();
            let body = res.into_body().collect().await.unwrap().to_bytes();
            assert_eq!(body, "json:readme");
        }
    }

    #[tokio::test]
    async fn test_router_equal_specificity_preserves_registration_order() {
        fn svc(
            label: &'static str,
        ) -> impl Service<Request, Output = Response, Error = Infallible> {
            service_fn(move |_req: Request| async move {
                Ok(Response::builder()
                    .status(200)
                    .body(Body::from(label))
                    .unwrap())
            })
        }

        let router = ErrorHandlerLayer::new().layer(
            Router::new()
                .with_get("/files/{a}", svc("first"))
                .with_get("/files/{b}", svc("second")),
        );
        let req = Request::get("/files/readme").body(Body::empty()).unwrap();
        let res = router.serve(req).await.unwrap();
        let body = res.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body, "first");
    }

    #[tokio::test]
    async fn test_router_anonymous_glob_surfaces_via_uri_params() {
        fn glob_svc() -> impl Service<Request, Output = Response, Error = Infallible> {
            service_fn(|req: Request| async move {
                let p = req.extensions().get_ref::<UriParams>().unwrap();
                // anon `{*}` is the glob, not a named param
                assert!(p.get("rest").is_none());
                Ok(Response::builder()
                    .status(200)
                    .body(Body::from(format!("glob:{}", p.glob().unwrap())))
                    .unwrap())
            })
        }
        let router =
            ErrorHandlerLayer::new().layer(Router::new().with_get("/assets/{*}", glob_svc()));
        let req = Request::get("/assets/css/app.css")
            .body(Body::empty())
            .unwrap();
        let res = router.serve(req).await.unwrap();
        let body = res.into_body().collect().await.unwrap().to_bytes();
        // glob() is path-style (leading `/`), unlike a named catch-all param.
        assert_eq!(body, "glob:/css/app.css");
    }

    #[tokio::test]
    async fn test_router_invalid_catch_all_mount_is_literal() {
        // RAMA-PR1027-001: `{*bad name}` is an invalid catch-all body, so the
        // matcher treats it as a literal segment. The mount must therefore NOT
        // collapse to `/api`; `/api/users` must not reach the nested service.
        let app = Router::new()
            .with_sub_service(
                "/api/{*bad name}",
                Router::new().with_get("/", root_service()),
            )
            .with_not_found(not_found_service());
        let app = ErrorHandlerLayer::new().layer(app);

        let req = Request::get("/api/users").body(Body::empty()).unwrap();
        let res = app.serve(req).await.unwrap();
        assert_eq!(
            res.status(),
            StatusCode::NOT_FOUND,
            "invalid catch-all must not mount the sub-service at /api"
        );
    }

    #[tokio::test]
    async fn test_sub_service_mount_respects_segment_boundaries() {
        for prefix in ["/api", "/api/{id}"] {
            let app = Router::new()
                .with_sub_service(prefix, Router::new().with_get("/", root_service()))
                .with_not_found(not_found_service());
            let app = ErrorHandlerLayer::new().layer(app);

            let req = Request::get("/apix/123").body(Body::empty()).unwrap();
            let res = app.serve(req).await.unwrap();
            assert_eq!(
                res.status(),
                StatusCode::NOT_FOUND,
                "mount prefix {prefix:?} must not match inside a path segment",
            );
        }
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn test_router_nest() {
        let cases = [
            (Method::GET, "/", "Hello, World!", StatusCode::OK),
            (Method::GET, "/api/users", "List Users", StatusCode::OK),
            (Method::POST, "/api/users", "Create User", StatusCode::OK),
            (
                Method::DELETE,
                "/api/users/123",
                "Delete User: 123",
                StatusCode::OK,
            ),
            (
                Method::GET,
                "/api/users/123",
                "Get User: 123",
                StatusCode::OK,
            ),
            (
                Method::GET,
                "/api/users/123/orders/456",
                "Get Order: 456 for User: 123",
                StatusCode::OK,
            ),
            (Method::GET, "/api/state", "state", StatusCode::OK),
            (Method::GET, "/api/users/123/state", "state", StatusCode::OK),
            // to test case insensitive :)
            (Method::GET, "/Api/USERS/123/State", "state", StatusCode::OK),
        ];

        let state = "state".to_owned();

        for prefix in ["/", ""] {
            let api_router = Router::new_with_state(state.clone())
                .with_get(format!("{prefix}users"), get_users_service())
                .with_get(
                    format!("{prefix}state"),
                    async |State(state): State<String>| state,
                )
                .with_post(format!("{prefix}users"), create_user_service())
                .with_delete(format!("{prefix}users/{{user_id}}"), delete_user_service())
                .with_sub_router_make_fn(
                    format!("{prefix}users/{{user_id}}/{{*}}"), // glob should be dropped by nester
                    |router| {
                        router
                            .with_get(prefix, get_user_service())
                            .with_get(
                                format!("{prefix}orders/{{order_id}}"),
                                get_user_order_service(),
                            )
                            .with_get(
                                format!("{prefix}/state"),
                                async |State(state): State<String>| state,
                            )
                    },
                );

            let app = Router::new()
                .with_sub_service(format!("{prefix}api"), api_router)
                .with_get(prefix, root_service());

            let app = ErrorHandlerLayer::new().layer(app);

            for (method, path, expected_body, expected_status) in cases.iter() {
                let req = match *method {
                    Method::GET => Request::get(*path),
                    Method::POST => Request::post(*path),
                    Method::DELETE => Request::delete(*path),
                    _ => panic!("Unsupported HTTP method"),
                }
                .body(Body::empty())
                .unwrap();

                let res = app.serve(req).await.unwrap();
                assert_eq!(
                    res.status(),
                    *expected_status,
                    "method: {method} ; path = {path}; prefix = {prefix}"
                );
                let body = res.into_body().collect().await.unwrap().to_bytes();
                assert_eq!(
                    body, expected_body,
                    "method: {method} ; path = {path}; prefix = {prefix}"
                );
            }

            // PUT /api/users/123 → the outer router has no direct route for this path,
            // but the api_router has DELETE /users/{user_id} registered directly.
            // However the sub-router for users/{user_id}/* takes priority (deferred 405),
            // and that sub-router has GET / — so the final 405 reflects Allow: GET.
            let req = Request::put("/api/users/123").body(Body::empty()).unwrap();
            let res = app.serve(req).await.unwrap();
            assert_eq!(
                res.status(),
                StatusCode::METHOD_NOT_ALLOWED,
                "nested router: PUT /api/users/123 must be 405; prefix = {prefix}"
            );
            assert_eq!(
                res.headers().get(header::ALLOW).unwrap().to_str().unwrap(),
                "GET",
                "nested router: Allow header reflects sub-router's registered methods; prefix = {prefix}"
            );
        }
    }
}
