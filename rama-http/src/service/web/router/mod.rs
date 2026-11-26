#![expect(
    clippy::allow_attributes,
    reason = "macro-generated `#[allow]` attributes whose underlying lints fire only for some expansions"
)]

use std::{
    any::Any,
    convert::Infallible,
    error::Error,
    fmt,
    path::Path,
    sync::{Arc, Weak},
};

use parking_lot::Mutex;

use rama_core::{
    Layer,
    extensions::{Extension, Extensions, ExtensionsRef},
    layer::MapResult,
    matcher::Matcher,
    service::{BoxService, Service},
    telemetry::tracing,
};
use rama_http_types::Method;
use rama_http_types::{Body, OriginalRouterUri, StatusCode};
use rama_net::uri::PathRouter;
use rama_utils::{
    collections::{NonEmptySmallVec, smallvec::SmallVec},
    include_dir,
};

use crate::{
    Request, Response,
    headers::Allow,
    matcher::path::compile_pattern_with_policy,
    matcher::{HttpMatcher, MethodMatcher, PathMatchPolicy, UriParams},
    mime::Mime,
    service::fs::{DirectoryServeMode, ServeDir},
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
/// Each route compiles to a [`PathPattern`](rama_net::uri::PathPattern); on lookup the most-specific
/// matching pattern wins (static segments beat captures beat catch-alls).
/// Routes use [`PathPattern`](rama_net::uri::PathPattern) syntax, not RFC 6570 URI Templates; see the
/// [`uri` module](rama_net::uri#patterns-and-templates).
/// Nested services are mounted under a prefix via a typed [`PathRouter`].
/// Path matching uses [`PathMatchPolicy::default`] unless an explicit policy
/// is selected at construction with [`Router::new_with_path_match_policy`] or
/// [`Router::new_with_state_and_path_match_policy`].
/// Routers created by [`Router::with_sub_router_make_fn`] inherit that policy.
/// A separately constructed router passed to [`Router::with_sub_service`]
/// retains its own policy; the parent policy still governs its mount prefix.
///
/// ```
/// use rama_http::service::web::{PathMatchPolicy, Router};
///
/// let default_router: Router = Router::new();
/// assert_eq!(default_router.path_match_policy(), PathMatchPolicy::default());
///
/// let strict_router: Router =
///     Router::new_with_path_match_policy(PathMatchPolicy::STRICT);
/// assert_eq!(strict_router.path_match_policy(), PathMatchPolicy::STRICT);
/// ```
#[allow(unused)]
pub struct Router<State = (), Layer = DefaultEndpointLayer, O = Response, E = RouterError> {
    routes: PathRouter<RouteEntry<O, E>>,
    sub_services: Option<PathRouter<SubService<O, E>>>,
    /// Matchers without a route path, tried in registration order.
    matchers: Vec<(HttpMatcher<Body>, BoxService<Request, O, E>)>,
    path_match_policy: PathMatchPolicy,
    not_found: Option<BoxService<Request, O, E>>,
    layer: Layer,
    state: State,
}

/// The per-method handlers sharing one registered route path.
struct RouteEntry<O, E> {
    handlers: Vec<(HttpMatcher<Body>, BoxService<Request, O, E>)>,
    fallback_handlers: Vec<(HttpMatcher<Body>, BoxService<Request, O, E>)>,
}

impl<O, E> Default for RouteEntry<O, E> {
    fn default() -> Self {
        Self {
            handlers: Vec::new(),
            fallback_handlers: Vec::new(),
        }
    }
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
        Self::new_with_path_match_policy(PathMatchPolicy::default())
    }

    /// Create a new router with an explicit path-matching policy.
    ///
    /// The policy applies consistently to ordinary routes, fallback routes,
    /// captures, wildcards, and mounted prefixes.
    #[must_use]
    pub fn new_with_path_match_policy(path_match_policy: PathMatchPolicy) -> Self {
        Self::new_with_state_and_path_match_policy((), path_match_policy)
    }
}

impl<State, O, E> Router<State, DefaultEndpointLayer, O, E>
where
    State: Send + Sync + Clone + 'static,
{
    #[must_use]
    /// Create a new router with state
    pub fn new_with_state(state: State) -> Self {
        Self::new_with_state_and_path_match_policy(state, PathMatchPolicy::default())
    }

    /// Create a new router with state and an explicit path-matching policy.
    ///
    /// The policy applies consistently to ordinary routes, fallback routes,
    /// captures, wildcards, and mounted prefixes.
    #[must_use]
    pub fn new_with_state_and_path_match_policy(
        state: State,
        path_match_policy: PathMatchPolicy,
    ) -> Self {
        Self {
            routes: PathRouter::new(),
            sub_services: None,
            matchers: Vec::new(),
            path_match_policy,
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

    /// Return the immutable path-matching policy selected at construction.
    #[inline]
    #[must_use]
    pub const fn path_match_policy(&self) -> PathMatchPolicy {
        self.path_match_policy
    }

    /// Apply `layer` to every endpoint registered after this call.
    ///
    /// Routes registered before this call keep whatever layer was in effect at the time of registration.
    pub fn with_endpoint_layer<N>(self, layer: N) -> Router<State, N, O, E> {
        Router {
            routes: self.routes,
            sub_services: self.sub_services,
            matchers: self.matchers,
            path_match_policy: self.path_match_policy,
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
            matchers: self.matchers,
            path_match_policy: self.path_match_policy,
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
            routes: PathRouter::new(),
            sub_services: None,
            matchers: Vec::new(),
            path_match_policy: self.path_match_policy,
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
    ///
    /// A separately constructed [`Router`] used as the service retains its own
    /// path policy. This router's policy applies only to the mount prefix.
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
        // `/assets`, `/assets/` and `/assets/?` name the same mount.
        let prefix = prefix.as_ref().trim();
        let prefix = prefix.strip_suffix("/?").unwrap_or(prefix);
        let prefix = prefix.trim_end_matches('/');
        let opts = self.path_match_policy.options();
        // A prefix mounted before keeps its services; this one answers after them.
        let mut mount = router
            .insert_prefix_with_opts(prefix, opts, SubService::default())
            .unwrap_or_default();
        mount.services.push(nested);
        router.insert_prefix_with_opts(prefix, opts, mount);

        self
    }

    /// Add a route to the router with its matcher and service.
    ///
    /// The route path uses the router's policy. Any path patterns inside
    /// `matcher` retain the policy explicitly selected for that matcher.
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

    /// Add a route to the router with its matcher and service.
    ///
    /// The route path uses the router's policy. Any path patterns inside
    /// `matcher` retain the policy explicitly selected for that matcher.
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

        let pattern = compile_pattern_with_policy(path.as_ref(), self.path_match_policy);

        self.routes
            .get_or_insert_full_with(pattern, RouteEntry::default)
            .handlers
            .push((matcher, service));

        self
    }

    /// Add a route fallback evaluated after ordinary handlers and mounted
    /// sub-services for the same request path.
    ///
    /// This is useful for protocol-specific error responses that must not
    /// shadow another handler sharing the path. A matching fallback runs only
    /// when no ordinary handler or mounted sub-service accepted the request,
    /// and before the router produces its generic 405 or 404 response.
    /// The fallback path uses the router's policy; path patterns inside
    /// `matcher` retain their own explicitly selected policy.
    #[inline(always)]
    #[must_use]
    pub fn with_fallback_match_route<I, T>(
        mut self,
        path: impl AsRef<str>,
        matcher: HttpMatcher<Body>,
        service: I,
    ) -> Self
    where
        I: IntoEndpointServiceWithState<T, State>,
        L: Layer<I::Service, Service: Service<Request, Output = O, Error = E>>,
    {
        self.set_fallback_match_route(path, matcher, service);
        self
    }

    /// Add a route fallback evaluated after ordinary handlers and mounted
    /// sub-services for the same request path.
    ///
    /// The fallback path uses the router's policy; path patterns inside
    /// `matcher` retain their own explicitly selected policy.
    pub fn set_fallback_match_route<I, T>(
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
        let pattern = compile_pattern_with_policy(path.as_ref(), self.path_match_policy);

        self.routes
            .get_or_insert_full_with(pattern, RouteEntry::default)
            .fallback_handlers
            .push((matcher, service));

        self
    }

    /// Add a route for every request `matcher` accepts.
    ///
    /// A matcher that requires exactly one path becomes a route on that path and
    /// ranks like any other route. A matcher without one is tried in registration
    /// order once no route or mount answered, before the not-found service.
    #[inline(always)]
    #[must_use]
    pub fn with_matcher<I, T>(mut self, matcher: HttpMatcher<Body>, service: I) -> Self
    where
        I: IntoEndpointServiceWithState<T, State>,
        L: Layer<I::Service, Service: Service<Request, Output = O, Error = E>>,
    {
        self.set_matcher(matcher, service);
        self
    }

    /// Add a route for every request `matcher` accepts.
    ///
    /// A matcher that requires exactly one path becomes a route on that path and
    /// ranks like any other route. A matcher without one is tried in registration
    /// order once no route or mount answered, before the not-found service.
    pub fn set_matcher<I, T>(&mut self, matcher: HttpMatcher<Body>, service: I) -> &mut Self
    where
        I: IntoEndpointServiceWithState<T, State>,
        L: Layer<I::Service, Service: Service<Request, Output = O, Error = E>>,
    {
        let service = self
            .layer
            .layer(service.into_endpoint_service_with_state(self.state.clone()))
            .boxed();
        match matcher.into_path_and_rest() {
            Ok((pattern, rest)) => self
                .routes
                .get_or_insert_full_with(pattern, RouteEntry::default)
                .handlers
                .push((rest, service)),
            Err(matcher) => self.matchers.push((matcher, service)),
        }
        self
    }

    /// Serve the file at `path` under `prefix`.
    ///
    /// A request the file does not answer continues with the rest of this router.
    #[inline(always)]
    #[must_use]
    pub fn with_file(mut self, prefix: impl AsRef<str>, path: impl AsRef<Path>, mime: Mime) -> Self
    where
        L: Layer<FileMount, Service: Service<Request, Output = O, Error = E>>,
    {
        self.set_file(prefix, path, mime);
        self
    }

    /// Serve the file at `path` under `prefix`.
    ///
    /// A request the file does not answer continues with the rest of this router.
    pub fn set_file(
        &mut self,
        prefix: impl AsRef<str>,
        path: impl AsRef<Path>,
        mime: Mime,
    ) -> &mut Self
    where
        L: Layer<FileMount, Service: Service<Request, Output = O, Error = E>>,
    {
        self.set_file_mount(prefix, ServeDir::new_single_file(path, mime))
    }

    /// Serve the directory at `path` under `prefix`.
    ///
    /// A request for a file it does not hold continues with the rest of this router.
    #[inline(always)]
    #[must_use]
    pub fn with_dir(self, prefix: impl AsRef<str>, path: impl AsRef<Path>) -> Self
    where
        L: Layer<FileMount, Service: Service<Request, Output = O, Error = E>>,
    {
        self.with_dir_with_serve_mode(prefix, path, DirectoryServeMode::default())
    }

    /// Serve the directory at `path` under `prefix`.
    ///
    /// A request for a file it does not hold continues with the rest of this router.
    #[inline(always)]
    pub fn set_dir(&mut self, prefix: impl AsRef<str>, path: impl AsRef<Path>) -> &mut Self
    where
        L: Layer<FileMount, Service: Service<Request, Output = O, Error = E>>,
    {
        self.set_dir_with_serve_mode(prefix, path, DirectoryServeMode::default())
    }

    /// Serve the directory at `path` under `prefix`, with a custom serve mode.
    ///
    /// A request for a file it does not hold continues with the rest of this router.
    #[inline(always)]
    #[must_use]
    pub fn with_dir_with_serve_mode(
        mut self,
        prefix: impl AsRef<str>,
        path: impl AsRef<Path>,
        mode: DirectoryServeMode,
    ) -> Self
    where
        L: Layer<FileMount, Service: Service<Request, Output = O, Error = E>>,
    {
        self.set_dir_with_serve_mode(prefix, path, mode);
        self
    }

    /// Serve the directory at `path` under `prefix`, with a custom serve mode.
    ///
    /// A request for a file it does not hold continues with the rest of this router.
    pub fn set_dir_with_serve_mode(
        &mut self,
        prefix: impl AsRef<str>,
        path: impl AsRef<Path>,
        mode: DirectoryServeMode,
    ) -> &mut Self
    where
        L: Layer<FileMount, Service: Service<Request, Output = O, Error = E>>,
    {
        self.set_file_mount(prefix, ServeDir::new(path).with_directory_serve_mode(mode))
    }

    /// Serve the embedded directory `dir` under `prefix`.
    ///
    /// A request for a file it does not hold continues with the rest of this router.
    #[inline(always)]
    #[must_use]
    pub fn with_dir_embed(self, prefix: impl AsRef<str>, dir: include_dir::Dir<'static>) -> Self
    where
        L: Layer<FileMount, Service: Service<Request, Output = O, Error = E>>,
    {
        self.with_dir_embed_with_serve_mode(prefix, dir, DirectoryServeMode::default())
    }

    /// Serve the embedded directory `dir` under `prefix`.
    ///
    /// A request for a file it does not hold continues with the rest of this router.
    #[inline(always)]
    pub fn set_dir_embed(
        &mut self,
        prefix: impl AsRef<str>,
        dir: include_dir::Dir<'static>,
    ) -> &mut Self
    where
        L: Layer<FileMount, Service: Service<Request, Output = O, Error = E>>,
    {
        self.set_dir_embed_with_serve_mode(prefix, dir, DirectoryServeMode::default())
    }

    /// Serve the embedded directory `dir` under `prefix`, with a custom serve mode.
    ///
    /// A request for a file it does not hold continues with the rest of this router.
    #[inline(always)]
    #[must_use]
    pub fn with_dir_embed_with_serve_mode(
        mut self,
        prefix: impl AsRef<str>,
        dir: include_dir::Dir<'static>,
        mode: DirectoryServeMode,
    ) -> Self
    where
        L: Layer<FileMount, Service: Service<Request, Output = O, Error = E>>,
    {
        self.set_dir_embed_with_serve_mode(prefix, dir, mode);
        self
    }

    /// Serve the embedded directory `dir` under `prefix`, with a custom serve mode.
    ///
    /// A request for a file it does not hold continues with the rest of this router.
    pub fn set_dir_embed_with_serve_mode(
        &mut self,
        prefix: impl AsRef<str>,
        dir: include_dir::Dir<'static>,
        mode: DirectoryServeMode,
    ) -> &mut Self
    where
        L: Layer<FileMount, Service: Service<Request, Output = O, Error = E>>,
    {
        self.set_file_mount(
            prefix,
            ServeDir::new_embedded(dir).with_directory_serve_mode(mode),
        )
    }

    fn set_file_mount<F>(&mut self, prefix: impl AsRef<str>, files: ServeDir<F>) -> &mut Self
    where
        L: Layer<FileMount, Service: Service<Request, Output = O, Error = E>>,
    {
        let files = files
            .fallback(HandBackToRouter)
            .with_call_fallback_on_method_not_allowed(true);
        let nested = self.layer.layer(files).boxed();
        self.set_sub_service_inner(prefix, nested)
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
            Self::NotFound => {
                let response = StatusCode::NOT_FOUND.into_response();
                response.extensions().insert(RouterMiss);
                response
            }
        }
    }
}

/// Marks the response a router's miss was turned into, so the router that mounted
/// it still continues with a request handed back to it.
#[derive(Debug, Clone, Extension)]
#[extension(tags(http))]
struct RouterMiss;

/// Whether a mount's result is a router's miss, as an error or turned into a response.
fn is_router_miss<O: 'static, E>(result: &Result<O, E>) -> bool {
    match result {
        Err(_) => true,
        Ok(output) => (output as &dyn Any)
            .downcast_ref::<Response>()
            .is_some_and(|response| {
                response.status() == StatusCode::NOT_FOUND
                    && response.extensions().contains::<RouterMiss>()
            }),
    }
}

impl From<Infallible> for RouterError {
    fn from(infallible: Infallible) -> Self {
        match infallible {}
    }
}

/// The services mounted on one prefix, in registration order.
struct SubService<O, E> {
    services: Vec<BoxService<Request, O, E>>,
}

impl<O, E> Default for SubService<O, E> {
    fn default() -> Self {
        Self {
            services: Vec::new(),
        }
    }
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

        // What the matched path takes, for a 405 once nothing else answered.
        let mut path_methods = PathMethods::default();
        let mut fallback_handlers = None;

        // The most specific matching route owns the path
        // (method mismatch -> 405, no fall-through to a vaguer route).
        let matched = self.routes.match_full(path).map(|matched| {
            let (entry, _, captures) = matched.into_parts();
            (entry, UriParams::from_captures(&captures))
        });
        if let Some((entry, captured)) = matched {
            // merge with any existing (nested-router) UriParams
            let params = match req.extensions().get_ref::<UriParams>() {
                Some(existing) => {
                    let mut params = existing.clone();
                    params.extend(captured.iter());
                    params
                }
                None => captured,
            };
            req.extensions().insert(params);

            // one scratch store serves every matcher that leaves it empty
            let mut mext = Extensions::new();
            for (matcher, service) in entry.handlers.iter() {
                if matcher.matches(Some(&mext), &req) {
                    req.extensions().extend(&mext);
                    return service.serve(req).await;
                }
                if mext.self_iter_all().next().is_some() {
                    mext = Extensions::new();
                }
            }

            // No handler took the request: mounts and matchers get their turn first.
            for (matcher, _) in entry.handlers.iter().chain(&entry.fallback_handlers) {
                path_methods.add(matcher, req.method());
            }
            fallback_handlers = Some(&entry.fallback_handlers);
        }

        let mut req = req;
        if let Some(mounts) = self.sub_services.as_ref() {
            // Mounts answer by longest prefix. One that hands the request back gives
            // the next shorter prefix its turn.
            let mut max_segments = usize::MAX;
            let mut tried: SmallVec<[&SubService<O, E>; 4]> = SmallVec::new();
            'mounts: loop {
                let matched = mounts
                    .match_prefix_within(req.uri().path_ref_or_root(), max_segments)
                    .map(|matched| {
                        let (mount, segments, captures) = matched.into_parts();
                        (mount, segments, UriParams::from_captures(&captures))
                    });
                let Some((mount, segments, captured)) = matched else {
                    break;
                };
                // A prefix with an optional segment matches at more than one length.
                if tried.iter().any(|tried| std::ptr::eq(*tried, mount)) {
                    let Some(shorter) = segments.checked_sub(1) else {
                        break;
                    };
                    max_segments = shorter;
                    continue;
                }
                tried.push(mount);

                // Services sharing a prefix answer in registration order.
                for service in &mount.services {
                    let (mut parts, body) = req.into_parts();
                    let mut modified_uri = parts.uri.clone();
                    if !modified_uri.path_mut().strip_leading_segments(segments) {
                        tracing::warn!(
                            "failed to strip {segments} matched path segments from Uri (bug??)",
                        );
                        return Err(RouterError::Internal.into());
                    }

                    // The mount works on a fork, so a request it hands back is as it arrived.
                    let extensions = parts.extensions.fork();
                    if !captured.is_empty() {
                        let params = match extensions.get_ref::<UriParams>() {
                            Some(existing) => {
                                let mut params = existing.clone();
                                params.extend(captured.iter());
                                params
                            }
                            None => captured.clone(),
                        };
                        extensions.insert(params);
                    }
                    if !extensions.contains::<OriginalRouterUri>() {
                        extensions.insert(OriginalRouterUri(parts.uri.clone()));
                    }
                    // Owned here, so a cancelled request does not keep the slot alive.
                    let slot = Arc::new(Mutex::new(None));
                    extensions.insert(RouterHandBack(Arc::downgrade(&slot)));
                    let original_uri = std::mem::replace(&mut parts.uri, modified_uri);
                    let original_extensions = std::mem::replace(&mut parts.extensions, extensions);

                    tracing::trace!(
                        "svc request using sub service of router with {segments} matched path segments removed from path; new uri: {}",
                        parts.uri,
                    );
                    let result = service.serve(Request::from_parts(parts, body)).await;
                    let handed = slot.lock().take();
                    // An answer from a service that looked elsewhere first stands.
                    let Some(handed) =
                        handed.filter(|handed| handed.by_files || is_router_miss(&result))
                    else {
                        return result;
                    };

                    path_methods.merge(handed.path_methods);
                    let (mut parts, body) = handed.request.into_parts();
                    parts.uri = original_uri;
                    parts.extensions = original_extensions;
                    req = Request::from_parts(parts, body);
                }

                let Some(shorter) = segments.checked_sub(1) else {
                    break 'mounts;
                };
                max_segments = shorter;
            }
        }

        if !self.matchers.is_empty() {
            // one scratch store serves every matcher that leaves it empty
            let mut mext = Extensions::new();
            for (matcher, service) in &self.matchers {
                if matcher.matches(Some(&mext), &req) {
                    req.extensions().extend(&mext);
                    return service.serve(req).await;
                }
                if mext.self_iter_all().next().is_some() {
                    mext = Extensions::new();
                }
            }
        }

        if let Some(handlers) = fallback_handlers.filter(|handlers| !handlers.is_empty()) {
            let mut mext = Extensions::new();
            for (matcher, service) in handlers {
                if matcher.matches(Some(&mext), &req) {
                    req.extensions().extend(&mext);
                    return service.serve(req).await;
                }
                if mext.self_iter_all().next().is_some() {
                    mext = Extensions::new();
                }
            }
        }

        // Mounted in another router, this one hands back what it has no answer for.
        if self.not_found.is_none() {
            req = match RouterHandBack::hand_back(req, path_methods, false) {
                Ok(()) => return Err(RouterError::NotFound.into()),
                Err(req) => req,
            };
        }

        if let Some(methods) = path_methods.refused() {
            return Err(RouterError::MethodNotAllowed(Box::new(methods)).into());
        }

        if let Some(not_found) = &self.not_found {
            not_found.serve(req).await
        } else {
            Err(RouterError::NotFound.into())
        }
    }
}

/// The methods the handlers of a matched path take.
#[derive(Debug, Clone, Copy, Default)]
struct PathMethods {
    listed: Option<MethodMatcher>,
    /// A handler that takes the request's method refused it for another reason.
    taken: bool,
}

impl PathMethods {
    fn add(&mut self, matcher: &HttpMatcher<Body>, method: &Method) {
        self.taken |= matcher.method_verdict(method) != Some(false);
        // The list only serves a 405, which a taken method rules out.
        if !self.taken {
            self.list(Some(matcher.methods_not_ruled_out()));
        }
    }

    fn list(&mut self, methods: Option<MethodMatcher>) {
        if let Some(methods) = methods {
            self.listed = Some(self.listed.map_or(methods, |all| all.or_method(methods)));
        }
    }

    fn merge(&mut self, other: Self) {
        self.list(other.listed);
        self.taken |= other.taken;
    }

    /// The methods to name in a 405: none when the path takes the request's method,
    /// which another matcher then refused.
    fn refused(self) -> Option<NonEmptySmallVec<7, Method>> {
        if self.taken {
            return None;
        }
        NonEmptySmallVec::collect(self.listed?.iter())
    }
}

/// Where a nested router or a file mount without an answer returns the request to
/// the router that mounted it.
#[derive(Clone, Extension)]
#[extension(tags(http))]
struct RouterHandBack(Weak<Mutex<Option<HandedBack>>>);

struct HandedBack {
    request: Request,
    path_methods: PathMethods,
    /// Set by a file mount, whose placeholder answer is not an error.
    by_files: bool,
}

impl fmt::Debug for RouterHandBack {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RouterHandBack").finish_non_exhaustive()
    }
}

impl RouterHandBack {
    /// Return `request` to the router that mounted the caller, if one is waiting for it.
    fn hand_back(
        request: Request,
        path_methods: PathMethods,
        by_files: bool,
    ) -> Result<(), Request> {
        let slot = request
            .extensions()
            .get_ref::<Self>()
            .and_then(|hand_back| hand_back.0.upgrade());
        let Some(slot) = slot else {
            return Err(request);
        };
        *slot.lock() = Some(HandedBack {
            request,
            path_methods,
            by_files,
        });
        Ok(())
    }
}

/// The fallback of a file mount: the router that mounted it continues with the request.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct HandBackToRouter;

impl Service<Request> for HandBackToRouter {
    type Output = Response;
    type Error = Infallible;

    async fn serve(&self, req: Request) -> Result<Self::Output, Self::Error> {
        // Outside a router there is nothing to continue with.
        _ = RouterHandBack::hand_back(req, PathMethods::default(), true);
        Ok(StatusCode::NOT_FOUND.into_response())
    }
}

/// The service behind [`Router::with_dir`], [`Router::with_file`] and their variants.
pub type FileMount = ServeDir<HandBackToRouter>;

#[cfg(test)]
mod tests;
