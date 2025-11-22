use matchit::Router as MatchitRouter;
use radix_trie::Trie;
use std::{convert::Infallible, path::Path, sync::Arc};

use crate::{
    Request, Response,
    matcher::{HttpMatcher, UriParams},
    service::{
        fs::{DirectoryServeMode, ServeDir},
        web::{IntoEndpointService, IntoEndpointServiceWithState, response::IntoResponse},
    },
};

use rama_core::{
    extensions::{Extensions, ExtensionsMut, ExtensionsRef},
    matcher::Matcher,
    service::{BoxService, Service},
    telemetry::tracing,
};
use rama_http_types::{Body, StatusCode, mime::Mime};
use rama_utils::include_dir;

/// A basic router that can be used to route requests to different services based on the request path.
///
/// This router uses `matchit::Router` to efficiently match incoming requests
/// to predefined routes. Each route is associated with an `HttpMatcher`
/// and a corresponding service handler.
#[allow(unused)]
pub struct Router<State = ()> {
    routes: MatchitRouter<Vec<(HttpMatcher<Body>, BoxService<Request, Response, Infallible>)>>,
    sub_routers: Option<Trie<Arc<str>, Router<State>>>,
    not_found: Option<BoxService<Request, Response, Infallible>>,
    state: State,
}

impl std::fmt::Debug for Router {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Router").finish()
    }
}

impl Router {
    /// create a new router.
    #[must_use]
    pub fn new() -> Self {
        Self {
            routes: MatchitRouter::new(),
            sub_routers: None,
            not_found: None,
            state: (),
        }
    }
}

impl<State> Router<State>
where
    State: Send + Sync + Clone + 'static,
{
    #[must_use]
    /// Create a new router with state
    pub fn new_with_state(state: State) -> Self {
        Self {
            routes: MatchitRouter::new(),
            sub_routers: None,
            not_found: None,
            state,
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
    {
        let matcher = HttpMatcher::method_get();
        self.match_route(path, matcher, service)
    }

    /// add a GET route to the router.
    /// the path can contain parameters, e.g. `/users/{id}`.
    /// the path can also contain a catch call, e.g. `/assets/{*path}`.
    #[inline]
    pub fn set_get<I, T>(&mut self, path: impl AsRef<str>, service: I) -> &mut Self
    where
        I: IntoEndpointServiceWithState<T, State>,
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
    {
        let matcher = HttpMatcher::method_post();
        self.match_route(path, matcher, service)
    }

    /// add a POST route to the router.
    #[inline]
    pub fn set_post<I, T>(&mut self, path: impl AsRef<str>, service: I) -> &mut Self
    where
        I: IntoEndpointServiceWithState<T, State>,
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
    {
        let matcher = HttpMatcher::method_put();
        self.match_route(path, matcher, service)
    }

    /// add a PUT route to the router.
    #[inline]
    pub fn set_put<I, T>(&mut self, path: impl AsRef<str>, service: I) -> &mut Self
    where
        I: IntoEndpointServiceWithState<T, State>,
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
    {
        let matcher = HttpMatcher::method_delete();
        self.match_route(path, matcher, service)
    }

    /// add a DELETE route to the router.
    #[inline]
    pub fn set_delete<I, T>(&mut self, path: impl AsRef<str>, service: I) -> &mut Self
    where
        I: IntoEndpointServiceWithState<T, State>,
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
    {
        let matcher = HttpMatcher::method_patch();
        self.match_route(path, matcher, service)
    }

    /// add a PATCH route to the router.
    #[inline]
    pub fn set_patch<I, T>(&mut self, path: impl AsRef<str>, service: I) -> &mut Self
    where
        I: IntoEndpointServiceWithState<T, State>,
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
    {
        let matcher = HttpMatcher::method_head();
        self.match_route(path, matcher, service)
    }

    /// add a HEAD route to the router.
    #[inline]
    pub fn set_head<I, T>(&mut self, path: impl AsRef<str>, service: I) -> &mut Self
    where
        I: IntoEndpointServiceWithState<T, State>,
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
    {
        let matcher = HttpMatcher::method_options();
        self.match_route(path, matcher, service)
    }

    /// add a OPTIONS route to the router.
    #[inline]
    pub fn set_options<I, T>(&mut self, path: impl AsRef<str>, service: I) -> &mut Self
    where
        I: IntoEndpointServiceWithState<T, State>,
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
    {
        let matcher = HttpMatcher::method_trace();
        self.match_route(path, matcher, service)
    }

    /// add a TRACE route to the router.
    #[inline]
    pub fn set_trace<I, T>(&mut self, path: impl AsRef<str>, service: I) -> &mut Self
    where
        I: IntoEndpointServiceWithState<T, State>,
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
    {
        let matcher = HttpMatcher::method_connect();
        self.match_route(path, matcher, service)
    }

    /// add a CONNECT route to the router.
    #[inline]
    pub fn set_connect<I, T>(&mut self, path: impl AsRef<str>, service: I) -> &mut Self
    where
        I: IntoEndpointServiceWithState<T, State>,
    {
        let matcher = HttpMatcher::method_connect();
        self.set_match_route(path, matcher, service)
    }

    /// serve the given file under the given path.
    #[must_use]
    #[inline]
    pub fn with_file(self, path: &str, file: impl AsRef<Path>, mime: Mime) -> Self {
        let service = ServeDir::new_single_file(file, mime);
        match self.not_found.clone() {
            Some(not_found) => self.with_sub_service(path, service.fallback(not_found)),
            None => self.with_sub_service(path, service),
        }
    }

    /// serve the given file under the given prefix (path).
    #[inline]
    pub fn set_file(
        &mut self,
        prefix: impl AsRef<str>,
        file: impl AsRef<Path>,
        mime: Mime,
    ) -> &mut Self {
        let service = ServeDir::new_single_file(file, mime);
        match self.not_found.clone() {
            Some(not_found) => self.set_sub_service(prefix, service.fallback(not_found)),
            None => self.set_sub_service(prefix, service),
        }
    }

    /// serve the given directory under the given prefix (path).
    #[inline]
    #[must_use]
    pub fn with_dir(self, prefix: impl AsRef<str>, dir: impl AsRef<Path>) -> Self {
        self.with_dir_and_serve_mode(prefix, dir, Default::default())
    }

    /// serve the given directory under the given prefix (path).
    #[inline]
    pub fn set_dir(&mut self, prefix: impl AsRef<str>, dir: impl AsRef<Path>) -> &mut Self {
        self.set_dir_with_serve_mode(prefix, dir, Default::default())
    }

    /// serve the given directory under the given prefix (path),
    /// with a custom serve move.
    #[must_use]
    #[inline]
    pub fn with_dir_and_serve_mode(
        self,
        prefix: impl AsRef<str>,
        dir: impl AsRef<Path>,
        mode: DirectoryServeMode,
    ) -> Self {
        let service = ServeDir::new(dir).with_directory_serve_mode(mode);
        match self.not_found.clone() {
            Some(not_found) => self.with_sub_service(prefix, service.fallback(not_found)),
            None => self.with_sub_service(prefix, service),
        }
    }

    /// serve the given directory under the given prefix (path),
    /// with a custom serve move.
    #[inline]
    pub fn set_dir_with_serve_mode(
        &mut self,
        prefix: impl AsRef<str>,
        dir: impl AsRef<Path>,
        mode: DirectoryServeMode,
    ) -> &mut Self {
        let service = ServeDir::new(dir).with_directory_serve_mode(mode);
        match self.not_found.clone() {
            Some(not_found) => self.set_sub_service(prefix, service.fallback(not_found)),
            None => self.set_sub_service(prefix, service),
        }
    }

    /// serve the given embedded directory under the given prefix (path).
    #[inline]
    #[must_use]
    pub fn with_dir_embed(self, prefix: impl AsRef<str>, dir: include_dir::Dir<'static>) -> Self {
        self.with_dir_embed_and_serve_mode(prefix, dir, Default::default())
    }

    /// serve the given embedded directory under the given prefix (path).
    #[inline]
    pub fn set_dir_embed(
        &mut self,
        prefix: impl AsRef<str>,
        dir: include_dir::Dir<'static>,
    ) -> &mut Self {
        self.set_dir_embed_with_serve_mode(prefix, dir, Default::default())
    }

    /// serve the given embedded directory under the given prefix (path)
    /// with a custom serve move.
    #[must_use]
    #[inline]
    pub fn with_dir_embed_and_serve_mode(
        mut self,
        prefix: impl AsRef<str>,
        dir: include_dir::Dir<'static>,
        mode: DirectoryServeMode,
    ) -> Self {
        self.set_dir_embed_with_serve_mode(prefix, dir, mode);
        self
    }

    /// serve the given embedded directory under the given prefix (path)
    /// with a custom serve move.
    #[inline]
    pub fn set_dir_embed_with_serve_mode(
        &mut self,
        prefix: impl AsRef<str>,
        dir: include_dir::Dir<'static>,
        mode: DirectoryServeMode,
    ) -> &mut Self {
        let service = ServeDir::new_embedded(dir).with_directory_serve_mode(mode);
        match self.not_found.clone() {
            Some(not_found) => self.set_sub_service(prefix, service.fallback(not_found)),
            None => self.set_sub_service(prefix, service),
        }
    }

    /// register a nested router under a prefix (path).
    ///
    /// The prefix is used to match the request path and strip it from the request URI.
    ///
    /// Note: this sub-router is configured with the same State this router has.
    #[must_use]
    #[inline]
    pub fn with_sub_router_make_fn(
        mut self,
        prefix: impl AsRef<str>,
        configure_router: impl FnOnce(Self) -> Self,
    ) -> Self {
        self.set_sub_router_make_fn(prefix, configure_router);
        self
    }

    /// register a nested router under a prefix (path).
    ///
    /// The prefix is used to match the request path and strip it from the request URI.
    ///
    /// Note: this sub-router is configured with the same State this router has.
    pub fn set_sub_router_make_fn(
        &mut self,
        prefix: impl AsRef<str>,
        configure_router: impl FnOnce(Self) -> Self,
    ) -> &mut Self {
        let router = Self::new_with_state(self.state.clone());
        let router = configure_router(router);
        let nested = router.boxed();
        self.set_sub_service_inner(prefix, nested)
    }

    /// Register a nested service under a prefix (path).
    ///
    /// The prefix is used to match the request path and strip it from the request URI.
    ///
    /// Warning: This sub-service has no notion of the state this router has. If you want
    /// to create a sub-router that shares the same state this router has, use [`Router::sub`] instead.
    #[must_use]
    #[inline]
    pub fn with_sub_service<I, T>(mut self, prefix: impl AsRef<str>, service: I) -> Self
    where
        I: IntoEndpointService<T>,
    {
        self.set_sub_service(prefix, service);
        self
    }

    /// Register a nested service under a prefix.
    ///
    /// The prefix is used to match the request path and strip it from the request URI.
    ///
    /// Warning: This sub-service has no notion of the state this router has. If you want
    /// to create a sub-router that shares the same state this router has, use [`Router::sub`] instead.
    #[inline]
    pub fn set_sub_service<I, T>(&mut self, prefix: impl AsRef<str>, service: I) -> &mut Self
    where
        I: IntoEndpointService<T>,
    {
        let nested = service.into_endpoint_service().boxed();
        self.set_sub_service_inner(prefix, nested)
    }

    fn set_sub_service_inner(
        &mut self,
        prefix: impl AsRef<str>,
        nested: BoxService<Request, Response, Infallible>,
    ) -> &mut Self {
        let prefix = prefix.as_ref();

        let path =
            smol_str::format_smolstr!("{}/{}", prefix.trim().trim_end_matches(['/']), "{*nest}");

        let nested_router_service = NestedRouterService {
            prefix: Arc::from(prefix),
            nested,
        };

        self.set_match_route(
            prefix,
            HttpMatcher::custom(true),
            nested_router_service.clone(),
        )
        .set_match_route(&path, HttpMatcher::custom(true), nested_router_service)
    }

    /// add a route to the router with it's matcher and service.
    #[inline(always)]
    #[must_use]
    pub fn match_route<I, T>(
        mut self,
        path: impl AsRef<str>,
        matcher: HttpMatcher<Body>,
        service: I,
    ) -> Self
    where
        I: IntoEndpointServiceWithState<T, State>,
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
    {
        let service = service
            .into_endpoint_service_with_state(self.state.clone())
            .boxed();

        let path = path.as_ref().trim().trim_matches('/');
        let path = smol_str::format_smolstr!("/{path}");

        if let Ok(matched) = self.routes.at_mut(&path) {
            matched.value.push((matcher, service));
        } else {
            self.routes
                .insert(path, vec![(matcher, service)])
                .expect("Failed to add route");
        }

        self
    }

    /// use the provided service when no route matches the request.
    #[inline(always)]
    #[must_use]
    pub fn with_not_found<I, T>(mut self, service: I) -> Self
    where
        I: IntoEndpointServiceWithState<T, State>,
    {
        self.set_not_found(service);
        self
    }

    /// use the provided service when no route matches the request.
    pub fn set_not_found<I, T>(&mut self, service: I) -> &mut Self
    where
        I: IntoEndpointServiceWithState<T, State>,
    {
        self.not_found = Some(
            service
                .into_endpoint_service_with_state(self.state.clone())
                .boxed(),
        );
        self
    }
}

#[derive(Debug, Clone)]
struct NestedRouterService {
    #[expect(unused)]
    prefix: Arc<str>,
    nested: BoxService<Request, Response, Infallible>,
}

impl Service<Request> for NestedRouterService {
    type Response = Response;
    type Error = Infallible;

    async fn serve(&self, mut req: Request) -> Result<Self::Response, Self::Error> {
        let params = match req.extensions().get::<UriParams>() {
            Some(params) => {
                let nested_path = params.get("nest").unwrap_or_else(|| {
                    tracing::debug!("failed to fetch nest value in params: {params:?}; bug?");
                    Default::default()
                });

                let filtered_params: UriParams =
                    params.iter().filter(|(key, _)| *key != "nest").collect();

                // build the nested path and update the request URI
                let path = smol_str::format_smolstr!("/{nested_path}");
                *req.uri_mut() = match path.parse() {
                    Ok(uri) => uri,
                    Err(err) => {
                        tracing::debug!("failed to parse nested path as the req's new uri: {err}");
                        return Ok(StatusCode::INTERNAL_SERVER_ERROR.into_response());
                    }
                };

                filtered_params
            }
            None => UriParams::default(),
        };

        req.extensions_mut().insert(params);

        self.nested.serve(req).await
    }
}

impl Default for Router {
    fn default() -> Self {
        Self::new()
    }
}

impl<State> Service<Request> for Router<State>
where
    State: Send + Sync + Clone + 'static,
{
    type Response = Response;
    type Error = Infallible;

    async fn serve(&self, mut req: Request) -> Result<Self::Response, Self::Error> {
        let mut ext = Extensions::new();

        let uri = req.uri().path().to_owned();
        if let Ok(matched) = self.routes.at(&uri) {
            let uri_params = matched.params.iter();

            match req.extensions_mut().get_mut::<UriParams>() {
                Some(params) => {
                    params.extend(uri_params);
                }
                None => {
                    req.extensions_mut()
                        .insert(uri_params.collect::<UriParams>());
                }
            }

            for (matcher, service) in matched.value.iter() {
                if matcher.matches(Some(&mut ext), &req) {
                    req.extensions_mut().extend(ext);
                    return service.serve(req).await;
                }
                ext.clear();
            }
        }

        if let Some(not_found) = &self.not_found {
            not_found.serve(req).await
        } else {
            Ok(StatusCode::NOT_FOUND.into_response())
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{matcher::UriParams, service::web::extract::State};

    use super::*;
    use rama_core::{extensions::ExtensionsRef, service::service_fn};
    use rama_http_types::{Body, Method, Request, StatusCode, body::util::BodyExt};

    fn root_service() -> impl Service<Request, Response = Response, Error = Infallible> {
        service_fn(|_req| async {
            Ok(Response::builder()
                .status(200)
                .body(Body::from("Hello, World!"))
                .unwrap())
        })
    }

    fn create_user_service() -> impl Service<Request, Response = Response, Error = Infallible> {
        service_fn(|_req| async {
            Ok(Response::builder()
                .status(200)
                .body(Body::from("Create User"))
                .unwrap())
        })
    }

    fn get_users_service() -> impl Service<Request, Response = Response, Error = Infallible> {
        service_fn(|_req| async {
            Ok(Response::builder()
                .status(200)
                .body(Body::from("List Users"))
                .unwrap())
        })
    }

    fn get_user_service() -> impl Service<Request, Response = Response, Error = Infallible> {
        service_fn(|req: Request| async move {
            let uri_params = req.extensions().get::<UriParams>().unwrap();
            let id = uri_params.get("user_id").unwrap();
            Ok(Response::builder()
                .status(200)
                .body(Body::from(format!("Get User: {id}")))
                .unwrap())
        })
    }

    fn delete_user_service() -> impl Service<Request, Response = Response, Error = Infallible> {
        service_fn(|req: Request| async move {
            let uri_params = req.extensions().get::<UriParams>().unwrap();
            let id = uri_params.get("user_id").unwrap();
            Ok(Response::builder()
                .status(200)
                .body(Body::from(format!("Delete User: {id}")))
                .unwrap())
        })
    }

    fn serve_assets_service() -> impl Service<Request, Response = Response, Error = Infallible> {
        service_fn(|req: Request| async move {
            let uri_params = req.extensions().get::<UriParams>().unwrap();
            let path = uri_params.get("path").unwrap();
            Ok(Response::builder()
                .status(200)
                .body(Body::from(format!("Serve Assets: /{path}")))
                .unwrap())
        })
    }

    fn not_found_service() -> impl Service<Request, Response = Response, Error = Infallible> {
        service_fn(|_req| async {
            Ok(Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Body::from("Not Found"))
                .unwrap())
        })
    }

    fn get_user_order_service() -> impl Service<Request, Response = Response, Error = Infallible> {
        service_fn(|req: Request| async move {
            let uri_params = req.extensions().get::<UriParams>().unwrap();
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
                "Not Found",
                StatusCode::NOT_FOUND,
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
                .with_sub_router_make_fn(format!("{prefix}users/{{user_id}}"), |router| {
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
                });

            let app = Router::new()
                .with_sub_service(format!("{prefix}api"), api_router)
                .with_get(prefix, root_service());

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
        }
    }
}
