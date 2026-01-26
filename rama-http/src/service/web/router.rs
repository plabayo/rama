use matchit::Router as MatchitRouter;
use radix_trie::{Trie, TrieCommon as _};
use std::{convert::Infallible, path::Path, sync::Arc};

use crate::{
    Request, Response,
    matcher::{HttpMatcher, PathMatcher, UriParams},
    service::{
        fs::{DirectoryServeMode, ServeDir},
        web::{IntoEndpointService, IntoEndpointServiceWithState, response::IntoResponse},
    },
};

use rama_core::{
    extensions::{Extensions, ExtensionsMut},
    matcher::Matcher,
    service::{BoxService, Service},
    telemetry::tracing,
};
use rama_http_types::{
    Body, OriginalRouterUri, StatusCode, mime::Mime, uri::try_to_strip_path_prefix_from_uri,
};
use rama_utils::{
    include_dir,
    str::smol_str::{StrExt as _, format_smolstr},
};

/// A basic router that can be used to route requests to different services based on the request path.
///
/// This router uses `matchit::Router` to efficiently match incoming requests
/// to predefined routes. Each route is associated with an `HttpMatcher`
/// and a corresponding service handler.
#[allow(unused)]
pub struct Router<State = ()> {
    routes: MatchitRouter<Vec<(HttpMatcher<Body>, BoxService<Request, Response, Infallible>)>>,
    sub_services: Option<Trie<String, SubService>>,
    not_found: Option<BoxService<Request, Response, Infallible>>,
    state: State,
}

impl<S> std::fmt::Debug for Router<S> {
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
            sub_services: None,
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
            sub_services: None,
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
        self.with_match_route(path, matcher, service)
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
        self.with_match_route(path, matcher, service)
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
        self.with_match_route(path, matcher, service)
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
        self.with_match_route(path, matcher, service)
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
        self.with_match_route(path, matcher, service)
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
        self.with_match_route(path, matcher, service)
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
        self.with_match_route(path, matcher, service)
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
        self.with_match_route(path, matcher, service)
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
        self.with_match_route(path, matcher, service)
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
    /// to create a sub-router that shares the same state this router has, use [`Router::with_sub_router_make_fn`] instead.
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
    /// to create a sub-router that shares the same state this router has, use [`Router::with_sub_router_make_fn`] instead.
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
        let prefix = prefix.as_ref().trim().trim_matches('/').to_lowercase();
        let trie = self.sub_services.get_or_insert_default();

        if !prefix.contains(['*', '{', '}']) {
            trie.insert(
                prefix,
                SubService {
                    svc: nested,
                    matcher: None,
                },
            );
        } else {
            const DISALLOW_GLOB: bool = false;
            match PathMatcher::new(prefix).try_remove_literal_prefix(DISALLOW_GLOB) {
                Ok((literal, maybe_matcher)) => {
                    trie.insert(
                        literal.to_string(),
                        SubService {
                            svc: nested,
                            matcher: maybe_matcher,
                        },
                    );
                }
                Err(matcher) => {
                    trie.insert(
                        Default::default(),
                        SubService {
                            svc: nested,
                            matcher: Some(matcher),
                        },
                    );
                }
            }
        }

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
    {
        self.set_match_route(path, matcher, service);
        self
    }

    // TODO: Make this fallible,
    // and also do not allow empty path, instead folks should use `not_found` for that

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
        let path = format_smolstr!("/{path}").to_lowercase_smolstr();

        if let Ok(matched) = self.routes.at_mut(&path) {
            matched.value.push((matcher, service));
        } else {
            #[allow(clippy::expect_used, reason = "TODO later")]
            self.routes
                .insert(path, vec![(matcher, service)])
                .expect("add route");
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

impl Default for Router {
    fn default() -> Self {
        Self::new()
    }
}

struct SubService {
    svc: BoxService<Request, Response, Infallible>,
    matcher: Option<PathMatcher>,
}

impl<State> Service<Request> for Router<State>
where
    State: Send + Sync + Clone + 'static,
{
    type Output = Response;
    type Error = Infallible;

    async fn serve(&self, mut req: Request) -> Result<Self::Output, Self::Error> {
        let path = req.uri().path().to_lowercase_smolstr();

        if let Ok(matched) = self.routes.at(path.as_str()) {
            let uri_params = matched.params.iter();

            let params = match req.extensions_mut().get::<UriParams>() {
                Some(params) => {
                    let mut params = params.clone();
                    params.extend(uri_params);
                    params
                }
                None => uri_params.collect::<UriParams>(),
            };

            req.extensions_mut().insert(params);

            for (matcher, service) in matched.value.iter() {
                let mut ext = Extensions::new();
                if matcher.matches(Some(&mut ext), &req) {
                    req.extensions_mut().extend(ext);
                    return service.serve(req).await;
                }
            }
        }

        let (mut parts, body) = req.into_parts();

        if let Some(trie) = self.sub_services.as_ref() {
            let norm_path = parts.uri.path().trim_matches('/').to_lowercase_smolstr();
            if let Some((prefix, sub_svc)) =
                trie.get_ancestor(norm_path.as_str()).and_then(|sub_trie| {
                    sub_trie
                        .key()
                        .and_then(|k| sub_trie.value().map(|v| (k, v)))
                })
            {
                if let Some(matcher) = sub_svc.matcher.as_ref() {
                    let fragment_count = matcher.fragment_count();
                    let mut pos = 0;
                    let mut fragment_index = 0;
                    let path = parts.uri.path().trim_matches('/');

                    let offset = prefix.len().min(path.len());
                    let path = &path[offset..].trim_matches('/');

                    for char in path.bytes() {
                        if fragment_index >= fragment_count {
                            break;
                        }
                        pos += 1;
                        if char == b'/' {
                            fragment_index += 1;
                        }
                    }

                    let fragments_path = &path[..pos];

                    let mut ext = Extensions::new();
                    if matcher.matches_path(Some(&mut ext), fragments_path) {
                        let full_prefix = format_smolstr!("{prefix}/{fragments_path}",);
                        let modified_uri = match try_to_strip_path_prefix_from_uri(
                            &parts.uri,
                            &full_prefix,
                        ) {
                            Ok(value) => value,
                            Err(err) => {
                                tracing::warn!(
                                    "failed to strip full prefix '{full_prefix}' (static: '{prefix}') from Uri (bug??); err = {err}",
                                );
                                return Ok(StatusCode::INTERNAL_SERVER_ERROR.into_response());
                            }
                        };

                        parts.extensions.extend(ext);
                        parts
                            .extensions
                            .insert(OriginalRouterUri(Arc::new(parts.uri)));
                        parts.uri = modified_uri;

                        tracing::trace!(
                            "svc request using sub service of router using uri with full prefix '{full_prefix}' (static: '{prefix}') removed from path; new uri: {}",
                            parts.uri,
                        );
                        let req = Request::from_parts(parts, body);
                        return sub_svc.svc.serve(req).await;
                    }

                    tracing::trace!(
                        "svc request using sub service matched with static prefix '{prefix}' (fragment path: '{fragments_path}'), but matcher didn't match"
                    );
                } else {
                    match try_to_strip_path_prefix_from_uri(&parts.uri, prefix) {
                        Ok(modified_uri) => {
                            if !parts.extensions.contains::<OriginalRouterUri>() {
                                parts
                                    .extensions
                                    .insert(OriginalRouterUri(Arc::new(parts.uri)));
                            }
                            parts.uri = modified_uri;
                        }
                        Err(err) => {
                            tracing::warn!(
                                "failed to strip literal prefix '{prefix}' from Uri (bug??); err = {err}",
                            );
                            return Ok(StatusCode::INTERNAL_SERVER_ERROR.into_response());
                        }
                    }

                    tracing::trace!(
                        "svc request using sub service of router using uri with literal prefix '{prefix}' removed from path; new uri: {}",
                        parts.uri,
                    );
                    let req = Request::from_parts(parts, body);
                    return sub_svc.svc.serve(req).await;
                }
            }
        }

        if let Some(not_found) = &self.not_found {
            let req = Request::from_parts(parts, body);
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
            let uri_params = req.extensions().get::<UriParams>().unwrap();
            let id = uri_params.get("user_id").unwrap();
            Ok(Response::builder()
                .status(200)
                .body(Body::from(format!("Get User: {id}")))
                .unwrap())
        })
    }

    fn delete_user_service() -> impl Service<Request, Output = Response, Error = Infallible> {
        service_fn(|req: Request| async move {
            let uri_params = req.extensions().get::<UriParams>().unwrap();
            let id = uri_params.get("user_id").unwrap();
            Ok(Response::builder()
                .status(200)
                .body(Body::from(format!("Delete User: {id}")))
                .unwrap())
        })
    }

    fn serve_assets_service() -> impl Service<Request, Output = Response, Error = Infallible> {
        service_fn(|req: Request| async move {
            let uri_params = req.extensions().get::<UriParams>().unwrap();
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
                    format!("{prefix}users/{{user_id}}/*"), // glob should be dropped by nester
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
