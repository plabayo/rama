use std::{convert::Infallible, sync::Arc};

use crate::{
    Request, Response,
    matcher::{HttpMatcher, MethodMatcher, UriParams},
};

use matchit::Router as MatchitRouter;
use rama_core::{
    Context,
    context::Extensions,
    matcher::Matcher,
    service::{BoxService, Service},
};
use rama_http_types::{Body, StatusCode};

use super::IntoEndpointService;

/// A basic router that can be used to route requests to different services based on the request path.
///
/// This router uses `matchit::Router` to efficiently match incoming requests
/// to predefined routes. Each route is associated with an `HttpMatcher`
/// and a corresponding service handler.
pub struct Router {
    routes: MatchitRouter<Vec<(HttpMatcher<Body>, BoxService<Request, Response, Infallible>)>>,
    not_found: Option<BoxService<Request, Response, Infallible>>,
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
            not_found: None,
        }
    }

    /// add a GET route to the router.
    /// the path can contain parameters, e.g. `/users/{id}`.
    /// the path can also contain a catch call, e.g. `/assets/{*path}`.
    #[must_use]
    pub fn get<I, T>(self, path: &str, service: I) -> Self
    where
        I: IntoEndpointService<T>,
    {
        let matcher = HttpMatcher::method(MethodMatcher::GET);
        self.match_route(path, matcher, service)
    }

    /// add a POST route to the router.
    #[must_use]
    pub fn post<I, T>(self, path: &str, service: I) -> Self
    where
        I: IntoEndpointService<T>,
    {
        let matcher = HttpMatcher::method(MethodMatcher::POST);
        self.match_route(path, matcher, service)
    }

    /// add a PUT route to the router.
    #[must_use]
    pub fn put<I, T>(self, path: &str, service: I) -> Self
    where
        I: IntoEndpointService<T>,
    {
        let matcher = HttpMatcher::method(MethodMatcher::PUT);
        self.match_route(path, matcher, service)
    }

    /// add a DELETE route to the router.
    #[must_use]
    pub fn delete<I, T>(self, path: &str, service: I) -> Self
    where
        I: IntoEndpointService<T>,
    {
        let matcher = HttpMatcher::method(MethodMatcher::DELETE);
        self.match_route(path, matcher, service)
    }

    /// add a PATCH route to the router.
    #[must_use]
    pub fn patch<I, T>(self, path: &str, service: I) -> Self
    where
        I: IntoEndpointService<T>,
    {
        let matcher = HttpMatcher::method(MethodMatcher::PATCH);
        self.match_route(path, matcher, service)
    }

    /// add a HEAD route to the router.
    #[must_use]
    pub fn head<I, T>(self, path: &str, service: I) -> Self
    where
        I: IntoEndpointService<T>,
    {
        let matcher = HttpMatcher::method(MethodMatcher::HEAD);
        self.match_route(path, matcher, service)
    }

    /// add a OPTIONS route to the router.
    #[must_use]
    pub fn options<I, T>(self, path: &str, service: I) -> Self
    where
        I: IntoEndpointService<T>,
    {
        let matcher = HttpMatcher::method(MethodMatcher::OPTIONS);
        self.match_route(path, matcher, service)
    }

    /// add a TRACE route to the router.
    #[must_use]
    pub fn trace<I, T>(self, path: &str, service: I) -> Self
    where
        I: IntoEndpointService<T>,
    {
        let matcher = HttpMatcher::method(MethodMatcher::TRACE);
        self.match_route(path, matcher, service)
    }

    /// add a CONNECT route to the router.
    #[must_use]
    pub fn connect<I, T>(self, path: &str, service: I) -> Self
    where
        I: IntoEndpointService<T>,
    {
        let matcher = HttpMatcher::method(MethodMatcher::CONNECT);
        self.match_route(path, matcher, service)
    }

    /// register a nested router under a prefix.
    ///
    /// The prefix is used to match the request path and strip it from the request URI.
    #[must_use]
    pub fn sub<I, T>(self, prefix: &str, service: I) -> Self
    where
        I: IntoEndpointService<T>,
    {
        let path = format!("{}/{}", prefix.trim().trim_end_matches(['/']), "{*nest}");
        let nested = Arc::new(service.into_endpoint_service().boxed());

        let nested_router_service = NestedRouterService {
            prefix: Arc::from(prefix),
            nested,
        };

        self.match_route(
            prefix,
            HttpMatcher::custom(true),
            nested_router_service.clone(),
        )
        .match_route(&path, HttpMatcher::custom(true), nested_router_service)
    }

    /// add a route to the router with it's matcher and service.
    #[must_use]
    pub fn match_route<I, T>(mut self, path: &str, matcher: HttpMatcher<Body>, service: I) -> Self
    where
        I: IntoEndpointService<T>,
    {
        let service = service.into_endpoint_service().boxed();

        let path = path.trim().trim_matches('/');
        let path = format!("/{path}");

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
    #[must_use]
    pub fn not_found<I, T>(mut self, service: I) -> Self
    where
        I: IntoEndpointService<T>,
    {
        self.not_found = Some(service.into_endpoint_service().boxed());
        self
    }
}

#[derive(Debug, Clone)]
struct NestedRouterService {
    #[expect(unused)]
    prefix: Arc<str>,
    nested: Arc<BoxService<Request, Response, Infallible>>,
}

impl Service<Request> for NestedRouterService {
    type Response = Response;
    type Error = Infallible;

    async fn serve(
        &self,
        mut ctx: Context,
        mut req: Request,
    ) -> Result<Self::Response, Self::Error> {
        let params: UriParams = match ctx.remove::<UriParams>() {
            Some(params) => {
                let nested_path = params.get("nest").unwrap_or_default();

                let filtered_params: UriParams =
                    params.iter().filter(|(key, _)| *key != "nest").collect();

                // build the nested path and update the request URI
                let path = format!("/{nested_path}");
                *req.uri_mut() = path.parse().unwrap();

                filtered_params
            }
            None => UriParams::default(),
        };

        ctx.insert(params);

        self.nested.serve(ctx, req).await
    }
}

impl Default for Router {
    fn default() -> Self {
        Self::new()
    }
}

impl Service<Request> for Router {
    type Response = Response;
    type Error = Infallible;

    async fn serve(&self, mut ctx: Context, req: Request) -> Result<Self::Response, Self::Error> {
        let mut ext = Extensions::new();

        if let Ok(matched) = self.routes.at(req.uri().path()) {
            let uri_params = matched.params.iter();

            let params: UriParams = match ctx.remove::<UriParams>() {
                Some(mut params) => {
                    params.extend(uri_params);
                    params
                }
                None => uri_params.collect(),
            };
            ctx.insert(params);

            for (matcher, service) in matched.value.iter() {
                if matcher.matches(Some(&mut ext), &ctx, &req) {
                    ctx.extend(ext);
                    return service.serve(ctx, req).await;
                }
                ext.clear();
            }
        }

        if let Some(not_found) = &self.not_found {
            not_found.serve(ctx, req).await
        } else {
            Ok(Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Body::from("Not Found"))
                .unwrap())
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::matcher::UriParams;

    use super::*;
    use rama_core::service::service_fn;
    use rama_http_types::{Body, Method, Request, StatusCode, body::util::BodyExt};

    fn root_service() -> impl Service<Request, Response = Response, Error = Infallible> {
        service_fn(|_ctx, _req| async {
            Ok(Response::builder()
                .status(200)
                .body(Body::from("Hello, World!"))
                .unwrap())
        })
    }

    fn create_user_service() -> impl Service<Request, Response = Response, Error = Infallible> {
        service_fn(|_ctx, _req| async {
            Ok(Response::builder()
                .status(200)
                .body(Body::from("Create User"))
                .unwrap())
        })
    }

    fn get_users_service() -> impl Service<Request, Response = Response, Error = Infallible> {
        service_fn(|_ctx, _req| async {
            Ok(Response::builder()
                .status(200)
                .body(Body::from("List Users"))
                .unwrap())
        })
    }

    fn get_user_service() -> impl Service<Request, Response = Response, Error = Infallible> {
        service_fn(|ctx: Context, _req| async move {
            let uri_params = ctx.get::<UriParams>().unwrap();
            let id = uri_params.get("user_id").unwrap();
            Ok(Response::builder()
                .status(200)
                .body(Body::from(format!("Get User: {id}")))
                .unwrap())
        })
    }

    fn delete_user_service() -> impl Service<Request, Response = Response, Error = Infallible> {
        service_fn(|ctx: Context, _req| async move {
            let uri_params = ctx.get::<UriParams>().unwrap();
            let id = uri_params.get("user_id").unwrap();
            Ok(Response::builder()
                .status(200)
                .body(Body::from(format!("Delete User: {id}")))
                .unwrap())
        })
    }

    fn serve_assets_service() -> impl Service<Request, Response = Response, Error = Infallible> {
        service_fn(|ctx: Context, _req| async move {
            let uri_params = ctx.get::<UriParams>().unwrap();
            let path = uri_params.get("path").unwrap();
            Ok(Response::builder()
                .status(200)
                .body(Body::from(format!("Serve Assets: /{path}")))
                .unwrap())
        })
    }

    fn not_found_service() -> impl Service<Request, Response = Response, Error = Infallible> {
        service_fn(|_ctx, _req| async {
            Ok(Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Body::from("Not Found"))
                .unwrap())
        })
    }

    fn get_user_order_service() -> impl Service<Request, Response = Response, Error = Infallible> {
        service_fn(|ctx: Context, _req| async move {
            let uri_params = ctx.get::<UriParams>().unwrap();
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
                .get(prefix, root_service())
                .get(&format!("{prefix}users"), get_users_service())
                .post(&format!("{prefix}users"), create_user_service())
                .get(&format!("{prefix}users/{{user_id}}"), get_user_service())
                .delete(&format!("{prefix}users/{{user_id}}"), delete_user_service())
                .get(
                    &format!("{prefix}users/{{user_id}}/orders/{{order_id}}"),
                    get_user_order_service(),
                )
                .get(&format!("{prefix}assets/{{*path}}"), serve_assets_service())
                .not_found(not_found_service());

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

                let res = router.serve(Context::default(), req).await.unwrap();
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
        let cases = vec![
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
        ];

        for prefix in ["/", ""] {
            let api_router = Router::new()
                .get(&format!("{prefix}users"), get_users_service())
                .post(&format!("{prefix}users"), create_user_service())
                .delete(&format!("{prefix}users/{{user_id}}"), delete_user_service())
                .sub(
                    &format!("{prefix}users/{{user_id}}"),
                    Router::new().get(prefix, get_user_service()).get(
                        &format!("{prefix}orders/{{order_id}}"),
                        get_user_order_service(),
                    ),
                );

            let app = Router::new()
                .sub(&format!("{prefix}api"), api_router)
                .get(prefix, root_service());

            for (method, path, expected_body, expected_status) in cases.iter() {
                let req = match *method {
                    Method::GET => Request::get(*path),
                    Method::POST => Request::post(*path),
                    Method::DELETE => Request::delete(*path),
                    _ => panic!("Unsupported HTTP method"),
                }
                .body(Body::empty())
                .unwrap();

                let res = app.serve(Context::default(), req).await.unwrap();
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
