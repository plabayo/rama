use std::convert::Infallible;

use crate::{
    Request, Response,
    matcher::{HttpMatcher, UriParams},
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

pub struct Router<State> {
    routes: MatchitRouter<
        Vec<(
            HttpMatcher<State, Body>,
            BoxService<State, Request, Response, Infallible>,
        )>,
    >,
    not_found: Option<BoxService<State, Request, Response, Infallible>>,
}

impl<State> std::fmt::Debug for Router<State> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Router").finish()
    }
}

impl<State> Router<State>
where
    State: Clone + Send + Sync + 'static,
{
    pub fn new() -> Self {
        Self {
            routes: MatchitRouter::new(),
            not_found: None,
        }
    }

    pub fn get<I, T>(self, path: &str, service: I) -> Self
    where
        I: IntoEndpointService<State, T>,
    {
        let matcher = HttpMatcher::get(path);
        self.add_route(path, matcher, service)
    }

    pub fn post<I, T>(self, path: &str, service: I) -> Self
    where
        I: IntoEndpointService<State, T>,
    {
        let matcher = HttpMatcher::post(path);
        self.add_route(path, matcher, service)
    }

    pub fn put<I, T>(self, path: &str, service: I) -> Self
    where
        I: IntoEndpointService<State, T>,
    {
        let matcher = HttpMatcher::put(path);
        self.add_route(path, matcher, service)
    }

    pub fn delete<I, T>(self, path: &str, service: I) -> Self
    where
        I: IntoEndpointService<State, T>,
    {
        let matcher = HttpMatcher::delete(path);
        self.add_route(path, matcher, service)
    }

    pub fn patch<I, T>(self, path: &str, service: I) -> Self
    where
        I: IntoEndpointService<State, T>,
    {
        let matcher = HttpMatcher::patch(path);
        self.add_route(path, matcher, service)
    }

    pub fn head<I, T>(self, path: &str, service: I) -> Self
    where
        I: IntoEndpointService<State, T>,
    {
        let matcher = HttpMatcher::head(path);
        self.add_route(path, matcher, service)
    }

    pub fn options<I, T>(self, path: &str, service: I) -> Self
    where
        I: IntoEndpointService<State, T>,
    {
        let matcher = HttpMatcher::options(path);
        self.add_route(path, matcher, service)
    }

    pub fn trace<I, T>(self, path: &str, service: I) -> Self
    where
        I: IntoEndpointService<State, T>,
    {
        let matcher = HttpMatcher::trace(path);
        self.add_route(path, matcher, service)
    }

    pub fn sub<I, T>(self, prefix: &str, service: I) -> Self
    where
        I: IntoEndpointService<State, T>,
    {
        let path = format!("{}/{}", prefix.trim_end_matches(['/']), "{*nest}");
        let matcher = HttpMatcher::path("*");

        let nested_router_service = NestedRouterService {
            prefix: prefix.to_owned(),
            nested: service.into_endpoint_service().boxed(),
        };

        self.add_route(&path, matcher, nested_router_service)
    }

    fn add_route<I, T>(mut self, path: &str, matcher: HttpMatcher<State, Body>, service: I) -> Self
    where
        I: IntoEndpointService<State, T>,
    {
        let service = service.into_endpoint_service().boxed();

        if let Ok(matched) = self.routes.at_mut(path) {
            matched.value.push((matcher, service));
        } else {
            self.routes
                .insert(path, vec![(matcher, service)])
                .expect("Failed to add route");
        }

        self
    }

    pub fn not_found<I, T>(mut self, service: I) -> Self
    where
        I: IntoEndpointService<State, T>,
    {
        self.not_found = Some(service.into_endpoint_service().boxed());
        self
    }
}

struct NestedRouterService<State> {
    prefix: String,
    nested: BoxService<State, Request, Response, Infallible>,
}

impl<State: std::fmt::Debug> std::fmt::Debug for NestedRouterService<State> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NestedRouterService")
            .field("prefix", &self.prefix)
            .finish()
    }
}

impl<State> Service<State, Request> for NestedRouterService<State>
where
    State: Clone + Send + Sync + 'static,
{
    type Response = Response;
    type Error = Infallible;

    async fn serve(
        &self,
        ctx: Context<State>,
        mut req: Request,
    ) -> Result<Self::Response, Self::Error> {
        let path = ctx.get::<UriParams>().unwrap().glob().unwrap();

        if path.starts_with(&self.prefix) {
            // strip the "/prefix" from the request URI
            let new_path = &path[self.prefix.len()..];
            // update the request URI with the new path
            *req.uri_mut() = new_path.parse().unwrap();
        }

        self.nested.serve(ctx, req).await
    }
}

impl<State> Default for Router<State>
where
    State: Clone + Send + Sync + 'static,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<State> Service<State, Request> for Router<State>
where
    State: Clone + Send + Sync + 'static,
{
    type Response = Response;
    type Error = Infallible;

    async fn serve(
        &self,
        mut ctx: Context<State>,
        req: Request,
    ) -> Result<Self::Response, Self::Error> {
        let mut ext = Extensions::new();

        if let Ok(matched) = self.routes.at(req.uri().path()) {
            for (matcher, service) in matched.value.iter() {
                if matcher.matches(Some(&mut ext), &ctx, &req) {
                    let uri_params = matched.params.iter().collect::<UriParams>();
                    ctx.insert(uri_params);
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
    use rama_http_types::{Body, Method, Request, StatusCode, dep::http_body_util::BodyExt};

    fn root_service() -> impl Service<(), Request, Response = Response, Error = Infallible> {
        service_fn(|_ctx, _req| async {
            Ok(Response::builder()
                .status(200)
                .body(Body::from("Hello, World!"))
                .unwrap())
        })
    }

    fn create_user_service() -> impl Service<(), Request, Response = Response, Error = Infallible> {
        service_fn(|_ctx, _req| async {
            Ok(Response::builder()
                .status(200)
                .body(Body::from("Create User"))
                .unwrap())
        })
    }

    fn get_users_servic() -> impl Service<(), Request, Response = Response, Error = Infallible> {
        service_fn(|_ctx, _req| async {
            Ok(Response::builder()
                .status(200)
                .body(Body::from("List Users"))
                .unwrap())
        })
    }

    fn get_user_service() -> impl Service<(), Request, Response = Response, Error = Infallible> {
        service_fn(|ctx: Context<()>, _req| async move {
            let uri_params = ctx.get::<UriParams>().unwrap();
            let id = uri_params.get("id").unwrap();
            Ok(Response::builder()
                .status(200)
                .body(Body::from(format!("Get User: {}", id)))
                .unwrap())
        })
    }

    fn delete_user_service() -> impl Service<(), Request, Response = Response, Error = Infallible> {
        service_fn(|ctx: Context<()>, _req| async move {
            let uri_params = ctx.get::<UriParams>().unwrap();
            let id = uri_params.get("id").unwrap();
            Ok(Response::builder()
                .status(200)
                .body(Body::from(format!("Delete User: {}", id)))
                .unwrap())
        })
    }

    fn not_found_service() -> impl Service<(), Request, Response = Response, Error = Infallible> {
        service_fn(|_ctx, _req| async {
            Ok(Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Body::from("Not Found"))
                .unwrap())
        })
    }

    #[tokio::test]
    async fn test_router() {
        let router = Router::new()
            .get("/", root_service())
            .get("/users", get_users_servic())
            .post("/users", create_user_service())
            .get("/users/{id}", get_user_service())
            .delete("/users/{id}", delete_user_service())
            .not_found(not_found_service());

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
                "/not-found",
                "Not Found",
                StatusCode::NOT_FOUND,
            ),
        ];

        for (method, path, expected_body, expected_status) in cases {
            let req = match method {
                Method::GET => Request::get(path),
                Method::POST => Request::post(path),
                Method::DELETE => Request::delete(path),
                _ => panic!("Unsupported HTTP method"),
            }
            .body(Body::empty())
            .unwrap();

            let res = router.serve(Context::default(), req).await.unwrap();
            assert_eq!(res.status(), expected_status);
            let body = res.into_body().collect().await.unwrap().to_bytes();
            assert_eq!(body, expected_body);
        }
    }

    #[tokio::test]
    async fn test_router_nest() {
        let api_router = Router::new()
            .get("/users", get_users_servic())
            .post("/users", create_user_service())
            .delete("/users/{id}", delete_user_service());

        let app = Router::new()
            .sub("/api", api_router)
            .get("/", root_service());

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
        ];

        for (method, path, expected_body, expected_status) in cases {
            let req = match method {
                Method::GET => Request::get(path),
                Method::POST => Request::post(path),
                Method::DELETE => Request::delete(path),
                _ => panic!("Unsupported HTTP method"),
            }
            .body(Body::empty())
            .unwrap();

            let res = app.serve(Context::default(), req).await.unwrap();
            assert_eq!(res.status(), expected_status);
            let body = res.into_body().collect().await.unwrap().to_bytes();
            assert_eq!(body, expected_body);
        }
    }
}
