use std::{convert::Infallible, sync::Arc};

use crate::{
    Request, Response,
    matcher::{HttpMatcher, UriParams},
};

use matchit::Router as MatchitRouter;
use rama_core::{
    Context,
    context::Extensions,
    matcher::Matcher,
    service::{BoxService, Service, service_fn},
};
use rama_http_types::{Body, IntoResponse, StatusCode};

use super::IntoEndpointService;

pub struct Router<State> {
    routes: MatchitRouter<
        Vec<(
            HttpMatcher<State, Body>,
            Arc<BoxService<State, Request, Response, Infallible>>,
        )>,
    >,
    not_found: Arc<BoxService<State, Request, Response, Infallible>>,
}

impl<State> std::fmt::Debug for Router<State> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Router").finish()
    }
}

impl<State> Router<State>
where
    State: Send + Sync + 'static,
{
    pub fn new() -> Self {
        Self {
            routes: MatchitRouter::new(),
            not_found: Arc::new(
                service_fn(async || Ok(StatusCode::NOT_FOUND.into_response())).boxed(),
            ),
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

    fn add_route<I, T>(mut self, path: &str, matcher: HttpMatcher<State, Body>, service: I) -> Self
    where
        I: IntoEndpointService<State, T>,
    {
        let service = service.into_endpoint_service().boxed();

        if let Ok(matched) = self.routes.at_mut(path) {
            matched.value.push((matcher, Arc::new(service)));
        } else {
            self.routes
                .insert(path, vec![(matcher, Arc::new(service))])
                .expect("Failed to add route");
        }

        self
    }

    pub fn not_found<I, T>(mut self, service: I) -> Self
    where
        I: IntoEndpointService<State, T>,
    {
        self.not_found = Arc::new(service.into_endpoint_service().boxed());
        self
    }
}

impl<State> Default for Router<State>
where
    State: Send + Sync + 'static,
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
        self.not_found.serve(ctx, req).await
    }
}

#[cfg(test)]
mod tests {
    use crate::matcher::UriParams;

    use super::*;
    use rama_core::service::service_fn;
    use rama_http_types::{Body, Request, StatusCode, dep::http_body_util::BodyExt};

    #[tokio::test]
    async fn test_router() {
        let root = service_fn(|_ctx, _req| async {
            Ok(Response::builder()
                .status(200)
                .body(Body::from("Hello, World!"))
                .unwrap())
        });

        let list_users = service_fn(|_ctx, _req| async {
            Ok(Response::builder()
                .status(200)
                .body(Body::from("List Users"))
                .unwrap())
        });

        let create_user = service_fn(|_ctx, _req| async {
            Ok(Response::builder()
                .status(200)
                .body(Body::from("Create User"))
                .unwrap())
        });

        let get_user = service_fn(|ctx: Context<()>, _req| async move {
            let uri_params = ctx.get::<UriParams>().unwrap();
            let id = uri_params.get("id").unwrap();
            Ok(Response::builder()
                .status(200)
                .body(Body::from(format!("Get User: {}", id)))
                .unwrap())
        });

        let delete_user = service_fn(|ctx: Context<()>, _req| async move {
            let uri_params = ctx.get::<UriParams>().unwrap();
            let id = uri_params.get("id").unwrap();
            Ok(Response::builder()
                .status(200)
                .body(Body::from(format!("Delete User: {}", id)))
                .unwrap())
        });

        let not_found_service = service_fn(|_ctx, _req| async {
            Ok(Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Body::from("Not Found"))
                .unwrap())
        });

        let router = Router::new()
            .get("/", root)
            .get("/users", list_users)
            .post("/users", create_user)
            .get("/users/{id}", get_user)
            .delete("/users/{id}", delete_user)
            .not_found(not_found_service);

        let req = Request::get("/").body(Body::empty()).unwrap();
        let res = router.serve(Context::default(), req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = res.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body, "Hello, World!");

        let req = Request::get("/users").body(Body::empty()).unwrap();
        let res = router.serve(Context::default(), req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = res.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body, "List Users");

        let req = Request::post("/users").body(Body::empty()).unwrap();
        let res = router.serve(Context::default(), req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = res.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body, "Create User");

        let req = Request::get("/users/123").body(Body::empty()).unwrap();
        let res = router.serve(Context::default(), req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = res.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body, "Get User: 123");

        let req = Request::delete("/users/123").body(Body::empty()).unwrap();
        let res = router.serve(Context::default(), req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = res.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body, "Delete User: 123");

        let req = Request::get("/not-found").body(Body::empty()).unwrap();
        let res = router.serve(Context::default(), req).await.unwrap();
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
        let body = res.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body, "Not Found");
    }
}
