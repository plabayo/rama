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
    service::{BoxService, Service},
};
use rama_http_types::Body;

use super::IntoEndpointService;

pub struct Router<State> {
    routes: MatchitRouter<
        Vec<(
            HttpMatcher<State, Body>,
            Arc<BoxService<State, Request, Response, Infallible>>,
        )>,
    >,
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
            // println!("Matched: {:?}", matched);
            for (matcher, service) in matched.value.iter() {
                // println!("Matcher: {:?}", matcher);
                // TODO: matcher.matches not matching here
                if matcher.matches(Some(&mut ext), &ctx, &req) {
                    // println!("Matched: {:?}", matched);
                    let uri_params = matched.params.iter().collect::<UriParams>();
                    ctx.insert(uri_params);
                    ctx.extend(ext);
                    return service.serve(ctx, req).await;
                }
                ext.clear();
            }
        }

        let not_found = Response::builder()
            .status(404)
            .body(Body::from("Not Found"))
            .unwrap();

        Ok(not_found)
    }
}

#[cfg(test)]
mod tests {
    use crate::matcher::UriParams;

    use super::*;
    use rama_core::service::service_fn;
    use rama_http_types::{Body, Request, StatusCode, dep::http_body_util::BodyExt};

    #[tokio::test]
    async fn test_router_get() {
        let list_user = service_fn(|| async {
            Ok::<_, Infallible>(Response::new(Body::from("Hello, World!")))
        });

        let router = Router::new().get("/user", list_user);

        let req = Request::post("/user").body(Body::empty()).unwrap();
        let resp = router.serve(Context::default(), req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        let req = Request::get("/user").body(Body::empty()).unwrap();
        let resp = router.serve(Context::default(), req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body, "Hello, World!");
    }

    #[tokio::test]
    async fn test_router_chain() {
        let list_user = service_fn(|| async {
            Ok::<_, Infallible>(Response::new(Body::from("Hello, World!")))
        });

        let create_user =
            service_fn(|| async { Ok::<_, Infallible>(Response::new(Body::from("User created"))) });

        let router = Router::new()
            .get("/user", list_user)
            .post("/user", create_user);

        let req = Request::get("/user").body(Body::empty()).unwrap();
        let resp = router.serve(Context::default(), req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body, "Hello, World!");

        let req = Request::post("/user").body(Body::empty()).unwrap();
        let resp = router.serve(Context::default(), req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body, "User created");
    }

    #[tokio::test]
    async fn test_router_params() {
        // Service that extracts :id from UriParams in context
        let user_service = service_fn(|ctx: Context<()>, _req| async move {
            Ok::<_, Infallible>(Response::new(Body::from(format!(
                "User ID: {}",
                ctx.get::<UriParams>().unwrap().get("id").unwrap()
            ))))
        });

        let router = Router::new().get("/user/{id}", user_service);
        let req = Request::get("/user/42").body(Body::empty()).unwrap();
        let resp = router.serve(Context::default(), req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body, "User ID: 42");
    }
}
