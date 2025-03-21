use std::{collections::HashMap, convert::Infallible, sync::Arc};

use crate::{Method, Request, Response};

use matchit::Router as MatchitRouter;
use rama_core::{
    Context,
    service::{BoxService, Service},
};
use rama_http_types::Body;

pub struct Router<State> {
    routes: HashMap<Method, MatchitRouter<Arc<BoxService<State, Request, Response, Infallible>>>>,
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
            routes: HashMap::new(),
        }
    }

    pub fn get<I>(mut self, path: &str, service: I) -> Self
    where
        I: Service<State, Request, Response = Response, Error = Infallible> + 'static,
    {
        self.add_route(Method::GET, path, service);
        self
    }

    fn add_route<I>(&mut self, method: Method, path: &str, service: I)
    where
        I: Service<State, Request, Response = Response, Error = Infallible> + 'static,
    {
        let router = self.routes.entry(method).or_default();
        let boxed_service = service.boxed();
        router
            .insert(path, Arc::new(boxed_service))
            .expect("Failed to add route");
    }

    pub fn merge(&mut self, other: Router<State>) -> Result<(), String> {
        for (method, other_router) in other.routes {
            let router = self.routes.entry(method).or_default();

            match router.merge(other_router) {
                Ok(_) => continue,
                Err(_) => return Err("Failed to merge routes".to_string()),
            }
        }

        Ok(())
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
    State: Send + Sync + 'static,
{
    type Response = Response;
    type Error = Infallible;

    async fn serve(
        &self,
        ctx: Context<State>,
        req: Request,
    ) -> Result<Self::Response, Self::Error> {
        let method = req.method();
        if let Some(router) = self.routes.get(method) {
            if let Ok(matched) = router.at(req.uri().path()) {
                let service = matched.value.clone();

                return service.serve(ctx, req).await;
            }
        }

        // TODO: Return 404 response
        Ok(Response::new(Body::empty()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama_core::service::service_fn;
    use rama_http_types::{Body, Request, StatusCode, dep::http_body_util::BodyExt};

    #[tokio::test]
    async fn test_router_get() {
        let service = service_fn(|| async {
            Ok::<_, Infallible>(Response::new(Body::from("Hello, World!")))
        });

        let router: Router<()> = Router::new().get("/hello", service);

        let req = Request::get("/hello").body(Body::empty()).unwrap();

        let resp = router.serve(Context::default(), req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body, "Hello, World!");
    }

    #[tokio::test]
    async fn test_router_merge() {
        let mut root_router: Router<()> = Router::new().get(
            "/home",
            service_fn(|| async {
                Ok::<_, Infallible>(Response::new(Body::from("Welcome Home!")))
            }),
        );

        let child_router: Router<()> = Router::new().get(
            "/user/{id}",
            service_fn(|| async { Ok::<_, Infallible>(Response::new(Body::from("User Info"))) }),
        );

        root_router.merge(child_router).unwrap();

        let req = Request::get("/home").body(Body::empty()).unwrap();
        let resp = root_router.serve(Context::default(), req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body, "Welcome Home!");

        let req = Request::get("/user/1").body(Body::empty()).unwrap();
        let resp = root_router.serve(Context::default(), req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body, "User Info");
    }
}
