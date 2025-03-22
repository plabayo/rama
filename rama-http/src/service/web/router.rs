use std::convert::Infallible;

use crate::{
    Request, Response,
    matcher::{HttpMatcher, MethodMatcher},
};

use matchit::Router as MatchitRouter;
use rama_core::{
    Context,
    matcher::Matcher,
    service::{BoxService, Service},
};
use rama_http_types::Body;

pub struct Router<State> {
    routes: MatchitRouter<
        Vec<(
            HttpMatcher<State, Body>,
            BoxService<State, Request, Response, Infallible>,
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

    pub fn get<I>(mut self, path: &str, service: I) -> Self
    where
        I: Service<State, Request, Response = Response, Error = Infallible> + 'static,
    {
        self.add_route(MethodMatcher::GET, path, service);
        self
    }

    pub fn post<I>(mut self, path: &str, service: I) -> Self
    where
        I: Service<State, Request, Response = Response, Error = Infallible> + 'static,
    {
        self.add_route(MethodMatcher::POST, path, service);
        self
    }

    fn add_route<I>(&mut self, method_matcher: MethodMatcher, path: &str, service: I)
    where
        I: Service<State, Request, Response = Response, Error = Infallible> + 'static,
    {
        let matcher = HttpMatcher::method(method_matcher);
        let box_service = service.boxed();

        match self.routes.at_mut(path) {
            Ok(matched) => {
                matched.value.push((matcher, box_service));
            }
            Err(_) => {
                self.routes
                    .insert(path, vec![(matcher, box_service)])
                    .unwrap();
            }
        }
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
        if let Ok(matched) = self.routes.at(req.uri().path()) {
            for (matcher, service) in matched.value.iter() {
                // if matcher.matches(None, &ctx, &req) {
                //     return service.serve(ctx, req).await;
                // }
            }
        }

        // // TODO: Return 404 response
        Ok(Response::new(Body::empty()))
    }
}

// #[cfg(test)]
// mod tests {
// use super::*;
// use rama_core::service::service_fn;
// use rama_http_types::{Body, Request, StatusCode, dep::http_body_util::BodyExt};
//
// #[tokio::test]
// async fn test_router_get() {
// let list_user = service_fn(|| async {
//     Ok::<_, Infallible>(Response::new(Body::from("Hello, World!")))
// });
//
// let router: Router<()> = Router::new().get("/user", list_user);
//
// let req = Request::post("/user").body(Body::empty()).unwrap();
//
// let resp = router.serve(Context::default(), req).await.unwrap();

// assert_eq!(resp.status(), StatusCode::OK);
// let body = resp.into_body().collect().await.unwrap().to_bytes();
// assert_eq!(body, "Hello, World!");
// }

// #[tokio::test]
// async fn test_router_merge() {
//     let mut root_router: Router<()> = Router::new().get(
//         "/home",
//         service_fn(|| async {
//             Ok::<_, Infallible>(Response::new(Body::from("Welcome Home!")))
//         }),
//     );
//
//     let child_router: Router<()> = Router::new().get(
//         "/user/{id}",
//         service_fn(|| async { Ok::<_, Infallible>(Response::new(Body::from("User Info"))) }),
//     );
//
//     root_router.merge(child_router).unwrap();
//
//     let req = Request::get("/home").body(Body::empty()).unwrap();
//     let resp = root_router.serve(Context::default(), req).await.unwrap();
//     assert_eq!(resp.status(), StatusCode::OK);
//     let body = resp.into_body().collect().await.unwrap().to_bytes();
//     assert_eq!(body, "Welcome Home!");
//
//     let req = Request::get("/user/1").body(Body::empty()).unwrap();
//     let resp = root_router.serve(Context::default(), req).await.unwrap();
//     assert_eq!(resp.status(), StatusCode::OK);
//     let body = resp.into_body().collect().await.unwrap().to_bytes();
//     assert_eq!(body, "User Info");
// }
// }
