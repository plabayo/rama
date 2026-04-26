use std::{convert::Infallible, error::Error, io, iter::successors, sync::Arc};

use derive_more::{Display, Error};
use h2_support::prelude::Response;
use rama::{
    error::BoxError,
    http::{
        service::web::{extract::Host, Router}, Body, Method, Request,
        StatusCode,
    },
    Service,
};
use rama_http::{
    matcher::HttpMatcher,
    service::web::{
        extract::host::MissingHost, response::IntoResponse,
        ResponseError, RouterError,
    },
};

pub fn downcast_ref<'a, E: Error + Send + Sync + 'static>(
    err: &'a (dyn Error + 'static),
) -> Option<&'a E> {
    successors(Some(err), |p| (*p).source()).find_map(|e| e.downcast_ref::<E>())
}

async fn test_func1(method: Host) -> Result<&'static str, BoxError> {
    // Err("test".into())
    Ok("test")
}
async fn test_func2(method: Method) -> Result<StatusCode, BoxError> {
    // Err("test".into())
    Ok(StatusCode::OK)
}

struct TestService1;

impl Service<Request> for TestService1 {
    type Output = &'static str;
    type Error = BoxError;

    async fn serve(&self, input: Request) -> Result<Self::Output, Self::Error> {
        Ok("test service 1")
    }
}

struct TestService2;

impl Service<Request> for TestService2 {
    type Output = StatusCode;
    type Error = BoxError;

    async fn serve(&self, input: Request) -> Result<Self::Output, Self::Error> {
        Ok(StatusCode::ACCEPTED)
    }
}

#[derive(Clone)]
struct Test {}

impl IntoResponse for Test {
    fn into_response(self) -> Response {
        todo!()
    }
}

#[derive(Debug, Error, Display)]
struct MyCustomErr;

impl From<MissingHost> for MyCustomErr {
    fn from(value: MissingHost) -> Self {
        todo!()
    }
}

impl From<ResponseError> for MyCustomErr {
    fn from(value: ResponseError) -> Self {
        Self
    }
}

async fn test_func5(host: Host) -> Result<StatusCode, MyCustomErr> {
    // Err("test".into())
    Ok(StatusCode::OK)
}

#[tokio::main]
async fn main() {
    let mut router = Router::new();
    router.set_match_route("/test1", HttpMatcher::method_get(), test_func1);
    router.set_match_route("/test2", HttpMatcher::method_get(), test_func2);

    router.set_match_route("/test3", HttpMatcher::method_get(), TestService1);
    router.set_match_route("/test4", HttpMatcher::method_get(), TestService2);

    router.set_match_route("/test5", HttpMatcher::method_get(), test_func5);

    router.set_match_route(
        "/test6",
        HttpMatcher::method_get(),
        Ok::<_, Infallible>("test"),
    );
    router.set_match_route(
        "/test7",
        HttpMatcher::method_get(),
        Err::<Infallible, _>(Arc::new(io::Error::from(io::ErrorKind::BrokenPipe))),
    );

    // let router = (ErrorHandlerLayer::new()).layer(router);

    // let router = SimplifiedRouter {
    //     layer: MapResponseLayer,
    // };

    // router.testfn(TestService1);
    // router.testfn(TestService2);

    let res = router
        .serve(
            Request::builder()
                .uri("/test555")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    dbg!(&res);

    if let Err(err) = res {
        dbg!(downcast_ref::<ResponseError>(&*err));
        dbg!(downcast_ref::<RouterError>(&*err));

        if let Some(err) = downcast_ref::<ResponseError>(&*err) {
            let resp = err.as_response();
        }
    }

    let mut router1 = Router::new().with_endpoint_layer(());
    router1.set_match_route("/", HttpMatcher::method_get(), test_func5);

    let res = router1
        .serve(
            Request::builder()
                .uri("/test555")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    dbg!(res);
}
