use derive_more::{Display, Error};
use h2_support::prelude::Response;
use rama::Service;
use rama::error::BoxError;
use rama::http::service::web::Router;
use rama::http::service::web::extract::Host;
use rama::http::{Body, Method, Request, StatusCode};
use rama_core::Layer;
use rama_core::layer::{MapErr, MapErrLayer};
use rama_http::layer::error_handling::ErrorHandlerLayer;
use rama_http::matcher::HttpMatcher;
use rama_http::service::web::extract::host::MissingHost;
use rama_http::service::web::response::IntoResponse;
use rama_http::service::web::{
    IntoEndpointService, IntoEndpointServiceWithState, MapResponseService, ResponseError,
    RouterError,
};
use std::convert::Infallible;
use std::error::Error;
use std::io;
use std::iter::successors;
use std::sync::Arc;

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

struct MapResponseLayer;

impl<S, O, E> Layer<S> for MapResponseLayer
where
    S: Service<Request, Output = O, Error = E>,
    O: IntoResponse + Send + Sync + 'static,
{
    type Service = MapResponseService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        MapResponseService::new(inner)
    }
}

fn map_response_layer<S>(inner: S) -> MapResponseService<S>
where
    S: Service<Request, Output: IntoResponse + Send + Sync + 'static>,
{
    MapResponseService::new(inner)
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

async fn test_func5(host: Host) -> Result<StatusCode, MyCustomErr> {
    // Err("test".into())
    Ok(StatusCode::OK)
}

struct IntoErrLayer;

impl<S: Service<Request, Error = E>, E: Into<BoxError>> Layer<S> for IntoErrLayer {
    type Service = MapErr<S, fn(S::Error) -> BoxError>;

    fn layer(&self, inner: S) -> Self::Service {
        MapErr::new(inner, |err| err.into())
    }
}

#[tokio::main]
async fn main() {
    let mut router = Router::new_with_layer((MapResponseLayer, IntoErrLayer));
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
}
