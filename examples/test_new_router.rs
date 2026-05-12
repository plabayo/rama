use std::{error::Error, fmt, iter::successors};

use rama::{
    Layer, Service,
    error::BoxError,
    http::{
        Body, Method, Request, Response, StatusCode,
        layer::into_response::IntoResponseLayer,
        service::web::{Router, extract::Host},
    },
    layer::IntoErrLayer,
};
use rama_http::{
    self,
    layer::error_handling::DowncastErrorHandlerLayer,
    matcher::HttpMatcher,
    service::web::{
        RouterError, error::DowncastResponseError, extract::host::MissingHost,
        response::IntoResponse,
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

#[derive(Debug)]
struct MyCustomErr;

impl fmt::Display for MyCustomErr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

impl Error for MyCustomErr {}

impl From<MissingHost> for MyCustomErr {
    fn from(value: MissingHost) -> Self {
        todo!()
    }
}

impl From<RouterError> for MyCustomErr {
    fn from(value: RouterError) -> Self {
        Self
    }
}

async fn test_func5(host: Host) -> Result<StatusCode, MyCustomErr> {
    // Err("test".into())
    Ok(StatusCode::OK)
}

#[tokio::main]
async fn main() {
    let mut router = Router::new()
        .with_endpoint_layer((IntoResponseLayer::new(), IntoErrLayer::<BoxError>::new()));
    router.set_match_route("/test1", HttpMatcher::method_get(), test_func1);
    router.set_match_route("/test2", HttpMatcher::method_get(), test_func2);

    router.set_match_route("/test3", HttpMatcher::method_get(), TestService1);
    router.set_match_route("/test4", HttpMatcher::method_get(), TestService2);

    router.set_match_route("/test5", HttpMatcher::method_get(), test_func5);

    router.set_match_route("/test6", HttpMatcher::method_get(), Ok("test"));

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
        dbg!(downcast_ref::<DowncastResponseError>(&*err));
        dbg!(downcast_ref::<RouterError>(&*err));
        dbg!(DowncastResponseError::try_as_response(&*err));
    }

    let router = DowncastErrorHandlerLayer::as_ref().layer(router);
    let res = router
        .serve(
            Request::builder()
                .uri("/test555")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    dbg!(&res);

    let mut router1 = Router::new().with_endpoint_layer(());
    router1.set_match_route("/", HttpMatcher::method_get(), test_func5);

    let res = DowncastErrorHandlerLayer::auto()
        .layer(router1)
        .serve(
            Request::builder()
                .uri("/test555")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    dbg!(res);

    let res = router
        .serve(
            Request::builder()
                .uri("/test555")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    dbg!(res);
}
