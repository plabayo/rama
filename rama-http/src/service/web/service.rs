#[doc(hidden)]
#[macro_export]
/// Create a new [`Service`](rama_core::Service) from a chain of matcher-service tuples.
///
/// Think of it like the Rust match statement, but for http services.
/// Which is nothing more then a convenient wrapper to create a tuple of matcher-service tuples,
/// with the last tuple being the fallback service. And all services implement
/// the [`IntoEndpointService`](crate::service::web::IntoEndpointService) trait.
///
/// # Example
///
/// ```rust
/// use rama_http::matcher::{HttpMatcher, MethodMatcher};
/// use rama_http::{Body, Request, Response, StatusCode};
/// use rama_http::body::util::BodyExt;
/// use rama_core::{Service};
///
/// #[tokio::main]
/// async fn main() {
///   let svc = rama_http::service::web::match_service! {
///     HttpMatcher::get("/hello") => "hello",
///     HttpMatcher::post("/world") => "world",
///     MethodMatcher::CONNECT => "connect",
///     _ => StatusCode::NOT_FOUND,
///   };
///
///   let resp = svc.serve(
///       Request::post("https://www.test.io/world").body(Body::empty()).unwrap(),
///   ).await.unwrap();
///   assert_eq!(resp.status(), StatusCode::OK);
///   let body = resp.into_body().collect().await.unwrap().to_bytes();
///   assert_eq!(body, "world");
/// }
/// ```
///
/// Which is short for the following:
///
/// ```rust
/// use rama_http::matcher::{HttpMatcher, MethodMatcher};
/// use rama_http::{Body, Request, Response, StatusCode};
/// use rama_http::body::util::BodyExt;
/// use rama_http::service::web::IntoEndpointService;
/// use rama_http::layer::error_handling::ErrorHandler;
/// use rama_core::{Service};
/// use rama_core::matcher::MatcherRouter;
///
/// #[tokio::main]
/// async fn main() {
///   let svc = MatcherRouter((
///     (HttpMatcher::get("/hello"), ErrorHandler::new("hello".into_endpoint_service())),
///     (HttpMatcher::post("/world"), ErrorHandler::new("world".into_endpoint_service())),
///     (MethodMatcher::CONNECT, ErrorHandler::new("connect".into_endpoint_service())),
///     ErrorHandler::new(StatusCode::NOT_FOUND.into_endpoint_service()),
///   ));
///
///   let resp = svc.serve(
///
///      Request::post("https://www.test.io/world").body(Body::empty()).unwrap(),
///   ).await.unwrap();
///   assert_eq!(resp.status(), StatusCode::OK);
///   let body = resp.into_body().collect().await.unwrap().to_bytes();
///   assert_eq!(body, "world");
/// }
/// ```
///
/// As you can see it is pretty much the same, except that you need to explicitly ensure
/// that each service is an actual Endpoint service.
macro_rules! __match_service {
    ($($M:expr_2021 => $S:expr_2021),+, _ => $F:expr $(,)?) => {{
        use $crate::service::web::IntoEndpointService;
        use $crate::layer::error_handling::ErrorHandler;
        use $crate::__macro_dep::__core::matcher::MatcherRouter;
        MatcherRouter((
            $(($M, ErrorHandler::new($S.into_endpoint_service()))),+,
            ErrorHandler::new($F.into_endpoint_service()))
        )
    }};
}

#[doc(inline)]
pub use crate::__match_service as match_service;

#[cfg(test)]
mod test {
    use crate::matcher::{HttpMatcher, MethodMatcher};
    use crate::{Body, Request, Response, StatusCode, body::util::BodyExt};
    use rama_core::Service;
    use std::convert::Infallible;

    use super::*;

    async fn response<S>(service: &S, req: Request) -> Response
    where
        S: Service<Request, Output = Response, Error = Infallible>,
    {
        service.serve(req).await.unwrap()
    }

    fn request(method: &str, uri: &str) -> Request {
        Request::builder()
            .method(method)
            .uri(uri)
            .body(Body::empty())
            .unwrap()
    }

    #[tokio::test]
    async fn test_matcher_service_tuples() {
        let svc = match_service! {
            HttpMatcher::get("/hello") => "hello",
            HttpMatcher::post("/world") => "world",
            MethodMatcher::CONNECT => "connect",
            _ => StatusCode::NOT_FOUND,
        };

        let res = response(&svc, request("GET", "https://www.test.io/hello")).await;
        assert_eq!(res.status(), StatusCode::OK);
        let body = res.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body, "hello");

        let res = response(&svc, request("POST", "https://www.test.io/world")).await;
        assert_eq!(res.status(), StatusCode::OK);
        let body = res.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body, "world");

        let res = response(&svc, request("CONNECT", "https://www.test.io")).await;
        assert_eq!(res.status(), StatusCode::OK);
        let body = res.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body, "connect");

        let res = response(&svc, request("GET", "https://www.test.io/world")).await;
        assert_eq!(res.status(), StatusCode::NOT_FOUND);

        let res = response(&svc, request("GET", "https://www.test.io")).await;
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
    }
}
