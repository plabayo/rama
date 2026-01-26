use std::fmt;

use rama_core::{Service, bytes, error::BoxError, telemetry::tracing};
use rama_http_types::{
    Body, HeaderMap, HeaderValue, Method, Request, Response, StatusCode, StreamingBody, Version,
    header,
};

use crate::{metadata::GRPC_CONTENT_TYPE, server::NamedService};

use super::call::content_types::is_grpc_web;
use super::call::{Encoding, GrpcWebCall};

/// Service implementing the grpc-web protocol.
#[derive(Debug, Clone)]
pub struct GrpcWebService<S> {
    inner: S,
}

#[derive(Debug, PartialEq)]
enum RequestKind<'a> {
    // The request is considered a grpc-web request if its `content-type`
    // header is exactly one of:
    //
    //  - "application/grpc-web"
    //  - "application/grpc-web+proto"
    //  - "application/grpc-web-text"
    //  - "application/grpc-web-text+proto"
    GrpcWeb {
        method: &'a Method,
        encoding: Encoding,
        accept: Encoding,
    },
    // All other requests, including `application/grpc`
    Other(rama_http_types::Version),
}

impl<S> GrpcWebService<S> {
    pub(crate) fn new(inner: S) -> Self {
        Self { inner }
    }
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for GrpcWebService<S>
where
    S: Service<Request<Body>, Output = Response<ResBody>>,
    ReqBody: StreamingBody<Data = bytes::Bytes, Error: Into<BoxError> + fmt::Display>
        + Send
        + Sync
        + 'static,
    ResBody: StreamingBody<Data = bytes::Bytes, Error: Into<BoxError> + fmt::Display>
        + Send
        + Sync
        + 'static,
{
    type Output = Response<Body>;
    type Error = S::Error;

    async fn serve(&self, req: Request<ReqBody>) -> Result<Self::Output, Self::Error> {
        match RequestKind::new(req.headers(), req.method(), req.version()) {
            // A valid grpc-web request, regardless of HTTP version.
            //
            // If the request includes an `origin` header, we verify it is allowed
            // to access the resource, an HTTP 403 response is returned otherwise.
            //
            // If the origin is allowed to access the resource or there is no
            // `origin` header present, translate the request into a grpc request,
            // call the inner service, and translate the response back to
            // grpc-web.
            RequestKind::GrpcWeb {
                method: &Method::POST,
                encoding,
                accept,
            } => {
                tracing::trace!(
                    kind = "simple",
                    path = ?req.uri().path(),
                    ?encoding,
                    ?accept,
                );

                let res = self.inner.serve(coerce_request(req, encoding)).await?;
                Ok(coerce_response(res, accept))
            }

            // The request's content-type matches one of the 4 supported grpc-web
            // content-types, but the request method is not `POST`.
            // This is not a valid grpc-web request, return HTTP 405.
            RequestKind::GrpcWeb { .. } => {
                tracing::debug!(
                    kind = "simple",
                    error="method not allowed",
                    method = ?req.method(),
                );

                let mut res = Response::new(Body::empty());
                *res.status_mut() = StatusCode::METHOD_NOT_ALLOWED;
                Ok(res)
            }

            // All http/2 requests that are not grpc-web are passed through to the inner service,
            // whatever they are.
            RequestKind::Other(Version::HTTP_2) => {
                tracing::debug!(
                    kind = "other h2",
                    content_type = ?req.headers().get(header::CONTENT_TYPE),
                );

                Ok(self.inner.serve(req.map(Body::new)).await?.map(Body::new))
            }

            // Return HTTP 400 for all other requests.
            RequestKind::Other(_) => {
                tracing::debug!(
                    kind = "other h1",
                    content_type = ?req.headers().get(header::CONTENT_TYPE),
                );

                let mut res = Response::new(Body::empty());
                *res.status_mut() = StatusCode::BAD_REQUEST;
                Ok(res)
            }
        }
    }
}

impl<S: NamedService> NamedService for GrpcWebService<S> {
    const NAME: &'static str = S::NAME;
}

impl<'a> RequestKind<'a> {
    fn new(headers: &'a HeaderMap, method: &'a Method, version: Version) -> Self {
        if is_grpc_web(headers) {
            return RequestKind::GrpcWeb {
                method,
                encoding: Encoding::from_content_type(headers),
                accept: Encoding::from_accept(headers),
            };
        }

        RequestKind::Other(version)
    }
}

// Mutating request headers to conform to a gRPC request is not really
// necessary for us at this point. We could remove most of these except
// maybe for inserting `header::TE`, which rama-grpc should check?
fn coerce_request<B>(mut req: Request<B>, encoding: Encoding) -> Request<Body>
where
    B: StreamingBody<Data = bytes::Bytes, Error: Into<BoxError> + fmt::Display>
        + Send
        + Sync
        + 'static,
{
    req.headers_mut().remove(header::CONTENT_LENGTH);

    req.headers_mut()
        .insert(header::CONTENT_TYPE, GRPC_CONTENT_TYPE);

    req.headers_mut()
        .insert(header::TE, HeaderValue::from_static("trailers"));

    req.headers_mut().insert(
        header::ACCEPT_ENCODING,
        HeaderValue::from_static("identity,deflate,gzip"),
    );

    req.map(|b| Body::new(GrpcWebCall::request(b, encoding)))
}

fn coerce_response<B>(res: Response<B>, encoding: Encoding) -> Response<Body>
where
    B: StreamingBody<Data = bytes::Bytes, Error: Into<BoxError> + fmt::Display>
        + Send
        + Sync
        + 'static,
{
    let mut res = res
        .map(|b| GrpcWebCall::response(b, encoding))
        .map(Body::new);

    res.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(encoding.to_content_type()),
    );

    res
}

#[cfg(test)]
mod tests {
    use rama_core::{Layer as _, Service};
    use rama_http::layer::cors::{Cors, CorsLayer};
    use rama_http_types::header::{
        ACCESS_CONTROL_REQUEST_HEADERS, ACCESS_CONTROL_REQUEST_METHOD, CONTENT_TYPE, ORIGIN,
    };

    use crate::web::call::content_types::*;

    use super::*;

    #[derive(Debug, Clone)]
    struct Svc;

    impl<B: Send + 'static> Service<Request<B>> for Svc {
        type Output = Response<Body>;
        type Error = std::convert::Infallible;

        async fn serve(&self, _: Request<B>) -> Result<Self::Output, Self::Error> {
            Ok(Response::new(Body::default()))
        }
    }

    impl NamedService for Svc {
        const NAME: &'static str = "test";
    }

    fn enable<S>(service: S) -> Cors<GrpcWebService<S>>
    where
        S: Service<rama_http_types::Request<Body>, Output = rama_http_types::Response<Body>>,
    {
        (CorsLayer::new(), crate::web::GrpcWebLayer::new()).into_layer(service)
    }

    mod grpc_web {
        use super::*;

        use rama_core::Layer;
        use rama_http::service::web::Router;

        fn request() -> Request<Body> {
            Request::builder()
                .method(Method::POST)
                .header(CONTENT_TYPE, GRPC_WEB)
                .header(ORIGIN, "http://example.com")
                .body(Body::default())
                .unwrap()
        }

        #[tokio::test]
        async fn default_cors_config() {
            let svc = enable(Svc);
            let res = svc.serve(request()).await.unwrap();

            assert_eq!(res.status(), StatusCode::OK);
        }

        #[tokio::test]
        async fn web_layer() {
            let svc = crate::web::GrpcWebLayer::new().into_layer(Svc);
            let res = svc.serve(request()).await.unwrap();

            assert_eq!(res.status(), StatusCode::OK);
        }

        #[tokio::test]
        async fn web_layer_with_axum() {
            let svc = crate::web::GrpcWebLayer::new().into_layer(Router::new().with_post("/", Svc));

            let res = svc.serve(request()).await.unwrap();

            assert_eq!(res.status(), StatusCode::OK);
        }

        #[tokio::test]
        async fn without_origin() {
            let svc = enable(Svc);

            let mut req = request();
            req.headers_mut().remove(ORIGIN);

            let res = svc.serve(req).await.unwrap();

            assert_eq!(res.status(), StatusCode::OK);
        }

        #[tokio::test]
        async fn only_post_and_options_allowed() {
            let svc = enable(Svc);

            for method in &[
                Method::GET,
                Method::PUT,
                Method::DELETE,
                Method::HEAD,
                Method::PATCH,
            ] {
                let mut req = request();
                *req.method_mut() = method.clone();

                let res = svc.serve(req).await.unwrap();

                assert_eq!(
                    res.status(),
                    StatusCode::METHOD_NOT_ALLOWED,
                    "{method} should not be allowed"
                );
            }
        }

        #[tokio::test]
        async fn grpc_web_content_types() {
            let svc = enable(Svc);

            for ct in &[GRPC_WEB_TEXT, GRPC_WEB_PROTO, GRPC_WEB_TEXT_PROTO, GRPC_WEB] {
                let mut req = request();
                req.headers_mut()
                    .insert(CONTENT_TYPE, HeaderValue::from_static(ct));

                let res = svc.serve(req).await.unwrap();

                assert_eq!(res.status(), StatusCode::OK);
            }
        }
    }

    mod options {
        use super::*;

        fn request() -> Request<Body> {
            Request::builder()
                .method(Method::OPTIONS)
                .header(ORIGIN, "http://example.com")
                .header(ACCESS_CONTROL_REQUEST_HEADERS, "x-grpc-web")
                .header(ACCESS_CONTROL_REQUEST_METHOD, "POST")
                .body(Body::default())
                .unwrap()
        }

        #[tokio::test]
        async fn valid_grpc_web_preflight() {
            let svc = enable(Svc);
            let res = svc.serve(request()).await.unwrap();

            assert_eq!(res.status(), StatusCode::OK);
        }
    }

    mod grpc {
        use super::*;

        fn request() -> Request<Body> {
            Request::builder()
                .version(Version::HTTP_2)
                .header(CONTENT_TYPE, GRPC_CONTENT_TYPE)
                .body(Body::default())
                .unwrap()
        }

        #[tokio::test]
        async fn h2_is_ok() {
            let svc = enable(Svc);

            let req = request();
            let res = svc.serve(req).await.unwrap();

            assert_eq!(res.status(), StatusCode::OK)
        }

        #[tokio::test]
        async fn h1_is_err() {
            let svc = enable(Svc);

            let req = Request::builder()
                .header(CONTENT_TYPE, GRPC_CONTENT_TYPE)
                .body(Body::default())
                .unwrap();

            let res = svc.serve(req).await.unwrap();
            assert_eq!(res.status(), StatusCode::BAD_REQUEST)
        }

        #[tokio::test]
        async fn content_type_variants() {
            let svc = enable(Svc);

            for variant in &["grpc", "grpc+proto", "grpc+thrift", "grpc+foo"] {
                let mut req = request();
                req.headers_mut().insert(
                    CONTENT_TYPE,
                    HeaderValue::from_maybe_shared(format!("application/{variant}")).unwrap(),
                );

                let res = svc.serve(req).await.unwrap();

                assert_eq!(res.status(), StatusCode::OK)
            }
        }
    }

    mod other {
        use super::*;

        fn request() -> Request<Body> {
            Request::builder()
                .header(CONTENT_TYPE, "application/text")
                .body(Body::default())
                .unwrap()
        }

        #[tokio::test]
        async fn h1_is_err() {
            let svc = enable(Svc);
            let res = svc.serve(request()).await.unwrap();

            assert_eq!(res.status(), StatusCode::BAD_REQUEST)
        }

        #[tokio::test]
        async fn h2_is_ok() {
            let svc = enable(Svc);
            let mut req = request();
            *req.version_mut() = Version::HTTP_2;

            let res = svc.serve(req).await.unwrap();
            assert_eq!(res.status(), StatusCode::OK)
        }
    }
}
