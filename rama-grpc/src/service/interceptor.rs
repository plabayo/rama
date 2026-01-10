//! gRPC interceptors which are a kind of middleware.
//!
//! gRPC interceptors are similar to regular rama middleware [`Service`]s. but have less flexibility. An interceptor allows
//! you to do two main things, one is to add/remove/check items in the `MetadataMap` of each
//! request. Two, cancel a request with a `Status`.
//!
//! An interceptor can be used on both the server and client.
//!
//! If you need more powerful middleware, regular rama layers are the recommended approach.
//!
//! Additionally, interceptors is not the recommended way to add logging to your service. For that
//! a rama middleware is more appropriate since it can also act on the response. For example
//! rama-http's [`Trace`](rama_http::layer::trace::Trace)
//! middleware supports gRPC out of the box.
use rama_core::{Layer, Service, telemetry::tracing};
use rama_http::{self as http, Response, StatusCode, body::OptionalBody};

use crate::request::SanitizeHeaders;

/// A gRPC interceptor that can be used as a [`Layer`],
#[derive(Debug, Clone, Copy)]
pub struct InterceptorLayer<I> {
    interceptor: I,
}

impl<I> InterceptorLayer<I> {
    /// Create a new interceptor layer.
    pub fn new(interceptor: I) -> Self {
        Self { interceptor }
    }
}

impl<S, I> Layer<S> for InterceptorLayer<I>
where
    I: Clone,
{
    type Service = InterceptedService<S, I>;

    fn layer(&self, service: S) -> Self::Service {
        InterceptedService::new(service, self.interceptor.clone())
    }

    fn into_layer(self, service: S) -> Self::Service {
        InterceptedService::new(service, self.interceptor)
    }
}

/// A service wrapped in an interceptor middleware.
#[derive(Debug, Clone)]
pub struct InterceptedService<S, I> {
    inner: S,
    interceptor: I,
}

impl<S, I> InterceptedService<S, I> {
    /// Create a new `InterceptedService` that wraps `S` and intercepts each request with the
    /// the given interceptor [`Service`] (`I`).
    pub fn new(service: S, interceptor: I) -> Self {
        Self {
            inner: service,
            interceptor,
        }
    }
}

impl<S, I, ReqBody, ResBody> Service<http::Request<ReqBody>> for InterceptedService<S, I>
where
    S: Service<http::Request<ReqBody>, Output = http::Response<ResBody>>,
    I: Service<crate::Request<()>, Output = crate::Request<()>, Error = crate::Status>,
    ReqBody: Send + 'static,
    ResBody: Send + 'static,
{
    type Output = http::Response<OptionalBody<ResBody>>;
    type Error = S::Error;

    async fn serve(&self, req: http::Request<ReqBody>) -> Result<Self::Output, Self::Error> {
        // It is bad practice to modify the body (i.e. Message) of the request via an interceptor.
        // To avoid exposing the body of the request to the interceptor function, we first remove it
        // here, allow the interceptor to modify the metadata and extensions, and then recreate the
        // HTTP request with the body. rama-grpc requests do not preserve the URI, HTTP version, and
        // HTTP method of the HTTP request, so we extract them here and then add them back in below.
        let uri = req.uri().clone();
        let method = req.method().clone();
        let version = req.version();
        let req = crate::Request::from_http(req);
        let (metadata, extensions, msg) = req.into_parts();

        match self
            .interceptor
            .serve(crate::Request::from_parts(metadata, extensions, ()))
            .await
        {
            Ok(req) => {
                let (metadata, extensions, _) = req.into_parts();
                let req = crate::Request::from_parts(metadata, extensions, msg);
                let req = req.into_http(uri, method, version, SanitizeHeaders::No);
                Ok(self.inner.serve(req).await?.map(OptionalBody::some))
            }
            Err(status) => match status.try_into_http::<OptionalBody<ResBody>>() {
                Ok(status_res) => Ok(status_res),
                Err(status) => {
                    tracing::debug!("failed to turn status into response: status = {status:?}");
                    let mut res = Response::new(OptionalBody::none());
                    *res.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                    Ok(res)
                }
            },
        }
    }
}

impl<S, I> crate::server::NamedService for InterceptedService<S, I>
where
    S: crate::server::NamedService,
{
    const NAME: &'static str = S::NAME;
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;

    use rama_core::{
        layer::MapErrLayer,
        service::{MirrorService, service_fn},
    };

    use crate::Status;

    use super::*;

    #[tokio::test]
    async fn doesnt_remove_headers_from_requests() {
        let svc = service_fn(async |request: http::Request<()>| {
            assert_eq!(
                request
                    .headers()
                    .get("user-agent")
                    .expect("missing in leaf service"),
                "test-tonic"
            );

            Ok::<_, crate::Status>(http::Response::new(()))
        });

        let svc = InterceptedService::new(
            svc,
            service_fn(async |request: crate::Request<()>| {
                assert_eq!(
                    request
                        .metadata()
                        .get("user-agent")
                        .expect("missing in interceptor"),
                    "test-tonic"
                );

                Ok(request)
            }),
        );

        let request = http::Request::builder()
            .header("user-agent", "test-tonic")
            .body(())
            .unwrap();

        svc.serve(request).await.unwrap();
    }

    #[tokio::test]
    async fn handles_intercepted_status_as_response() {
        const MESSAGE: &str = "Blocked by the interceptor";

        let expected = crate::Status::permission_denied(MESSAGE)
            .try_into_http::<()>()
            .unwrap();

        let svc = service_fn(async |_: http::Request<()>| {
            Ok::<_, crate::Status>(http::Response::new(()))
        });

        let svc = InterceptedService::new(
            svc,
            service_fn(async |_: crate::Request<()>| {
                Err(crate::Status::permission_denied(MESSAGE))
            }),
        );

        let request = http::Request::builder().body(()).unwrap();
        let response = svc.serve(request).await.unwrap();

        assert_eq!(expected.status(), response.status());
        assert_eq!(expected.version(), response.version());
        assert_eq!(expected.headers(), response.headers());
    }

    #[tokio::test]
    async fn doesnt_change_http_method() {
        let svc = service_fn(async |request: http::Request<()>| {
            assert_eq!(request.method(), http::Method::OPTIONS);

            Ok::<_, Infallible>(Response::new(()))
        });

        let svc = InterceptedService::new(
            svc,
            MapErrLayer::new(|_| Status::internal("unexpected")).into_layer(MirrorService::new()),
        );

        let request = http::Request::builder()
            .method(http::Method::OPTIONS)
            .body(())
            .unwrap();

        svc.serve(request).await.unwrap();
    }
}
