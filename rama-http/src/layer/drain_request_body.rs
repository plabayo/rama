//! Explicitly finish an upload before invoking a service that ignores its body.
//!
//! Frames are discarded as they arrive, without collecting the upload. The inner
//! service receives the original request parts and an empty body. This is an
//! application policy for all HTTP versions, not required H2/H3 cleanup. It also
//! avoids early upload cancellation for clients that discard a response when
//! their upload is stopped early.
//!
//! Install only on routes whose handlers do not need the body. Original headers
//! (including Content-Length) remain available as request metadata; do not use
//! this layer in front of a forwarding service or a streaming/tunnel handler.
//!
//! By default this layer adds no byte limit or timeout. Optional [`CollectOptions`]
//! impose additional bounds. Place the normal request-body limit
//! outside it, and compose with a request deadline. Reading the already-limited
//! body enforces that limit, including for chunked uploads. Body errors prevent
//! invocation of the inner service: size-limit errors return 413, timeout errors
//! return 408, and other body errors return 400, without exposing error details.
//! Polling an H1 body may send `100 Continue`; this layer intentionally accepts
//! the upload. Apply it only to ordinary HTTP routes, never CONNECT/tunnels.

use crate::{
    Body, Request, Response, StatusCode, StreamingBody,
    body::util::{BodyExt, CollectOptions, LengthLimitError},
};
use rama_core::{Layer, Service, error::BoxError, extensions::ExtensionsRef};
use rama_utils::macros::define_inner_service_accessors;

/// Discard the complete request body before invoking the inner service.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct DrainRequestBodyLayer {
    options: CollectOptions,
}

impl DrainRequestBodyLayer {
    /// Create a layer without adding another body limit or deadline.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            options: CollectOptions::new(),
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Configure additional byte and total-time limits for the drain.
        pub fn options(mut self, options: CollectOptions) -> Self {
            self.options = options;
            self
        }
    }
}

impl<S> Layer<S> for DrainRequestBodyLayer {
    type Service = DrainRequestBody<S>;

    fn layer(&self, inner: S) -> Self::Service {
        DrainRequestBody {
            inner,
            options: self.options.clone(),
        }
    }
}

/// Service produced by [`DrainRequestBodyLayer`].
#[derive(Debug, Clone, ExtensionsRef)]
pub struct DrainRequestBody<S> {
    inner: S,
    options: CollectOptions,
}

impl<S> DrainRequestBody<S> {
    /// Wrap a service whose request body is intentionally empty.
    pub const fn new(inner: S) -> Self {
        Self {
            inner,
            options: CollectOptions::new(),
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Configure additional byte and total-time limits for the drain.
        pub fn options(mut self, options: CollectOptions) -> Self {
            self.options = options;
            self
        }
    }

    define_inner_service_accessors!();
}

impl<S, B> Service<Request<B>> for DrainRequestBody<S>
where
    S: Service<Request, Output = Response>,
    B: StreamingBody<Data: Send, Error: Into<BoxError> + Send> + Send + 'static,
{
    type Output = Response;
    type Error = S::Error;

    async fn serve(&self, request: Request<B>) -> Result<Self::Output, Self::Error> {
        let (parts, body) = request.into_parts();
        if let Err(error) = body.drain_with(self.options.clone()).await {
            let mut status = if rama_core::error::is_timeout_error(error.as_ref()) {
                StatusCode::REQUEST_TIMEOUT
            } else {
                StatusCode::BAD_REQUEST
            };
            for cause in rama_core::error::error_chain(error.as_ref()) {
                if cause.is::<LengthLimitError>() {
                    status = StatusCode::PAYLOAD_TOO_LARGE;
                    break;
                }
            }
            let mut response = Response::new(Body::empty());
            *response.status_mut() = status;
            if status == StatusCode::REQUEST_TIMEOUT && parts.version < crate::Version::HTTP_2 {
                response.headers_mut().insert(
                    crate::header::CONNECTION,
                    crate::HeaderValue::from_static("close"),
                );
            }
            return Ok(response);
        }
        self.inner
            .serve(Request::from_parts(parts, Body::empty()))
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Version, body::Frame};
    use rama_core::{bytes::Bytes, service::service_fn};
    use std::{convert::Infallible, time::Duration};

    #[tokio::test]
    async fn forwards_metadata_only_after_eof() {
        for version in [Version::HTTP_11, Version::HTTP_2, Version::HTTP_3] {
            let (eof_tx, eof_rx) = tokio::sync::oneshot::channel();
            let body = Body::from("abc").with_trailers(async move {
                eof_rx.await.unwrap();
                Some(Ok(crate::HeaderMap::new()))
            });
            let service = DrainRequestBodyLayer::new().into_layer(service_fn(
                move |request: Request| async move {
                    assert_eq!(request.version(), version);
                    assert_eq!(request.headers()["content-length"], "3");
                    assert!(request.body().is_end_stream());
                    Ok::<_, Infallible>(Response::new(Body::empty()))
                },
            ));
            let mut response = Box::pin(
                service.serve(
                    Request::builder()
                        .version(version)
                        .header("content-length", "3")
                        .body(body)
                        .unwrap(),
                ),
            );
            assert!(rama_core::futures::poll!(&mut response).is_pending());
            eof_tx.send(()).unwrap();
            assert_eq!(response.await.unwrap().status(), StatusCode::OK);
        }
    }

    #[tokio::test]
    async fn shared_timeout_with_context_returns_request_timeout() {
        use rama_core::error::ErrorExt as _;
        let service = DrainRequestBodyLayer::new().into_layer(service_fn(
            async |_: Request| -> Result<Response, Infallible> {
                panic!("timed-out upload must not reach handler")
            },
        ));
        let body = Body::from_frame_stream(rama_core::stream::iter([Err::<Frame<Bytes>, _>(
            rama_core::error::TimeoutError.context("custom deadline"),
        )]));
        let response = service.serve(Request::new(body)).await.unwrap();
        assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);
    }

    #[tokio::test(start_paused = true)]
    async fn inherited_body_timeouts_return_request_timeout() {
        let service = DrainRequestBodyLayer::new().into_layer(service_fn(
            async |_: Request| -> Result<Response, Infallible> {
                panic!("timed-out upload must not reach handler")
            },
        ));
        for deadline in [false, true] {
            for version in [Version::HTTP_11, Version::HTTP_2, Version::HTTP_3] {
                let body = Body::from_frame_stream(rama_core::stream::pending::<
                    Result<Frame<Bytes>, Infallible>,
                >());
                let body = if deadline {
                    Body::new(crate::layer::timeout::DeadlineBody::new(
                        Duration::from_secs(1),
                        body,
                    ))
                } else {
                    Body::new(crate::layer::timeout::TimeoutBody::new(
                        Duration::from_secs(1),
                        body,
                    ))
                };
                let response = service
                    .serve(Request::builder().version(version).body(body).unwrap())
                    .await
                    .unwrap();
                assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);
                assert_eq!(
                    response.headers().contains_key(crate::header::CONNECTION),
                    version == Version::HTTP_11
                );
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn rejects_failures_without_dispatching() {
        let service = DrainRequestBodyLayer::new().into_layer(service_fn(
            async |_: Request| -> Result<Response, Infallible> {
                panic!("failed upload must not reach handler")
            },
        ));
        let limited = crate::layer::body_limit::BodyLimitLayer::new(2).into_layer(service.clone());
        assert_eq!(
            limited
                .serve(Request::new(Body::from("abc")))
                .await
                .unwrap()
                .status(),
            StatusCode::PAYLOAD_TOO_LARGE
        );
        let body = Body::from_frame_stream(rama_core::stream::iter([Err::<Frame<Bytes>, _>(
            std::io::Error::other("private details"),
        )]));
        let response = service.serve(Request::new(body)).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(response.body().is_end_stream());
        let bounded = service
            .clone()
            .with_options(CollectOptions::new().with_max_size(2));
        assert_eq!(
            bounded
                .serve(Request::new(Body::from("abc")))
                .await
                .unwrap()
                .status(),
            StatusCode::PAYLOAD_TOO_LARGE
        );
        let timed =
            service.with_options(CollectOptions::new().with_timeout(Duration::from_secs(1)));
        for version in [Version::HTTP_11, Version::HTTP_2, Version::HTTP_3] {
            let body = Body::from_frame_stream(rama_core::stream::pending::<
                Result<Frame<Bytes>, Infallible>,
            >());
            let response = timed
                .serve(Request::builder().version(version).body(body).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);
            assert_eq!(
                response.headers().contains_key(crate::header::CONNECTION),
                version == Version::HTTP_11
            );
        }
    }
}
