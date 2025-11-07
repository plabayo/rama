use super::TimeoutBody;
use crate::{Request, Response, StatusCode};
use rama_core::{Layer, Service};
use rama_utils::macros::define_inner_service_accessors;
use std::fmt;
use std::time::Duration;

/// Layer that applies the [`Timeout`] middleware which apply a timeout to requests.
///
/// See the [module docs](super) for an example.
#[derive(Debug, Clone)]
pub struct TimeoutLayer {
    timeout: Duration,
    status_code: StatusCode,
}

impl TimeoutLayer {
    /// Creates a new [`TimeoutLayer`].
    ///
    /// By default, it will return a `408 Request Timeout` response if the request does not complete within the specified timeout.
    /// To customize the response status code, use the `with_status_code` method.
    #[must_use]
    #[inline(always)]
    pub const fn new(timeout: Duration) -> Self {
        Self::with_status_code(StatusCode::REQUEST_TIMEOUT, timeout)
    }

    /// Creates a new [`TimeoutLayer`] with the specified status code for the timeout response.
    #[must_use]
    pub const fn with_status_code(status_code: StatusCode, timeout: Duration) -> Self {
        Self {
            timeout,
            status_code,
        }
    }
}

impl<S> Layer<S> for TimeoutLayer {
    type Service = Timeout<S>;

    fn layer(&self, inner: S) -> Self::Service {
        Timeout::with_status_code(inner, self.status_code, self.timeout)
    }
}

/// Middleware which apply a timeout to requests.
///
/// See the [module docs](super) for an example.
pub struct Timeout<S> {
    inner: S,
    timeout: Duration,
    status_code: StatusCode,
}

impl<S> Timeout<S> {
    #[inline(always)]
    /// Creates a new [`Timeout`].
    ///
    /// By default, it will return a `408 Request Timeout` response if the request does not complete within the specified timeout.
    /// To customize the response status code, use the `with_status_code` method.
    pub const fn new(inner: S, timeout: Duration) -> Self {
        Self::with_status_code(inner, StatusCode::REQUEST_TIMEOUT, timeout)
    }

    /// Creates a new [`Timeout`] with the specified status code for the timeout response.
    pub const fn with_status_code(inner: S, status_code: StatusCode, timeout: Duration) -> Self {
        Self {
            inner,
            timeout,
            status_code,
        }
    }

    define_inner_service_accessors!();
}

impl<S: fmt::Debug> fmt::Debug for Timeout<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Timeout")
            .field("inner", &self.inner)
            .field("timeout", &self.timeout)
            .field("status_code", &self.status_code)
            .finish()
    }
}

impl<S: Clone> Clone for Timeout<S> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            timeout: self.timeout,
            status_code: self.status_code,
        }
    }
}

impl<S: Copy> Copy for Timeout<S> {}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for Timeout<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>>,
    ReqBody: Send + 'static,
    ResBody: Default + Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;

    async fn serve(&self, req: Request<ReqBody>) -> Result<Self::Response, Self::Error> {
        tokio::select! {
            res = self.inner.serve(req) => res,
            _ = tokio::time::sleep(self.timeout) => {
                let mut res = Response::new(ResBody::default());
                *res.status_mut() = self.status_code;
                Ok(res)
            }
        }
    }
}

/// Applies a [`TimeoutBody`] to the request body.
#[derive(Clone, Debug)]
pub struct RequestBodyTimeoutLayer {
    timeout: Duration,
}

impl RequestBodyTimeoutLayer {
    /// Creates a new [`RequestBodyTimeoutLayer`].
    #[must_use]
    pub fn new(timeout: Duration) -> Self {
        Self { timeout }
    }
}

impl<S> Layer<S> for RequestBodyTimeoutLayer {
    type Service = RequestBodyTimeout<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RequestBodyTimeout::new(inner, self.timeout)
    }
}

/// Applies a [`TimeoutBody`] to the request body.
#[derive(Clone, Debug)]
pub struct RequestBodyTimeout<S> {
    inner: S,
    timeout: Duration,
}

impl<S> RequestBodyTimeout<S> {
    /// Creates a new [`RequestBodyTimeout`].
    pub fn new(service: S, timeout: Duration) -> Self {
        Self {
            inner: service,
            timeout,
        }
    }

    /// Returns a new [`Layer`] that wraps services with a [`RequestBodyTimeoutLayer`] middleware.
    ///
    /// [`Layer`]: tower_layer::Layer
    #[must_use]
    pub fn layer(timeout: Duration) -> RequestBodyTimeoutLayer {
        RequestBodyTimeoutLayer::new(timeout)
    }

    define_inner_service_accessors!();
}

impl<S, ReqBody> Service<Request<ReqBody>> for RequestBodyTimeout<S>
where
    S: Service<Request<TimeoutBody<ReqBody>>>,
    ReqBody: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;

    async fn serve(&self, req: Request<ReqBody>) -> Result<Self::Response, Self::Error> {
        let req = req.map(|body| TimeoutBody::new(self.timeout, body));
        self.inner.serve(req).await
    }
}

/// Applies a [`TimeoutBody`] to the response body.
#[derive(Clone)]
pub struct ResponseBodyTimeoutLayer {
    timeout: Duration,
}

impl ResponseBodyTimeoutLayer {
    /// Creates a new [`ResponseBodyTimeoutLayer`].
    #[must_use]
    pub fn new(timeout: Duration) -> Self {
        Self { timeout }
    }
}

impl<S> Layer<S> for ResponseBodyTimeoutLayer {
    type Service = ResponseBodyTimeout<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ResponseBodyTimeout::new(inner, self.timeout)
    }
}

/// Applies a [`TimeoutBody`] to the response body.
#[derive(Clone)]
pub struct ResponseBodyTimeout<S> {
    inner: S,
    timeout: Duration,
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for ResponseBodyTimeout<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>>,
    ReqBody: Send + 'static,
    ResBody: Default + Send + 'static,
{
    type Response = Response<TimeoutBody<ResBody>>;
    type Error = S::Error;

    async fn serve(&self, req: Request<ReqBody>) -> Result<Self::Response, Self::Error> {
        let res = self.inner.serve(req).await?;
        let res = res.map(|body| TimeoutBody::new(self.timeout, body));
        Ok(res)
    }
}

impl<S> ResponseBodyTimeout<S> {
    /// Creates a new [`ResponseBodyTimeout`].
    pub fn new(service: S, timeout: Duration) -> Self {
        Self {
            inner: service,
            timeout,
        }
    }

    /// Returns a new [`Layer`] that wraps services with a [`ResponseBodyTimeoutLayer`] middleware.
    ///
    /// [`Layer`]: tower_layer::Layer
    #[must_use]
    pub fn layer(timeout: Duration) -> ResponseBodyTimeoutLayer {
        ResponseBodyTimeoutLayer::new(timeout)
    }

    define_inner_service_accessors!();
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;

    use super::*;
    use crate::{Body, body::util::BodyExt};
    use rama_core::service::service_fn;

    #[tokio::test]
    async fn request_completes_within_timeout() {
        let service =
            TimeoutLayer::with_status_code(StatusCode::GATEWAY_TIMEOUT, Duration::from_secs(1))
                .into_layer(service_fn(fast_handler));

        let request = Request::get("/").body(Body::empty()).unwrap();
        let res = service.serve(request).await.unwrap();

        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn timeout_middleware_with_custom_status_code() {
        let service = Timeout::with_status_code(
            service_fn(slow_handler),
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_millis(10),
        );

        let request = Request::get("/").body(Body::empty()).unwrap();
        let res = service.serve(request).await.unwrap();

        assert_eq!(res.status(), StatusCode::REQUEST_TIMEOUT);
    }

    #[tokio::test]
    async fn timeout_response_has_empty_body() {
        let service =
            TimeoutLayer::with_status_code(StatusCode::GATEWAY_TIMEOUT, Duration::from_millis(10))
                .into_layer(service_fn(slow_handler));

        let request = Request::get("/").body(Body::empty()).unwrap();
        let res = service.serve(request).await.unwrap();

        assert_eq!(res.status(), StatusCode::GATEWAY_TIMEOUT);

        // Verify the body is empty (default)
        let body = res.into_body();
        let bytes = body.collect().await.unwrap().to_bytes();
        assert!(bytes.is_empty());
    }

    #[tokio::test]
    async fn deprecated_new_method_compatibility() {
        #[allow(deprecated)]
        let layer = TimeoutLayer::new(Duration::from_millis(10));
        let service = layer.into_layer(service_fn(slow_handler));

        let request = Request::get("/").body(Body::empty()).unwrap();
        let res = service.serve(request).await.unwrap();

        // Should use default 408 status code
        assert_eq!(res.status(), StatusCode::REQUEST_TIMEOUT);
    }

    async fn slow_handler(_req: Request<Body>) -> Result<Response<Body>, Infallible> {
        tokio::time::sleep(Duration::from_secs(10)).await;
        Ok(Response::builder()
            .status(StatusCode::OK)
            .body(Body::empty())
            .unwrap())
    }

    async fn fast_handler(_req: Request<Body>) -> Result<Response<Body>, Infallible> {
        Ok(Response::builder()
            .status(StatusCode::OK)
            .body(Body::empty())
            .unwrap())
    }
}
