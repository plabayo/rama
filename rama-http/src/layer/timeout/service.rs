use super::TimeoutBody;
use crate::{Request, Response, StatusCode};
use rama_core::{Context, Layer, Service};
use rama_utils::macros::define_inner_service_accessors;
use std::fmt;
use std::time::Duration;

/// Layer that applies the [`Timeout`] middleware which apply a timeout to requests.
///
/// See the [module docs](super) for an example.
#[derive(Debug, Clone)]
pub struct TimeoutLayer {
    timeout: Duration,
}

impl TimeoutLayer {
    /// Creates a new [`TimeoutLayer`].
    pub const fn new(timeout: Duration) -> Self {
        TimeoutLayer { timeout }
    }
}

impl<S> Layer<S> for TimeoutLayer {
    type Service = Timeout<S>;

    fn layer(&self, inner: S) -> Self::Service {
        Timeout::new(inner, self.timeout)
    }
}

/// Middleware which apply a timeout to requests.
///
/// If the request does not complete within the specified timeout it will be aborted and a `408
/// Request Timeout` response will be sent.
///
/// See the [module docs](super) for an example.
pub struct Timeout<S> {
    inner: S,
    timeout: Duration,
}

impl<S> Timeout<S> {
    /// Creates a new [`Timeout`].
    pub const fn new(inner: S, timeout: Duration) -> Self {
        Self { inner, timeout }
    }

    define_inner_service_accessors!();
}

impl<S: fmt::Debug> fmt::Debug for Timeout<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Timeout")
            .field("inner", &self.inner)
            .field("timeout", &self.timeout)
            .finish()
    }
}

impl<S: Clone> Clone for Timeout<S> {
    fn clone(&self) -> Self {
        Timeout {
            inner: self.inner.clone(),
            timeout: self.timeout,
        }
    }
}

impl<S: Copy> Copy for Timeout<S> {}

impl<S, State, ReqBody, ResBody> Service<State, Request<ReqBody>> for Timeout<S>
where
    S: Service<State, Request<ReqBody>, Response = Response<ResBody>>,
    ReqBody: Send + 'static,
    ResBody: Default + Send + 'static,
    State: Clone + Send + Sync + 'static,
{
    type Response = S::Response;
    type Error = S::Error;

    async fn serve(
        &self,
        ctx: Context<State>,
        req: Request<ReqBody>,
    ) -> Result<Self::Response, Self::Error> {
        tokio::select! {
            res = self.inner.serve(ctx, req) => res,
            _ = tokio::time::sleep(self.timeout) => {
                let mut res = Response::new(ResBody::default());
                *res.status_mut() = StatusCode::REQUEST_TIMEOUT;
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
    pub fn layer(timeout: Duration) -> RequestBodyTimeoutLayer {
        RequestBodyTimeoutLayer::new(timeout)
    }

    define_inner_service_accessors!();
}

impl<S, State, ReqBody> Service<State, Request<ReqBody>> for RequestBodyTimeout<S>
where
    S: Service<State, Request<TimeoutBody<ReqBody>>>,
    ReqBody: Send + 'static,
    State: Clone + Send + Sync + 'static,
{
    type Response = S::Response;
    type Error = S::Error;

    async fn serve(
        &self,
        ctx: Context<State>,
        req: Request<ReqBody>,
    ) -> Result<Self::Response, Self::Error> {
        let req = req.map(|body| TimeoutBody::new(self.timeout, body));
        self.inner.serve(ctx, req).await
    }
}

/// Applies a [`TimeoutBody`] to the response body.
#[derive(Clone)]
pub struct ResponseBodyTimeoutLayer {
    timeout: Duration,
}

impl ResponseBodyTimeoutLayer {
    /// Creates a new [`ResponseBodyTimeoutLayer`].
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

impl<S, State, ReqBody, ResBody> Service<State, Request<ReqBody>> for ResponseBodyTimeout<S>
where
    S: Service<State, Request<ReqBody>, Response = Response<ResBody>>,
    ReqBody: Send + 'static,
    ResBody: Default + Send + 'static,
    State: Clone + Send + Sync + 'static,
{
    type Response = Response<TimeoutBody<ResBody>>;
    type Error = S::Error;

    async fn serve(
        &self,
        ctx: Context<State>,
        req: Request<ReqBody>,
    ) -> Result<Self::Response, Self::Error> {
        let res = self.inner.serve(ctx, req).await?;
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
    pub fn layer(timeout: Duration) -> ResponseBodyTimeoutLayer {
        ResponseBodyTimeoutLayer::new(timeout)
    }

    define_inner_service_accessors!();
}
