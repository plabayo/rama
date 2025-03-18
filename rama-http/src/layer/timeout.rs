//! Middleware that applies a timeout to requests.
//!
//! If the request does not complete within the specified timeout it will be aborted and a `408
//! Request Timeout` response will be sent.
//!
//! # Differences from `rama_core::service::layer::Timeout`
//!
//! The generic [`Timeout`] middleware uses an error to signal timeout, i.e.
//! it changes the error type to [`BoxError`](rama_core::error::BoxError). For HTTP services that is rarely
//! what you want as returning errors will terminate the connection without sending a response.
//!
//! This middleware won't change the error type and instead return a `408 Request Timeout`
//! response. That means if your service's error type is [`Infallible`] it will still be
//! [`Infallible`] after applying this middleware.
//!
//! # Example
//!
//! ```
//! use std::{convert::Infallible, time::Duration};
//!
//! use rama_core::Layer;
//! use rama_core::service::service_fn;
//! use rama_http::{Body, Request, Response};
//! use rama_http::layer::timeout::TimeoutLayer;
//! use rama_core::error::BoxError;
//!
//! async fn handle(_: Request) -> Result<Response, Infallible> {
//!     // ...
//!     # Ok(Response::new(Body::empty()))
//! }
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), BoxError> {
//! let svc = (
//!     // Timeout requests after 30 seconds
//!     TimeoutLayer::new(Duration::from_secs(30)),
//! ).into_layer(service_fn(handle));
//! # Ok(())
//! # }
//! ```
//!
//! [`Infallible`]: std::convert::Infallible

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
