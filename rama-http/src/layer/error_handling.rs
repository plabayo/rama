//! Middleware to turn [`Service`] errors into [`Response`]s.
//!
//! # Example
//!
//! ```
//! use rama_core::{
//!     service::service_fn,
//!     Service, Layer,
//!     telemetry::tracing,
//! };
//! use rama_http::{
//!     service::client::HttpClientExt,
//!     layer::{error_handling::ErrorHandlerLayer, timeout::TimeoutLayer},
//!     service::web::WebService,
//!     service::web::response::IntoResponse,
//!     Body, Request, Response, StatusCode,
//! };
//! use std::time::Duration;
//!
//! # async fn some_expensive_io_operation() -> Result<(), std::io::Error> {
//! #     Ok(())
//! # }
//!
//! async fn handler(_req: Request) -> Result<Response, std::io::Error> {
//!     some_expensive_io_operation().await?;
//!     Ok(StatusCode::OK.into_response())
//! }
//!
//! # #[tokio::main]
//! # async fn main() {
//!     let home_handler = (
//!         ErrorHandlerLayer::new().error_mapper(|err| {
//!             tracing::error!("Error: {err:?}");
//!             StatusCode::INTERNAL_SERVER_ERROR.into_response()
//!         }),
//!         TimeoutLayer::new(Duration::from_secs(5)),
//!         ).into_layer(service_fn(handler));
//!
//!     let service = WebService::default().get("/", home_handler);
//!
//!     let _ = service.serve(Request::builder()
//!         .method("GET")
//!         .uri("/")
//!         .body(Body::empty())
//!         .unwrap()).await;
//! # }
//! ```

use crate::service::web::response::IntoResponse;
use crate::{Request, Response};
use rama_core::{Layer, Service};
use rama_utils::macros::define_inner_service_accessors;
use std::{convert::Infallible, fmt};

/// A [`Layer`] that wraps a [`Service`] and converts errors into [`Response`]s.
pub struct ErrorHandlerLayer<F = ()> {
    error_mapper: F,
}

impl Default for ErrorHandlerLayer {
    fn default() -> Self {
        Self::new()
    }
}

impl<F: fmt::Debug> fmt::Debug for ErrorHandlerLayer<F> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("ErrorHandlerLayer")
            .field("error_mapper", &self.error_mapper)
            .finish()
    }
}

impl<F: Clone> Clone for ErrorHandlerLayer<F> {
    fn clone(&self) -> Self {
        Self {
            error_mapper: self.error_mapper.clone(),
        }
    }
}

impl ErrorHandlerLayer {
    /// Create a new [`ErrorHandlerLayer`].
    #[must_use]
    pub const fn new() -> Self {
        Self { error_mapper: () }
    }

    /// Set the error mapper function (not set by default).
    ///
    /// The error mapper function is called with the error,
    /// and should return an [`IntoResponse`] implementation.
    pub fn error_mapper<F>(self, error_mapper: F) -> ErrorHandlerLayer<F> {
        ErrorHandlerLayer { error_mapper }
    }
}

impl<S, F: Clone> Layer<S> for ErrorHandlerLayer<F> {
    type Service = ErrorHandler<S, F>;

    fn layer(&self, inner: S) -> Self::Service {
        ErrorHandler::new(inner).error_mapper(self.error_mapper.clone())
    }

    fn into_layer(self, inner: S) -> Self::Service {
        ErrorHandler::new(inner).error_mapper(self.error_mapper)
    }
}

/// A [`Service`] adapter that handles errors by converting them into [`Response`]s.
pub struct ErrorHandler<S, F = ()> {
    inner: S,
    error_mapper: F,
}

impl<S: fmt::Debug, F: fmt::Debug> fmt::Debug for ErrorHandler<S, F> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("ErrorHandler")
            .field("inner", &self.inner)
            .field("error_mapper", &self.error_mapper)
            .finish()
    }
}

impl<S: Clone, F: Clone> Clone for ErrorHandler<S, F> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            error_mapper: self.error_mapper.clone(),
        }
    }
}

impl<S> ErrorHandler<S> {
    /// Create a new [`ErrorHandler`] wrapping the given service.
    pub const fn new(inner: S) -> Self {
        Self {
            inner,
            error_mapper: (),
        }
    }

    define_inner_service_accessors!();

    /// Set the error mapper function (not set by default).
    ///
    /// The error mapper function is called with the error,
    /// and should return an [`IntoResponse`] implementation.
    pub fn error_mapper<F>(self, error_mapper: F) -> ErrorHandler<S, F> {
        ErrorHandler {
            inner: self.inner,
            error_mapper,
        }
    }
}

impl<S, Body> Service<Request<Body>> for ErrorHandler<S, ()>
where
    S: Service<Request<Body>, Response: IntoResponse, Error: IntoResponse>,
    Body: Send + 'static,
{
    type Response = Response;
    type Error = Infallible;

    async fn serve(&self, req: Request<Body>) -> Result<Self::Response, Self::Error> {
        match self.inner.serve(req).await {
            Ok(response) => Ok(response.into_response()),
            Err(error) => Ok(error.into_response()),
        }
    }
}

impl<S, F, R, Body> Service<Request<Body>> for ErrorHandler<S, F>
where
    S: Service<Request<Body>, Response: IntoResponse>,
    F: Fn(S::Error) -> R + Clone + Send + Sync + 'static,
    R: IntoResponse + 'static,
    Body: Send + 'static,
{
    type Response = Response;
    type Error = Infallible;

    async fn serve(&self, req: Request<Body>) -> Result<Self::Response, Self::Error> {
        match self.inner.serve(req).await {
            Ok(response) => Ok(response.into_response()),
            Err(error) => Ok((self.error_mapper)(error).into_response()),
        }
    }
}
