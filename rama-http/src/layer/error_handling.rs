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
//!     let service = WebService::default().with_get("/", home_handler);
//!
//!     _ = service.serve(Request::builder()
//!         .method("GET")
//!         .uri("/")
//!         .body(Body::empty())
//!         .unwrap()).await;
//! # }
//! ```

use crate::service::web::{
    error::DowncastResponseError,
    response::{ErrorResponse, IntoResponse},
};
use crate::{Request, Response};
use http::StatusCode;
use rama_core::{Layer, Service};
use rama_utils::macros::define_inner_service_accessors;
use std::convert::Infallible;
use std::error::Error;
use std::marker::PhantomData;

/// A [`Layer`] that wraps a [`Service`] and converts errors into [`Response`]s.
#[derive(Debug, Clone)]
pub struct ErrorHandlerLayer<F = ()> {
    error_mapper: F,
}

impl Default for ErrorHandlerLayer {
    fn default() -> Self {
        Self::new()
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
#[derive(Debug, Clone)]
pub struct ErrorHandler<S, F = ()> {
    inner: S,
    error_mapper: F,
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
    S: Service<Request<Body>, Output: IntoResponse, Error: Into<ErrorResponse>>,
    Body: Send + 'static,
{
    type Output = Response;
    type Error = Infallible;

    async fn serve(&self, req: Request<Body>) -> Result<Self::Output, Self::Error> {
        match self.inner.serve(req).await {
            Ok(response) => Ok(response.into_response()),
            Err(error) => Ok(error.into().into_response()),
        }
    }
}

impl<S, F, R, Body> Service<Request<Body>> for ErrorHandler<S, F>
where
    S: Service<Request<Body>, Output: IntoResponse>,
    F: Fn(S::Error) -> R + Clone + Send + Sync + 'static,
    R: IntoResponse + 'static,
    Body: Send + 'static,
{
    type Output = Response;
    type Error = Infallible;

    async fn serve(&self, req: Request<Body>) -> Result<Self::Output, Self::Error> {
        match self.inner.serve(req).await {
            Ok(response) => Ok(response.into_response()),
            Err(error) => Ok((self.error_mapper)(error).into_response()),
        }
    }
}

/// Marker type for [`DowncastErrorHandler`] representing errors implementing [`Error`] trait
#[derive(Default, Clone, Copy)]
#[non_exhaustive]
pub struct ImplErrorKind;

/// Marker type for [`DowncastErrorHandler`] representing errors
/// implementing [`AsRef<dyn Error + Send + Sync>`]
#[derive(Default, Clone, Copy)]
#[non_exhaustive]
pub struct AsRefKind;

/// [`Service`] that tries to downcast an Error into [`Response`] using [`DowncastResponseError`]
///
/// If there is no [`DowncastResponseError`] in the error chain, it returns INTERNAL_SERVER_ERROR
pub struct DowncastErrorHandler<S, K> {
    inner: S,
    _kind: PhantomData<fn(K) -> K>,
}

impl<S, I> Service<I> for DowncastErrorHandler<S, ImplErrorKind>
where
    S: Service<I, Output: IntoResponse, Error: Error + 'static>,
    I: Send + 'static,
{
    type Output = Response;
    type Error = Infallible;

    async fn serve(&self, input: I) -> Result<Self::Output, Self::Error> {
        Ok(match self.inner.serve(input).await {
            Ok(resp) => resp.into_response(),
            Err(err) => DowncastResponseError::try_as_response(&err)
                .unwrap_or_else(|| StatusCode::INTERNAL_SERVER_ERROR.into_response()),
        })
    }
}

impl<S, I> Service<I> for DowncastErrorHandler<S, AsRefKind>
where
    S: Service<I, Output: IntoResponse, Error: AsRef<dyn Error + Send + Sync>>,
    I: Send + 'static,
{
    type Output = Response;
    type Error = Infallible;

    async fn serve(&self, input: I) -> Result<Self::Output, Self::Error> {
        Ok(match self.inner.serve(input).await {
            Ok(resp) => resp.into_response(),
            Err(err) => DowncastResponseError::try_as_response(err.as_ref())
                .unwrap_or_else(|| StatusCode::INTERNAL_SERVER_ERROR.into_response()),
        })
    }
}

/// [`Layer`] that tries to downcast an Error into [`Response`] using [`DowncastResponseError`]
///
/// See [`DowncastErrorHandler`] for additional documentation
#[derive(Debug, Default, Clone)]
pub struct DowncastErrorHandlerLayer<K>(PhantomData<fn(K) -> K>);

impl DowncastErrorHandlerLayer<()> {
    /// Creates [`DowncastErrorHandlerLayer`] for errors implementing [`AsRef<dyn Error + Send + Sync>`]
    pub fn as_ref() -> DowncastErrorHandlerLayer<AsRefKind> {
        Default::default()
    }

    /// Creates [`DowncastErrorHandlerLayer`] for errors implementing [`Error`]
    pub fn impl_error() -> DowncastErrorHandlerLayer<ImplErrorKind> {
        Default::default()
    }

    /// Creates [`DowncastErrorHandlerLayer`] by inferring Error kind from context
    pub fn auto<M: Default>() -> DowncastErrorHandlerLayer<M> {
        Default::default()
    }
}

impl<S, K: Copy> Layer<S> for DowncastErrorHandlerLayer<K> {
    type Service = DowncastErrorHandler<S, K>;

    fn layer(&self, inner: S) -> Self::Service {
        DowncastErrorHandler {
            inner,
            _kind: self.0,
        }
    }
}
